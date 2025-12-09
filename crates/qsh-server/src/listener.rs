//! QUIC server listener with improved connection handling.
//!
//! This module provides `QshListener` which wraps the QUIC backend with:
//! - IP_RECVERR for fast disconnect detection on Linux
//! - Reduced idle timeout for faster reconnection in bootstrap mode
//! - Clean separation between listener and connection handling
//! - Backend-agnostic transport abstraction (quiche or s2n-quic)

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, error, info};

use qsh_core::constants::IDLE_TIMEOUT;
use qsh_core::error::{Error, Result};
use qsh_core::protocol::{HeartbeatPayload, Message};
use qsh_core::transport::{Connection, QuicAcceptor, QuicConnection, ListenerConfig};

use crate::connection::{ConnectionConfig, ConnectionHandler};
use crate::registry::ConnectionRegistry;
use crate::session::SessionConfig;
use crate::{PendingSession, SessionAuthorizer};

// =============================================================================
// Constants
// =============================================================================

/// Reduced idle timeout for bootstrap mode (5 seconds).
/// This allows faster detection of client disconnection and quicker reconnection.
const BOOTSTRAP_IDLE_TIMEOUT_MS: u64 = 5_000;

// =============================================================================
// Server Configuration
// =============================================================================

/// Server configuration for the QUIC listener.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Bind address for the server.
    pub bind_addr: SocketAddr,
    /// TLS certificate (PEM format).
    pub cert_pem: Vec<u8>,
    /// TLS private key (PEM format).
    pub key_pem: Vec<u8>,
    /// Session configuration.
    pub session_config: SessionConfig,
    /// Connection configuration.
    pub conn_config: ConnectionConfig,
    /// Bootstrap mode (uses shorter idle timeout for faster reconnection).
    pub bootstrap_mode: bool,
}

// =============================================================================
// QshListener - Main server listener
// =============================================================================

/// QUIC server listener with improved connection handling.
///
/// Key features:
/// - Backend-agnostic (supports quiche and s2n-quic)
/// - Configurable idle timeout (reduced in bootstrap mode)
/// - Clean registry-based session management
pub struct QshListener {
    /// QUIC acceptor (backend-agnostic).
    acceptor: QuicAcceptor,
    /// Local address.
    local_addr: SocketAddr,
    /// Connection registry for session persistence.
    registry: Arc<ConnectionRegistry>,
    /// Server configuration.
    config: ServerConfig,
    /// Session authorizer (for bootstrap mode).
    authorizer: Option<Arc<SessionAuthorizer>>,
}

impl QshListener {
    /// Create a new listener bound to the specified address.
    ///
    /// This binds a UDP socket and configures it for optimal QUIC handling,
    /// including IP_RECVERR on Linux for fast disconnect detection.
    pub async fn bind(config: ServerConfig) -> Result<Self> {
        // Use shorter idle timeout for bootstrap mode (faster reconnection)
        let idle_timeout = if config.bootstrap_mode {
            Duration::from_millis(BOOTSTRAP_IDLE_TIMEOUT_MS)
        } else {
            IDLE_TIMEOUT
        };

        let listener_config = ListenerConfig {
            cert_pem: config.cert_pem.clone(),
            key_pem: config.key_pem.clone(),
            idle_timeout,
            ticket_key: None,
        };

        let acceptor = QuicAcceptor::bind(config.bind_addr, listener_config).await?;
        let local_addr = acceptor.local_addr();
        let registry = Arc::new(ConnectionRegistry::new(config.conn_config.clone()));

        Ok(Self {
            acceptor,
            local_addr,
            registry,
            config,
            authorizer: None,
        })
    }

    /// Create a new listener with an existing UDP socket.
    ///
    /// This is useful for bootstrap mode where the socket is pre-created.
    /// Note: This is only supported with the quiche backend.
    #[cfg(feature = "quiche-backend")]
    pub async fn with_socket(
        socket: Arc<tokio::net::UdpSocket>,
        config: ServerConfig,
    ) -> Result<Self> {
        // Use shorter idle timeout for bootstrap mode (faster reconnection)
        let idle_timeout = if config.bootstrap_mode {
            Duration::from_millis(BOOTSTRAP_IDLE_TIMEOUT_MS)
        } else {
            IDLE_TIMEOUT
        };

        let listener_config = ListenerConfig {
            cert_pem: config.cert_pem.clone(),
            key_pem: config.key_pem.clone(),
            idle_timeout,
            ticket_key: None,
        };

        let acceptor = QuicAcceptor::with_socket(socket, listener_config).await?;
        let local_addr = acceptor.local_addr();
        let registry = Arc::new(ConnectionRegistry::new(config.conn_config.clone()));

        Ok(Self {
            acceptor,
            local_addr,
            registry,
            config,
            authorizer: None,
        })
    }

    /// Set the session authorizer (for bootstrap mode).
    pub fn with_authorizer(mut self, authorizer: Arc<SessionAuthorizer>) -> Self {
        self.authorizer = Some(authorizer);
        self
    }

    /// Get the local address this listener is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Get a reference to the connection registry.
    pub fn registry(&self) -> &Arc<ConnectionRegistry> {
        &self.registry
    }

    /// Run the server accept loop.
    ///
    /// If `single_session` is true, the server will exit after all sessions
    /// from the first connection have ended (used for bootstrap mode).
    pub async fn run(self, single_session: bool) -> Result<()> {
        // Log the idle timeout (configured at bind time via ServerConfig.bootstrap_mode)
        let idle_timeout_ms = if self.config.bootstrap_mode {
            BOOTSTRAP_IDLE_TIMEOUT_MS
        } else {
            IDLE_TIMEOUT.as_millis() as u64
        };

        if single_session {
            info!(
                addr = %self.local_addr,
                idle_timeout_ms,
                "Bootstrap mode server starting"
            );
        } else {
            info!(
                addr = %self.local_addr,
                idle_timeout_ms,
                "Server starting"
            );
        }

        self.accept_loop(single_session).await
    }

    /// Main accept loop for incoming connections.
    async fn accept_loop(mut self, single_session: bool) -> Result<()> {
        // Track peak session count for bootstrap mode exit condition
        let mut peak_session_count: usize = 0;

        loop {
            // Get current session count (non-blocking via cached value)
            let current_count = self.registry.session_count_cached();
            if current_count > peak_session_count {
                peak_session_count = current_count;
            }

            // Check exit condition for single session mode:
            // Exit when we've had at least one session and now have zero
            if single_session && peak_session_count > 0 && current_count == 0 {
                info!("Session expired, exiting bootstrap mode");
                self.registry.shutdown().await;
                return Ok(());
            }

            // Wait for either a connection or session count change
            let accept_result = tokio::select! {
                biased;

                // Wait for incoming connection
                result = self.acceptor.accept() => result,

                // Wait for session count to change (only in single_session mode after peak > 0)
                _ = async {
                    if single_session && peak_session_count > 0 {
                        self.registry.wait_session_count_change().await
                    } else {
                        // Never complete if not waiting for session changes
                        std::future::pending::<usize>().await
                    }
                } => {
                    // Session count changed - loop back to check exit condition
                    continue;
                }
            };

            match accept_result {
                Ok((quic_conn, peer_addr)) => {
                    let session_config = self.config.session_config.clone();
                    let conn_config = self.config.conn_config.clone();
                    let authorizer_clone = self.authorizer.clone();

                    if single_session {
                        // In bootstrap mode, handle synchronously so the handler
                        // has exclusive access. The main loop will resume after
                        // the handler returns (on disconnect) to accept reconnection attempts.
                        let result = handle_connection_abstracted(
                            quic_conn,
                            peer_addr,
                            self.local_addr,
                            session_config,
                            conn_config,
                            authorizer_clone,
                            &self.registry,
                        )
                        .await;

                        if let Err(e) = &result {
                            error!(error = %e, "Connection handler error");
                        }

                        // Update peak_session_count after handler completes
                        let count = self.registry.session_count().await;
                        if count > peak_session_count {
                            peak_session_count = count;
                        }

                        info!(
                            sessions = count,
                            peak = peak_session_count,
                            "Connection handler finished, checking for reconnection"
                        );
                    } else {
                        // Normal mode: spawn handler task
                        let registry_clone = Arc::clone(&self.registry);
                        let local_addr = self.local_addr;
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection_abstracted(
                                quic_conn,
                                peer_addr,
                                local_addr,
                                session_config,
                                conn_config,
                                authorizer_clone,
                                &registry_clone,
                            )
                            .await
                            {
                                error!(error = %e, "Connection handler error");
                            }
                        });
                    }
                }
                Err(e) => {
                    // Log error and continue accepting
                    debug!(error = %e, "Accept error");
                }
            }
        }
    }
}

// =============================================================================
// Connection Handler
// =============================================================================

use tokio::sync::mpsc;
use tracing::warn;

/// Handle an established QUIC connection (backend-agnostic).
async fn handle_connection_abstracted(
    quic: QuicConnection,
    remote_addr: SocketAddr,
    _local_addr: SocketAddr,
    session_config: SessionConfig,
    conn_config: ConnectionConfig,
    authorizer: Option<Arc<SessionAuthorizer>>,
    registry: &ConnectionRegistry,
) -> Result<()> {
    info!(addr = %remote_addr, "Connection established");

    // Create pending session and validate
    let pending = PendingSession::new(quic, authorizer, session_config).await?;

    // Accept the session with registry support
    let (handler, shutdown_rx) = pending.accept_with_registry(conn_config, registry).await?;

    // Run the channel model session loop
    run_session_loop(handler, shutdown_rx).await
}

/// Why the session loop exited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionExitReason {
    /// Client explicitly requested shutdown - close everything.
    ClientShutdown,
    /// Registry/server shutdown - close everything.
    RegistryShutdown,
    /// Connection lost (timeout, error, etc.) - keep PTY alive for reconnection.
    ConnectionLost,
}

/// Run the channel model session loop.
///
/// For mosh-style persistence:
/// - Connection loss -> detach (keep PTY alive for reconnection)
/// - Client shutdown request -> shutdown (close PTY)
/// - Registry shutdown -> shutdown (close PTY)
async fn run_session_loop(
    handler: Arc<ConnectionHandler>,
    mut shutdown_rx: mpsc::Receiver<()>,
) -> Result<()> {
    let remote_addr = handler.remote_addr().await;
    let rtt = handler.rtt().await;
    info!(
        session_id = ?handler.session_id(),
        addr = %remote_addr,
        rtt = ?rtt,
        "Channel model session started"
    );

    let quic = handler.quic().await;
    let handler_clone = handler.clone();

    // Spawn stream acceptor task
    let accept_handler = handler.clone();
    let accept_task = tokio::spawn(async move {
        loop {
            match quic.accept_stream().await {
                Ok((stream_type, stream)) => {
                    let h = accept_handler.clone();
                    tokio::spawn(async move {
                        if let Err(e) = h.handle_incoming_stream(stream_type, stream).await {
                            warn!(error = %e, "Failed to handle incoming stream");
                        }
                    });
                }
                Err(Error::ConnectionClosed) => break,
                Err(e) => {
                    warn!(error = %e, "Failed to accept stream");
                    break;
                }
            }
        }
    });

    // Track why we exit the loop (default to ConnectionLost since that's most common)
    #[allow(unused_assignments)]
    let mut exit_reason = SessionExitReason::ConnectionLost;

    // Main control message loop
    loop {
        tokio::select! {
            biased;

            // Handle shutdown signal from registry
            _ = shutdown_rx.recv() => {
                debug!("Shutdown signal received");
                exit_reason = SessionExitReason::RegistryShutdown;
                break;
            }

            // Handle control messages
            msg = handler_clone.recv_control() => {
                match msg {
                    Ok(Message::ChannelOpen(payload)) => {
                        if let Err(e) = handler_clone.handle_channel_open(payload).await {
                            error!(error = %e, "Failed to handle ChannelOpen");
                        }
                    }
                    Ok(Message::ChannelClose(payload)) => {
                        if let Err(e) = handler_clone.handle_channel_close(payload).await {
                            error!(error = %e, "Failed to handle ChannelClose");
                        }
                    }
                    Ok(Message::ChannelAccept(payload)) => {
                        if let Err(e) = handler_clone.handle_channel_accept(payload).await {
                            error!(error = %e, "Failed to handle ChannelAccept");
                        }
                    }
                    Ok(Message::ChannelReject(payload)) => {
                        if let Err(e) = handler_clone.handle_channel_reject(payload).await {
                            error!(error = %e, "Failed to handle ChannelReject");
                        }
                    }
                    Ok(Message::GlobalRequest(payload)) => {
                        if let Err(e) = handler_clone.handle_global_request(payload).await {
                            error!(error = %e, "Failed to handle GlobalRequest");
                        }
                    }
                    Ok(Message::Resize(payload)) => {
                        if let Err(e) = handler_clone.handle_resize(payload).await {
                            warn!(error = %e, "Failed to handle Resize");
                        }
                    }
                    Ok(Message::StateAck(payload)) => {
                        if let Err(e) = handler_clone.handle_state_ack(payload).await {
                            warn!(error = %e, "Failed to handle StateAck");
                        }
                    }
                    Ok(Message::Heartbeat(payload)) => {
                        // Echo heartbeat immediately for RTT measurement
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| (d.as_millis() % 65536) as u16)
                            .unwrap_or(0);
                        let reply = Message::Heartbeat(HeartbeatPayload::reply(now_ms, payload.timestamp, payload.seq));
                        if let Err(e) = handler_clone.send_control(&reply).await {
                            warn!(error = %e, "Failed to send heartbeat reply");
                        }
                    }
                    Ok(Message::Shutdown(payload)) => {
                        info!(reason = ?payload.reason, "Client requested shutdown");
                        exit_reason = SessionExitReason::ClientShutdown;
                        break;
                    }
                    Ok(other) => {
                        warn!(msg = ?other, "Unexpected control message");
                    }
                    Err(Error::ConnectionClosed) => {
                        info!("Connection lost (will keep PTY alive for reconnection)");
                        exit_reason = SessionExitReason::ConnectionLost;
                        break;
                    }
                    Err(e) => {
                        warn!(error = %e, "Control stream error (will keep PTY alive for reconnection)");
                        exit_reason = SessionExitReason::ConnectionLost;
                        break;
                    }
                }
            }
        }
    }

    // Cleanup - only shutdown on explicit request, not on connection loss
    accept_task.abort();

    match exit_reason {
        SessionExitReason::ConnectionLost => {
            // Mosh-style: keep PTY alive for reconnection
            // Don't shutdown - the session in the registry still holds a reference
            // to the handler, keeping the PTY alive
            info!(
                session_id = ?handler.session_id(),
                "Session detached (PTY kept alive for reconnection)"
            );
        }
        SessionExitReason::ClientShutdown | SessionExitReason::RegistryShutdown => {
            // Explicit shutdown: close everything
            info!(
                session_id = ?handler.session_id(),
                reason = ?exit_reason,
                "Session ended (shutting down PTY)"
            );
            handler.shutdown().await;
        }
    }

    Ok(())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_config() {
        let config = ServerConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            cert_pem: vec![],
            key_pem: vec![],
            session_config: SessionConfig::default(),
            conn_config: ConnectionConfig::default(),
            bootstrap_mode: false,
        };

        assert_eq!(config.bind_addr.ip().to_string(), "127.0.0.1");
        assert!(!config.bootstrap_mode);
    }

    #[test]
    fn test_timeout_constants() {
        assert!(BOOTSTRAP_IDLE_TIMEOUT_MS < IDLE_TIMEOUT.as_millis() as u64);
        assert_eq!(BOOTSTRAP_IDLE_TIMEOUT_MS, 5_000);
        assert_eq!(IDLE_TIMEOUT.as_secs(), 30);
    }
}
