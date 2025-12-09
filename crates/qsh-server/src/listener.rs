//! QUIC server listener with improved connection handling.
//!
//! This module provides `QshListener` which wraps the quiche-based server with:
//! - IP_RECVERR for fast disconnect detection on Linux
//! - Reduced idle timeout for faster reconnection in bootstrap mode
//! - Clean separation between listener and connection handling

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use qsh_core::error::{Error, Result};
use qsh_core::protocol::{HeartbeatPayload, Message};
use qsh_core::transport::{enable_error_queue, server_config, Connection, QuicConnection};

use crate::connection::{ConnectionConfig, ConnectionHandler};
use crate::registry::ConnectionRegistry;
use crate::session::SessionConfig;
use crate::{PendingSession, SessionAuthorizer};

// =============================================================================
// Constants
// =============================================================================

/// Default idle timeout for normal server mode (30 seconds).
const DEFAULT_IDLE_TIMEOUT_MS: u64 = 30_000;

/// Reduced idle timeout for bootstrap mode (5 seconds).
/// This allows faster detection of client disconnection and quicker reconnection.
const BOOTSTRAP_IDLE_TIMEOUT_MS: u64 = 5_000;

/// Packet receive timeout for the main loop.
const RECV_TIMEOUT_MS: u64 = 50;

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
}

// =============================================================================
// QshListener - Main server listener
// =============================================================================

/// QUIC server listener with improved connection handling.
///
/// Key improvements over the basic quiche server:
/// - IP_RECVERR enabled for immediate ICMP error delivery (Linux)
/// - Configurable idle timeout (reduced in bootstrap mode)
/// - Clean registry-based session management
pub struct QshListener {
    /// UDP socket (shared for packet routing).
    socket: Arc<UdpSocket>,
    /// Local address.
    local_addr: SocketAddr,
    /// quiche configuration.
    quiche_config: quiche::Config,
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
        // Create quiche config with certificates
        let quiche_config = server_config(&config.cert_pem, &config.key_pem)?;

        // Bind UDP socket
        let socket = UdpSocket::bind(config.bind_addr)
            .await
            .map_err(|e| Error::Transport {
                message: format!("failed to bind server: {}", e),
            })?;

        let local_addr = socket.local_addr().map_err(|e| Error::Transport {
            message: format!("failed to get local address: {}", e),
        })?;

        // Enable IP_RECVERR for fast error detection (Linux-specific)
        if let Err(e) = enable_error_queue(&socket) {
            debug!(error = %e, "Failed to enable IP_RECVERR (non-fatal)");
        }

        let socket = Arc::new(socket);
        let registry = Arc::new(ConnectionRegistry::new(config.conn_config.clone()));

        Ok(Self {
            socket,
            local_addr,
            quiche_config,
            registry,
            config,
            authorizer: None,
        })
    }

    /// Create a new listener with an existing UDP socket.
    ///
    /// This is useful for bootstrap mode where the socket is pre-created.
    pub async fn with_socket(socket: Arc<UdpSocket>, config: ServerConfig) -> Result<Self> {
        let quiche_config = server_config(&config.cert_pem, &config.key_pem)?;

        let local_addr = socket.local_addr().map_err(|e| Error::Transport {
            message: format!("failed to get local address: {}", e),
        })?;

        // Enable IP_RECVERR for fast error detection
        if let Err(e) = enable_error_queue(&socket) {
            debug!(error = %e, "Failed to enable IP_RECVERR (non-fatal)");
        }

        let registry = Arc::new(ConnectionRegistry::new(config.conn_config.clone()));

        Ok(Self {
            socket,
            local_addr,
            quiche_config,
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
    pub async fn run(mut self, single_session: bool) -> Result<()> {
        // Adjust idle timeout for bootstrap mode
        if single_session {
            self.quiche_config.set_max_idle_timeout(BOOTSTRAP_IDLE_TIMEOUT_MS);
            info!(
                addr = %self.local_addr,
                idle_timeout_ms = BOOTSTRAP_IDLE_TIMEOUT_MS,
                "Bootstrap mode server starting"
            );
        } else {
            self.quiche_config.set_max_idle_timeout(DEFAULT_IDLE_TIMEOUT_MS);
            info!(
                addr = %self.local_addr,
                idle_timeout_ms = DEFAULT_IDLE_TIMEOUT_MS,
                "Server starting"
            );
        }

        self.accept_loop(single_session).await
    }

    /// Main accept loop for incoming connections.
    async fn accept_loop(mut self, single_session: bool) -> Result<()> {
        let mut buf = [0u8; 65535];
        let mut out = [0u8; 65535];
        let mut connections: HashMap<Vec<u8>, (quiche::Connection, Option<SocketAddr>)> =
            HashMap::new();

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

            // Wait for either a packet or session count change (efficient, no polling)
            let recv_result = tokio::select! {
                biased;

                // Wait for incoming packet
                result = tokio::time::timeout(
                    Duration::from_millis(RECV_TIMEOUT_MS),
                    self.socket.recv_from(&mut buf),
                ) => result,

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

            match recv_result {
                Ok(Ok((len, from))) => {
                    // Parse QUIC header to get connection ID
                    let hdr =
                        match quiche::Header::from_slice(&mut buf[..len], quiche::MAX_CONN_ID_LEN) {
                            Ok(h) => h,
                            Err(e) => {
                                debug!(error = %e, "Failed to parse QUIC header");
                                continue;
                            }
                        };

                    let dcid = hdr.dcid.to_vec();

                    // Look up or create connection
                    let conn_key = if connections.contains_key(&dcid) {
                        dcid.clone()
                    } else if hdr.ty == quiche::Type::Initial {
                        // New connection - generate scid and store
                        let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
                        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut scid);
                        let scid_vec = scid.to_vec();
                        let scid = quiche::ConnectionId::from_vec(scid_vec.clone());

                        let conn = quiche::accept(
                            &scid,
                            None,
                            self.local_addr,
                            from,
                            &mut self.quiche_config,
                        )
                        .map_err(|e| Error::Transport {
                            message: format!("failed to accept connection: {}", e),
                        })?;

                        connections.insert(scid_vec.clone(), (conn, Some(from)));
                        scid_vec
                    } else {
                        // Unknown connection
                        continue;
                    };

                    // Get mutable reference to the connection
                    let Some((conn, _peer)) = connections.get_mut(&conn_key) else {
                        continue;
                    };

                    let recv_info = quiche::RecvInfo {
                        from,
                        to: self.local_addr,
                    };

                    if let Err(e) = conn.recv(&mut buf[..len], recv_info) {
                        if e != quiche::Error::Done {
                            debug!(error = %e, "recv failed");
                        }
                    }

                    // Check if connection is established
                    if conn.is_established() {
                        let conn_id = conn_key;

                        // Take ownership of connection
                        if let Some((conn, peer_addr)) = connections.remove(&conn_id) {
                            let socket_clone = Arc::clone(&self.socket);
                            let session_config = self.config.session_config.clone();
                            let conn_config = self.config.conn_config.clone();
                            let authorizer_clone = self.authorizer.clone();
                            let peer = peer_addr.unwrap_or(from);

                            if single_session {
                                // In bootstrap mode, handle synchronously so the handler
                                // has exclusive access to the socket. The main loop will
                                // resume after the handler returns (on disconnect) to
                                // accept reconnection attempts.
                                let result = handle_connection(
                                    conn,
                                    socket_clone,
                                    peer,
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
                                tokio::spawn(async move {
                                    if let Err(e) = handle_connection(
                                        conn,
                                        socket_clone,
                                        peer,
                                        self.local_addr,
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
                    }
                }
                Ok(Err(e)) => {
                    // Check if this is an ICMP error (from IP_RECVERR)
                    if let Some(errno) = e.raw_os_error() {
                        #[cfg(target_os = "linux")]
                        if errno == libc::ECONNREFUSED
                            || errno == libc::ENETUNREACH
                            || errno == libc::EHOSTUNREACH
                        {
                            debug!(error = %e, "ICMP error received (fast disconnect detection)");
                            continue;
                        }
                    }
                    warn!(error = %e, "Socket recv error");
                }
                Err(_) => {
                    // Timeout, continue
                }
            }

            // Send pending packets for all connections
            let conn_ids: Vec<Vec<u8>> = connections.keys().cloned().collect();
            for conn_id in conn_ids {
                if let Some((conn, _peer)) = connections.get_mut(&conn_id) {
                    loop {
                        match conn.send(&mut out) {
                            Ok((write, send_info)) => {
                                if let Err(e) = self.socket.send_to(&out[..write], send_info.to).await
                                {
                                    debug!(error = %e, "send failed");
                                }
                            }
                            Err(quiche::Error::Done) => break,
                            Err(e) => {
                                debug!(error = %e, "send failed");
                                break;
                            }
                        }
                    }

                    // Remove closed connections
                    if conn.is_closed() {
                        connections.remove(&conn_id);
                    }
                }
            }
        }
    }
}

// =============================================================================
// Connection Handler
// =============================================================================

/// Handle an established QUIC connection.
async fn handle_connection(
    conn: quiche::Connection,
    socket: Arc<UdpSocket>,
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
    session_config: SessionConfig,
    conn_config: ConnectionConfig,
    authorizer: Option<Arc<SessionAuthorizer>>,
    registry: &ConnectionRegistry,
) -> Result<()> {
    info!(addr = %remote_addr, "Connection established");

    // Wrap in QuicConnection
    let quic = QuicConnection::new(conn, socket, remote_addr, local_addr, true);

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
        };

        assert_eq!(config.bind_addr.ip().to_string(), "127.0.0.1");
    }

    #[test]
    fn test_timeout_constants() {
        assert!(BOOTSTRAP_IDLE_TIMEOUT_MS < DEFAULT_IDLE_TIMEOUT_MS);
        assert_eq!(BOOTSTRAP_IDLE_TIMEOUT_MS, 5_000);
        assert_eq!(DEFAULT_IDLE_TIMEOUT_MS, 30_000);
    }
}
