//! Server session handling.
//!
//! Manages client sessions using the SSH-style channel model:
//! - Session key validation
//! - Channel-based multiplexing (multiple terminals, file transfers, forwards per connection)
//! - Reconnection support

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use qsh_core::ConnectMode;
use qsh_core::constants::{DEFAULT_IDLE_TIMEOUT_SECS, DEFAULT_MAX_FORWARDS, SESSION_KEY_LEN};
use qsh_core::error::{Error, Result};
use qsh_core::protocol::{Capabilities, HelloAckPayload, HelloPayload, Message, SessionId};
use qsh_core::transport::{Connection, QuicConnection, QuicStream, StreamPair, StreamType};
use rand::Rng;

use crate::connection::{ConnectionConfig, ConnectionHandler, ShutdownReason};

/// Server session configuration.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Server capabilities to advertise.
    pub capabilities: Capabilities,
    /// Session timeout for idle connections.
    pub idle_timeout: Duration,
    /// Maximum number of port forwards.
    pub max_forwards: u16,
    /// Allow remote forwards.
    pub allow_remote_forwards: bool,
    /// Connect mode (initiate or respond).
    pub connect_mode: ConnectMode,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            capabilities: Capabilities {
                predictive_echo: true,
                compression: false,
                max_forwards: DEFAULT_MAX_FORWARDS,
                tunnel: false,
            },
            idle_timeout: Duration::from_secs(DEFAULT_IDLE_TIMEOUT_SECS),
            max_forwards: DEFAULT_MAX_FORWARDS,
            allow_remote_forwards: false,
            connect_mode: ConnectMode::Respond,
        }
    }
}

/// Controls which session keys may attach.
#[derive(Debug, Default)]
pub struct SessionAuthorizer {
    allowed: RwLock<HashSet<[u8; SESSION_KEY_LEN]>>,
}

impl SessionAuthorizer {
    /// Create a new authorizer.
    pub fn new() -> Self {
        Self {
            allowed: RwLock::new(HashSet::new()),
        }
    }

    /// Allow a specific session key.
    pub async fn allow(&self, key: [u8; SESSION_KEY_LEN]) {
        self.allowed.write().await.insert(key);
    }

    /// Generate and allow a new random session key.
    pub async fn allow_random(&self) -> [u8; SESSION_KEY_LEN] {
        let mut key = [0u8; SESSION_KEY_LEN];
        rand::thread_rng().fill(&mut key);
        self.allow(key).await;
        key
    }

    /// Check whether a key is allowed.
    pub async fn is_allowed(&self, key: &[u8; SESSION_KEY_LEN]) -> bool {
        self.allowed.read().await.contains(key)
    }
}

/// Pending session handshake (Hello received, not yet Acked).
pub struct PendingSession {
    quic: QuicConnection,
    control: QuicStream,
    hello: HelloPayload,
    config: SessionConfig,
}

impl PendingSession {
    /// Receive Hello and validate the incoming connection.
    pub async fn new(
        quic: QuicConnection,
        authorizer: Option<Arc<SessionAuthorizer>>,
        config: SessionConfig,
    ) -> Result<Self> {
        info!(addr = %quic.remote_addr(), "New connection");

        // Accept control stream
        let (stream_type, mut control) = quic.accept_stream().await?;
        if !matches!(stream_type, StreamType::Control) {
            return Err(Error::Protocol {
                message: format!("expected control stream, got {:?}", stream_type),
            });
        }

        // Receive Hello
        let hello = match control.recv().await? {
            Message::Hello(h) => h,
            other => {
                return Err(Error::Protocol {
                    message: format!("expected Hello, got {:?}", other),
                });
            }
        };

        debug!(
            protocol_version = hello.protocol_version,
            client_nonce = hello.client_nonce,
            "Received Hello"
        );

        // Validate protocol version
        if hello.protocol_version != 1 {
            let ack = HelloAckPayload {
                protocol_version: 1,
                accepted: false,
                reject_reason: Some(format!(
                    "unsupported protocol version: {}",
                    hello.protocol_version
                )),
                capabilities: config.capabilities.clone(),
                session_id: SessionId::new(),
                server_nonce: 0,
                zero_rtt_available: false,
                existing_channels: vec![],
            };
            control.send(&Message::HelloAck(ack)).await?;
            return Err(Error::Protocol {
                message: "unsupported protocol version".to_string(),
            });
        }

        // Validate session key if required
        if let Some(auth) = &authorizer
            && !auth.is_allowed(&hello.session_key).await
        {
            let ack = HelloAckPayload {
                protocol_version: 1,
                accepted: false,
                reject_reason: Some("invalid session key".to_string()),
                capabilities: config.capabilities.clone(),
                session_id: SessionId::new(),
                server_nonce: 0,
                zero_rtt_available: false,
                existing_channels: vec![],
            };
            control.send(&Message::HelloAck(ack)).await?;
            return Err(Error::AuthenticationFailed);
        }

        Ok(Self {
            quic,
            control,
            hello,
            config,
        })
    }

    /// Get the received Hello payload.
    pub fn hello(&self) -> &HelloPayload {
        &self.hello
    }

    /// Reject the session with a reason.
    pub async fn reject(mut self, reason: String) -> Result<()> {
        let ack = HelloAckPayload {
            protocol_version: 1,
            accepted: false,
            reject_reason: Some(reason),
            capabilities: self.config.capabilities.clone(),
            session_id: SessionId::new(),
            server_nonce: 0,
            zero_rtt_available: false,
            existing_channels: vec![],
        };
        self.control.send(&Message::HelloAck(ack)).await?;
        Ok(())
    }

    /// Finalize the handshake and build a [`ConnectionHandler`] for the channel model.
    ///
    /// This is the SSH-style channel model where channels are created dynamically
    /// after the connection is established, rather than having a single terminal
    /// session per connection.
    pub async fn accept_channel_model(
        mut self,
        conn_config: ConnectionConfig,
    ) -> Result<(
        Arc<ConnectionHandler>,
        tokio::sync::mpsc::Receiver<ShutdownReason>,
    )> {
        let session_id = SessionId::new();

        // Send HelloAck (channels created separately via ChannelOpen)
        let ack = HelloAckPayload {
            protocol_version: 1,
            accepted: true,
            reject_reason: None,
            capabilities: self.config.capabilities.clone(),
            session_id,
            server_nonce: rand::random(),
            zero_rtt_available: true,
            existing_channels: vec![],
        };
        self.control.send(&Message::HelloAck(ack)).await?;

        info!(
            session_id = ?session_id,
            addr = %self.quic.remote_addr(),
            "Connection established (channel model)"
        );

        // Create the connection handler
        let (handler, shutdown_rx) =
            ConnectionHandler::new(self.quic, self.control, session_id, conn_config);

        Ok((handler, shutdown_rx))
    }

    /// Finalize handshake with registry support (for session persistence).
    ///
    /// This version integrates with `ConnectionRegistry` to support session
    /// resumption across disconnects. If the client sends `resume_session`,
    /// the existing session is looked up and reattached.
    ///
    /// For mosh-style persistence: if the session has an existing handler with
    /// channels (PTYs), we reuse it by updating its QUIC connection.
    pub async fn accept_with_registry(
        mut self,
        conn_config: ConnectionConfig,
        registry: &crate::registry::ConnectionRegistry,
    ) -> Result<(
        Arc<ConnectionHandler>,
        tokio::sync::mpsc::Receiver<ShutdownReason>,
    )> {
        let client_addr = self.quic.remote_addr();

        // Check if this is a session resume attempt
        if let Some(resume_id) = self.hello.resume_session {
            info!(
                session_id = ?resume_id,
                addr = %client_addr,
                "Session resume requested"
            );

            // Look up existing session by ID
            if let Some(session_guard) = registry
                .get_session_for_resume(resume_id, &self.hello.session_key)
                .await
            {
                // Validate connect_mode consistency
                if session_guard.session.connect_mode != self.config.connect_mode {
                    let stored_mode = session_guard.session.connect_mode;
                    let requested_mode = self.config.connect_mode;
                    warn!(
                        session_id = ?resume_id,
                        stored_mode = ?stored_mode,
                        requested_mode = ?requested_mode,
                        "Session resume rejected: connect_mode mismatch"
                    );
                    let reject_message = format!(
                        "connect_mode mismatch: session was established with {:?}, but reconnection attempted with {:?}",
                        stored_mode,
                        requested_mode
                    );
                    self.reject(reject_message).await?;
                    return Err(Error::Protocol {
                        message: "connect_mode mismatch on session resume".to_string(),
                    });
                }

                // Resume successful - reuse the session ID
                let session_id = session_guard.session.session_id;

                // Check if there's an existing handler we can reuse (mosh-style)
                let existing_handler = session_guard.session.handler.lock().await.clone();

                if let Some(handler) = existing_handler {
                    // Mosh-style: reuse existing handler with its PTYs
                    let channel_count = handler.channel_count().await;
                    info!(
                        session_id = ?session_id,
                        addr = %client_addr,
                        channels = channel_count,
                        "Reusing existing handler with channels (mosh-style resume)"
                    );

                    // Get existing channel info BEFORE reconnecting (to get current state)
                    let existing_channels = handler.get_existing_channels().await;

                    // Update the handler's QUIC connection to the new one
                    let (shutdown_tx, shutdown_rx) =
                        tokio::sync::mpsc::channel::<ShutdownReason>(1);
                    handler
                        .reconnect(self.quic, self.control, shutdown_tx)
                        .await;

                    // Send HelloAck with existing session ID and channel info
                    let ack = HelloAckPayload {
                        protocol_version: 1,
                        accepted: true,
                        reject_reason: None,
                        capabilities: self.config.capabilities.clone(),
                        session_id,
                        server_nonce: rand::random(),
                        zero_rtt_available: true,
                        existing_channels,
                    };
                    // Use the new control stream to send ack
                    handler.send_control(&Message::HelloAck(ack)).await?;

                    session_guard.session.touch().await;

                    return Ok((handler, shutdown_rx));
                }

                // No existing handler - create new one
                info!(
                    session_id = ?session_id,
                    addr = %client_addr,
                    "Session resumed (no existing handler, creating new)"
                );

                // Send HelloAck with the existing session ID
                let ack = HelloAckPayload {
                    protocol_version: 1,
                    accepted: true,
                    reject_reason: None,
                    capabilities: self.config.capabilities.clone(),
                    session_id,
                    server_nonce: rand::random(),
                    zero_rtt_available: true,
                    existing_channels: vec![],
                };
                self.control.send(&Message::HelloAck(ack)).await?;

                // Create new connection handler with existing session ID
                let (handler, shutdown_rx) =
                    ConnectionHandler::new(self.quic, self.control, session_id, conn_config);

                // Attach new handler to session
                session_guard
                    .session
                    .attach(Arc::clone(&handler), client_addr)
                    .await;

                return Ok((handler, shutdown_rx));
            } else {
                // Session not found or expired - fall through to create new session
                info!(
                    session_id = ?resume_id,
                    "Session resume failed: session not found or expired"
                );
            }
        }

        // Create new session with the configured connect_mode
        let session_guard = registry
            .get_or_create_session(self.hello.session_key, client_addr, self.config.connect_mode)
            .await?;
        let session_id = session_guard.session.session_id;

        // Send HelloAck
        let ack = HelloAckPayload {
            protocol_version: 1,
            accepted: true,
            reject_reason: None,
            capabilities: self.config.capabilities.clone(),
            session_id,
            server_nonce: rand::random(),
            zero_rtt_available: true,
            existing_channels: vec![],
        };
        self.control.send(&Message::HelloAck(ack)).await?;

        info!(
            session_id = ?session_id,
            addr = %client_addr,
            "New connection established (channel model with registry)"
        );

        // Create the connection handler
        let (handler, shutdown_rx) =
            ConnectionHandler::new(self.quic, self.control, session_id, conn_config);

        // Attach handler to session
        session_guard
            .session
            .attach(Arc::clone(&handler), client_addr)
            .await;

        debug!(
            session_id = ?session_id,
            session_key_prefix = ?&session_guard.session.session_key[..4],
            "Session attached to handler"
        );

        Ok((handler, shutdown_rx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_config_default() {
        let config = SessionConfig::default();
        assert!(config.capabilities.predictive_echo);
        assert_eq!(config.max_forwards, DEFAULT_MAX_FORWARDS);
    }

    #[tokio::test]
    async fn session_authorizer_allows_known_keys() {
        let auth = SessionAuthorizer::new();
        let key = [0xAA; SESSION_KEY_LEN];
        auth.allow(key).await;
        assert!(auth.is_allowed(&key).await);

        let unknown = [0xBB; SESSION_KEY_LEN];
        assert!(!auth.is_allowed(&unknown).await);
    }
}
