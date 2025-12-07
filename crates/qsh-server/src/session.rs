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
use tracing::{debug, info};

use qsh_core::constants::SESSION_KEY_LEN;
use qsh_core::error::{Error, Result};
use qsh_core::protocol::{
    Capabilities, HelloAckPayload, HelloPayload, Message, SessionId,
};
use qsh_core::transport::{Connection, QuicConnection, QuicStream, StreamPair, StreamType};
use rand::Rng;

use crate::connection::{ConnectionConfig, ConnectionHandler};

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
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            capabilities: Capabilities {
                predictive_echo: true,
                compression: false,
                max_forwards: 10,
                tunnel: false,
            },
            idle_timeout: Duration::from_secs(300),
            max_forwards: 10,
            allow_remote_forwards: false,
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
    ) -> Result<(Arc<ConnectionHandler>, tokio::sync::mpsc::Receiver<()>)> {
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
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_config_default() {
        let config = SessionConfig::default();
        assert!(config.capabilities.predictive_echo);
        assert_eq!(config.max_forwards, 10);
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
