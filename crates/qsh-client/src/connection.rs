//! Client connection management.
//!
//! Handles the full connection lifecycle:
//! 1. SSH bootstrap to discover QUIC endpoint
//! 2. QUIC connection establishment with cert pinning
//! 3. Session handshake (Hello/HelloAck)
//! 4. Terminal I/O with prediction
//! 5. Reconnection on network change

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::{ClientConfig, Endpoint};
use tracing::{debug, info};

use qsh_core::error::{Error, Result};
use qsh_core::protocol::{
    Capabilities, HelloPayload, Message, ResizePayload, ShutdownPayload, ShutdownReason, TermSize,
    TerminalInputPayload,
};
use qsh_core::session::{InputTracker, SessionState};
use qsh_core::transport::{
    Connection, QuicConnection, QuicStream, StreamPair, client_crypto_config,
};

use crate::prediction::PredictionEngine;

/// Client connection configuration.
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    /// Server address for QUIC connection.
    pub server_addr: SocketAddr,
    /// Session key from bootstrap.
    pub session_key: [u8; 32],
    /// Expected server certificate hash (optional, for pinning).
    pub cert_hash: Option<Vec<u8>>,
    /// Terminal size.
    pub term_size: TermSize,
    /// TERM environment variable.
    pub term_type: String,
    /// Enable predictive echo.
    pub predictive_echo: bool,
    /// Connection timeout.
    pub connect_timeout: Duration,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            server_addr: "127.0.0.1:4500".parse().unwrap(),
            session_key: [0; 32],
            cert_hash: None,
            term_size: TermSize { cols: 80, rows: 24 },
            term_type: "xterm-256color".to_string(),
            predictive_echo: true,
            connect_timeout: Duration::from_secs(10),
        }
    }
}

/// Active client connection.
pub struct ClientConnection {
    /// QUIC connection wrapper (shared for forwarders).
    quic: Arc<QuicConnection>,
    /// Control stream for protocol messages.
    control: QuicStream,
    /// Session state.
    session: SessionState,
    /// Input sequence tracker.
    input_tracker: InputTracker,
    /// Prediction engine for local echo.
    #[allow(dead_code)] // Will be used when terminal I/O is implemented
    prediction: PredictionEngine,
    /// Server capabilities.
    server_caps: Capabilities,
}

impl ClientConnection {
    /// Establish a new connection to the server.
    pub async fn connect(config: ConnectionConfig) -> Result<Self> {
        info!(addr = %config.server_addr, "Connecting to server");

        // Create QUIC endpoint
        let mut endpoint =
            Endpoint::client("0.0.0.0:0".parse().unwrap()).map_err(|e| Error::Transport {
                message: format!("failed to create QUIC endpoint: {}", e),
            })?;

        // Configure TLS with optional cert pinning
        let crypto = client_crypto_config(config.cert_hash.as_deref())?;
        let client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto).map_err(|e| {
                Error::Transport {
                    message: format!("failed to create QUIC config: {}", e),
                }
            })?,
        ));
        endpoint.set_default_client_config(client_config);

        // Connect to server
        let connecting = endpoint
            .connect(config.server_addr, "qsh-server")
            .map_err(|e| Error::Transport {
                message: format!("failed to initiate connection: {}", e),
            })?;

        let conn = tokio::time::timeout(config.connect_timeout, connecting)
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|e| Error::Transport {
                message: format!("connection failed: {}", e),
            })?;

        info!("QUIC connection established");
        let quic = Arc::new(QuicConnection::new(conn));

        // Open control stream (client-initiated bidi 0)
        let mut control = quic
            .open_stream(qsh_core::transport::StreamType::Control)
            .await?;

        // Send Hello
        let hello = HelloPayload {
            protocol_version: 1,
            session_key: config.session_key,
            client_nonce: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
            capabilities: Capabilities {
                predictive_echo: config.predictive_echo,
                compression: false,
                max_forwards: 10,
                tunnel: false,
            },
            term_size: config.term_size,
            term_type: config.term_type.clone(),
            last_generation: 0,
            last_input_seq: 0,
        };

        control.send(&Message::Hello(hello)).await?;
        debug!("Sent Hello");

        // Wait for HelloAck
        let hello_ack = match control.recv().await? {
            Message::HelloAck(ack) => ack,
            other => {
                return Err(Error::Protocol {
                    message: format!("expected HelloAck, got {:?}", other),
                });
            }
        };

        if !hello_ack.accepted {
            return Err(Error::AuthenticationFailed);
        }

        info!(
            zero_rtt = hello_ack.zero_rtt_available,
            "Session established"
        );

        let session = SessionState::new(config.session_key);
        let input_tracker = InputTracker::new();
        let prediction = PredictionEngine::new();

        Ok(Self {
            quic,
            control,
            session,
            input_tracker,
            prediction,
            server_caps: hello_ack.capabilities,
        })
    }

    /// Get the server capabilities.
    pub fn server_capabilities(&self) -> &Capabilities {
        &self.server_caps
    }

    /// Get the session state.
    pub fn session(&self) -> &SessionState {
        &self.session
    }

    /// Get the current RTT estimate.
    pub fn rtt(&self) -> Duration {
        self.quic.rtt()
    }

    /// Get a shared reference to the underlying QUIC connection.
    ///
    /// Used by forwarders to open additional streams.
    pub fn quic_connection(&self) -> Arc<QuicConnection> {
        Arc::clone(&self.quic)
    }

    /// Send terminal input to the server.
    pub async fn send_input(&mut self, data: &[u8]) -> Result<()> {
        // Track for reliable delivery
        let predictable = self.server_caps.predictive_echo;
        let seq = self.input_tracker.push(data.to_vec(), predictable);

        let msg = Message::TerminalInput(TerminalInputPayload {
            sequence: seq,
            data: data.to_vec(),
            predictable,
        });

        self.control.send(&msg).await
    }

    /// Send a ping for latency measurement.
    pub async fn ping(&mut self) -> Result<Duration> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;

        self.control.send(&Message::Ping(timestamp)).await?;

        // Wait for Pong
        let pong_time = match self.control.recv().await? {
            Message::Pong(ts) => ts,
            other => {
                return Err(Error::Protocol {
                    message: format!("expected Pong, got {:?}", other),
                });
            }
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;

        Ok(Duration::from_micros(now - pong_time))
    }

    /// Receive a message from the server.
    pub async fn recv(&mut self) -> Result<Message> {
        self.control.recv().await
    }

    /// Send a resize notification to the server.
    pub async fn send_resize(&mut self, cols: u16, rows: u16) -> Result<()> {
        self.control
            .send(&Message::Resize(ResizePayload { cols, rows }))
            .await
    }

    /// Close the connection gracefully.
    pub async fn close(mut self) -> Result<()> {
        self.control
            .send(&Message::Shutdown(ShutdownPayload {
                reason: ShutdownReason::UserRequested,
                message: Some("client disconnect".to_string()),
            }))
            .await?;

        self.control.close();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_config_default() {
        let config = ConnectionConfig::default();
        assert_eq!(config.term_size.cols, 80);
        assert_eq!(config.term_size.rows, 24);
        assert!(config.predictive_echo);
    }
}
