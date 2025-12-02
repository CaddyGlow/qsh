//! Server session handling.
//!
//! Manages client sessions including:
//! - Session key validation
//! - PTY spawning and I/O relay
//! - State tracking and updates
//! - Reconnection handling

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tracing::{debug, info};

use qsh_core::error::{Error, Result};
use qsh_core::protocol::{
    Capabilities, HelloAckPayload, Message, StateDiff, StateUpdatePayload,
    TerminalState as ProtoTermState,
};
use qsh_core::session::SessionState;
use qsh_core::terminal::TerminalParser;
use qsh_core::transport::{Connection, QuicConnection, QuicStream, StreamPair, StreamType};

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

/// An active server session.
pub struct ServerSession {
    /// QUIC connection.
    quic: QuicConnection,
    /// Control stream.
    control: QuicStream,
    /// Session state.
    #[allow(dead_code)] // Will be used for reconnection
    session_state: SessionState,
    /// Terminal parser (owns terminal state).
    parser: Arc<Mutex<TerminalParser>>,
    /// Last confirmed input sequence.
    confirmed_input_seq: u64,
    /// Server configuration.
    #[allow(dead_code)] // Will be used for session management
    config: SessionConfig,
    /// Terminal size (cols, rows).
    term_size: (u16, u16),
}

impl ServerSession {
    /// Accept a new session from an incoming connection.
    pub async fn accept(
        quic: QuicConnection,
        expected_key: Option<[u8; 32]>,
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
            term_type = hello.term_type,
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
                initial_state: None,
                zero_rtt_available: false,
            };
            control.send(&Message::HelloAck(ack)).await?;
            return Err(Error::Protocol {
                message: "unsupported protocol version".to_string(),
            });
        }

        // Validate session key if expected
        if let Some(expected) = expected_key
            && hello.session_key != expected
        {
            let ack = HelloAckPayload {
                protocol_version: 1,
                accepted: false,
                reject_reason: Some("invalid session key".to_string()),
                capabilities: config.capabilities.clone(),
                initial_state: None,
                zero_rtt_available: false,
            };
            control.send(&Message::HelloAck(ack)).await?;
            return Err(Error::AuthenticationFailed);
        }

        // Create terminal parser (owns state)
        let parser = TerminalParser::new(hello.term_size.cols, hello.term_size.rows);

        // Build initial state for client (simplified - just dimensions)
        let initial_state = ProtoTermState {
            generation: 1,
            cols: hello.term_size.cols,
            rows: hello.term_size.rows,
        };

        // Send HelloAck
        let ack = HelloAckPayload {
            protocol_version: 1,
            accepted: true,
            reject_reason: None,
            capabilities: config.capabilities.clone(),
            initial_state: Some(initial_state),
            zero_rtt_available: true,
        };
        control.send(&Message::HelloAck(ack)).await?;

        let session_state = SessionState::new(hello.session_key);

        info!(
            term_size = %format!("{}x{}", hello.term_size.cols, hello.term_size.rows),
            term_type = hello.term_type,
            "Session established"
        );

        Ok(Self {
            quic,
            control,
            session_state,
            parser: Arc::new(Mutex::new(parser)),
            confirmed_input_seq: 0,
            config,
            term_size: (hello.term_size.cols, hello.term_size.rows),
        })
    }

    /// Get the session state.
    pub fn state(&self) -> &SessionState {
        &self.session_state
    }

    /// Get the remote address.
    pub fn remote_addr(&self) -> std::net::SocketAddr {
        self.quic.remote_addr()
    }

    /// Get the terminal size (cols, rows).
    pub fn term_size(&self) -> (u16, u16) {
        self.term_size
    }

    /// Get the current RTT.
    pub fn rtt(&self) -> Duration {
        self.quic.rtt()
    }

    /// Send a state update to the client.
    pub async fn send_state_update(&mut self, data: Vec<u8>, input_seq: u64) -> Result<()> {
        // Parse output through terminal emulator
        let state = {
            let mut parser = self.parser.lock().await;
            parser.process(&data);
            parser.state().clone()
        };

        self.confirmed_input_seq = input_seq;

        let update = StateUpdatePayload {
            diff: StateDiff::Full(ProtoTermState {
                generation: state.generation,
                cols: state.primary.cols(),
                rows: state.primary.rows(),
            }),
            confirmed_input_seq: self.confirmed_input_seq,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_micros() as u64,
        };

        self.control.send(&Message::StateUpdate(update)).await
    }

    /// Handle a terminal input message.
    pub async fn handle_input(&mut self, data: &[u8]) -> Result<()> {
        // In a full implementation, this would write to the PTY
        debug!(len = data.len(), "Received terminal input");
        Ok(())
    }

    /// Send a ping response.
    pub async fn send_pong(&mut self, timestamp: u64) -> Result<()> {
        self.control.send(&Message::Pong(timestamp)).await
    }

    /// Process incoming control messages.
    pub async fn process_control(&mut self) -> Result<Option<Message>> {
        match self.control.recv().await {
            Ok(msg) => Ok(Some(msg)),
            Err(Error::ConnectionClosed) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Close the session gracefully.
    pub fn close(mut self) {
        self.control.close();
        info!(addr = %self.quic.remote_addr(), "Session closed");
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
}
