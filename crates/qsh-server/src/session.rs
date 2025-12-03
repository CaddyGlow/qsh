//! Server session handling.
//!
//! Manages client sessions including:
//! - Session key validation
//! - PTY spawning and I/O relay
//! - State tracking and updates
//! - Reconnection handling

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::sync::RwLock;
use tracing::{debug, info};

use qsh_core::error::{Error, Result};
use qsh_core::protocol::{
    Capabilities, HelloAckPayload, HelloPayload, Message, ShutdownPayload, ShutdownReason,
    StateDiff, StateUpdatePayload, TerminalOutputPayload,
};
use qsh_core::constants::SESSION_KEY_LEN;
use qsh_core::session::SessionState;
use qsh_core::terminal::{TerminalParser, TerminalState};
use qsh_core::transport::{Connection, QuicConnection, QuicStream, StreamPair, StreamType};
use rand::Rng;

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
    /// QUIC connection (shared for forward handling).
    quic: Arc<QuicConnection>,
    /// Control stream.
    control: QuicStream,
    /// Terminal output stream (server -> client).
    terminal_out: QuicStream,
    /// Session state.
    #[allow(dead_code)] // Will be used for reconnection
    session_state: SessionState,
    /// Terminal parser (owns terminal state).
    parser: Arc<Mutex<TerminalParser>>,
    /// Last confirmed input sequence.
    confirmed_input_seq: u64,
    /// Server configuration.
    config: SessionConfig,
    /// Terminal size (cols, rows).
    term_size: (u16, u16),
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

        // Validate session key if required
        if let Some(auth) = &authorizer
            && !auth.is_allowed(&hello.session_key).await
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
            initial_state: None,
            zero_rtt_available: false,
        };
        self.control.send(&Message::HelloAck(ack)).await?;
        Ok(())
    }

    /// Finalize the handshake and build a [`ServerSession`].
    pub async fn accept(
        mut self,
        parser: Arc<Mutex<TerminalParser>>,
        mut initial_state: TerminalState,
    ) -> Result<ServerSession> {
        initial_state.generation = initial_state.generation.max(1);

        // Send HelloAck
        let ack = HelloAckPayload {
            protocol_version: 1,
            accepted: true,
            reject_reason: None,
            capabilities: self.config.capabilities.clone(),
            initial_state: Some(initial_state.clone()),
            zero_rtt_available: true,
        };
        self.control.send(&Message::HelloAck(ack)).await?;

        let session_state = SessionState::new(self.hello.session_key);

        // Open terminal output stream (server uni to client)
        let terminal_out = self
            .quic
            .open_stream(StreamType::TerminalOut)
            .await
            .map_err(|e| Error::Transport {
                message: format!("failed to open terminal output stream: {}", e),
            })?;

        let actual_size = initial_state.size();

        info!(
            term_size = %format!("{}x{}", actual_size.0, actual_size.1),
            term_type = self.hello.term_type,
            "Session established"
        );

        Ok(ServerSession {
            quic: Arc::new(self.quic),
            control: self.control,
            terminal_out,
            session_state,
            parser,
            confirmed_input_seq: 0,
            config: self.config,
            term_size: actual_size,
        })
    }
}

impl ServerSession {

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

    /// Maximum number of forwards allowed for this session.
    pub fn max_forwards(&self) -> u16 {
        self.config.max_forwards
    }

    /// Get the current RTT.
    pub fn rtt(&self) -> Duration {
        self.quic.rtt()
    }

    /// Get a shared reference to the underlying QUIC connection.
    ///
    /// Used by forward handlers to accept streams.
    pub fn quic_connection(&self) -> Arc<QuicConnection> {
        Arc::clone(&self.quic)
    }

    /// Accept an incoming stream from the client.
    ///
    /// Returns the stream type and the stream itself.
    pub async fn accept_stream(&self) -> Result<(StreamType, QuicStream)> {
        self.quic.accept_stream().await
    }

    /// Send raw terminal output to the client.
    ///
    /// This sends the raw PTY output directly without state tracking.
    /// For simple terminal use, this is sufficient.
    pub async fn send_output(&mut self, data: Vec<u8>, input_seq: u64) -> Result<()> {
        self.confirmed_input_seq = input_seq;

        let output = TerminalOutputPayload {
            data,
            confirmed_input_seq: self.confirmed_input_seq,
        };

        self.terminal_out
            .send(&Message::TerminalOutput(output))
            .await
    }

    /// Send a state update to the client.
    ///
    /// This parses the output through the terminal emulator and sends
    /// a state diff. Use `send_output` for simpler raw output mode.
    pub async fn send_state_update(&mut self, data: Vec<u8>, input_seq: u64) -> Result<()> {
        // Parse output through terminal emulator
        let state = {
            let mut parser = self.parser.lock().await;
            parser.process(&data);
            parser.state().clone()
        };

        self.confirmed_input_seq = input_seq;

        let update = StateUpdatePayload {
            diff: StateDiff::Full(state.clone()),
            confirmed_input_seq: self.confirmed_input_seq,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_micros() as u64,
        };

        self.terminal_out.send(&Message::StateUpdate(update)).await
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

    /// Send a shutdown message to the client.
    pub async fn send_shutdown(
        &mut self,
        reason: ShutdownReason,
        message: Option<String>,
    ) -> Result<()> {
        let payload = ShutdownPayload { reason, message };
        self.control.send(&Message::Shutdown(payload)).await
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
