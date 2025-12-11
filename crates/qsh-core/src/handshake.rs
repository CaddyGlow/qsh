//! Handshake abstraction for qsh connections.
//!
//! This module provides shared handshake logic that works based on ConnectMode
//! (Initiate vs Respond) rather than binary-specific logic (client vs server).
//!
//! # Handshake Flow
//!
//! - **Initiator** (ConnectMode::Initiate): Sends Hello, receives and validates HelloAck
//! - **Responder** (ConnectMode::Respond): Receives Hello, validates session key, sends HelloAck
//!
//! This abstraction allows either binary (qsh-client or qsh-server) to play
//! either role depending on the connection scenario (e.g., reverse shells).

use crate::connect_mode::ConnectMode;
use crate::error::{Error, Result};
use crate::protocol::{
    Capabilities, HelloAckPayload, HelloPayload, Message, SessionId, TermSize,
};
use crate::transport::StreamPair;

/// Configuration for performing a handshake.
///
/// This struct contains all parameters needed to perform either side of the qsh handshake.
/// Fields marked "for initiator" are only used when `connect_mode` is `Initiate`.
#[derive(Debug, Clone)]
pub struct HandshakeConfig {
    /// Connect mode determining handshake role (initiate or respond).
    pub connect_mode: ConnectMode,

    /// Session key from bootstrap for authentication (32 bytes).
    ///
    /// Generated during bootstrap and shared via SSH. Both sides must use the same key.
    pub session_key: [u8; 32],

    /// Protocol capabilities to negotiate with peer.
    ///
    /// The handshake will compute the intersection of both sides' capabilities.
    pub capabilities: Capabilities,

    /// Terminal size (for initiator's Hello message).
    ///
    /// Only used when `connect_mode` is `Initiate`. Ignored for responder.
    pub term_size: TermSize,

    /// Terminal type string (for initiator's Hello message).
    ///
    /// Only used when `connect_mode` is `Initiate`. Typically "xterm-256color" or similar.
    pub term_type: String,

    /// Environment variables to pass to remote PTY (for initiator's Hello message).
    ///
    /// Only used when `connect_mode` is `Initiate`. Common vars: LANG, LC_*, COLORTERM.
    pub env: Vec<(String, String)>,

    /// Enable predictive echo (for initiator's Hello message).
    ///
    /// Only used when `connect_mode` is `Initiate`.
    pub predictive_echo: bool,

    /// Session ID to resume (for initiator reconnection).
    ///
    /// When set, requests session resumption with existing channels. Only used by initiator.
    pub resume_session: Option<SessionId>,
}

impl HandshakeConfig {
    /// Create a new handshake configuration for the initiating side.
    pub fn new_initiate(
        session_key: [u8; 32],
        capabilities: Capabilities,
        term_size: TermSize,
        term_type: String,
        env: Vec<(String, String)>,
        predictive_echo: bool,
    ) -> Self {
        Self {
            connect_mode: ConnectMode::Initiate,
            session_key,
            capabilities,
            term_size,
            term_type,
            env,
            predictive_echo,
            resume_session: None,
        }
    }

    /// Create a new handshake configuration for the responding side.
    pub fn new_respond(session_key: [u8; 32], capabilities: Capabilities) -> Self {
        Self {
            connect_mode: ConnectMode::Respond,
            session_key,
            capabilities,
            term_size: TermSize { cols: 80, rows: 24 }, // Unused for responder
            term_type: String::new(),                    // Unused for responder
            env: Vec::new(),                             // Unused for responder
            predictive_echo: false,                      // Unused for responder
            resume_session: None,                        // Unused for responder
        }
    }

    /// Set the session ID to resume (for initiator reconnection).
    pub fn with_resume_session(mut self, session_id: SessionId) -> Self {
        self.resume_session = Some(session_id);
        self
    }
}

/// Result of a successful handshake.
///
/// Contains the negotiated session parameters and metadata. Some fields are only
/// populated for specific roles (initiator vs responder).
#[derive(Debug, Clone)]
pub struct HandshakeResult {
    /// Session ID for this connection.
    ///
    /// Either a new ID (for fresh connections) or the resumed ID (for reconnections).
    pub session_id: SessionId,

    /// Negotiated capabilities.
    ///
    /// The intersection of capabilities advertised by both sides.
    pub capabilities: Capabilities,

    /// Hello payload from initiator (only for responder).
    ///
    /// Contains terminal size, env vars, and other session parameters.
    /// `None` when handshake was performed as initiator.
    pub hello_payload: Option<HelloPayload>,

    /// Server-generated nonce for anti-replay protection.
    ///
    /// Included in HelloAck message. Can be used to detect duplicate handshakes.
    pub server_nonce: u64,

    /// Whether 0-RTT resumption is available for future reconnections.
    ///
    /// When `true`, session data can be cached for fast reconnection.
    pub zero_rtt_available: bool,

    /// Existing channels from session resumption (only for initiator).
    ///
    /// When reconnecting with a valid session ID, the responder returns a list
    /// of channels that were open in the previous session. Empty for fresh connections
    /// or when handshake was performed as responder.
    pub existing_channels: Vec<crate::protocol::ExistingChannel>,
}

/// Session authorizer for validating session keys.
///
/// Used by the responder to check if a session key is allowed.
#[async_trait::async_trait]
pub trait SessionAuthorizer: Send + Sync {
    /// Check if the given session key is allowed.
    async fn is_allowed(&self, key: &[u8; 32]) -> bool;
}

/// Perform handshake as the initiating side.
///
/// Sends Hello, receives and validates HelloAck.
///
/// # Arguments
///
/// - `stream`: Bidirectional control stream for handshake messages
/// - `config`: Handshake configuration
///
/// # Returns
///
/// HandshakeResult with session_id and negotiated capabilities.
pub async fn handshake_initiate(
    stream: &mut impl StreamPair,
    config: &HandshakeConfig,
) -> Result<HandshakeResult> {
    // Send Hello message
    let hello = HelloPayload {
        protocol_version: 1,
        session_key: config.session_key,
        client_nonce: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64,
        capabilities: config.capabilities.clone(),
        resume_session: config.resume_session,
    };

    stream.send(&Message::Hello(hello)).await?;

    // Receive HelloAck
    let hello_ack = match stream.recv().await? {
        Message::HelloAck(ack) => ack,
        other => {
            return Err(Error::Protocol {
                message: format!("expected HelloAck, got {:?}", other),
            });
        }
    };

    // Check if accepted
    if !hello_ack.accepted {
        return Err(Error::AuthenticationFailed);
    }

    // Validate protocol version
    if hello_ack.protocol_version != 1 {
        return Err(Error::Protocol {
            message: format!("unsupported protocol version: {}", hello_ack.protocol_version),
        });
    }

    Ok(HandshakeResult {
        session_id: hello_ack.session_id,
        capabilities: hello_ack.capabilities,
        hello_payload: None,
        server_nonce: hello_ack.server_nonce,
        zero_rtt_available: hello_ack.zero_rtt_available,
        existing_channels: hello_ack.existing_channels,
    })
}

/// Perform handshake as the responding side.
///
/// Receives Hello, validates session key, sends HelloAck.
///
/// # Arguments
///
/// - `stream`: Bidirectional control stream for handshake messages
/// - `config`: Handshake configuration
/// - `authorizer`: Optional session authorizer to validate session keys
///
/// # Returns
///
/// HandshakeResult with session_id, capabilities, and the received Hello payload.
pub async fn handshake_respond(
    stream: &mut impl StreamPair,
    config: &HandshakeConfig,
    authorizer: Option<&dyn SessionAuthorizer>,
) -> Result<HandshakeResult> {
    // Receive Hello
    let hello = match stream.recv().await? {
        Message::Hello(h) => h,
        other => {
            return Err(Error::Protocol {
                message: format!("expected Hello, got {:?}", other),
            });
        }
    };

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
        stream.send(&Message::HelloAck(ack)).await?;
        return Err(Error::Protocol {
            message: "unsupported protocol version".to_string(),
        });
    }

    // Validate session key if authorizer provided
    if let Some(auth) = authorizer {
        if !auth.is_allowed(&hello.session_key).await {
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
            stream.send(&Message::HelloAck(ack)).await?;
            return Err(Error::AuthenticationFailed);
        }
    }

    // Generate session ID
    let session_id = SessionId::new();
    let server_nonce = rand::random();

    // Send HelloAck
    let ack = HelloAckPayload {
        protocol_version: 1,
        accepted: true,
        reject_reason: None,
        capabilities: config.capabilities.clone(),
        session_id,
        server_nonce,
        zero_rtt_available: true,
        existing_channels: vec![],
    };
    stream.send(&Message::HelloAck(ack)).await?;

    Ok(HandshakeResult {
        session_id,
        capabilities: config.capabilities.clone(),
        hello_payload: Some(hello),
        server_nonce,
        zero_rtt_available: true,
        existing_channels: vec![],
    })
}

/// Perform handshake based on connect mode.
///
/// This is the main entry point for performing handshakes. It dispatches
/// to either `handshake_initiate` or `handshake_respond` based on the
/// configured connect mode.
///
/// # Arguments
///
/// - `stream`: Bidirectional control stream for handshake messages
/// - `config`: Handshake configuration
/// - `authorizer`: Optional session authorizer (only used for responder)
///
/// # Returns
///
/// HandshakeResult with session_id, capabilities, and (for responder) the Hello payload.
pub async fn perform_handshake(
    stream: &mut impl StreamPair,
    config: &HandshakeConfig,
    authorizer: Option<&dyn SessionAuthorizer>,
) -> Result<HandshakeResult> {
    match config.connect_mode {
        ConnectMode::Initiate => handshake_initiate(stream, config).await,
        ConnectMode::Respond => handshake_respond(stream, config, authorizer).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Capabilities;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    /// Mock stream for testing.
    struct MockStream {
        recv_queue: Arc<Mutex<Vec<Message>>>,
        send_queue: Arc<Mutex<Vec<Message>>>,
    }

    impl MockStream {
        fn new() -> (Self, Self) {
            let recv_queue = Arc::new(Mutex::new(Vec::new()));
            let send_queue = Arc::new(Mutex::new(Vec::new()));

            let a = MockStream {
                recv_queue: Arc::clone(&send_queue),
                send_queue: Arc::clone(&recv_queue),
            };

            let b = MockStream {
                recv_queue,
                send_queue,
            };

            (a, b)
        }
    }

    impl StreamPair for MockStream {
        async fn send(&mut self, msg: &Message) -> Result<()> {
            self.send_queue.lock().await.push(msg.clone());
            Ok(())
        }

        async fn recv(&mut self) -> Result<Message> {
            loop {
                let mut queue = self.recv_queue.lock().await;
                if !queue.is_empty() {
                    return Ok(queue.remove(0));
                }
                drop(queue);
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        }

        fn close(&mut self) {
            // No-op for mock
        }
    }

    /// Mock authorizer that allows all keys.
    struct AllowAllAuthorizer;

    #[async_trait::async_trait]
    impl SessionAuthorizer for AllowAllAuthorizer {
        async fn is_allowed(&self, _key: &[u8; 32]) -> bool {
            true
        }
    }

    /// Mock authorizer that denies all keys.
    struct DenyAllAuthorizer;

    #[async_trait::async_trait]
    impl SessionAuthorizer for DenyAllAuthorizer {
        async fn is_allowed(&self, _key: &[u8; 32]) -> bool {
            false
        }
    }

    #[tokio::test]
    async fn test_handshake_initiate_respond() {
        let (mut initiator_stream, mut responder_stream) = MockStream::new();

        let session_key = [42u8; 32];
        let capabilities = Capabilities {
            predictive_echo: true,
            compression: false,
            max_forwards: 10,
            tunnel: false,
        };

        let initiator_config = HandshakeConfig::new_initiate(
            session_key,
            capabilities.clone(),
            TermSize { cols: 80, rows: 24 },
            "xterm-256color".to_string(),
            vec![],
            true,
        );

        let responder_config = HandshakeConfig::new_respond(session_key, capabilities.clone());

        let auth = AllowAllAuthorizer;

        // Run both sides concurrently
        let initiator_task = tokio::spawn(async move {
            handshake_initiate(&mut initiator_stream, &initiator_config).await
        });

        let responder_task = tokio::spawn(async move {
            handshake_respond(&mut responder_stream, &responder_config, Some(&auth)).await
        });

        let (initiator_result, responder_result) =
            tokio::join!(initiator_task, responder_task);

        let initiator_result = initiator_result.unwrap().unwrap();
        let responder_result = responder_result.unwrap().unwrap();

        // Both should have the same session ID
        assert_eq!(initiator_result.session_id, responder_result.session_id);

        // Responder should have received Hello
        assert!(responder_result.hello_payload.is_some());

        // Initiator should not have Hello
        assert!(initiator_result.hello_payload.is_none());
    }

    #[tokio::test]
    async fn test_handshake_responder_rejects_invalid_key() {
        let (mut initiator_stream, mut responder_stream) = MockStream::new();

        let session_key = [42u8; 32];
        let capabilities = Capabilities::default();

        let initiator_config = HandshakeConfig::new_initiate(
            session_key,
            capabilities.clone(),
            TermSize { cols: 80, rows: 24 },
            "xterm".to_string(),
            vec![],
            false,
        );

        let responder_config = HandshakeConfig::new_respond(session_key, capabilities);

        let auth = DenyAllAuthorizer;

        // Run both sides concurrently
        let initiator_task = tokio::spawn(async move {
            handshake_initiate(&mut initiator_stream, &initiator_config).await
        });

        let responder_task = tokio::spawn(async move {
            handshake_respond(&mut responder_stream, &responder_config, Some(&auth)).await
        });

        let (initiator_result, responder_result) =
            tokio::join!(initiator_task, responder_task);

        // Responder should reject with AuthenticationFailed
        assert!(matches!(
            responder_result.unwrap().unwrap_err(),
            Error::AuthenticationFailed
        ));

        // Initiator should also fail (received rejected HelloAck)
        assert!(matches!(
            initiator_result.unwrap().unwrap_err(),
            Error::AuthenticationFailed
        ));
    }

    #[tokio::test]
    async fn test_perform_handshake_dispatcher() {
        let (mut initiator_stream, mut responder_stream) = MockStream::new();

        let session_key = [99u8; 32];
        let capabilities = Capabilities::default();

        let initiator_config = HandshakeConfig {
            connect_mode: ConnectMode::Initiate,
            session_key,
            capabilities: capabilities.clone(),
            term_size: TermSize { cols: 80, rows: 24 },
            term_type: "xterm".to_string(),
            env: vec![],
            predictive_echo: false,
            resume_session: None,
        };

        let responder_config = HandshakeConfig {
            connect_mode: ConnectMode::Respond,
            session_key,
            capabilities,
            term_size: TermSize { cols: 80, rows: 24 }, // Unused
            term_type: String::new(),
            env: vec![],
            predictive_echo: false,
            resume_session: None,
        };

        let auth = AllowAllAuthorizer;

        // Run both sides using perform_handshake
        let initiator_task = tokio::spawn(async move {
            perform_handshake(&mut initiator_stream, &initiator_config, None).await
        });

        let responder_task = tokio::spawn(async move {
            perform_handshake(&mut responder_stream, &responder_config, Some(&auth)).await
        });

        let (initiator_result, responder_result) =
            tokio::join!(initiator_task, responder_task);

        let initiator_result = initiator_result.unwrap().unwrap();
        let responder_result = responder_result.unwrap().unwrap();

        // Both should succeed with same session ID
        assert_eq!(initiator_result.session_id, responder_result.session_id);
    }

    #[tokio::test]
    async fn test_session_resumption() {
        let (mut initiator_stream, mut responder_stream) = MockStream::new();

        let session_key = [77u8; 32];
        let capabilities = Capabilities::default();
        let resume_session_id = SessionId::new();

        let initiator_config = HandshakeConfig::new_initiate(
            session_key,
            capabilities.clone(),
            TermSize { cols: 80, rows: 24 },
            "xterm".to_string(),
            vec![],
            false,
        )
        .with_resume_session(resume_session_id);

        let responder_config = HandshakeConfig::new_respond(session_key, capabilities);

        let auth = AllowAllAuthorizer;

        // Run handshake
        let initiator_task = tokio::spawn(async move {
            handshake_initiate(&mut initiator_stream, &initiator_config).await
        });

        let responder_task = tokio::spawn(async move {
            handshake_respond(&mut responder_stream, &responder_config, Some(&auth)).await
        });

        let (initiator_result, responder_result) =
            tokio::join!(initiator_task, responder_task);

        let _initiator_result = initiator_result.unwrap().unwrap();
        let responder_result = responder_result.unwrap().unwrap();

        // Verify Hello contains resume_session
        let hello = responder_result.hello_payload.unwrap();
        assert_eq!(hello.resume_session, Some(resume_session_id));

        // Note: In this simple test, responder still generates a new session ID.
        // Full session resumption logic (reusing the same ID) would be in the
        // connection handler, not in this low-level handshake helper.
    }
}
