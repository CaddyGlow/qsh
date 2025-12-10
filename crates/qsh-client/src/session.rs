//! Session context for reconnection support.
//!
//! Provides abstractions for managing connection state across reconnections:
//! - `SessionContext`: Cached connection info for transparent reconnection
//! - `TerminalSessionState`: Terminal-specific state for recovery (re-exported from qsh-core)
//! - `ConnectionState`: Current connection status (re-exported from qsh-core)

use std::net::SocketAddr;

use qsh_core::protocol::SessionId;

// Re-export shared session types from qsh-core
pub use qsh_core::session::{ConnectionState, TerminalSessionState};

#[cfg(feature = "standalone")]
use crate::standalone::DirectAuthenticator;

use crate::ConnectionConfig;

/// Cached connection info for reconnection.
///
/// Populated after initial connection succeeds. Used to re-establish
/// connection without re-running bootstrap or re-authenticating.
pub struct SessionContext {
    /// Server address (from bootstrap or direct).
    pub server_addr: SocketAddr,
    /// Session key (from bootstrap or generated).
    pub session_key: [u8; 32],
    /// Certificate hash for pinning (optional).
    pub cert_hash: Option<Vec<u8>>,
    /// Connection config template.
    pub config: ConnectionConfig,
    /// Session ID from server (for resume).
    pub session_id: Option<SessionId>,
    /// For standalone mode: authenticator for re-auth.
    #[cfg(feature = "standalone")]
    pub authenticator: Option<DirectAuthenticator>,
}

impl std::fmt::Debug for SessionContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionContext")
            .field("server_addr", &self.server_addr)
            .field("session_key", &"[REDACTED]")
            .field("cert_hash", &self.cert_hash.as_ref().map(|_| "[PRESENT]"))
            .field("config", &self.config)
            .field("session_id", &self.session_id)
            .finish()
    }
}

impl SessionContext {
    /// Create a new session context from a successful connection.
    pub fn new(config: ConnectionConfig, session_id: SessionId) -> Self {
        Self {
            server_addr: config.server_addr,
            session_key: config.session_key,
            cert_hash: config.cert_hash.clone(),
            config,
            session_id: Some(session_id),
            #[cfg(feature = "standalone")]
            authenticator: None,
        }
    }

    /// Create a session context with a standalone authenticator.
    #[cfg(feature = "standalone")]
    pub fn with_authenticator(mut self, authenticator: DirectAuthenticator) -> Self {
        self.authenticator = Some(authenticator);
        self
    }

    /// Get the session ID for reconnection.
    pub fn session_id(&self) -> Option<SessionId> {
        self.session_id
    }

    /// Update the session ID after reconnection.
    pub fn set_session_id(&mut self, session_id: SessionId) {
        self.session_id = Some(session_id);
    }

    /// Get a connection config for reconnection.
    ///
    /// Returns a config with the cached server address and session key.
    pub fn reconnect_config(&self) -> ConnectionConfig {
        ConnectionConfig {
            server_addr: self.server_addr,
            session_key: self.session_key,
            cert_hash: self.cert_hash.clone(),
            ..self.config.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qsh_core::protocol::TermSize;

    fn test_config() -> ConnectionConfig {
        ConnectionConfig {
            server_addr: "127.0.0.1:4500".parse().unwrap(),
            session_key: [0xAB; 32],
            cert_hash: Some(vec![1, 2, 3]),
            term_size: TermSize { cols: 80, rows: 24 },
            term_type: "xterm".to_string(),
            env: vec![],
            predictive_echo: true,
            connect_timeout: std::time::Duration::from_secs(5),
            zero_rtt_available: false,
            keep_alive_interval: None,
            max_idle_timeout: std::time::Duration::from_secs(30),
            session_data: None,
            local_port: None,
        }
    }

    #[test]
    fn session_context_creation() {
        let config = test_config();
        let session_id = SessionId::from_bytes([0x42; 16]);
        let ctx = SessionContext::new(config.clone(), session_id);

        assert_eq!(ctx.server_addr, config.server_addr);
        assert_eq!(ctx.session_key, config.session_key);
        assert_eq!(ctx.session_id(), Some(session_id));
    }

    #[test]
    fn session_context_reconnect_config() {
        let config = test_config();
        let session_id = SessionId::from_bytes([0x42; 16]);
        let ctx = SessionContext::new(config.clone(), session_id);

        let reconnect = ctx.reconnect_config();
        assert_eq!(reconnect.server_addr, config.server_addr);
        assert_eq!(reconnect.session_key, config.session_key);
        assert_eq!(reconnect.cert_hash, config.cert_hash);
    }

    #[test]
    fn terminal_session_state_update() {
        let mut state = TerminalSessionState::new();
        assert_eq!(state.last_generation, 0);
        assert_eq!(state.last_input_seq, 0);

        state.update(42, 100);
        assert_eq!(state.last_generation, 42);
        assert_eq!(state.last_input_seq, 100);
    }

    #[test]
    fn connection_state_variants() {
        assert_ne!(ConnectionState::Connected, ConnectionState::Reconnecting);
        assert_ne!(ConnectionState::Reconnecting, ConnectionState::Disconnected);
    }
}
