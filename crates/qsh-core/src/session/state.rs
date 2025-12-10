//! Session state types shared between client and server.
//!
//! Provides common state tracking for connection lifecycle and
//! terminal recovery.

use std::time::{Duration, Instant};

use crate::protocol::SessionId;

/// Connection state for reconnection handling.
///
/// Tracks the current state of the connection lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Initial state, not yet connected.
    Disconnected,
    /// Attempting to establish connection.
    Connecting,
    /// Connected and operational.
    Connected,
    /// Connection lost, attempting to reconnect.
    Reconnecting,
    /// Shutting down gracefully.
    ShuttingDown,
    /// Connection terminated (fatal error or user cancelled).
    Terminated,
}

impl ConnectionState {
    /// Check if the connection is active (connected or reconnecting).
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Connected | Self::Reconnecting)
    }

    /// Check if the connection is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Terminated)
    }

    /// Check if the connection can be used for sending data.
    pub fn can_send(&self) -> bool {
        matches!(self, Self::Connected)
    }
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self::Disconnected
    }
}

/// Core session state tracking.
///
/// Contains the fundamental state needed for session management
/// on both client and server sides.
#[derive(Debug)]
pub struct SessionState {
    /// Session ID (assigned by server).
    session_id: SessionId,
    /// Current connection state.
    state: ConnectionState,
    /// When the session was created.
    created_at: Instant,
    /// Last activity timestamp.
    last_activity: Instant,
    /// Number of reconnections.
    reconnect_count: u32,
}

impl SessionState {
    /// Create a new session state with the given session ID.
    pub fn new(session_id: SessionId) -> Self {
        let now = Instant::now();
        Self {
            session_id,
            state: ConnectionState::Connecting,
            created_at: now,
            last_activity: now,
            reconnect_count: 0,
        }
    }

    /// Get the session ID.
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Get the current connection state.
    pub fn state(&self) -> ConnectionState {
        self.state
    }

    /// Set the connection state.
    pub fn set_state(&mut self, state: ConnectionState) {
        self.state = state;
        self.touch();
    }

    /// Mark the session as connected.
    pub fn connected(&mut self) {
        self.set_state(ConnectionState::Connected);
    }

    /// Mark the session as reconnecting.
    pub fn reconnecting(&mut self) {
        self.reconnect_count += 1;
        self.set_state(ConnectionState::Reconnecting);
    }

    /// Mark the session as disconnected.
    pub fn disconnected(&mut self) {
        self.set_state(ConnectionState::Disconnected);
    }

    /// Mark the session as terminated.
    pub fn terminated(&mut self) {
        self.set_state(ConnectionState::Terminated);
    }

    /// Update the last activity timestamp.
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Get the time since last activity.
    pub fn idle_duration(&self) -> Duration {
        self.last_activity.elapsed()
    }

    /// Get the total session duration.
    pub fn session_duration(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Get the number of reconnections.
    pub fn reconnect_count(&self) -> u32 {
        self.reconnect_count
    }

    /// Check if the session is active.
    pub fn is_active(&self) -> bool {
        self.state.is_active()
    }

    /// Check if the session can send data.
    pub fn can_send(&self) -> bool {
        self.state.can_send()
    }
}

/// Terminal-specific state for recovery after reconnection.
///
/// Used to request state diff from server based on last known state.
#[derive(Debug, Clone, Copy, Default)]
pub struct TerminalSessionState {
    /// Last confirmed terminal generation from server.
    pub last_generation: u64,
    /// Last confirmed input sequence from server.
    pub last_input_seq: u64,
}

impl TerminalSessionState {
    /// Create a new terminal session state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Update state from server confirmation.
    pub fn update(&mut self, generation: u64, input_seq: u64) {
        self.last_generation = generation;
        self.last_input_seq = input_seq;
    }

    /// Check if any state has been received.
    pub fn has_state(&self) -> bool {
        self.last_generation > 0 || self.last_input_seq > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_state_is_active() {
        assert!(!ConnectionState::Disconnected.is_active());
        assert!(!ConnectionState::Connecting.is_active());
        assert!(ConnectionState::Connected.is_active());
        assert!(ConnectionState::Reconnecting.is_active());
        assert!(!ConnectionState::ShuttingDown.is_active());
        assert!(!ConnectionState::Terminated.is_active());
    }

    #[test]
    fn test_connection_state_can_send() {
        assert!(!ConnectionState::Disconnected.can_send());
        assert!(!ConnectionState::Connecting.can_send());
        assert!(ConnectionState::Connected.can_send());
        assert!(!ConnectionState::Reconnecting.can_send());
        assert!(!ConnectionState::ShuttingDown.can_send());
        assert!(!ConnectionState::Terminated.can_send());
    }

    #[test]
    fn test_session_state_lifecycle() {
        let session_id = SessionId::new();
        let mut state = SessionState::new(session_id);

        assert_eq!(state.state(), ConnectionState::Connecting);
        assert_eq!(state.reconnect_count(), 0);

        state.connected();
        assert_eq!(state.state(), ConnectionState::Connected);
        assert!(state.is_active());
        assert!(state.can_send());

        state.reconnecting();
        assert_eq!(state.state(), ConnectionState::Reconnecting);
        assert_eq!(state.reconnect_count(), 1);
        assert!(state.is_active());
        assert!(!state.can_send());

        state.connected();
        state.reconnecting();
        assert_eq!(state.reconnect_count(), 2);

        state.terminated();
        assert!(!state.is_active());
    }

    #[test]
    fn test_session_state_timing() {
        let session_id = SessionId::new();
        let state = SessionState::new(session_id);

        std::thread::sleep(Duration::from_millis(10));

        assert!(state.idle_duration() >= Duration::from_millis(10));
        assert!(state.session_duration() >= Duration::from_millis(10));
    }

    #[test]
    fn test_terminal_session_state() {
        let mut state = TerminalSessionState::new();
        assert!(!state.has_state());
        assert_eq!(state.last_generation, 0);
        assert_eq!(state.last_input_seq, 0);

        state.update(42, 100);
        assert!(state.has_state());
        assert_eq!(state.last_generation, 42);
        assert_eq!(state.last_input_seq, 100);
    }
}
