//! Reconnection handling for qsh sessions.
//!
//! Provides reconnection logic including:
//! - Reconnection state machine
//! - Exponential backoff
//! - State recovery negotiation
//! - Input replay

use std::time::{Duration, Instant};

use crate::constants::{RECONNECT_TIMEOUT, SESSION_KEY_LEN};
use crate::error::{Error, Result};

use super::state::{InputTracker, SessionState, SessionStatus};

/// Reconnection attempt result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconnectResult {
    /// Successfully reconnected with state preserved.
    Success {
        /// Server's confirmed input sequence.
        server_input_seq: u64,
        /// Server's terminal state generation.
        server_generation: u64,
        /// Whether we need full state sync.
        needs_full_sync: bool,
    },
    /// Session expired on server side.
    SessionExpired,
    /// Authentication failed (wrong session key).
    AuthenticationFailed,
    /// Server rejected reconnection for other reason.
    Rejected { reason: String },
}

/// Reconnection handler state machine.
#[derive(Debug)]
pub struct ReconnectionHandler {
    /// Maximum reconnection attempts before giving up.
    max_attempts: u32,
    /// Current attempt number (1-indexed).
    current_attempt: u32,
    /// Base delay for exponential backoff.
    base_delay: Duration,
    /// Maximum delay cap.
    max_delay: Duration,
    /// When reconnection process started.
    started_at: Option<Instant>,
    /// Whether we have a 0-RTT session ticket.
    has_session_ticket: bool,
    /// Last known server generation.
    last_generation: u64,
    /// Last known confirmed input sequence.
    last_input_seq: u64,
}

impl Default for ReconnectionHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ReconnectionHandler {
    /// Create a new reconnection handler with default settings.
    pub fn new() -> Self {
        Self {
            max_attempts: 10,
            current_attempt: 0,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            started_at: None,
            has_session_ticket: false,
            last_generation: 0,
            last_input_seq: 0,
        }
    }

    /// Create a handler with custom settings.
    pub fn with_config(max_attempts: u32, base_delay: Duration, max_delay: Duration) -> Self {
        Self {
            max_attempts,
            current_attempt: 0,
            base_delay,
            max_delay,
            started_at: None,
            has_session_ticket: false,
            last_generation: 0,
            last_input_seq: 0,
        }
    }

    /// Start reconnection process.
    pub fn start(&mut self, last_generation: u64, last_input_seq: u64, has_ticket: bool) {
        self.current_attempt = 0;
        self.started_at = Some(Instant::now());
        self.has_session_ticket = has_ticket;
        self.last_generation = last_generation;
        self.last_input_seq = last_input_seq;
    }

    /// Check if we should attempt another reconnection.
    pub fn should_retry(&self) -> bool {
        if self.current_attempt >= self.max_attempts {
            return false;
        }

        // Check overall timeout
        if let Some(started) = self.started_at {
            if started.elapsed() > RECONNECT_TIMEOUT {
                return false;
            }
        }

        true
    }

    /// Get the delay before the next reconnection attempt.
    pub fn next_delay(&mut self) -> Duration {
        self.current_attempt += 1;

        // Exponential backoff: base_delay * 2^(attempt-1)
        let multiplier = 2u64.saturating_pow(self.current_attempt.saturating_sub(1));
        let delay = self.base_delay.saturating_mul(multiplier as u32);

        // Add jitter (up to 25% of delay)
        let jitter_range = delay.as_millis() as u64 / 4;
        let jitter = if jitter_range > 0 {
            // Simple deterministic "jitter" based on attempt count
            Duration::from_millis(
                (self.current_attempt as u64 * 17) % jitter_range.max(1),
            )
        } else {
            Duration::ZERO
        };

        (delay + jitter).min(self.max_delay)
    }

    /// Get the current attempt number.
    pub fn attempt(&self) -> u32 {
        self.current_attempt
    }

    /// Get elapsed time since reconnection started.
    pub fn elapsed(&self) -> Duration {
        self.started_at
            .map(|t| t.elapsed())
            .unwrap_or(Duration::ZERO)
    }

    /// Check if we can use 0-RTT reconnection.
    pub fn can_use_0rtt(&self) -> bool {
        self.has_session_ticket
    }

    /// Process reconnection result and update session state.
    pub fn process_result(
        &self,
        result: &ReconnectResult,
        session: &mut SessionState,
        input_tracker: &mut InputTracker,
    ) -> Result<()> {
        match result {
            ReconnectResult::Success {
                server_input_seq,
                server_generation,
                needs_full_sync,
            } => {
                // Update session state
                session.confirm_generation(*server_generation);
                session.confirm_input_seq(*server_input_seq);
                session.record_reconnect();

                // Confirm inputs that server has processed
                input_tracker.confirm(*server_input_seq);

                if *needs_full_sync {
                    // Clear pending inputs - server will resend full state
                    input_tracker.clear();
                }

                Ok(())
            }

            ReconnectResult::SessionExpired => {
                session.set_status(SessionStatus::Expired);
                Err(Error::SessionExpired)
            }

            ReconnectResult::AuthenticationFailed => {
                session.set_status(SessionStatus::Closed);
                Err(Error::AuthenticationFailed)
            }

            ReconnectResult::Rejected { reason } => {
                session.set_status(SessionStatus::Closed);
                Err(Error::Protocol {
                    message: format!("Reconnection rejected: {}", reason),
                })
            }
        }
    }

    /// Reset the handler for a new reconnection cycle.
    pub fn reset(&mut self) {
        self.current_attempt = 0;
        self.started_at = None;
    }

    /// Get the last known server state for Hello message.
    pub fn last_known_state(&self) -> (u64, u64) {
        (self.last_generation, self.last_input_seq)
    }
}

/// Reconnection request sent to server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconnectRequest {
    /// Session key for authentication.
    pub session_key: [u8; SESSION_KEY_LEN],
    /// Client's last confirmed terminal generation.
    pub last_generation: u64,
    /// Client's last confirmed input sequence.
    pub last_input_seq: u64,
    /// Client nonce (must be higher than previous).
    pub client_nonce: u64,
    /// Whether client is using 0-RTT.
    pub is_0rtt: bool,
}

/// Reconnection response from server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconnectResponse {
    /// Whether reconnection was accepted.
    pub accepted: bool,
    /// Reason for rejection (if not accepted).
    pub reject_reason: Option<String>,
    /// Server's current terminal generation.
    pub server_generation: u64,
    /// Server's confirmed input sequence.
    pub server_input_seq: u64,
    /// Whether full state will be sent.
    pub will_send_full_state: bool,
}

impl ReconnectResponse {
    /// Convert to ReconnectResult.
    pub fn into_result(self) -> ReconnectResult {
        if self.accepted {
            ReconnectResult::Success {
                server_input_seq: self.server_input_seq,
                server_generation: self.server_generation,
                needs_full_sync: self.will_send_full_state,
            }
        } else {
            match self.reject_reason.as_deref() {
                Some("session_expired") => ReconnectResult::SessionExpired,
                Some("authentication_failed") => ReconnectResult::AuthenticationFailed,
                Some(reason) => ReconnectResult::Rejected {
                    reason: reason.to_string(),
                },
                None => ReconnectResult::Rejected {
                    reason: "unknown".to_string(),
                },
            }
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handler_new_defaults() {
        let handler = ReconnectionHandler::new();
        assert_eq!(handler.attempt(), 0);
        assert!(handler.should_retry());
    }

    #[test]
    fn handler_start_initializes() {
        let mut handler = ReconnectionHandler::new();
        handler.start(42, 100, true);

        assert!(handler.can_use_0rtt());
        assert_eq!(handler.last_known_state(), (42, 100));
    }

    #[test]
    fn handler_exponential_backoff() {
        let mut handler =
            ReconnectionHandler::with_config(10, Duration::from_millis(100), Duration::from_secs(5));

        handler.start(0, 0, false);

        // First delay should be ~100ms
        let d1 = handler.next_delay();
        assert!(d1 >= Duration::from_millis(100));
        assert!(d1 < Duration::from_millis(200));

        // Second delay should be ~200ms
        let d2 = handler.next_delay();
        assert!(d2 >= Duration::from_millis(200));
        assert!(d2 < Duration::from_millis(400));

        // Third delay should be ~400ms
        let d3 = handler.next_delay();
        assert!(d3 >= Duration::from_millis(400));
        assert!(d3 < Duration::from_millis(800));
    }

    #[test]
    fn handler_max_delay_cap() {
        let mut handler =
            ReconnectionHandler::with_config(20, Duration::from_millis(100), Duration::from_secs(1));

        handler.start(0, 0, false);

        // Exhaust backoff to hit cap
        for _ in 0..15 {
            handler.next_delay();
        }

        let d = handler.next_delay();
        assert!(d <= Duration::from_secs(1));
    }

    #[test]
    fn handler_max_attempts() {
        let mut handler =
            ReconnectionHandler::with_config(3, Duration::from_millis(10), Duration::from_secs(1));

        handler.start(0, 0, false);

        assert!(handler.should_retry());
        handler.next_delay();
        assert!(handler.should_retry());
        handler.next_delay();
        assert!(handler.should_retry());
        handler.next_delay();
        assert!(!handler.should_retry()); // Max attempts reached
    }

    #[test]
    fn handler_reset() {
        let mut handler = ReconnectionHandler::new();
        handler.start(0, 0, false);
        handler.next_delay();
        handler.next_delay();

        assert_eq!(handler.attempt(), 2);

        handler.reset();
        assert_eq!(handler.attempt(), 0);
    }

    #[test]
    fn process_success_result() {
        let handler = ReconnectionHandler::new();
        let mut session = SessionState::new([0xAB; 32]);
        let mut input_tracker = InputTracker::new();

        session.set_status(SessionStatus::Reconnecting);

        let result = ReconnectResult::Success {
            server_input_seq: 10,
            server_generation: 5,
            needs_full_sync: false,
        };

        handler
            .process_result(&result, &mut session, &mut input_tracker)
            .unwrap();

        assert_eq!(session.status(), SessionStatus::Connected);
        assert_eq!(session.last_confirmed_generation(), 5);
        assert_eq!(session.last_confirmed_input_seq(), 10);
        assert_eq!(session.reconnect_count(), 1);
    }

    #[test]
    fn process_success_with_full_sync() {
        let handler = ReconnectionHandler::new();
        let mut session = SessionState::new([0xAB; 32]);
        let mut input_tracker = InputTracker::new();

        // Add some pending inputs
        input_tracker.push(vec![1, 2, 3], true);
        input_tracker.push(vec![4, 5, 6], true);

        let result = ReconnectResult::Success {
            server_input_seq: 0,
            server_generation: 0,
            needs_full_sync: true,
        };

        handler
            .process_result(&result, &mut session, &mut input_tracker)
            .unwrap();

        // Pending inputs should be cleared for full sync
        assert!(!input_tracker.has_pending());
    }

    #[test]
    fn process_session_expired() {
        let handler = ReconnectionHandler::new();
        let mut session = SessionState::new([0xAB; 32]);
        let mut input_tracker = InputTracker::new();

        let result = ReconnectResult::SessionExpired;
        let err = handler
            .process_result(&result, &mut session, &mut input_tracker)
            .unwrap_err();

        assert!(matches!(err, Error::SessionExpired));
        assert_eq!(session.status(), SessionStatus::Expired);
    }

    #[test]
    fn process_authentication_failed() {
        let handler = ReconnectionHandler::new();
        let mut session = SessionState::new([0xAB; 32]);
        let mut input_tracker = InputTracker::new();

        let result = ReconnectResult::AuthenticationFailed;
        let err = handler
            .process_result(&result, &mut session, &mut input_tracker)
            .unwrap_err();

        assert!(matches!(err, Error::AuthenticationFailed));
        assert_eq!(session.status(), SessionStatus::Closed);
    }

    #[test]
    fn reconnect_response_into_result() {
        let success = ReconnectResponse {
            accepted: true,
            reject_reason: None,
            server_generation: 10,
            server_input_seq: 5,
            will_send_full_state: false,
        };

        assert!(matches!(
            success.into_result(),
            ReconnectResult::Success { .. }
        ));

        let expired = ReconnectResponse {
            accepted: false,
            reject_reason: Some("session_expired".to_string()),
            server_generation: 0,
            server_input_seq: 0,
            will_send_full_state: false,
        };

        assert!(matches!(
            expired.into_result(),
            ReconnectResult::SessionExpired
        ));

        let auth_failed = ReconnectResponse {
            accepted: false,
            reject_reason: Some("authentication_failed".to_string()),
            server_generation: 0,
            server_input_seq: 0,
            will_send_full_state: false,
        };

        assert!(matches!(
            auth_failed.into_result(),
            ReconnectResult::AuthenticationFailed
        ));

        let rejected = ReconnectResponse {
            accepted: false,
            reject_reason: Some("too_many_attempts".to_string()),
            server_generation: 0,
            server_input_seq: 0,
            will_send_full_state: false,
        };

        match rejected.into_result() {
            ReconnectResult::Rejected { reason } => {
                assert_eq!(reason, "too_many_attempts");
            }
            _ => panic!("Expected Rejected"),
        }
    }

    #[test]
    fn reconnect_request_fields() {
        let request = ReconnectRequest {
            session_key: [0xAB; 32],
            last_generation: 42,
            last_input_seq: 100,
            client_nonce: 5,
            is_0rtt: true,
        };

        assert_eq!(request.session_key, [0xAB; 32]);
        assert_eq!(request.last_generation, 42);
        assert_eq!(request.last_input_seq, 100);
        assert_eq!(request.client_nonce, 5);
        assert!(request.is_0rtt);
    }
}
