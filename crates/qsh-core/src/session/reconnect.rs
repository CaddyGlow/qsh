//! Reconnection handling for qsh sessions.
//!
//! Provides reconnection logic including:
//! - Reconnection state machine
//! - Mosh-style constant retry (RTT/2 delay, no exponential backoff)
//! - State recovery negotiation

use std::time::{Duration, Instant};

use crate::constants::SESSION_KEY_LEN;

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

/// Mosh-style retry constants (from mosh/src/network/network.cc).
const MIN_RETRY_DELAY_MS: u64 = 50; // Mosh MIN_RTO
const MAX_RETRY_DELAY_MS: u64 = 250; // Mosh sends at SRTT/2, clamped to SEND_INTERVAL_MAX
const DEFAULT_RETRY_DELAY_MS: u64 = 50; // When RTT unknown, use MIN_RTO (aggressive like Mosh)

/// Reconnection handler state machine.
#[derive(Debug)]
pub struct ReconnectionHandler {
    /// Maximum reconnection attempts before giving up.
    max_attempts: u32,
    /// Current attempt number (1-indexed).
    current_attempt: u32,
    /// Default delay when RTT is unknown (Mosh-style constant, not exponential).
    default_delay: Duration,
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
    ///
    /// Like mosh, retries indefinitely until server session expires or user cancels.
    /// Uses constant retry delay (RTT/2) instead of exponential backoff.
    pub fn new() -> Self {
        Self {
            max_attempts: u32::MAX, // Retry forever like mosh
            current_attempt: 0,
            default_delay: Duration::from_millis(DEFAULT_RETRY_DELAY_MS),
            started_at: None,
            has_session_ticket: false,
            last_generation: 0,
            last_input_seq: 0,
        }
    }

    /// Create a handler with custom settings.
    pub fn with_config(max_attempts: u32, default_delay: Duration) -> Self {
        Self {
            max_attempts,
            current_attempt: 0,
            default_delay,
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
    ///
    /// Like mosh, returns true indefinitely - reconnection only stops when:
    /// - Server returns SessionExpired or AuthenticationFailed
    /// - User cancels (ctrl+c)
    pub fn should_retry(&self) -> bool {
        // Only stop if we've hit the max attempts (which is u32::MAX by default)
        self.current_attempt < self.max_attempts
    }

    /// Get the delay before the next reconnection attempt.
    ///
    /// Uses Mosh-style constant retry: RTT/2 (or default 100ms), clamped to [50ms, 250ms].
    /// This is fundamentally different from TCP's exponential backoff because:
    /// - State synchronization is idempotent (only latest state matters)
    /// - We want fast recovery, not congestion avoidance
    /// - The server-side session stays alive regardless of retry rate
    pub fn next_delay(&mut self, rtt: Option<Duration>) -> Duration {
        self.current_attempt += 1;

        // Mosh-style: use RTT/2 if known, otherwise default
        let base = match rtt {
            Some(rtt) => rtt / 2,
            None => self.default_delay,
        };

        // Clamp to Mosh's bounds: MIN_RTO (50ms) to SEND_INTERVAL_MAX (250ms)
        let base_ms = base.as_millis() as u64;
        let clamped_ms = base_ms.clamp(MIN_RETRY_DELAY_MS, MAX_RETRY_DELAY_MS);

        // Add jitter (up to 25% of delay) to prevent thundering herd
        let jitter_range = clamped_ms / 4;
        let jitter_ms = if jitter_range > 0 {
            // Simple deterministic "jitter" based on attempt count
            (self.current_attempt as u64 * 17) % jitter_range.max(1)
        } else {
            0
        };

        Duration::from_millis(clamped_ms + jitter_ms)
    }

    /// Get the delay before the next reconnection attempt (without RTT info).
    pub fn next_delay_default(&mut self) -> Duration {
        self.next_delay(None)
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
        // Default is infinite retries (like mosh)
        assert_eq!(handler.max_attempts, u32::MAX);
    }

    #[test]
    fn handler_start_initializes() {
        let mut handler = ReconnectionHandler::new();
        handler.start(42, 100, true);

        assert!(handler.can_use_0rtt());
        assert_eq!(handler.last_known_state(), (42, 100));
    }

    #[test]
    fn handler_mosh_style_constant_delay() {
        let mut handler = ReconnectionHandler::with_config(10, Duration::from_millis(50));

        handler.start(0, 0, false);

        // Without RTT: all delays should be constant ~50ms (MIN_RTO, with jitter)
        let d1 = handler.next_delay(None);
        assert!(d1 >= Duration::from_millis(50));
        assert!(d1 <= Duration::from_millis(63)); // 50 + 25% jitter max

        let d2 = handler.next_delay(None);
        assert!(d2 >= Duration::from_millis(50));
        assert!(d2 <= Duration::from_millis(63));

        // No exponential increase - delays stay constant
        let d3 = handler.next_delay(None);
        assert!(d3 >= Duration::from_millis(50));
        assert!(d3 <= Duration::from_millis(63));
    }

    #[test]
    fn handler_rtt_based_delay() {
        let mut handler = ReconnectionHandler::new();
        handler.start(0, 0, false);

        // With 200ms RTT: delay should be RTT/2 = 100ms
        let d1 = handler.next_delay(Some(Duration::from_millis(200)));
        assert!(d1 >= Duration::from_millis(100));
        assert!(d1 <= Duration::from_millis(125));

        // With 20ms RTT: delay should be clamped to MIN (50ms)
        let d2 = handler.next_delay(Some(Duration::from_millis(20)));
        assert!(d2 >= Duration::from_millis(50));
        assert!(d2 <= Duration::from_millis(63)); // 50 + 25% jitter

        // With 1000ms RTT: delay should be clamped to MAX (250ms)
        let d3 = handler.next_delay(Some(Duration::from_millis(1000)));
        assert!(d3 >= Duration::from_millis(250));
        assert!(d3 <= Duration::from_millis(313)); // 250 + 25% jitter
    }

    #[test]
    fn handler_max_attempts() {
        let mut handler = ReconnectionHandler::with_config(3, Duration::from_millis(50));

        handler.start(0, 0, false);

        assert!(handler.should_retry());
        handler.next_delay(None);
        assert!(handler.should_retry());
        handler.next_delay(None);
        assert!(handler.should_retry());
        handler.next_delay(None);
        assert!(!handler.should_retry()); // Max attempts reached
    }

    #[test]
    fn handler_reset() {
        let mut handler = ReconnectionHandler::new();
        handler.start(0, 0, false);
        handler.next_delay(None);
        handler.next_delay(None);

        assert_eq!(handler.attempt(), 2);

        handler.reset();
        assert_eq!(handler.attempt(), 0);
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
