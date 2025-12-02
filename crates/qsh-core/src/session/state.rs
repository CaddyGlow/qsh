//! Session state types.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::constants::{MAX_PENDING_PREDICTIONS, SESSION_KEY_LEN, SESSION_TIMEOUT};

/// Session connection status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    /// Not yet connected.
    Disconnected,
    /// Initial handshake in progress.
    Connecting,
    /// Fully connected and operational.
    Connected,
    /// Lost connection, attempting to reconnect.
    Reconnecting,
    /// Session has been explicitly closed.
    Closed,
    /// Session has expired due to timeout.
    Expired,
}

impl SessionStatus {
    /// Check if this status represents an active session.
    pub fn is_active(&self) -> bool {
        matches!(self, SessionStatus::Connected | SessionStatus::Reconnecting)
    }

    /// Check if this status allows reconnection.
    pub fn can_reconnect(&self) -> bool {
        matches!(
            self,
            SessionStatus::Connected | SessionStatus::Reconnecting | SessionStatus::Disconnected
        )
    }
}

/// Session state tracking.
#[derive(Debug)]
pub struct SessionState {
    /// Session key for authentication.
    session_key: [u8; SESSION_KEY_LEN],
    /// Current connection status.
    status: SessionStatus,
    /// Client nonce for anti-replay (monotonic).
    client_nonce: u64,
    /// Last confirmed terminal state generation.
    last_confirmed_generation: u64,
    /// Last confirmed input sequence.
    last_confirmed_input_seq: u64,
    /// When the session was created.
    created_at: Instant,
    /// When we last received data from the server.
    last_server_activity: Option<Instant>,
    /// When we last sent data to the server.
    last_client_activity: Option<Instant>,
    /// Measured round-trip time.
    rtt: Option<Duration>,
    /// Number of successful reconnections.
    reconnect_count: u32,
}

impl SessionState {
    /// Create a new session state with the given session key.
    pub fn new(session_key: [u8; SESSION_KEY_LEN]) -> Self {
        Self {
            session_key,
            status: SessionStatus::Disconnected,
            client_nonce: 0,
            last_confirmed_generation: 0,
            last_confirmed_input_seq: 0,
            created_at: Instant::now(),
            last_server_activity: None,
            last_client_activity: None,
            rtt: None,
            reconnect_count: 0,
        }
    }

    /// Get the session key.
    pub fn session_key(&self) -> &[u8; SESSION_KEY_LEN] {
        &self.session_key
    }

    /// Get the current status.
    pub fn status(&self) -> SessionStatus {
        self.status
    }

    /// Set the session status.
    pub fn set_status(&mut self, status: SessionStatus) {
        self.status = status;
    }

    /// Get and increment the client nonce.
    pub fn next_nonce(&mut self) -> u64 {
        let nonce = self.client_nonce;
        self.client_nonce += 1;
        nonce
    }

    /// Get the last confirmed terminal state generation.
    pub fn last_confirmed_generation(&self) -> u64 {
        self.last_confirmed_generation
    }

    /// Update the last confirmed generation.
    pub fn confirm_generation(&mut self, generation: u64) {
        if generation > self.last_confirmed_generation {
            self.last_confirmed_generation = generation;
        }
    }

    /// Get the last confirmed input sequence.
    pub fn last_confirmed_input_seq(&self) -> u64 {
        self.last_confirmed_input_seq
    }

    /// Update the last confirmed input sequence.
    pub fn confirm_input_seq(&mut self, seq: u64) {
        if seq > self.last_confirmed_input_seq {
            self.last_confirmed_input_seq = seq;
        }
    }

    /// Record server activity.
    pub fn record_server_activity(&mut self) {
        self.last_server_activity = Some(Instant::now());
    }

    /// Record client activity.
    pub fn record_client_activity(&mut self) {
        self.last_client_activity = Some(Instant::now());
    }

    /// Update measured RTT.
    pub fn update_rtt(&mut self, rtt: Duration) {
        self.rtt = Some(rtt);
    }

    /// Get the current RTT estimate.
    pub fn rtt(&self) -> Option<Duration> {
        self.rtt
    }

    /// Record a successful reconnection.
    pub fn record_reconnect(&mut self) {
        self.reconnect_count += 1;
        self.status = SessionStatus::Connected;
    }

    /// Get the reconnection count.
    pub fn reconnect_count(&self) -> u32 {
        self.reconnect_count
    }

    /// Check if the session has expired.
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > SESSION_TIMEOUT
    }

    /// Get session age.
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Get time since last server activity.
    pub fn idle_time(&self) -> Option<Duration> {
        self.last_server_activity.map(|t| t.elapsed())
    }
}

/// Tracks pending input for reliable delivery and prediction.
#[derive(Debug)]
pub struct InputTracker {
    /// Next sequence number to assign.
    next_seq: u64,
    /// Pending inputs waiting for server confirmation.
    pending: VecDeque<PendingInput>,
    /// Last sequence confirmed by server.
    last_confirmed: u64,
}

/// A pending input waiting for confirmation.
#[derive(Debug, Clone)]
struct PendingInput {
    /// Sequence number.
    seq: u64,
    /// Input data.
    #[allow(dead_code)] // Will be used for replay on reconnect
    data: Vec<u8>,
    /// When this was sent.
    sent_at: Instant,
    /// Whether this input is predictable (can show locally).
    #[allow(dead_code)] // Will be used for prediction display
    predictable: bool,
}

impl InputTracker {
    /// Create a new input tracker.
    pub fn new() -> Self {
        Self {
            next_seq: 1, // Start at 1, 0 means "no input"
            pending: VecDeque::new(),
            last_confirmed: 0,
        }
    }

    /// Create an input tracker starting from a given sequence.
    pub fn from_seq(last_confirmed: u64) -> Self {
        Self {
            next_seq: last_confirmed + 1,
            pending: VecDeque::new(),
            last_confirmed,
        }
    }

    /// Record new input, returning the sequence number.
    pub fn push(&mut self, data: Vec<u8>, predictable: bool) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;

        self.pending.push_back(PendingInput {
            seq,
            data,
            sent_at: Instant::now(),
            predictable,
        });

        // Limit pending size
        while self.pending.len() > MAX_PENDING_PREDICTIONS {
            self.pending.pop_front();
        }

        seq
    }

    /// Confirm inputs up to and including the given sequence.
    pub fn confirm(&mut self, seq: u64) {
        if seq <= self.last_confirmed {
            return;
        }

        self.last_confirmed = seq;

        // Remove confirmed inputs
        while let Some(front) = self.pending.front() {
            if front.seq <= seq {
                self.pending.pop_front();
            } else {
                break;
            }
        }
    }

    /// Get the last confirmed sequence number.
    pub fn last_confirmed(&self) -> u64 {
        self.last_confirmed
    }

    /// Get the number of pending inputs.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Check if there are pending inputs.
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Get pending inputs for replay (after reconnection).
    pub fn pending_for_replay(&self) -> impl Iterator<Item = (u64, &[u8])> {
        self.pending.iter().map(|p| (p.seq, p.data.as_slice()))
    }

    /// Get the oldest pending input's age.
    pub fn oldest_pending_age(&self) -> Option<Duration> {
        self.pending.front().map(|p| p.sent_at.elapsed())
    }

    /// Clear all pending inputs (e.g., on session reset).
    pub fn clear(&mut self) {
        self.pending.clear();
    }
}

impl Default for InputTracker {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_status_is_active() {
        assert!(!SessionStatus::Disconnected.is_active());
        assert!(!SessionStatus::Connecting.is_active());
        assert!(SessionStatus::Connected.is_active());
        assert!(SessionStatus::Reconnecting.is_active());
        assert!(!SessionStatus::Closed.is_active());
        assert!(!SessionStatus::Expired.is_active());
    }

    #[test]
    fn session_status_can_reconnect() {
        assert!(SessionStatus::Disconnected.can_reconnect());
        assert!(!SessionStatus::Connecting.can_reconnect());
        assert!(SessionStatus::Connected.can_reconnect());
        assert!(SessionStatus::Reconnecting.can_reconnect());
        assert!(!SessionStatus::Closed.can_reconnect());
        assert!(!SessionStatus::Expired.can_reconnect());
    }

    #[test]
    fn session_state_new() {
        let key = [0xAB; 32];
        let state = SessionState::new(key);

        assert_eq!(state.session_key(), &key);
        assert_eq!(state.status(), SessionStatus::Disconnected);
        assert_eq!(state.last_confirmed_generation(), 0);
        assert_eq!(state.last_confirmed_input_seq(), 0);
        assert_eq!(state.reconnect_count(), 0);
    }

    #[test]
    fn session_state_nonce_increments() {
        let key = [0xAB; 32];
        let mut state = SessionState::new(key);

        assert_eq!(state.next_nonce(), 0);
        assert_eq!(state.next_nonce(), 1);
        assert_eq!(state.next_nonce(), 2);
    }

    #[test]
    fn session_state_confirm_generation() {
        let key = [0xAB; 32];
        let mut state = SessionState::new(key);

        state.confirm_generation(5);
        assert_eq!(state.last_confirmed_generation(), 5);

        // Can't go backwards
        state.confirm_generation(3);
        assert_eq!(state.last_confirmed_generation(), 5);

        // Can go forwards
        state.confirm_generation(10);
        assert_eq!(state.last_confirmed_generation(), 10);
    }

    #[test]
    fn session_state_status_transitions() {
        let key = [0xAB; 32];
        let mut state = SessionState::new(key);

        state.set_status(SessionStatus::Connecting);
        assert_eq!(state.status(), SessionStatus::Connecting);

        state.set_status(SessionStatus::Connected);
        assert_eq!(state.status(), SessionStatus::Connected);

        state.record_reconnect();
        assert_eq!(state.reconnect_count(), 1);
        assert_eq!(state.status(), SessionStatus::Connected);
    }

    #[test]
    fn input_tracker_new() {
        let tracker = InputTracker::new();
        assert_eq!(tracker.last_confirmed(), 0);
        assert_eq!(tracker.pending_count(), 0);
        assert!(!tracker.has_pending());
    }

    #[test]
    fn input_tracker_push_and_confirm() {
        let mut tracker = InputTracker::new();

        let seq1 = tracker.push(vec![1, 2, 3], true);
        let seq2 = tracker.push(vec![4, 5, 6], true);
        let seq3 = tracker.push(vec![7, 8, 9], false);

        assert_eq!(seq1, 1);
        assert_eq!(seq2, 2);
        assert_eq!(seq3, 3);
        assert_eq!(tracker.pending_count(), 3);

        tracker.confirm(2);
        assert_eq!(tracker.last_confirmed(), 2);
        assert_eq!(tracker.pending_count(), 1);

        tracker.confirm(3);
        assert_eq!(tracker.pending_count(), 0);
    }

    #[test]
    fn input_tracker_from_seq() {
        let tracker = InputTracker::from_seq(100);
        assert_eq!(tracker.last_confirmed(), 100);
    }

    #[test]
    fn input_tracker_pending_for_replay() {
        let mut tracker = InputTracker::new();

        tracker.push(vec![1, 2], true);
        tracker.push(vec![3, 4], false);

        let pending: Vec<_> = tracker.pending_for_replay().collect();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0], (1, &[1, 2][..]));
        assert_eq!(pending[1], (2, &[3, 4][..]));
    }

    #[test]
    fn input_tracker_confirm_idempotent() {
        let mut tracker = InputTracker::new();

        tracker.push(vec![1], true);
        tracker.push(vec![2], true);

        tracker.confirm(1);
        tracker.confirm(1); // Same seq
        tracker.confirm(0); // Lower seq

        assert_eq!(tracker.last_confirmed(), 1);
        assert_eq!(tracker.pending_count(), 1);
    }

    #[test]
    fn input_tracker_clear() {
        let mut tracker = InputTracker::new();

        tracker.push(vec![1], true);
        tracker.push(vec![2], true);

        assert!(tracker.has_pending());
        tracker.clear();
        assert!(!tracker.has_pending());
    }
}
