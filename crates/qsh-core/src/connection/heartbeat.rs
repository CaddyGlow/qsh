//! Mosh-style heartbeat tracking for RTT measurement.
//!
//! Uses Jacobson/Karamcheti algorithm (RFC 6298) for SRTT calculation,
//! the same algorithm used by Mosh for accurate RTT estimation.

use std::time::{Duration, Instant, SystemTime};

/// Re-export the protocol heartbeat payload for convenience.
pub use crate::protocol::HeartbeatPayload;

/// Mosh-style heartbeat tracker for RTT measurement.
///
/// Uses Jacobson/Karamcheti algorithm (RFC 6298) for SRTT calculation.
#[derive(Debug)]
pub struct HeartbeatTracker {
    /// Smoothed RTT in milliseconds.
    srtt: f64,
    /// RTT variance.
    rttvar: f64,
    /// Whether we've received at least one RTT sample.
    hit: bool,
    /// Pending heartbeats: (seq, sent_at). Supports multiple in-flight.
    pending: Vec<(u16, Instant)>,
    /// Next sequence number to use.
    next_seq: u16,
    /// Last received timestamp from peer.
    last_peer_timestamp: Option<u16>,
    /// Last received sequence from peer.
    last_peer_seq: Option<u16>,
    /// When we received the last peer timestamp.
    last_peer_received_at: Option<Instant>,
}

impl HeartbeatTracker {
    /// Initial SRTT before any measurements (ms).
    const INITIAL_SRTT: f64 = 1000.0;
    /// Initial RTTVAR before any measurements (ms).
    const INITIAL_RTTVAR: f64 = 500.0;
    /// Alpha for SRTT smoothing (1/16, slower than mosh for less jitter).
    const ALPHA: f64 = 0.0625;
    /// Beta for RTTVAR smoothing (1/4).
    const BETA: f64 = 0.25;
    /// Minimum RTO in ms.
    pub const MIN_RTO: f64 = 50.0;
    /// Maximum RTO in ms.
    pub const MAX_RTO: f64 = 1000.0;
    /// Minimum send interval (ms) - same as mosh.
    const SEND_INTERVAL_MIN: f64 = 20.0;
    /// Maximum send interval (ms) - same as mosh.
    const SEND_INTERVAL_MAX: f64 = 250.0;

    /// Create a new heartbeat tracker.
    pub fn new() -> Self {
        Self {
            srtt: Self::INITIAL_SRTT,
            rttvar: Self::INITIAL_RTTVAR,
            hit: false,
            pending: Vec::new(),
            next_seq: 1, // Start at 1, 0 means no reply
            last_peer_timestamp: None,
            last_peer_seq: None,
            last_peer_received_at: None,
        }
    }

    /// Get current timestamp (ms mod 65536) like mosh.
    pub fn timestamp16() -> u16 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| (d.as_millis() % 65536) as u16)
            .unwrap_or(0)
    }

    /// Record sending a heartbeat. Returns the heartbeat to send.
    ///
    /// Supports multiple in-flight heartbeats for accurate RTT measurement
    /// even with adaptive send intervals.
    pub fn send_heartbeat(&mut self) -> HeartbeatPayload {
        let timestamp = Self::timestamp16();
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        if self.next_seq == 0 {
            self.next_seq = 1; // Skip 0
        }
        let now = Instant::now();

        // Add to pending list (prune old entries > 5s to prevent unbounded growth)
        self.pending
            .retain(|(_, sent_at)| sent_at.elapsed().as_secs() < 5);
        self.pending.push((seq, now));

        // Include reply if we have a recent peer timestamp
        let (timestamp_reply, seq_reply) =
            if let (Some(peer_ts), Some(peer_seq), Some(received_at)) = (
                self.last_peer_timestamp,
                self.last_peer_seq,
                self.last_peer_received_at,
            ) {
                // Correct for hold time (how long we held it before sending)
                let hold_ms = received_at.elapsed().as_millis() as u16;
                (peer_ts.wrapping_add(hold_ms), peer_seq)
            } else {
                (u16::MAX, 0) // No reply yet
            };

        HeartbeatPayload {
            timestamp,
            timestamp_reply,
            seq,
            seq_reply,
        }
    }

    /// Process a received heartbeat. Returns the measured RTT if available.
    pub fn receive_heartbeat(&mut self, payload: &HeartbeatPayload) -> Option<Duration> {
        // Store peer's timestamp and seq for echoing back
        self.last_peer_timestamp = Some(payload.timestamp);
        self.last_peer_seq = Some(payload.seq);
        self.last_peer_received_at = Some(Instant::now());

        // If this is a reply, find matching pending heartbeat by sequence number
        if payload.has_reply() && payload.seq_reply != 0 {
            // Find the pending heartbeat with matching sequence number
            if let Some(idx) = self
                .pending
                .iter()
                .position(|(seq, _)| *seq == payload.seq_reply)
            {
                let (seq, sent_at) = self.pending.remove(idx);
                let rtt_ms = sent_at.elapsed().as_secs_f64() * 1000.0;

                // Ignore large values (> 5 seconds) - likely stale
                if rtt_ms < 5000.0 {
                    tracing::trace!(
                        seq_reply = payload.seq_reply,
                        seq,
                        rtt_ms,
                        srtt = self.srtt,
                        pending_count = self.pending.len(),
                        "Heartbeat RTT sample"
                    );
                    self.update_srtt(rtt_ms);
                    return Some(Duration::from_secs_f64(rtt_ms / 1000.0));
                }
            }
        }

        None
    }

    /// Update SRTT with a new sample (Jacobson/Karamcheti algorithm, same as mosh).
    fn update_srtt(&mut self, rtt: f64) {
        if !self.hit {
            // First measurement
            self.srtt = rtt;
            self.rttvar = rtt / 2.0;
            self.hit = true;
        } else {
            // Subsequent measurements
            self.rttvar = (1.0 - Self::BETA) * self.rttvar + Self::BETA * (self.srtt - rtt).abs();
            self.srtt = (1.0 - Self::ALPHA) * self.srtt + Self::ALPHA * rtt;
        }
    }

    /// Get the smoothed RTT.
    pub fn srtt(&self) -> Option<Duration> {
        if self.hit {
            Some(Duration::from_secs_f64(self.srtt / 1000.0))
        } else {
            None
        }
    }

    /// Get the smoothed RTT in milliseconds.
    pub fn srtt_ms(&self) -> f64 {
        self.srtt
    }

    /// Get the RTO (retransmission timeout).
    pub fn rto(&self) -> Duration {
        let rto = (self.srtt + 4.0 * self.rttvar).clamp(Self::MIN_RTO, Self::MAX_RTO);
        Duration::from_secs_f64(rto / 1000.0)
    }

    /// Check if we have measured RTT at least once.
    pub fn has_measurement(&self) -> bool {
        self.hit
    }

    /// Get the adaptive send interval (SRTT / 2, clamped to 20-250ms).
    ///
    /// Same algorithm as mosh: faster heartbeats for low latency,
    /// slower for high latency connections.
    pub fn send_interval(&self) -> Duration {
        let interval_ms = (self.srtt / 2.0).clamp(Self::SEND_INTERVAL_MIN, Self::SEND_INTERVAL_MAX);
        Duration::from_secs_f64(interval_ms / 1000.0)
    }
}

impl Default for HeartbeatTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_heartbeat_tracker_new() {
        let tracker = HeartbeatTracker::new();
        assert!(!tracker.has_measurement());
        assert!(tracker.srtt().is_none());
    }

    #[test]
    fn test_heartbeat_send() {
        let mut tracker = HeartbeatTracker::new();
        let hb1 = tracker.send_heartbeat();
        let hb2 = tracker.send_heartbeat();

        assert_eq!(hb1.seq, 1);
        assert_eq!(hb2.seq, 2);
        assert_eq!(hb1.seq_reply, 0); // No reply yet
    }

    #[test]
    fn test_heartbeat_receive_updates_peer_state() {
        let mut tracker = HeartbeatTracker::new();

        let incoming = HeartbeatPayload {
            timestamp: 1000,
            timestamp_reply: u16::MAX,
            seq: 5,
            seq_reply: 0,
        };

        tracker.receive_heartbeat(&incoming);

        // Next send should include reply
        let outgoing = tracker.send_heartbeat();
        assert_eq!(outgoing.seq_reply, 5);
    }

    #[test]
    fn test_heartbeat_rtt_calculation() {
        let mut tracker = HeartbeatTracker::new();

        // Send heartbeat
        let sent = tracker.send_heartbeat();

        // Simulate receiving reply after some delay
        std::thread::sleep(Duration::from_millis(10));

        let reply = HeartbeatPayload {
            timestamp: HeartbeatTracker::timestamp16(),
            timestamp_reply: sent.timestamp,
            seq: 1,
            seq_reply: sent.seq,
        };

        let rtt = tracker.receive_heartbeat(&reply);
        assert!(rtt.is_some());
        assert!(rtt.unwrap() >= Duration::from_millis(10));
        assert!(tracker.has_measurement());
    }

    #[test]
    fn test_send_interval_bounds() {
        let tracker = HeartbeatTracker::new();
        let interval = tracker.send_interval();

        // Should be within mosh bounds
        assert!(interval >= Duration::from_millis(20));
        assert!(interval <= Duration::from_millis(250));
    }

    #[test]
    fn test_rto_bounds() {
        let tracker = HeartbeatTracker::new();
        let rto = tracker.rto();

        // Should be within configured bounds
        assert!(rto >= Duration::from_millis(50));
        assert!(rto <= Duration::from_millis(1000));
    }
}
