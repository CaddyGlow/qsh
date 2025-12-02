//! Metrics collection for qsh connections.
//!
//! Provides connection metrics tracking including:
//! - RTT measurement with smoothing
//! - Byte counters
//! - Message counters
//! - Reconnection tracking

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Connection metrics tracking.
///
/// Tracks RTT with exponential smoothing, byte/message counts,
/// and reconnection statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionMetrics {
    /// Most recent RTT sample.
    #[serde(with = "duration_opt_millis")]
    pub rtt: Option<Duration>,
    /// Smoothed RTT estimate (EWMA).
    #[serde(with = "duration_opt_millis")]
    pub rtt_smoothed: Option<Duration>,
    /// RTT jitter/variance estimate.
    #[serde(with = "duration_opt_millis")]
    pub jitter: Option<Duration>,
    /// Estimated packet loss percentage (0.0 - 1.0).
    pub packet_loss: f64,
    /// Total bytes sent.
    pub bytes_sent: u64,
    /// Total bytes received.
    pub bytes_recv: u64,
    /// Total messages sent.
    pub messages_sent: u64,
    /// Total messages received.
    pub messages_recv: u64,
    /// Number of reconnection attempts.
    pub reconnect_count: u32,
    /// Session start timestamp (not serialized, reset on deserialize).
    #[serde(skip, default = "Instant::now")]
    pub session_start: Instant,
}

impl Default for ConnectionMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionMetrics {
    /// Create new metrics tracker.
    pub fn new() -> Self {
        Self {
            rtt: None,
            rtt_smoothed: None,
            jitter: None,
            packet_loss: 0.0,
            bytes_sent: 0,
            bytes_recv: 0,
            messages_sent: 0,
            messages_recv: 0,
            reconnect_count: 0,
            session_start: Instant::now(),
        }
    }

    /// Update RTT with a new sample.
    ///
    /// Uses exponential weighted moving average (EWMA) for smoothing:
    /// - SRTT = 0.875 * SRTT + 0.125 * sample
    /// - Jitter = 0.75 * Jitter + 0.25 * |sample - SRTT|
    pub fn update_rtt(&mut self, sample: Duration) {
        self.rtt = Some(sample);

        // Smoothed RTT calculation (RFC 6298 style)
        self.rtt_smoothed = Some(match self.rtt_smoothed {
            Some(srtt) => {
                // SRTT = 7/8 * SRTT + 1/8 * sample
                let srtt_nanos = srtt.as_nanos() as u64;
                let sample_nanos = sample.as_nanos() as u64;
                let new_srtt = (srtt_nanos * 7 + sample_nanos) / 8;
                Duration::from_nanos(new_srtt)
            }
            None => sample,
        });

        // Jitter calculation
        if let Some(srtt) = self.rtt_smoothed {
            let diff = Duration::from_nanos(sample.as_nanos().abs_diff(srtt.as_nanos()) as u64);
            self.jitter = Some(match self.jitter {
                Some(j) => {
                    // Jitter = 3/4 * Jitter + 1/4 * diff
                    let j_nanos = j.as_nanos() as u64;
                    let diff_nanos = diff.as_nanos() as u64;
                    Duration::from_nanos((j_nanos * 3 + diff_nanos) / 4)
                }
                None => diff,
            });
        }
    }

    /// Record bytes sent.
    pub fn record_send(&mut self, bytes: usize) {
        self.bytes_sent = self.bytes_sent.saturating_add(bytes as u64);
        self.messages_sent = self.messages_sent.saturating_add(1);
    }

    /// Record bytes received.
    pub fn record_recv(&mut self, bytes: usize) {
        self.bytes_recv = self.bytes_recv.saturating_add(bytes as u64);
        self.messages_recv = self.messages_recv.saturating_add(1);
    }

    /// Record a reconnection.
    pub fn record_reconnect(&mut self) {
        self.reconnect_count = self.reconnect_count.saturating_add(1);
    }

    /// Update packet loss estimate.
    pub fn update_packet_loss(&mut self, loss: f64) {
        self.packet_loss = loss.clamp(0.0, 1.0);
    }

    /// Get session duration.
    pub fn session_duration(&self) -> Duration {
        self.session_start.elapsed()
    }

    /// Check if connection quality is degraded.
    ///
    /// Returns true if:
    /// - RTT > 500ms
    /// - Packet loss > 5%
    pub fn is_degraded(&self) -> bool {
        if let Some(rtt) = self.rtt_smoothed.or(self.rtt)
            && rtt > Duration::from_millis(500)
        {
            return true;
        }
        self.packet_loss > 0.05
    }

    /// Format RTT for display.
    pub fn rtt_display(&self) -> String {
        self.rtt_smoothed
            .or(self.rtt)
            .map(|d| format!("{}ms", d.as_millis()))
            .unwrap_or_else(|| "-".to_string())
    }

    /// Format bandwidth for display (bytes/sec).
    pub fn bandwidth_display(&self) -> String {
        let duration = self.session_duration();
        if duration.is_zero() {
            return "-".to_string();
        }
        let secs = duration.as_secs_f64();
        let total = self.bytes_sent + self.bytes_recv;
        let bps = total as f64 / secs;

        if bps >= 1_000_000.0 {
            format!("{:.1} MB/s", bps / 1_000_000.0)
        } else if bps >= 1_000.0 {
            format!("{:.1} KB/s", bps / 1_000.0)
        } else {
            format!("{:.0} B/s", bps)
        }
    }

    /// Reset all counters (useful after reconnect).
    pub fn reset_counters(&mut self) {
        self.bytes_sent = 0;
        self.bytes_recv = 0;
        self.messages_sent = 0;
        self.messages_recv = 0;
        // Keep RTT estimates and session start
    }
}

/// Serde helper for optional Duration as milliseconds.
mod duration_opt_millis {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(value: &Option<Duration>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(d) => d.as_millis().serialize(serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<u64> = Option::deserialize(deserializer)?;
        Ok(opt.map(Duration::from_millis))
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_new() {
        let metrics = ConnectionMetrics::new();

        assert!(metrics.rtt.is_none());
        assert!(metrics.rtt_smoothed.is_none());
        assert!(metrics.jitter.is_none());
        assert_eq!(metrics.packet_loss, 0.0);
        assert_eq!(metrics.bytes_sent, 0);
        assert_eq!(metrics.bytes_recv, 0);
        assert_eq!(metrics.messages_sent, 0);
        assert_eq!(metrics.messages_recv, 0);
        assert_eq!(metrics.reconnect_count, 0);
    }

    #[test]
    fn metrics_update_rtt_first_sample() {
        let mut metrics = ConnectionMetrics::new();

        metrics.update_rtt(Duration::from_millis(100));

        assert_eq!(metrics.rtt, Some(Duration::from_millis(100)));
        assert_eq!(metrics.rtt_smoothed, Some(Duration::from_millis(100)));
        // First sample has no jitter reference
    }

    #[test]
    fn metrics_update_rtt_smoothing() {
        let mut metrics = ConnectionMetrics::new();

        // First sample
        metrics.update_rtt(Duration::from_millis(100));
        assert_eq!(metrics.rtt_smoothed, Some(Duration::from_millis(100)));

        // Second sample - should smooth
        metrics.update_rtt(Duration::from_millis(200));
        let srtt = metrics.rtt_smoothed.unwrap();

        // SRTT = 7/8 * 100 + 1/8 * 200 = 87.5 + 25 = 112.5
        assert!(srtt.as_millis() > 100);
        assert!(srtt.as_millis() < 200);
    }

    #[test]
    fn metrics_update_rtt_jitter() {
        let mut metrics = ConnectionMetrics::new();

        metrics.update_rtt(Duration::from_millis(100));
        metrics.update_rtt(Duration::from_millis(150));

        // Should have some jitter calculated
        assert!(metrics.jitter.is_some());
        let jitter = metrics.jitter.unwrap();
        assert!(jitter.as_millis() > 0);
    }

    #[test]
    fn metrics_record_send() {
        let mut metrics = ConnectionMetrics::new();

        metrics.record_send(100);
        assert_eq!(metrics.bytes_sent, 100);
        assert_eq!(metrics.messages_sent, 1);

        metrics.record_send(50);
        assert_eq!(metrics.bytes_sent, 150);
        assert_eq!(metrics.messages_sent, 2);
    }

    #[test]
    fn metrics_record_recv() {
        let mut metrics = ConnectionMetrics::new();

        metrics.record_recv(200);
        assert_eq!(metrics.bytes_recv, 200);
        assert_eq!(metrics.messages_recv, 1);

        metrics.record_recv(300);
        assert_eq!(metrics.bytes_recv, 500);
        assert_eq!(metrics.messages_recv, 2);
    }

    #[test]
    fn metrics_record_reconnect() {
        let mut metrics = ConnectionMetrics::new();

        assert_eq!(metrics.reconnect_count, 0);

        metrics.record_reconnect();
        assert_eq!(metrics.reconnect_count, 1);

        metrics.record_reconnect();
        assert_eq!(metrics.reconnect_count, 2);
    }

    #[test]
    fn metrics_packet_loss() {
        let mut metrics = ConnectionMetrics::new();

        metrics.update_packet_loss(0.10);
        assert_eq!(metrics.packet_loss, 0.10);

        // Clamp to valid range
        metrics.update_packet_loss(1.5);
        assert_eq!(metrics.packet_loss, 1.0);

        metrics.update_packet_loss(-0.5);
        assert_eq!(metrics.packet_loss, 0.0);
    }

    #[test]
    fn metrics_is_degraded_rtt() {
        let mut metrics = ConnectionMetrics::new();

        assert!(!metrics.is_degraded());

        // High RTT = degraded
        metrics.update_rtt(Duration::from_millis(600));
        assert!(metrics.is_degraded());

        metrics.update_rtt(Duration::from_millis(100));
        // Smoothed RTT still high initially
        // After a few samples it would go down
    }

    #[test]
    fn metrics_is_degraded_packet_loss() {
        let mut metrics = ConnectionMetrics::new();

        metrics.update_packet_loss(0.03);
        assert!(!metrics.is_degraded());

        metrics.update_packet_loss(0.10);
        assert!(metrics.is_degraded());
    }

    #[test]
    fn metrics_rtt_display() {
        let mut metrics = ConnectionMetrics::new();

        assert_eq!(metrics.rtt_display(), "-");

        metrics.update_rtt(Duration::from_millis(45));
        assert_eq!(metrics.rtt_display(), "45ms");
    }

    #[test]
    fn metrics_bandwidth_display() {
        let metrics = ConnectionMetrics::new();

        // Fresh metrics with zero duration
        let display = metrics.bandwidth_display();
        // Should handle zero duration gracefully
        assert!(!display.is_empty());
    }

    #[test]
    fn metrics_reset_counters() {
        let mut metrics = ConnectionMetrics::new();

        metrics.record_send(100);
        metrics.record_recv(200);
        metrics.update_rtt(Duration::from_millis(50));

        metrics.reset_counters();

        assert_eq!(metrics.bytes_sent, 0);
        assert_eq!(metrics.bytes_recv, 0);
        assert_eq!(metrics.messages_sent, 0);
        assert_eq!(metrics.messages_recv, 0);
        // RTT should be preserved
        assert!(metrics.rtt.is_some());
    }

    #[test]
    fn metrics_session_duration() {
        let metrics = ConnectionMetrics::new();

        // Should be non-zero after creation
        std::thread::sleep(std::time::Duration::from_millis(10));
        let duration = metrics.session_duration();
        assert!(duration.as_millis() >= 10);
    }

    #[test]
    fn metrics_saturating_add() {
        let mut metrics = ConnectionMetrics::new();
        metrics.bytes_sent = u64::MAX - 10;
        metrics.messages_sent = u64::MAX - 1;

        metrics.record_send(100);

        // Should saturate, not overflow
        assert_eq!(metrics.bytes_sent, u64::MAX);
        assert_eq!(metrics.messages_sent, u64::MAX);
    }

    #[test]
    fn metrics_serialize_roundtrip() {
        let mut metrics = ConnectionMetrics::new();
        metrics.update_rtt(Duration::from_millis(50));
        metrics.record_send(100);
        metrics.record_recv(200);
        metrics.update_packet_loss(0.02);

        let json = serde_json::to_string(&metrics).unwrap();
        let restored: ConnectionMetrics = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.rtt, metrics.rtt);
        assert_eq!(restored.bytes_sent, metrics.bytes_sent);
        assert_eq!(restored.packet_loss, metrics.packet_loss);
    }
}
