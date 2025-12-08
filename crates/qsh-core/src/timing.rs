//! Mosh-style timing utilities for RTT measurement.
//!
//! Uses 16-bit timestamps (milliseconds mod 65536) piggybacked on every message.
//! This approach is from mosh and provides accurate RTT measurement with minimal
//! overhead (4 bytes per message: timestamp + timestamp_reply).

use std::time::Instant;

/// Sentinel value indicating no timestamp reply available.
pub const TIMESTAMP_NONE: u16 = 0xFFFF;

/// Maximum RTT sample to accept (5 seconds). Larger values are likely bogus
/// (e.g., server was suspended/Ctrl-Z'd).
const MAX_RTT_SAMPLE_MS: u16 = 5000;

/// Get current timestamp as 16-bit milliseconds (wraps every ~65 seconds).
///
/// Uses a process-local epoch to avoid issues with system time changes.
pub fn timestamp16() -> u16 {
    static EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let epoch = EPOCH.get_or_init(Instant::now);
    (epoch.elapsed().as_millis() % 65536) as u16
}

/// Calculate timestamp difference handling wraparound.
#[inline]
pub fn timestamp_diff(now: u16, then: u16) -> u16 {
    now.wrapping_sub(then)
}

/// RTT tracker using RFC 6298 EWMA smoothing (same as mosh).
///
/// Tracks smoothed RTT (SRTT) and RTT variance (RTTVAR) for calculating
/// retransmission timeouts and adaptive send rates.
#[derive(Debug, Clone)]
pub struct RttTracker {
    /// Smoothed RTT estimate in milliseconds.
    srtt: f64,
    /// RTT variance estimate in milliseconds.
    rttvar: f64,
    /// Whether we've received at least one RTT sample.
    hit: bool,
}

impl Default for RttTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl RttTracker {
    /// Create a new RTT tracker with no samples.
    pub fn new() -> Self {
        Self {
            srtt: 0.0,
            rttvar: 0.0,
            hit: false,
        }
    }

    /// Process an RTT sample from a timestamp echo.
    ///
    /// Call this when receiving a message with a valid `timestamp_reply`:
    /// ```ignore
    /// let rtt_sample = timestamp_diff(timestamp16(), msg.timestamp_reply);
    /// tracker.update(rtt_sample);
    /// ```
    pub fn update(&mut self, sample_ms: u16) {
        // Ignore bogus values (likely from suspended process)
        if sample_ms >= MAX_RTT_SAMPLE_MS {
            return;
        }

        let r = sample_ms as f64;

        if !self.hit {
            // First sample: initialize directly
            self.srtt = r;
            self.rttvar = r / 2.0;
            self.hit = true;
        } else {
            // RFC 6298 EWMA update
            // RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - R|
            // SRTT = (1 - alpha) * SRTT + alpha * R
            // where alpha = 1/8, beta = 1/4
            const ALPHA: f64 = 1.0 / 8.0;
            const BETA: f64 = 1.0 / 4.0;

            self.rttvar = (1.0 - BETA) * self.rttvar + BETA * (self.srtt - r).abs();
            self.srtt = (1.0 - ALPHA) * self.srtt + ALPHA * r;
        }
    }

    /// Get smoothed RTT estimate in milliseconds.
    ///
    /// Returns None if no samples have been received yet.
    pub fn srtt(&self) -> Option<f64> {
        if self.hit {
            Some(self.srtt)
        } else {
            None
        }
    }

    /// Get RTT variance estimate in milliseconds.
    pub fn rttvar(&self) -> Option<f64> {
        if self.hit {
            Some(self.rttvar)
        } else {
            None
        }
    }

    /// Get smoothed RTT as Duration.
    pub fn srtt_duration(&self) -> Option<std::time::Duration> {
        self.srtt().map(|ms| std::time::Duration::from_millis(ms as u64))
    }

    /// Calculate RTO (retransmission timeout) per RFC 6298.
    ///
    /// RTO = SRTT + max(G, 4 * RTTVAR)
    /// where G is clock granularity (we use 1ms).
    /// Clamped to [MIN_RTO, MAX_RTO].
    pub fn rto(&self) -> std::time::Duration {
        const MIN_RTO_MS: u64 = 50;   // mosh MIN_RTO
        const MAX_RTO_MS: u64 = 1000; // mosh MAX_RTO

        let rto_ms = if self.hit {
            let rto = self.srtt + 4.0 * self.rttvar;
            (rto.ceil() as u64).clamp(MIN_RTO_MS, MAX_RTO_MS)
        } else {
            // No samples yet, use default
            1000
        };

        std::time::Duration::from_millis(rto_ms)
    }

    /// Calculate adaptive send interval (mosh-style: SRTT/2, clamped).
    ///
    /// Aims for roughly 2 frames per RTT.
    pub fn send_interval(&self) -> std::time::Duration {
        const MIN_INTERVAL_MS: u64 = 20;  // mosh SEND_INTERVAL_MIN
        const MAX_INTERVAL_MS: u64 = 250; // mosh SEND_INTERVAL_MAX

        let interval_ms = if self.hit {
            ((self.srtt / 2.0).ceil() as u64).clamp(MIN_INTERVAL_MS, MAX_INTERVAL_MS)
        } else {
            MAX_INTERVAL_MS
        };

        std::time::Duration::from_millis(interval_ms)
    }

    /// Check if we have any RTT data.
    pub fn has_data(&self) -> bool {
        self.hit
    }

    /// Reset the tracker (e.g., after reconnection).
    pub fn reset(&mut self) {
        self.srtt = 0.0;
        self.rttvar = 0.0;
        self.hit = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp16_wraps() {
        let t1 = timestamp16();
        // Should be a valid 16-bit value
        assert!(t1 <= 0xFFFF);
    }

    #[test]
    fn timestamp_diff_handles_wraparound() {
        // Normal case
        assert_eq!(timestamp_diff(100, 50), 50);

        // Wraparound case: now=10, then=65530 means 10 - 65530 = 16 (wrapped)
        assert_eq!(timestamp_diff(10, 65530), 16);
    }

    #[test]
    fn rtt_tracker_first_sample() {
        let mut tracker = RttTracker::new();
        assert!(!tracker.has_data());
        assert!(tracker.srtt().is_none());

        tracker.update(100);
        assert!(tracker.has_data());
        assert_eq!(tracker.srtt(), Some(100.0));
        assert_eq!(tracker.rttvar(), Some(50.0)); // R/2
    }

    #[test]
    fn rtt_tracker_ewma_update() {
        let mut tracker = RttTracker::new();
        tracker.update(100);

        // Second sample
        tracker.update(200);
        // SRTT = 0.875 * 100 + 0.125 * 200 = 87.5 + 25 = 112.5
        assert!((tracker.srtt().unwrap() - 112.5).abs() < 0.01);
    }

    #[test]
    fn rtt_tracker_ignores_bogus_values() {
        let mut tracker = RttTracker::new();
        tracker.update(100);
        let srtt_before = tracker.srtt();

        // Bogus value (> 5000ms)
        tracker.update(10000);
        assert_eq!(tracker.srtt(), srtt_before);
    }

    #[test]
    fn rtt_tracker_rto_bounds() {
        let mut tracker = RttTracker::new();

        // No data: default RTO
        assert_eq!(tracker.rto().as_millis(), 1000);

        // With very low RTT
        tracker.update(10);
        let rto = tracker.rto();
        assert!(rto.as_millis() >= 50); // MIN_RTO

        // Reset and set very high RTT
        tracker.reset();
        tracker.update(4000);
        let rto = tracker.rto();
        assert!(rto.as_millis() <= 1000); // MAX_RTO
    }

    #[test]
    fn rtt_tracker_send_interval() {
        let mut tracker = RttTracker::new();

        // No data: max interval
        assert_eq!(tracker.send_interval().as_millis(), 250);

        // Low RTT: min interval
        tracker.update(20);
        assert_eq!(tracker.send_interval().as_millis(), 20); // MIN

        // High RTT: SRTT/2, clamped to max
        tracker.reset();
        tracker.update(1000);
        assert_eq!(tracker.send_interval().as_millis(), 250); // MAX
    }
}
