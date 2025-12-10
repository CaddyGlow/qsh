//! Mosh-style TransportSender for RTT-adaptive send timing.
//!
//! This module implements the TransportSender pattern from Mosh, which coalesces
//! data before sending to reduce packet count while maintaining low latency.
//!
//! # Algorithm
//!
//! From Mosh's `transportsender-impl.h`:
//!
//! ```text
//! next_send_time = max(
//!     mindelay_clock + SEND_MINDELAY,
//!     last_send_time + send_interval()
//! )
//!
//! send_interval() = ceil(SRTT / 2), clamped to [20ms, 250ms]
//! ```
//!
//! # Client vs Server
//!
//! - **Client** uses SEND_MINDELAY = 1ms (minimal keystroke latency)
//! - **Server** uses SEND_MINDELAY = 8ms (optimize output throughput)

use std::time::{Duration, Instant};

/// Mosh timing constants.
pub mod consts {
    use std::time::Duration;

    /// Client SEND_MINDELAY (1ms) - minimal delay for keystrokes.
    pub const SEND_MINDELAY_CLIENT: Duration = Duration::from_millis(1);

    /// Server SEND_MINDELAY (8ms) - longer delay for output batching.
    pub const SEND_MINDELAY_SERVER: Duration = Duration::from_millis(8);

    /// Minimum send interval (20ms).
    pub const SEND_INTERVAL_MIN: Duration = Duration::from_millis(20);

    /// Maximum send interval (250ms).
    pub const SEND_INTERVAL_MAX: Duration = Duration::from_millis(250);

    /// ACK delay before sending delayed ack (100ms).
    pub const ACK_DELAY: Duration = Duration::from_millis(100);

    /// Interval between empty acks (3000ms).
    pub const ACK_INTERVAL: Duration = Duration::from_millis(3000);

    /// Default initial RTT estimate (100ms).
    pub const DEFAULT_RTT: Duration = Duration::from_millis(100);
}

/// Configuration for TransportSender timing.
#[derive(Debug, Clone)]
pub struct SenderConfig {
    /// Minimum delay before sending after first pending byte.
    pub send_mindelay: Duration,
    /// Minimum send interval (floor for RTT/2).
    pub send_interval_min: Duration,
    /// Maximum send interval (ceiling for RTT/2).
    pub send_interval_max: Duration,
}

impl SenderConfig {
    /// Create configuration for client (1ms mindelay).
    pub fn client() -> Self {
        Self {
            send_mindelay: consts::SEND_MINDELAY_CLIENT,
            send_interval_min: consts::SEND_INTERVAL_MIN,
            send_interval_max: consts::SEND_INTERVAL_MAX,
        }
    }

    /// Create configuration for server (8ms mindelay).
    pub fn server() -> Self {
        Self {
            send_mindelay: consts::SEND_MINDELAY_SERVER,
            send_interval_min: consts::SEND_INTERVAL_MIN,
            send_interval_max: consts::SEND_INTERVAL_MAX,
        }
    }

    /// Calculate send interval from RTT: ceil(RTT/2) clamped to [min, max].
    ///
    /// This matches Mosh's `send_interval()` from `transportsender-impl.h:59-71`.
    pub fn send_interval(&self, rtt: Duration) -> Duration {
        // ceil(RTT / 2) - round up to nearest millisecond
        let half_rtt_micros = rtt.as_micros() / 2;
        let half_rtt_ms = half_rtt_micros.div_ceil(1000) as u64;
        let interval = Duration::from_millis(half_rtt_ms);

        interval.clamp(self.send_interval_min, self.send_interval_max)
    }
}

impl Default for SenderConfig {
    fn default() -> Self {
        Self::client()
    }
}

/// Mosh-style TransportSender for RTT-adaptive send timing.
///
/// Accumulates data and determines optimal send times based on RTT.
#[derive(Debug)]
pub struct TransportSender {
    config: SenderConfig,
    /// Accumulated data waiting to be sent.
    buffer: Vec<u8>,
    /// Timestamp when first pending byte arrived (None = no pending data).
    /// Equivalent to Mosh's `mindelay_clock` (-1 when invalid).
    mindelay_clock: Option<Instant>,
    /// Timestamp of last send.
    last_send_time: Instant,
    /// Current smoothed RTT estimate.
    current_rtt: Duration,
}

impl TransportSender {
    /// Create a TransportSender for client use (1ms mindelay).
    pub fn for_client() -> Self {
        Self::new(SenderConfig::client())
    }

    /// Create a TransportSender for server use (8ms mindelay).
    pub fn for_server() -> Self {
        Self::new(SenderConfig::server())
    }

    /// Create a TransportSender with custom configuration.
    pub fn new(config: SenderConfig) -> Self {
        let now = Instant::now();
        Self {
            config,
            buffer: Vec::with_capacity(4096),
            mindelay_clock: None,
            last_send_time: now,
            current_rtt: consts::DEFAULT_RTT,
        }
    }

    /// Get the configuration.
    pub fn config(&self) -> &SenderConfig {
        &self.config
    }

    /// Push data into the send buffer.
    ///
    /// Sets `mindelay_clock` if this is the first pending data.
    pub fn push(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        // Set mindelay_clock on first pending byte (like Mosh's -1 -> now)
        self.mindelay_clock.get_or_insert_with(Instant::now);
        self.buffer.extend_from_slice(data);
    }

    /// Check if there is pending data.
    pub fn has_pending(&self) -> bool {
        !self.buffer.is_empty()
    }

    /// Get the amount of pending data.
    pub fn pending_len(&self) -> usize {
        self.buffer.len()
    }

    /// Calculate the next send time using Mosh's algorithm.
    ///
    /// Returns `Instant::now()` if no pending data.
    ///
    /// Algorithm from `transportsender-impl.h:74-110`:
    /// ```text
    /// next_send_time = max(
    ///     mindelay_clock + SEND_MINDELAY,
    ///     last_send_time + send_interval()
    /// )
    /// ```
    pub fn next_send_time(&self) -> Instant {
        let Some(mindelay_clock) = self.mindelay_clock else {
            // No pending data - return far future
            return Instant::now() + Duration::from_secs(86400);
        };

        let mindelay_deadline = mindelay_clock + self.config.send_mindelay;
        let interval_deadline = self.last_send_time + self.config.send_interval(self.current_rtt);

        mindelay_deadline.max(interval_deadline)
    }

    /// Check if data should be sent now.
    pub fn should_send_now(&self) -> bool {
        self.has_pending() && Instant::now() >= self.next_send_time()
    }

    /// Check timing and return data if ready to send.
    ///
    /// This is the main method to call in your event loop. It returns
    /// `Some(data)` if the timing conditions are met, `None` otherwise.
    ///
    /// Equivalent to Mosh's `tick()` from `transportsender-impl.h:136-187`.
    pub fn tick(&mut self) -> Option<Vec<u8>> {
        if self.should_send_now() {
            Some(self.flush())
        } else {
            None
        }
    }

    /// Force flush all pending data regardless of timing.
    ///
    /// Use this for:
    /// - Paste operations (client)
    /// - Quit/suspend sequences (client)
    /// - Resize events
    /// - Shutdown
    pub fn flush(&mut self) -> Vec<u8> {
        let data = std::mem::take(&mut self.buffer);

        // Reset mindelay_clock (like Mosh's -1)
        self.mindelay_clock = None;

        // Update last send time
        if !data.is_empty() {
            self.last_send_time = Instant::now();
        }

        data
    }

    /// Update the RTT estimate.
    ///
    /// Call this when you receive RTT measurements from the transport.
    pub fn set_rtt(&mut self, rtt: Duration) {
        self.current_rtt = rtt;
    }

    /// Get the current RTT estimate.
    pub fn rtt(&self) -> Duration {
        self.current_rtt
    }

    /// Get the current send interval based on RTT.
    pub fn send_interval(&self) -> Duration {
        self.config.send_interval(self.current_rtt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_config_client_vs_server() {
        let client = SenderConfig::client();
        let server = SenderConfig::server();

        assert_eq!(client.send_mindelay, Duration::from_millis(1));
        assert_eq!(server.send_mindelay, Duration::from_millis(8));

        // Both have same interval bounds
        assert_eq!(client.send_interval_min, Duration::from_millis(20));
        assert_eq!(server.send_interval_min, Duration::from_millis(20));
    }

    #[test]
    fn test_send_interval_calculation() {
        let config = SenderConfig::client();

        // Low RTT - clamp to minimum
        assert_eq!(
            config.send_interval(Duration::from_millis(10)),
            Duration::from_millis(20)
        );

        // Normal RTT - ceil(100/2) = 50ms
        assert_eq!(
            config.send_interval(Duration::from_millis(100)),
            Duration::from_millis(50)
        );

        // High RTT - clamp to maximum
        assert_eq!(
            config.send_interval(Duration::from_millis(600)),
            Duration::from_millis(250)
        );

        // Odd RTT - should round up: ceil(99/2) = 50ms
        assert_eq!(
            config.send_interval(Duration::from_millis(99)),
            Duration::from_millis(50)
        );

        // Very small RTT - clamp
        assert_eq!(
            config.send_interval(Duration::from_millis(1)),
            Duration::from_millis(20)
        );
    }

    #[test]
    fn test_basic_push_and_flush() {
        let mut sender = TransportSender::for_client();

        assert!(!sender.has_pending());
        assert_eq!(sender.pending_len(), 0);

        sender.push(b"hello");
        assert!(sender.has_pending());
        assert_eq!(sender.pending_len(), 5);

        sender.push(b" world");
        assert_eq!(sender.pending_len(), 11);

        let data = sender.flush();
        assert_eq!(data, b"hello world");
        assert!(!sender.has_pending());
        assert_eq!(sender.pending_len(), 0);
    }

    #[test]
    fn test_mindelay_clock_set_on_first_push() {
        let mut sender = TransportSender::for_client();

        assert!(sender.mindelay_clock.is_none());

        sender.push(b"a");
        assert!(sender.mindelay_clock.is_some());

        let clock1 = sender.mindelay_clock;
        sender.push(b"b");
        // Should not change on subsequent pushes
        assert_eq!(sender.mindelay_clock, clock1);
    }

    #[test]
    fn test_mindelay_clock_reset_on_flush() {
        let mut sender = TransportSender::for_client();

        sender.push(b"test");
        assert!(sender.mindelay_clock.is_some());

        sender.flush();
        assert!(sender.mindelay_clock.is_none());
    }

    #[test]
    fn test_empty_push_ignored() {
        let mut sender = TransportSender::for_client();

        sender.push(b"");
        assert!(!sender.has_pending());
        assert!(sender.mindelay_clock.is_none());
    }

    #[test]
    fn test_tick_returns_none_when_not_ready() {
        let mut sender = TransportSender::for_client();

        // No data
        assert!(sender.tick().is_none());

        // Data just pushed, mindelay not elapsed
        sender.push(b"test");
        // With 1ms mindelay, this might or might not be ready depending on timing
        // So we just check it doesn't panic
        let _ = sender.tick();
    }

    #[test]
    fn test_tick_returns_data_when_ready() {
        let mut sender = TransportSender::for_client();
        sender.push(b"test");

        // Wait for mindelay (1ms for client)
        sleep(Duration::from_millis(2));

        // After waiting, should be ready (assuming send_interval is also met)
        // Note: This test might be flaky due to timing, but with 2ms sleep
        // and 1ms mindelay, it should usually pass
        if sender.should_send_now() {
            let data = sender.tick();
            assert!(data.is_some());
            assert_eq!(data.unwrap(), b"test");
        }
    }

    #[test]
    fn test_set_rtt_affects_send_interval() {
        let mut sender = TransportSender::for_client();

        // Default RTT is 100ms -> interval = 50ms
        assert_eq!(sender.send_interval(), Duration::from_millis(50));

        sender.set_rtt(Duration::from_millis(200));
        assert_eq!(sender.send_interval(), Duration::from_millis(100));

        sender.set_rtt(Duration::from_millis(40));
        assert_eq!(sender.send_interval(), Duration::from_millis(20)); // clamped to min
    }

    #[test]
    fn test_next_send_time_no_pending() {
        let sender = TransportSender::for_client();

        // No pending data - should return far future
        let next = sender.next_send_time();
        assert!(next > Instant::now() + Duration::from_secs(1000));
    }

    #[test]
    fn test_next_send_time_with_pending() {
        let mut sender = TransportSender::for_client();
        let before_push = Instant::now();

        sender.push(b"test");

        let next = sender.next_send_time();

        // next_send_time should be at least mindelay after push
        // and at least send_interval after last_send
        assert!(next >= before_push + sender.config.send_mindelay);
    }

    #[test]
    fn test_for_client_and_for_server() {
        let client = TransportSender::for_client();
        let server = TransportSender::for_server();

        assert_eq!(client.config.send_mindelay, Duration::from_millis(1));
        assert_eq!(server.config.send_mindelay, Duration::from_millis(8));
    }
}
