//! Status overlay widget.
//!
//! Displays connection status, RTT, and other metrics.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Position of the status overlay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OverlayPosition {
    /// Top of terminal.
    Top,
    /// Bottom of terminal.
    #[default]
    Bottom,
    /// Top-right corner.
    TopRight,
}

/// Connection status indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionStatus {
    /// Connected and operational.
    Connected,
    /// Waiting for server response (stale > 250ms, like mosh "Connecting...").
    Waiting,
    /// Reconnecting after disconnect.
    Reconnecting,
    /// Degraded (high latency, packet loss).
    Degraded,
    /// Disconnected.
    Disconnected,
}

/// Rolling window duration for packet loss and RTT calculation.
const METRICS_WINDOW: Duration = Duration::from_secs(30);

/// Maximum samples to keep in rolling window (one per second for 30s).
const METRICS_MAX_SAMPLES: usize = 60;

/// A sample of packet counts for rolling window loss calculation.
#[derive(Debug, Clone, Copy)]
struct PacketSample {
    timestamp: Instant,
    sent: u64,
    lost: u64,
}

/// A sample of RTT for rolling window minimum calculation.
#[derive(Debug, Clone, Copy)]
struct RttSample {
    timestamp: Instant,
    rtt: Duration,
}

/// Connection metrics for display.
#[derive(Debug, Clone, Default)]
pub struct ConnectionMetrics {
    /// Current RTT (latest sample).
    pub rtt: Option<Duration>,
    /// Rolling minimum RTT over 30s window.
    pub rtt_min: Option<Duration>,
    /// Smoothed RTT estimate.
    pub rtt_smoothed: Option<Duration>,
    /// RTT jitter/variance.
    pub jitter: Option<Duration>,
    /// Estimated packet loss percentage (rolling 30s window).
    pub packet_loss: Option<f64>,
    /// Total bytes sent.
    pub bytes_sent: u64,
    /// Total bytes received.
    pub bytes_recv: u64,
    /// Number of reconnections.
    pub reconnect_count: u32,
    /// Session start time.
    pub session_start: Option<Instant>,
    /// Time of last received data from server (for stale detection like mosh's 250ms threshold).
    pub last_heard: Option<Instant>,
    /// Time of last successful internal keepalive (if tracked separately from data).
    pub last_keepalive: Option<Instant>,
    /// Rolling window of packet samples for loss calculation.
    packet_samples: VecDeque<PacketSample>,
    /// Rolling window of RTT samples for minimum calculation.
    rtt_samples: VecDeque<RttSample>,
}

impl ConnectionMetrics {
    /// Create new empty metrics.
    pub fn new() -> Self {
        Self {
            session_start: Some(Instant::now()),
            packet_samples: VecDeque::with_capacity(METRICS_MAX_SAMPLES),
            rtt_samples: VecDeque::with_capacity(METRICS_MAX_SAMPLES),
            ..Default::default()
        }
    }

    /// Update RTT with new sample.
    ///
    /// Tracks samples in a rolling 30s window and computes:
    /// - `rtt`: Latest sample
    /// - `rtt_min`: Minimum over the window (reflects true network latency)
    /// - `rtt_smoothed`: Latest sample (QUIC already smooths)
    /// - `jitter`: Variation between samples
    pub fn update_rtt(&mut self, sample: Duration) {
        let now = Instant::now();
        let prev = self.rtt_smoothed.unwrap_or(sample);

        self.rtt = Some(sample);
        self.rtt_smoothed = Some(sample);

        // Add sample to rolling window
        self.rtt_samples.push_back(RttSample {
            timestamp: now,
            rtt: sample,
        });

        // Prune samples older than the window
        while let Some(front) = self.rtt_samples.front() {
            if now.duration_since(front.timestamp) > METRICS_WINDOW {
                self.rtt_samples.pop_front();
            } else {
                break;
            }
        }

        // Limit buffer size
        while self.rtt_samples.len() > METRICS_MAX_SAMPLES {
            self.rtt_samples.pop_front();
        }

        // Compute 10th percentile RTT (filters out retransmission-inflated samples
        // while still reflecting current network conditions)
        if !self.rtt_samples.is_empty() {
            let mut rtts: Vec<Duration> = self.rtt_samples.iter().map(|s| s.rtt).collect();
            rtts.sort();
            // 10th percentile index (at least index 0)
            let p10_idx = (rtts.len() as f64 * 0.1).floor() as usize;
            self.rtt_min = Some(rtts[p10_idx]);
        }

        // Jitter: difference from previous sample
        let diff = Duration::from_nanos(sample.as_nanos().abs_diff(prev.as_nanos()) as u64);
        self.jitter = Some(match self.jitter {
            Some(j) => {
                // EWMA for jitter: 3/4 old + 1/4 new
                let j_nanos = j.as_nanos() as u64;
                let diff_nanos = diff.as_nanos() as u64;
                Duration::from_nanos((j_nanos * 3 + diff_nanos) / 4)
            }
            None => diff,
        });
    }

    /// Record bytes sent.
    pub fn record_send(&mut self, bytes: usize) {
        self.bytes_sent += bytes as u64;
    }

    /// Record bytes received.
    pub fn record_recv(&mut self, bytes: usize) {
        self.bytes_recv += bytes as u64;
    }

    /// Record a reconnection event.
    pub fn record_reconnect(&mut self) {
        self.reconnect_count = self.reconnect_count.saturating_add(1);
    }

    /// Update packet loss using cumulative packet counts.
    ///
    /// Calculates loss over a rolling 30-second window by comparing
    /// current counts to counts from 30 seconds ago.
    ///
    /// # Arguments
    /// * `sent` - Total packets sent (cumulative)
    /// * `lost` - Total packets lost (cumulative)
    pub fn update_packet_counts(&mut self, sent: u64, lost: u64) {
        let now = Instant::now();

        // Add new sample
        self.packet_samples.push_back(PacketSample {
            timestamp: now,
            sent,
            lost,
        });

        // Prune samples older than the window
        while let Some(front) = self.packet_samples.front() {
            if now.duration_since(front.timestamp) > METRICS_WINDOW {
                self.packet_samples.pop_front();
            } else {
                break;
            }
        }

        // Limit buffer size
        while self.packet_samples.len() > METRICS_MAX_SAMPLES {
            self.packet_samples.pop_front();
        }

        // Calculate rolling loss from oldest to newest sample
        if let (Some(oldest), Some(newest)) = (
            self.packet_samples.front(),
            self.packet_samples.back(),
        ) {
            let sent_delta = newest.sent.saturating_sub(oldest.sent);
            let lost_delta = newest.lost.saturating_sub(oldest.lost);

            if sent_delta > 0 {
                let loss = (lost_delta as f64 / sent_delta as f64).clamp(0.0, 1.0);
                self.packet_loss = Some(loss);
            }
        }
    }

    /// Update packet loss ratio directly (0.0 - 1.0).
    ///
    /// Prefer `update_packet_counts()` for rolling window calculation.
    /// This method is kept for backward compatibility.
    pub fn update_packet_loss(&mut self, loss: f64) {
        self.packet_loss = Some(loss.clamp(0.0, 1.0));
    }

    /// Get session duration.
    pub fn session_duration(&self) -> Duration {
        self.session_start
            .map(|t| t.elapsed())
            .unwrap_or(Duration::ZERO)
    }

    /// Check if connection quality is degraded.
    pub fn is_degraded(&self) -> bool {
        // Consider degraded if RTT > 500ms or packet loss > 5%
        if let Some(rtt) = self.rtt
            && rtt > Duration::from_millis(500)
        {
            return true;
        }
        if let Some(loss) = self.packet_loss
            && loss > 0.05
        {
            return true;
        }
        false
    }

    /// Record that we received data from the server.
    pub fn record_heard(&mut self) {
        self.last_heard = Some(Instant::now());
    }

    /// Record that a keepalive was acknowledged.
    pub fn record_keepalive(&mut self) {
        self.last_keepalive = Some(Instant::now());
    }

    /// Latest moment we know the connection was alive (data or keepalive).
    pub fn last_alive(&self) -> Option<Instant> {
        match (self.last_heard, self.last_keepalive) {
            (Some(h), Some(k)) => Some(std::cmp::max(h, k)),
            (Some(h), None) => Some(h),
            (None, Some(k)) => Some(k),
            (None, None) => None,
        }
    }

    /// Get time since last heard from server.
    pub fn time_since_heard(&self) -> Option<Duration> {
        self.last_heard.map(|t| t.elapsed())
    }

    /// Check if connection appears stale (no data for threshold duration).
    /// Default threshold is 250ms (like mosh).
    pub fn is_stale(&self) -> bool {
        self.is_stale_threshold(Duration::from_millis(250))
    }

    /// Check if connection appears stale with custom threshold.
    pub fn is_stale_threshold(&self, threshold: Duration) -> bool {
        self.time_since_heard()
            .map(|elapsed| elapsed > threshold)
            .unwrap_or(false)
    }
}

/// Status overlay widget.
#[derive(Debug)]
pub struct StatusOverlay {
    /// Whether overlay is visible.
    visible: bool,
    /// Display position.
    position: OverlayPosition,
    /// Current connection status.
    status: ConnectionStatus,
    /// Connection metrics.
    metrics: ConnectionMetrics,
    /// User@host string.
    user_host: Option<String>,
    /// Optional status message to display.
    message: Option<String>,
    /// When the current status was set (for elapsed display).
    status_since: Option<std::time::Instant>,
}

impl Default for StatusOverlay {
    fn default() -> Self {
        Self::new()
    }
}

impl StatusOverlay {
    /// Create a new status overlay.
    pub fn new() -> Self {
        Self {
            visible: false,
            position: OverlayPosition::Bottom,
            status: ConnectionStatus::Disconnected,
            metrics: ConnectionMetrics::new(),
            user_host: None,
            message: None,
            status_since: None,
        }
    }

    /// Set the user@host string.
    pub fn set_user_host(&mut self, user_host: String) {
        self.user_host = Some(user_host);
    }

    /// Set visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Toggle visibility.
    pub fn toggle(&mut self) {
        self.visible = !self.visible;
    }

    /// Check if visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Set position.
    pub fn set_position(&mut self, position: OverlayPosition) {
        self.position = position;
    }

    /// Get position.
    pub fn position(&self) -> OverlayPosition {
        self.position
    }

    /// Set an optional status message.
    pub fn set_message(&mut self, message: Option<String>) {
        self.message = message;
    }

    /// Clear any message.
    pub fn clear_message(&mut self) {
        self.message = None;
    }

    /// Get current connection status.
    pub fn status(&self) -> ConnectionStatus {
        self.status
    }

    /// Update connection status.
    pub fn set_status(&mut self, status: ConnectionStatus) {
        self.status = status;
        self.status_since = Some(std::time::Instant::now());
    }

    /// Update metrics.
    pub fn update_metrics(&mut self, metrics: ConnectionMetrics) {
        self.metrics = metrics;
    }

    /// Get mutable reference to metrics.
    pub fn metrics_mut(&mut self) -> &mut ConnectionMetrics {
        &mut self.metrics
    }

    /// Render the status overlay as ANSI sequences.
    ///
    /// Returns empty string if not visible.
    pub fn render(&self, cols: u16) -> String {
        // Force-show overlay during reconnection/disconnection (like mosh)
        let should_render = self.visible
            || matches!(
                self.status,
                ConnectionStatus::Reconnecting | ConnectionStatus::Disconnected
            );
        if !should_render {
            return String::new();
        }

        let _content = self.build_content();
        let mut output = String::new();

        // Build the display line
        let status_char = match self.status {
            ConnectionStatus::Connected => "+",    // checkmark substitute
            ConnectionStatus::Waiting => "?",      // waiting for server
            ConnectionStatus::Reconnecting => "~", // arrows substitute
            ConnectionStatus::Degraded => "!",     // warning substitute
            ConnectionStatus::Disconnected => "x",
        };
        let status_elapsed = self
            .metrics
            .last_alive()
            .map(|t| t.elapsed())
            .or_else(|| self.status_since.map(|t| t.elapsed()));

        // Build status bar content
        let user_host = self.user_host.as_deref().unwrap_or("?");
        // Use rolling minimum RTT (true network latency without retransmission delays)
        let rtt_str = self
            .metrics
            .rtt_min
            .or(self.metrics.rtt_smoothed) // fallback if no min yet
            .map(|d| format!("{}ms", d.as_millis()))
            .unwrap_or_else(|| "-".to_string());
        let loss_str = self
            .metrics
            .packet_loss
            .map(|l| format!("{:.1}%", l * 100.0))
            .unwrap_or_else(|| "-".to_string());

        // Show elapsed time when waiting/reconnecting/disconnected
        let status_str = match self.status {
            ConnectionStatus::Waiting
            | ConnectionStatus::Reconnecting
            | ConnectionStatus::Disconnected => {
                let symbol = match self.status {
                    ConnectionStatus::Waiting => "?",
                    ConnectionStatus::Reconnecting => "~",
                    ConnectionStatus::Disconnected => "x",
                    _ => unreachable!(),
                };
                status_elapsed
                    .map(|elapsed| format_duration(symbol, elapsed))
                    .unwrap_or_else(|| symbol.to_string())
            }
            _ => status_char.to_string(),
        };

        let bar_content = format!(
            " qsh | {} | RTT: {} | loss: {} | {} ",
            user_host, rtt_str, loss_str, status_str
        );
        let bar_content = if let Some(msg) = &self.message {
            format!("{bar_content}| {msg} ")
        } else {
            bar_content
        };

        // Pad or truncate to fit width
        let bar_width = cols as usize;
        let display = if bar_content.len() >= bar_width {
            bar_content[..bar_width].to_string()
        } else {
            let padding = bar_width - bar_content.len();
            let left_pad = padding / 2;
            let right_pad = padding - left_pad;
            format!(
                "{}{}{}",
                " ".repeat(left_pad),
                bar_content,
                " ".repeat(right_pad)
            )
        };

        // Position based on setting
        let row = match self.position {
            OverlayPosition::Top => 1,
            OverlayPosition::Bottom => 1, // Would need terminal height
            OverlayPosition::TopRight => 1,
        };

        // Save cursor, move to position, style, print, reset, restore
        output.push_str("\x1b[s"); // Save cursor
        output.push_str(&format!("\x1b[{};1H", row)); // Move to row
        output.push_str("\x1b[7m"); // Reverse video
        output.push_str(&display);
        output.push_str("\x1b[0m"); // Reset
        output.push_str("\x1b[u"); // Restore cursor

        output
    }

    /// Build content string (internal).
    fn build_content(&self) -> String {
        let status_str = match self.status {
            ConnectionStatus::Connected => "connected",
            ConnectionStatus::Waiting => "waiting",
            ConnectionStatus::Reconnecting => "reconnecting",
            ConnectionStatus::Degraded => "degraded",
            ConnectionStatus::Disconnected => "disconnected",
        };

        let rtt_str = self
            .metrics
            .rtt_min
            .or(self.metrics.rtt_smoothed)
            .map(|d| format!("{}ms", d.as_millis()))
            .unwrap_or_else(|| "?".to_string());

        let elapsed_str = self
            .metrics
            .last_alive()
            .or(self.status_since)
            .map(|t| format!("{}s", t.elapsed().as_secs()))
            .unwrap_or_else(|| "-s".to_string());

        format!("{} | RTT: {} | {}", status_str, rtt_str, elapsed_str)
    }
}

fn format_duration(symbol: &str, elapsed: Duration) -> String {
    let secs = elapsed.as_secs_f32();
    if secs < 1.0 {
        format!("{symbol} {:.0}ms", elapsed.as_millis())
    } else {
        format!("{symbol} {:.1}s", secs)
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
        assert!(metrics.session_start.is_some());
        assert!(metrics.rtt.is_none());
    }

    #[test]
    fn metrics_update_rtt() {
        let mut metrics = ConnectionMetrics::new();

        metrics.update_rtt(Duration::from_millis(100));
        assert_eq!(metrics.rtt, Some(Duration::from_millis(100)));
        assert_eq!(metrics.rtt_smoothed, Some(Duration::from_millis(100)));

        metrics.update_rtt(Duration::from_millis(200));
        // No additional smoothing - Quinn's RTT is already smoothed
        assert_eq!(metrics.rtt_smoothed, Some(Duration::from_millis(200)));
        // Jitter should reflect the change
        assert!(metrics.jitter.is_some());
    }

    #[test]
    fn metrics_record_bytes() {
        let mut metrics = ConnectionMetrics::new();

        metrics.record_send(100);
        metrics.record_send(50);
        assert_eq!(metrics.bytes_sent, 150);

        metrics.record_recv(200);
        assert_eq!(metrics.bytes_recv, 200);
    }

    #[test]
    fn metrics_record_reconnect() {
        let mut metrics = ConnectionMetrics::new();
        metrics.record_reconnect();
        metrics.record_reconnect();
        assert_eq!(metrics.reconnect_count, 2);
    }

    #[test]
    fn metrics_is_degraded() {
        let mut metrics = ConnectionMetrics::new();

        // Not degraded initially
        assert!(!metrics.is_degraded());

        // Degraded with high RTT
        metrics.rtt = Some(Duration::from_millis(600));
        assert!(metrics.is_degraded());

        metrics.rtt = Some(Duration::from_millis(100));
        assert!(!metrics.is_degraded());

        // Degraded with high packet loss
        metrics.packet_loss = Some(0.10);
        assert!(metrics.is_degraded());
    }

    #[test]
    fn overlay_new() {
        let overlay = StatusOverlay::new();
        assert!(!overlay.is_visible());
        assert_eq!(overlay.position, OverlayPosition::Bottom);
    }

    #[test]
    fn overlay_toggle() {
        let mut overlay = StatusOverlay::new();

        assert!(!overlay.is_visible());
        overlay.toggle();
        assert!(overlay.is_visible());
        overlay.toggle();
        assert!(!overlay.is_visible());
    }

    #[test]
    fn overlay_render_when_hidden() {
        let mut overlay = StatusOverlay::new();
        // Set to Connected status (Disconnected/Reconnecting force-render even when hidden)
        overlay.set_status(ConnectionStatus::Connected);
        assert!(overlay.render(80).is_empty());
    }

    #[test]
    fn overlay_render_when_visible() {
        let mut overlay = StatusOverlay::new();
        overlay.set_visible(true);
        overlay.set_user_host("user@host".to_string());
        overlay.set_status(ConnectionStatus::Connected);

        let rendered = overlay.render(80);

        assert!(!rendered.is_empty());
        assert!(rendered.contains("\x1b[s")); // Save cursor
        assert!(rendered.contains("\x1b[7m")); // Reverse video
        assert!(rendered.contains("qsh"));
        assert!(rendered.contains("user@host"));
        assert!(rendered.contains("\x1b[u")); // Restore cursor
    }

    #[test]
    fn overlay_status_changes() {
        let mut overlay = StatusOverlay::new();
        overlay.set_visible(true);

        overlay.set_status(ConnectionStatus::Connected);
        let rendered = overlay.render(80);
        assert!(rendered.contains('+')); // Connected indicator

        overlay.set_status(ConnectionStatus::Reconnecting);
        let rendered = overlay.render(80);
        assert!(rendered.contains('~')); // Reconnecting indicator

        overlay.set_status(ConnectionStatus::Degraded);
        let rendered = overlay.render(80);
        assert!(rendered.contains('!')); // Degraded indicator
    }

    #[test]
    fn overlay_position() {
        let mut overlay = StatusOverlay::new();

        overlay.set_position(OverlayPosition::Top);
        assert_eq!(overlay.position, OverlayPosition::Top);

        overlay.set_position(OverlayPosition::TopRight);
        assert_eq!(overlay.position, OverlayPosition::TopRight);
    }

    #[test]
    fn overlay_metrics_update() {
        let mut overlay = StatusOverlay::new();
        overlay.set_visible(true);

        overlay.metrics_mut().update_rtt(Duration::from_millis(50));

        let rendered = overlay.render(80);
        assert!(rendered.contains("50ms"));
    }

    #[test]
    fn metrics_last_heard() {
        let mut metrics = ConnectionMetrics::new();

        // Initially no last_heard
        assert!(metrics.last_heard.is_none());
        assert!(metrics.time_since_heard().is_none());
        assert!(!metrics.is_stale()); // not stale if never heard

        // Record hearing from server
        metrics.record_heard();
        assert!(metrics.last_heard.is_some());
        assert!(metrics.time_since_heard().is_some());
        assert!(!metrics.is_stale()); // just heard, not stale
    }

    #[test]
    fn metrics_stale_detection() {
        let mut metrics = ConnectionMetrics::new();
        metrics.record_heard();

        // Not stale immediately
        assert!(!metrics.is_stale());

        // Stale with very short threshold
        assert!(metrics.is_stale_threshold(Duration::ZERO));
    }

    #[test]
    fn overlay_waiting_status() {
        let mut overlay = StatusOverlay::new();
        overlay.set_visible(true);
        overlay.set_user_host("user@host".into());
        overlay.set_status(ConnectionStatus::Waiting);

        // Simulate keepalive more recent than last_heard so we pick the freshest signal.
        overlay.status_since = Some(Instant::now() - Duration::from_secs(30));
        overlay.metrics.last_heard = Some(Instant::now() - Duration::from_secs(10));
        overlay.metrics.last_keepalive = Some(Instant::now() - Duration::from_millis(1500));

        let rendered = overlay.render(80);
        assert!(rendered.contains('?')); // Waiting indicator

        let parts: Vec<_> = rendered.split('|').map(str::trim).collect();
        let status_part = parts.last().unwrap_or(&"");
        assert!(status_part.contains('s')); // uses keepalive-based elapsed (~1.5s)
        assert!(!status_part.contains("30s")); // should pick most recent signal
    }

    #[test]
    fn metrics_rolling_packet_loss() {
        let mut metrics = ConnectionMetrics::new();

        // Initial state - no loss data
        assert!(metrics.packet_loss.is_none());

        // First sample: 100 sent, 0 lost
        metrics.update_packet_counts(100, 0);
        // Need at least 2 samples for delta calculation
        assert!(metrics.packet_loss.is_none() || metrics.packet_loss == Some(0.0));

        // Second sample: 200 sent, 10 lost (10% loss in this window)
        metrics.update_packet_counts(200, 10);
        assert!(metrics.packet_loss.is_some());
        let loss = metrics.packet_loss.unwrap();
        assert!((loss - 0.10).abs() < 0.01, "Expected ~10% loss, got {}", loss);

        // Third sample: 300 sent, 10 lost (0% loss in this window)
        metrics.update_packet_counts(300, 10);
        let loss = metrics.packet_loss.unwrap();
        // Delta: 100 sent, 0 lost -> 0% loss in latest window
        // But overall window still includes older samples
        assert!(loss <= 0.10);
    }

    #[test]
    fn metrics_rolling_loss_no_packets() {
        let mut metrics = ConnectionMetrics::new();

        // No packets sent - should not panic or produce NaN
        metrics.update_packet_counts(0, 0);
        metrics.update_packet_counts(0, 0);
        assert!(
            metrics.packet_loss.is_none() || metrics.packet_loss == Some(0.0),
            "Loss should be None or 0 when no packets sent"
        );
    }

    #[test]
    fn metrics_rolling_loss_clamped() {
        let mut metrics = ConnectionMetrics::new();

        // Edge case: more lost than sent (shouldn't happen, but handle gracefully)
        metrics.update_packet_counts(100, 0);
        metrics.update_packet_counts(200, 150); // 50 lost out of 100 delta = 50%

        let loss = metrics.packet_loss.unwrap();
        assert!(loss <= 1.0, "Loss should be clamped to 1.0");
        assert!(loss >= 0.0, "Loss should be non-negative");
    }
}
