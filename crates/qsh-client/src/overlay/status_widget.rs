//! Status overlay widget.
//!
//! Displays connection status, RTT, and other metrics.

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

/// Connection metrics for display.
#[derive(Debug, Clone, Default)]
pub struct ConnectionMetrics {
    /// Current RTT.
    pub rtt: Option<Duration>,
    /// Smoothed RTT estimate.
    pub rtt_smoothed: Option<Duration>,
    /// RTT jitter/variance.
    pub jitter: Option<Duration>,
    /// Estimated packet loss percentage.
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
}

impl ConnectionMetrics {
    /// Create new empty metrics.
    pub fn new() -> Self {
        Self {
            session_start: Some(Instant::now()),
            ..Default::default()
        }
    }

    /// Update RTT with new sample.
    ///
    /// Note: When using Quinn's `conn.rtt()`, the value is already smoothed
    /// by QUIC's internal RTT estimator, so we store it directly.
    pub fn update_rtt(&mut self, sample: Duration) {
        let prev = self.rtt_smoothed.unwrap_or(sample);
        self.rtt = Some(sample);
        self.rtt_smoothed = Some(sample);

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

    /// Update packet loss ratio (0.0 - 1.0).
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
        let rtt_str = self
            .metrics
            .rtt_smoothed
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
            .rtt_smoothed
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
}
