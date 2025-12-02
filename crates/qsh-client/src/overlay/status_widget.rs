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
    pub fn update_rtt(&mut self, sample: Duration) {
        self.rtt = Some(sample);

        // Smoothed RTT: SRTT = 0.875 * SRTT + 0.125 * sample
        self.rtt_smoothed = Some(match self.rtt_smoothed {
            Some(srtt) => {
                let srtt_nanos = srtt.as_nanos() as u64;
                let sample_nanos = sample.as_nanos() as u64;
                let new_srtt = (srtt_nanos * 7 + sample_nanos) / 8;
                Duration::from_nanos(new_srtt)
            }
            None => sample,
        });

        // Jitter calculation (simplified)
        if let Some(srtt) = self.rtt_smoothed {
            let diff = if sample > srtt {
                sample - srtt
            } else {
                srtt - sample
            };
            self.jitter = Some(match self.jitter {
                Some(j) => {
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
        self.bytes_sent += bytes as u64;
    }

    /// Record bytes received.
    pub fn record_recv(&mut self, bytes: usize) {
        self.bytes_recv += bytes as u64;
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
        if let Some(rtt) = self.rtt {
            if rtt > Duration::from_millis(500) {
                return true;
            }
        }
        if let Some(loss) = self.packet_loss {
            if loss > 0.05 {
                return true;
            }
        }
        false
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

    /// Update connection status.
    pub fn set_status(&mut self, status: ConnectionStatus) {
        self.status = status;
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
        if !self.visible {
            return String::new();
        }

        let content = self.build_content();
        let mut output = String::new();

        // Build the display line
        let status_char = match self.status {
            ConnectionStatus::Connected => "+",    // checkmark substitute
            ConnectionStatus::Reconnecting => "~", // arrows substitute
            ConnectionStatus::Degraded => "!",     // warning substitute
            ConnectionStatus::Disconnected => "x",
        };

        // Build status bar content
        let user_host = self.user_host.as_deref().unwrap_or("?");
        let rtt_str = self
            .metrics
            .rtt_smoothed
            .map(|d| format!("{}ms", d.as_millis()))
            .unwrap_or_else(|| "-".to_string());

        let bar_content = format!(" qsh | {} | RTT: {} | {} ", user_host, rtt_str, status_char);

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
            ConnectionStatus::Reconnecting => "reconnecting",
            ConnectionStatus::Degraded => "degraded",
            ConnectionStatus::Disconnected => "disconnected",
        };

        let rtt_str = self
            .metrics
            .rtt_smoothed
            .map(|d| format!("{}ms", d.as_millis()))
            .unwrap_or_else(|| "?".to_string());

        format!("{} | RTT: {}", status_str, rtt_str)
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
        // SRTT should be between 100 and 200
        let srtt = metrics.rtt_smoothed.unwrap().as_millis();
        assert!(srtt > 100 && srtt < 200);
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
        let overlay = StatusOverlay::new();
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
}
