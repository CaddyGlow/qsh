//! Mosh-style notification bar.
//!
//! Provides a notification bar that mimics mosh's behavior:
//! - Auto-shows when server contact is late (6.5s threshold)
//! - Shows "Last reply" vs "Last contact" based on which is stale
//! - Blue background with white bold text
//! - Displays quit keystroke hint

use std::time::{Duration, Instant};

mod format;
mod render;
mod state;

#[cfg(test)]
mod tests;

use format::{format_escape_key, format_rtt};
pub use render::NotificationStyle;
use render::{NotificationMetrics, render, render_with_cursor};
use state::NotificationState;

/// Mosh-style notification engine.
///
/// Tracks connection state and renders a notification bar when the
/// connection appears stale or there's a message to display.
#[derive(Debug)]
pub struct NotificationEngine {
    /// Notification state (timing, messages).
    state: NotificationState,
    /// Display style (minimal or enhanced).
    style: NotificationStyle,
    /// Metrics for enhanced display.
    metrics: NotificationMetrics,
    /// Smoothed RTT from quiche (QUIC layer).
    quiche_srtt: Option<f64>,
    /// RTTVAR for quiche smoothing.
    quiche_rttvar: Option<f64>,
    /// Whether we've received at least one quiche RTT sample.
    quiche_hit: bool,
}

impl Default for NotificationEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl NotificationEngine {
    /// Alpha for quiche SRTT smoothing (1/8, same as TCP/mosh).
    const QUICHE_ALPHA: f64 = 0.125;
    /// Beta for quiche RTTVAR smoothing (1/4).
    const QUICHE_BETA: f64 = 0.25;

    /// Create a new notification engine.
    pub fn new() -> Self {
        Self {
            state: NotificationState::new(),
            style: NotificationStyle::default(),
            metrics: NotificationMetrics::new(),
            quiche_srtt: None,
            quiche_rttvar: None,
            quiche_hit: false,
        }
    }

    /// Set the escape key string for the quit hint.
    ///
    /// # Arguments
    /// * `key_spec` - Key specification like "ctrl+^" or "ctrl+]"
    pub fn set_escape_key(&mut self, key_spec: &str) {
        self.state.escape_key_string = format_escape_key(key_spec);
    }

    /// Set the display style.
    pub fn set_style(&mut self, style: NotificationStyle) {
        self.style = style;
    }

    /// Set user@host for enhanced display.
    pub fn set_user_host(&mut self, user_host: String) {
        self.metrics.set_user_host(user_host);
    }

    /// Update RTT for enhanced display (from heartbeat SRTT).
    ///
    /// This also marks the connection as alive, since RTT updates mean
    /// QUIC keepalives are working even if no application data is flowing.
    pub fn update_rtt(&mut self, rtt: Duration) {
        self.metrics.update_rtt(rtt);
        // RTT update means the connection is alive (QUIC level)
        self.state.connection_alive(Instant::now());
    }

    /// Update quiche RTT with Jacobson/Karels smoothing (same algorithm as mosh).
    ///
    /// This tracks the QUIC layer's RTT separately from the heartbeat SRTT,
    /// allowing comparison between application-level and transport-level measurements.
    pub fn update_quiche_rtt(&mut self, rtt: Duration) {
        let rtt_ms = rtt.as_secs_f64() * 1000.0;

        // Filter out bogus values - quiche SRTT grows unboundedly due to
        // congestion control (includes RTO backoff). Real RTT is never > 500ms.
        if rtt_ms > 500.0 {
            return;
        }

        if !self.quiche_hit {
            // First measurement: initialize SRTT and RTTVAR
            self.quiche_srtt = Some(rtt_ms);
            self.quiche_rttvar = Some(rtt_ms / 2.0);
            self.quiche_hit = true;
        } else if let (Some(srtt), Some(rttvar)) = (self.quiche_srtt, self.quiche_rttvar) {
            // Subsequent measurements: Jacobson/Karels algorithm (RFC 6298)
            let new_rttvar =
                (1.0 - Self::QUICHE_BETA) * rttvar + Self::QUICHE_BETA * (srtt - rtt_ms).abs();
            let new_srtt = (1.0 - Self::QUICHE_ALPHA) * srtt + Self::QUICHE_ALPHA * rtt_ms;
            self.quiche_srtt = Some(new_srtt);
            self.quiche_rttvar = Some(new_rttvar);
        }
    }

    /// Get the smoothed quiche RTT.
    pub fn quiche_srtt(&self) -> Option<Duration> {
        self.quiche_srtt
            .map(|ms| Duration::from_secs_f64(ms / 1000.0))
    }

    /// Update packet loss for enhanced display.
    pub fn update_packet_loss(&mut self, loss: f64) {
        self.metrics.update_packet_loss(loss);
    }

    /// Record a frame for FPS calculation.
    ///
    /// Call this for each terminal output frame to maintain a rolling FPS average.
    pub fn record_frame(&mut self, timestamp: Instant) {
        self.metrics.record_frame(timestamp);
    }

    /// Set the FPS averaging window duration.
    ///
    /// # Arguments
    /// * `window` - Duration for the rolling FPS window (default: 1 second)
    pub fn set_fps_window(&mut self, window: Duration) {
        self.metrics.set_fps_window(window);
    }

    /// Record that we received data from the server.
    ///
    /// This is called for any data received, including keepalives.
    pub fn server_heard(&mut self, timestamp: Instant) {
        self.state.server_heard(timestamp);
    }

    /// Record that the server acknowledged our state.
    ///
    /// This is called when we receive confirmation of input delivery.
    pub fn server_acked(&mut self, timestamp: Instant) {
        self.state.server_acked(timestamp);
    }

    /// Set a notification message.
    ///
    /// # Arguments
    /// * `msg` - The message to display
    /// * `permanent` - If false, message expires after 1 second
    /// * `show_quit` - Whether to show the quit keystroke hint
    pub fn set_notification_string(&mut self, msg: &str, permanent: bool, show_quit: bool) {
        self.state
            .set_notification_string(msg, permanent, show_quit);
    }

    /// Set a network error message (permanent, shows quit hint).
    pub fn set_network_error(&mut self, msg: &str) {
        self.state.set_network_error(msg);
    }

    /// Set a reconnecting message with error details and duration since last contact.
    ///
    /// Format: "Reconnecting: <error>. Last contact Xs ago."
    pub fn set_reconnecting(&mut self, error: &str) {
        self.state.set_reconnecting(error);
    }

    /// Update the reconnecting message with current duration.
    ///
    /// Call this periodically while reconnecting to update the "Last contact" time.
    pub fn update_reconnecting(&mut self, error: &str) {
        self.state.update_reconnecting(error);
    }

    /// Clear any network error message.
    pub fn clear_network_error(&mut self) {
        self.state.clear_network_error();
    }

    /// Clear all messages.
    pub fn clear_message(&mut self) {
        self.state.clear_message();
    }

    /// Show connection info (triggered by escape key press, like mosh).
    ///
    /// Displays RTT, frame rate, and packet loss in the notification bar.
    ///
    /// # Arguments
    /// * `frame_rate` - Optional override for frame rate (fps). If None, uses internal rolling average.
    /// * `permanent` - If true, stays visible until cleared; if false, expires after 1 second
    pub fn show_info(&mut self, frame_rate: Option<f64>, permanent: bool) {
        // Heartbeat SRTT (application-level)
        let hb_rtt_str = self
            .metrics
            .rtt
            .map(|d| format_rtt(d))
            .unwrap_or_else(|| "-".to_string());

        // Quiche SRTT (QUIC transport-level)
        let quiche_rtt_str = self
            .quiche_srtt()
            .map(|d| format_rtt(d))
            .unwrap_or_else(|| "-".to_string());

        let loss_str = self
            .metrics
            .packet_loss
            .map(|l| format!("{:.1}%", l * 100.0))
            .unwrap_or_else(|| "-".to_string());

        // Use provided frame_rate or fall back to internal rolling average
        let fps = frame_rate.or_else(|| self.metrics.fps());
        let fps_str = fps
            .map(|f| format!("{:.0}fps", f))
            .unwrap_or_else(|| "-".to_string());

        // Show both RTTs: heartbeat (app) and quiche (transport)
        let info = format!(
            "RTT: {} (quic: {}) | loss: {} | {}",
            hb_rtt_str, quiche_rtt_str, loss_str, fps_str
        );
        self.set_notification_string(&info, permanent, true);
    }

    /// Check if a transient info message is currently displayed.
    pub fn has_info_message(&self) -> bool {
        self.state.message.is_some()
            && !self.state.message_is_network_error
            && self.state.message_expiration.is_some()
    }

    /// Expire old messages.
    ///
    /// Call this periodically to clear expired non-permanent messages.
    pub fn adjust_message(&mut self) {
        self.state.adjust_message();
    }

    /// Get the recommended wait time until the next display update.
    ///
    /// Returns shorter intervals when actively counting, longer in power-save mode.
    pub fn wait_time(&self) -> Duration {
        self.state.wait_time()
    }

    /// Render the notification bar.
    ///
    /// Returns an empty string if nothing to display.
    ///
    /// # Arguments
    /// * `width` - Terminal width in columns
    pub fn render(&self, width: u16) -> String {
        render(&self.state, self.style, &self.metrics, width)
    }

    /// Render the notification bar, optionally hiding cursor if overlapped.
    ///
    /// # Arguments
    /// * `width` - Terminal width in columns
    /// * `cursor_row` - Current cursor row (0-indexed), if known
    pub fn render_with_cursor(&self, width: u16, cursor_row: Option<u16>) -> String {
        render_with_cursor(&self.state, self.style, &self.metrics, width, cursor_row)
    }
}
