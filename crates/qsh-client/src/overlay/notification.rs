//! Mosh-style notification bar.
//!
//! Provides a notification bar that mimics mosh's behavior:
//! - Auto-shows when server contact is late (6.5s threshold)
//! - Shows "Last reply" vs "Last contact" based on which is stale
//! - Blue background with white bold text
//! - Displays quit keystroke hint

use std::time::{Duration, Instant};

/// Threshold for considering server contact "late" (show "Last contact X ago").
/// From mosh: `server_late() = (now - last_word_from_server) > 6500ms`
const SERVER_LATE_THRESHOLD: Duration = Duration::from_millis(6500);

/// Threshold for considering server reply "late" (show "Last reply X ago").
/// From mosh: `reply_late() = (now - last_acked_state) > 10000ms`
const REPLY_LATE_THRESHOLD: Duration = Duration::from_millis(10000);

/// Threshold for power-save mode (reduce update frequency).
/// From mosh: After 60s disconnect, reduce refresh rate.
const POWER_SAVE_THRESHOLD: Duration = Duration::from_secs(60);

/// Default message expiration time (non-permanent messages).
const MESSAGE_EXPIRATION: Duration = Duration::from_secs(1);

/// Notification display style.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NotificationStyle {
    /// Mosh-compatible minimal display.
    /// Only shows on timeout/errors with "Last contact Xs ago" format.
    #[default]
    Minimal,
    /// Enhanced display with RTT and metrics when visible.
    /// Format: "qsh: user@host | RTT: 50ms | loss: 0.1% | Last contact Xs ago."
    Enhanced,
}

/// Mosh-style notification engine.
///
/// Tracks connection state and renders a notification bar when the
/// connection appears stale or there's a message to display.
#[derive(Debug)]
pub struct NotificationEngine {
    /// Timestamp of last data received from server.
    last_word_from_server: Instant,
    /// Timestamp of last state acknowledgment from server.
    last_acked_state: Instant,
    /// Timestamp of last confirmed connection activity (RTT update, keepalive, etc.).
    /// This is updated even when idle, as long as QUIC reports the connection is alive.
    last_connection_alive: Instant,
    /// Escape key string for quit hint (e.g., "^\\").
    escape_key_string: String,
    /// Custom message to display.
    message: Option<String>,
    /// Whether current message is a network error.
    message_is_network_error: bool,
    /// When the current message expires.
    message_expiration: Option<Instant>,
    /// Whether to show quit keystroke hint.
    show_quit_keystroke: bool,
    /// Display style (minimal or enhanced).
    style: NotificationStyle,
    /// User@host string for enhanced display.
    user_host: Option<String>,
    /// Current RTT for enhanced display.
    rtt: Option<Duration>,
    /// Packet loss for enhanced display.
    packet_loss: Option<f64>,
}

impl Default for NotificationEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl NotificationEngine {
    /// Create a new notification engine.
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            last_word_from_server: now,
            last_acked_state: now,
            last_connection_alive: now,
            escape_key_string: "^\\".to_string(),
            message: None,
            message_is_network_error: false,
            message_expiration: None,
            show_quit_keystroke: true,
            style: NotificationStyle::default(),
            user_host: None,
            rtt: None,
            packet_loss: None,
        }
    }

    /// Set the escape key string for the quit hint.
    ///
    /// # Arguments
    /// * `key_spec` - Key specification like "ctrl+^" or "ctrl+]"
    pub fn set_escape_key(&mut self, key_spec: &str) {
        self.escape_key_string = format_escape_key(key_spec);
    }

    /// Set the display style.
    pub fn set_style(&mut self, style: NotificationStyle) {
        self.style = style;
    }

    /// Set user@host for enhanced display.
    pub fn set_user_host(&mut self, user_host: String) {
        self.user_host = Some(user_host);
    }

    /// Update RTT for enhanced display.
    ///
    /// This also marks the connection as alive, since RTT updates mean
    /// QUIC keepalives are working even if no application data is flowing.
    pub fn update_rtt(&mut self, rtt: Duration) {
        self.rtt = Some(rtt);
        // RTT update means the connection is alive (QUIC level)
        self.last_connection_alive = Instant::now();
    }

    /// Update packet loss for enhanced display.
    pub fn update_packet_loss(&mut self, loss: f64) {
        self.packet_loss = Some(loss.clamp(0.0, 1.0));
    }

    /// Record that we received data from the server.
    ///
    /// This is called for any data received, including keepalives.
    pub fn server_heard(&mut self, timestamp: Instant) {
        self.last_word_from_server = timestamp;
    }

    /// Record that the server acknowledged our state.
    ///
    /// This is called when we receive confirmation of input delivery.
    pub fn server_acked(&mut self, timestamp: Instant) {
        self.last_acked_state = timestamp;
    }

    /// Set a notification message.
    ///
    /// # Arguments
    /// * `msg` - The message to display
    /// * `permanent` - If false, message expires after 1 second
    /// * `show_quit` - Whether to show the quit keystroke hint
    pub fn set_notification_string(&mut self, msg: &str, permanent: bool, show_quit: bool) {
        self.message = Some(msg.to_string());
        self.message_is_network_error = false;
        self.message_expiration = if permanent {
            None
        } else {
            Some(Instant::now() + MESSAGE_EXPIRATION)
        };
        self.show_quit_keystroke = show_quit;
    }

    /// Set a network error message (permanent, shows quit hint).
    pub fn set_network_error(&mut self, msg: &str) {
        self.message = Some(msg.to_string());
        self.message_is_network_error = true;
        self.message_expiration = None;
        self.show_quit_keystroke = true;
    }

    /// Set a reconnecting message with error details and duration since last contact.
    ///
    /// Format: "Reconnecting: <error>. Last contact Xs ago."
    pub fn set_reconnecting(&mut self, error: &str) {
        let since_heard = std::time::Instant::now().duration_since(self.last_word_from_server);
        let duration_str = human_readable_duration(since_heard);
        let msg = format!("{} Last contact {}.", error, duration_str);
        self.message = Some(msg);
        self.message_is_network_error = true;
        self.message_expiration = None;
        self.show_quit_keystroke = true;
    }

    /// Update the reconnecting message with current duration.
    ///
    /// Call this periodically while reconnecting to update the "Last contact" time.
    pub fn update_reconnecting(&mut self, error: &str) {
        if self.message_is_network_error {
            self.set_reconnecting(error);
        }
    }

    /// Clear any network error message.
    pub fn clear_network_error(&mut self) {
        if self.message_is_network_error {
            self.message = None;
            self.message_is_network_error = false;
            self.message_expiration = None;
        }
    }

    /// Clear all messages.
    pub fn clear_message(&mut self) {
        self.message = None;
        self.message_is_network_error = false;
        self.message_expiration = None;
    }

    /// Show connection info (triggered by escape key press, like mosh).
    ///
    /// Displays RTT, frame rate, and packet loss in the notification bar.
    ///
    /// # Arguments
    /// * `frame_rate` - Current frame rate (fps)
    /// * `permanent` - If true, stays visible until cleared; if false, expires after 1 second
    pub fn show_info(&mut self, frame_rate: Option<f64>, permanent: bool) {
        let rtt_str = self
            .rtt
            .map(|d| format!("{}ms", d.as_millis()))
            .unwrap_or_else(|| "-".to_string());

        let loss_str = self
            .packet_loss
            .map(|l| format!("{:.1}%", l * 100.0))
            .unwrap_or_else(|| "-".to_string());

        let fps_str = frame_rate
            .map(|f| format!("{:.0}fps", f))
            .unwrap_or_else(|| "-".to_string());

        let info = format!("RTT: {} | loss: {} | {}", rtt_str, loss_str, fps_str);
        self.set_notification_string(&info, permanent, true);
    }

    /// Check if a transient info message is currently displayed.
    pub fn has_info_message(&self) -> bool {
        self.message.is_some() && !self.message_is_network_error && self.message_expiration.is_some()
    }

    /// Check if server contact is late (>6.5s since last data AND connection activity).
    ///
    /// Returns true only if:
    /// - No application data received for >6.5s, AND
    /// - No connection-level activity (RTT updates) for >6.5s
    ///
    /// This prevents showing "Last contact" for idle sessions where the
    /// QUIC connection is healthy but no shell output is being generated.
    pub fn server_late(&self, now: Instant) -> bool {
        let app_late = now.duration_since(self.last_word_from_server) > SERVER_LATE_THRESHOLD;
        let conn_late = now.duration_since(self.last_connection_alive) > SERVER_LATE_THRESHOLD;
        // Both must be stale - if connection is alive, don't show warning
        app_late && conn_late
    }

    /// Check if server reply is late (>10s since last ack AND connection activity).
    ///
    /// Returns true only if:
    /// - No input acknowledgment for >10s, AND
    /// - No connection-level activity (RTT updates) for >10s
    ///
    /// This prevents showing "Last reply" for idle sessions where no input
    /// has been sent but the QUIC connection is healthy.
    pub fn reply_late(&self, now: Instant) -> bool {
        let ack_late = now.duration_since(self.last_acked_state) > REPLY_LATE_THRESHOLD;
        let conn_late = now.duration_since(self.last_connection_alive) > REPLY_LATE_THRESHOLD;
        // Both must be stale - if connection is alive, don't show warning
        ack_late && conn_late
    }

    /// Check if we're in power-save mode (>60s since server contact).
    pub fn in_power_save(&self, now: Instant) -> bool {
        now.duration_since(self.last_word_from_server) > POWER_SAVE_THRESHOLD
    }

    /// Check if the notification bar should display a time counter.
    pub fn need_countup(&self, now: Instant) -> bool {
        self.server_late(now) || self.reply_late(now)
    }

    /// Expire old messages.
    ///
    /// Call this periodically to clear expired non-permanent messages.
    pub fn adjust_message(&mut self) {
        if let Some(expiration) = self.message_expiration {
            if Instant::now() >= expiration {
                self.message = None;
                self.message_expiration = None;
            }
        }
    }

    /// Get the recommended wait time until the next display update.
    ///
    /// Returns shorter intervals when actively counting, longer in power-save mode.
    pub fn wait_time(&self) -> Duration {
        let now = Instant::now();

        // If we have an expiring message, wait until expiration
        if let Some(expiration) = self.message_expiration {
            if expiration > now {
                return expiration.duration_since(now);
            }
        }

        // In power-save mode, update less frequently
        if self.in_power_save(now) {
            return Duration::from_secs(1);
        }

        // When counting up, update every second
        if self.need_countup(now) {
            return Duration::from_secs(1);
        }

        // Check time until we'd need to show the bar
        let since_heard = now.duration_since(self.last_word_from_server);
        if since_heard < SERVER_LATE_THRESHOLD {
            return SERVER_LATE_THRESHOLD - since_heard;
        }

        // Default: check every second
        Duration::from_secs(1)
    }

    /// Render the notification bar.
    ///
    /// Returns an empty string if nothing to display.
    ///
    /// # Arguments
    /// * `width` - Terminal width in columns
    pub fn render(&self, width: u16) -> String {
        self.render_with_cursor(width, None)
    }

    /// Render the notification bar, optionally hiding cursor if overlapped.
    ///
    /// # Arguments
    /// * `width` - Terminal width in columns
    /// * `cursor_row` - Current cursor row (0-indexed), if known
    pub fn render_with_cursor(&self, width: u16, cursor_row: Option<u16>) -> String {
        let now = Instant::now();

        // Check if we need to display anything
        if self.message.is_none() && !self.need_countup(now) {
            return String::new();
        }

        // Build message content based on style
        let content = match self.style {
            NotificationStyle::Minimal => self.build_minimal_content(now),
            NotificationStyle::Enhanced => self.build_enhanced_content(now),
        };

        if content.is_empty() {
            return String::new();
        }

        // Build ANSI output
        let mut output = String::new();

        // Save cursor position
        output.push_str("\x1b[s");

        // Move to row 1, col 1 (top of terminal)
        output.push_str("\x1b[1;1H");

        // Set colors: blue background (44), white foreground (37), bold (1)
        output.push_str("\x1b[44;37;1m");

        // Center the content and pad to full width
        let content_len = content.chars().count();
        let width = width as usize;

        let padded = if content_len >= width {
            // Truncate if too long
            content.chars().take(width).collect::<String>()
        } else {
            // Center with padding
            let total_pad = width - content_len;
            let left_pad = total_pad / 2;
            let right_pad = total_pad - left_pad;
            format!(
                "{}{}{}",
                " ".repeat(left_pad),
                content,
                " ".repeat(right_pad)
            )
        };

        output.push_str(&padded);

        // Reset attributes
        output.push_str("\x1b[0m");

        // Hide cursor if it would be under the bar
        if cursor_row == Some(0) {
            output.push_str("\x1b[?25l");
        }

        // Restore cursor position
        output.push_str("\x1b[u");

        output
    }

    /// Build minimal (mosh-style) message content.
    fn build_minimal_content(&self, now: Instant) -> String {
        let since_heard = now.duration_since(self.last_word_from_server);
        let since_ack = now.duration_since(self.last_acked_state);

        // Determine which time to show and what to call it
        let (time_elapsed, explanation) = if self.reply_late(now) && !self.server_late(now) {
            // Only uplink is stale
            (since_ack, "reply")
        } else {
            // Downlink is stale (or both)
            (since_heard, "contact")
        };

        // Build quit hint
        let quit_hint = if self.show_quit_keystroke {
            format!(" [To quit: {} .]", self.escape_key_string)
        } else {
            String::new()
        };

        // Build message based on state
        match (&self.message, self.need_countup(now)) {
            (None, false) => String::new(),
            (None, true) => {
                // No message, just timeout
                format!(
                    "qsh: Last {} {}.{}",
                    explanation,
                    human_readable_duration(time_elapsed),
                    quit_hint
                )
            }
            (Some(msg), false) => {
                // Message, no timeout
                format!("qsh: {}{}", msg, quit_hint)
            }
            (Some(msg), true) => {
                // Message with timeout info
                format!(
                    "qsh: {} ({} without {}.){}",
                    msg,
                    human_readable_duration_short(time_elapsed),
                    explanation,
                    quit_hint
                )
            }
        }
    }

    /// Build enhanced message content with RTT and metrics.
    fn build_enhanced_content(&self, now: Instant) -> String {
        let since_heard = now.duration_since(self.last_word_from_server);
        let since_ack = now.duration_since(self.last_acked_state);

        // Determine which time to show
        let (time_elapsed, explanation) = if self.reply_late(now) && !self.server_late(now) {
            (since_ack, "reply")
        } else {
            (since_heard, "contact")
        };

        // Build components
        let user_host = self.user_host.as_deref().unwrap_or("?");
        let rtt_str = self
            .rtt
            .map(|d| format!("{}ms", d.as_millis()))
            .unwrap_or_else(|| "-".to_string());
        let loss_str = self
            .packet_loss
            .map(|l| format!("{:.1}%", l * 100.0))
            .unwrap_or_else(|| "-".to_string());

        let quit_hint = if self.show_quit_keystroke {
            format!(" [{}.]", self.escape_key_string)
        } else {
            String::new()
        };

        // Build message
        let base = format!("qsh: {} | RTT: {} | loss: {}", user_host, rtt_str, loss_str);

        match (&self.message, self.need_countup(now)) {
            (None, false) => String::new(), // Nothing to show in enhanced mode either
            (None, true) => {
                format!(
                    "{} | Last {} {}.{}",
                    base,
                    explanation,
                    human_readable_duration(time_elapsed),
                    quit_hint
                )
            }
            (Some(msg), false) => {
                format!("{} | {}{}", base, msg, quit_hint)
            }
            (Some(msg), true) => {
                format!(
                    "{} | {} ({} without {}.){}",
                    base,
                    msg,
                    human_readable_duration_short(time_elapsed),
                    explanation,
                    quit_hint
                )
            }
        }
    }
}

/// Format a duration in human-readable form (long version).
///
/// - `<60s`: "X seconds ago"
/// - `60s-3600s`: "M:SS ago"
/// - `>3600s`: "H:MM:SS ago"
pub fn human_readable_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{} seconds ago", secs)
    } else if secs < 3600 {
        format!("{}:{:02} ago", secs / 60, secs % 60)
    } else {
        format!(
            "{}:{:02}:{:02} ago",
            secs / 3600,
            (secs / 60) % 60,
            secs % 60
        )
    }
}

/// Format a duration in human-readable form (short version).
///
/// - `<60s`: "Xs"
/// - `60s-3600s`: "M:SS"
/// - `>3600s`: "H:MM:SS"
pub fn human_readable_duration_short(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}:{:02}", secs / 60, secs % 60)
    } else {
        format!("{}:{:02}:{:02}", secs / 3600, (secs / 60) % 60, secs % 60)
    }
}

/// Format escape key specification for display.
///
/// Converts "ctrl+^" to "^\\" or "ctrl+]" to "^]"
fn format_escape_key(spec: &str) -> String {
    let spec_lower = spec.to_lowercase();
    if spec_lower == "none" {
        return String::new();
    }
    if spec_lower.starts_with("ctrl+") {
        let ch = spec.chars().last().unwrap_or('^');
        if ch == '^' {
            "^\\".to_string()
        } else {
            format!("^{}", ch.to_ascii_uppercase())
        }
    } else {
        spec.to_string()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_engine() {
        let engine = NotificationEngine::new();
        let now = Instant::now();

        // Should not be late immediately
        assert!(!engine.server_late(now));
        assert!(!engine.reply_late(now));
        assert!(!engine.need_countup(now));
    }

    #[test]
    fn test_server_late_threshold() {
        let mut engine = NotificationEngine::new();
        let now = Instant::now();

        // Set last heard to 7 seconds ago
        engine.last_word_from_server = now - Duration::from_millis(7000);
        // Connection also stale
        engine.last_connection_alive = now - Duration::from_millis(7000);

        assert!(engine.server_late(now));
        assert!(engine.need_countup(now));
    }

    #[test]
    fn test_server_late_but_connection_alive() {
        let mut engine = NotificationEngine::new();
        let now = Instant::now();

        // No app data for 7 seconds
        engine.last_word_from_server = now - Duration::from_millis(7000);
        // But connection is alive (RTT updated recently)
        engine.last_connection_alive = now - Duration::from_millis(1000);

        // Should NOT be considered late - connection is healthy, just idle
        assert!(!engine.server_late(now));
        assert!(!engine.need_countup(now));
    }

    #[test]
    fn test_reply_late_threshold() {
        let mut engine = NotificationEngine::new();
        let now = Instant::now();

        // Server heard recently
        engine.server_heard(now);
        // But ack is stale AND connection is stale
        engine.last_acked_state = now - Duration::from_millis(11000);
        engine.last_connection_alive = now - Duration::from_millis(11000);

        assert!(engine.reply_late(now));
        assert!(!engine.server_late(now));
        assert!(engine.need_countup(now));
    }

    #[test]
    fn test_reply_late_but_connection_alive() {
        let mut engine = NotificationEngine::new();
        let now = Instant::now();

        // No ack for 11 seconds (no input sent)
        engine.last_acked_state = now - Duration::from_millis(11000);
        // But connection is alive (RTT updated recently)
        engine.last_connection_alive = now - Duration::from_millis(1000);

        // Should NOT be considered late - connection is healthy, just no input sent
        assert!(!engine.reply_late(now));
        assert!(!engine.need_countup(now));
    }

    #[test]
    fn test_message_expiration() {
        let mut engine = NotificationEngine::new();

        // Set a non-permanent message
        engine.set_notification_string("Test", false, true);
        assert!(engine.message.is_some());

        // Simulate time passing
        engine.message_expiration = Some(Instant::now() - Duration::from_millis(100));
        engine.adjust_message();
        assert!(engine.message.is_none());
    }

    #[test]
    fn test_permanent_message() {
        let mut engine = NotificationEngine::new();

        // Set a permanent message
        engine.set_notification_string("Permanent", true, true);
        assert!(engine.message.is_some());
        assert!(engine.message_expiration.is_none());

        // adjust_message should not clear it
        engine.adjust_message();
        assert!(engine.message.is_some());
    }

    #[test]
    fn test_network_error() {
        let mut engine = NotificationEngine::new();

        engine.set_network_error("Connection lost");
        assert!(engine.message.is_some());
        assert!(engine.message_is_network_error);

        // Regular clear_message doesn't clear network errors
        engine.clear_network_error();
        assert!(engine.message.is_none());
    }

    #[test]
    fn test_time_formatting_seconds() {
        assert_eq!(human_readable_duration(Duration::from_secs(0)), "0 seconds ago");
        assert_eq!(human_readable_duration(Duration::from_secs(30)), "30 seconds ago");
        assert_eq!(human_readable_duration(Duration::from_secs(59)), "59 seconds ago");
    }

    #[test]
    fn test_time_formatting_minutes() {
        assert_eq!(human_readable_duration(Duration::from_secs(60)), "1:00 ago");
        assert_eq!(human_readable_duration(Duration::from_secs(90)), "1:30 ago");
        assert_eq!(human_readable_duration(Duration::from_secs(3599)), "59:59 ago");
    }

    #[test]
    fn test_time_formatting_hours() {
        assert_eq!(human_readable_duration(Duration::from_secs(3600)), "1:00:00 ago");
        assert_eq!(human_readable_duration(Duration::from_secs(3661)), "1:01:01 ago");
        assert_eq!(human_readable_duration(Duration::from_secs(7322)), "2:02:02 ago");
    }

    #[test]
    fn test_time_formatting_short() {
        assert_eq!(human_readable_duration_short(Duration::from_secs(30)), "30s");
        assert_eq!(human_readable_duration_short(Duration::from_secs(90)), "1:30");
        assert_eq!(human_readable_duration_short(Duration::from_secs(3661)), "1:01:01");
    }

    #[test]
    fn test_render_output_format() {
        let mut engine = NotificationEngine::new();
        let now = Instant::now();

        // Make server late (both app data and connection)
        engine.last_word_from_server = now - Duration::from_millis(7000);
        engine.last_connection_alive = now - Duration::from_millis(7000);

        let output = engine.render(80);

        // Should have ANSI sequences
        assert!(output.contains("\x1b[s")); // Save cursor
        assert!(output.contains("\x1b[44;37;1m")); // Blue bg, white fg, bold
        assert!(output.contains("qsh:"));
        assert!(output.contains("Last contact"));
        assert!(output.contains("\x1b[u")); // Restore cursor
    }

    #[test]
    fn test_render_empty_when_connected() {
        let engine = NotificationEngine::new();
        let output = engine.render(80);
        assert!(output.is_empty());
    }

    #[test]
    fn test_escape_key_formatting() {
        assert_eq!(format_escape_key("ctrl+^"), "^\\");
        assert_eq!(format_escape_key("ctrl+]"), "^]");
        assert_eq!(format_escape_key("ctrl+a"), "^A");
        assert_eq!(format_escape_key("none"), "");
    }

    #[test]
    fn test_cursor_hiding() {
        let mut engine = NotificationEngine::new();
        let now = Instant::now();
        engine.last_word_from_server = now - Duration::from_millis(7000);
        engine.last_connection_alive = now - Duration::from_millis(7000);

        // With cursor on row 0, should hide cursor
        let output = engine.render_with_cursor(80, Some(0));
        assert!(output.contains("\x1b[?25l")); // Hide cursor

        // With cursor elsewhere, should not hide
        let output = engine.render_with_cursor(80, Some(5));
        assert!(!output.contains("\x1b[?25l"));
    }

    #[test]
    fn test_power_save_mode() {
        let mut engine = NotificationEngine::new();
        let now = Instant::now();

        // Not in power save initially
        assert!(!engine.in_power_save(now));

        // After 61 seconds without contact
        engine.last_word_from_server = now - Duration::from_secs(61);
        assert!(engine.in_power_save(now));
    }

    #[test]
    fn test_wait_time() {
        let engine = NotificationEngine::new();
        let wait = engine.wait_time();

        // Should be waiting until SERVER_LATE_THRESHOLD
        assert!(wait <= SERVER_LATE_THRESHOLD);
        assert!(wait > Duration::ZERO);
    }

    #[test]
    fn test_enhanced_style() {
        let mut engine = NotificationEngine::new();
        engine.set_style(NotificationStyle::Enhanced);
        engine.set_user_host("user@host".to_string());
        engine.update_packet_loss(0.01);

        let now = Instant::now();
        engine.last_word_from_server = now - Duration::from_millis(7000);
        engine.last_connection_alive = now - Duration::from_millis(7000);
        // Set RTT without updating last_connection_alive
        engine.rtt = Some(Duration::from_millis(50));

        let output = engine.render(120);

        assert!(output.contains("user@host"));
        assert!(output.contains("RTT: 50ms"));
        assert!(output.contains("1.0%"));
        assert!(output.contains("Last contact"));
    }

    #[test]
    fn test_show_info() {
        let mut engine = NotificationEngine::new();
        engine.update_rtt(Duration::from_millis(42));
        engine.update_packet_loss(0.005);

        // Show info with frame rate (non-permanent)
        engine.show_info(Some(60.5), false);

        assert!(engine.has_info_message());
        let output = engine.render(80);
        assert!(output.contains("RTT: 42ms"));
        assert!(output.contains("0.5%"));
        assert!(output.contains("60fps") || output.contains("61fps")); // ~60
    }

    #[test]
    fn test_show_info_permanent() {
        let mut engine = NotificationEngine::new();
        engine.update_rtt(Duration::from_millis(42));

        // Show info permanently (no expiration)
        engine.show_info(Some(60.0), true);

        assert!(engine.message.is_some());
        assert!(engine.message_expiration.is_none()); // permanent = no expiration
    }

    #[test]
    fn test_show_info_no_fps() {
        let mut engine = NotificationEngine::new();
        engine.update_rtt(Duration::from_millis(100));

        engine.show_info(None, false);

        let output = engine.render(80);
        assert!(output.contains("RTT: 100ms"));
        assert!(output.contains("-")); // fps placeholder
    }

    #[test]
    fn test_set_reconnecting() {
        let mut engine = NotificationEngine::new();
        let now = Instant::now();

        // Simulate last contact was 5 seconds ago
        engine.last_word_from_server = now - Duration::from_secs(5);

        engine.set_reconnecting("Connection reset");

        assert!(engine.message.is_some());
        assert!(engine.message_is_network_error);
        let msg = engine.message.as_ref().unwrap();
        assert!(msg.contains("Connection reset"));
        assert!(msg.contains("Last contact"));
        assert!(msg.contains("5 seconds ago"));
    }

    #[test]
    fn test_update_reconnecting() {
        let mut engine = NotificationEngine::new();
        let now = Instant::now();

        engine.last_word_from_server = now - Duration::from_secs(10);
        engine.set_reconnecting("Timeout");

        // Simulate time passing
        engine.last_word_from_server = now - Duration::from_secs(15);
        engine.update_reconnecting("Timeout");

        let msg = engine.message.as_ref().unwrap();
        assert!(msg.contains("15 seconds ago"));
    }
}
