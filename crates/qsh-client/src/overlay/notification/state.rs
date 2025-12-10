//! State management for notification engine.

use std::time::{Duration, Instant};

use super::format::human_readable_duration;

/// Threshold for considering server contact "late" (show "Last contact X ago").
/// From mosh: `server_late() = (now - last_word_from_server) > 6500ms`
pub const SERVER_LATE_THRESHOLD: Duration = Duration::from_millis(6500);

/// Threshold for considering server reply "late" (show "Last reply X ago").
/// From mosh: `reply_late() = (now - last_acked_state) > 10000ms`
pub const REPLY_LATE_THRESHOLD: Duration = Duration::from_millis(10000);

/// Threshold for power-save mode (reduce update frequency).
/// From mosh: After 60s disconnect, reduce refresh rate.
pub const POWER_SAVE_THRESHOLD: Duration = Duration::from_secs(60);

/// Default message expiration time (non-permanent messages).
pub const MESSAGE_EXPIRATION: Duration = Duration::from_secs(1);

/// Timing and message state for notification engine.
#[derive(Debug)]
pub struct NotificationState {
    /// Timestamp of last data received from server.
    pub last_word_from_server: Instant,
    /// Timestamp of last state acknowledgment from server.
    pub last_acked_state: Instant,
    /// Timestamp of last confirmed connection activity (RTT update, keepalive, etc.).
    /// This is updated even when idle, as long as QUIC reports the connection is alive.
    pub last_connection_alive: Instant,
    /// Escape key string for quit hint (e.g., "^\\").
    pub escape_key_string: String,
    /// Custom message to display.
    pub message: Option<String>,
    /// Whether current message is a network error.
    pub message_is_network_error: bool,
    /// When the current message expires.
    pub message_expiration: Option<Instant>,
    /// Whether to show quit keystroke hint.
    pub show_quit_keystroke: bool,
}

impl Default for NotificationState {
    fn default() -> Self {
        Self::new()
    }
}

impl NotificationState {
    /// Create a new notification state.
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
        }
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

    /// Record that the connection is alive (QUIC keepalives, RTT updates).
    pub fn connection_alive(&mut self, timestamp: Instant) {
        self.last_connection_alive = timestamp;
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
}
