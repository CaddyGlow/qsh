//! Rendering logic for notification bar.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::format::{format_rtt, human_readable_duration, human_readable_duration_short};
use super::state::NotificationState;

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

/// Metrics for enhanced display.
#[derive(Debug, Clone)]
pub struct NotificationMetrics {
    /// User@host string for enhanced display.
    pub user_host: Option<String>,
    /// Current RTT for enhanced display (from heartbeat SRTT).
    pub rtt: Option<Duration>,
    /// Packet loss for enhanced display.
    pub packet_loss: Option<f64>,
    /// Frame timestamps for FPS calculation (rolling window).
    frame_timestamps: VecDeque<Instant>,
    /// FPS averaging window duration (default: 1 second).
    fps_window: Duration,
}

impl Default for NotificationMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl NotificationMetrics {
    /// Default FPS averaging window duration (1 second).
    const DEFAULT_FPS_WINDOW: Duration = Duration::from_secs(1);

    /// Create new metrics with default 1-second FPS window.
    pub fn new() -> Self {
        Self {
            user_host: None,
            rtt: None,
            packet_loss: None,
            frame_timestamps: VecDeque::new(),
            fps_window: Self::DEFAULT_FPS_WINDOW,
        }
    }

    /// Set the FPS averaging window duration.
    ///
    /// # Arguments
    /// * `window` - Duration for the rolling FPS window (e.g., 1s, 5s)
    pub fn set_fps_window(&mut self, window: Duration) {
        self.fps_window = window;
    }

    /// Set user@host for enhanced display.
    pub fn set_user_host(&mut self, user_host: String) {
        self.user_host = Some(user_host);
    }

    /// Update RTT for enhanced display.
    pub fn update_rtt(&mut self, rtt: Duration) {
        self.rtt = Some(rtt);
    }

    /// Update packet loss for enhanced display.
    pub fn update_packet_loss(&mut self, loss: f64) {
        self.packet_loss = Some(loss.clamp(0.0, 1.0));
    }

    /// Record a frame for FPS calculation.
    ///
    /// Maintains a rolling window of frame timestamps.
    pub fn record_frame(&mut self, now: Instant) {
        // Add the new frame timestamp
        self.frame_timestamps.push_back(now);

        // Remove frames older than the window
        let cutoff = now - self.fps_window;
        while let Some(&oldest) = self.frame_timestamps.front() {
            if oldest < cutoff {
                self.frame_timestamps.pop_front();
            } else {
                break;
            }
        }
    }

    /// Get the average FPS over the configured window.
    ///
    /// Returns None if there are no frames in the window.
    pub fn fps(&self) -> Option<f64> {
        if self.frame_timestamps.len() < 2 {
            return None;
        }

        // Calculate elapsed time from oldest to newest frame
        let oldest = *self.frame_timestamps.front()?;
        let newest = *self.frame_timestamps.back()?;
        let elapsed = newest.duration_since(oldest).as_secs_f64();

        if elapsed > 0.0 {
            // Count is len - 1 because we're measuring intervals
            Some((self.frame_timestamps.len() - 1) as f64 / elapsed)
        } else {
            None
        }
    }
}

/// Render the notification bar.
///
/// Returns an empty string if nothing to display.
///
/// # Arguments
/// * `state` - Notification state
/// * `style` - Display style (minimal or enhanced)
/// * `metrics` - Metrics for enhanced display
/// * `width` - Terminal width in columns
pub fn render(
    state: &NotificationState,
    style: NotificationStyle,
    metrics: &NotificationMetrics,
    width: u16,
) -> String {
    render_with_cursor(state, style, metrics, width, None)
}

/// Render the notification bar, optionally hiding cursor if overlapped.
///
/// # Arguments
/// * `state` - Notification state
/// * `style` - Display style (minimal or enhanced)
/// * `metrics` - Metrics for enhanced display
/// * `width` - Terminal width in columns
/// * `cursor_row` - Current cursor row (0-indexed), if known
pub fn render_with_cursor(
    state: &NotificationState,
    style: NotificationStyle,
    metrics: &NotificationMetrics,
    width: u16,
    cursor_row: Option<u16>,
) -> String {
    let now = Instant::now();

    // Check if we need to display anything
    if state.message.is_none() && !state.need_countup(now) {
        return String::new();
    }

    // Build message content based on style
    let content = match style {
        NotificationStyle::Minimal => build_minimal_content(state, now),
        NotificationStyle::Enhanced => build_enhanced_content(state, metrics, now),
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
pub fn build_minimal_content(state: &NotificationState, now: Instant) -> String {
    let since_heard = now.duration_since(state.last_word_from_server);
    let since_ack = now.duration_since(state.last_acked_state);

    // Determine which time to show and what to call it
    let (time_elapsed, explanation) = if state.reply_late(now) && !state.server_late(now) {
        // Only uplink is stale
        (since_ack, "reply")
    } else {
        // Downlink is stale (or both)
        (since_heard, "contact")
    };

    // Build quit hint
    let quit_hint = if state.show_quit_keystroke {
        format!(" [To quit: {} .]", state.escape_key_string)
    } else {
        String::new()
    };

    // Build message based on state
    match (&state.message, state.need_countup(now)) {
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
pub fn build_enhanced_content(
    state: &NotificationState,
    metrics: &NotificationMetrics,
    now: Instant,
) -> String {
    let since_heard = now.duration_since(state.last_word_from_server);
    let since_ack = now.duration_since(state.last_acked_state);

    // Determine which time to show
    let (time_elapsed, explanation) = if state.reply_late(now) && !state.server_late(now) {
        (since_ack, "reply")
    } else {
        (since_heard, "contact")
    };

    // Build components
    let user_host = metrics.user_host.as_deref().unwrap_or("?");
    let rtt_str = metrics
        .rtt
        .map(|d| format_rtt(d))
        .unwrap_or_else(|| "-".to_string());
    let loss_str = metrics
        .packet_loss
        .map(|l| format!("{:.1}%", l * 100.0))
        .unwrap_or_else(|| "-".to_string());

    let quit_hint = if state.show_quit_keystroke {
        format!(" [{}.]", state.escape_key_string)
    } else {
        String::new()
    };

    // Build message
    let base = format!("qsh: {} | RTT: {} | loss: {}", user_host, rtt_str, loss_str);

    match (&state.message, state.need_countup(now)) {
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
