//! Tests for notification engine.

use std::time::{Duration, Instant};

use super::NotificationEngine;
use super::format::{format_escape_key, human_readable_duration, human_readable_duration_short};
use super::state::{NotificationState, SERVER_LATE_THRESHOLD};

#[test]
fn test_new_engine() {
    let engine = NotificationEngine::new();
    let now = Instant::now();

    // Should not be late immediately
    assert!(!engine.state.server_late(now));
    assert!(!engine.state.reply_late(now));
    assert!(!engine.state.need_countup(now));
}

#[test]
fn test_server_late_threshold() {
    let mut engine = NotificationEngine::new();
    let now = Instant::now();

    // Set last heard to 7 seconds ago
    engine.state.last_word_from_server = now - Duration::from_millis(7000);
    // Connection also stale
    engine.state.last_connection_alive = now - Duration::from_millis(7000);

    assert!(engine.state.server_late(now));
    assert!(engine.state.need_countup(now));
}

#[test]
fn test_server_late_but_connection_alive() {
    let mut engine = NotificationEngine::new();
    let now = Instant::now();

    // No app data for 7 seconds
    engine.state.last_word_from_server = now - Duration::from_millis(7000);
    // But connection is alive (RTT updated recently)
    engine.state.last_connection_alive = now - Duration::from_millis(1000);

    // Should NOT be considered late - connection is healthy, just idle
    assert!(!engine.state.server_late(now));
    assert!(!engine.state.need_countup(now));
}

#[test]
fn test_reply_late_threshold() {
    let mut engine = NotificationEngine::new();
    let now = Instant::now();

    // Server heard recently
    engine.server_heard(now);
    // But ack is stale AND connection is stale
    engine.state.last_acked_state = now - Duration::from_millis(11000);
    engine.state.last_connection_alive = now - Duration::from_millis(11000);

    assert!(engine.state.reply_late(now));
    assert!(!engine.state.server_late(now));
    assert!(engine.state.need_countup(now));
}

#[test]
fn test_reply_late_but_connection_alive() {
    let mut engine = NotificationEngine::new();
    let now = Instant::now();

    // No ack for 11 seconds (no input sent)
    engine.state.last_acked_state = now - Duration::from_millis(11000);
    // But connection is alive (RTT updated recently)
    engine.state.last_connection_alive = now - Duration::from_millis(1000);

    // Should NOT be considered late - connection is healthy, just no input sent
    assert!(!engine.state.reply_late(now));
    assert!(!engine.state.need_countup(now));
}

#[test]
fn test_message_expiration() {
    let mut engine = NotificationEngine::new();

    // Set a non-permanent message
    engine.set_notification_string("Test", false, true);
    assert!(engine.state.message.is_some());

    // Simulate time passing
    engine.state.message_expiration = Some(Instant::now() - Duration::from_millis(100));
    engine.adjust_message();
    assert!(engine.state.message.is_none());
}

#[test]
fn test_permanent_message() {
    let mut engine = NotificationEngine::new();

    // Set a permanent message
    engine.set_notification_string("Permanent", true, true);
    assert!(engine.state.message.is_some());
    assert!(engine.state.message_expiration.is_none());

    // adjust_message should not clear it
    engine.adjust_message();
    assert!(engine.state.message.is_some());
}

#[test]
fn test_network_error() {
    let mut engine = NotificationEngine::new();

    engine.set_network_error("Connection lost");
    assert!(engine.state.message.is_some());
    assert!(engine.state.message_is_network_error);

    // Regular clear_message doesn't clear network errors
    engine.clear_network_error();
    assert!(engine.state.message.is_none());
}

#[test]
fn test_time_formatting_seconds() {
    assert_eq!(
        human_readable_duration(Duration::from_secs(0)),
        "0 seconds ago"
    );
    assert_eq!(
        human_readable_duration(Duration::from_secs(30)),
        "30 seconds ago"
    );
    assert_eq!(
        human_readable_duration(Duration::from_secs(59)),
        "59 seconds ago"
    );
}

#[test]
fn test_time_formatting_minutes() {
    assert_eq!(human_readable_duration(Duration::from_secs(60)), "1:00 ago");
    assert_eq!(human_readable_duration(Duration::from_secs(90)), "1:30 ago");
    assert_eq!(
        human_readable_duration(Duration::from_secs(3599)),
        "59:59 ago"
    );
}

#[test]
fn test_time_formatting_hours() {
    assert_eq!(
        human_readable_duration(Duration::from_secs(3600)),
        "1:00:00 ago"
    );
    assert_eq!(
        human_readable_duration(Duration::from_secs(3661)),
        "1:01:01 ago"
    );
    assert_eq!(
        human_readable_duration(Duration::from_secs(7322)),
        "2:02:02 ago"
    );
}

#[test]
fn test_time_formatting_short() {
    assert_eq!(
        human_readable_duration_short(Duration::from_secs(30)),
        "30s"
    );
    assert_eq!(
        human_readable_duration_short(Duration::from_secs(90)),
        "1:30"
    );
    assert_eq!(
        human_readable_duration_short(Duration::from_secs(3661)),
        "1:01:01"
    );
}

#[test]
fn test_render_output_format() {
    let mut engine = NotificationEngine::new();
    let now = Instant::now();

    // Make server late (both app data and connection)
    engine.state.last_word_from_server = now - Duration::from_millis(7000);
    engine.state.last_connection_alive = now - Duration::from_millis(7000);

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
    engine.state.last_word_from_server = now - Duration::from_millis(7000);
    engine.state.last_connection_alive = now - Duration::from_millis(7000);

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
    assert!(!engine.state.in_power_save(now));

    // After 61 seconds without contact
    engine.state.last_word_from_server = now - Duration::from_secs(61);
    assert!(engine.state.in_power_save(now));
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
    engine.set_style(super::NotificationStyle::Enhanced);
    engine.set_user_host("user@host".to_string());
    engine.update_packet_loss(0.01);

    let now = Instant::now();
    engine.state.last_word_from_server = now - Duration::from_millis(7000);
    engine.state.last_connection_alive = now - Duration::from_millis(7000);
    // Set RTT without updating last_connection_alive
    engine.metrics.rtt = Some(Duration::from_millis(50));

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
    engine.update_quiche_rtt(Duration::from_millis(38));
    engine.update_packet_loss(0.005);

    // Show info with frame rate (non-permanent)
    engine.show_info(Some(60.5), false);

    assert!(engine.has_info_message());
    let output = engine.render(120); // Wider to fit both RTTs
    assert!(output.contains("RTT: 42ms"));
    assert!(output.contains("quic: 38ms")); // quiche SRTT
    assert!(output.contains("0.5%"));
    assert!(output.contains("60fps") || output.contains("61fps")); // ~60
}

#[test]
fn test_show_info_permanent() {
    let mut engine = NotificationEngine::new();
    engine.update_rtt(Duration::from_millis(42));

    // Show info permanently (no expiration)
    engine.show_info(Some(60.0), true);

    assert!(engine.state.message.is_some());
    assert!(engine.state.message_expiration.is_none()); // permanent = no expiration
}

#[test]
fn test_show_info_no_fps() {
    let mut engine = NotificationEngine::new();
    engine.update_rtt(Duration::from_millis(100));
    // No quiche RTT - will show "-" for quic

    engine.show_info(None, false);

    let output = engine.render(120); // Wider to fit both RTTs
    assert!(output.contains("RTT: 100ms"));
    assert!(output.contains("(quic: -)")); // quiche SRTT placeholder
}

#[test]
fn test_set_reconnecting() {
    let mut engine = NotificationEngine::new();
    let now = Instant::now();

    // Simulate last contact was 5 seconds ago
    engine.state.last_word_from_server = now - Duration::from_secs(5);

    engine.set_reconnecting("Connection reset");

    assert!(engine.state.message.is_some());
    assert!(engine.state.message_is_network_error);
    let msg = engine.state.message.as_ref().unwrap();
    assert!(msg.contains("Connection reset"));
    assert!(msg.contains("Last contact"));
    assert!(msg.contains("5 seconds ago"));
}

#[test]
fn test_update_reconnecting() {
    let mut engine = NotificationEngine::new();
    let now = Instant::now();

    engine.state.last_word_from_server = now - Duration::from_secs(10);
    engine.set_reconnecting("Timeout");

    // Simulate time passing
    engine.state.last_word_from_server = now - Duration::from_secs(15);
    engine.update_reconnecting("Timeout");

    let msg = engine.state.message.as_ref().unwrap();
    assert!(msg.contains("15 seconds ago"));
}

#[test]
fn test_state_new() {
    let state = NotificationState::new();
    assert!(state.message.is_none());
    assert!(!state.message_is_network_error);
    assert_eq!(state.escape_key_string, "^\\");
}

#[test]
fn test_state_server_heard() {
    let mut state = NotificationState::new();
    let now = Instant::now();
    let later = now + Duration::from_secs(1);

    state.server_heard(later);
    assert_eq!(state.last_word_from_server, later);
}

#[test]
fn test_state_server_acked() {
    let mut state = NotificationState::new();
    let now = Instant::now();
    let later = now + Duration::from_secs(1);

    state.server_acked(later);
    assert_eq!(state.last_acked_state, later);
}
