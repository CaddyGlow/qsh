//! Formatting utilities for notification display.

use std::time::Duration;

/// Format RTT for display, showing fractional ms for small values.
pub fn format_rtt(d: Duration) -> String {
    let ms = d.as_secs_f64() * 1000.0;
    if ms < 1.0 {
        format!("{:.1}ms", ms)
    } else if ms < 10.0 {
        format!("{:.1}ms", ms)
    } else {
        format!("{:.0}ms", ms)
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
pub fn format_escape_key(spec: &str) -> String {
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
