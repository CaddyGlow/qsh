//! CLI commands for terminal resource management.
//!
//! This module provides subcommands for the terminal resource:
//! - `qsh terminal add` - Create a new terminal
//! - `qsh terminal list` - List all terminals
//! - `qsh terminal attach` - Attach to a terminal
//! - `qsh terminal detach` - Detach from a terminal
//! - `qsh terminal resize` - Resize a terminal
//! - `qsh terminal close` - Close a terminal

use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use qsh_core::protocol::OutputMode;

/// Prediction mode for local echo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum PredictionMode {
    /// Adaptive: Show predictions based on RTT thresholds (mosh-style).
    #[default]
    Adaptive,
    /// Always show predictions with underline styling.
    Always,
    /// Experimental: Always predict with mosh-style cell tracking.
    Experimental,
    /// Disable prediction entirely.
    Off,
}

/// Notification bar display style.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum NotificationStyle {
    /// Mosh-compatible minimal display.
    #[default]
    Minimal,
    /// Enhanced display with RTT and metrics when visible.
    Enhanced,
}

/// Overlay placement for the status widget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum OverlayPosition {
    #[default]
    Top,
    Bottom,
    #[clap(name = "top-right")]
    TopRight,
    None,
}

/// Terminal display options shared between main CLI and terminal commands.
///
/// These options configure client-side terminal rendering features like
/// prediction, overlays, and notifications.
#[derive(Debug, Clone, Parser)]
pub struct TerminalDisplayOptions {
    /// Prediction mode for local echo
    #[arg(long = "prediction", value_enum, default_value = "adaptive")]
    pub prediction_mode: PredictionMode,

    /// Force predictive echo off (shorthand for --prediction=off)
    #[arg(long = "no-prediction", conflicts_with = "prediction_mode")]
    pub no_prediction: bool,

    /// Notification bar display style
    #[arg(long = "notification-style", value_enum, default_value = "minimal")]
    pub notification_style: NotificationStyle,

    /// Overlay position
    #[arg(long = "overlay-position", value_enum, default_value = "top")]
    pub overlay_position: OverlayPosition,

    /// Disable status overlay
    #[arg(long = "no-overlay")]
    pub no_overlay: bool,

    /// Custom overlay toggle key
    #[arg(long = "overlay-key", default_value = "ctrl+shift+o", value_name = "KEY")]
    pub overlay_key: String,

    /// Escape key for client commands (e.g., ctrl+^ then . to disconnect).
    /// Use "none" to disable escape sequences.
    #[arg(long = "escape-key", default_value = "ctrl+^", value_name = "KEY")]
    pub escape_key: String,
}

impl Default for TerminalDisplayOptions {
    fn default() -> Self {
        Self {
            prediction_mode: PredictionMode::Adaptive,
            no_prediction: false,
            notification_style: NotificationStyle::Minimal,
            overlay_position: OverlayPosition::Top,
            no_overlay: false,
            overlay_key: "ctrl+shift+o".to_string(),
            escape_key: "ctrl+^".to_string(),
        }
    }
}

impl TerminalDisplayOptions {
    /// Get the effective prediction mode, handling --no-prediction flag.
    pub fn effective_prediction_mode(&self) -> PredictionMode {
        if self.no_prediction {
            PredictionMode::Off
        } else {
            self.prediction_mode
        }
    }
}

/// Terminal resource subcommands.
#[derive(Debug, Parser)]
pub struct TerminalCommand {
    #[command(subcommand)]
    pub action: TerminalAction,
}

/// Terminal actions.
#[derive(Debug, Subcommand)]
pub enum TerminalAction {
    /// Create a new terminal resource
    Add(TerminalAddArgs),
    /// List all terminal resources
    List,
    /// Attach to a terminal for interactive I/O
    Attach(TerminalAttachArgs),
    /// Detach from a terminal
    Detach(TerminalDetachArgs),
    /// Resize a terminal
    Resize(TerminalResizeArgs),
    /// Close a terminal
    Close(TerminalCloseArgs),
}

/// Arguments for creating a new terminal.
#[derive(Debug, Parser)]
pub struct TerminalAddArgs {
    /// Terminal columns
    #[arg(long, value_name = "COLS", default_value = "80")]
    pub cols: u32,

    /// Terminal rows
    #[arg(long, value_name = "ROWS", default_value = "24")]
    pub rows: u32,

    /// Terminal type (TERM env var)
    #[arg(long = "term", value_name = "TYPE", default_value = "xterm-256color")]
    pub term_type: String,

    /// Shell to run (default: user's shell)
    #[arg(long, value_name = "SHELL")]
    pub shell: Option<String>,

    /// Command to run instead of shell
    #[arg(value_name = "COMMAND")]
    pub command: Option<String>,

    /// Environment variables (KEY=VALUE)
    #[arg(long = "env", action = ArgAction::Append, value_name = "KEY=VALUE")]
    pub env: Vec<String>,

    /// Terminal output mode (server-side batching)
    #[arg(long = "mode", value_enum, default_value = "mosh")]
    pub output_mode: OutputMode,

    /// Attach to terminal after creation (interactive mode)
    #[arg(short = 'a', long = "attach")]
    pub attach: bool,

    /// Display options (only used when --attach is specified)
    #[command(flatten)]
    pub display: TerminalDisplayOptions,
}

/// Arguments for attaching to a terminal.
#[derive(Debug, Parser)]
pub struct TerminalAttachArgs {
    /// Terminal resource ID to attach to
    #[arg(value_name = "RESOURCE_ID")]
    pub resource_id: String,

    /// Interactive mode: start full terminal session with features
    /// (default: just print socket path)
    #[arg(short = 'i', long = "interactive")]
    pub interactive: bool,

    /// Display options for interactive mode
    #[command(flatten)]
    pub display: TerminalDisplayOptions,
}

/// Arguments for detaching from a terminal.
#[derive(Debug, Parser)]
pub struct TerminalDetachArgs {
    /// Terminal resource ID to detach from
    #[arg(value_name = "RESOURCE_ID")]
    pub resource_id: String,
}

/// Arguments for resizing a terminal.
#[derive(Debug, Parser)]
pub struct TerminalResizeArgs {
    /// Terminal resource ID
    #[arg(value_name = "RESOURCE_ID")]
    pub resource_id: String,

    /// New terminal columns
    #[arg(long, value_name = "COLS")]
    pub cols: u32,

    /// New terminal rows
    #[arg(long, value_name = "ROWS")]
    pub rows: u32,
}

/// Arguments for closing a terminal.
#[derive(Debug, Parser)]
pub struct TerminalCloseArgs {
    /// Terminal resource ID to close
    #[arg(value_name = "RESOURCE_ID")]
    pub resource_id: String,
}

impl TerminalAddArgs {
    /// Parse environment variables from KEY=VALUE format.
    pub fn parse_env(&self) -> Vec<(String, String)> {
        self.env
            .iter()
            .filter_map(|s| {
                let parts: Vec<&str> = s.splitn(2, '=').collect();
                if parts.len() == 2 {
                    Some((parts[0].to_string(), parts[1].to_string()))
                } else {
                    None
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_env() {
        let args = TerminalAddArgs {
            cols: 80,
            rows: 24,
            term_type: "xterm".to_string(),
            shell: None,
            command: None,
            env: vec![
                "FOO=bar".to_string(),
                "BAZ=qux".to_string(),
                "INVALID".to_string(), // Should be ignored
            ],
            output_mode: OutputMode::Mosh,
            attach: false,
            display: TerminalDisplayOptions::default(),
        };

        let parsed = args.parse_env();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], ("FOO".to_string(), "bar".to_string()));
        assert_eq!(parsed[1], ("BAZ".to_string(), "qux".to_string()));
    }

    #[test]
    fn test_display_options_default() {
        let opts = TerminalDisplayOptions::default();
        assert_eq!(opts.prediction_mode, PredictionMode::Adaptive);
        assert_eq!(opts.notification_style, NotificationStyle::Minimal);
        assert_eq!(opts.overlay_position, OverlayPosition::Top);
        assert!(!opts.no_overlay);
    }

    #[test]
    fn test_effective_prediction_mode() {
        let mut opts = TerminalDisplayOptions::default();
        assert_eq!(opts.effective_prediction_mode(), PredictionMode::Adaptive);

        opts.no_prediction = true;
        assert_eq!(opts.effective_prediction_mode(), PredictionMode::Off);
    }
}
