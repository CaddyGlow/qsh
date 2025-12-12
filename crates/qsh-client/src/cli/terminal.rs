//! CLI commands for terminal resource management.
//!
//! This module provides subcommands for the terminal resource:
//! - `qsh terminal add` - Create a new terminal
//! - `qsh terminal list` - List all terminals
//! - `qsh terminal attach` - Attach to a terminal
//! - `qsh terminal detach` - Detach from a terminal
//! - `qsh terminal resize` - Resize a terminal
//! - `qsh terminal close` - Close a terminal

use clap::{Parser, Subcommand};

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
    #[arg(long = "env", value_name = "KEY=VALUE")]
    pub env: Vec<String>,
}

/// Arguments for attaching to a terminal.
#[derive(Debug, Parser)]
pub struct TerminalAttachArgs {
    /// Terminal resource ID to attach to
    #[arg(value_name = "RESOURCE_ID")]
    pub resource_id: String,
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
        };

        let parsed = args.parse_env();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], ("FOO".to_string(), "bar".to_string()));
        assert_eq!(parsed[1], ("BAZ".to_string(), "qux".to_string()));
    }
}
