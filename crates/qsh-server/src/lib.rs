//! qsh-server: Server library for qsh remote terminal.
//!
//! Provides:
//! - CLI argument parsing
//! - PTY management
//! - Session handling
//! - Port forwarding (local/remote)
//! - Terminal state tracking

pub mod cli;
pub mod forward;

pub use cli::Cli;
