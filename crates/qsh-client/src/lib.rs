//! qsh-client: Client library for qsh remote terminal.
//!
//! Provides:
//! - CLI argument parsing
//! - Prediction engine for local echo
//! - Overlay rendering for status and predictions
//! - Bootstrap client for SSH-based server discovery
//! - Session management
//! - Port forwarding handlers
//! - Connection management
//! - Raw terminal mode handling

pub mod cli;
pub mod connection;
pub mod forward;
pub mod overlay;
pub mod prediction;
pub mod ssh;
pub mod terminal;

pub use cli::Cli;
pub use connection::{ClientConnection, ConnectionConfig};
pub use ssh::{bootstrap, SshConfig};
pub use terminal::{RawModeGuard, StdinReader, StdoutWriter, get_terminal_size, restore_terminal};
