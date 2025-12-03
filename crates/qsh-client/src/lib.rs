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
pub mod render;
pub mod ssh;
pub mod terminal;

pub use cli::Cli;
pub use connection::{ClientConnection, ConnectionConfig, LatencyStats, LatencyTracker};
pub use forward::{LocalForwarder, Socks5Proxy};
pub use ssh::{BootstrapHandle, BootstrapMode, SshConfig, bootstrap};
pub use terminal::{RawModeGuard, StdinReader, StdoutWriter, get_terminal_size, restore_terminal};
