//! qsh-client: Client library for qsh remote terminal.
//!
//! Provides:
//! - CLI argument parsing
//! - Prediction engine for local echo
//! - Overlay rendering for status and predictions
//! - Bootstrap client for SSH-based server discovery
//! - Session management
//! - Port forwarding handlers
//! - File transfer client
//! - Connection management
//! - Raw terminal mode handling
//! - Channel-based multiplexing (SSH-style)
//! - Direct connection mode with SSH key authentication (feature-gated)

pub mod channel;
pub mod cli;
pub mod connection;
pub mod escape;
pub mod file;
pub mod forward;
pub mod overlay;
pub mod prediction;
pub mod render;
pub mod ssh;
pub mod terminal;

#[cfg(feature = "standalone")]
pub mod standalone;

pub use channel::{FileChannel, ForwardChannel, TerminalChannel};
pub use cli::{Cli, CpCli, FilePath};
pub use connection::{
    ChannelConnection, ChannelHandle, ConnectionConfig, LatencyStats, LatencyTracker, connect_quic,
};
pub use escape::{EscapeCommand, EscapeHandler, EscapeResult, parse_escape_key};
pub use file::TransferResult;
pub use ssh::{BootstrapHandle, BootstrapMode, SshConfig, bootstrap};
pub use terminal::{RawModeGuard, StdinReader, StdoutWriter, get_terminal_size, restore_terminal};

#[cfg(feature = "standalone")]
pub use standalone::{DirectAuthenticator, DirectConfig};
