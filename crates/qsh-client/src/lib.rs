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
pub mod reconnectable;
pub mod render;
pub mod session;
pub mod ssh;
pub mod terminal;

#[cfg(feature = "standalone")]
pub mod standalone;

pub use channel::{FileChannel, ForwardChannel, TerminalChannel, TerminalEvent};
pub use cli::{Cli, CpCli, FilePath};
pub use connection::{
    ChannelConnection, ChannelHandle, ConnectionConfig, HeartbeatTracker,
    establish_quic_connection, random_local_port,
};
pub use escape::{EscapeCommand, EscapeHandler, EscapeResult, parse_escape_key};
pub use file::TransferResult;
pub use forward::{
    ForwarderHandle, LocalForwarder, ProxyHandle, RemoteForwarder, RemoteForwarderHandle,
    Socks5Proxy, parse_dynamic_forward, parse_local_forward, parse_remote_forward,
};
pub use reconnectable::ReconnectableConnection;
pub use session::{ConnectionState, SessionContext, TerminalSessionState};
pub use ssh::{BootstrapHandle, BootstrapMode, SshConfig, bootstrap};
pub use terminal::{RawModeGuard, StdinReader, StdoutWriter, get_terminal_size, restore_terminal};

#[cfg(feature = "standalone")]
pub use standalone::{DirectAuthenticator, DirectConfig};
