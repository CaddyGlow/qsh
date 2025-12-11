//! qsh-server: Server library for qsh remote terminal.
//!
//! Provides:
//! - CLI argument parsing
//! - Bootstrap mode for SSH-based discovery
//! - PTY management
//! - Session handling
//! - Port forwarding (local/remote)
//! - File transfer handling
//! - Terminal state tracking
//! - Channel-based multiplexing (SSH-style)
//! - Standalone mode with SSH key authentication (feature-gated)

pub mod bootstrap;
pub mod channel;
pub mod cli;
pub mod connection;
pub mod file;
pub mod forward;
pub mod listener;
pub mod pty;
pub mod registry;
pub mod session;
pub mod ssh;

#[cfg(feature = "standalone")]
pub mod standalone;

pub use bootstrap::BootstrapServer;
pub use channel::{ChannelHandle, FileTransferChannel, ForwardChannel, TerminalChannel};
pub use cli::Cli;
pub use connection::{ConnectionConfig, ConnectionHandler, ConnectionSession};
pub use pty::{Pty, PtyRelay};
pub use registry::{ConnectionRegistry, ConnectionSessionGuard, PtyControl};
pub use session::{PendingSession, SessionAuthorizer, SessionConfig};

#[cfg(feature = "standalone")]
pub use standalone::{StandaloneAuthenticator, StandaloneConfig};
