//! qsh-server: Server library for qsh remote terminal.
//!
//! Provides:
//! - CLI argument parsing
//! - Bootstrap mode for SSH-based discovery
//! - PTY management
//! - Session handling
//! - Port forwarding (local/remote)
//! - Terminal state tracking

pub mod bootstrap;
pub mod cli;
pub mod forward;
pub mod pty;
pub mod session;

pub use bootstrap::BootstrapServer;
pub use cli::Cli;
pub use forward::ForwardHandler;
pub use pty::{Pty, PtyRelay};
pub use session::{ServerSession, SessionConfig};
