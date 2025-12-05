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
//! - Standalone mode with SSH key authentication (feature-gated)

pub mod bootstrap;
pub mod cli;
pub mod file;
pub mod forward;
pub mod pty;
pub mod registry;
pub mod session;

#[cfg(feature = "standalone")]
pub mod standalone;

pub use bootstrap::BootstrapServer;
pub use cli::Cli;
pub use file::FileHandler;
pub use forward::ForwardHandler;
pub use pty::{Pty, PtyRelay};
pub use registry::{RealSessionSpawner, SessionRegistry};
pub use session::{PendingSession, ServerSession, SessionAuthorizer, SessionConfig};

#[cfg(feature = "standalone")]
pub use standalone::{StandaloneAuthenticator, StandaloneConfig};
