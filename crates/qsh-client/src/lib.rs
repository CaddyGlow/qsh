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

pub mod cli;
pub mod connection;
pub mod forward;
pub mod overlay;
pub mod prediction;

pub use cli::Cli;
pub use connection::{ClientConnection, ConnectionConfig, bootstrap_via_ssh};
