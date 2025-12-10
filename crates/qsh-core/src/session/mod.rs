//! Session state management for qsh.
//!
//! This module provides:
//! - Reconnection handling with Mosh-style constant retry
//! - Shared session configuration types
//! - Connection state tracking

mod config;
mod reconnect;
mod state;

pub use config::BaseSessionConfig;
pub use reconnect::{ReconnectRequest, ReconnectResponse, ReconnectResult, ReconnectionHandler};
pub use state::{ConnectionState, SessionState, TerminalSessionState};
