//! Session state management for qsh.
//!
//! This module provides:
//! - Session state tracking (connected, reconnecting, etc.)
//! - Input sequence tracking for reliable delivery
//! - State generation tracking for reconnection
//! - Reconnection handling with exponential backoff

mod reconnect;
mod state;

pub use reconnect::{ReconnectRequest, ReconnectResponse, ReconnectResult, ReconnectionHandler};
pub use state::{InputTracker, SessionState, SessionStatus};
