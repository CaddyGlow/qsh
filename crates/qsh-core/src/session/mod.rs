//! Session state management for qsh.
//!
//! This module provides:
//! - Session state tracking (connected, reconnecting, etc.)
//! - Input sequence tracking for reliable delivery
//! - State generation tracking for reconnection

mod state;

pub use state::{InputTracker, SessionState, SessionStatus};
