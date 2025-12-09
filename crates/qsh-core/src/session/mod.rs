//! Session state management for qsh.
//!
//! This module provides:
//! - Reconnection handling with Mosh-style constant retry

mod reconnect;

pub use reconnect::{ReconnectRequest, ReconnectResponse, ReconnectResult, ReconnectionHandler};
