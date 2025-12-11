//! Connection management abstractions for qsh.
//!
//! This module provides shared types and utilities for connection management:
//! - `HeartbeatTracker`: Mosh-style RTT measurement using Jacobson/Karamcheti algorithm
//! - `ChannelMap`: Generic channel container for both client and server
//! - `GlobalRequestTracker`: Track pending global requests and responses

mod channel_map;
mod global_request;
mod heartbeat;

pub use channel_map::ChannelMap;
pub use global_request::GlobalRequestTracker;
pub use heartbeat::{HeartbeatPayload, HeartbeatTracker};
