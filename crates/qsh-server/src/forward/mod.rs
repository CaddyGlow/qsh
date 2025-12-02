//! Port forwarding handlers for qsh server.
//!
//! This module provides:
//! - Forward handler: connects to targets for local/dynamic forwards
//! - Remote forward handler: binds on server for remote forwards (-R)

mod handler;
mod remote;

pub use handler::ForwardHandler;
pub use remote::RemoteForwarder;

#[cfg(test)]
mod tests;
