//! Control socket interface for qsh-server.
//!
//! Provides a Unix socket-based control interface for monitoring and managing
//! the qsh server. Commands include:
//! - Server status (uptime, session count)
//! - List active sessions
//! - Session enrollment (for bootstrap reuse)
//!
//! The protocol uses length-prefixed protobuf messages over Unix domain sockets,
//! shared with qsh-client via the qsh-control crate.

mod handler;

pub use handler::{ServerControlHandler, ServerInfo};
