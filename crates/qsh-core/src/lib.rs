//! qsh-core: Shared library for qsh protocol, types, and terminal state.
//!
//! This crate provides:
//! - Protocol message definitions and wire format codec
//! - Terminal state representation and parsing
//! - Transport abstractions
//! - Session management types
//! - Port forwarding types
//! - Logging and metrics
//! - Tunnel types (feature-gated)

pub mod bootstrap;
pub mod constants;
pub mod error;
pub mod forward;
pub mod logging;
pub mod metrics;
pub mod protocol;
pub mod session;
pub mod terminal;
pub mod transport;

pub use error::{Error, Result};
pub use logging::{LogFormat, init_logging};
pub use metrics::ConnectionMetrics;
