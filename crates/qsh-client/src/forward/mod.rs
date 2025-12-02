//! Port forwarding handlers for qsh client.
//!
//! This module provides:
//! - Local forward handler (-L): binds locally, connects via server
//! - SOCKS5 proxy (-D): dynamic forwarding via SOCKS5 protocol

mod local;
mod socks;

pub use local::LocalForwarder;
pub use socks::Socks5Proxy;

#[cfg(test)]
mod tests;
