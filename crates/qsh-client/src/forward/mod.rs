//! Port forwarding handlers for qsh client.
//!
//! Port forwarding is now handled via the channel model:
//! - Local forward (-L): Use `ChannelConnection::open_direct_tcpip()`
//! - Dynamic forward (-D): Use `ChannelConnection::open_dynamic()`
//!
//! The `ForwardChannel` type in the `channel` module provides the bidirectional
//! stream for forwarding data.
//!
//! TODO: Migrate LocalForwarder and Socks5Proxy to use the channel model.
