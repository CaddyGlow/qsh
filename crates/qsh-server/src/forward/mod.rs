//! Port forwarding handlers for qsh server.
//!
//! Port forwards are now handled via the channel model:
//! - Local (-L): Client sends ChannelOpen with DirectTcpIp params
//! - Remote (-R): Client sends GlobalRequest::TcpIpForward, server sends ChannelOpen with ForwardedTcpIp
//! - Dynamic (-D): Client sends ChannelOpen with DynamicForward params
//!
//! See the `channel` module and `ConnectionHandler` for the implementation.
