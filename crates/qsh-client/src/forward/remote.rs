//! Remote port forward handler (-R).
//!
//! This module provides the `RemoteForwarder` which requests the server to bind
//! a port and forward incoming connections back to a local target on the client.

use std::sync::Arc;

use tracing::{debug, info};

use qsh_core::error::Result;

use crate::connection::ChannelConnection;

/// Remote port forwarder (-R).
///
/// Requests the server to listen on a port and forward incoming connections
/// back to a local target on the client side.
pub struct RemoteForwarder {
    /// Connection to the server.
    connection: Arc<ChannelConnection>,
    /// Bind host on server.
    bind_host: String,
    /// Bind port on server.
    bind_port: u16,
    /// Local target host.
    target_host: String,
    /// Local target port.
    target_port: u16,
}

impl RemoteForwarder {
    /// Create a new remote forwarder.
    ///
    /// - `bind_host`: Address to bind on the server (e.g., "0.0.0.0" or "localhost")
    /// - `bind_port`: Port to bind on the server (0 for ephemeral)
    /// - `target_host`: Local address to connect to when server gets a connection
    /// - `target_port`: Local port to connect to
    pub fn new(
        connection: Arc<ChannelConnection>,
        bind_host: String,
        bind_port: u16,
        target_host: String,
        target_port: u16,
    ) -> Self {
        Self {
            connection,
            bind_host,
            bind_port,
            target_host,
            target_port,
        }
    }

    /// Start the remote forward.
    ///
    /// Sends a GlobalRequest to the server to bind the port. Returns a handle
    /// that can be used to stop the forward.
    ///
    /// The actual handling of incoming connections is done by the connection's
    /// control message loop calling `handle_forwarded_channel_open`.
    pub async fn start(&self) -> Result<RemoteForwarderHandle> {
        debug!(
            bind = %format!("{}:{}", self.bind_host, self.bind_port),
            target = %format!("{}:{}", self.target_host, self.target_port),
            "Starting remote forward"
        );

        // Request the server to bind the port
        let bound_port = self
            .connection
            .request_remote_forward(
                &self.bind_host,
                self.bind_port,
                &self.target_host,
                self.target_port,
            )
            .await?;

        info!(
            bind_host = %self.bind_host,
            bind_port = self.bind_port,
            bound_port,
            target = %format!("{}:{}", self.target_host, self.target_port),
            "Remote forward established"
        );

        Ok(RemoteForwarderHandle {
            connection: Arc::clone(&self.connection),
            bind_host: self.bind_host.clone(),
            bound_port,
        })
    }
}

/// Handle to an active remote forward.
pub struct RemoteForwarderHandle {
    /// Connection to the server.
    connection: Arc<ChannelConnection>,
    /// Bind host on server.
    bind_host: String,
    /// Actual bound port on server.
    bound_port: u16,
}

impl RemoteForwarderHandle {
    /// Get the actual bound port on the server.
    pub fn bound_port(&self) -> u16 {
        self.bound_port
    }

    /// Get the bind host.
    pub fn bind_host(&self) -> &str {
        &self.bind_host
    }

    /// Stop the remote forward.
    ///
    /// Sends a GlobalRequest to cancel the forward on the server.
    pub async fn stop(&self) -> Result<()> {
        debug!(
            bind = %format!("{}:{}", self.bind_host, self.bound_port),
            "Stopping remote forward"
        );

        self.connection
            .cancel_remote_forward(&self.bind_host, self.bound_port)
            .await?;

        info!(
            bind = %format!("{}:{}", self.bind_host, self.bound_port),
            "Remote forward stopped"
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remote_forwarder_compiles() {
        // Just verify the types compile
        fn _assert_send<T: Send>() {}
        fn _assert_sync<T: Sync>() {}
        _assert_send::<RemoteForwarder>();
        _assert_sync::<RemoteForwarder>();
        _assert_send::<RemoteForwarderHandle>();
        _assert_sync::<RemoteForwarderHandle>();
    }
}
