//! Local port forward (-L) implementation.
//!
//! Listens on a local address and forwards connections through the qsh connection
//! to a target on the server side.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use qsh_core::constants::FORWARD_BUFFER_SIZE;
use qsh_core::error::{Error, Result};
use qsh_core::protocol::{ChannelCloseReason, DirectTcpIpParams};

use crate::connection::ChannelConnection;

/// Local port forwarder (-L).
///
/// Listens on a local address and opens a DirectTcpIp channel for each
/// incoming connection, forwarding data bidirectionally.
pub struct LocalForwarder {
    /// Local bind address.
    bind_addr: SocketAddr,
    /// Target host on server side.
    target_host: String,
    /// Target port on server side.
    target_port: u16,
    /// Connection to qsh server.
    connection: Arc<ChannelConnection>,
    /// Shutdown signal sender.
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl LocalForwarder {
    /// Create a new local forwarder.
    pub fn new(
        bind_addr: SocketAddr,
        target_host: String,
        target_port: u16,
        connection: Arc<ChannelConnection>,
    ) -> Self {
        Self {
            bind_addr,
            target_host,
            target_port,
            connection,
            shutdown_tx: None,
        }
    }

    /// Start the forwarder, accepting connections until shutdown.
    ///
    /// Returns a handle that can be used to stop the forwarder.
    pub async fn start(mut self) -> Result<ForwarderHandle> {
        let listener = TcpListener::bind(self.bind_addr).await.map_err(|e| Error::Forward {
            message: format!("failed to bind to {}: {}", self.bind_addr, e),
        })?;

        let actual_addr = listener.local_addr().map_err(|e| Error::Forward {
            message: format!("failed to get local address: {}", e),
        })?;

        info!(
            bind = %actual_addr,
            target = %format!("{}:{}", self.target_host, self.target_port),
            "Local forward listening"
        );

        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx.clone());

        let target_host = self.target_host.clone();
        let target_port = self.target_port;
        let connection = Arc::clone(&self.connection);

        // Spawn accept loop
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        debug!(bind = %actual_addr, "Local forward shutdown");
                        break;
                    }
                    accept = listener.accept() => {
                        match accept {
                            Ok((stream, peer_addr)) => {
                                debug!(peer = %peer_addr, "Accepted local forward connection");
                                let conn = Arc::clone(&connection);
                                let host = target_host.clone();
                                let port = target_port;
                                tokio::spawn(async move {
                                    if let Err(e) = Self::handle_connection(stream, peer_addr, host, port, conn).await {
                                        warn!(peer = %peer_addr, error = %e, "Forward connection failed");
                                    }
                                });
                            }
                            Err(e) => {
                                warn!(error = %e, "Failed to accept connection");
                            }
                        }
                    }
                }
            }
        });

        Ok(ForwarderHandle {
            shutdown_tx,
            task: Some(task),
            local_addr: actual_addr,
        })
    }

    /// Handle a single forwarded connection.
    async fn handle_connection(
        local_stream: TcpStream,
        peer_addr: SocketAddr,
        target_host: String,
        target_port: u16,
        connection: Arc<ChannelConnection>,
    ) -> Result<()> {
        // Open a DirectTcpIp channel
        let params = DirectTcpIpParams {
            target_host: target_host.clone(),
            target_port,
            originator_host: peer_addr.ip().to_string(),
            originator_port: peer_addr.port(),
        };

        let channel = connection.open_direct_tcpip(params).await?;
        debug!(
            channel_id = %channel.channel_id(),
            target = %format!("{}:{}", target_host, target_port),
            "Opened forward channel"
        );

        // Split the local stream
        let (mut local_read, mut local_write) = local_stream.into_split();

        // Relay: local -> QUIC
        let channel_clone = channel.clone();
        let local_to_quic = tokio::spawn(async move {
            let mut buf = vec![0u8; FORWARD_BUFFER_SIZE];
            loop {
                match local_read.read(&mut buf).await {
                    Ok(0) => {
                        debug!("Local EOF");
                        break;
                    }
                    Ok(n) => {
                        if let Err(e) = channel_clone.send(&buf[..n]).await {
                            debug!(error = %e, "Failed to send to channel");
                            break;
                        }
                    }
                    Err(e) => {
                        debug!(error = %e, "Local read error");
                        break;
                    }
                }
            }
        });

        // Relay: QUIC -> local
        let channel_clone = channel.clone();
        let quic_to_local = tokio::spawn(async move {
            let mut buf = vec![0u8; FORWARD_BUFFER_SIZE];
            loop {
                match channel_clone.recv(&mut buf).await {
                    Ok(0) => {
                        debug!("QUIC EOF");
                        break;
                    }
                    Ok(n) => {
                        if let Err(e) = local_write.write_all(&buf[..n]).await {
                            debug!(error = %e, "Local write error");
                            break;
                        }
                    }
                    Err(e) => {
                        debug!(error = %e, "QUIC recv error");
                        break;
                    }
                }
            }
            let _ = local_write.shutdown().await;
        });

        // Wait for either direction to complete
        tokio::select! {
            _ = local_to_quic => {}
            _ = quic_to_local => {}
        }

        // Close the channel properly to release server resources
        let channel_id = channel.channel_id();
        if let Err(e) = connection.close_channel(channel_id, ChannelCloseReason::Normal).await {
            warn!(channel_id = %channel_id, error = %e, "Failed to close channel");
        }

        debug!(channel_id = %channel_id, "Forward connection completed");

        Ok(())
    }
}

/// Handle for a running forwarder.
pub struct ForwarderHandle {
    shutdown_tx: mpsc::Sender<()>,
    task: Option<tokio::task::JoinHandle<()>>,
    local_addr: SocketAddr,
}

impl ForwarderHandle {
    /// Get the local address the forwarder is listening on.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Stop the forwarder.
    pub async fn stop(mut self) {
        let _ = self.shutdown_tx.send(()).await;
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for ForwarderHandle {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forwarder_structure() {
        // Just verify the struct compiles
        fn _assert_send<T: Send>() {}
        _assert_send::<ForwarderHandle>();
    }
}
