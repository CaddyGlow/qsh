//! Remote port forwarding handler (-R).
//!
//! Flow:
//! 1. Client sends ForwardRequest with Remote spec
//! 2. Server binds the specified port
//! 3. When connection arrives, server sends ForwardRequest to client
//! 4. Client connects to local target
//! 5. Bidirectional data relay

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};

use qsh_core::protocol::{
    ForwardAcceptPayload, ForwardClosePayload, ForwardDataPayload, ForwardEofPayload,
    ForwardRejectPayload, ForwardRequestPayload, ForwardSpec, Message,
};
use qsh_core::transport::{Connection, StreamPair, StreamType};
use qsh_core::{Error, Result};

/// Maximum buffer size for forwarding data.
const FORWARD_BUFFER_SIZE: usize = 32 * 1024;

/// Remote port forwarder.
///
/// Binds on the server and forwards incoming connections back to the client.
pub struct RemoteForwarder<C: Connection> {
    /// The bind address on the server.
    bind_addr: SocketAddr,
    /// Target host on the client side.
    target_host: String,
    /// Target port on the client side.
    target_port: u16,
    /// TCP listener for incoming connections.
    listener: TcpListener,
    /// Connection to the qsh client.
    connection: Arc<C>,
    /// Forward ID counter.
    next_forward_id: AtomicU64,
    /// Shutdown signal receiver.
    shutdown_rx: Option<oneshot::Receiver<()>>,
}

impl<C: Connection + 'static> RemoteForwarder<C> {
    /// Create a new remote forwarder.
    pub async fn new(
        bind_addr: SocketAddr,
        target_host: String,
        target_port: u16,
        connection: Arc<C>,
    ) -> Result<Self> {
        let listener = TcpListener::bind(bind_addr).await.map_err(Error::Io)?;
        let actual_addr = listener.local_addr().map_err(Error::Io)?;

        info!(
            bind = %actual_addr,
            target = %format!("{}:{}", target_host, target_port),
            "Remote forwarder bound"
        );

        Ok(Self {
            bind_addr: actual_addr,
            target_host,
            target_port,
            listener,
            connection,
            next_forward_id: AtomicU64::new(0),
            shutdown_rx: None,
        })
    }

    /// Get the actual bound address.
    pub fn local_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    /// Set a shutdown signal for graceful termination.
    pub fn set_shutdown(&mut self, rx: oneshot::Receiver<()>) {
        self.shutdown_rx = Some(rx);
    }

    /// Run the forwarder, accepting connections until shutdown.
    pub async fn run(&mut self) -> Result<()> {
        loop {
            tokio::select! {
                accept_result = self.listener.accept() => {
                    match accept_result {
                        Ok((stream, peer_addr)) => {
                            debug!(peer = %peer_addr, "Accepted remote forward connection");
                            self.handle_connection(stream, peer_addr).await;
                        }
                        Err(e) => {
                            error!(error = %e, "Accept failed");
                        }
                    }
                }
                _ = async {
                    if let Some(ref mut rx) = self.shutdown_rx {
                        let _ = rx.await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {
                    info!("Remote forwarder shutting down");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Handle a single incoming connection.
    async fn handle_connection(&self, stream: TcpStream, peer_addr: SocketAddr) {
        let forward_id = self.next_forward_id.fetch_add(1, Ordering::SeqCst);
        let connection = Arc::clone(&self.connection);
        let target_host = self.target_host.clone();
        let target_port = self.target_port;
        let bind_port = self.bind_addr.port();

        tokio::spawn(async move {
            if let Err(e) = Self::forward_connection(
                forward_id,
                stream,
                peer_addr,
                target_host,
                target_port,
                bind_port,
                connection,
            )
            .await
            {
                debug!(
                    forward_id,
                    peer = %peer_addr,
                    error = %e,
                    "Remote forward connection failed"
                );
            }
        });
    }

    /// Handle the full lifecycle of a remote forwarded connection.
    async fn forward_connection(
        forward_id: u64,
        mut stream: TcpStream,
        peer_addr: SocketAddr,
        target_host: String,
        target_port: u16,
        bind_port: u16,
        connection: Arc<C>,
    ) -> Result<()> {
        // Open a forward stream to the client
        let mut client_stream = connection
            .open_stream(StreamType::Forward(forward_id as u32))
            .await?;

        // Send forward request to client
        let request = Message::ForwardRequest(ForwardRequestPayload {
            forward_id,
            spec: ForwardSpec::Remote {
                bind_addr: std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    bind_port,
                ),
                target_host: target_host.clone(),
                target_port,
            },
        });
        client_stream.send(&request).await?;

        // Wait for accept/reject from client
        let response = client_stream.recv().await?;
        match response {
            Message::ForwardAccept(ForwardAcceptPayload { forward_id: id }) if id == forward_id => {
                debug!(
                    forward_id,
                    target = %format!("{}:{}", target_host, target_port),
                    "Client accepted remote forward"
                );
            }
            Message::ForwardReject(ForwardRejectPayload {
                forward_id: id,
                reason,
            }) if id == forward_id => {
                warn!(forward_id, %reason, "Client rejected remote forward");
                return Err(Error::Protocol {
                    message: format!("client rejected forward: {}", reason),
                });
            }
            other => {
                return Err(Error::Protocol {
                    message: format!("unexpected response: {:?}", other),
                });
            }
        }

        // Relay data using channels to avoid mutable borrow issues
        let (mut tcp_read, mut tcp_write) = stream.into_split();
        let (tx, mut rx) = mpsc::channel::<Message>(32);

        // Main relay task: handles client_stream (recv) and tcp_write
        let relay_task = async {
            loop {
                tokio::select! {
                    // Read from client stream
                    msg_result = client_stream.recv() => {
                        match msg_result {
                            Ok(Message::ForwardData(ForwardDataPayload { forward_id: id, data }))
                                if id == forward_id =>
                            {
                                if let Err(e) = tcp_write.write_all(&data).await {
                                    error!(forward_id, error = %e, "Incoming write error");
                                    break;
                                }
                            }
                            Ok(Message::ForwardEof(ForwardEofPayload { forward_id: id }))
                                if id == forward_id =>
                            {
                                debug!(forward_id, "Client EOF");
                                let _ = tcp_write.shutdown().await;
                            }
                            Ok(Message::ForwardClose(ForwardClosePayload { forward_id: id, reason }))
                                if id == forward_id =>
                            {
                                debug!(forward_id, ?reason, "Client closed forward");
                                break;
                            }
                            Ok(other) => {
                                warn!(forward_id, "Unexpected message: {:?}", other);
                            }
                            Err(e) => {
                                debug!(forward_id, error = %e, "Client stream error");
                                break;
                            }
                        }
                    }
                    // Forward messages from TCP reader to client
                    Some(msg) = rx.recv() => {
                        if let Err(e) = client_stream.send(&msg).await {
                            debug!(forward_id, error = %e, "Failed to send to client");
                            break;
                        }
                        if matches!(msg, Message::ForwardEof(_) | Message::ForwardClose(_)) {
                            break;
                        }
                    }
                }
            }

            // Send close
            let close = Message::ForwardClose(ForwardClosePayload {
                forward_id,
                reason: None,
            });
            let _ = client_stream.send(&close).await;
            client_stream.close();
        };

        // TCP reader task: reads from incoming connection, sends via channel
        let tcp_reader = async {
            let mut buf = vec![0u8; FORWARD_BUFFER_SIZE];
            loop {
                match tcp_read.read(&mut buf).await {
                    Ok(0) => {
                        debug!(forward_id, "Incoming connection EOF");
                        let eof = Message::ForwardEof(ForwardEofPayload { forward_id });
                        let _ = tx.send(eof).await;
                        break;
                    }
                    Ok(n) => {
                        let data = Message::ForwardData(ForwardDataPayload {
                            forward_id,
                            data: buf[..n].to_vec(),
                        });
                        if tx.send(data).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        error!(forward_id, error = %e, "Incoming read error");
                        break;
                    }
                }
            }
        };

        // Run both tasks
        tokio::join!(relay_task, tcp_reader);

        debug!(
            forward_id,
            peer = %peer_addr,
            target = %format!("{}:{}", target_host, target_port),
            "Remote forward connection closed"
        );

        Ok(())
    }
}

/// Manager for multiple remote forwards.
pub struct RemoteForwardManager<C: Connection> {
    /// Active forwarders.
    forwarders: Vec<RemoteForwarder<C>>,
    /// Connection to the client.
    connection: Arc<C>,
}

impl<C: Connection + 'static> RemoteForwardManager<C> {
    /// Create a new remote forward manager.
    pub fn new(connection: Arc<C>) -> Self {
        Self {
            forwarders: Vec::new(),
            connection,
        }
    }

    /// Add a remote forward.
    pub async fn add_forward(
        &mut self,
        bind_addr: SocketAddr,
        target_host: String,
        target_port: u16,
    ) -> Result<SocketAddr> {
        let forwarder = RemoteForwarder::new(
            bind_addr,
            target_host,
            target_port,
            Arc::clone(&self.connection),
        )
        .await?;
        let addr = forwarder.local_addr();
        self.forwarders.push(forwarder);
        Ok(addr)
    }

    /// Run all forwarders concurrently.
    pub async fn run_all(&mut self) -> Result<()> {
        let mut handles = Vec::new();

        for mut forwarder in self.forwarders.drain(..) {
            handles.push(tokio::spawn(async move {
                if let Err(e) = forwarder.run().await {
                    error!("Remote forwarder error: {}", e);
                }
            }));
        }

        // Wait for all to complete
        for handle in handles {
            let _ = handle.await;
        }

        Ok(())
    }
}
