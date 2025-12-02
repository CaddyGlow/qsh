//! Local port forwarding handler (-L).
//!
//! Flow:
//! 1. Client binds local port
//! 2. Accept local TCP connection
//! 3. Send ForwardRequest to server
//! 4. Server connects to target
//! 5. Server sends ForwardAccept or ForwardReject
//! 6. Bidirectional data relay

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Mutex};
use tracing::{debug, error, info, warn};

use qsh_core::forward::ParsedForwardSpec;
use qsh_core::protocol::{
    ForwardAcceptPayload, ForwardClosePayload, ForwardDataPayload, ForwardEofPayload,
    ForwardRejectPayload, ForwardRequestPayload, Message,
};
use qsh_core::transport::{Connection, StreamPair, StreamType};
use qsh_core::{Error, Result};

/// Maximum buffer size for forwarding data.
const FORWARD_BUFFER_SIZE: usize = 32 * 1024; // 32KB

/// Local port forwarder.
///
/// Binds to a local address and forwards connections to a target through
/// the qsh server.
pub struct LocalForwarder<C: Connection> {
    /// The forward specification.
    spec: ParsedForwardSpec,
    /// TCP listener for local connections.
    listener: TcpListener,
    /// Connection to the qsh server.
    connection: Arc<C>,
    /// Forward ID counter.
    next_forward_id: AtomicU64,
    /// Active forwards keyed by forward_id.
    active_forwards: Arc<Mutex<HashMap<u64, ForwardState>>>,
    /// Shutdown signal receiver.
    shutdown_rx: Option<oneshot::Receiver<()>>,
}

/// State for a single forwarded connection.
struct ForwardState {
    /// Target host for logging.
    target_host: String,
    /// Target port for logging.
    target_port: u16,
}

impl<C: Connection + 'static> LocalForwarder<C> {
    /// Create a new local forwarder.
    ///
    /// Binds to the address specified in the forward spec.
    pub async fn new(spec: ParsedForwardSpec, connection: Arc<C>) -> Result<Self> {
        let bind_addr = spec.bind_addr();
        let listener = TcpListener::bind(bind_addr).await.map_err(|e| Error::Io(e))?;

        info!(
            addr = %bind_addr,
            target = ?spec.target(),
            "Local forwarder bound"
        );

        Ok(Self {
            spec,
            listener,
            connection,
            next_forward_id: AtomicU64::new(0),
            active_forwards: Arc::new(Mutex::new(HashMap::new())),
            shutdown_rx: None,
        })
    }

    /// Get the local address the forwarder is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.listener.local_addr().map_err(|e| Error::Io(e))
    }

    /// Set a shutdown signal for graceful termination.
    pub fn set_shutdown(&mut self, rx: oneshot::Receiver<()>) {
        self.shutdown_rx = Some(rx);
    }

    /// Run the forwarder, accepting connections until shutdown.
    pub async fn run(&mut self) -> Result<()> {
        let (target_host, target_port) = self
            .spec
            .target()
            .ok_or_else(|| Error::Protocol {
                message: "local forward requires target".into(),
            })?;
        let target_host = target_host.to_string();

        loop {
            tokio::select! {
                accept_result = self.listener.accept() => {
                    match accept_result {
                        Ok((stream, peer_addr)) => {
                            debug!(peer = %peer_addr, "Accepted local connection");
                            self.handle_connection(
                                stream,
                                peer_addr,
                                target_host.clone(),
                                target_port,
                            ).await;
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
                    info!("Local forwarder shutting down");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Handle a single forwarded connection.
    async fn handle_connection(
        &self,
        stream: TcpStream,
        peer_addr: SocketAddr,
        target_host: String,
        target_port: u16,
    ) {
        let forward_id = self.next_forward_id.fetch_add(1, Ordering::SeqCst);
        let connection = Arc::clone(&self.connection);
        let active_forwards = Arc::clone(&self.active_forwards);

        tokio::spawn(async move {
            if let Err(e) = Self::forward_connection(
                forward_id,
                stream,
                peer_addr,
                target_host,
                target_port,
                connection,
                active_forwards,
            )
            .await
            {
                warn!(
                    forward_id,
                    peer = %peer_addr,
                    error = %e,
                    "Forward connection failed"
                );
            }
        });
    }

    /// Handle the full lifecycle of a forwarded connection.
    async fn forward_connection(
        forward_id: u64,
        mut stream: TcpStream,
        peer_addr: SocketAddr,
        target_host: String,
        target_port: u16,
        connection: Arc<C>,
        active_forwards: Arc<Mutex<HashMap<u64, ForwardState>>>,
    ) -> Result<()> {
        // Open a forward stream to the server
        let mut server_stream = connection.open_stream(StreamType::Forward(forward_id as u32)).await?;

        // Send forward request
        let request = Message::ForwardRequest(ForwardRequestPayload {
            forward_id,
            spec: qsh_core::protocol::ForwardSpec::Local {
                bind_port: 0, // Server doesn't need this for local forwards
            },
            target: target_host.clone(),
            target_port,
        });
        server_stream.send(&request).await?;

        // Wait for accept/reject
        let response = server_stream.recv().await?;
        match response {
            Message::ForwardAccept(ForwardAcceptPayload { forward_id: id }) if id == forward_id => {
                debug!(
                    forward_id,
                    target = %format!("{}:{}", target_host, target_port),
                    "Forward accepted"
                );
            }
            Message::ForwardReject(ForwardRejectPayload { forward_id: id, reason }) if id == forward_id => {
                warn!(forward_id, %reason, "Forward rejected");
                return Err(Error::Protocol {
                    message: format!("forward rejected: {}", reason),
                });
            }
            other => {
                return Err(Error::Protocol {
                    message: format!("unexpected response to forward request: {:?}", other),
                });
            }
        }

        // Register the forward
        {
            let mut forwards = active_forwards.lock().await;
            forwards.insert(
                forward_id,
                ForwardState {
                    target_host: target_host.clone(),
                    target_port,
                },
            );
        }

        // Split TCP stream and set up channel for server messages
        let (mut tcp_read, mut tcp_write) = stream.into_split();
        let (tx, mut rx) = mpsc::channel::<Message>(32);

        // Main relay task: handles server_stream and tcp_write
        let relay_task = async {
            loop {
                tokio::select! {
                    // Read from server stream
                    msg_result = server_stream.recv() => {
                        match msg_result {
                            Ok(Message::ForwardData(ForwardDataPayload { forward_id: id, data }))
                                if id == forward_id =>
                            {
                                if let Err(e) = tcp_write.write_all(&data).await {
                                    error!(forward_id, error = %e, "Local write error");
                                    break;
                                }
                            }
                            Ok(Message::ForwardEof(ForwardEofPayload { forward_id: id }))
                                if id == forward_id =>
                            {
                                debug!(forward_id, "Server EOF");
                                let _ = tcp_write.shutdown().await;
                            }
                            Ok(Message::ForwardClose(ForwardClosePayload { forward_id: id, reason }))
                                if id == forward_id =>
                            {
                                debug!(forward_id, ?reason, "Forward closed by server");
                                break;
                            }
                            Ok(other) => {
                                warn!(forward_id, "Unexpected message: {:?}", other);
                            }
                            Err(e) => {
                                debug!(forward_id, error = %e, "Server stream error");
                                break;
                            }
                        }
                    }
                    // Forward messages from TCP reader to server
                    Some(msg) = rx.recv() => {
                        if let Err(e) = server_stream.send(&msg).await {
                            debug!(forward_id, error = %e, "Failed to send to server");
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
            let _ = server_stream.send(&close).await;
            server_stream.close();
        };

        // TCP reader task: reads from local, sends via channel
        let tcp_reader = async {
            let mut buf = vec![0u8; FORWARD_BUFFER_SIZE];
            loop {
                match tcp_read.read(&mut buf).await {
                    Ok(0) => {
                        debug!(forward_id, "Local client EOF");
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
                        error!(forward_id, error = %e, "Local read error");
                        break;
                    }
                }
            }
        };

        // Run both tasks
        tokio::join!(relay_task, tcp_reader);

        // Cleanup
        {
            let mut forwards = active_forwards.lock().await;
            forwards.remove(&forward_id);
        }

        debug!(
            forward_id,
            peer = %peer_addr,
            target = %format!("{}:{}", target_host, target_port),
            "Forward connection closed"
        );

        Ok(())
    }
}

/// Manager for multiple local forwards.
pub struct LocalForwardManager<C: Connection> {
    /// Active forwarders.
    forwarders: Vec<LocalForwarder<C>>,
    /// Connection to the server.
    connection: Arc<C>,
}

impl<C: Connection + 'static> LocalForwardManager<C> {
    /// Create a new forward manager.
    pub fn new(connection: Arc<C>) -> Self {
        Self {
            forwarders: Vec::new(),
            connection,
        }
    }

    /// Add a local forward from a specification string.
    pub async fn add_forward(&mut self, spec_str: &str) -> Result<SocketAddr> {
        let spec = ParsedForwardSpec::parse_local(spec_str)?;
        let forwarder = LocalForwarder::new(spec, Arc::clone(&self.connection)).await?;
        let addr = forwarder.local_addr()?;
        self.forwarders.push(forwarder);
        Ok(addr)
    }

    /// Run all forwarders concurrently.
    pub async fn run_all(&mut self) -> Result<()> {
        let mut handles = Vec::new();

        for mut forwarder in self.forwarders.drain(..) {
            handles.push(tokio::spawn(async move {
                if let Err(e) = forwarder.run().await {
                    error!("Forwarder error: {}", e);
                }
            }));
        }

        // Wait for all to complete (they shouldn't unless shutdown)
        for handle in handles {
            let _ = handle.await;
        }

        Ok(())
    }
}
