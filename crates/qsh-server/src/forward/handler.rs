//! Server-side forward handler.
//!
//! Handles ForwardRequest messages from clients by connecting to targets
//! and relaying data bidirectionally.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, error, warn};

use qsh_core::Result;
use qsh_core::protocol::{
    ForwardAcceptPayload, ForwardClosePayload, ForwardDataPayload, ForwardEofPayload,
    ForwardRejectPayload, ForwardRequestPayload, ForwardSpec, Message,
};
use qsh_core::transport::{Connection, StreamPair, StreamType};

/// Maximum buffer size for forwarding data.
const FORWARD_BUFFER_SIZE: usize = 32 * 1024;

/// Server-side forward handler.
///
/// Handles incoming forward requests from clients and manages
/// active forward connections.
pub struct ForwardHandler<C: Connection> {
    /// Connection to the client.
    #[allow(dead_code)] // Will be used for sending responses
    connection: Arc<C>,
    /// Active forward connections keyed by forward_id.
    active_forwards: Arc<Mutex<HashMap<u64, ForwardInfo>>>,
    /// Maximum allowed forwards (0 = unlimited).
    max_forwards: u16,
}

/// Information about an active forward.
#[allow(dead_code)] // Fields will be used for connection tracking
struct ForwardInfo {
    spec: ForwardSpec,
}

impl<C: Connection + 'static> ForwardHandler<C> {
    /// Create a new forward handler.
    pub fn new(connection: Arc<C>, max_forwards: u16) -> Self {
        Self {
            connection,
            active_forwards: Arc::new(Mutex::new(HashMap::new())),
            max_forwards,
        }
    }

    /// Handle an incoming forward request.
    ///
    /// This is called when the server receives a ForwardRequest message.
    /// It connects to the target and sets up bidirectional relay.
    pub async fn handle_request(
        &self,
        request: ForwardRequestPayload,
        mut stream: impl StreamPair + 'static,
    ) -> Result<()> {
        let forward_id = request.forward_id;
        let (target_host, target_port) = request.spec.target().unwrap_or(("localhost", 0));
        let target = format!("{}:{}", target_host, target_port);

        debug!(
            forward_id,
            %target,
            spec = ?request.spec,
            "Handling forward request"
        );

        // Check limits
        {
            let forwards = self.active_forwards.lock().await;
            if self.max_forwards > 0 && forwards.len() >= self.max_forwards as usize {
                let reject = Message::ForwardReject(ForwardRejectPayload {
                    forward_id,
                    reason: "max forwards exceeded".into(),
                });
                stream.send(&reject).await?;
                return Ok(());
            }
        }

        // Try to connect to target
        let target_stream = match TcpStream::connect(&target).await {
            Ok(s) => {
                debug!(forward_id, %target, "Connected to target");
                s
            }
            Err(e) => {
                warn!(forward_id, %target, error = %e, "Failed to connect to target");
                let reject = Message::ForwardReject(ForwardRejectPayload {
                    forward_id,
                    reason: format!("connection failed: {}", e),
                });
                stream.send(&reject).await?;
                return Ok(());
            }
        };

        // Send accept
        let accept = Message::ForwardAccept(ForwardAcceptPayload { forward_id });
        stream.send(&accept).await?;

        // Register forward
        {
            let mut forwards = self.active_forwards.lock().await;
            forwards.insert(forward_id, ForwardInfo { spec: request.spec });
        }

        // Spawn relay task
        let active_forwards = Arc::clone(&self.active_forwards);
        tokio::spawn(async move {
            if let Err(e) = Self::relay(forward_id, stream, target_stream).await {
                debug!(forward_id, error = %e, "Forward relay ended");
            }

            // Cleanup
            let mut forwards = active_forwards.lock().await;
            forwards.remove(&forward_id);
        });

        Ok(())
    }

    /// Handle an accepted forward stream (from accept_stream).
    pub async fn handle_stream(&self, stream_type: StreamType, stream: impl StreamPair + 'static) {
        let forward_id = match stream_type {
            StreamType::Forward(id) => id as u64,
            _ => {
                warn!("Unexpected stream type: {:?}", stream_type);
                return;
            }
        };

        // Wait for request message
        let mut stream = stream;
        match stream.recv().await {
            Ok(Message::ForwardRequest(request)) => {
                if let Err(e) = self.handle_request(request, stream).await {
                    error!(forward_id, error = %e, "Forward request handling failed");
                }
            }
            Ok(other) => {
                warn!(forward_id, "Expected ForwardRequest, got: {:?}", other);
            }
            Err(e) => {
                error!(forward_id, error = %e, "Failed to read forward request");
            }
        }
    }

    /// Relay data between client stream and target TCP connection.
    async fn relay(
        forward_id: u64,
        mut client_stream: impl StreamPair,
        target_stream: TcpStream,
    ) -> Result<()> {
        let (mut target_read, mut target_write) = target_stream.into_split();

        // Channel for sending messages to client (from target reader)
        let (tx, mut rx) = mpsc::channel::<Message>(32);

        // Client -> Target: read from client_stream, write to target_write
        // Also receives messages from the channel to send to client
        let relay_task = async {
            loop {
                tokio::select! {
                    // Read from client stream
                    msg_result = client_stream.recv() => {
                        match msg_result {
                            Ok(Message::ForwardData(ForwardDataPayload { forward_id: id, data }))
                                if id == forward_id =>
                            {
                                if let Err(e) = target_write.write_all(&data).await {
                                    error!(forward_id, error = %e, "Target write error");
                                    break;
                                }
                            }
                            Ok(Message::ForwardEof(ForwardEofPayload { forward_id: id }))
                                if id == forward_id =>
                            {
                                debug!(forward_id, "Client EOF");
                                let _ = target_write.shutdown().await;
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
                    // Send messages from target reader to client
                    Some(msg) = rx.recv() => {
                        if let Err(e) = client_stream.send(&msg).await {
                            debug!(forward_id, error = %e, "Failed to send to client");
                            break;
                        }
                        // Check if this was an EOF or Close, and if so break
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

        // Target -> Client: read from target, send via channel
        let target_reader = async {
            let mut buf = vec![0u8; FORWARD_BUFFER_SIZE];
            loop {
                match target_read.read(&mut buf).await {
                    Ok(0) => {
                        debug!(forward_id, "Target EOF");
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
                        error!(forward_id, error = %e, "Target read error");
                        break;
                    }
                }
            }
        };

        // Run both tasks
        tokio::join!(relay_task, target_reader);

        debug!(forward_id, "Forward relay complete");
        Ok(())
    }

    /// Get the number of active forwards.
    pub async fn active_count(&self) -> usize {
        self.active_forwards.lock().await.len()
    }
}
