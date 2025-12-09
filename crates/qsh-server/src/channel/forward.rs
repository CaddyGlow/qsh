//! Port forward channel implementation.
//!
//! Manages port forwarding (direct-tcpip, forwarded-tcpip, dynamic) within a channel.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use qsh_core::constants::FORWARD_BUFFER_SIZE;
use qsh_core::error::{Error, Result};
use qsh_core::protocol::{
    ChannelId, DirectTcpIpParams, DynamicForwardParams, ForwardedTcpIpParams,
};
use qsh_core::transport::{Connection, QuicConnection, QuicStream, StreamType};

/// Type of port forward.
#[derive(Debug, Clone)]
pub enum ForwardType {
    /// Direct TCP/IP (-L local forward): client listens, server connects to target.
    Direct {
        target_host: String,
        target_port: u16,
    },
    /// Forwarded TCP/IP (-R remote forward): server listens, client connects to target.
    Forwarded {
        bound_host: String,
        bound_port: u16,
    },
    /// Dynamic SOCKS5 forward (-D).
    Dynamic {
        target_host: String,
        target_port: u16,
    },
}

/// Port forward channel managing bidirectional data relay.
#[derive(Clone)]
pub struct ForwardChannel {
    inner: Arc<ForwardChannelInner>,
}

struct ForwardChannelInner {
    /// Channel ID.
    channel_id: ChannelId,
    /// QUIC connection (for server-initiated streams).
    #[allow(dead_code)]
    quic: Arc<QuicConnection>,
    /// Forward type.
    forward_type: ForwardType,
    /// Target TCP connection (if connected).
    target_stream: Mutex<Option<TcpStream>>,
    /// Whether the channel is closed.
    closed: AtomicBool,
    /// Relay task handle.
    relay_task: Mutex<Option<JoinHandle<()>>>,
    /// Shutdown signal sender.
    shutdown_tx: Mutex<Option<mpsc::Sender<()>>>,
    /// Channel to send the client's QUIC stream when it arrives.
    stream_tx: Mutex<Option<oneshot::Sender<QuicStream>>>,
}

impl ForwardChannel {
    /// Create a new direct TCP/IP forward channel (-L).
    ///
    /// For client-initiated channels, we connect to the target but wait for
    /// the client's QUIC stream to arrive via `handle_incoming_stream`.
    pub async fn new_direct(
        channel_id: ChannelId,
        params: DirectTcpIpParams,
        quic: Arc<QuicConnection>,
    ) -> Result<Self> {
        let target = format!("{}:{}", params.target_host, params.target_port);
        debug!(
            channel_id = %channel_id,
            target = %target,
            "Creating direct-tcpip channel"
        );

        // Connect to target
        let target_stream = TcpStream::connect(&target)
            .await
            .map_err(|e| Error::Forward {
                message: format!("failed to connect to {}: {}", target, e),
            })?;

        info!(
            channel_id = %channel_id,
            target = %target,
            "Connected to forward target"
        );

        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
        let (stream_tx, stream_rx) = oneshot::channel();

        let inner = Arc::new(ForwardChannelInner {
            channel_id,
            quic,
            forward_type: ForwardType::Direct {
                target_host: params.target_host,
                target_port: params.target_port,
            },
            target_stream: Mutex::new(Some(target_stream)),
            closed: AtomicBool::new(false),
            relay_task: Mutex::new(None),
            shutdown_tx: Mutex::new(Some(shutdown_tx)),
            stream_tx: Mutex::new(Some(stream_tx)),
        });

        let channel = Self { inner };

        // Start relay task that waits for client's stream
        channel.start_relay_waiting(shutdown_rx, stream_rx).await;

        Ok(channel)
    }

    /// Create a new forwarded TCP/IP channel (-R).
    ///
    /// This is called by the server when a connection arrives on a remote forward listener.
    /// For server-initiated channels, the server opens the QUIC stream and has the incoming
    /// TCP connection ready.
    pub async fn new_forwarded(
        channel_id: ChannelId,
        params: ForwardedTcpIpParams,
        quic: Arc<QuicConnection>,
        tcp_stream: TcpStream,
    ) -> Result<Self> {
        debug!(
            channel_id = %channel_id,
            bound = %format!("{}:{}", params.bound_host, params.bound_port),
            originator = %format!("{}:{}", params.originator_host, params.originator_port),
            "Creating forwarded-tcpip channel"
        );

        // For forwarded channels, we open the QUIC stream since this is server-initiated
        let quic_stream = quic
            .as_ref()
            .open_stream(StreamType::ChannelBidi(channel_id))
            .await
            .map_err(|e| Error::Transport {
                message: format!("failed to open forward stream: {}", e),
            })?;

        info!(
            channel_id = %channel_id,
            bound = %format!("{}:{}", params.bound_host, params.bound_port),
            "Forwarded channel ready"
        );

        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        let inner = Arc::new(ForwardChannelInner {
            channel_id,
            quic,
            forward_type: ForwardType::Forwarded {
                bound_host: params.bound_host,
                bound_port: params.bound_port,
            },
            target_stream: Mutex::new(None), // Not used - we have the stream already
            closed: AtomicBool::new(false),
            relay_task: Mutex::new(None),
            shutdown_tx: Mutex::new(Some(shutdown_tx)),
            stream_tx: Mutex::new(None), // Not needed for server-initiated
        });

        let channel = Self { inner };

        // Start relay immediately since we have both the TCP stream and QUIC stream
        channel.start_relay_immediate(tcp_stream, quic_stream, shutdown_rx).await;

        Ok(channel)
    }

    /// Start the bidirectional relay immediately with both streams ready.
    ///
    /// Used for forwarded-tcpip channels where we have both the incoming TCP
    /// connection and the QUIC stream ready.
    async fn start_relay_immediate(
        &self,
        tcp_stream: TcpStream,
        quic_stream: QuicStream,
        shutdown_rx: mpsc::Receiver<()>,
    ) {
        let inner = Arc::clone(&self.inner);
        let channel_id = inner.channel_id;

        let task = tokio::spawn(async move {
            debug!(channel_id = %channel_id, "Starting forwarded relay");
            Self::run_relay(channel_id, tcp_stream, quic_stream, shutdown_rx).await;
        });

        *self.inner.relay_task.lock().await = Some(task);
    }

    /// Create a new dynamic SOCKS5 forward channel (-D).
    ///
    /// Same as direct-tcpip: wait for client's QUIC stream.
    pub async fn new_dynamic(
        channel_id: ChannelId,
        params: DynamicForwardParams,
        quic: Arc<QuicConnection>,
    ) -> Result<Self> {
        let target = format!("{}:{}", params.target_host, params.target_port);
        debug!(
            channel_id = %channel_id,
            target = %target,
            "Creating dynamic forward channel"
        );

        // Connect to target (SOCKS proxy has already resolved the destination)
        let target_stream = TcpStream::connect(&target)
            .await
            .map_err(|e| Error::Forward {
                message: format!("failed to connect to {}: {}", target, e),
            })?;

        info!(
            channel_id = %channel_id,
            target = %target,
            "Connected to dynamic forward target"
        );

        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
        let (stream_tx, stream_rx) = oneshot::channel();

        let inner = Arc::new(ForwardChannelInner {
            channel_id,
            quic,
            forward_type: ForwardType::Dynamic {
                target_host: params.target_host,
                target_port: params.target_port,
            },
            target_stream: Mutex::new(Some(target_stream)),
            closed: AtomicBool::new(false),
            relay_task: Mutex::new(None),
            shutdown_tx: Mutex::new(Some(shutdown_tx)),
            stream_tx: Mutex::new(Some(stream_tx)),
        });

        let channel = Self { inner };

        // Start relay task that waits for client's stream
        channel.start_relay_waiting(shutdown_rx, stream_rx).await;

        Ok(channel)
    }

    /// Start the bidirectional relay, waiting for the client's QUIC stream first.
    async fn start_relay_waiting(
        &self,
        mut shutdown_rx: mpsc::Receiver<()>,
        stream_rx: oneshot::Receiver<QuicStream>,
    ) {
        let inner = Arc::clone(&self.inner);

        let task = tokio::spawn(async move {
            let channel_id = inner.channel_id;

            // Wait for the client's QUIC stream to arrive
            debug!(channel_id = %channel_id, "Waiting for client QUIC stream");

            let quic_stream = tokio::select! {
                result = stream_rx => {
                    match result {
                        Ok(stream) => stream,
                        Err(_) => {
                            debug!(channel_id = %channel_id, "Stream channel cancelled");
                            return;
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    debug!(channel_id = %channel_id, "Shutdown before stream arrived");
                    return;
                }
            };

            debug!(channel_id = %channel_id, "Client QUIC stream received, starting relay");

            // Take ownership of the target stream
            let target_stream = inner.target_stream.lock().await.take();

            let target_stream = match target_stream {
                Some(t) => t,
                None => {
                    warn!(channel_id = %channel_id, "No target stream available");
                    return;
                }
            };

            // Run the bidirectional relay
            Self::run_relay(channel_id, target_stream, quic_stream, shutdown_rx).await;
        });

        *self.inner.relay_task.lock().await = Some(task);
    }

    /// Run the bidirectional relay between target TCP and QUIC stream.
    async fn run_relay(
        channel_id: ChannelId,
        target_stream: TcpStream,
        quic_stream: QuicStream,
        mut shutdown_rx: mpsc::Receiver<()>,
    ) {
        let (mut target_read, mut target_write) = target_stream.into_split();

        // Task: target -> QUIC (returns the sender so we can finish it)
        let quic_sender = quic_stream.sender().expect("forward stream must support sending");
        let quic_sender_for_finish = quic_sender.clone();
        let target_to_quic = {
            let channel_id = channel_id;
            tokio::spawn(async move {
                let mut buf = vec![0u8; FORWARD_BUFFER_SIZE];
                loop {
                    match target_read.read(&mut buf).await {
                        Ok(0) => {
                            debug!(channel_id = %channel_id, "Target EOF");
                            break;
                        }
                        Ok(n) => {
                            if let Err(e) = quic_sender.send_raw(&buf[..n]).await {
                                debug!(channel_id = %channel_id, error = %e, "QUIC send error");
                                break;
                            }
                        }
                        Err(e) => {
                            debug!(channel_id = %channel_id, error = %e, "Target read error");
                            break;
                        }
                    }
                }
                // Send FIN to signal EOF to the remote peer
                if let Err(e) = quic_sender.finish().await {
                    debug!(channel_id = %channel_id, error = %e, "QUIC finish error");
                }
            })
        };

        // Task: QUIC -> target
        let quic_to_target = {
            let channel_id = channel_id;
            tokio::spawn(async move {
                let mut buf = vec![0u8; FORWARD_BUFFER_SIZE];
                loop {
                    match quic_stream.recv_raw(&mut buf).await {
                        Ok(0) => {
                            debug!(channel_id = %channel_id, "QUIC EOF");
                            break;
                        }
                        Ok(n) => {
                            if let Err(e) = target_write.write_all(&buf[..n]).await {
                                debug!(channel_id = %channel_id, error = %e, "Target write error");
                                break;
                            }
                        }
                        Err(e) => {
                            debug!(channel_id = %channel_id, error = %e, "QUIC recv error");
                            break;
                        }
                    }
                }
                let _ = target_write.shutdown().await;
            })
        };

        // Wait for shutdown or either direction to complete
        tokio::select! {
            _ = shutdown_rx.recv() => {
                debug!(channel_id = %channel_id, "Forward relay shutdown signal");
                // Finish the QUIC stream to signal EOF
                let _ = quic_sender_for_finish.finish().await;
            }
            _ = target_to_quic => {
                debug!(channel_id = %channel_id, "Target->QUIC complete");
            }
            _ = quic_to_target => {
                debug!(channel_id = %channel_id, "QUIC->Target complete");
            }
        }

        debug!(channel_id = %channel_id, "Forward relay ended");
    }

    /// Get the channel ID.
    pub fn channel_id(&self) -> ChannelId {
        self.inner.channel_id
    }

    /// Get the forward type.
    pub fn forward_type(&self) -> &ForwardType {
        &self.inner.forward_type
    }

    /// Handle an incoming stream for this channel.
    ///
    /// For client-initiated channels (DirectTcpIp, DynamicForward), this is
    /// where we receive the client's QUIC data stream.
    pub async fn handle_incoming_stream(&self, stream: QuicStream) -> Result<()> {
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(Error::ConnectionClosed);
        }

        // Send the stream to the waiting relay task
        if let Some(tx) = self.inner.stream_tx.lock().await.take() {
            if tx.send(stream).is_err() {
                warn!(channel_id = %self.inner.channel_id, "Failed to send stream to relay");
            } else {
                debug!(channel_id = %self.inner.channel_id, "Delivered client stream to relay");
            }
        } else {
            warn!(channel_id = %self.inner.channel_id, "No stream receiver available");
        }

        Ok(())
    }

    /// Close the channel.
    pub async fn close(&self) {
        if self.inner.closed.swap(true, Ordering::SeqCst) {
            return;
        }

        // Signal shutdown
        if let Some(tx) = self.inner.shutdown_tx.lock().await.take() {
            let _ = tx.send(()).await;
        }

        // Cancel relay task
        if let Some(task) = self.inner.relay_task.lock().await.take() {
            task.abort();
        }

        info!(channel_id = %self.inner.channel_id, "Forward channel closed");
    }

    /// Check if the channel is closed.
    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forward_channel_structure() {
        // Just verify the struct compiles
        fn _assert_clone<T: Clone>() {}
        _assert_clone::<ForwardChannel>();
    }

    #[test]
    fn test_forward_type_variants() {
        let _direct = ForwardType::Direct {
            target_host: "localhost".to_string(),
            target_port: 80,
        };
        let _forwarded = ForwardType::Forwarded {
            bound_host: "0.0.0.0".to_string(),
            bound_port: 8080,
        };
        let _dynamic = ForwardType::Dynamic {
            target_host: "example.com".to_string(),
            target_port: 443,
        };
    }
}
