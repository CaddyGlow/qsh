//! Port forward channel implementation.
//!
//! Manages port forwarding (direct-tcpip, forwarded-tcpip, dynamic) within a channel.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use qsh_core::error::{Error, Result};
use qsh_core::protocol::{
    ChannelId, DirectTcpIpParams, DynamicForwardParams, ForwardedTcpIpParams,
};
use qsh_core::transport::{Connection, QuicConnection, QuicStream, StreamType};

/// Buffer size for forwarding.
const FORWARD_BUFFER_SIZE: usize = 32 * 1024;

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
    /// QUIC connection.
    quic: Arc<QuicConnection>,
    /// Forward type.
    forward_type: ForwardType,
    /// Target TCP connection (if connected).
    target_stream: Mutex<Option<TcpStream>>,
    /// QUIC bidirectional stream.
    quic_stream: Mutex<Option<QuicStream>>,
    /// Whether the channel is closed.
    closed: AtomicBool,
    /// Relay task handle.
    relay_task: Mutex<Option<JoinHandle<()>>>,
    /// Shutdown signal sender.
    shutdown_tx: Mutex<Option<mpsc::Sender<()>>>,
}

impl ForwardChannel {
    /// Create a new direct TCP/IP forward channel (-L).
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

        // Open QUIC bidirectional stream
        let quic_stream = quic
            .as_ref()
            .open_stream(StreamType::ChannelBidi(channel_id))
            .await
            .map_err(|e| Error::Transport {
                message: format!("failed to open forward stream: {}", e),
            })?;

        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        let inner = Arc::new(ForwardChannelInner {
            channel_id,
            quic,
            forward_type: ForwardType::Direct {
                target_host: params.target_host,
                target_port: params.target_port,
            },
            target_stream: Mutex::new(Some(target_stream)),
            quic_stream: Mutex::new(Some(quic_stream)),
            closed: AtomicBool::new(false),
            relay_task: Mutex::new(None),
            shutdown_tx: Mutex::new(Some(shutdown_tx)),
        });

        // Start relay
        let channel = Self { inner };
        channel.start_relay(shutdown_rx).await;

        Ok(channel)
    }

    /// Create a new forwarded TCP/IP channel (-R).
    ///
    /// This is called by the server when a connection arrives on a remote forward listener.
    pub async fn new_forwarded(
        channel_id: ChannelId,
        params: ForwardedTcpIpParams,
        quic: Arc<QuicConnection>,
    ) -> Result<Self> {
        debug!(
            channel_id = %channel_id,
            bound = %format!("{}:{}", params.bound_host, params.bound_port),
            originator = %format!("{}:{}", params.originator_host, params.originator_port),
            "Creating forwarded-tcpip channel"
        );

        // For forwarded channels, the target connection is established by the client
        // We just set up the QUIC stream

        let quic_stream = quic
            .as_ref()
            .open_stream(StreamType::ChannelBidi(channel_id))
            .await
            .map_err(|e| Error::Transport {
                message: format!("failed to open forward stream: {}", e),
            })?;

        let (shutdown_tx, _shutdown_rx) = mpsc::channel(1);

        let inner = Arc::new(ForwardChannelInner {
            channel_id,
            quic,
            forward_type: ForwardType::Forwarded {
                bound_host: params.bound_host,
                bound_port: params.bound_port,
            },
            target_stream: Mutex::new(None),
            quic_stream: Mutex::new(Some(quic_stream)),
            closed: AtomicBool::new(false),
            relay_task: Mutex::new(None),
            shutdown_tx: Mutex::new(Some(shutdown_tx)),
        });

        Ok(Self { inner })
    }

    /// Create a new dynamic SOCKS5 forward channel (-D).
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

        let quic_stream = quic
            .as_ref()
            .open_stream(StreamType::ChannelBidi(channel_id))
            .await
            .map_err(|e| Error::Transport {
                message: format!("failed to open forward stream: {}", e),
            })?;

        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        let inner = Arc::new(ForwardChannelInner {
            channel_id,
            quic,
            forward_type: ForwardType::Dynamic {
                target_host: params.target_host,
                target_port: params.target_port,
            },
            target_stream: Mutex::new(Some(target_stream)),
            quic_stream: Mutex::new(Some(quic_stream)),
            closed: AtomicBool::new(false),
            relay_task: Mutex::new(None),
            shutdown_tx: Mutex::new(Some(shutdown_tx)),
        });

        let channel = Self { inner };
        channel.start_relay(shutdown_rx).await;

        Ok(channel)
    }

    /// Start the bidirectional relay.
    async fn start_relay(&self, mut shutdown_rx: mpsc::Receiver<()>) {
        let inner = Arc::clone(&self.inner);

        let task = tokio::spawn(async move {
            let channel_id = inner.channel_id;

            // Take ownership of the streams
            let target_stream = inner.target_stream.lock().await.take();
            let quic_stream = inner.quic_stream.lock().await.take();

            let (target_stream, quic_stream) = match (target_stream, quic_stream) {
                (Some(t), Some(q)) => (t, q),
                _ => {
                    warn!(channel_id = %channel_id, "Missing stream for relay");
                    return;
                }
            };

            let (mut target_read, mut target_write) = target_stream.into_split();
            let (quic_send, quic_recv) = (quic_stream, None::<QuicStream>);
            let quic_send = Arc::new(Mutex::new(quic_send));

            // Channel for sending data to QUIC
            let (to_quic_tx, mut to_quic_rx) = mpsc::channel::<Vec<u8>>(32);

            // Task: target -> QUIC
            let to_quic_tx_clone = to_quic_tx.clone();
            let target_to_quic = tokio::spawn(async move {
                let mut buf = vec![0u8; FORWARD_BUFFER_SIZE];
                loop {
                    match target_read.read(&mut buf).await {
                        Ok(0) => {
                            debug!(channel_id = %channel_id, "Target EOF");
                            break;
                        }
                        Ok(n) => {
                            if to_quic_tx_clone.send(buf[..n].to_vec()).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            debug!(channel_id = %channel_id, error = %e, "Target read error");
                            break;
                        }
                    }
                }
            });

            // Task: QUIC send loop
            let quic_send_clone = Arc::clone(&quic_send);
            let quic_send_task = tokio::spawn(async move {
                while let Some(data) = to_quic_rx.recv().await {
                    let mut stream = quic_send_clone.lock().await;
                    // Send raw bytes (forwards use raw data, not wrapped messages)
                    // For channel-based forwards, we use the bidirectional stream directly
                    if let Err(e) = stream.send_raw(&data).await {
                        debug!("QUIC send error: {}", e);
                        break;
                    }
                }
            });

            // Task: QUIC -> target (would need recv_raw on the stream)
            // For now, this is simplified - full implementation would handle both directions

            // Wait for shutdown or completion
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    debug!(channel_id = %channel_id, "Forward relay shutdown");
                }
                _ = target_to_quic => {
                    debug!(channel_id = %channel_id, "Target->QUIC complete");
                }
            }

            // Clean up
            quic_send_task.abort();
            let _ = target_write.shutdown().await;

            // Put streams back (in case they need cleanup)
            drop(quic_recv);

            debug!(channel_id = %channel_id, "Forward relay ended");
        });

        *self.inner.relay_task.lock().await = Some(task);
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
    pub async fn handle_incoming_stream(&self, stream: QuicStream) -> Result<()> {
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(Error::ConnectionClosed);
        }

        // Store the stream (for forwarded-tcpip channels where client sends data)
        *self.inner.quic_stream.lock().await = Some(stream);

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

        // Close streams
        if let Some(mut stream) = self.inner.quic_stream.lock().await.take() {
            stream.close();
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
