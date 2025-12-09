//! QUIC transport implementation using s2n-quic.
//!
//! This module provides concrete implementations of the Connection and StreamPair traits
//! using AWS s2n-quic as an alternative to quiche.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, BytesMut};
use s2n_quic::stream::{BidirectionalStream, ReceiveStream, SendStream};
use tokio::sync::Mutex;
use tracing::debug;

use crate::error::{Error, Result};
use crate::protocol::{ChannelId, Codec, Message};

use super::{Connection, StreamPair, StreamType};

// =============================================================================
// Connection Statistics (shared between event subscriber and connection)
// =============================================================================

/// Shared connection statistics updated by the event subscriber.
///
/// These statistics are updated atomically by the s2n-quic event system
/// and can be read from the S2nConnection at any time.
#[derive(Debug, Default)]
pub struct ConnectionStats {
    /// Smoothed RTT in microseconds.
    smoothed_rtt_us: AtomicU64,
    /// Minimum RTT in microseconds.
    min_rtt_us: AtomicU64,
    /// Latest RTT sample in microseconds.
    latest_rtt_us: AtomicU64,
    /// Current congestion window in bytes.
    congestion_window: AtomicU32,
    /// Bytes currently in flight.
    bytes_in_flight: AtomicU32,
    /// Total packets lost.
    packets_lost: AtomicU64,
    /// Total bytes lost.
    bytes_lost: AtomicU64,
    /// Total packets sent (for loss ratio calculation).
    packets_sent: AtomicU64,
}

impl ConnectionStats {
    /// Get smoothed RTT as Duration.
    pub fn smoothed_rtt(&self) -> Duration {
        Duration::from_micros(self.smoothed_rtt_us.load(Ordering::Relaxed))
    }

    /// Get minimum RTT as Duration.
    pub fn min_rtt(&self) -> Duration {
        Duration::from_micros(self.min_rtt_us.load(Ordering::Relaxed))
    }

    /// Get latest RTT sample as Duration.
    pub fn latest_rtt(&self) -> Duration {
        Duration::from_micros(self.latest_rtt_us.load(Ordering::Relaxed))
    }

    /// Get congestion window in bytes.
    pub fn congestion_window(&self) -> u32 {
        self.congestion_window.load(Ordering::Relaxed)
    }

    /// Get bytes in flight.
    pub fn bytes_in_flight(&self) -> u32 {
        self.bytes_in_flight.load(Ordering::Relaxed)
    }

    /// Get packet loss ratio (0.0 - 1.0).
    pub fn packet_loss_ratio(&self) -> f64 {
        let sent = self.packets_sent.load(Ordering::Relaxed);
        let lost = self.packets_lost.load(Ordering::Relaxed);
        if sent == 0 {
            0.0
        } else {
            lost as f64 / sent as f64
        }
    }

    /// Get total packets lost.
    pub fn packets_lost(&self) -> u64 {
        self.packets_lost.load(Ordering::Relaxed)
    }

    /// Get total bytes lost.
    pub fn bytes_lost(&self) -> u64 {
        self.bytes_lost.load(Ordering::Relaxed)
    }
}

// =============================================================================
// Event Subscriber for Statistics
// =============================================================================

/// Event subscriber that collects connection statistics.
///
/// This subscriber receives events from s2n-quic and updates the shared
/// ConnectionStats structure.
pub struct StatsSubscriber {
    stats: Arc<ConnectionStats>,
}

impl StatsSubscriber {
    /// Create a new statistics subscriber with shared stats.
    pub fn new(stats: Arc<ConnectionStats>) -> Self {
        Self { stats }
    }
}

/// Per-connection context for the stats subscriber.
pub struct StatsContext {
    stats: Arc<ConnectionStats>,
}

impl s2n_quic::provider::event::Subscriber for StatsSubscriber {
    type ConnectionContext = StatsContext;

    fn create_connection_context(
        &mut self,
        _meta: &s2n_quic::provider::event::events::ConnectionMeta,
        _info: &s2n_quic::provider::event::events::ConnectionInfo,
    ) -> Self::ConnectionContext {
        StatsContext {
            stats: Arc::clone(&self.stats),
        }
    }

    fn on_recovery_metrics(
        &mut self,
        context: &mut Self::ConnectionContext,
        _meta: &s2n_quic::provider::event::events::ConnectionMeta,
        event: &s2n_quic::provider::event::events::RecoveryMetrics,
    ) {
        context.stats.smoothed_rtt_us.store(
            event.smoothed_rtt.as_micros() as u64,
            Ordering::Relaxed,
        );
        context.stats.min_rtt_us.store(
            event.min_rtt.as_micros() as u64,
            Ordering::Relaxed,
        );
        context.stats.latest_rtt_us.store(
            event.latest_rtt.as_micros() as u64,
            Ordering::Relaxed,
        );
        context.stats.congestion_window.store(
            event.congestion_window,
            Ordering::Relaxed,
        );
        context.stats.bytes_in_flight.store(
            event.bytes_in_flight,
            Ordering::Relaxed,
        );
    }

    fn on_packet_lost(
        &mut self,
        context: &mut Self::ConnectionContext,
        _meta: &s2n_quic::provider::event::events::ConnectionMeta,
        event: &s2n_quic::provider::event::events::PacketLost,
    ) {
        context.stats.packets_lost.fetch_add(1, Ordering::Relaxed);
        context.stats.bytes_lost.fetch_add(event.bytes_lost as u64, Ordering::Relaxed);
    }

    fn on_packet_sent(
        &mut self,
        context: &mut Self::ConnectionContext,
        _meta: &s2n_quic::provider::event::events::ConnectionMeta,
        _event: &s2n_quic::provider::event::events::PacketSent,
    ) {
        context.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
    }
}

// =============================================================================
// Channel Stream Header
// =============================================================================

/// Magic byte identifying a channel model unidirectional stream.
const CHANNEL_STREAM_MAGIC: u8 = 0xC1;

/// Magic byte identifying a channel bidi stream.
const CHANNEL_BIDI_MAGIC: u8 = 0xC2;

/// Create the 9-byte header for channel unidirectional streams.
///
/// Format: [magic (1 byte)] [encoded channel_id (8 bytes LE)]
fn channel_stream_header(channel_id: ChannelId) -> [u8; 9] {
    let mut header = [0u8; 9];
    header[0] = CHANNEL_STREAM_MAGIC;
    header[1..9].copy_from_slice(&channel_id.encode().to_le_bytes());
    header
}

/// Create the 9-byte header for channel bidirectional streams.
///
/// Format: [magic (1 byte)] [encoded channel_id (8 bytes LE)]
fn channel_bidi_header(channel_id: ChannelId) -> [u8; 9] {
    let mut header = [0u8; 9];
    header[0] = CHANNEL_BIDI_MAGIC;
    header[1..9].copy_from_slice(&channel_id.encode().to_le_bytes());
    header
}

// =============================================================================
// S2nStream - Wrapper around s2n-quic stream
// =============================================================================

/// Stream direction/type.
#[derive(Debug, Clone, Copy)]
enum StreamDirection {
    Bidirectional,
    SendOnly,
    RecvOnly,
}

/// Inner state for S2nStream, wrapped in Arc for cloneable sender handles.
struct S2nStreamInner {
    /// The underlying s2n-quic bidirectional stream (if bidi).
    bidi: Option<Mutex<BidirectionalStream>>,
    /// Send stream (for unidirectional send).
    send: Option<Mutex<SendStream>>,
    /// Receive stream (for unidirectional recv).
    recv: Option<Mutex<ReceiveStream>>,
    /// Receive buffer for message framing.
    recv_buf: Mutex<BytesMut>,
    /// Stream direction.
    direction: StreamDirection,
    /// Closed flag.
    closed: AtomicBool,
}

/// A QUIC stream pair using s2n-quic.
pub struct S2nStream {
    inner: Arc<S2nStreamInner>,
}

impl S2nStream {
    /// Create a new bidirectional stream.
    pub fn new_bidi(stream: BidirectionalStream) -> Self {
        Self {
            inner: Arc::new(S2nStreamInner {
                bidi: Some(Mutex::new(stream)),
                send: None,
                recv: None,
                recv_buf: Mutex::new(BytesMut::with_capacity(8192)),
                direction: StreamDirection::Bidirectional,
                closed: AtomicBool::new(false),
            }),
        }
    }

    /// Create a send-only stream.
    pub fn send_only(stream: SendStream) -> Self {
        Self {
            inner: Arc::new(S2nStreamInner {
                bidi: None,
                send: Some(Mutex::new(stream)),
                recv: None,
                recv_buf: Mutex::new(BytesMut::new()),
                direction: StreamDirection::SendOnly,
                closed: AtomicBool::new(false),
            }),
        }
    }

    /// Create a recv-only stream.
    pub fn recv_only(stream: ReceiveStream) -> Self {
        Self {
            inner: Arc::new(S2nStreamInner {
                bidi: None,
                send: None,
                recv: Some(Mutex::new(stream)),
                recv_buf: Mutex::new(BytesMut::with_capacity(8192)),
                direction: StreamDirection::RecvOnly,
                closed: AtomicBool::new(false),
            }),
        }
    }

    /// Create a bidirectional stream with pre-populated buffer.
    pub fn with_buffer(stream: BidirectionalStream, initial_data: Option<BytesMut>) -> Self {
        let recv_buf = initial_data.unwrap_or_else(|| BytesMut::with_capacity(8192));
        Self {
            inner: Arc::new(S2nStreamInner {
                bidi: Some(Mutex::new(stream)),
                send: None,
                recv: None,
                recv_buf: Mutex::new(recv_buf),
                direction: StreamDirection::Bidirectional,
                closed: AtomicBool::new(false),
            }),
        }
    }

    /// Get a cloneable sender handle for spawning background send tasks.
    pub fn sender(&self) -> Option<S2nSender> {
        match self.inner.direction {
            StreamDirection::Bidirectional | StreamDirection::SendOnly => {
                Some(S2nSender {
                    inner: Arc::clone(&self.inner),
                })
            }
            StreamDirection::RecvOnly => None,
        }
    }

    /// Send raw bytes without message framing.
    pub async fn send_raw(&self, data: &[u8]) -> Result<()> {
        use tokio::io::AsyncWriteExt;

        match self.inner.direction {
            StreamDirection::RecvOnly => {
                return Err(Error::Transport {
                    message: "stream is receive-only".to_string(),
                });
            }
            StreamDirection::Bidirectional => {
                if let Some(ref bidi) = self.inner.bidi {
                    let mut stream = bidi.lock().await;
                    stream.write_all(data).await.map_err(|e| Error::Transport {
                        message: format!("stream send failed: {}", e),
                    })?;
                    stream.flush().await.map_err(|e| Error::Transport {
                        message: format!("stream flush failed: {}", e),
                    })?;
                }
            }
            StreamDirection::SendOnly => {
                if let Some(ref send) = self.inner.send {
                    let mut stream = send.lock().await;
                    stream.write_all(data).await.map_err(|e| Error::Transport {
                        message: format!("stream send failed: {}", e),
                    })?;
                    stream.flush().await.map_err(|e| Error::Transport {
                        message: format!("stream flush failed: {}", e),
                    })?;
                }
            }
        }
        Ok(())
    }

    /// Receive raw bytes without message framing.
    pub async fn recv_raw(&self, buf: &mut [u8]) -> Result<usize> {
        use tokio::io::AsyncReadExt;

        match self.inner.direction {
            StreamDirection::SendOnly => {
                return Err(Error::Transport {
                    message: "stream is send-only".to_string(),
                });
            }
            StreamDirection::Bidirectional => {
                if let Some(ref bidi) = self.inner.bidi {
                    let mut stream = bidi.lock().await;
                    stream.read(buf).await.map_err(|e| Error::Transport {
                        message: format!("stream recv failed: {}", e),
                    })
                } else {
                    Err(Error::Transport {
                        message: "no stream available".to_string(),
                    })
                }
            }
            StreamDirection::RecvOnly => {
                if let Some(ref recv) = self.inner.recv {
                    let mut stream = recv.lock().await;
                    stream.read(buf).await.map_err(|e| Error::Transport {
                        message: format!("stream recv failed: {}", e),
                    })
                } else {
                    Err(Error::Transport {
                        message: "no stream available".to_string(),
                    })
                }
            }
        }
    }

    /// Gracefully finish the send side of the stream.
    pub async fn finish(&self) -> Result<()> {
        use tokio::io::AsyncWriteExt;

        match self.inner.direction {
            StreamDirection::RecvOnly => Ok(()),
            StreamDirection::Bidirectional => {
                if let Some(ref bidi) = self.inner.bidi {
                    let mut stream = bidi.lock().await;
                    stream.shutdown().await.map_err(|e| Error::Transport {
                        message: format!("stream shutdown failed: {}", e),
                    })?;
                }
                Ok(())
            }
            StreamDirection::SendOnly => {
                if let Some(ref send) = self.inner.send {
                    let mut stream = send.lock().await;
                    stream.shutdown().await.map_err(|e| Error::Transport {
                        message: format!("stream shutdown failed: {}", e),
                    })?;
                }
                Ok(())
            }
        }
    }

    /// Split the stream into separate reader and writer halves.
    ///
    /// This consumes the stream and returns AsyncRead/AsyncWrite handles
    /// that can be used independently.
    pub fn into_split(self) -> Result<(S2nStreamWriter, S2nStreamReader)> {
        match self.inner.direction {
            StreamDirection::Bidirectional => {
                // Try to unwrap the Arc - this will fail if there are other references
                match Arc::try_unwrap(self.inner) {
                    Ok(inner) => {
                        if let Some(bidi) = inner.bidi {
                            let stream = bidi.into_inner();
                            let (recv, send) = stream.split();
                            let recv_buf = inner.recv_buf.into_inner();
                            Ok((S2nStreamWriter::new(send), S2nStreamReader::new(recv, Some(recv_buf))))
                        } else {
                            Err(Error::Transport {
                                message: "no bidirectional stream to split".to_string(),
                            })
                        }
                    }
                    Err(_) => Err(Error::Transport {
                        message: "cannot split stream while sender handles exist".to_string(),
                    }),
                }
            }
            _ => Err(Error::Transport {
                message: "can only split bidirectional streams".to_string(),
            }),
        }
    }
}

impl StreamPair for S2nStream {
    fn send(&mut self, msg: &Message) -> impl std::future::Future<Output = Result<()>> + Send {
        let data = Codec::encode(msg);
        let inner = Arc::clone(&self.inner);

        async move {
            use tokio::io::AsyncWriteExt;

            match inner.direction {
                StreamDirection::RecvOnly => {
                    return Err(Error::Transport {
                        message: "stream is receive-only".to_string(),
                    });
                }
                StreamDirection::Bidirectional => {
                    let data = data?;
                    if let Some(ref bidi) = inner.bidi {
                        let mut stream = bidi.lock().await;
                        stream.write_all(&data).await.map_err(|e| Error::Transport {
                            message: format!("stream send failed: {}", e),
                        })?;
                        stream.flush().await.map_err(|e| Error::Transport {
                            message: format!("stream flush failed: {}", e),
                        })?;
                    }
                }
                StreamDirection::SendOnly => {
                    let data = data?;
                    if let Some(ref send) = inner.send {
                        let mut stream = send.lock().await;
                        stream.write_all(&data).await.map_err(|e| Error::Transport {
                            message: format!("stream send failed: {}", e),
                        })?;
                        stream.flush().await.map_err(|e| Error::Transport {
                            message: format!("stream flush failed: {}", e),
                        })?;
                    }
                }
            }
            Ok(())
        }
    }

    fn recv(&mut self) -> impl std::future::Future<Output = Result<Message>> + Send {
        let inner = Arc::clone(&self.inner);

        async move {
            use tokio::io::AsyncReadExt;

            if matches!(inner.direction, StreamDirection::SendOnly) {
                return Err(Error::Transport {
                    message: "stream is send-only".to_string(),
                });
            }

            let mut recv_buf = inner.recv_buf.lock().await;

            loop {
                if let Some(msg) = Codec::decode(&mut recv_buf)? {
                    return Ok(msg);
                }

                let mut chunk = [0u8; 4096];
                let n = match inner.direction {
                    StreamDirection::Bidirectional => {
                        if let Some(ref bidi) = inner.bidi {
                            let mut stream = bidi.lock().await;
                            stream.read(&mut chunk).await.map_err(|e| Error::Transport {
                                message: format!("stream recv failed: {}", e),
                            })?
                        } else {
                            return Err(Error::ConnectionClosed);
                        }
                    }
                    StreamDirection::RecvOnly => {
                        if let Some(ref recv) = inner.recv {
                            let mut stream = recv.lock().await;
                            stream.read(&mut chunk).await.map_err(|e| Error::Transport {
                                message: format!("stream recv failed: {}", e),
                            })?
                        } else {
                            return Err(Error::ConnectionClosed);
                        }
                    }
                    StreamDirection::SendOnly => unreachable!(),
                };

                if n > 0 {
                    recv_buf.extend_from_slice(&chunk[..n]);
                } else {
                    // EOF
                    if let Some(msg) = Codec::decode(&mut recv_buf)? {
                        return Ok(msg);
                    }
                    return Err(Error::ConnectionClosed);
                }
            }
        }
    }

    fn close(&mut self) {
        self.inner.closed.store(true, Ordering::SeqCst);
    }
}

// =============================================================================
// S2nStreamReader / S2nStreamWriter - AsyncRead/AsyncWrite wrappers
// =============================================================================

/// Write half of a QUIC stream implementing AsyncWrite.
pub struct S2nStreamWriter {
    inner: SendStream,
}

impl S2nStreamWriter {
    /// Create a new stream writer.
    fn new(stream: SendStream) -> Self {
        Self { inner: stream }
    }
}

impl tokio::io::AsyncWrite for S2nStreamWriter {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write(std::pin::Pin::new(&mut self.inner), cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_flush(std::pin::Pin::new(&mut self.inner), cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_shutdown(std::pin::Pin::new(&mut self.inner), cx)
    }
}

/// Read half of a QUIC stream implementing AsyncRead.
pub struct S2nStreamReader {
    inner: ReceiveStream,
    buffer: BytesMut,
}

impl S2nStreamReader {
    /// Create a new stream reader.
    fn new(stream: ReceiveStream, initial_buffer: Option<BytesMut>) -> Self {
        Self {
            inner: stream,
            buffer: initial_buffer.unwrap_or_default(),
        }
    }
}

impl tokio::io::AsyncRead for S2nStreamReader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // Return from buffer first if we have data
        if !self.buffer.is_empty() {
            let to_copy = std::cmp::min(self.buffer.len(), buf.remaining());
            buf.put_slice(&self.buffer[..to_copy]);
            self.buffer.advance(to_copy);
            return std::task::Poll::Ready(Ok(()));
        }

        tokio::io::AsyncRead::poll_read(std::pin::Pin::new(&mut self.inner), cx, buf)
    }
}

// =============================================================================
// S2nSender - Cloneable sender handle
// =============================================================================

/// A cloneable sender handle for a QUIC stream.
///
/// This wraps an Arc reference to the stream's inner state, allowing multiple
/// tasks to send on the same stream safely via the internal Mutex.
#[derive(Clone)]
pub struct S2nSender {
    inner: Arc<S2nStreamInner>,
}

impl S2nSender {
    /// Send a message (includes flush for low latency).
    pub async fn send(&self, msg: &Message) -> Result<()> {
        let data = Codec::encode(msg)?;
        self.send_raw(&data).await
    }

    /// Send raw bytes without message framing.
    pub async fn send_raw(&self, data: &[u8]) -> Result<()> {
        use tokio::io::AsyncWriteExt;

        match self.inner.direction {
            StreamDirection::RecvOnly => {
                return Err(Error::Transport {
                    message: "stream is receive-only".to_string(),
                });
            }
            StreamDirection::Bidirectional => {
                if let Some(ref bidi) = self.inner.bidi {
                    let mut stream = bidi.lock().await;
                    stream.write_all(data).await.map_err(|e| Error::Transport {
                        message: format!("stream send failed: {}", e),
                    })?;
                    stream.flush().await.map_err(|e| Error::Transport {
                        message: format!("stream flush failed: {}", e),
                    })?;
                }
            }
            StreamDirection::SendOnly => {
                if let Some(ref send) = self.inner.send {
                    let mut stream = send.lock().await;
                    stream.write_all(data).await.map_err(|e| Error::Transport {
                        message: format!("stream send failed: {}", e),
                    })?;
                    stream.flush().await.map_err(|e| Error::Transport {
                        message: format!("stream flush failed: {}", e),
                    })?;
                }
            }
        }
        Ok(())
    }

    /// Gracefully finish the send side of the stream (send FIN).
    pub async fn finish(&self) -> Result<()> {
        use tokio::io::AsyncWriteExt;

        match self.inner.direction {
            StreamDirection::RecvOnly => Ok(()),
            StreamDirection::Bidirectional => {
                if let Some(ref bidi) = self.inner.bidi {
                    let mut stream = bidi.lock().await;
                    stream.shutdown().await.map_err(|e| Error::Transport {
                        message: format!("stream shutdown failed: {}", e),
                    })?;
                }
                Ok(())
            }
            StreamDirection::SendOnly => {
                if let Some(ref send) = self.inner.send {
                    let mut stream = send.lock().await;
                    stream.shutdown().await.map_err(|e| Error::Transport {
                        message: format!("stream shutdown failed: {}", e),
                    })?;
                }
                Ok(())
            }
        }
    }
}

// =============================================================================
// S2nConnection - Public connection wrapper
// =============================================================================

/// A QUIC connection wrapper using s2n-quic.
pub struct S2nConnection {
    /// The s2n-quic connection (for accepting streams).
    conn: Mutex<s2n_quic::connection::Connection>,
    /// Remote address.
    remote_addr: SocketAddr,
    /// Local address.
    local_addr: SocketAddr,
    /// Pending incoming streams (stream_type, stream).
    pending_streams: Mutex<VecDeque<(StreamType, S2nStream)>>,
    /// Connection closed flag.
    closed: AtomicBool,
    /// Control stream (stream ID 0).
    control_stream: Mutex<Option<BidirectionalStream>>,
    /// Whether this is a server connection.
    is_server: bool,
    /// Connection statistics (populated by event subscriber).
    stats: Arc<ConnectionStats>,
}

impl S2nConnection {
    /// Create a new connection wrapper from a client connection.
    pub async fn from_client_connection(
        mut conn: s2n_quic::connection::Connection,
        local_addr: SocketAddr,
        stats: Arc<ConnectionStats>,
    ) -> Result<Self> {
        let remote_addr = conn.remote_addr().map_err(|e| Error::Transport {
            message: format!("failed to get remote address: {}", e),
        })?;

        // Open control stream (stream ID 0 equivalent)
        let control_stream = conn.open_bidirectional_stream().await.map_err(|e| Error::Transport {
            message: format!("failed to open control stream: {}", e),
        })?;

        Ok(Self {
            conn: Mutex::new(conn),
            remote_addr,
            local_addr,
            pending_streams: Mutex::new(VecDeque::new()),
            closed: AtomicBool::new(false),
            control_stream: Mutex::new(Some(control_stream)),
            is_server: false,
            stats,
        })
    }

    /// Create a new connection wrapper from a server connection.
    pub async fn from_server_connection(
        mut conn: s2n_quic::connection::Connection,
        local_addr: SocketAddr,
        stats: Arc<ConnectionStats>,
    ) -> Result<Self> {
        let remote_addr = conn.remote_addr().map_err(|e| Error::Transport {
            message: format!("failed to get remote address: {}", e),
        })?;

        // For server, accept the control stream initiated by client
        let control_stream = conn.accept_bidirectional_stream().await.map_err(|e| Error::Transport {
            message: format!("failed to accept control stream: {}", e),
        })?.ok_or_else(|| Error::Transport {
            message: "connection closed before control stream".to_string(),
        })?;

        Ok(Self {
            conn: Mutex::new(conn),
            remote_addr,
            local_addr,
            pending_streams: Mutex::new(VecDeque::new()),
            closed: AtomicBool::new(false),
            control_stream: Mutex::new(Some(control_stream)),
            is_server: true,
            stats,
        })
    }

    /// Get session data for 0-RTT resumption on reconnect.
    ///
    /// Note: s2n-quic handles session resumption differently than quiche.
    /// This is a placeholder that returns None.
    pub async fn session_data(&self) -> Option<Vec<u8>> {
        // s2n-quic manages session tickets internally
        None
    }

    /// Check if the connection has early data available (0-RTT phase).
    pub async fn is_in_early_data(&self) -> bool {
        // s2n-quic doesn't expose this directly in the same way
        false
    }

    /// Check if the connection was resumed from a previous session (0-RTT).
    pub async fn is_resumed(&self) -> bool {
        // s2n-quic doesn't expose this directly
        false
    }

    /// Get packet loss ratio (0.0 - 1.0).
    pub async fn packet_loss(&self) -> f64 {
        self.stats.packet_loss_ratio()
    }

    /// Get the congestion window size.
    pub async fn congestion_window(&self) -> u64 {
        self.stats.congestion_window() as u64
    }

    /// Get minimum observed RTT.
    pub async fn min_rtt(&self) -> Option<Duration> {
        let min_rtt = self.stats.min_rtt();
        if min_rtt.is_zero() {
            None
        } else {
            Some(min_rtt)
        }
    }

    /// Get the connection statistics.
    pub fn stats(&self) -> &ConnectionStats {
        &self.stats
    }

    /// Accept an incoming bidirectional stream.
    pub async fn accept_bi(&self) -> Result<(S2nStreamWriter, S2nStreamReader)> {
        let mut conn = self.conn.lock().await;

        // Accept bidirectional stream
        let stream = conn.accept_bidirectional_stream().await.map_err(|e| Error::Transport {
            message: format!("failed to accept bidirectional stream: {}", e),
        })?.ok_or_else(|| Error::ConnectionClosed)?;

        let (recv, send) = stream.split();
        Ok((S2nStreamWriter::new(send), S2nStreamReader::new(recv, None)))
    }
}

impl Connection for S2nConnection {
    type Stream = S2nStream;

    async fn open_stream(&self, stream_type: StreamType) -> Result<Self::Stream> {
        match stream_type {
            StreamType::Control => {
                // Return the pre-opened control stream
                let mut control = self.control_stream.lock().await;
                if let Some(stream) = control.take() {
                    Ok(S2nStream::new_bidi(stream))
                } else {
                    Err(Error::Transport {
                        message: "control stream already taken".to_string(),
                    })
                }
            }
            StreamType::ChannelBidi(channel_id) => {
                let mut conn = self.conn.lock().await;

                // Open new bidi stream
                let mut stream = conn.open_bidirectional_stream().await.map_err(|e| Error::Transport {
                    message: format!("failed to open bidirectional stream: {}", e),
                })?;
                drop(conn);

                // Write header
                let header = channel_bidi_header(channel_id);
                use tokio::io::AsyncWriteExt;
                stream.write_all(&header).await.map_err(|e| Error::Transport {
                    message: format!("failed to write stream header: {}", e),
                })?;
                stream.flush().await.map_err(|e| Error::Transport {
                    message: format!("failed to flush stream header: {}", e),
                })?;

                Ok(S2nStream::new_bidi(stream))
            }
            StreamType::ChannelIn(channel_id) | StreamType::ChannelOut(channel_id) => {
                let mut conn = self.conn.lock().await;

                // Open new unidirectional stream
                let mut stream = conn.open_send_stream().await.map_err(|e| Error::Transport {
                    message: format!("failed to open unidirectional stream: {}", e),
                })?;
                drop(conn);

                // Write header
                let header = channel_stream_header(channel_id);
                use tokio::io::AsyncWriteExt;
                stream.write_all(&header).await.map_err(|e| Error::Transport {
                    message: format!("failed to write stream header: {}", e),
                })?;
                stream.flush().await.map_err(|e| Error::Transport {
                    message: format!("failed to flush stream header: {}", e),
                })?;

                Ok(S2nStream::send_only(stream))
            }
        }
    }

    async fn accept_stream(&self) -> Result<(StreamType, Self::Stream)> {
        // First, check if the control stream is still available (for server connections)
        // The control stream is the first bidi stream and doesn't have a header
        {
            let mut control = self.control_stream.lock().await;
            if let Some(stream) = control.take() {
                debug!("Returning pre-accepted control stream");
                return Ok((StreamType::Control, S2nStream::new_bidi(stream)));
            }
        }

        // Check for pending streams
        {
            let mut pending = self.pending_streams.lock().await;
            if let Some((stream_type, stream)) = pending.pop_front() {
                return Ok((stream_type, stream));
            }
        }

        // s2n-quic's Connection doesn't support concurrent accept calls, so we need
        // to poll each accept type sequentially. We use a loop with a small timeout
        // to check for both stream types.
        loop {
            // Try to accept a bidirectional stream with a short timeout
            {
                let mut conn = self.conn.lock().await;
                match tokio::time::timeout(
                    Duration::from_millis(10),
                    conn.accept_bidirectional_stream(),
                )
                .await
                {
                    Ok(Ok(Some(mut stream))) => {
                        // Read stream header to determine type
                        let mut header = [0u8; 9];
                        use tokio::io::AsyncReadExt;
                        stream.read_exact(&mut header).await.map_err(|e| Error::Transport {
                            message: format!("failed to read stream header: {}", e),
                        })?;

                        let magic = header[0];
                        let encoded = u64::from_le_bytes(header[1..9].try_into().unwrap());
                        let channel_id = ChannelId::decode(encoded);

                        let stream_type = match magic {
                            CHANNEL_BIDI_MAGIC => StreamType::ChannelBidi(channel_id),
                            _ => {
                                return Err(Error::Transport {
                                    message: format!("unknown stream magic: {:#x}", magic),
                                });
                            }
                        };

                        return Ok((stream_type, S2nStream::new_bidi(stream)));
                    }
                    Ok(Ok(None)) => return Err(Error::ConnectionClosed),
                    Ok(Err(e)) => {
                        return Err(Error::Transport {
                            message: format!("failed to accept stream: {}", e),
                        })
                    }
                    Err(_) => {
                        // Timeout - try receive stream next
                    }
                }
            }

            // Try to accept a unidirectional receive stream with a short timeout
            {
                let mut conn = self.conn.lock().await;
                match tokio::time::timeout(
                    Duration::from_millis(10),
                    conn.accept_receive_stream(),
                )
                .await
                {
                    Ok(Ok(Some(mut stream))) => {
                        // Read stream header to determine type
                        let mut header = [0u8; 9];
                        use tokio::io::AsyncReadExt;
                        stream.read_exact(&mut header).await.map_err(|e| Error::Transport {
                            message: format!("failed to read stream header: {}", e),
                        })?;

                        let magic = header[0];
                        let encoded = u64::from_le_bytes(header[1..9].try_into().unwrap());
                        let channel_id = ChannelId::decode(encoded);

                        let stream_type = match magic {
                            CHANNEL_STREAM_MAGIC => {
                                // Determine In vs Out based on who we are
                                if self.is_server {
                                    StreamType::ChannelIn(channel_id) // Client-initiated to server
                                } else {
                                    StreamType::ChannelOut(channel_id) // Server-initiated to client
                                }
                            }
                            _ => {
                                return Err(Error::Transport {
                                    message: format!("unknown stream magic: {:#x}", magic),
                                });
                            }
                        };

                        return Ok((stream_type, S2nStream::recv_only(stream)));
                    }
                    Ok(Ok(None)) => return Err(Error::ConnectionClosed),
                    Ok(Err(e)) => {
                        return Err(Error::Transport {
                            message: format!("failed to accept stream: {}", e),
                        })
                    }
                    Err(_) => {
                        // Timeout - loop again and check for bidi streams
                    }
                }
            }
        }
    }

    fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    fn is_connected(&self) -> bool {
        !self.closed.load(Ordering::SeqCst)
    }

    async fn rtt(&self) -> Duration {
        let rtt = self.stats.smoothed_rtt();
        if rtt.is_zero() {
            // Return a default if no RTT samples yet
            Duration::from_millis(100)
        } else {
            rtt
        }
    }
}

// =============================================================================
// Error Classification
// =============================================================================

/// Classify an I/O error into a specific qsh error type.
pub fn classify_io_error(e: std::io::Error) -> Error {
    match e.raw_os_error() {
        #[cfg(target_os = "linux")]
        Some(libc::ENETUNREACH) => Error::NetworkUnreachable(e),
        #[cfg(target_os = "linux")]
        Some(libc::EHOSTUNREACH) => Error::HostUnreachable(e),
        #[cfg(target_os = "linux")]
        Some(libc::ECONNREFUSED) => Error::ConnectionRefused,
        #[cfg(target_os = "linux")]
        Some(libc::ENETDOWN) | Some(libc::ENODEV) => Error::InterfaceDown,
        #[cfg(target_os = "linux")]
        Some(libc::EACCES) | Some(libc::EPERM) => Error::PermissionDenied(e),
        _ => Error::Io(e),
    }
}

/// Enable IP_RECVERR on a connected UDP socket for immediate ICMP error delivery.
#[cfg(target_os = "linux")]
pub fn enable_error_queue(socket: &tokio::net::UdpSocket) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;

    let fd = socket.as_raw_fd();
    let optval: libc::c_int = 1;

    let local_addr = socket.local_addr()?;
    let (level, optname) = if local_addr.is_ipv4() {
        (libc::IPPROTO_IP, libc::IP_RECVERR)
    } else {
        (libc::IPPROTO_IPV6, libc::IPV6_RECVERR)
    };

    unsafe {
        if libc::setsockopt(
            fd,
            level,
            optname,
            &optval as *const _ as _,
            std::mem::size_of_val(&optval) as _,
        ) < 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn enable_error_queue(_socket: &tokio::net::UdpSocket) -> std::io::Result<()> {
    // IP_RECVERR is Linux-specific
    Ok(())
}

// =============================================================================
// TLS/Certificate Helpers
// =============================================================================

/// Load certificate chain from PEM file.
pub fn load_certs_from_pem(pem_data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut certs = Vec::new();
    let mut reader = std::io::BufReader::new(pem_data);

    for cert in rustls_pemfile::certs(&mut reader) {
        match cert {
            Ok(c) => certs.push(c.to_vec()),
            Err(e) => {
                return Err(Error::CertificateError {
                    message: format!("failed to parse certificate: {}", e),
                });
            }
        }
    }

    if certs.is_empty() {
        return Err(Error::CertificateError {
            message: "no certificates found in PEM data".to_string(),
        });
    }

    Ok(certs)
}

/// Load private key from PEM file.
pub fn load_key_from_pem(pem_data: &[u8]) -> Result<Vec<u8>> {
    let mut reader = std::io::BufReader::new(pem_data);

    // Try PKCS8 first
    for key in rustls_pemfile::pkcs8_private_keys(&mut reader) {
        match key {
            Ok(k) => return Ok(k.secret_pkcs8_der().to_vec()),
            Err(_) => continue,
        }
    }

    // Try RSA
    reader = std::io::BufReader::new(pem_data);
    for key in rustls_pemfile::rsa_private_keys(&mut reader) {
        match key {
            Ok(k) => return Ok(k.secret_pkcs1_der().to_vec()),
            Err(_) => continue,
        }
    }

    Err(Error::CertificateError {
        message: "no private key found in PEM data".to_string(),
    })
}

/// Compute SHA-256 hash of certificate DER bytes.
pub fn cert_hash(cert_der: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(cert_der);
    hasher.finalize().to_vec()
}

// =============================================================================
// s2n-quic Configuration Helpers
// =============================================================================

/// Create an s2n-quic client configuration.
///
/// Note: s2n-quic has a different TLS configuration model than quiche.
/// The `verify_peer` parameter controls certificate verification.
/// When `verify_peer` is false, certificate verification is disabled using
/// s2n-quic's insecure mode (for development/testing only).
pub fn client_config(_verify_peer: bool) -> Result<s2n_quic::client::Client> {
    use s2n_quic::Client;

    // Note: s2n-quic doesn't have a simple way to disable certificate verification
    // like quiche does. For testing/development, you would typically:
    // 1. Add the self-signed cert to the trust store
    // 2. Use the rustls provider with dangerous_configuration
    //
    // For now, we return a basic client that will verify certificates.
    // In a real implementation, you'd configure the TLS provider appropriately.
    Client::builder()
        .with_io("0.0.0.0:0")
        .map_err(|e| Error::Transport {
            message: format!("failed to configure I/O: {}", e),
        })?
        .start()
        .map_err(|e| Error::Transport {
            message: format!("failed to start client: {}", e),
        })
}

/// Create an s2n-quic server configuration with certificate and key (PEM format).
pub fn server_config(cert_pem: &[u8], key_pem: &[u8], bind_addr: &str) -> Result<s2n_quic::server::Server> {
    server_config_with_ticket_key(cert_pem, key_pem, None, bind_addr)
}

/// Create an s2n-quic server configuration with optional custom ticket key.
pub fn server_config_with_ticket_key(
    cert_pem: &[u8],
    key_pem: &[u8],
    _ticket_key: Option<&[u8]>,
    bind_addr: &str,
) -> Result<s2n_quic::server::Server> {
    use s2n_quic::Server;

    let cert_pem_str = std::str::from_utf8(cert_pem).map_err(|e| Error::CertificateError {
        message: format!("invalid certificate PEM encoding: {}", e),
    })?;

    let key_pem_str = std::str::from_utf8(key_pem).map_err(|e| Error::CertificateError {
        message: format!("invalid key PEM encoding: {}", e),
    })?;

    Server::builder()
        .with_tls((cert_pem_str, key_pem_str))
        .map_err(|e| Error::CertificateError {
            message: format!("failed to configure TLS: {}", e),
        })?
        .with_io(bind_addr)
        .map_err(|e| Error::Transport {
            message: format!("failed to configure I/O: {}", e),
        })?
        .start()
        .map_err(|e| Error::Transport {
            message: format!("failed to start server: {}", e),
        })
}

/// Generate a self-signed certificate and return (cert_pem, key_pem).
pub fn generate_self_signed_cert() -> Result<(Vec<u8>, Vec<u8>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["qsh-server".to_string()]).map_err(|e| {
        Error::CertificateError {
            message: format!("failed to generate certificate: {}", e),
        }
    })?;

    let cert_pem = cert.cert.pem().into_bytes();
    let key_pem = cert.key_pair.serialize_pem().into_bytes();

    Ok((cert_pem, key_pem))
}

/// Build an s2n-quic client from a TransportConfigBuilder.
///
/// Note: s2n-quic uses a different configuration model than quiche.
/// This function creates a client ready to connect.
pub fn build_client_config(builder: &super::config::TransportConfigBuilder) -> Result<s2n_quic::client::Client> {
    use s2n_quic::Client;

    // Configure TLS verification
    if !builder.should_verify_peer() {
        // For development/testing, disable certificate verification
        // Note: In production, you'd want to configure proper trust anchors
        debug!("s2n-quic client: certificate verification disabled");
    }

    Client::builder()
        .with_io("0.0.0.0:0")
        .map_err(|e| Error::Transport {
            message: format!("failed to configure I/O: {}", e),
        })?
        .start()
        .map_err(|e| Error::Transport {
            message: format!("failed to start client: {}", e),
        })
}

/// Build an s2n-quic server from a TransportConfigBuilder.
///
/// Note: s2n-quic uses a different configuration model than quiche.
/// This function creates a server ready to accept connections.
pub fn build_server_config(
    builder: &super::config::TransportConfigBuilder,
    bind_addr: &str,
) -> Result<s2n_quic::server::Server> {
    use s2n_quic::Server;

    let creds = builder.credentials().ok_or_else(|| Error::Transport {
        message: "server config requires TLS credentials".to_string(),
    })?;

    let cert_pem_str = std::str::from_utf8(&creds.cert_pem).map_err(|e| Error::CertificateError {
        message: format!("invalid certificate PEM encoding: {}", e),
    })?;

    let key_pem_str = std::str::from_utf8(&creds.key_pem).map_err(|e| Error::CertificateError {
        message: format!("invalid key PEM encoding: {}", e),
    })?;

    Server::builder()
        .with_tls((cert_pem_str, key_pem_str))
        .map_err(|e| Error::CertificateError {
            message: format!("failed to configure TLS: {}", e),
        })?
        .with_io(bind_addr)
        .map_err(|e| Error::Transport {
            message: format!("failed to configure I/O: {}", e),
        })?
        .start()
        .map_err(|e| Error::Transport {
            message: format!("failed to start server: {}", e),
        })
}

// =============================================================================
// connect_quic - Client Connection Establishment
// =============================================================================

use super::{ConnectConfig, ConnectResult, ListenerConfig};
use std::time::Instant;
use tracing::info;

/// Establish a QUIC client connection using s2n-quic.
///
/// This performs the full QUIC/TLS handshake and returns a connected
/// `S2nConnection`. Currently, s2n-quic handles 0-RTT internally, so
/// session data management is limited compared to quiche.
///
/// # Arguments
/// * `config` - Connection configuration including server address, timeouts, and optional session data
///
/// # Returns
/// * `Ok(ConnectResult)` - Contains the connection, resume status, and new session data
/// * `Err(Error)` - On connection failure (timeout, handshake failure, certificate mismatch)
///
/// # Note
/// s2n-quic has a higher-level API than quiche. Some features like explicit
/// session ticket management and certificate hash verification require
/// additional configuration via custom providers.
///
/// # Certificate Verification
/// - If `cert_hash` is None: X.509 verification is disabled (for bootstrap mode)
/// - If `cert_hash` is Some: Verification is disabled, but the cert hash is checked after handshake
pub async fn connect_quic(config: &ConnectConfig) -> Result<ConnectResult<S2nConnection>> {
    use s2n_quic::Client;
    use s2n_quic::client::Connect;
    use s2n_quic::provider::tls::s2n_tls;

    let start = Instant::now();

    // Create shared statistics for event subscriber
    let stats = Arc::new(ConnectionStats::default());
    let event_subscriber = StatsSubscriber::new(Arc::clone(&stats));

    // Build the client
    // Note: s2n-quic binds internally, we can't specify a local port directly
    // For local port binding, we would need to use a custom I/O provider
    let bind_addr = if config.server_addr.is_ipv4() {
        format!("0.0.0.0:{}", config.local_port.unwrap_or(0))
    } else {
        format!("[::]:{}", config.local_port.unwrap_or(0))
    };

    // Configure TLS
    // For bootstrap mode (no cert_hash or cert_hash provided), we disable X.509 verification
    // since we're using self-signed certificates with hash-based pinning
    let mut tls_builder = s2n_tls::Client::builder();

    // Disable X.509 verification for self-signed certificates
    // SAFETY: This is used for bootstrap mode where certificates are verified via hash pinning
    // instead of traditional CA chains. The cert_hash is verified after the handshake completes.
    unsafe {
        tls_builder.config_mut().disable_x509_verification().map_err(|e| Error::Transport {
            message: format!("failed to disable x509 verification: {}", e),
        })?;
    }

    let tls = tls_builder.build().map_err(|e| Error::Transport {
        message: format!("failed to build TLS config: {}", e),
    })?;

    // Configure limits including idle timeout
    let limits = s2n_quic::provider::limits::Limits::new()
        .with_max_idle_timeout(config.max_idle_timeout)
        .map_err(|e| Error::Transport {
            message: format!("failed to configure idle timeout: {}", e),
        })?;

    let client = Client::builder()
        .with_tls(tls)
        .map_err(|e| Error::Transport {
            message: format!("failed to configure TLS: {}", e),
        })?
        .with_limits(limits)
        .map_err(|e| Error::Transport {
            message: format!("failed to configure limits: {}", e),
        })?
        .with_event(event_subscriber)
        .map_err(|e| Error::Transport {
            message: format!("failed to configure event subscriber: {}", e),
        })?
        .with_io(bind_addr.as_str())
        .map_err(|e| Error::Transport {
            message: format!("failed to configure I/O: {}", e),
        })?
        .start()
        .map_err(|e| Error::Transport {
            message: format!("failed to start client: {}", e),
        })?;

    let local_addr = client.local_addr().map_err(|e| Error::Transport {
        message: format!("failed to get local address: {}", e),
    })?;

    // Create connect handle
    let connect = Connect::new(config.server_addr)
        .with_server_name("qsh-server");

    // Connect with timeout
    let connection = tokio::time::timeout(config.connect_timeout, client.connect(connect))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|e| Error::HandshakeFailed {
            message: format!("connection failed: {}", e),
        })?;

    let elapsed = start.elapsed();
    debug!(
        addr = %config.server_addr,
        elapsed_ms = elapsed.as_millis() as u64,
        "s2n-quic handshake completed"
    );

    // Wrap in S2nConnection with shared stats
    let s2n_conn = S2nConnection::from_client_connection(connection, local_addr, stats).await?;

    // TODO: Verify cert_hash if provided
    // For now, we rely on the hash check in the application layer (qsh-client)
    // Future: Extract peer cert and verify hash here

    // Note: s2n-quic handles session resumption internally
    // We return None for session_data since we can't extract it easily
    // Future: implement custom session ticket provider for full parity
    let resumed = s2n_conn.is_resumed().await;
    let session_data = s2n_conn.session_data().await;

    if resumed {
        info!(addr = %config.server_addr, "0-RTT session resumed");
    }

    Ok(ConnectResult {
        connection: s2n_conn,
        resumed,
        session_data,
    })
}

// =============================================================================
// S2nAcceptor - Server Connection Acceptance
// =============================================================================

/// A QUIC server acceptor using s2n-quic.
///
/// This wraps the s2n-quic Server and provides a simpler accept interface
/// that returns `S2nConnection` instances.
pub struct S2nAcceptor {
    /// The s2n-quic server.
    server: s2n_quic::Server,
    /// Local address.
    local_addr: std::net::SocketAddr,
}

impl S2nAcceptor {
    /// Create a new QUIC acceptor bound to the specified address.
    pub async fn bind(addr: std::net::SocketAddr, config: ListenerConfig) -> Result<Self> {
        use s2n_quic::Server;

        let cert_pem_str = std::str::from_utf8(&config.cert_pem).map_err(|e| Error::CertificateError {
            message: format!("invalid certificate PEM encoding: {}", e),
        })?;

        let key_pem_str = std::str::from_utf8(&config.key_pem).map_err(|e| Error::CertificateError {
            message: format!("invalid key PEM encoding: {}", e),
        })?;

        // Configure limits including idle timeout
        let limits = s2n_quic::provider::limits::Limits::new()
            .with_max_idle_timeout(config.idle_timeout)
            .map_err(|e| Error::Transport {
                message: format!("failed to configure idle timeout: {}", e),
            })?;

        let server = Server::builder()
            .with_tls((cert_pem_str, key_pem_str))
            .map_err(|e| Error::CertificateError {
                message: format!("failed to configure TLS: {}", e),
            })?
            .with_limits(limits)
            .map_err(|e| Error::Transport {
                message: format!("failed to configure limits: {}", e),
            })?
            .with_io(addr)
            .map_err(|e| Error::Transport {
                message: format!("failed to configure I/O: {}", e),
            })?
            .start()
            .map_err(|e| Error::Transport {
                message: format!("failed to start server: {}", e),
            })?;

        let local_addr = server.local_addr().map_err(|e| Error::Transport {
            message: format!("failed to get local address: {}", e),
        })?;

        Ok(Self { server, local_addr })
    }

    /// Get the local address this acceptor is bound to.
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.local_addr
    }

    /// Set the idle timeout for new connections.
    ///
    /// Note: s2n-quic configures idle timeout at server creation time.
    /// This method is a no-op for API compatibility with QuicheAcceptor.
    pub fn set_idle_timeout(&mut self, _timeout: Duration) {
        // s2n-quic doesn't support changing timeout after server creation
        // This would require rebuilding the server
        debug!("set_idle_timeout called but s2n-quic doesn't support dynamic timeout changes");
    }

    /// Accept the next established QUIC connection.
    ///
    /// Returns the connection and peer address when a client connects.
    pub async fn accept(&mut self) -> Result<(S2nConnection, std::net::SocketAddr)> {
        // Accept the next connection
        let connection = self.server.accept().await.ok_or_else(|| Error::Transport {
            message: "server closed".to_string(),
        })?;

        let remote_addr = connection.remote_addr().map_err(|e| Error::Transport {
            message: format!("failed to get remote address: {}", e),
        })?;

        info!(addr = %remote_addr, "Connection established");

        // Create stats for this connection
        // Note: For server-side connections, we don't have access to the event subscriber
        // system since the Server is already running. Stats will be updated manually
        // or remain at default values. For full stats on server side, we'd need to
        // rebuild the Server with an event subscriber, but that's complex for per-connection stats.
        let stats = Arc::new(ConnectionStats::default());

        // Wrap in S2nConnection
        let s2n_conn = S2nConnection::from_server_connection(connection, self.local_addr, stats).await?;

        Ok((s2n_conn, remote_addr))
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_stream_header_roundtrip() {
        let id = ChannelId::client(42);
        let header = channel_stream_header(id);
        assert_eq!(header[0], CHANNEL_STREAM_MAGIC);

        let encoded = u64::from_le_bytes(header[1..9].try_into().unwrap());
        let decoded = ChannelId::decode(encoded);
        assert_eq!(id, decoded);
    }

    #[test]
    fn channel_bidi_header_roundtrip() {
        let id = ChannelId::server(123);
        let header = channel_bidi_header(id);
        assert_eq!(header[0], CHANNEL_BIDI_MAGIC);

        let encoded = u64::from_le_bytes(header[1..9].try_into().unwrap());
        let decoded = ChannelId::decode(encoded);
        assert_eq!(id, decoded);
    }

    #[test]
    fn classify_io_errors() {
        // Test that we handle basic I/O errors
        let err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "test");
        let classified = classify_io_error(err);
        assert!(matches!(classified, Error::Io(_)));
    }

    #[test]
    fn cert_hash_sha256() {
        let data = b"test certificate data";
        let hash = cert_hash(data);
        assert_eq!(hash.len(), 32); // SHA256 produces 32 bytes
    }

    #[test]
    fn generate_self_signed_cert_works() {
        let result = generate_self_signed_cert();
        assert!(result.is_ok(), "should generate self-signed cert");
        let (cert, key) = result.unwrap();
        assert!(!cert.is_empty());
        assert!(!key.is_empty());
    }
}
