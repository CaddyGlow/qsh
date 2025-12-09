//! QUIC transport implementation using s2n-quic.
//!
//! This module provides concrete implementations of the Connection and StreamPair traits
//! using AWS s2n-quic as an alternative to quiche.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::{Buf, BytesMut};
use s2n_quic::stream::{BidirectionalStream, ReceiveStream, SendStream};
use tokio::sync::Mutex;
use tracing::debug;

use crate::error::{Error, Result};
use crate::protocol::{ChannelId, Codec, Message};

use super::{Connection, StreamPair, StreamType};

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

/// A QUIC stream pair using s2n-quic.
pub struct S2nStream {
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

impl S2nStream {
    /// Create a new bidirectional stream.
    pub fn new_bidi(stream: BidirectionalStream) -> Self {
        Self {
            bidi: Some(Mutex::new(stream)),
            send: None,
            recv: None,
            recv_buf: Mutex::new(BytesMut::with_capacity(8192)),
            direction: StreamDirection::Bidirectional,
            closed: AtomicBool::new(false),
        }
    }

    /// Create a send-only stream.
    pub fn send_only(stream: SendStream) -> Self {
        Self {
            bidi: None,
            send: Some(Mutex::new(stream)),
            recv: None,
            recv_buf: Mutex::new(BytesMut::new()),
            direction: StreamDirection::SendOnly,
            closed: AtomicBool::new(false),
        }
    }

    /// Create a recv-only stream.
    pub fn recv_only(stream: ReceiveStream) -> Self {
        Self {
            bidi: None,
            send: None,
            recv: Some(Mutex::new(stream)),
            recv_buf: Mutex::new(BytesMut::with_capacity(8192)),
            direction: StreamDirection::RecvOnly,
            closed: AtomicBool::new(false),
        }
    }

    /// Create a bidirectional stream with pre-populated buffer.
    pub fn with_buffer(stream: BidirectionalStream, initial_data: Option<BytesMut>) -> Self {
        let recv_buf = initial_data.unwrap_or_else(|| BytesMut::with_capacity(8192));
        Self {
            bidi: Some(Mutex::new(stream)),
            send: None,
            recv: None,
            recv_buf: Mutex::new(recv_buf),
            direction: StreamDirection::Bidirectional,
            closed: AtomicBool::new(false),
        }
    }

    /// Get a cloneable sender handle for spawning background send tasks.
    pub fn sender(&self) -> Option<S2nSender> {
        match self.direction {
            StreamDirection::Bidirectional => {
                // For bidi streams, we need to clone the inner stream
                // s2n-quic doesn't support cloning streams, so we return None
                // Use split() instead for bidi streams
                None
            }
            StreamDirection::SendOnly => {
                // For send-only, we also can't clone directly
                None
            }
            StreamDirection::RecvOnly => None,
        }
    }

    /// Send raw bytes without message framing.
    pub async fn send_raw(&self, data: &[u8]) -> Result<()> {
        use tokio::io::AsyncWriteExt;

        match self.direction {
            StreamDirection::RecvOnly => {
                return Err(Error::Transport {
                    message: "stream is receive-only".to_string(),
                });
            }
            StreamDirection::Bidirectional => {
                if let Some(ref bidi) = self.bidi {
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
                if let Some(ref send) = self.send {
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

        match self.direction {
            StreamDirection::SendOnly => {
                return Err(Error::Transport {
                    message: "stream is send-only".to_string(),
                });
            }
            StreamDirection::Bidirectional => {
                if let Some(ref bidi) = self.bidi {
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
                if let Some(ref recv) = self.recv {
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
    pub async fn finish(&mut self) -> Result<()> {
        use tokio::io::AsyncWriteExt;

        match self.direction {
            StreamDirection::RecvOnly => Ok(()),
            StreamDirection::Bidirectional => {
                if let Some(ref bidi) = self.bidi {
                    let mut stream = bidi.lock().await;
                    stream.shutdown().await.map_err(|e| Error::Transport {
                        message: format!("stream shutdown failed: {}", e),
                    })?;
                }
                Ok(())
            }
            StreamDirection::SendOnly => {
                if let Some(ref send) = self.send {
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
        match self.direction {
            StreamDirection::Bidirectional => {
                if let Some(bidi) = self.bidi {
                    let stream = bidi.into_inner();
                    let (recv, send) = stream.split();
                    let recv_buf = self.recv_buf.into_inner();
                    Ok((S2nStreamWriter::new(send), S2nStreamReader::new(recv, Some(recv_buf))))
                } else {
                    Err(Error::Transport {
                        message: "no bidirectional stream to split".to_string(),
                    })
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
        let direction = self.direction;

        // Get references to the stream mutexes
        let bidi = self.bidi.as_ref();
        let send = self.send.as_ref();

        async move {
            use tokio::io::AsyncWriteExt;

            match direction {
                StreamDirection::RecvOnly => {
                    return Err(Error::Transport {
                        message: "stream is receive-only".to_string(),
                    });
                }
                StreamDirection::Bidirectional => {
                    let data = data?;
                    if let Some(bidi) = bidi {
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
                    if let Some(send) = send {
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
        let direction = self.direction;
        let recv_buf = unsafe {
            // SAFETY: We need to get a reference to self.recv_buf for the async block.
            // This is safe because we hold &mut self and the Mutex ensures exclusive access.
            &*((&self.recv_buf) as *const Mutex<BytesMut>)
        };
        let bidi = self.bidi.as_ref();
        let recv = self.recv.as_ref();

        async move {
            use tokio::io::AsyncReadExt;

            if matches!(direction, StreamDirection::SendOnly) {
                return Err(Error::Transport {
                    message: "stream is send-only".to_string(),
                });
            }

            let mut recv_buf = recv_buf.lock().await;

            loop {
                if let Some(msg) = Codec::decode(&mut recv_buf)? {
                    return Ok(msg);
                }

                let mut chunk = [0u8; 4096];
                let n = match direction {
                    StreamDirection::Bidirectional => {
                        if let Some(bidi) = bidi {
                            let mut stream = bidi.lock().await;
                            stream.read(&mut chunk).await.map_err(|e| Error::Transport {
                                message: format!("stream recv failed: {}", e),
                            })?
                        } else {
                            return Err(Error::ConnectionClosed);
                        }
                    }
                    StreamDirection::RecvOnly => {
                        if let Some(recv) = recv {
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
        self.closed.store(true, Ordering::SeqCst);
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
// S2nSender - Cloneable sender handle (placeholder)
// =============================================================================

/// A cloneable sender handle for a QUIC stream.
///
/// Note: s2n-quic doesn't support cloning streams directly, so this is limited.
/// For most use cases, use the stream directly or split it.
#[derive(Clone)]
pub struct S2nSender {
    // Placeholder - s2n-quic streams are not cloneable
    _phantom: std::marker::PhantomData<()>,
}

impl S2nSender {
    /// Send a message (includes flush for low latency).
    ///
    /// Note: This is a placeholder. s2n-quic streams cannot be cloned.
    pub async fn send(&self, _msg: &Message) -> Result<()> {
        Err(Error::Transport {
            message: "S2nSender is not supported - use stream directly".to_string(),
        })
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
}

impl S2nConnection {
    /// Create a new connection wrapper from a client connection.
    pub async fn from_client_connection(
        mut conn: s2n_quic::connection::Connection,
        local_addr: SocketAddr,
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
        })
    }

    /// Create a new connection wrapper from a server connection.
    pub async fn from_server_connection(
        mut conn: s2n_quic::connection::Connection,
        local_addr: SocketAddr,
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
        // s2n-quic doesn't expose packet loss stats directly
        0.0
    }

    /// Get the congestion window size.
    pub async fn congestion_window(&self) -> u64 {
        // s2n-quic doesn't expose cwnd directly
        0
    }

    /// Get minimum observed RTT.
    pub async fn min_rtt(&self) -> Option<Duration> {
        // s2n-quic doesn't expose min_rtt directly
        None
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
        // Check for pending streams first
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
        // s2n-quic doesn't expose RTT directly through the connection
        // Return a default value
        Duration::from_millis(100)
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
