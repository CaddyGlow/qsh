//! QUIC transport implementation using tokio-quiche.
//!
//! This module provides concrete implementations of the Connection and StreamPair traits
//! using Cloudflare's tokio-quiche for faster network error detection via connected UDP
//! sockets with IP_RECVERR.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use bytes::{Buf, BytesMut};
use tokio::sync::{Mutex, RwLock};
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
// QuicheStream - Wrapper around quiche stream
// =============================================================================

/// A bidirectional QUIC stream pair using quiche.
pub struct QuicheStream {
    /// Connection handle for sending.
    conn: Arc<QuicheConnectionInner>,
    /// Stream ID.
    stream_id: u64,
    /// Receive buffer.
    recv_buf: Mutex<BytesMut>,
    /// Send-only flag.
    send_only: bool,
    /// Recv-only flag.
    recv_only: bool,
    /// Closed flag.
    closed: AtomicBool,
}

impl QuicheStream {
    /// Create a new bidirectional stream.
    pub fn new(conn: Arc<QuicheConnectionInner>, stream_id: u64) -> Self {
        Self {
            conn,
            stream_id,
            recv_buf: Mutex::new(BytesMut::with_capacity(8192)),
            send_only: false,
            recv_only: false,
            closed: AtomicBool::new(false),
        }
    }

    /// Create a send-only stream.
    pub fn send_only(conn: Arc<QuicheConnectionInner>, stream_id: u64) -> Self {
        Self {
            conn,
            stream_id,
            recv_buf: Mutex::new(BytesMut::new()),
            send_only: true,
            recv_only: false,
            closed: AtomicBool::new(false),
        }
    }

    /// Create a recv-only stream.
    pub fn recv_only(conn: Arc<QuicheConnectionInner>, stream_id: u64) -> Self {
        Self {
            conn,
            stream_id,
            recv_buf: Mutex::new(BytesMut::with_capacity(8192)),
            send_only: false,
            recv_only: true,
            closed: AtomicBool::new(false),
        }
    }

    /// Create a stream with pre-populated buffer and configurable direction.
    pub fn with_buffer(
        conn: Arc<QuicheConnectionInner>,
        stream_id: u64,
        initial_data: Option<BytesMut>,
        send_only: bool,
        recv_only: bool,
    ) -> Self {
        let recv_buf = match initial_data {
            Some(data) => data,
            None => BytesMut::with_capacity(8192),
        };
        Self {
            conn,
            stream_id,
            recv_buf: Mutex::new(recv_buf),
            send_only,
            recv_only,
            closed: AtomicBool::new(false),
        }
    }

    /// Get a cloneable sender handle for spawning background send tasks.
    ///
    /// Returns `Some(sender)` for bidirectional and send-only streams.
    /// Returns `None` for receive-only streams (which can't send).
    pub fn sender(&self) -> Option<QuicheSender> {
        // For now, always return Some since quiche streams are always
        // constructed from contexts that can send
        Some(QuicheSender {
            conn: Arc::clone(&self.conn),
            stream_id: self.stream_id,
        })
    }

    /// Send raw bytes without message framing.
    pub async fn send_raw(&self, data: &[u8]) -> Result<()> {
        if self.recv_only {
            return Err(Error::Transport {
                message: "stream is receive-only".to_string(),
            });
        }
        self.conn.stream_send(self.stream_id, data, false).await
    }

    /// Receive raw bytes without message framing.
    pub async fn recv_raw(&self, buf: &mut [u8]) -> Result<usize> {
        if self.send_only {
            return Err(Error::Transport {
                message: "stream is send-only".to_string(),
            });
        }
        self.conn.stream_recv(self.stream_id, buf).await
    }

    /// Gracefully finish the send side of the stream.
    pub async fn finish(&mut self) -> Result<()> {
        if self.recv_only {
            return Ok(());
        }
        self.conn.stream_send(self.stream_id, &[], true).await
    }

    /// Close the stream.
    pub fn close(&mut self) {
        self.closed.store(true, Ordering::SeqCst);
    }

    /// Split the stream into separate reader and writer halves.
    ///
    /// This consumes the stream and returns AsyncRead/AsyncWrite handles
    /// that can be used independently.
    pub fn into_split(self) -> (QuicheStreamWriter, QuicheStreamReader) {
        let recv_buf = self.recv_buf.into_inner();
        let writer = QuicheStreamWriter::new(Arc::clone(&self.conn), self.stream_id);
        let reader = QuicheStreamReader::new(self.conn, self.stream_id, Some(recv_buf));
        (writer, reader)
    }
}

impl StreamPair for QuicheStream {
    fn send(&mut self, msg: &Message) -> impl std::future::Future<Output = Result<()>> + Send {
        let data = Codec::encode(msg);
        let conn = Arc::clone(&self.conn);
        let stream_id = self.stream_id;
        let recv_only = self.recv_only;

        async move {
            if recv_only {
                return Err(Error::Transport {
                    message: "stream is receive-only".to_string(),
                });
            }
            let data = data?;
            conn.stream_send(stream_id, &data, false).await
        }
    }

    fn recv(&mut self) -> impl std::future::Future<Output = Result<Message>> + Send {
        let conn = Arc::clone(&self.conn);
        let stream_id = self.stream_id;
        let recv_buf = unsafe {
            // SAFETY: We need to get a reference to self.recv_buf for the async block.
            // This is safe because we hold &mut self and the Mutex ensures exclusive access.
            &*((&self.recv_buf) as *const Mutex<BytesMut>)
        };
        let send_only = self.send_only;

        async move {
            if send_only {
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
                match conn.stream_recv(stream_id, &mut chunk).await {
                    Ok(n) if n > 0 => {
                        recv_buf.extend_from_slice(&chunk[..n]);
                    }
                    Ok(_) => {
                        // EOF
                        if let Some(msg) = Codec::decode(&mut recv_buf)? {
                            return Ok(msg);
                        }
                        return Err(Error::ConnectionClosed);
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }

    fn close(&mut self) {
        self.closed.store(true, Ordering::SeqCst);
    }
}

// =============================================================================
// QuicheStreamReader / QuicheStreamWriter - AsyncRead/AsyncWrite wrappers
// =============================================================================

/// Write half of a QUIC stream implementing AsyncWrite.
pub struct QuicheStreamWriter {
    conn: Arc<QuicheConnectionInner>,
    stream_id: u64,
}

impl QuicheStreamWriter {
    /// Create a new stream writer.
    fn new(conn: Arc<QuicheConnectionInner>, stream_id: u64) -> Self {
        Self { conn, stream_id }
    }
}

impl tokio::io::AsyncWrite for QuicheStreamWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let conn = Arc::clone(&this.conn);
        let stream_id = this.stream_id;
        let data = buf.to_vec();

        // Create a future for the write operation
        let fut = async move {
            conn.stream_send(stream_id, &data, false)
                .await
                .map(|()| data.len())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
        };

        // Pin the future and poll it
        tokio::pin!(fut);
        fut.poll(cx)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let conn = Arc::clone(&this.conn);

        let fut = async move {
            conn.flush_send()
                .await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
        };

        tokio::pin!(fut);
        fut.poll(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let conn = Arc::clone(&this.conn);
        let stream_id = this.stream_id;

        let fut = async move {
            conn.stream_send(stream_id, &[], true)
                .await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
        };

        tokio::pin!(fut);
        fut.poll(cx)
    }
}

/// Read half of a QUIC stream implementing AsyncRead.
pub struct QuicheStreamReader {
    conn: Arc<QuicheConnectionInner>,
    stream_id: u64,
    buffer: BytesMut,
}

impl QuicheStreamReader {
    /// Create a new stream reader.
    fn new(conn: Arc<QuicheConnectionInner>, stream_id: u64, initial_buffer: Option<BytesMut>) -> Self {
        Self {
            conn,
            stream_id,
            buffer: initial_buffer.unwrap_or_default(),
        }
    }
}

impl tokio::io::AsyncRead for QuicheStreamReader {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // Return from buffer first if we have data
        if !this.buffer.is_empty() {
            let to_copy = std::cmp::min(this.buffer.len(), buf.remaining());
            buf.put_slice(&this.buffer[..to_copy]);
            this.buffer.advance(to_copy);
            return std::task::Poll::Ready(Ok(()));
        }

        let conn = Arc::clone(&this.conn);
        let stream_id = this.stream_id;
        let capacity = buf.remaining();

        let fut = async move {
            let mut temp_buf = vec![0u8; capacity];
            match conn.stream_recv(stream_id, &mut temp_buf).await {
                Ok(n) => Ok((temp_buf, n)),
                Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())),
            }
        };

        tokio::pin!(fut);
        match fut.poll(cx) {
            std::task::Poll::Ready(Ok((data, n))) => {
                buf.put_slice(&data[..n]);
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

// =============================================================================
// QuicheSender - Cloneable sender handle
// =============================================================================

/// A cloneable sender handle for a QUIC stream.
#[derive(Clone)]
pub struct QuicheSender {
    conn: Arc<QuicheConnectionInner>,
    stream_id: u64,
}

impl QuicheSender {
    /// Send a message (includes flush for low latency).
    pub async fn send(&self, msg: &Message) -> Result<()> {
        let data = Codec::encode(msg)?;
        self.conn.stream_send(self.stream_id, &data, false).await
    }

    /// Send raw bytes without message framing.
    pub async fn send_raw(&self, data: &[u8]) -> Result<()> {
        self.conn.stream_send(self.stream_id, data, false).await
    }

    /// Gracefully finish the send side of the stream.
    pub async fn finish(&self) -> Result<()> {
        self.conn.stream_send(self.stream_id, &[], true).await
    }
}

// =============================================================================
// QuicheConnectionInner - Internal connection state
// =============================================================================

/// Mosh-style keepalive constants.
/// Like Mosh's SRTT/2 approach: adaptive to network conditions.
const KEEPALIVE_MIN_INTERVAL: Duration = Duration::from_millis(50); // Mosh MIN_RTO
const KEEPALIVE_MAX_INTERVAL: Duration = Duration::from_millis(500); // Max keepalive rate
const KEEPALIVE_DEFAULT_INTERVAL: Duration = Duration::from_millis(500); // When RTT unknown

/// Internal state for a quiche connection.
pub struct QuicheConnectionInner {
    /// The quiche connection (protected by mutex for thread safety).
    conn: Mutex<quiche::Connection>,
    /// UDP socket for I/O.
    socket: Arc<tokio::net::UdpSocket>,
    /// Remote address.
    remote_addr: SocketAddr,
    /// Local address.
    local_addr: SocketAddr,
    /// Pending incoming streams (stream_type, stream_id).
    pending_streams: Mutex<VecDeque<(StreamType, u64)>>,
    /// Stream data buffers for reading (also used to track partial headers).
    stream_bufs: RwLock<HashMap<u64, BytesMut>>,
    /// Streams we've already detected and returned (to avoid duplicates).
    known_streams: RwLock<std::collections::HashSet<u64>>,
    /// Next client-initiated bidi stream ID.
    next_bidi_stream_id: AtomicU64,
    /// Next client-initiated uni stream ID.
    next_uni_stream_id: AtomicU64,
    /// Connection closed flag.
    closed: AtomicBool,
    /// Notifier for new readable data.
    readable_notify: tokio::sync::Notify,
    /// Notifier for writable streams.
    writable_notify: tokio::sync::Notify,
    /// Last time we sent a keepalive ping.
    last_keepalive: std::sync::Mutex<std::time::Instant>,
}

impl QuicheConnectionInner {
    /// Create new connection inner from a quiche connection.
    pub fn new(
        conn: quiche::Connection,
        socket: Arc<tokio::net::UdpSocket>,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
        is_server: bool,
    ) -> Self {
        // QUIC stream ID convention:
        // Client-initiated bidi: 0, 4, 8, 12, ...
        // Server-initiated bidi: 1, 5, 9, 13, ...
        // Client-initiated uni: 2, 6, 10, 14, ...
        // Server-initiated uni: 3, 7, 11, 15, ...
        //
        // Stream 0 is reserved for the control stream, so client starts at 4
        // Stream 1 is reserved for server's control stream, so server starts at 5
        let (next_bidi, next_uni) = if is_server {
            (5, 3) // Server-initiated: skip control stream 1
        } else {
            (4, 2) // Client-initiated: skip control stream 0
        };

        Self {
            conn: Mutex::new(conn),
            socket,
            remote_addr,
            local_addr,
            pending_streams: Mutex::new(VecDeque::new()),
            stream_bufs: RwLock::new(HashMap::new()),
            known_streams: RwLock::new(std::collections::HashSet::new()),
            next_bidi_stream_id: AtomicU64::new(next_bidi),
            next_uni_stream_id: AtomicU64::new(next_uni),
            closed: AtomicBool::new(false),
            readable_notify: tokio::sync::Notify::new(),
            writable_notify: tokio::sync::Notify::new(),
            last_keepalive: std::sync::Mutex::new(std::time::Instant::now()),
        }
    }

    /// Allocate a new bidirectional stream ID.
    fn alloc_bidi_stream_id(&self) -> u64 {
        self.next_bidi_stream_id.fetch_add(4, Ordering::SeqCst)
    }

    /// Allocate a new unidirectional stream ID.
    fn alloc_uni_stream_id(&self) -> u64 {
        self.next_uni_stream_id.fetch_add(4, Ordering::SeqCst)
    }

    /// Send data on a stream.
    pub async fn stream_send(&self, stream_id: u64, data: &[u8], fin: bool) -> Result<()> {
        let mut offset = 0;
        while offset < data.len() || (data.is_empty() && fin) {
            {
                let mut conn = self.conn.lock().await;

                // Check if connection is closed (e.g., due to idle timeout)
                if conn.is_closed() {
                    return Err(Error::ConnectionClosed);
                }

                match conn.stream_send(stream_id, &data[offset..], fin) {
                    Ok(written) => {
                        offset += written;
                        if offset >= data.len() {
                            break;
                        }
                    }
                    Err(quiche::Error::Done) => {
                        // Stream buffer full, flush and wait
                    }
                    Err(e) => {
                        return Err(Error::Transport {
                            message: format!("stream send failed: {}", e),
                        });
                    }
                }
            }

            // Flush pending packets
            self.flush_send().await?;

            // Wait for writable
            self.writable_notify.notified().await;
        }

        // Flush after write
        self.flush_send().await?;
        Ok(())
    }

    /// Receive data from a stream.
    pub async fn stream_recv(&self, stream_id: u64, buf: &mut [u8]) -> Result<usize> {
        loop {
            {
                let mut conn = self.conn.lock().await;

                // Check if connection is closed (e.g., due to idle timeout)
                if conn.is_closed() {
                    return Err(Error::ConnectionClosed);
                }

                match conn.stream_recv(stream_id, buf) {
                    Ok((read, _fin)) => return Ok(read),
                    Err(quiche::Error::Done) => {
                        // No data available, need to receive more
                    }
                    Err(e) => {
                        return Err(Error::Transport {
                            message: format!("stream recv failed: {}", e),
                        });
                    }
                }
            }

            // Drive I/O
            self.drive_io().await?;
        }
    }

    /// Flush pending outbound packets.
    pub async fn flush_send(&self) -> Result<()> {
        let mut out = [0u8; 65535];

        loop {
            let (write, send_info) = {
                let mut conn = self.conn.lock().await;
                match conn.send(&mut out) {
                    Ok(v) => v,
                    Err(quiche::Error::Done) => break,
                    Err(e) => {
                        return Err(Error::Transport {
                            message: format!("send failed: {}", e),
                        });
                    }
                }
            };

            self.socket
                .send_to(&out[..write], send_info.to)
                .await
                .map_err(|e| classify_io_error(e))?;
        }

        Ok(())
    }

    /// Drive I/O - receive packets and process them.
    ///
    /// This implements mosh-style keepalive detection:
    /// - Send periodic PING frames to keep the connection alive
    /// - If the peer stops responding, quiche's timeout mechanism detects it
    /// - The connection stays alive during normal user idle periods
    /// - Keepalive interval adapts to RTT (like Mosh's SRTT/2 approach)
    pub async fn drive_io(&self) -> Result<()> {
        let mut buf = [0u8; 65535];

        // Compute RTT-adaptive keepalive interval (Mosh-style: RTT/2)
        let keepalive_interval = {
            let conn = self.conn.lock().await;
            // Prefer the active path's RTT if available.
            let rtt = conn
                .path_stats()
                .find(|p| p.active)
                .map(|p| p.rtt)
                .or_else(|| conn.path_stats().next().map(|p| p.rtt));
            match rtt {
                Some(rtt) => {
                    // Mosh-style: RTT/2, clamped to [50ms, 500ms]
                    let interval = rtt / 2;
                    interval.clamp(KEEPALIVE_MIN_INTERVAL, KEEPALIVE_MAX_INTERVAL)
                }
                None => KEEPALIVE_DEFAULT_INTERVAL,
            }
        };

        // Check if we need to send a keepalive ping (mosh-style heartbeat)
        let should_send_keepalive = {
            let now = std::time::Instant::now();
            let last_keepalive = self.last_keepalive.lock().unwrap();
            now.duration_since(*last_keepalive) >= keepalive_interval
        };

        if should_send_keepalive {
            let mut conn = self.conn.lock().await;
            // Send a PING frame to keep the connection alive and detect peer liveness
            conn.send_ack_eliciting().ok();
            // Update timestamp after sending
            let mut last_keepalive = self.last_keepalive.lock().unwrap();
            *last_keepalive = std::time::Instant::now();
        }

        // Determine quiche's requested timeout (if any).
        // This represents how long we should wait before calling `on_timeout()`.
        let quiche_timeout = {
            let conn = self.conn.lock().await;
            let t = conn.timeout();
            debug!(
                quiche_timeout_ms = t.map(|d| d.as_millis() as u64),
                "quiche timeout poll"
            );
            t
        };

        // Try to receive a packet, honoring quiche's timeout semantics:
        // - If quiche requests a timeout, use that as the recv timeout and
        //   call `on_timeout()` only when that timer actually fires.
        // - If quiche has no pending timeout, block until a packet arrives.
        let recv_result = if let Some(t) = quiche_timeout {
            tokio::time::timeout(t, self.socket.recv_from(&mut buf)).await
        } else {
            Ok(self.socket.recv_from(&mut buf).await)
        };

        match recv_result {
            Ok(Ok((len, from))) => {
                let recv_info = quiche::RecvInfo {
                    from,
                    to: self.local_addr,
                };

                let mut conn = self.conn.lock().await;
                if let Err(e) = conn.recv(&mut buf[..len], recv_info) {
                    if e != quiche::Error::Done {
                        return Err(Error::Transport {
                            message: format!("recv failed: {}", e),
                        });
                    }
                }

                // Check for new readable streams
                for stream_id in conn.readable() {
                    self.readable_notify.notify_waiters();
                    // Detect stream type from ID
                    let stream_type = self.detect_stream_type(stream_id, &mut conn).await;
                    if let Some(st) = stream_type {
                        let mut pending = self.pending_streams.lock().await;
                        pending.push_back((st, stream_id));
                    }
                }

                // Check for writable streams
                for _stream_id in conn.writable() {
                    self.writable_notify.notify_waiters();
                }
            }
            Ok(Err(e)) => {
                return Err(classify_io_error(e));
            }
            Err(_) => {
                // quiche's timeout elapsed without a packet - drive its timers
                debug!("quiche timeout elapsed; calling on_timeout()");
                let mut conn = self.conn.lock().await;
                conn.on_timeout();
            }
        }

        // Always try to send pending data (including keepalive pings)
        self.flush_send().await?;

        // Check if connection is closed after processing
        {
            let conn = self.conn.lock().await;
            if conn.is_closed() {
                self.closed.store(true, Ordering::SeqCst);
                return Err(Error::ConnectionClosed);
            }
        }

        Ok(())
    }

    /// Detect stream type from stream ID and header.
    async fn detect_stream_type(
        &self,
        stream_id: u64,
        conn: &mut quiche::Connection,
    ) -> Option<StreamType> {
        // Check if we've already detected this stream
        {
            let known = self.known_streams.read().await;
            if known.contains(&stream_id) {
                return None; // Already processed
            }
        }

        // Control stream is always bidi stream 0 (client) or 1 (server)
        if stream_id == 0 || stream_id == 1 {
            let mut known = self.known_streams.write().await;
            known.insert(stream_id);
            return Some(StreamType::Control);
        }

        // Check if we have a partial header buffered for this stream
        let mut bufs = self.stream_bufs.write().await;
        let buffered = bufs.entry(stream_id).or_insert_with(BytesMut::new);

        // Read more data to complete the header
        let mut header = [0u8; 9];
        let need = 9 - buffered.len();
        if need > 0 {
            match conn.stream_recv(stream_id, &mut header[..need]) {
                Ok((n, _)) if n > 0 => {
                    buffered.extend_from_slice(&header[..n]);
                }
                Ok(_) | Err(quiche::Error::Done) => {
                    // No data available yet
                    return None;
                }
                Err(_) => return None,
            }
        }

        // Check if we have a complete header now
        if buffered.len() < 9 {
            return None; // Still need more data
        }

        // Parse the header
        let magic = buffered[0];
        let encoded = u64::from_le_bytes(buffered[1..9].try_into().unwrap());
        let channel_id = ChannelId::decode(encoded);

        // Remove processed header from buffer
        buffered.advance(9);
        drop(bufs); // Release lock before acquiring known_streams lock

        // Determine stream direction from QUIC stream ID
        // bit 0: initiator (0 = client, 1 = server)
        // bit 1: stream type (0 = bidi, 1 = uni)
        let is_uni = (stream_id & 0x2) != 0;

        let result = match (magic, is_uni) {
            (CHANNEL_BIDI_MAGIC, false) => Some(StreamType::ChannelBidi(channel_id)),
            (CHANNEL_STREAM_MAGIC, true) => {
                // Determine In vs Out based on initiator
                if (stream_id & 0x1) == 1 {
                    Some(StreamType::ChannelOut(channel_id)) // Server-initiated
                } else {
                    Some(StreamType::ChannelIn(channel_id)) // Client-initiated
                }
            }
            _ => None,
        };

        // Mark stream as known if we successfully detected its type
        if result.is_some() {
            let mut known = self.known_streams.write().await;
            known.insert(stream_id);
        }

        result
    }

    /// Check if connection is closed.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Get RTT of last path for application use.
    ///
    /// This is derived from quiche's smoothed RTT (SRTT) but is
    /// clamped to avoid pathological values after heavy loss or long
    /// recovery. For low-latency links this will generally reflect the
    /// true RTT; for highly congested links it is capped.
    pub async fn rtt(&self) -> Duration {
        let conn = self.conn.lock().await;

        // Snapshot connection-level stats.
        let stats = conn.stats();

        // Collect all path stats so we can both log them and select the active one.
        let paths: Vec<_> = conn.path_stats().collect();

        // Log detailed stats for each known path.
        for (idx, path) in paths.iter().enumerate() {
            debug!(
                path_index = idx,
                local_addr = %path.local_addr,
                peer_addr = %path.peer_addr,
                active = path.active,
                recv = path.recv,
                sent = path.sent,
                lost = path.lost,
                retrans = path.retrans,
                total_pto_count = path.total_pto_count,
                rtt_ms = path.rtt.as_millis() as u64,
                min_rtt_ms = path.min_rtt.map(|d| d.as_millis() as u64),
                max_rtt_ms = path.max_rtt.map(|d| d.as_millis() as u64),
                rttvar_ms = path.rttvar.as_millis() as u64,
                cwnd = path.cwnd,
                sent_bytes = path.sent_bytes,
                recv_bytes = path.recv_bytes,
                lost_bytes = path.lost_bytes,
                stream_retrans_bytes = path.stream_retrans_bytes,
                delivery_rate = path.delivery_rate,
                "quiche path_stats_detail"
            );
        }

        // Log aggregate connection stats.
        debug!(
            conn_sent = stats.sent,
            conn_lost = stats.lost,
            conn_retrans = stats.retrans,
            conn_sent_bytes = stats.sent_bytes,
            conn_recv_bytes = stats.recv_bytes,
            conn_lost_bytes = stats.lost_bytes,
            conn_paths_count = stats.paths_count,
            "quiche connection_stats"
        );

        // Prefer the active path when computing RTT, fall back to the first path.
        let selected = paths
            .iter()
            .find(|p| p.active)
            .or_else(|| paths.first());

        // Clamp SRTT so application-level RTT does not grow without bound.
        const RTT_CLAMP_MS: u64 = 1_000;

        if let Some(path) = selected {
            let raw_rtt = path.rtt;
            let clamped_rtt = raw_rtt.min(Duration::from_millis(RTT_CLAMP_MS));

            debug!(
                rtt_ms = raw_rtt.as_millis() as u64,
                min_rtt_ms = path.min_rtt.map(|d| d.as_millis() as u64),
                rttvar_ms = path.rttvar.as_millis() as u64,
                cwnd = path.cwnd,
                delivery_rate = path.delivery_rate,
                active = path.active,
                clamped_rtt_ms = clamped_rtt.as_millis() as u64,
                "quiche path_stats_selected"
            );
            clamped_rtt
        } else {
            Duration::from_millis(0) // Default fallback
        }
    }

    /// Get minimum observed RTT.
    ///
    /// This represents the best-case latency without retransmission delays.
    /// Preferred for display as it shows the true network latency.
    pub async fn min_rtt(&self) -> Option<Duration> {
        let conn = self.conn.lock().await;
        conn.path_stats()
            .find(|p| p.active)
            .or_else(|| conn.path_stats().next())
            .and_then(|p| p.min_rtt)
    }

    /// Get packet loss ratio.
    pub async fn packet_loss(&self) -> f64 {
        let conn = self.conn.lock().await;
        let stats = conn.stats();
        let sent = stats.sent as f64;
        if sent == 0.0 {
            0.0
        } else {
            (stats.lost as f64 / sent).clamp(0.0, 1.0)
        }
    }

    /// Get session data for 0-RTT resumption on reconnect.
    ///
    /// Returns the serialized cryptographic session that can be used to
    /// resume the connection later using `set_session()`. This should be
    /// called after the handshake is complete.
    pub async fn session_data(&self) -> Option<Vec<u8>> {
        let conn = self.conn.lock().await;
        conn.session().map(|s| s.to_vec())
    }

    /// Check if the connection has early data available.
    ///
    /// Returns true if the handshake has progressed enough to send or
    /// receive early data (0-RTT).
    pub async fn is_in_early_data(&self) -> bool {
        let conn = self.conn.lock().await;
        conn.is_in_early_data()
    }

    /// Check if the connection was resumed from a previous session.
    ///
    /// Returns true if the current connection is a 0-RTT resumed session.
    pub async fn is_resumed(&self) -> bool {
        let conn = self.conn.lock().await;
        conn.is_resumed()
    }
}

// =============================================================================
// QuicheConnection - Public connection wrapper
// =============================================================================

/// A QUIC connection wrapper using tokio-quiche.
pub struct QuicheConnection {
    inner: Arc<QuicheConnectionInner>,
    /// I/O driver task handle.
    _io_task: tokio::task::JoinHandle<()>,
}

impl QuicheConnection {
    /// Create a new connection wrapper.
    pub fn new(
        conn: quiche::Connection,
        socket: Arc<tokio::net::UdpSocket>,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
        is_server: bool,
    ) -> Self {
        let inner = Arc::new(QuicheConnectionInner::new(
            conn,
            socket,
            remote_addr,
            local_addr,
            is_server,
        ));

        // Spawn I/O driver task
        let inner_clone = Arc::clone(&inner);
        let io_task = tokio::spawn(async move {
            loop {
                if inner_clone.is_closed() {
                    break;
                }
                if let Err(_e) = inner_clone.drive_io().await {
                    break;
                }
                tokio::time::sleep(Duration::from_micros(100)).await;
            }
        });

        Self {
            inner,
            _io_task: io_task,
        }
    }

    /// Get the inner connection state (for advanced use).
    pub fn inner(&self) -> &Arc<QuicheConnectionInner> {
        &self.inner
    }

    /// Get packet loss ratio (0.0 - 1.0).
    pub async fn packet_loss(&self) -> f64 {
        self.inner.packet_loss().await
    }

    /// Get the congestion window size.
    pub async fn congestion_window(&self) -> u64 {
        let conn = self.inner.conn.lock().await;
        // Get cwnd from path stats
        if let Some(path) = conn
            .path_stats()
            .find(|p| p.active)
            .or_else(|| conn.path_stats().next())
        {
            path.cwnd as u64
        } else {
            0
        }
    }

    /// Get total packets sent.
    pub async fn packets_sent(&self) -> u64 {
        let conn = self.inner.conn.lock().await;
        conn.stats().sent as u64
    }

    /// Get total packets lost.
    pub async fn packets_lost(&self) -> u64 {
        let conn = self.inner.conn.lock().await;
        conn.stats().lost as u64
    }

    /// Open a unidirectional send stream.
    pub async fn open_uni(&self) -> Result<u64> {
        let stream_id = self.inner.alloc_uni_stream_id();
        Ok(stream_id)
    }

    /// Get session data for 0-RTT resumption on reconnect.
    ///
    /// Returns the serialized cryptographic session that can be cached and
    /// used for 0-RTT session resumption on the next connection using
    /// `set_session()`. Call this after the handshake is complete.
    ///
    /// Returns `None` if the session data is not yet available.
    pub async fn session_data(&self) -> Option<Vec<u8>> {
        self.inner.session_data().await
    }

    /// Check if the connection has early data available (0-RTT phase).
    ///
    /// Returns true if the handshake has progressed enough to send or
    /// receive early data. Use this to determine if Hello can be sent
    /// as early data before the handshake completes.
    pub async fn is_in_early_data(&self) -> bool {
        self.inner.is_in_early_data().await
    }

    /// Check if the connection was resumed from a previous session (0-RTT).
    ///
    /// Returns true if the current connection successfully resumed from
    /// cached session data. This indicates a faster connection with
    /// reduced latency.
    pub async fn is_resumed(&self) -> bool {
        self.inner.is_resumed().await
    }

    /// Get async RTT estimate (smoothed).
    pub async fn rtt_async(&self) -> Duration {
        self.inner.rtt().await
    }

    /// Get minimum observed RTT.
    ///
    /// This is the best-case latency without retransmission delays.
    /// Preferred for display as it shows true network latency.
    pub async fn min_rtt(&self) -> Option<Duration> {
        self.inner.min_rtt().await
    }

    /// Accept an incoming bidirectional stream.
    ///
    /// This waits for a new server-initiated bidirectional stream and returns
    /// wrapped reader/writer handles that implement AsyncRead/AsyncWrite.
    ///
    /// This is primarily used for standalone authentication where the server
    /// initiates an auth stream.
    pub async fn accept_bi(&self) -> Result<(QuicheStreamWriter, QuicheStreamReader)> {
        loop {
            // Check for pending streams
            {
                let mut pending = self.inner.pending_streams.lock().await;
                if let Some((stream_type, stream_id)) = pending.pop_front() {
                    // Only accept bidirectional streams
                    if stream_type.is_bidirectional() {
                        // Get any leftover buffered data
                        let leftover = {
                            let mut bufs = self.inner.stream_bufs.write().await;
                            bufs.remove(&stream_id)
                        };

                        let stream = QuicheStream::with_buffer(
                            Arc::clone(&self.inner),
                            stream_id,
                            leftover,
                            false,
                            false,
                        );

                        // Split into reader/writer
                        return Ok(stream.into_split());
                    }
                    // Put non-bidi streams back (or handle them)
                    pending.push_front((stream_type, stream_id));
                }
            }

            // Drive I/O and wait for new streams
            self.inner.drive_io().await?;

            if self.inner.is_closed() {
                return Err(Error::ConnectionClosed);
            }
        }
    }
}

impl Connection for QuicheConnection {
    type Stream = QuicheStream;

    async fn open_stream(&self, stream_type: StreamType) -> Result<Self::Stream> {
        match stream_type {
            StreamType::Control => {
                // Control stream: bidi stream ID 0 (already exists after handshake)
                let stream_id = 0;
                Ok(QuicheStream::new(Arc::clone(&self.inner), stream_id))
            }
            StreamType::ChannelBidi(channel_id) => {
                // Allocate new bidi stream
                let stream_id = self.inner.alloc_bidi_stream_id();

                // Write header
                let header = channel_bidi_header(channel_id);
                self.inner.stream_send(stream_id, &header, false).await?;

                Ok(QuicheStream::new(Arc::clone(&self.inner), stream_id))
            }
            StreamType::ChannelIn(channel_id) | StreamType::ChannelOut(channel_id) => {
                // Allocate new uni stream
                let stream_id = self.inner.alloc_uni_stream_id();

                // Write header
                let header = channel_stream_header(channel_id);
                self.inner.stream_send(stream_id, &header, false).await?;

                Ok(QuicheStream::send_only(Arc::clone(&self.inner), stream_id))
            }
        }
    }

    async fn accept_stream(&self) -> Result<(StreamType, Self::Stream)> {
        loop {
            // Check for pending streams
            {
                let mut pending = self.inner.pending_streams.lock().await;
                if let Some((stream_type, stream_id)) = pending.pop_front() {
                    // Check for any leftover buffered data from header parsing
                    let leftover = {
                        let mut bufs = self.inner.stream_bufs.write().await;
                        bufs.remove(&stream_id)
                    };

                    let stream = match stream_type {
                        StreamType::Control | StreamType::ChannelBidi(_) => {
                            QuicheStream::with_buffer(
                                Arc::clone(&self.inner),
                                stream_id,
                                leftover,
                                false,
                                false,
                            )
                        }
                        StreamType::ChannelIn(_) | StreamType::ChannelOut(_) => {
                            QuicheStream::with_buffer(
                                Arc::clone(&self.inner),
                                stream_id,
                                leftover,
                                false,
                                true, // recv_only
                            )
                        }
                    };
                    return Ok((stream_type, stream));
                }
            }

            // Drive I/O and wait for new streams
            self.inner.drive_io().await?;

            if self.inner.is_closed() {
                return Err(Error::ConnectionClosed);
            }
        }
    }

    fn remote_addr(&self) -> SocketAddr {
        self.inner.remote_addr
    }

    fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }

    fn is_connected(&self) -> bool {
        !self.inner.is_closed()
    }

    async fn rtt(&self) -> Duration {
        self.inner.rtt().await
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
pub fn enable_error_queue(socket: &tokio::net::UdpSocket) -> io::Result<()> {
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
            return Err(io::Error::last_os_error());
        }
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn enable_error_queue(_socket: &tokio::net::UdpSocket) -> io::Result<()> {
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
// quiche Configuration Helpers
// =============================================================================

/// Create a quiche client configuration.
pub fn client_config(verify_peer: bool) -> Result<quiche::Config> {
    let mut config =
        quiche::Config::new(quiche::PROTOCOL_VERSION).map_err(|e| Error::Transport {
            message: format!("failed to create quiche config: {}", e),
        })?;

    config
        .set_application_protos(&[crate::constants::ALPN])
        .map_err(|e| Error::Transport {
            message: format!("failed to set application protos: {}", e),
        })?;

    // Enable 0-RTT early data for faster reconnection
    config.enable_early_data();

    config.set_max_idle_timeout(30_000); // 30 seconds
    config.set_max_recv_udp_payload_size(65535);
    config.set_max_send_udp_payload_size(1350);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    // Connection migration enabled (like Mosh's roaming support)

    if !verify_peer {
        config.verify_peer(false);
    }

    Ok(config)
}

/// Create a quiche server configuration with certificate and key (PEM format).
///
/// Note: quiche requires file paths, so we write to temp files.
pub fn server_config(cert_pem: &[u8], key_pem: &[u8]) -> Result<quiche::Config> {
    server_config_with_ticket_key(cert_pem, key_pem, None)
}

/// Create a quiche server configuration with optional custom ticket key.
///
/// The ticket key is used to encrypt session tickets for 0-RTT resumption.
/// If `ticket_key` is None, quiche generates and rotates keys automatically.
/// For multi-server deployments, provide a shared key and rotate it periodically.
///
/// Note: quiche requires file paths, so we write to temp files.
pub fn server_config_with_ticket_key(
    cert_pem: &[u8],
    key_pem: &[u8],
    ticket_key: Option<&[u8]>,
) -> Result<quiche::Config> {
    use std::io::Write;

    let mut config =
        quiche::Config::new(quiche::PROTOCOL_VERSION).map_err(|e| Error::Transport {
            message: format!("failed to create quiche config: {}", e),
        })?;

    config
        .set_application_protos(&[crate::constants::ALPN])
        .map_err(|e| Error::Transport {
            message: format!("failed to set application protos: {}", e),
        })?;

    // Write cert/key to temp files (quiche requires file paths)
    // Use process ID + thread ID + timestamp for uniqueness in parallel tests
    let temp_dir = std::env::temp_dir();
    let unique_id = format!(
        "{}-{:?}-{}",
        std::process::id(),
        std::thread::current().id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let cert_path = temp_dir.join(format!("qsh-cert-{}.pem", unique_id));
    let key_path = temp_dir.join(format!("qsh-key-{}.pem", unique_id));

    let mut cert_file = std::fs::File::create(&cert_path).map_err(|e| Error::CertificateError {
        message: format!("failed to create temp cert file: {}", e),
    })?;
    cert_file
        .write_all(cert_pem)
        .map_err(|e| Error::CertificateError {
            message: format!("failed to write cert file: {}", e),
        })?;

    let mut key_file = std::fs::File::create(&key_path).map_err(|e| Error::CertificateError {
        message: format!("failed to create temp key file: {}", e),
    })?;
    key_file
        .write_all(key_pem)
        .map_err(|e| Error::CertificateError {
            message: format!("failed to write key file: {}", e),
        })?;

    // Load certificate and key from temp files
    config
        .load_cert_chain_from_pem_file(cert_path.to_str().unwrap())
        .map_err(|e| Error::CertificateError {
            message: format!("failed to load certificate: {}", e),
        })?;

    config
        .load_priv_key_from_pem_file(key_path.to_str().unwrap())
        .map_err(|e| Error::CertificateError {
            message: format!("failed to load private key: {}", e),
        })?;

    // Clean up temp files
    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    // Enable 0-RTT early data for faster reconnection
    config.enable_early_data();

    // Set custom ticket key if provided (for multi-server deployments)
    if let Some(key) = ticket_key {
        config.set_ticket_key(key).map_err(|e| Error::Transport {
            message: format!("failed to set ticket key: {}", e),
        })?;
    }

    config.set_max_idle_timeout(30_000);
    config.set_max_recv_udp_payload_size(65535);
    config.set_max_send_udp_payload_size(1350);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    // Connection migration enabled (like Mosh's roaming support)

    Ok(config)
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

/// Build a quiche::Config from a TransportConfigBuilder.
///
/// This converts the library-agnostic configuration to a quiche-specific config.
pub fn build_config(builder: &super::config::TransportConfigBuilder) -> Result<quiche::Config> {
    use super::config::EndpointRole;
    use std::io::Write;

    let mut config =
        quiche::Config::new(quiche::PROTOCOL_VERSION).map_err(|e| Error::Transport {
            message: format!("failed to create quiche config: {}", e),
        })?;

    // Set ALPN protocols
    let alpn_refs: Vec<&[u8]> = builder.alpn().iter().map(|a| a.as_slice()).collect();
    config
        .set_application_protos(&alpn_refs)
        .map_err(|e| Error::Transport {
            message: format!("failed to set application protos: {}", e),
        })?;

    // Handle TLS credentials for server
    if builder.role() == EndpointRole::Server {
        let creds = builder.credentials().ok_or_else(|| Error::Transport {
            message: "server config requires TLS credentials".to_string(),
        })?;

        // Write cert/key to temp files (quiche requires file paths)
        let temp_dir = std::env::temp_dir();
        let unique_id = format!(
            "{}-{:?}-{}",
            std::process::id(),
            std::thread::current().id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let cert_path = temp_dir.join(format!("qsh-cert-{}.pem", unique_id));
        let key_path = temp_dir.join(format!("qsh-key-{}.pem", unique_id));

        let mut cert_file =
            std::fs::File::create(&cert_path).map_err(|e| Error::CertificateError {
                message: format!("failed to create temp cert file: {}", e),
            })?;
        cert_file
            .write_all(&creds.cert_pem)
            .map_err(|e| Error::CertificateError {
                message: format!("failed to write cert file: {}", e),
            })?;

        let mut key_file =
            std::fs::File::create(&key_path).map_err(|e| Error::CertificateError {
                message: format!("failed to create temp key file: {}", e),
            })?;
        key_file
            .write_all(&creds.key_pem)
            .map_err(|e| Error::CertificateError {
                message: format!("failed to write key file: {}", e),
            })?;

        config
            .load_cert_chain_from_pem_file(cert_path.to_str().unwrap())
            .map_err(|e| Error::CertificateError {
                message: format!("failed to load certificate: {}", e),
            })?;

        config
            .load_priv_key_from_pem_file(key_path.to_str().unwrap())
            .map_err(|e| Error::CertificateError {
                message: format!("failed to load private key: {}", e),
            })?;

        // Clean up temp files
        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);

        // Set custom ticket key if provided
        if let Some(key) = &creds.ticket_key {
            config.set_ticket_key(key).map_err(|e| Error::Transport {
                message: format!("failed to set ticket key: {}", e),
            })?;
        }
    }

    // Enable 0-RTT early data if requested
    if builder.early_data_enabled() {
        config.enable_early_data();
    }

    // Set peer verification for client
    if builder.role() == EndpointRole::Client && !builder.should_verify_peer() {
        config.verify_peer(false);
    }

    // Apply transport parameters
    config.set_max_idle_timeout(builder.idle_timeout().as_millis() as u64);
    config.set_max_recv_udp_payload_size(builder.max_recv_udp_payload_size() as usize);
    config.set_max_send_udp_payload_size(builder.max_send_udp_payload_size() as usize);
    config.set_initial_max_data(builder.max_data());
    config.set_initial_max_stream_data_bidi_local(builder.max_stream_data_bidi_local());
    config.set_initial_max_stream_data_bidi_remote(builder.max_stream_data_bidi_remote());
    config.set_initial_max_stream_data_uni(builder.max_stream_data_uni());
    config.set_initial_max_streams_bidi(builder.max_streams_bidi());
    config.set_initial_max_streams_uni(builder.max_streams_uni());

    Ok(config)
}

// =============================================================================
// connect_quic - Client Connection Establishment
// =============================================================================

use super::{ConnectConfig, ConnectResult, ListenerConfig};
use std::time::Instant;
use tokio::net::UdpSocket;
use tracing::info;

/// Establish a QUIC client connection using the provided configuration.
///
/// This performs the full QUIC/TLS handshake and returns a connected
/// `QuicheConnection`. If `config.session_data` is provided, attempts
/// 0-RTT session resumption for faster reconnection.
///
/// # Arguments
/// * `config` - Connection configuration including server address, timeouts, and optional session data
///
/// # Returns
/// * `Ok(ConnectResult)` - Contains the connection, resume status, and new session data
/// * `Err(Error)` - On connection failure (timeout, handshake failure, certificate mismatch)
pub async fn connect_quic(config: &ConnectConfig) -> Result<ConnectResult<QuicheConnection>> {
    // Bind UDP socket (use specified port or OS-assigned random port)
    let bind_addr: std::net::SocketAddr = if config.server_addr.is_ipv4() {
        format!("0.0.0.0:{}", config.local_port.unwrap_or(0))
            .parse()
            .unwrap()
    } else {
        format!("[::]:{}", config.local_port.unwrap_or(0))
            .parse()
            .unwrap()
    };

    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| classify_io_error(e))?;

    // Connect socket for ICMP error delivery
    socket
        .connect(config.server_addr)
        .await
        .map_err(|e| classify_io_error(e))?;

    // Enable IP_RECVERR (Linux) for immediate ICMP error delivery
    enable_error_queue(&socket)?;

    let local_addr = socket.local_addr().map_err(|e| classify_io_error(e))?;

    // Create quiche client config
    let mut quiche_config = client_config(config.cert_hash.is_none())?;

    // Set idle timeout
    quiche_config.set_max_idle_timeout(config.max_idle_timeout.as_millis() as u64);

    // Generate connection ID
    let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut scid);
    let scid = quiche::ConnectionId::from_ref(&scid);

    // Create quiche connection
    let mut conn = quiche::connect(
        Some("qsh-server"),
        &scid,
        local_addr,
        config.server_addr,
        &mut quiche_config,
    )
    .map_err(|e| Error::HandshakeFailed {
        message: format!("failed to create connection: {}", e),
    })?;

    // Apply cached session data for 0-RTT resumption (must be done immediately
    // after creating the connection, before any packets are sent/received)
    let has_session_data = config.session_data.is_some();
    if let Some(session_data) = &config.session_data {
        if let Err(e) = conn.set_session(session_data) {
            // Non-fatal: fall back to regular 1-RTT handshake
            debug!(error = %e, "Failed to set session data for 0-RTT, falling back to 1-RTT");
        } else {
            debug!("Set session data for 0-RTT resumption");
        }
    }

    let socket = Arc::new(socket);

    // Perform handshake
    let mut out = [0u8; 65535];
    let mut buf = [0u8; 65535];

    // Initial handshake packet
    let (write, send_info) = conn.send(&mut out).map_err(|e| Error::HandshakeFailed {
        message: format!("failed to generate initial packet: {}", e),
    })?;

    socket
        .send_to(&out[..write], send_info.to)
        .await
        .map_err(|e| classify_io_error(e))?;

    // Handshake loop
    let start = Instant::now();
    while !conn.is_established() {
        if start.elapsed() > config.connect_timeout {
            return Err(Error::Timeout);
        }

        // Receive response
        let recv_result = tokio::time::timeout(
            Duration::from_millis(100),
            socket.recv_from(&mut buf),
        )
        .await;

        match recv_result {
            Ok(Ok((len, from))) => {
                let recv_info = quiche::RecvInfo {
                    from,
                    to: local_addr,
                };
                if let Err(e) = conn.recv(&mut buf[..len], recv_info) {
                    if e != quiche::Error::Done {
                        return Err(Error::HandshakeFailed {
                            message: format!("handshake recv failed: {}", e),
                        });
                    }
                }
            }
            Ok(Err(e)) => {
                return Err(classify_io_error(e));
            }
            Err(_) => {
                // Timeout, continue
            }
        }

        // Send pending packets
        loop {
            match conn.send(&mut out) {
                Ok((write, send_info)) => {
                    socket
                        .send_to(&out[..write], send_info.to)
                        .await
                        .map_err(|e| classify_io_error(e))?;
                }
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    return Err(Error::HandshakeFailed {
                        message: format!("handshake send failed: {}", e),
                    });
                }
            }
        }
    }

    // Verify certificate hash if provided
    if let Some(expected_hash) = &config.cert_hash {
        if let Some(peer_cert) = conn.peer_cert() {
            let actual_hash = cert_hash(peer_cert);
            if actual_hash.as_slice() != expected_hash.as_slice() {
                return Err(Error::CertificateError {
                    message: "certificate hash mismatch".to_string(),
                });
            }
        }
    }

    let rtt = conn
        .path_stats()
        .find(|p| p.active)
        .or_else(|| conn.path_stats().next())
        .map(|p| p.rtt);
    let resumed = conn.is_resumed();
    debug!(
        addr = %config.server_addr,
        rtt = ?rtt,
        resumed,
        had_session_data = has_session_data,
        "QUIC handshake completed"
    );

    if resumed {
        info!(addr = %config.server_addr, "0-RTT session resumed");
    }

    let quic_conn = QuicheConnection::new(
        conn,
        socket,
        config.server_addr,
        local_addr,
        false, // is_server = false for client
    );

    // Get session data for future 0-RTT resumption
    let session_data = quic_conn.session_data().await;

    Ok(ConnectResult {
        connection: quic_conn,
        resumed,
        session_data,
    })
}

// =============================================================================
// QuicheAcceptor - Server Connection Acceptance
// =============================================================================

use std::collections::HashMap as StdHashMap;

/// A QUIC server acceptor using quiche.
///
/// This handles the low-level packet parsing and connection acceptance,
/// returning fully established `QuicheConnection` instances.
pub struct QuicheAcceptor {
    /// UDP socket for receiving packets.
    socket: Arc<UdpSocket>,
    /// Local address.
    local_addr: std::net::SocketAddr,
    /// quiche configuration.
    quiche_config: quiche::Config,
    /// Pending connections (connection ID -> (connection, peer address)).
    connections: StdHashMap<Vec<u8>, (quiche::Connection, Option<std::net::SocketAddr>)>,
    /// Receive buffer.
    recv_buf: [u8; 65535],
    /// Send buffer.
    send_buf: [u8; 65535],
}

impl QuicheAcceptor {
    /// Create a new QUIC acceptor bound to the specified address.
    pub async fn bind(addr: std::net::SocketAddr, config: ListenerConfig) -> Result<Self> {
        // Create quiche config with certificates
        let mut quiche_config = server_config_with_ticket_key(
            &config.cert_pem,
            &config.key_pem,
            config.ticket_key.as_deref(),
        )?;

        // Set idle timeout
        quiche_config.set_max_idle_timeout(config.idle_timeout.as_millis() as u64);

        // Bind UDP socket
        let socket = UdpSocket::bind(addr)
            .await
            .map_err(|e| Error::Transport {
                message: format!("failed to bind server: {}", e),
            })?;

        let local_addr = socket.local_addr().map_err(|e| Error::Transport {
            message: format!("failed to get local address: {}", e),
        })?;

        // Enable IP_RECVERR for fast error detection (Linux-specific)
        if let Err(e) = enable_error_queue(&socket) {
            debug!(error = %e, "Failed to enable IP_RECVERR (non-fatal)");
        }

        Ok(Self {
            socket: Arc::new(socket),
            local_addr,
            quiche_config,
            connections: StdHashMap::new(),
            recv_buf: [0u8; 65535],
            send_buf: [0u8; 65535],
        })
    }

    /// Create a new acceptor with an existing UDP socket.
    pub async fn with_socket(socket: Arc<UdpSocket>, config: ListenerConfig) -> Result<Self> {
        let mut quiche_config = server_config_with_ticket_key(
            &config.cert_pem,
            &config.key_pem,
            config.ticket_key.as_deref(),
        )?;

        quiche_config.set_max_idle_timeout(config.idle_timeout.as_millis() as u64);

        let local_addr = socket.local_addr().map_err(|e| Error::Transport {
            message: format!("failed to get local address: {}", e),
        })?;

        if let Err(e) = enable_error_queue(&socket) {
            debug!(error = %e, "Failed to enable IP_RECVERR (non-fatal)");
        }

        Ok(Self {
            socket,
            local_addr,
            quiche_config,
            connections: StdHashMap::new(),
            recv_buf: [0u8; 65535],
            send_buf: [0u8; 65535],
        })
    }

    /// Get the local address this acceptor is bound to.
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.local_addr
    }

    /// Get a clone of the underlying socket (for sharing with connection handlers).
    pub fn socket(&self) -> Arc<UdpSocket> {
        Arc::clone(&self.socket)
    }

    /// Set the idle timeout for new connections.
    pub fn set_idle_timeout(&mut self, timeout: Duration) {
        self.quiche_config.set_max_idle_timeout(timeout.as_millis() as u64);
    }

    /// Accept the next established QUIC connection.
    ///
    /// This loops internally until a connection completes its handshake,
    /// then returns it along with the peer's address.
    pub async fn accept(&mut self) -> Result<(QuicheConnection, std::net::SocketAddr)> {
        loop {
            // Wait for a packet with a short timeout to allow checking pending connections
            let recv_result = tokio::time::timeout(
                Duration::from_millis(50),
                self.socket.recv_from(&mut self.recv_buf),
            )
            .await;

            match recv_result {
                Ok(Ok((len, from))) => {
                    // Parse QUIC header to get connection ID
                    let hdr = match quiche::Header::from_slice(
                        &mut self.recv_buf[..len],
                        quiche::MAX_CONN_ID_LEN,
                    ) {
                        Ok(h) => h,
                        Err(e) => {
                            debug!(error = %e, "Failed to parse QUIC header");
                            continue;
                        }
                    };

                    let dcid = hdr.dcid.to_vec();

                    // Look up or create connection
                    let conn_key = if self.connections.contains_key(&dcid) {
                        dcid.clone()
                    } else if hdr.ty == quiche::Type::Initial {
                        // New connection - generate scid and store
                        let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
                        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut scid);
                        let scid_vec = scid.to_vec();
                        let scid = quiche::ConnectionId::from_vec(scid_vec.clone());

                        let conn = quiche::accept(
                            &scid,
                            None,
                            self.local_addr,
                            from,
                            &mut self.quiche_config,
                        )
                        .map_err(|e| Error::Transport {
                            message: format!("failed to accept connection: {}", e),
                        })?;

                        self.connections.insert(scid_vec.clone(), (conn, Some(from)));
                        scid_vec
                    } else {
                        // Unknown connection
                        continue;
                    };

                    // Get mutable reference to the connection
                    let Some((conn, _peer)) = self.connections.get_mut(&conn_key) else {
                        continue;
                    };

                    let recv_info = quiche::RecvInfo {
                        from,
                        to: self.local_addr,
                    };

                    if let Err(e) = conn.recv(&mut self.recv_buf[..len], recv_info) {
                        if e != quiche::Error::Done {
                            debug!(error = %e, "recv failed");
                        }
                    }

                    // Check if connection is established
                    if conn.is_established() {
                        // Take ownership of connection
                        if let Some((conn, peer_addr)) = self.connections.remove(&conn_key) {
                            let peer = peer_addr.unwrap_or(from);
                            info!(addr = %peer, "Connection established");

                            // Wrap in QuicheConnection
                            let quic_conn = QuicheConnection::new(
                                conn,
                                Arc::clone(&self.socket),
                                peer,
                                self.local_addr,
                                true, // is_server = true
                            );

                            return Ok((quic_conn, peer));
                        }
                    }
                }
                Ok(Err(e)) => {
                    // Check if this is an ICMP error (from IP_RECVERR)
                    if let Some(errno) = e.raw_os_error() {
                        #[cfg(target_os = "linux")]
                        if errno == libc::ECONNREFUSED
                            || errno == libc::ENETUNREACH
                            || errno == libc::EHOSTUNREACH
                        {
                            debug!(error = %e, "ICMP error received (fast disconnect detection)");
                            continue;
                        }
                    }
                    debug!(error = %e, "Socket recv error");
                }
                Err(_) => {
                    // Timeout - continue to send pending packets
                }
            }

            // Send pending packets for all pending connections
            let conn_ids: Vec<Vec<u8>> = self.connections.keys().cloned().collect();
            for conn_id in conn_ids {
                if let Some((conn, _peer)) = self.connections.get_mut(&conn_id) {
                    loop {
                        match conn.send(&mut self.send_buf) {
                            Ok((write, send_info)) => {
                                if let Err(e) = self.socket.send_to(&self.send_buf[..write], send_info.to).await {
                                    debug!(error = %e, "send failed");
                                }
                            }
                            Err(quiche::Error::Done) => break,
                            Err(e) => {
                                debug!(error = %e, "send failed");
                                break;
                            }
                        }
                    }

                    // Remove closed connections
                    if conn.is_closed() {
                        self.connections.remove(&conn_id);
                    }
                }
            }
        }
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
    fn client_config_enables_early_data() {
        // Client config should successfully create and enable early data
        let config = client_config(false);
        assert!(config.is_ok(), "client_config should succeed");
    }

    #[test]
    fn server_config_enables_early_data() {
        // Generate self-signed cert for testing
        let (cert_pem, key_pem) =
            generate_self_signed_cert().expect("should generate self-signed cert");

        // Server config should successfully create and enable early data
        let config = server_config(&cert_pem, &key_pem);
        assert!(config.is_ok(), "server_config should succeed");
    }

    #[test]
    fn server_config_with_custom_ticket_key() {
        // Generate self-signed cert for testing
        let (cert_pem, key_pem) =
            generate_self_signed_cert().expect("should generate self-signed cert");

        // 48 bytes for AES-256-GCM ticket key
        let ticket_key = [0x42u8; 48];

        // Server config with custom ticket key should succeed
        let config = server_config_with_ticket_key(&cert_pem, &key_pem, Some(&ticket_key));
        assert!(
            config.is_ok(),
            "server_config_with_ticket_key should succeed"
        );
    }

    #[test]
    fn server_config_without_ticket_key() {
        // Generate self-signed cert for testing
        let (cert_pem, key_pem) =
            generate_self_signed_cert().expect("should generate self-signed cert");

        // Server config without ticket key should use auto-generated key
        let config = server_config_with_ticket_key(&cert_pem, &key_pem, None);
        assert!(
            config.is_ok(),
            "server_config_with_ticket_key(None) should succeed: {:?}",
            config.err()
        );
    }
}
