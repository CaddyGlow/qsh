//! QUIC connection implementation for the quiche backend.
//!
//! This module provides the core connection types:
//! - QuicheConnectionInner: Internal connection state with I/O operations
//! - QuicheConnection: Public connection wrapper with Connection trait implementation

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use bytes::{Buf, BytesMut};
use tokio::sync::{Mutex, RwLock};
use tracing::debug;

use crate::error::{Error, Result};
use crate::protocol::ChannelId;

use super::common::{CHANNEL_BIDI_MAGIC, CHANNEL_STREAM_MAGIC};
use super::common::{channel_bidi_header, channel_stream_header, classify_io_error};
use super::stream::{QuicheStream, QuicheStreamReader, QuicheStreamWriter};
use crate::transport::{Connection, StreamDirectionMapper, StreamPair, StreamType};

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
    pub(crate) conn: Mutex<quiche::Connection>,
    /// UDP socket for I/O.
    socket: Arc<tokio::net::UdpSocket>,
    /// Remote address.
    pub(crate) remote_addr: SocketAddr,
    /// Local address.
    pub(crate) local_addr: SocketAddr,
    /// Stream direction mapper for role-aware stream type detection.
    mapper: StreamDirectionMapper,
    /// Pending incoming streams (stream_type, stream_id).
    pub(crate) pending_streams: Mutex<VecDeque<(StreamType, u64)>>,
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
    ///
    /// # Arguments
    ///
    /// * `conn` - The quiche connection
    /// * `socket` - The UDP socket
    /// * `remote_addr` - Remote peer address
    /// * `local_addr` - Local address
    /// * `logical_role` - Logical endpoint role (client/server) from application perspective
    /// * `quic_role` - QUIC endpoint role (client/server) from transport perspective
    pub fn new(
        conn: quiche::Connection,
        socket: Arc<tokio::net::UdpSocket>,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
        logical_role: crate::transport::config::EndpointRole,
        quic_role: crate::transport::config::EndpointRole,
    ) -> Self {
        use crate::transport::config::EndpointRole;

        // Create stream direction mapper
        let mapper = StreamDirectionMapper::new(logical_role, quic_role);

        // QUIC stream ID convention:
        // Client-initiated bidi: 0, 4, 8, 12, ...
        // Server-initiated bidi: 1, 5, 9, 13, ...
        // Client-initiated uni: 2, 6, 10, 14, ...
        // Server-initiated uni: 3, 7, 11, 15, ...
        //
        // Stream 0 is reserved for the control stream, so client starts at 4
        // Stream 1 is reserved for server's control stream, so server starts at 5
        //
        // Note: Stream ID allocation is based on QUIC role, not logical role
        let (next_bidi, next_uni) = if quic_role == EndpointRole::Server {
            (5, 3) // Server-initiated: skip control stream 1
        } else {
            (4, 2) // Client-initiated: skip control stream 0
        };

        Self {
            conn: Mutex::new(conn),
            socket,
            remote_addr,
            local_addr,
            mapper,
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
    pub fn alloc_bidi_stream_id(&self) -> u64 {
        self.next_bidi_stream_id.fetch_add(4, Ordering::SeqCst)
    }

    /// Allocate a new unidirectional stream ID.
    pub fn alloc_uni_stream_id(&self) -> u64 {
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
            // Check our closed flag first (set by close_connection())
            if self.closed.load(Ordering::SeqCst) {
                debug!(
                    stream_id,
                    "stream_recv: closed flag is set, returning ConnectionClosed"
                );
                return Err(Error::ConnectionClosed);
            }

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
        // Check our closed flag first (set by close_connection())
        if self.closed.load(Ordering::SeqCst) {
            debug!("drive_io: closed flag is set, returning ConnectionClosed");
            return Err(Error::ConnectionClosed);
        }

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
        // - If quiche has no pending timeout, use a short max timeout to
        //   ensure we periodically return and allow stream state checks.
        //   This is important for detecting stream closures promptly.
        const MAX_RECV_TIMEOUT: Duration = Duration::from_millis(100);
        let recv_timeout = quiche_timeout.unwrap_or(MAX_RECV_TIMEOUT);
        let recv_result = tokio::time::timeout(recv_timeout, self.socket.recv_from(&mut buf)).await;

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

        // Use the mapper to detect stream type based on roles
        let result = self.mapper.detect_stream_type(stream_id, channel_id, magic);

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

    /// Close the connection gracefully.
    ///
    /// This initiates a QUIC connection close. After calling this,
    /// `is_closed()` will return true and any pending `stream_recv()` calls
    /// will return `ConnectionClosed`.
    pub async fn close_connection(&self) {
        debug!("close_connection called, setting closed flag");
        self.closed.store(true, Ordering::SeqCst);
        let mut conn = self.conn.lock().await;
        // Close with NO_ERROR code (0) and no reason phrase
        let result = conn.close(false, 0, b"");
        debug!(?result, "quiche conn.close() result");
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
        let selected = paths.iter().find(|p| p.active).or_else(|| paths.first());

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
    ///
    /// # Arguments
    ///
    /// * `conn` - The quiche connection
    /// * `socket` - The UDP socket
    /// * `remote_addr` - Remote peer address
    /// * `local_addr` - Local address
    /// * `logical_role` - Logical endpoint role (client/server) from application perspective
    /// * `quic_role` - QUIC endpoint role (client/server) from transport perspective
    pub fn new(
        conn: quiche::Connection,
        socket: Arc<tokio::net::UdpSocket>,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
        logical_role: crate::transport::config::EndpointRole,
        quic_role: crate::transport::config::EndpointRole,
    ) -> Self {
        let inner = Arc::new(QuicheConnectionInner::new(
            conn,
            socket,
            remote_addr,
            local_addr,
            logical_role,
            quic_role,
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

    /// Close the connection gracefully.
    ///
    /// This initiates a QUIC connection close. After calling this,
    /// any pending `stream_recv()` calls will return `ConnectionClosed`.
    pub async fn close_connection(&self) {
        self.inner.close_connection().await
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
