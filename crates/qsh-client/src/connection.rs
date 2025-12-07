//! Client connection management.
//!
//! Handles the full connection lifecycle using the SSH-style channel model:
//! 1. SSH bootstrap to discover QUIC endpoint
//! 2. QUIC connection establishment with cert pinning
//! 3. Session handshake (Hello/HelloAck)
//! 4. Channel-based multiplexing (terminals, file transfers, forwards)

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::{ClientConfig, Endpoint, IdleTimeout, TransportConfig};
use tracing::{debug, info};

use qsh_core::constants::DEFAULT_MAX_FORWARDS;
use qsh_core::error::{Error, Result};
use qsh_core::protocol::{
    Capabilities, HelloPayload, Message, ResizePayload, ShutdownPayload, ShutdownReason, TermSize,
};
use qsh_core::transport::{
    Connection, QuicConnection, QuicSender, QuicStream, StreamPair, client_crypto_config,
};

// ============================================================================
// Latency Tracker
// ============================================================================

/// Tracks input-to-output latency for measuring responsiveness.
#[derive(Debug)]
pub struct LatencyTracker {
    /// Timestamps when input sequences were sent.
    pending: HashMap<u64, Instant>,
    /// Recent latency samples (circular buffer).
    samples: Vec<Duration>,
    /// Index for circular buffer.
    sample_idx: usize,
    /// Maximum samples to keep.
    max_samples: usize,
    /// Minimum observed latency.
    min_latency: Option<Duration>,
    /// Maximum observed latency.
    max_latency: Option<Duration>,
}

impl LatencyTracker {
    /// Create a new latency tracker.
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            samples: Vec::with_capacity(100),
            sample_idx: 0,
            max_samples: 100,
            min_latency: None,
            max_latency: None,
        }
    }

    /// Record when an input sequence was sent.
    pub fn record_send(&mut self, seq: u64) {
        self.pending.insert(seq, Instant::now());
        // Clean up old entries (keep last 1000)
        if self.pending.len() > 1000 {
            let min_seq = seq.saturating_sub(1000);
            self.pending.retain(|&k, _| k >= min_seq);
        }
    }

    /// Record when a sequence was confirmed, returning the latency.
    pub fn record_confirm(&mut self, seq: u64) -> Option<Duration> {
        if let Some(sent_at) = self.pending.remove(&seq) {
            let latency = sent_at.elapsed();

            // Update min/max
            self.min_latency = Some(self.min_latency.map_or(latency, |min| min.min(latency)));
            self.max_latency = Some(self.max_latency.map_or(latency, |max| max.max(latency)));

            // Add to samples
            if self.samples.len() < self.max_samples {
                self.samples.push(latency);
            } else {
                self.samples[self.sample_idx] = latency;
            }
            self.sample_idx = (self.sample_idx + 1) % self.max_samples;

            Some(latency)
        } else {
            None
        }
    }

    /// Get the average latency from recent samples.
    pub fn average(&self) -> Option<Duration> {
        if self.samples.is_empty() {
            return None;
        }
        let sum: Duration = self.samples.iter().sum();
        Some(sum / self.samples.len() as u32)
    }

    /// Get latency statistics.
    pub fn stats(&self) -> LatencyStats {
        LatencyStats {
            sample_count: self.samples.len(),
            average: self.average(),
            min: self.min_latency,
            max: self.max_latency,
        }
    }
}

impl Default for LatencyTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Latency statistics snapshot.
#[derive(Debug, Clone)]
pub struct LatencyStats {
    /// Number of samples collected.
    pub sample_count: usize,
    /// Average latency.
    pub average: Option<Duration>,
    /// Minimum observed latency.
    pub min: Option<Duration>,
    /// Maximum observed latency.
    pub max: Option<Duration>,
}

impl std::fmt::Display for LatencyStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(avg) = self.average {
            write!(
                f,
                "avg={:.1}ms min={:.1}ms max={:.1}ms (n={})",
                avg.as_secs_f64() * 1000.0,
                self.min.unwrap_or_default().as_secs_f64() * 1000.0,
                self.max.unwrap_or_default().as_secs_f64() * 1000.0,
                self.sample_count
            )
        } else {
            write!(f, "no samples")
        }
    }
}

/// Client connection configuration.
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    /// Server address for QUIC connection.
    pub server_addr: SocketAddr,
    /// Session key from bootstrap.
    pub session_key: [u8; 32],
    /// Expected server certificate hash (optional, for pinning).
    pub cert_hash: Option<Vec<u8>>,
    /// Terminal size.
    pub term_size: TermSize,
    /// TERM environment variable.
    pub term_type: String,
    /// Additional environment variables to pass to the PTY (e.g., COLORTERM).
    pub env: Vec<(String, String)>,
    /// Enable predictive echo.
    pub predictive_echo: bool,
    /// Connection timeout.
    pub connect_timeout: Duration,
    /// Whether 0-RTT resumption is available.
    pub zero_rtt_available: bool,
    /// QUIC keep-alive interval (None disables).
    pub keep_alive_interval: Option<Duration>,
    /// QUIC max idle timeout.
    pub max_idle_timeout: Duration,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            server_addr: "127.0.0.1:4500".parse().unwrap(),
            session_key: [0; 32],
            cert_hash: None,
            term_size: TermSize { cols: 80, rows: 24 },
            term_type: "xterm-256color".to_string(),
            env: Vec::new(),
            predictive_echo: true,
            connect_timeout: Duration::from_secs(5),
            zero_rtt_available: false,
            // Aggressive keepalive (500ms) for fast disconnection detection (mosh uses RTT/2)
            keep_alive_interval: Some(Duration::from_millis(500)),
            max_idle_timeout: Duration::from_secs(15),
        }
    }
}

/// Establish a raw QUIC connection using the provided configuration.
///
/// This performs the QUIC/TLS handshake but does not send qsh protocol
/// messages. Used by `ChannelConnection::connect()` and standalone authentication.
pub async fn connect_quic(config: &ConnectionConfig) -> Result<quinn::Connection> {
    // Create QUIC endpoint
    let mut endpoint =
        Endpoint::client("0.0.0.0:0".parse().unwrap()).map_err(|e| Error::Transport {
            message: format!("failed to create QUIC endpoint: {}", e),
        })?;

    // Configure transport (keepalive + idle timeout)
    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(config.keep_alive_interval);
    if let Ok(timeout) = IdleTimeout::try_from(config.max_idle_timeout) {
        transport.max_idle_timeout(Some(timeout));
    }

    // Configure TLS with optional cert pinning
    let crypto = client_crypto_config(config.cert_hash.as_deref())?;
    let mut client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).map_err(|e| Error::Transport {
            message: format!("failed to create QUIC config: {}", e),
        })?,
    ));
    client_config.transport_config(Arc::new(transport));
    endpoint.set_default_client_config(client_config);

    // Connect to server
    let connecting = endpoint
        .connect(config.server_addr, "qsh-server")
        .map_err(|e| Error::Transport {
            message: format!("failed to initiate connection: {}", e),
        })?;

    let conn = tokio::time::timeout(config.connect_timeout, connecting)
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|e| Error::Transport {
            message: format!("connection failed: {}", e),
        })?;

    Ok(conn)
}

// NOTE: ClientConnection has been removed. Use ChannelConnection instead.
// The channel model supports multiple terminals, file transfers, and forwards
// on a single connection via explicit channel opening.

// =============================================================================
// Channel-Model Connection (SSH-style multiplexing)
// =============================================================================

use std::collections::HashMap as StdHashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;

use qsh_core::protocol::{
    ChannelAcceptData, ChannelAcceptPayload, ChannelClosePayload, ChannelCloseReason, ChannelId,
    ChannelOpenPayload, ChannelParams, ChannelRejectCode, ChannelRejectPayload, DirectTcpIpParams,
    DynamicForwardParams, FileTransferParams, ForwardedTcpIpParams, GlobalReplyData,
    GlobalReplyResult, GlobalRequest, GlobalRequestPayload, SessionId, TerminalParams,
};
use qsh_core::transport::StreamType;
use tokio::net::TcpStream;

use crate::channel::{FileChannel, ForwardChannel, TerminalChannel};

/// Target for a remote forward.
///
/// When the server notifies us of an incoming connection on a remote forward,
/// we need to know which local target to connect to.
#[derive(Debug, Clone)]
pub struct RemoteForwardTarget {
    /// Local target host to connect to.
    pub target_host: String,
    /// Local target port to connect to.
    pub target_port: u16,
}

/// Channel-model connection for SSH-style multiplexing.
///
/// Unlike `ClientConnection`, this does not automatically open a terminal.
/// Channels are created dynamically via `open_terminal()`, `open_file_transfer()`, etc.
pub struct ChannelConnection {
    /// QUIC connection.
    quic: Arc<QuicConnection>,
    /// Control stream for protocol messages.
    control: tokio::sync::Mutex<QuicStream>,
    /// Control sender (allows sending without holding control lock).
    control_sender: QuicSender,
    /// Connection configuration.
    config: ConnectionConfig,
    /// Session ID from server.
    session_id: SessionId,
    /// Server capabilities.
    server_caps: Capabilities,
    /// Active channels.
    channels: RwLock<StdHashMap<ChannelId, ChannelHandle>>,
    /// Next client-side channel ID.
    next_channel_id: AtomicU64,
    /// Pending global requests.
    pending_global_requests: tokio::sync::Mutex<StdHashMap<u32, tokio::sync::oneshot::Sender<GlobalReplyResult>>>,
    /// Next global request ID.
    next_global_request_id: std::sync::atomic::AtomicU32,
    /// Remote forward targets: (bind_host, bind_port) -> target info.
    remote_forwards: RwLock<StdHashMap<(String, u16), RemoteForwardTarget>>,
}

/// Handle for an active channel (client-side).
#[derive(Clone)]
pub enum ChannelHandle {
    Terminal(TerminalChannel),
    FileTransfer(FileChannel),
    Forward(ForwardChannel),
}

impl ChannelConnection {
    /// Connect using the channel model (no implicit terminal).
    pub async fn connect(config: ConnectionConfig) -> Result<Self> {
        info!(addr = %config.server_addr, "Connecting (channel model)");
        let conn = connect_quic(&config).await?;
        Self::from_quic(conn, config).await
    }

    /// Complete the qsh protocol handshake on an existing QUIC connection.
    pub async fn from_quic(conn: quinn::Connection, config: ConnectionConfig) -> Result<Self> {
        info!("QUIC connection established (channel model)");
        let quic = Arc::new(QuicConnection::new(conn));

        // Open control stream
        let mut control = quic
            .open_stream(qsh_core::transport::StreamType::Control)
            .await?;

        // Send Hello (channel model - no implicit terminal)
        let hello = HelloPayload {
            protocol_version: 1,
            session_key: config.session_key,
            client_nonce: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
            capabilities: Capabilities {
                predictive_echo: config.predictive_echo,
                compression: false,
                max_forwards: DEFAULT_MAX_FORWARDS,
                tunnel: false,
            },
            resume_session: None,
        };

        control.send(&Message::Hello(hello)).await?;
        debug!("Sent Hello (channel model)");

        // Wait for HelloAck
        let hello_ack = match control.recv().await? {
            Message::HelloAck(ack) => ack,
            other => {
                return Err(Error::Protocol {
                    message: format!("expected HelloAck, got {:?}", other),
                });
            }
        };

        if !hello_ack.accepted {
            return Err(Error::AuthenticationFailed);
        }

        info!(
            session_id = ?hello_ack.session_id,
            "Channel model session established"
        );

        // Extract sender before wrapping in Mutex (allows concurrent send/recv)
        let control_sender = control.sender();

        Ok(Self {
            quic,
            control: tokio::sync::Mutex::new(control),
            control_sender,
            config,
            session_id: hello_ack.session_id,
            server_caps: hello_ack.capabilities,
            channels: RwLock::new(StdHashMap::new()),
            next_channel_id: AtomicU64::new(0),
            pending_global_requests: tokio::sync::Mutex::new(StdHashMap::new()),
            next_global_request_id: std::sync::atomic::AtomicU32::new(0),
            remote_forwards: RwLock::new(StdHashMap::new()),
        })
    }

    /// Get the session ID.
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Get server capabilities.
    pub fn server_capabilities(&self) -> &Capabilities {
        &self.server_caps
    }

    /// Get the QUIC connection.
    pub fn quic(&self) -> &Arc<QuicConnection> {
        &self.quic
    }

    /// Get the current RTT.
    pub fn rtt(&self) -> Duration {
        self.quic.rtt()
    }

    /// Allocate a new client-side channel ID.
    fn allocate_channel_id(&self) -> ChannelId {
        let id = self.next_channel_id.fetch_add(1, Ordering::SeqCst);
        ChannelId::client(id)
    }

    /// Open a terminal channel.
    pub async fn open_terminal(&self, params: TerminalParams) -> Result<TerminalChannel> {
        let channel_id = self.allocate_channel_id();

        // Send ChannelOpen
        let open = ChannelOpenPayload {
            channel_id,
            params: ChannelParams::Terminal(params),
        };
        self.send_control(&Message::ChannelOpen(open)).await?;

        // Wait for ChannelAccept or ChannelReject
        let (accept_data, _) = self.wait_channel_accept(channel_id).await?;

        // Open input/output streams
        let input_stream = self
            .quic
            .open_stream(StreamType::ChannelIn(channel_id))
            .await?;

        // Accept output stream from server
        let output_stream = loop {
            let (ty, stream) = self.quic.accept_stream().await?;
            if matches!(ty, StreamType::ChannelOut(id) if id == channel_id) {
                break stream;
            }
            // Other streams may arrive - handle them or ignore
            debug!(?ty, "Ignoring stream while waiting for terminal output");
        };

        let initial_state = match accept_data {
            ChannelAcceptData::Terminal { initial_state } => initial_state,
            _ => qsh_core::terminal::TerminalState::new(80, 24), // Fallback
        };

        let channel = TerminalChannel::new(channel_id, input_stream, output_stream, initial_state);

        // Register channel
        self.channels
            .write()
            .await
            .insert(channel_id, ChannelHandle::Terminal(channel.clone()));

        info!(?channel_id, "Terminal channel opened");
        Ok(channel)
    }

    /// Open a file transfer channel.
    pub async fn open_file_transfer(&self, params: FileTransferParams) -> Result<FileChannel> {
        let channel_id = self.allocate_channel_id();
        let resume_offset = params.resume_from;

        // Send ChannelOpen
        let open = ChannelOpenPayload {
            channel_id,
            params: ChannelParams::FileTransfer(params),
        };
        self.send_control(&Message::ChannelOpen(open)).await?;

        // Wait for ChannelAccept or ChannelReject
        let (accept_data, _) = self.wait_channel_accept(channel_id).await?;

        // Open bidirectional stream for file data
        let stream = self
            .quic
            .open_stream(StreamType::ChannelBidi(channel_id))
            .await?;

        let metadata = match accept_data {
            ChannelAcceptData::FileTransfer { metadata } => metadata,
            _ => None,
        };

        let channel = FileChannel::new(channel_id, stream, metadata, resume_offset);

        // Register channel
        self.channels
            .write()
            .await
            .insert(channel_id, ChannelHandle::FileTransfer(channel.clone()));

        info!(?channel_id, "File transfer channel opened");
        Ok(channel)
    }

    /// Open a direct TCP/IP forward channel (-L local forward).
    pub async fn open_direct_tcpip(&self, params: DirectTcpIpParams) -> Result<ForwardChannel> {
        let channel_id = self.allocate_channel_id();
        let target_host = params.target_host.clone();
        let target_port = params.target_port;

        // Send ChannelOpen
        let open = ChannelOpenPayload {
            channel_id,
            params: ChannelParams::DirectTcpIp(params),
        };
        self.send_control(&Message::ChannelOpen(open)).await?;

        // Wait for ChannelAccept or ChannelReject
        self.wait_channel_accept(channel_id).await?;

        // Open bidirectional stream for forwarded data
        let stream = self
            .quic
            .open_stream(StreamType::ChannelBidi(channel_id))
            .await?;

        let channel = ForwardChannel::new(channel_id, stream, target_host, target_port);

        // Register channel
        self.channels
            .write()
            .await
            .insert(channel_id, ChannelHandle::Forward(channel.clone()));

        info!(?channel_id, "Direct TCP/IP channel opened");
        Ok(channel)
    }

    /// Open a dynamic SOCKS5 forward channel (-D).
    pub async fn open_dynamic(&self, params: DynamicForwardParams) -> Result<ForwardChannel> {
        let channel_id = self.allocate_channel_id();
        let target_host = params.target_host.clone();
        let target_port = params.target_port;

        // Send ChannelOpen
        let open = ChannelOpenPayload {
            channel_id,
            params: ChannelParams::DynamicForward(params),
        };
        self.send_control(&Message::ChannelOpen(open)).await?;

        // Wait for ChannelAccept
        self.wait_channel_accept(channel_id).await?;

        // Open bidirectional stream
        let stream = self
            .quic
            .open_stream(StreamType::ChannelBidi(channel_id))
            .await?;

        let channel = ForwardChannel::new(channel_id, stream, target_host, target_port);

        self.channels
            .write()
            .await
            .insert(channel_id, ChannelHandle::Forward(channel.clone()));

        info!(?channel_id, "Dynamic forward channel opened");
        Ok(channel)
    }

    /// Request a remote port forward (-R).
    ///
    /// - `bind_host`, `bind_port`: Address to bind on the server
    /// - `target_host`, `target_port`: Local target to connect to when server gets a connection
    ///
    /// Returns the actual bound port (may differ if 0 was requested).
    pub async fn request_remote_forward(
        &self,
        bind_host: &str,
        bind_port: u16,
        target_host: &str,
        target_port: u16,
    ) -> Result<u16> {
        let request_id = self
            .next_global_request_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        let request = GlobalRequestPayload {
            request_id,
            request: GlobalRequest::TcpIpForward {
                bind_host: bind_host.to_string(),
                bind_port,
            },
        };

        // Send request and wait for reply within the same lock scope
        let result = {
            let mut control = self.control.lock().await;
            control.send(&Message::GlobalRequest(request)).await?;

            // Read until we get our GlobalReply
            loop {
                match control.recv().await? {
                    Message::GlobalReply(reply) if reply.request_id == request_id => {
                        break reply.result;
                    }
                    Message::GlobalReply(reply) => {
                        debug!(
                            request_id = reply.request_id,
                            "Received GlobalReply for different request"
                        );
                    }
                    other => {
                        debug!(?other, "Ignoring message while waiting for GlobalReply");
                    }
                }
            }
        };

        match result {
            GlobalReplyResult::Success(GlobalReplyData::TcpIpForward { bound_port: bp }) => {
                // Store the target info so we can connect when the server notifies us
                self.remote_forwards.write().await.insert(
                    (bind_host.to_string(), bp),
                    RemoteForwardTarget {
                        target_host: target_host.to_string(),
                        target_port,
                    },
                );
                info!(
                    bind_host,
                    bind_port,
                    bound_port = bp,
                    target_host,
                    target_port,
                    "Remote forward established"
                );
                Ok(bp)
            }
            GlobalReplyResult::Success(_) => {
                // Unexpected reply data type, but treat as success
                // Still store the target
                self.remote_forwards.write().await.insert(
                    (bind_host.to_string(), bind_port),
                    RemoteForwardTarget {
                        target_host: target_host.to_string(),
                        target_port,
                    },
                );
                Ok(bind_port)
            }
            GlobalReplyResult::Failure { message } => Err(Error::Forward { message }),
        }
    }

    /// Cancel a remote port forward.
    pub async fn cancel_remote_forward(&self, bind_host: &str, bind_port: u16) -> Result<()> {
        let request_id = self
            .next_global_request_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        let request = GlobalRequestPayload {
            request_id,
            request: GlobalRequest::CancelTcpIpForward {
                bind_host: bind_host.to_string(),
                bind_port,
            },
        };

        // Send request and wait for reply within the same lock scope
        let result = {
            let mut control = self.control.lock().await;
            control.send(&Message::GlobalRequest(request)).await?;

            // Read until we get our GlobalReply
            loop {
                match control.recv().await? {
                    Message::GlobalReply(reply) if reply.request_id == request_id => {
                        break reply.result;
                    }
                    Message::GlobalReply(reply) => {
                        debug!(
                            request_id = reply.request_id,
                            "Received GlobalReply for different request"
                        );
                    }
                    other => {
                        debug!(?other, "Ignoring message while waiting for GlobalReply");
                    }
                }
            }
        };

        match result {
            GlobalReplyResult::Success(_) => {
                // Remove from our tracking map
                self.remote_forwards
                    .write()
                    .await
                    .remove(&(bind_host.to_string(), bind_port));
                info!(bind_host, bind_port, "Remote forward cancelled");
                Ok(())
            }
            GlobalReplyResult::Failure { message } => Err(Error::Forward { message }),
        }
    }

    /// Close a channel.
    pub async fn close_channel(
        &self,
        channel_id: ChannelId,
        reason: ChannelCloseReason,
    ) -> Result<()> {
        // Mark channel as closed
        if let Some(handle) = self.channels.write().await.remove(&channel_id) {
            match handle {
                ChannelHandle::Terminal(ch) => ch.mark_closed(),
                ChannelHandle::FileTransfer(ch) => ch.mark_closed(),
                ChannelHandle::Forward(ch) => ch.mark_closed(),
            }
        }

        // Send ChannelClose
        let close = ChannelClosePayload { channel_id, reason };
        self.send_control(&Message::ChannelClose(close)).await?;

        info!(?channel_id, "Channel closed");
        Ok(())
    }

    /// Handle an incoming ChannelOpen::ForwardedTcpIp from the server.
    ///
    /// This is called when the server has accepted a connection on a remote forward
    /// listener and wants us to connect to the local target.
    pub async fn handle_forwarded_channel_open(
        &self,
        channel_id: ChannelId,
        params: ForwardedTcpIpParams,
    ) -> Result<()> {
        debug!(
            channel_id = %channel_id,
            bound = %format!("{}:{}", params.bound_host, params.bound_port),
            originator = %format!("{}:{}", params.originator_host, params.originator_port),
            "Received forwarded-tcpip channel open"
        );

        // Look up the target for this remote forward
        let target = {
            let forwards = self.remote_forwards.read().await;
            forwards
                .get(&(params.bound_host.clone(), params.bound_port))
                .cloned()
        };

        let target = match target {
            Some(t) => t,
            None => {
                // Unknown forward - reject
                debug!(
                    channel_id = %channel_id,
                    bound_host = %params.bound_host,
                    bound_port = params.bound_port,
                    "No target found for forwarded channel"
                );
                self.send_channel_reject(
                    channel_id,
                    ChannelRejectCode::AdministrativelyProhibited,
                    "unknown remote forward",
                )
                .await?;
                return Ok(());
            }
        };

        // Connect to local target
        let target_addr = format!("{}:{}", target.target_host, target.target_port);
        let tcp_stream = match TcpStream::connect(&target_addr).await {
            Ok(s) => s,
            Err(e) => {
                debug!(
                    channel_id = %channel_id,
                    target = %target_addr,
                    error = %e,
                    "Failed to connect to local target"
                );
                self.send_channel_reject(
                    channel_id,
                    ChannelRejectCode::ConnectFailed,
                    &format!("failed to connect to {}: {}", target_addr, e),
                )
                .await?;
                return Ok(());
            }
        };

        info!(
            channel_id = %channel_id,
            target = %target_addr,
            "Connected to local target for remote forward"
        );

        // Send ChannelAccept (uses sender to avoid deadlock with recv loop)
        self.send_control(&Message::ChannelAccept(ChannelAcceptPayload {
            channel_id,
            data: ChannelAcceptData::ForwardedTcpIp,
        }))
        .await?;

        // Accept the QUIC stream from server
        let quic_stream = loop {
            let (ty, stream) = self.quic.accept_stream().await?;
            if matches!(ty, StreamType::ChannelBidi(id) if id == channel_id) {
                break stream;
            }
            debug!(?ty, "Ignoring stream while waiting for forwarded channel bidi");
        };

        // Spawn relay tasks directly - no need for ForwardChannel wrapper
        Self::spawn_forwarded_relay(channel_id, tcp_stream, quic_stream);

        info!(?channel_id, "Forwarded channel relay started");
        Ok(())
    }

    /// Spawn bidirectional relay tasks for a forwarded-tcpip channel.
    fn spawn_forwarded_relay(channel_id: ChannelId, tcp_stream: TcpStream, quic_stream: QuicStream) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();
        let quic_sender = quic_stream.sender();

        // Task: TCP -> QUIC
        tokio::spawn(async move {
            const BUFFER_SIZE: usize = 32 * 1024;
            let mut buf = vec![0u8; BUFFER_SIZE];
            loop {
                match tcp_read.read(&mut buf).await {
                    Ok(0) => {
                        debug!(channel_id = %channel_id, "TCP EOF (forwarded)");
                        break;
                    }
                    Ok(n) => {
                        if let Err(e) = quic_sender.send_raw(&buf[..n]).await {
                            debug!(channel_id = %channel_id, error = %e, "QUIC send error (forwarded)");
                            break;
                        }
                    }
                    Err(e) => {
                        debug!(channel_id = %channel_id, error = %e, "TCP read error (forwarded)");
                        break;
                    }
                }
            }
            // Send FIN to signal EOF to the remote peer
            if let Err(e) = quic_sender.finish().await {
                debug!(channel_id = %channel_id, error = %e, "QUIC finish error (forwarded)");
            }
        });

        // Task: QUIC -> TCP
        tokio::spawn(async move {
            const BUFFER_SIZE: usize = 32 * 1024;
            let mut buf = vec![0u8; BUFFER_SIZE];
            loop {
                match quic_stream.recv_raw(&mut buf).await {
                    Ok(0) => {
                        debug!(channel_id = %channel_id, "QUIC EOF (forwarded)");
                        break;
                    }
                    Ok(n) => {
                        if let Err(e) = tcp_write.write_all(&buf[..n]).await {
                            debug!(channel_id = %channel_id, error = %e, "TCP write error (forwarded)");
                            break;
                        }
                    }
                    Err(e) => {
                        debug!(channel_id = %channel_id, error = %e, "QUIC recv error (forwarded)");
                        break;
                    }
                }
            }
            let _ = tcp_write.shutdown().await;
        });
    }

    /// Send a ChannelReject message.
    async fn send_channel_reject(
        &self,
        channel_id: ChannelId,
        code: ChannelRejectCode,
        message: &str,
    ) -> Result<()> {
        self.send_control(&Message::ChannelReject(ChannelRejectPayload {
            channel_id,
            code,
            message: message.to_string(),
        }))
        .await
    }

    /// Wait for ChannelAccept or ChannelReject.
    async fn wait_channel_accept(
        &self,
        channel_id: ChannelId,
    ) -> Result<(ChannelAcceptData, ChannelId)> {
        let mut control = self.control.lock().await;

        loop {
            match control.recv().await? {
                Message::ChannelAccept(accept) if accept.channel_id == channel_id => {
                    return Ok((accept.data, accept.channel_id));
                }
                Message::ChannelReject(reject) if reject.channel_id == channel_id => {
                    return Err(channel_reject_to_error(reject.code, Some(reject.message)));
                }
                Message::GlobalReply(reply) => {
                    // Handle global reply
                    if let Some(tx) = self
                        .pending_global_requests
                        .lock()
                        .await
                        .remove(&reply.request_id)
                    {
                        let _ = tx.send(reply.result);
                    }
                }
                other => {
                    debug!(?other, "Ignoring message while waiting for ChannelAccept");
                }
            }
        }
    }

    /// Receive a control message.
    pub async fn recv_control(&self) -> Result<Message> {
        self.control.lock().await.recv().await
    }

    /// Send a control message (uses sender to avoid blocking recv).
    pub async fn send_control(&self, msg: &Message) -> Result<()> {
        self.control_sender.send(msg).await
    }

    /// Send a resize notification for a terminal channel.
    pub async fn send_resize(&self, channel_id: ChannelId, cols: u16, rows: u16) -> Result<()> {
        self.send_control(&Message::Resize(ResizePayload {
            channel_id: Some(channel_id),
            cols,
            rows,
        }))
        .await
    }

    /// Close the connection gracefully.
    pub async fn close(self) -> Result<()> {
        self.shutdown().await
    }

    /// Shutdown the connection gracefully (callable on &self or Arc<Self>).
    pub async fn shutdown(&self) -> Result<()> {
        // Close all channels
        for (id, handle) in self.channels.write().await.drain() {
            match handle {
                ChannelHandle::Terminal(ch) => ch.mark_closed(),
                ChannelHandle::FileTransfer(ch) => ch.mark_closed(),
                ChannelHandle::Forward(ch) => ch.mark_closed(),
            }
            debug!(?id, "Channel marked closed");
        }

        // Send shutdown (uses sender to avoid deadlock)
        self.send_control(&Message::Shutdown(ShutdownPayload {
            reason: ShutdownReason::UserRequested,
            message: Some("client disconnect".to_string()),
        }))
        .await?;

        // Close the control stream
        self.control.lock().await.close();
        Ok(())
    }
}

/// Convert a channel reject code to an error.
fn channel_reject_to_error(code: ChannelRejectCode, message: Option<String>) -> Error {
    let msg = message.unwrap_or_else(|| format!("{:?}", code));
    match code {
        ChannelRejectCode::AdministrativelyProhibited => Error::Channel { message: msg },
        ChannelRejectCode::ConnectFailed => Error::Channel { message: msg },
        ChannelRejectCode::UnknownChannelType => Error::Channel { message: msg },
        ChannelRejectCode::ResourceShortage => Error::Channel { message: msg },
        ChannelRejectCode::InvalidChannelId => Error::Channel { message: msg },
        ChannelRejectCode::PermissionDenied => Error::AuthenticationFailed,
        ChannelRejectCode::NotFound => Error::Channel { message: msg },
        ChannelRejectCode::InternalError => Error::Channel { message: msg },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_config_default() {
        let config = ConnectionConfig::default();
        assert_eq!(config.term_size.cols, 80);
        assert_eq!(config.term_size.rows, 24);
        assert!(config.predictive_echo);
    }

    #[test]
    fn latency_tracker_new() {
        let tracker = LatencyTracker::new();
        assert!(tracker.average().is_none());
        let stats = tracker.stats();
        assert_eq!(stats.sample_count, 0);
    }

    #[test]
    fn latency_tracker_record_and_confirm() {
        let mut tracker = LatencyTracker::new();

        // Record send
        tracker.record_send(1);

        // Small delay to ensure measurable latency
        std::thread::sleep(std::time::Duration::from_millis(1));

        // Confirm and get latency
        let latency = tracker.record_confirm(1);
        assert!(latency.is_some());
        assert!(latency.unwrap() >= std::time::Duration::from_millis(1));

        // Stats should reflect the sample
        let stats = tracker.stats();
        assert_eq!(stats.sample_count, 1);
        assert!(stats.average.is_some());
        assert!(stats.min.is_some());
        assert!(stats.max.is_some());
    }

    #[test]
    fn latency_tracker_unknown_seq() {
        let mut tracker = LatencyTracker::new();

        // Confirming unknown sequence returns None
        let latency = tracker.record_confirm(999);
        assert!(latency.is_none());
    }

    #[test]
    fn latency_tracker_min_max() {
        let mut tracker = LatencyTracker::new();

        // First sample
        tracker.record_send(1);
        std::thread::sleep(std::time::Duration::from_millis(5));
        tracker.record_confirm(1);

        // Second sample (should be similar or longer due to sleep)
        tracker.record_send(2);
        std::thread::sleep(std::time::Duration::from_millis(10));
        tracker.record_confirm(2);

        let stats = tracker.stats();
        assert_eq!(stats.sample_count, 2);
        // Max should be >= min
        assert!(stats.max.unwrap() >= stats.min.unwrap());
    }

    #[test]
    fn latency_stats_display() {
        let mut tracker = LatencyTracker::new();
        tracker.record_send(1);
        std::thread::sleep(std::time::Duration::from_millis(1));
        tracker.record_confirm(1);

        let stats = tracker.stats();
        let display = format!("{}", stats);
        assert!(display.contains("avg="));
        assert!(display.contains("min="));
        assert!(display.contains("max="));
        assert!(display.contains("n=1"));
    }

    #[test]
    fn latency_stats_display_no_samples() {
        let tracker = LatencyTracker::new();
        let stats = tracker.stats();
        let display = format!("{}", stats);
        assert_eq!(display, "no samples");
    }
}
