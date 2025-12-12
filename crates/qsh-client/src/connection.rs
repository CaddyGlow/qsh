//! Client connection management.
//!
//! Handles the full connection lifecycle using the SSH-style channel model:
//! 1. SSH bootstrap to discover QUIC endpoint
//! 2. QUIC connection establishment with cert pinning
//! 3. Session handshake (Hello/HelloAck)
//! 4. Channel-based multiplexing (terminals, file transfers, forwards)

use std::collections::HashMap as StdHashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rand::Rng;
use tracing::{debug, info};

// Re-export shared connection types from qsh-core
pub use qsh_core::connection::HeartbeatTracker;

// ============================================================================
// Mosh-style Port Range (from mosh/src/network/network.cc)
// ============================================================================

/// Mosh-style local port range for client connections.
/// Using the same range as Mosh ensures NAT/firewall compatibility.
pub const LOCAL_PORT_RANGE_LOW: u16 = 60001;
pub const LOCAL_PORT_RANGE_HIGH: u16 = 60999;

/// Generate a random local port in the Mosh range.
pub fn random_local_port() -> u16 {
    rand::rng().random_range(LOCAL_PORT_RANGE_LOW..=LOCAL_PORT_RANGE_HIGH)
}

use qsh_core::ConnectMode;
use qsh_core::constants::{DEFAULT_MAX_FORWARDS, FORWARD_BUFFER_SIZE, IDLE_TIMEOUT};
use qsh_core::error::{Error, Result};
use qsh_core::handshake::{HandshakeConfig, handshake_initiate, handshake_respond};
use qsh_core::protocol::{
    Capabilities, Message, ResizePayload, SessionId, ShutdownPayload, ShutdownReason, TermSize,
};
use qsh_core::transport::{
    ConnectConfig, Connection, QuicConnection, QuicSender, QuicStream, StreamPair, connect_quic,
};

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
    /// Cached session data for 0-RTT resumption.
    ///
    /// When reconnecting, provide the session data from a previous connection
    /// to enable 0-RTT fast reconnection. This is obtained by calling
    /// `QuicConnection::session_data()` after a successful connection.
    pub session_data: Option<Vec<u8>>,
    /// Local port to bind (None = OS-assigned random port).
    ///
    /// Used for Mosh-style port hopping: if reconnection fails repeatedly,
    /// try a new local port in case the old one is blocked by NAT/firewall.
    pub local_port: Option<u16>,
    /// Connect mode (initiate or respond).
    pub connect_mode: ConnectMode,
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
            max_idle_timeout: IDLE_TIMEOUT,
            session_data: None,
            // Mosh-style: use random port from 60001-60999 range
            local_port: Some(random_local_port()),
            connect_mode: ConnectMode::Initiate,
        }
    }
}

impl ConnectionConfig {
    /// Convert ConnectionConfig to HandshakeConfig for the shared handshake helpers.
    fn to_handshake_config(&self, resume_session: Option<SessionId>) -> HandshakeConfig {
        HandshakeConfig {
            connect_mode: self.connect_mode,
            session_key: self.session_key,
            capabilities: Capabilities {
                predictive_echo: self.predictive_echo,
                compression: false,
                max_forwards: DEFAULT_MAX_FORWARDS,
                tunnel: false,
            },
            term_size: self.term_size,
            term_type: self.term_type.clone(),
            env: self.env.clone(),
            predictive_echo: self.predictive_echo,
            resume_session,
        }
    }
}

/// Establish a raw QUIC connection using the provided configuration.
///
/// This performs the QUIC/TLS handshake but does not send qsh protocol
/// messages. Used by `ChannelConnection::connect()` and standalone authentication.
///
/// If `config.session_data` is provided, attempts 0-RTT session resumption
/// for faster reconnection.
pub async fn establish_quic_connection(config: &ConnectionConfig) -> Result<QuicConnection> {
    // Convert client ConnectionConfig to transport ConnectConfig
    let transport_config = ConnectConfig {
        server_addr: config.server_addr,
        local_port: config.local_port,
        max_idle_timeout: config.max_idle_timeout,
        connect_timeout: config.connect_timeout,
        cert_hash: config.cert_hash.clone(),
        session_data: config.session_data.clone(),
        // For normal client mode, QUIC client = logical client
        logical_role: qsh_core::transport::EndpointRole::Client,
    };

    // Use the backend-agnostic connect_quic from transport module
    let result = connect_quic(&transport_config).await?;

    Ok(result.connection)
}

// NOTE: ClientConnection has been removed. Use ChannelConnection instead.
// The channel model supports multiple terminals, file transfers, and forwards
// on a single connection via explicit channel opening.

// =============================================================================
// Channel-Model Connection (SSH-style multiplexing)
// =============================================================================

use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;

use qsh_core::protocol::{
    ChannelAcceptData, ChannelAcceptPayload, ChannelClosePayload, ChannelCloseReason, ChannelId,
    ChannelOpenPayload, ChannelParams, ChannelRejectCode, ChannelRejectPayload, DirectTcpIpParams,
    DynamicForwardParams, FileTransferParams, ForwardedTcpIpParams, GlobalReplyData,
    GlobalReplyResult, GlobalRequest, GlobalRequestPayload, TerminalParams,
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
    #[allow(dead_code)]
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
    pub(crate) pending_global_requests:
        tokio::sync::Mutex<StdHashMap<u32, tokio::sync::oneshot::Sender<GlobalReplyResult>>>,
    /// Next global request ID.
    next_global_request_id: std::sync::atomic::AtomicU32,
    /// Pending channel accepts (for open_dynamic, open_direct_tcpip).
    pub(crate) pending_channel_accepts: tokio::sync::Mutex<
        StdHashMap<ChannelId, tokio::sync::oneshot::Sender<Result<ChannelAcceptData>>>,
    >,
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
        let conn = establish_quic_connection(&config).await?;
        Self::from_quic(conn, config).await
    }

    /// Complete the qsh protocol handshake on an existing QUIC connection.
    pub async fn from_quic(conn: QuicConnection, config: ConnectionConfig) -> Result<Self> {
        Self::from_quic_with_resume(conn, config, None).await
    }

    /// Reconnect to an existing session using the session ID.
    ///
    /// This is used for transparent reconnection after network interruption.
    /// The server will resume the existing session if it's still valid.
    pub async fn reconnect(config: ConnectionConfig, session_id: SessionId) -> Result<Self> {
        info!(addr = %config.server_addr, ?session_id, "Reconnecting (channel model)");
        let conn = establish_quic_connection(&config).await?;
        Self::from_quic_with_resume(conn, config, Some(session_id)).await
    }

    /// Complete the qsh protocol handshake with optional session resumption.
    async fn from_quic_with_resume(
        conn: QuicConnection,
        config: ConnectionConfig,
        resume_session: Option<SessionId>,
    ) -> Result<Self> {
        info!(
            resume = resume_session.is_some(),
            connect_mode = ?config.connect_mode,
            "QUIC connection established (channel model)"
        );
        let quic = Arc::new(conn);

        // Open or accept control stream based on connect mode
        let mut control = match config.connect_mode {
            ConnectMode::Initiate => {
                // Initiator opens the control stream
                quic.open_stream(qsh_core::transport::StreamType::Control)
                    .await?
            }
            ConnectMode::Respond => {
                // Responder accepts the control stream opened by initiator
                let (stream_type, stream) = quic.accept_stream().await?;
                if !matches!(stream_type, qsh_core::transport::StreamType::Control) {
                    return Err(Error::Protocol {
                        message: format!("expected Control stream, got {:?}", stream_type),
                    });
                }
                stream
            }
        };

        // Perform handshake based on connect mode
        let handshake_config = config.to_handshake_config(resume_session);
        let handshake_result = match config.connect_mode {
            ConnectMode::Initiate => handshake_initiate(&mut control, &handshake_config).await?,
            ConnectMode::Respond => {
                handshake_respond(&mut control, &handshake_config, None).await?
            }
        };

        let has_existing = !handshake_result.existing_channels.is_empty();
        info!(
            session_id = ?handshake_result.session_id,
            existing_channels = handshake_result.existing_channels.len(),
            "Session established"
        );

        // Extract sender before wrapping in Mutex (allows concurrent send/recv)
        let control_sender = control
            .sender()
            .expect("control stream must support sending");

        // Restore existing channels if this is a session resume
        let mut channels = StdHashMap::new();
        for existing in handshake_result.existing_channels {
            use qsh_core::protocol::ExistingChannelType;
            match existing.channel_type {
                ExistingChannelType::Terminal { state } => {
                    info!(
                        channel_id = %existing.channel_id,
                        "Restoring terminal channel from session resume"
                    );

                    // Open input stream to send keystrokes
                    let input_stream = quic
                        .open_stream(StreamType::ChannelIn(existing.channel_id))
                        .await
                        .map_err(|e| Error::Transport {
                            message: format!(
                                "failed to open input stream for restored channel: {}",
                                e
                            ),
                        })?;

                    // Accept output stream from server (any direction)
                    let (_stream_type, output_stream) = loop {
                        let (ty, stream) = quic.accept_stream().await?;
                        match ty {
                            StreamType::ChannelOut(id) if id == existing.channel_id => {
                                break (ty, stream);
                            }
                            StreamType::ChannelIn(id) if id == existing.channel_id => {
                                break (ty, stream);
                            }
                            StreamType::ChannelBidi(id) if id == existing.channel_id => {
                                break (ty, stream);
                            }
                            other => {
                                debug!(?other, "Ignoring stream while restoring terminal output")
                            }
                        }
                    };

                    // Create restored terminal channel
                    let terminal = TerminalChannel::restore(
                        existing.channel_id,
                        input_stream,
                        output_stream,
                        state,
                    );
                    channels.insert(existing.channel_id, ChannelHandle::Terminal(terminal));
                }
                ExistingChannelType::Other => {
                    // Non-terminal channels are not restored for now
                    debug!(
                        channel_id = %existing.channel_id,
                        "Skipping non-terminal existing channel"
                    );
                }
            }
        }

        if has_existing {
            info!(
                restored_channels = channels.len(),
                "Session channels restored"
            );
        }

        Ok(Self {
            quic,
            control: tokio::sync::Mutex::new(control),
            control_sender,
            config,
            session_id: handshake_result.session_id,
            server_caps: handshake_result.capabilities,
            channels: RwLock::new(channels),
            next_channel_id: AtomicU64::new(0),
            pending_global_requests: tokio::sync::Mutex::new(StdHashMap::new()),
            next_global_request_id: std::sync::atomic::AtomicU32::new(0),
            pending_channel_accepts: tokio::sync::Mutex::new(StdHashMap::new()),
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
    pub async fn rtt(&self) -> Duration {
        self.quic.rtt().await
    }

    /// Check if there are any restored channels from session resumption.
    pub async fn has_restored_channels(&self) -> bool {
        !self.channels.read().await.is_empty()
    }

    /// Get the first restored terminal channel (for mosh-style reconnection).
    ///
    /// Returns the terminal channel if one was restored during session resumption.
    /// This should be called instead of `open_terminal()` when reconnecting.
    pub async fn get_restored_terminal(&self) -> Option<TerminalChannel> {
        let channels = self.channels.read().await;
        for handle in channels.values() {
            if let ChannelHandle::Terminal(terminal) = handle {
                return Some(terminal.clone());
            }
        }
        None
    }

    /// Allocate a new client-side channel ID.
    fn allocate_channel_id(&self) -> ChannelId {
        let id = self.next_channel_id.fetch_add(1, Ordering::SeqCst);
        ChannelId::client(id)
    }

    /// Wait for a ChannelAccept or ChannelReject for the given channel ID.
    ///
    /// Reads control messages until the expected response arrives.
    /// Other messages are dispatched to their respective handlers.
    async fn wait_for_channel_accept(&self, channel_id: ChannelId) -> Result<ChannelAcceptData> {
        let mut control = self.control.lock().await;
        loop {
            let msg = control.recv().await?;
            match msg {
                Message::ChannelAccept(accept) if accept.channel_id == channel_id => {
                    return Ok(accept.data);
                }
                Message::ChannelReject(reject) if reject.channel_id == channel_id => {
                    return Err(Error::Protocol {
                        message: format!("Channel rejected: {}", reject.message),
                    });
                }
                Message::ChannelAccept(accept) => {
                    // Different channel - dispatch to pending accepts
                    if let Some(tx) = self
                        .pending_channel_accepts
                        .lock()
                        .await
                        .remove(&accept.channel_id)
                    {
                        let _ = tx.send(Ok(accept.data));
                    }
                }
                Message::ChannelReject(reject) => {
                    // Different channel - dispatch to pending accepts
                    if let Some(tx) = self
                        .pending_channel_accepts
                        .lock()
                        .await
                        .remove(&reject.channel_id)
                    {
                        let _ = tx.send(Err(Error::Protocol {
                            message: format!("Channel rejected: {}", reject.message),
                        }));
                    }
                }
                Message::GlobalReply(reply) => {
                    // Dispatch to pending global requests
                    if let Some(tx) = self
                        .pending_global_requests
                        .lock()
                        .await
                        .remove(&reply.request_id)
                    {
                        let _ = tx.send(reply.result);
                    }
                }
                Message::Heartbeat(_) => {
                    // Ignore heartbeats during channel open
                    // The Session event loop will handle them later
                }
                other => {
                    debug!(
                        ?other,
                        "Ignoring control message while waiting for ChannelAccept"
                    );
                }
            }
        }
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

        // Wait for ChannelAccept or ChannelReject by reading control messages
        // This is necessary because the Session event loop hasn't started yet
        let accept_data = self.wait_for_channel_accept(channel_id).await?;

        // Open input/output streams
        let input_stream = self
            .quic
            .open_stream(StreamType::ChannelIn(channel_id))
            .await?;

        // Accept output stream from server.
        // In reverse-initiate flows the server may send ChannelIn (direction flipped),
        // so accept either ChannelOut or ChannelIn for this channel.
        let output_stream = loop {
            let (ty, stream) = self.quic.accept_stream().await?;
            match ty {
                StreamType::ChannelOut(id) if id == channel_id => break stream,
                StreamType::ChannelIn(id) if id == channel_id => break stream,
                StreamType::ChannelBidi(id) if id == channel_id => break stream,
                other => {
                    debug!(?other, "Ignoring stream while waiting for terminal output");
                }
            }
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
        let accept_data = self.wait_for_channel_accept(channel_id).await?;

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
        let _accept_data = self.wait_for_channel_accept(channel_id).await?;

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

        // Register oneshot channel BEFORE sending ChannelOpen (avoid race)
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.pending_channel_accepts
            .lock()
            .await
            .insert(channel_id, tx);

        // Send ChannelOpen
        let open = ChannelOpenPayload {
            channel_id,
            params: ChannelParams::DynamicForward(params),
        };
        self.send_control(&Message::ChannelOpen(open)).await?;

        // Wait for ChannelAccept
        let _accept_data = match rx.await {
            Ok(Ok(data)) => data,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(qsh_core::Error::Protocol {
                    message: format!("Channel accept sender dropped for {:?}", channel_id),
                });
            }
        };

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

    /// Send a global request and wait for the reply.
    ///
    /// Handles request ID allocation, sending, and waiting for the matching response.
    async fn send_global_request(&self, request: GlobalRequest) -> Result<GlobalReplyResult> {
        let request_id = self
            .next_global_request_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        // Register oneshot channel BEFORE sending the request (avoid race)
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.pending_global_requests
            .lock()
            .await
            .insert(request_id, tx);

        let payload = GlobalRequestPayload {
            request_id,
            request,
        };

        // Send the request (using control_sender to avoid locking recv)
        self.control_sender
            .send(&Message::GlobalRequest(payload))
            .await?;

        // Wait for the reply (will be sent by Session::run() event loop)
        match rx.await {
            Ok(result) => Ok(result),
            Err(_) => Err(qsh_core::Error::Protocol {
                message: format!(
                    "Global request sender dropped for request_id {}",
                    request_id
                ),
            }),
        }
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
        let result = self
            .send_global_request(GlobalRequest::TcpIpForward {
                bind_host: bind_host.to_string(),
                bind_port,
            })
            .await?;

        // Extract the actual bound port from the result
        let actual_port = match &result {
            GlobalReplyResult::Success(GlobalReplyData::TcpIpForward { bound_port }) => *bound_port,
            GlobalReplyResult::Success(_) => bind_port, // Fallback to requested port
            GlobalReplyResult::Failure { message } => {
                return Err(Error::Forward {
                    message: message.clone(),
                });
            }
        };

        // Store the target info so we can connect when the server notifies us
        self.remote_forwards.write().await.insert(
            (bind_host.to_string(), actual_port),
            RemoteForwardTarget {
                target_host: target_host.to_string(),
                target_port,
            },
        );
        info!(
            bind_host,
            bind_port, actual_port, target_host, target_port, "Remote forward established"
        );
        Ok(actual_port)
    }

    /// Cancel a remote port forward.
    pub async fn cancel_remote_forward(&self, bind_host: &str, bind_port: u16) -> Result<()> {
        let result = self
            .send_global_request(GlobalRequest::CancelTcpIpForward {
                bind_host: bind_host.to_string(),
                bind_port,
            })
            .await?;

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
            debug!(
                ?ty,
                "Ignoring stream while waiting for forwarded channel bidi"
            );
        };

        // Spawn relay tasks directly - no need for ForwardChannel wrapper
        Self::spawn_forwarded_relay(channel_id, tcp_stream, quic_stream);

        info!(?channel_id, "Forwarded channel relay started");
        Ok(())
    }

    /// Spawn bidirectional relay tasks for a forwarded-tcpip channel.
    fn spawn_forwarded_relay(
        channel_id: ChannelId,
        tcp_stream: TcpStream,
        quic_stream: QuicStream,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();
        let quic_sender = quic_stream
            .sender()
            .expect("forward stream must support sending");

        // Task: TCP -> QUIC
        tokio::spawn(async move {
            let mut buf = vec![0u8; FORWARD_BUFFER_SIZE];
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
            let mut buf = vec![0u8; FORWARD_BUFFER_SIZE];
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
#[allow(dead_code)]
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
}
