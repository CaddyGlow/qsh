//! Connection-level handler for qsh server.
//!
//! Manages a single QUIC connection with multiplexed channels.
//! This is the SSH-style channel model implementation for qsh.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, RwLock, mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use qsh_core::constants::{
    DEFAULT_IDLE_TIMEOUT_SECS, DEFAULT_LINGER_TIMEOUT_SECS, DEFAULT_MAX_CHANNELS,
    DEFAULT_MAX_FILE_TRANSFERS, DEFAULT_MAX_FORWARDS, DEFAULT_MAX_TERMINALS,
};
use qsh_core::error::{Error, Result};
use qsh_core::protocol::{
    ChannelAcceptData, ChannelAcceptPayload, ChannelClosePayload, ChannelCloseReason, ChannelId,
    ChannelOpenPayload, ChannelParams, ChannelRejectCode, ChannelRejectPayload,
    GlobalReplyData, GlobalReplyPayload, GlobalReplyResult, GlobalRequest, GlobalRequestPayload,
    Message, ResizePayload, SessionId, StateAckPayload,
};
use qsh_core::terminal::TerminalState;
use qsh_core::transport::{Connection, QuicConnection, QuicSender, QuicStream, StreamPair, StreamType};

use crate::channel::{ChannelHandle, FileTransferChannel, ForwardChannel, TerminalChannel};

// =============================================================================
// Connection Configuration
// =============================================================================

/// Configuration for connection-level limits.
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    /// Maximum total channels per connection.
    pub max_channels: usize,
    /// Maximum terminal channels per connection.
    pub max_terminals: usize,
    /// Maximum port forward channels per connection.
    pub max_forwards: u16,
    /// Maximum file transfer channels per connection.
    pub max_file_transfers: usize,
    /// Allow remote port forwards (-R).
    pub allow_remote_forwards: bool,
    /// Session linger timeout (keep PTY alive after disconnect).
    pub linger_timeout: Duration,
    /// Idle timeout for channels.
    pub idle_timeout: Duration,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            max_channels: DEFAULT_MAX_CHANNELS,
            max_terminals: DEFAULT_MAX_TERMINALS,
            max_forwards: DEFAULT_MAX_FORWARDS,
            max_file_transfers: DEFAULT_MAX_FILE_TRANSFERS,
            allow_remote_forwards: false,
            linger_timeout: Duration::from_secs(DEFAULT_LINGER_TIMEOUT_SECS),
            idle_timeout: Duration::from_secs(DEFAULT_IDLE_TIMEOUT_SECS),
        }
    }
}

// =============================================================================
// Connection Handler
// =============================================================================

/// Handles a single QUIC connection with multiplexed channels.
///
/// This implements the SSH-style channel model where:
/// - Hello/HelloAck establishes the authenticated connection
/// - Either side sends ChannelOpen to create any resource
/// - Receiver responds with ChannelAccept or ChannelReject
/// - Either side can send ChannelClose to tear down a channel
///
/// Supports mosh-style reconnection: when a client reconnects, the QUIC
/// connection and control stream can be swapped while keeping channels
/// (and their PTYs) alive.
pub struct ConnectionHandler {
    /// Underlying QUIC connection (swappable for reconnection).
    quic: RwLock<Arc<QuicConnection>>,
    /// Control stream for lifecycle messages (recv side).
    control: Mutex<QuicStream>,
    /// Control stream sender (swappable for reconnection).
    control_sender: RwLock<QuicSender>,
    /// Active channels keyed by ChannelId.
    channels: RwLock<HashMap<ChannelId, ChannelHandle>>,
    /// Next server-assigned channel ID.
    next_server_channel_id: std::sync::atomic::AtomicU64,
    /// Connection configuration.
    config: ConnectionConfig,
    /// Session ID for this connection.
    session_id: SessionId,
    /// Pending global requests awaiting reply (request_id -> reply sender).
    pending_global_requests: Mutex<HashMap<u32, oneshot::Sender<GlobalReplyResult>>>,
    /// Next global request ID.
    next_global_request_id: std::sync::atomic::AtomicU32,
    /// Pending server-initiated channel opens awaiting accept/reject.
    pending_channel_opens: Mutex<HashMap<ChannelId, oneshot::Sender<Result<()>>>>,
    /// Remote forward listeners (bind_host:bind_port -> listener handle).
    remote_forward_listeners: Mutex<HashMap<(String, u16), RemoteForwardListener>>,
    /// Channel for signaling connection shutdown.
    shutdown_tx: Mutex<mpsc::Sender<()>>,
    /// Last activity timestamp.
    last_activity: Mutex<Instant>,
}

/// Handle for a remote forward listener on the server.
struct RemoteForwardListener {
    /// Task running the TCP listener accept loop.
    listener_task: JoinHandle<()>,
    /// Send to signal shutdown.
    shutdown_tx: mpsc::Sender<()>,
}

impl ConnectionHandler {
    /// Create a new connection handler.
    pub fn new(
        quic: QuicConnection,
        control: QuicStream,
        session_id: SessionId,
        config: ConnectionConfig,
    ) -> (Arc<Self>, mpsc::Receiver<()>) {
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        // Extract sender before wrapping stream - allows concurrent send/recv
        // The control stream is always bidirectional, so sender() should return Some
        let control_sender = control.sender().expect("control stream must support sending");

        let handler = Arc::new(Self {
            quic: RwLock::new(Arc::new(quic)),
            control: Mutex::new(control),
            control_sender: RwLock::new(control_sender),
            channels: RwLock::new(HashMap::new()),
            next_server_channel_id: std::sync::atomic::AtomicU64::new(0),
            config,
            session_id,
            pending_global_requests: Mutex::new(HashMap::new()),
            next_global_request_id: std::sync::atomic::AtomicU32::new(0),
            pending_channel_opens: Mutex::new(HashMap::new()),
            remote_forward_listeners: Mutex::new(HashMap::new()),
            shutdown_tx: Mutex::new(shutdown_tx),
            last_activity: Mutex::new(Instant::now()),
        });

        (handler, shutdown_rx)
    }

    /// Get the session ID.
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Get the remote peer address.
    pub async fn remote_addr(&self) -> SocketAddr {
        self.quic.read().await.remote_addr()
    }

    /// Get a clone of the underlying QUIC connection.
    pub async fn quic(&self) -> Arc<QuicConnection> {
        Arc::clone(&*self.quic.read().await)
    }

    /// Get the connection configuration.
    pub fn config(&self) -> &ConnectionConfig {
        &self.config
    }

    /// Get the current RTT estimate.
    pub async fn rtt(&self) -> Duration {
        self.quic.read().await.rtt().await
    }

    /// Update last activity timestamp.
    pub async fn touch(&self) {
        *self.last_activity.lock().await = Instant::now();
    }

    /// Get the idle duration.
    pub async fn idle_duration(&self) -> Duration {
        self.last_activity.lock().await.elapsed()
    }

    /// Reconnect to a new QUIC connection (mosh-style session resume).
    ///
    /// This updates the underlying QUIC connection and control stream while
    /// keeping all channels (and their PTYs) alive. Terminal channels will
    /// have their output streams reconnected to the new connection.
    pub async fn reconnect(
        &self,
        new_quic: QuicConnection,
        new_control: QuicStream,
        new_shutdown_tx: mpsc::Sender<()>,
    ) {
        let new_quic = Arc::new(new_quic);
        let new_control_sender = new_control.sender().expect("control stream must support sending");

        info!(
            session_id = ?self.session_id,
            new_addr = %new_quic.remote_addr(),
            "Reconnecting handler to new QUIC connection"
        );

        // Update the QUIC connection
        *self.quic.write().await = Arc::clone(&new_quic);

        // Update control stream
        *self.control.lock().await = new_control;
        *self.control_sender.write().await = new_control_sender;

        // Update shutdown channel
        *self.shutdown_tx.lock().await = new_shutdown_tx;

        // Update activity timestamp
        self.touch().await;

        // Reconnect all terminal channels' output streams
        let channels = self.channels.read().await;
        for (channel_id, handle) in channels.iter() {
            if let ChannelHandle::Terminal(terminal) = handle {
                if let Err(e) = terminal.reconnect_output(&new_quic).await {
                    warn!(
                        channel_id = %channel_id,
                        error = %e,
                        "Failed to reconnect terminal output stream"
                    );
                }
            }
        }

        info!(
            session_id = ?self.session_id,
            channel_count = channels.len(),
            "Handler reconnection complete"
        );
    }

    /// Allocate a new server-initiated channel ID.
    pub fn next_channel_id(&self) -> ChannelId {
        let id = self
            .next_server_channel_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        ChannelId::server(id)
    }

    /// Get the number of active channels.
    pub async fn channel_count(&self) -> usize {
        self.channels.read().await.len()
    }

    /// Count channels by type.
    pub async fn channel_counts(&self) -> ChannelCounts {
        let channels = self.channels.read().await;
        let mut counts = ChannelCounts::default();

        for handle in channels.values() {
            match handle {
                ChannelHandle::Terminal(_) => counts.terminals += 1,
                ChannelHandle::FileTransfer(_) => counts.file_transfers += 1,
                ChannelHandle::Forward(_) => counts.forwards += 1,
            }
        }

        counts
    }

    /// Get information about existing channels for session resumption.
    ///
    /// Returns channel info that can be sent to the client in HelloAck
    /// to restore channel state after reconnection.
    pub async fn get_existing_channels(
        &self,
    ) -> Vec<qsh_core::protocol::ExistingChannel> {
        use qsh_core::protocol::{ExistingChannel, ExistingChannelType};

        let channels = self.channels.read().await;
        let mut result = Vec::with_capacity(channels.len());

        for (channel_id, handle) in channels.iter() {
            let channel_type = match handle {
                ChannelHandle::Terminal(terminal) => {
                    // Get current terminal state
                    let state = {
                        let parser = terminal.parser();
                        let guard = parser.lock().await;
                        guard.state().clone()
                    };
                    ExistingChannelType::Terminal { state }
                }
                ChannelHandle::FileTransfer(_) | ChannelHandle::Forward(_) => {
                    ExistingChannelType::Other
                }
            };

            result.push(ExistingChannel {
                channel_id: *channel_id,
                channel_type,
            });
        }

        result
    }

    /// Send a message on the control stream.
    pub async fn send_control(&self, msg: &Message) -> Result<()> {
        self.touch().await;
        self.control_sender.read().await.send(msg).await
    }

    /// Receive a message from the control stream.
    pub async fn recv_control(&self) -> Result<Message> {
        self.touch().await;
        self.control.lock().await.recv().await
    }

    // =========================================================================
    // Channel Management
    // =========================================================================

    /// Handle a ChannelOpen request.
    pub async fn handle_channel_open(
        self: &Arc<Self>,
        payload: ChannelOpenPayload,
    ) -> Result<()> {
        let channel_id = payload.channel_id;
        debug!(
            channel_id = %channel_id,
            channel_type = %payload.params.channel_type(),
            "Received ChannelOpen request"
        );

        // Check if channel ID already exists
        {
            let channels = self.channels.read().await;
            if channels.contains_key(&channel_id) {
                return self
                    .send_channel_reject(
                        channel_id,
                        ChannelRejectCode::InvalidChannelId,
                        "channel ID already in use",
                    )
                    .await;
            }
        }

        // Check connection-level limits
        let counts = self.channel_counts().await;
        if counts.total() >= self.config.max_channels {
            return self
                .send_channel_reject(
                    channel_id,
                    ChannelRejectCode::ResourceShortage,
                    "max channels exceeded",
                )
                .await;
        }

        // Dispatch by channel type
        match payload.params {
            ChannelParams::Terminal(params) => {
                if counts.terminals >= self.config.max_terminals {
                    return self
                        .send_channel_reject(
                            channel_id,
                            ChannelRejectCode::ResourceShortage,
                            "max terminals exceeded",
                        )
                        .await;
                }
                self.open_terminal_channel(channel_id, params).await
            }
            ChannelParams::FileTransfer(params) => {
                if counts.file_transfers >= self.config.max_file_transfers {
                    return self
                        .send_channel_reject(
                            channel_id,
                            ChannelRejectCode::ResourceShortage,
                            "max file transfers exceeded",
                        )
                        .await;
                }
                self.open_file_transfer_channel(channel_id, params).await
            }
            ChannelParams::DirectTcpIp(params) => {
                if counts.forwards >= self.config.max_forwards as usize {
                    return self
                        .send_channel_reject(
                            channel_id,
                            ChannelRejectCode::ResourceShortage,
                            "max forwards exceeded",
                        )
                        .await;
                }
                self.open_direct_tcpip_channel(channel_id, params).await
            }
            ChannelParams::ForwardedTcpIp(_) => {
                // ForwardedTcpIp is server-initiated, should never come from client
                self.send_channel_reject(
                    channel_id,
                    ChannelRejectCode::UnknownChannelType,
                    "forwarded-tcpip is server-initiated only",
                )
                .await
            }
            ChannelParams::DynamicForward(params) => {
                if counts.forwards >= self.config.max_forwards as usize {
                    return self
                        .send_channel_reject(
                            channel_id,
                            ChannelRejectCode::ResourceShortage,
                            "max forwards exceeded",
                        )
                        .await;
                }
                self.open_dynamic_forward_channel(channel_id, params).await
            }
            #[cfg(feature = "tunnel")]
            ChannelParams::Tunnel(params) => {
                self.open_tunnel_channel(channel_id, params).await
            }
        }
    }

    /// Handle a ChannelClose request.
    pub async fn handle_channel_close(&self, payload: ChannelClosePayload) -> Result<()> {
        let channel_id = payload.channel_id;
        debug!(
            channel_id = %channel_id,
            reason = %payload.reason,
            "Received ChannelClose"
        );

        // Remove and get the channel
        let channel = {
            let mut channels = self.channels.write().await;
            channels.remove(&channel_id)
        };

        match channel {
            Some(handle) => {
                // Clean up channel resources
                handle.close().await;

                // Send close confirmation (SSH-style handshake)
                let confirm = Message::ChannelClose(ChannelClosePayload {
                    channel_id,
                    reason: ChannelCloseReason::Normal,
                });
                self.send_control(&confirm).await?;

                info!(channel_id = %channel_id, "Channel closed");
                Ok(())
            }
            None => {
                warn!(channel_id = %channel_id, "ChannelClose for unknown channel");
                Ok(())
            }
        }
    }

    /// Handle a ChannelAccept from the client (for server-initiated channels).
    pub async fn handle_channel_accept(&self, payload: ChannelAcceptPayload) -> Result<()> {
        let channel_id = payload.channel_id;
        debug!(channel_id = %channel_id, "Received ChannelAccept");

        // Notify waiting task
        if let Some(tx) = self.pending_channel_opens.lock().await.remove(&channel_id) {
            let _ = tx.send(Ok(()));
        } else {
            warn!(channel_id = %channel_id, "ChannelAccept for unknown pending channel");
        }

        Ok(())
    }

    /// Handle a ChannelReject from the client (for server-initiated channels).
    pub async fn handle_channel_reject(&self, payload: ChannelRejectPayload) -> Result<()> {
        let channel_id = payload.channel_id;
        debug!(
            channel_id = %channel_id,
            code = ?payload.code,
            message = %payload.message,
            "Received ChannelReject"
        );

        // Notify waiting task
        if let Some(tx) = self.pending_channel_opens.lock().await.remove(&channel_id) {
            let _ = tx.send(Err(Error::Forward {
                message: payload.message,
            }));
        } else {
            warn!(channel_id = %channel_id, "ChannelReject for unknown pending channel");
        }

        Ok(())
    }

    /// Handle a Resize message.
    pub async fn handle_resize(&self, payload: ResizePayload) -> Result<()> {
        let channel_id = match payload.channel_id {
            Some(id) => id,
            None => {
                // Legacy: resize applies to first terminal channel
                let channels = self.channels.read().await;
                if let Some((id, _)) = channels.iter().find(|(_, h)| matches!(h, ChannelHandle::Terminal(_))) {
                    *id
                } else {
                    warn!("Resize without channel_id and no terminal channels");
                    return Ok(());
                }
            }
        };

        let channels = self.channels.read().await;
        if let Some(ChannelHandle::Terminal(terminal)) = channels.get(&channel_id) {
            terminal.resize(payload.cols, payload.rows).await?;
        } else {
            warn!(channel_id = %channel_id, "Resize for non-terminal or unknown channel");
        }

        Ok(())
    }

    /// Handle a StateAck message.
    pub async fn handle_state_ack(&self, payload: StateAckPayload) -> Result<()> {
        let channel_id = match payload.channel_id {
            Some(id) => id,
            None => {
                // Legacy: ack applies to first terminal channel
                let channels = self.channels.read().await;
                if let Some((id, _)) = channels.iter().find(|(_, h)| matches!(h, ChannelHandle::Terminal(_))) {
                    *id
                } else {
                    return Ok(());
                }
            }
        };

        let channels = self.channels.read().await;
        if let Some(ChannelHandle::Terminal(terminal)) = channels.get(&channel_id) {
            terminal.handle_state_ack(payload.generation).await;
        }

        Ok(())
    }

    /// Send a ChannelReject message.
    pub async fn send_channel_reject(
        &self,
        channel_id: ChannelId,
        code: ChannelRejectCode,
        message: &str,
    ) -> Result<()> {
        let reject = Message::ChannelReject(ChannelRejectPayload {
            channel_id,
            code,
            message: message.to_string(),
        });
        self.send_control(&reject).await
    }

    /// Send a ChannelAccept message.
    pub async fn send_channel_accept(
        &self,
        channel_id: ChannelId,
        data: ChannelAcceptData,
    ) -> Result<()> {
        let accept = Message::ChannelAccept(ChannelAcceptPayload { channel_id, data });
        self.send_control(&accept).await
    }

    // =========================================================================
    // Channel Type Handlers (placeholders - will be implemented with channel structs)
    // =========================================================================

    async fn open_terminal_channel(
        self: &Arc<Self>,
        channel_id: ChannelId,
        params: qsh_core::protocol::TerminalParams,
    ) -> Result<()> {
        debug!(channel_id = %channel_id, "Opening terminal channel");

        // Create terminal channel
        let quic = self.quic().await;
        match TerminalChannel::new(
            channel_id,
            params,
            quic,
            Arc::clone(self),
        )
        .await
        {
            Ok((channel, initial_state)) => {
                // Register channel
                {
                    let mut channels = self.channels.write().await;
                    channels.insert(channel_id, ChannelHandle::Terminal(channel));
                }

                // Send accept with initial state
                self.send_channel_accept(
                    channel_id,
                    ChannelAcceptData::Terminal { initial_state },
                )
                .await
            }
            Err(e) => {
                error!(channel_id = %channel_id, error = %e, "Failed to create terminal channel");
                self.send_channel_reject(
                    channel_id,
                    ChannelRejectCode::InternalError,
                    &e.to_string(),
                )
                .await
            }
        }
    }

    async fn open_file_transfer_channel(
        self: &Arc<Self>,
        channel_id: ChannelId,
        params: qsh_core::protocol::FileTransferParams,
    ) -> Result<()> {
        debug!(channel_id = %channel_id, path = %params.path, "Opening file transfer channel");

        let quic = self.quic().await;
        match FileTransferChannel::new(channel_id, params, quic).await {
            Ok((channel, metadata)) => {
                {
                    let mut channels = self.channels.write().await;
                    channels.insert(channel_id, ChannelHandle::FileTransfer(channel));
                }

                self.send_channel_accept(
                    channel_id,
                    ChannelAcceptData::FileTransfer { metadata },
                )
                .await
            }
            Err(e) => {
                let code = match &e {
                    Error::FileTransfer { message } if message.contains("not found") => {
                        ChannelRejectCode::NotFound
                    }
                    Error::FileTransfer { message } if message.contains("permission") => {
                        ChannelRejectCode::PermissionDenied
                    }
                    _ => ChannelRejectCode::InternalError,
                };
                self.send_channel_reject(channel_id, code, &e.to_string())
                    .await
            }
        }
    }

    async fn open_direct_tcpip_channel(
        self: &Arc<Self>,
        channel_id: ChannelId,
        params: qsh_core::protocol::DirectTcpIpParams,
    ) -> Result<()> {
        debug!(
            channel_id = %channel_id,
            target = %format!("{}:{}", params.target_host, params.target_port),
            "Opening direct-tcpip channel"
        );

        let quic = self.quic().await;
        match ForwardChannel::new_direct(channel_id, params, quic).await {
            Ok(channel) => {
                {
                    let mut channels = self.channels.write().await;
                    channels.insert(channel_id, ChannelHandle::Forward(channel));
                }

                self.send_channel_accept(channel_id, ChannelAcceptData::DirectTcpIp)
                    .await
            }
            Err(e) => {
                self.send_channel_reject(
                    channel_id,
                    ChannelRejectCode::ConnectFailed,
                    &e.to_string(),
                )
                .await
            }
        }
    }

    async fn open_forwarded_tcpip_channel(
        self: &Arc<Self>,
        channel_id: ChannelId,
        params: qsh_core::protocol::ForwardedTcpIpParams,
        tcp_stream: TcpStream,
    ) -> Result<()> {
        debug!(
            channel_id = %channel_id,
            bound = %format!("{}:{}", params.bound_host, params.bound_port),
            originator = %format!("{}:{}", params.originator_host, params.originator_port),
            "Setting up forwarded-tcpip relay"
        );

        // Client already accepted - just set up the relay
        // Note: We don't send ChannelAccept here - for server-initiated channels,
        // the CLIENT sends ChannelAccept and we've already received it.
        let quic = self.quic().await;
        let channel =
            ForwardChannel::new_forwarded(channel_id, params, quic, tcp_stream)
                .await?;

        let mut channels = self.channels.write().await;
        channels.insert(channel_id, ChannelHandle::Forward(channel));

        info!(channel_id = %channel_id, "Forwarded channel relay started");
        Ok(())
    }

    async fn open_dynamic_forward_channel(
        self: &Arc<Self>,
        channel_id: ChannelId,
        params: qsh_core::protocol::DynamicForwardParams,
    ) -> Result<()> {
        debug!(
            channel_id = %channel_id,
            target = %format!("{}:{}", params.target_host, params.target_port),
            "Opening dynamic forward channel"
        );

        let quic = self.quic().await;
        match ForwardChannel::new_dynamic(channel_id, params, quic).await {
            Ok(channel) => {
                {
                    let mut channels = self.channels.write().await;
                    channels.insert(channel_id, ChannelHandle::Forward(channel));
                }

                self.send_channel_accept(channel_id, ChannelAcceptData::DynamicForward)
                    .await
            }
            Err(e) => {
                self.send_channel_reject(
                    channel_id,
                    ChannelRejectCode::ConnectFailed,
                    &e.to_string(),
                )
                .await
            }
        }
    }

    #[cfg(feature = "tunnel")]
    async fn open_tunnel_channel(
        self: &Arc<Self>,
        channel_id: ChannelId,
        _params: qsh_core::protocol::TunnelParams,
    ) -> Result<()> {
        // Tunnel channels are not yet implemented
        self.send_channel_reject(
            channel_id,
            ChannelRejectCode::UnknownChannelType,
            "tunnel channels not yet implemented",
        )
        .await
    }

    // =========================================================================
    // Global Request Handling
    // =========================================================================

    /// Handle a GlobalRequest message.
    pub async fn handle_global_request(
        self: &Arc<Self>,
        payload: GlobalRequestPayload,
    ) -> Result<()> {
        let request_id = payload.request_id;
        debug!(request_id, request = ?payload.request, "Received GlobalRequest");

        match payload.request {
            GlobalRequest::TcpIpForward {
                bind_host,
                bind_port,
            } => {
                if !self.config.allow_remote_forwards {
                    return self
                        .send_global_reply(
                            request_id,
                            GlobalReplyResult::Failure {
                                message: "remote forwards not allowed".to_string(),
                            },
                        )
                        .await;
                }

                // Check if we already have a listener for this address
                {
                    let listeners = self.remote_forward_listeners.lock().await;
                    if listeners.contains_key(&(bind_host.clone(), bind_port)) {
                        return self
                            .send_global_reply(
                                request_id,
                                GlobalReplyResult::Failure {
                                    message: "forward already exists".to_string(),
                                },
                            )
                            .await;
                    }
                }

                // Bind the TCP listener
                let bind_addr = if bind_host.is_empty() || bind_host == "0.0.0.0" {
                    format!("0.0.0.0:{}", bind_port)
                } else if bind_host == "localhost" {
                    format!("127.0.0.1:{}", bind_port)
                } else {
                    format!("{}:{}", bind_host, bind_port)
                };

                let listener = match TcpListener::bind(&bind_addr).await {
                    Ok(l) => l,
                    Err(e) => {
                        warn!(bind_addr = %bind_addr, error = %e, "Failed to bind remote forward");
                        return self
                            .send_global_reply(
                                request_id,
                                GlobalReplyResult::Failure {
                                    message: format!("failed to bind: {}", e),
                                },
                            )
                            .await;
                    }
                };

                let actual_port = listener.local_addr().map(|a| a.port()).unwrap_or(bind_port);
                info!(
                    bind_host = %bind_host,
                    requested_port = bind_port,
                    actual_port,
                    "Remote forward listener bound"
                );

                // Create shutdown channel and spawn listener task
                let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
                let handler = Arc::clone(self);
                let bind_host_clone = bind_host.clone();

                let listener_task = tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = shutdown_rx.recv() => {
                                debug!(bind_host = %bind_host_clone, port = actual_port, "Remote forward listener shutting down");
                                break;
                            }
                            result = listener.accept() => {
                                match result {
                                    Ok((tcp_stream, peer_addr)) => {
                                        debug!(
                                            peer = %peer_addr,
                                            bind_host = %bind_host_clone,
                                            bind_port = actual_port,
                                            "Accepted connection on remote forward"
                                        );

                                        // Allocate a server-side channel ID
                                        let channel_id = handler.next_channel_id();

                                        let params = qsh_core::protocol::ForwardedTcpIpParams {
                                            bound_host: bind_host_clone.clone(),
                                            bound_port: actual_port,
                                            originator_host: peer_addr.ip().to_string(),
                                            originator_port: peer_addr.port(),
                                        };

                                        // Send ChannelOpen to client and set up the forward
                                        let handler_clone = Arc::clone(&handler);
                                        tokio::spawn(async move {
                                            if let Err(e) = handler_clone
                                                .initiate_forwarded_channel(channel_id, params, tcp_stream)
                                                .await
                                            {
                                                warn!(
                                                    channel_id = %channel_id,
                                                    error = %e,
                                                    "Failed to initiate forwarded channel"
                                                );
                                            }
                                        });
                                    }
                                    Err(e) => {
                                        warn!(error = %e, "Error accepting connection on remote forward");
                                    }
                                }
                            }
                        }
                    }
                });

                // Store the listener handle
                {
                    let mut listeners = self.remote_forward_listeners.lock().await;
                    listeners.insert(
                        (bind_host, actual_port),
                        RemoteForwardListener {
                            listener_task,
                            shutdown_tx,
                        },
                    );
                }

                self.send_global_reply(
                    request_id,
                    GlobalReplyResult::Success(GlobalReplyData::TcpIpForward {
                        bound_port: actual_port,
                    }),
                )
                .await
            }
            GlobalRequest::CancelTcpIpForward {
                bind_host,
                bind_port,
            } => {
                let mut listeners = self.remote_forward_listeners.lock().await;
                if let Some(listener) = listeners.remove(&(bind_host.clone(), bind_port)) {
                    // Signal shutdown and abort the task
                    let _ = listener.shutdown_tx.send(()).await;
                    listener.listener_task.abort();
                    info!(bind_host = %bind_host, bind_port, "Remote forward cancelled");
                    self.send_global_reply(
                        request_id,
                        GlobalReplyResult::Success(GlobalReplyData::CancelTcpIpForward),
                    )
                    .await
                } else {
                    self.send_global_reply(
                        request_id,
                        GlobalReplyResult::Failure {
                            message: "no such forward".to_string(),
                        },
                    )
                    .await
                }
            }
        }
    }

    /// Initiate a forwarded-tcpip channel to the client.
    ///
    /// This sends ChannelOpen to the client and waits for accept/reject.
    async fn initiate_forwarded_channel(
        self: &Arc<Self>,
        channel_id: ChannelId,
        params: qsh_core::protocol::ForwardedTcpIpParams,
        tcp_stream: TcpStream,
    ) -> Result<()> {
        // Set up oneshot channel to receive accept/reject notification
        let (tx, rx) = oneshot::channel();
        self.pending_channel_opens
            .lock()
            .await
            .insert(channel_id, tx);

        // Send ChannelOpen to client (uses control_sender, doesn't block recv)
        let open_payload = ChannelOpenPayload {
            channel_id,
            params: ChannelParams::ForwardedTcpIp(params.clone()),
        };
        self.control_sender
            .read()
            .await
            .send(&Message::ChannelOpen(open_payload))
            .await?;
        debug!(channel_id = %channel_id, "Sent ChannelOpen for forwarded-tcpip, waiting for accept");

        // Wait for accept/reject (main loop will dispatch to us)
        match rx.await {
            Ok(Ok(())) => {
                debug!(channel_id = %channel_id, "Received ChannelAccept for forwarded-tcpip");
            }
            Ok(Err(e)) => {
                warn!(channel_id = %channel_id, error = %e, "Client rejected forwarded channel");
                return Err(e);
            }
            Err(_) => {
                warn!(channel_id = %channel_id, "Channel open cancelled");
                return Err(Error::ConnectionClosed);
            }
        }

        // Now set up the channel and start relay
        self.open_forwarded_tcpip_channel(channel_id, params, tcp_stream)
            .await
    }

    /// Send a GlobalReply message.
    async fn send_global_reply(
        &self,
        request_id: u32,
        result: GlobalReplyResult,
    ) -> Result<()> {
        let reply = Message::GlobalReply(GlobalReplyPayload { request_id, result });
        self.send_control(&reply).await
    }

    // =========================================================================
    // Stream Handling
    // =========================================================================

    /// Route an incoming stream to the appropriate channel.
    pub async fn handle_incoming_stream(
        &self,
        stream_type: StreamType,
        stream: QuicStream,
    ) -> Result<()> {
        match stream_type {
            StreamType::ChannelIn(channel_id) | StreamType::ChannelBidi(channel_id) => {
                let channels = self.channels.read().await;
                if let Some(handle) = channels.get(&channel_id) {
                    handle.handle_incoming_stream(stream).await
                } else {
                    warn!(channel_id = %channel_id, "Stream for unknown channel");
                    Err(Error::Protocol {
                        message: format!("unknown channel: {}", channel_id),
                    })
                }
            }
            StreamType::ChannelOut(channel_id) => {
                // Server doesn't expect to receive output streams from client
                warn!(channel_id = %channel_id, "Unexpected ChannelOut stream from client");
                Ok(())
            }
            StreamType::Control => {
                // Control stream is handled separately
                warn!("Unexpected additional control stream");
                Ok(())
            }
        }
    }

    // =========================================================================
    // Connection Lifecycle
    // =========================================================================

    /// Close all channels and clean up.
    pub async fn close_all_channels(&self, reason: ChannelCloseReason) {
        let channels: Vec<_> = {
            let mut guard = self.channels.write().await;
            guard.drain().collect()
        };

        for (channel_id, handle) in channels {
            debug!(channel_id = %channel_id, "Closing channel");
            handle.close().await;

            // Best-effort send close notification
            let _ = self
                .send_control(&Message::ChannelClose(ChannelClosePayload {
                    channel_id,
                    reason: reason.clone(),
                }))
                .await;
        }
    }

    /// Signal connection shutdown.
    pub async fn shutdown(&self) {
        let _ = self.shutdown_tx.lock().await.send(()).await;

        // Shutdown all remote forward listeners
        let listeners: Vec<_> = {
            let mut guard = self.remote_forward_listeners.lock().await;
            guard.drain().collect()
        };
        for ((host, port), listener) in listeners {
            debug!(bind_host = %host, bind_port = port, "Shutting down remote forward listener");
            let _ = listener.shutdown_tx.send(()).await;
            listener.listener_task.abort();
        }

        self.close_all_channels(ChannelCloseReason::ConnectionClosed)
            .await;
    }

    /// Get a terminal channel by ID (for legacy code paths).
    pub async fn get_terminal_channel(&self, channel_id: ChannelId) -> Option<TerminalChannel> {
        let channels = self.channels.read().await;
        if let Some(ChannelHandle::Terminal(terminal)) = channels.get(&channel_id) {
            Some(terminal.clone())
        } else {
            None
        }
    }

    /// Get the first terminal channel (for legacy code paths).
    pub async fn get_first_terminal_channel(&self) -> Option<(ChannelId, TerminalChannel)> {
        let channels = self.channels.read().await;
        for (id, handle) in channels.iter() {
            if let ChannelHandle::Terminal(terminal) = handle {
                return Some((*id, terminal.clone()));
            }
        }
        None
    }
}

// =============================================================================
// Channel Counts
// =============================================================================

/// Channel counts by type.
#[derive(Debug, Default, Clone, Copy)]
pub struct ChannelCounts {
    pub terminals: usize,
    pub file_transfers: usize,
    pub forwards: usize,
}

impl ChannelCounts {
    /// Total channel count.
    pub fn total(&self) -> usize {
        self.terminals + self.file_transfers + self.forwards
    }
}

// =============================================================================
// Connection Session
// =============================================================================

/// Logical session that persists across QUIC connection lifetimes.
///
/// This tracks session state for reconnection support:
/// - Session ID (opaque identifier)
/// - Session key (for authentication)
/// - Terminal states that can be resumed
pub struct ConnectionSession {
    /// Session ID.
    pub session_id: SessionId,
    /// Session key (32 bytes, for authentication).
    pub session_key: [u8; 32],
    /// When this session was created.
    pub created_at: SystemTime,
    /// Last activity timestamp.
    pub last_active_at: Mutex<SystemTime>,
    /// Client address (may change on reconnect).
    pub client_addr: Mutex<SocketAddr>,
    /// The current connection handler (None if disconnected but lingering).
    pub handler: Mutex<Option<Arc<ConnectionHandler>>>,
    /// Terminal states that can be resumed (channel_id -> state).
    pub terminal_states: RwLock<HashMap<u64, TerminalState>>,
}

impl ConnectionSession {
    /// Create a new session.
    pub fn new(session_key: [u8; 32], client_addr: SocketAddr) -> Self {
        Self {
            session_id: SessionId::new(),
            session_key,
            created_at: SystemTime::now(),
            last_active_at: Mutex::new(SystemTime::now()),
            client_addr: Mutex::new(client_addr),
            handler: Mutex::new(None),
            terminal_states: RwLock::new(HashMap::new()),
        }
    }

    /// Attach a connection handler to this session.
    pub async fn attach(&self, handler: Arc<ConnectionHandler>, addr: SocketAddr) {
        *self.handler.lock().await = Some(handler);
        *self.client_addr.lock().await = addr;
        *self.last_active_at.lock().await = SystemTime::now();
    }

    /// Detach the connection handler (client disconnected).
    pub async fn detach(&self) {
        *self.handler.lock().await = None;
    }

    /// Check if a handler is attached.
    pub async fn is_attached(&self) -> bool {
        self.handler.lock().await.is_some()
    }

    /// Update activity timestamp.
    pub async fn touch(&self) {
        *self.last_active_at.lock().await = SystemTime::now();
    }

    /// Get time since last activity.
    pub async fn idle_duration(&self) -> Duration {
        self.last_active_at
            .lock()
            .await
            .elapsed()
            .unwrap_or_default()
    }

    /// Save terminal state for reconnection.
    pub async fn save_terminal_state(&self, channel_seq: u64, state: TerminalState) {
        self.terminal_states.write().await.insert(channel_seq, state);
    }

    /// Get saved terminal state.
    pub async fn get_terminal_state(&self, channel_seq: u64) -> Option<TerminalState> {
        self.terminal_states.read().await.get(&channel_seq).cloned()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_config_default() {
        let config = ConnectionConfig::default();
        assert_eq!(config.max_channels, DEFAULT_MAX_CHANNELS);
        assert_eq!(config.max_terminals, DEFAULT_MAX_TERMINALS);
        assert_eq!(config.max_forwards, DEFAULT_MAX_FORWARDS);
        assert_eq!(config.max_file_transfers, DEFAULT_MAX_FILE_TRANSFERS);
        assert!(!config.allow_remote_forwards);
        assert_eq!(config.linger_timeout, Duration::from_secs(DEFAULT_LINGER_TIMEOUT_SECS));
        assert_eq!(config.idle_timeout, Duration::from_secs(DEFAULT_IDLE_TIMEOUT_SECS));
    }

    #[test]
    fn test_channel_counts() {
        let counts = ChannelCounts {
            terminals: 2,
            file_transfers: 3,
            forwards: 5,
        };
        assert_eq!(counts.total(), 10);
    }
}
