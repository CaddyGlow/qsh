//! Connection-level handler for qsh server.
//!
//! Manages a single QUIC connection with multiplexed channels.
//! This is the SSH-style channel model implementation for qsh.

mod channels;
mod config;
mod forwards;
mod handler;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use tokio::sync::{Mutex, RwLock, mpsc, oneshot};

use qsh_core::error::Result;
use qsh_core::protocol::SessionId;
use qsh_core::terminal::TerminalState;
use qsh_core::transport::{Connection, QuicConnection, QuicSender, QuicStream};
use qsh_core::ConnectMode;

use crate::channel::ChannelHandle;

// Re-exports
pub use channels::ChannelCounts;
pub use config::ConnectionConfig;
use forwards::RemoteForwardListener;

// =============================================================================
// Shutdown Reason
// =============================================================================

/// Reason for session shutdown signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownReason {
    /// Registry/server shutdown - close everything.
    RegistryShutdown,
    /// All channels closed (e.g., shell exited) - close everything.
    AllChannelsClosed,
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
    channels: RwLock<HashMap<qsh_core::protocol::ChannelId, ChannelHandle>>,
    /// Next server-assigned channel ID.
    next_server_channel_id: std::sync::atomic::AtomicU64,
    /// Connection configuration.
    config: ConnectionConfig,
    /// Session ID for this connection.
    session_id: SessionId,
    /// Pending global requests awaiting reply (request_id -> reply sender).
    #[allow(dead_code)]
    pending_global_requests:
        Mutex<HashMap<u32, oneshot::Sender<qsh_core::protocol::GlobalReplyResult>>>,
    /// Next global request ID.
    #[allow(dead_code)]
    next_global_request_id: std::sync::atomic::AtomicU32,
    /// Pending server-initiated channel opens awaiting accept/reject.
    pending_channel_opens:
        Mutex<HashMap<qsh_core::protocol::ChannelId, oneshot::Sender<Result<()>>>>,
    /// Remote forward listeners (bind_host:bind_port -> listener handle).
    remote_forward_listeners: Mutex<HashMap<(String, u16), RemoteForwardListener>>,
    /// Channel for signaling connection shutdown with reason.
    shutdown_tx: Mutex<mpsc::Sender<ShutdownReason>>,
    /// Last activity timestamp.
    last_activity: Mutex<Instant>,
}

impl ConnectionHandler {
    /// Create a new connection handler.
    pub fn new(
        quic: QuicConnection,
        control: QuicStream,
        session_id: SessionId,
        config: ConnectionConfig,
    ) -> (Arc<Self>, mpsc::Receiver<ShutdownReason>) {
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        // Extract sender before wrapping stream - allows concurrent send/recv
        // The control stream is always bidirectional, so sender() should return Some
        let control_sender = control
            .sender()
            .expect("control stream must support sending");

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

    /// Signal connection shutdown.
    pub async fn shutdown(&self) {
        use qsh_core::protocol::ChannelCloseReason;

        let _ = self
            .shutdown_tx
            .lock()
            .await
            .send(ShutdownReason::RegistryShutdown)
            .await;

        // Shutdown all remote forward listeners
        self.shutdown_remote_forward_listeners().await;

        self.close_all_channels(ChannelCloseReason::ConnectionClosed)
            .await;
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
/// - Connect mode (must stay consistent across reconnections)
/// - Terminal states that can be resumed
pub struct ConnectionSession {
    /// Session ID.
    pub session_id: SessionId,
    /// Session key (32 bytes, for authentication).
    pub session_key: [u8; 32],
    /// Connect mode established during initial connection.
    /// This must remain consistent across reconnections.
    pub connect_mode: ConnectMode,
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
    pub fn new(session_key: [u8; 32], client_addr: SocketAddr, connect_mode: ConnectMode) -> Self {
        Self {
            session_id: SessionId::new(),
            session_key,
            connect_mode,
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
        self.terminal_states
            .write()
            .await
            .insert(channel_seq, state);
    }

    /// Get saved terminal state.
    pub async fn get_terminal_state(&self, channel_seq: u64) -> Option<TerminalState> {
        self.terminal_states.read().await.get(&channel_seq).cloned()
    }
}
