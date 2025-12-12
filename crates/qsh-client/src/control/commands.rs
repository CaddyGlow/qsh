//! Command types for internal session communication.
//!
//! This module provides command types used to communicate between
//! the control socket handlers and the session event loop.

use std::sync::Arc;
use std::time::Instant;

use tokio::sync::mpsc;

use crate::forward::ForwardRegistry;

/// Session state passed to command handlers.
///
/// This provides read-only access to session state for queries, and
/// channels for sending commands that modify state.
pub struct SessionState {
    /// Session name (e.g., "user@host" or explicit -S name).
    pub session_name: String,

    /// Remote host (if connected).
    pub remote_host: Option<String>,

    /// Remote user (if known).
    pub remote_user: Option<String>,

    /// Connection state.
    pub connection_state: ConnectionState,

    /// Server address (if connected).
    pub server_addr: Option<String>,

    /// Connection start time.
    pub connected_at: Option<Instant>,

    /// Forward registry for listing forwards.
    pub forward_registry: Arc<std::sync::Mutex<ForwardRegistry>>,

    /// Channel for sending forward add requests.
    pub forward_add_tx: Option<mpsc::Sender<ForwardAddCommand>>,

    /// Channel for sending forward remove requests.
    pub forward_remove_tx: Option<mpsc::Sender<String>>,

    /// Channel for sending terminal commands.
    pub terminal_cmd_tx: Option<mpsc::Sender<TerminalCommand>>,

    /// Current terminals (channel_id -> info).
    pub terminals: Vec<TerminalState>,

    /// RTT in milliseconds (if known).
    pub rtt_ms: Option<u32>,

    /// Bytes sent.
    pub bytes_sent: u64,

    /// Bytes received.
    pub bytes_received: u64,

    /// Resource manager for unified resource tracking.
    pub resource_manager: Option<Arc<super::ResourceManager>>,
}

/// Connection state enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Connected,
    Reconnecting,
    Disconnected,
}

impl ConnectionState {
    pub fn as_str(&self) -> &'static str {
        match self {
            ConnectionState::Connected => "connected",
            ConnectionState::Reconnecting => "reconnecting",
            ConnectionState::Disconnected => "disconnected",
        }
    }
}

/// Command to add a forward.
pub enum ForwardAddCommand {
    Local {
        bind_addr: Option<String>,
        bind_port: u32,
        dest_host: String,
        dest_port: u32,
        response_tx: tokio::sync::oneshot::Sender<Result<String, String>>,
    },
    Remote {
        bind_addr: Option<String>,
        bind_port: u32,
        dest_host: String,
        dest_port: u32,
        response_tx: tokio::sync::oneshot::Sender<Result<String, String>>,
    },
    Dynamic {
        bind_addr: Option<String>,
        bind_port: u32,
        response_tx: tokio::sync::oneshot::Sender<Result<String, String>>,
    },
}

/// I/O channels returned from terminal attach.
pub struct TerminalAttachChannels {
    /// Receiver for terminal output data
    pub output_rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    /// Sender for terminal input data
    pub input_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    /// Terminal size (cols, rows)
    pub cols: u32,
    pub rows: u32,
}

/// Command to control terminals.
pub enum TerminalCommand {
    Open {
        cols: u32,
        rows: u32,
        term_type: String,
        shell: Option<String>,
        command: Option<String>,
        response_tx: tokio::sync::oneshot::Sender<Result<u64, String>>,
    },
    Close {
        terminal_id: u64,
        response_tx: tokio::sync::oneshot::Sender<Result<Option<i32>, String>>,
    },
    Resize {
        terminal_id: u64,
        cols: u32,
        rows: u32,
        response_tx: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    /// Attach to a terminal for I/O streaming
    Attach {
        terminal_id: u64,
        response_tx: tokio::sync::oneshot::Sender<Result<TerminalAttachChannels, String>>,
    },
    /// Detach from a terminal
    Detach {
        terminal_id: u64,
        response_tx: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
}

/// Terminal state for tracking.
#[derive(Debug, Clone)]
pub struct TerminalState {
    pub terminal_id: u64,
    pub cols: u32,
    pub rows: u32,
    pub status: String,
    pub shell: Option<String>,
    pub pid: Option<u64>,
}

impl Default for SessionState {
    fn default() -> Self {
        Self {
            session_name: String::new(),
            remote_host: None,
            remote_user: None,
            connection_state: ConnectionState::Disconnected,
            server_addr: None,
            connected_at: None,
            forward_registry: Arc::new(std::sync::Mutex::new(ForwardRegistry::new())),
            forward_add_tx: None,
            forward_remove_tx: None,
            terminal_cmd_tx: None,
            terminals: Vec::new(),
            rtt_ms: None,
            bytes_sent: 0,
            bytes_received: 0,
            resource_manager: None,
        }
    }
}
