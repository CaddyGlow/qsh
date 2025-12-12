//! Terminal resource implementation for the control plane.
//!
//! This module provides the `Terminal` resource which wraps a PTY session
//! and integrates it with the unified resource control system.
//!
//! # Features
//!
//! - Raw Unix socket for I/O (no protobuf overhead)
//! - Any TTY client can connect (socat, nc, custom tools)
//! - Single attached client (MVP): only one client at a time
//! - Resize support via control socket commands
//! - Resume on reconnect (marks Failed if resume fails)
//! - Graceful drain and close
//!
//! # Architecture
//!
//! The Terminal resource manages:
//! - A TerminalChannel (input/output streams to the remote PTY)
//! - A Unix socket for raw I/O (e.g., /run/user/1000/qsh/session/term-0.io.sock)
//! - I/O bridging between socket clients and remote PTY
//! - Lifecycle tracking (start, running, draining, closed)

use std::any::Any;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::RwLock as StdRwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, warn};

use qsh_core::protocol::TerminalParams;

use crate::channel::TerminalChannel;
use crate::ChannelConnection;

use super::super::resource::{
    Resource, ResourceDetails, ResourceError, ResourceInfo, ResourceKind,
    ResourceState, ResourceStats, TerminalDetails as TerminalDetailsInfo,
};

/// Parser for CSI 8 (xterm window resize) sequences.
///
/// Parses `\x1b[8;<rows>;<cols>t` sequences from the input stream,
/// handling partial sequences across buffer boundaries.
///
/// This allows terminal emulators that report size via CSI 8 to
/// automatically trigger PTY resize when connected to the raw socket.
struct Csi8Parser {
    /// Buffer for partial sequence data
    partial: Vec<u8>,
    /// Current parse state
    state: Csi8State,
    /// Accumulated rows value (for partial sequences)
    rows: u32,
    /// Accumulated cols value (for partial sequences)
    cols: u32,
}

#[derive(Clone, Copy, PartialEq)]
enum Csi8State {
    /// Normal passthrough
    Normal,
    /// Saw ESC (\x1b)
    Escape,
    /// Saw ESC [
    Csi,
    /// Saw ESC [ 8
    Csi8,
    /// Parsing first parameter (rows)
    Rows,
    /// Parsing second parameter (cols)
    Cols,
}

impl Csi8Parser {
    fn new() -> Self {
        Self {
            partial: Vec::new(),
            state: Csi8State::Normal,
            rows: 0,
            cols: 0,
        }
    }

    /// Parse input, returning (filtered_output, resize_commands).
    ///
    /// filtered_output contains input with CSI 8 sequences removed.
    /// resize_commands contains (rows, cols) pairs for each detected resize.
    fn parse(&mut self, input: &[u8]) -> (Vec<u8>, Vec<(u32, u32)>) {
        let mut output = Vec::with_capacity(input.len());
        let mut resizes = Vec::new();

        for &byte in input {
            match self.state {
                Csi8State::Normal => {
                    if byte == 0x1b {
                        // Start of escape sequence
                        self.state = Csi8State::Escape;
                        self.partial.clear();
                        self.partial.push(byte);
                    } else {
                        output.push(byte);
                    }
                }
                Csi8State::Escape => {
                    self.partial.push(byte);
                    if byte == b'[' {
                        self.state = Csi8State::Csi;
                    } else {
                        // Not CSI, flush partial and continue
                        output.extend_from_slice(&self.partial);
                        self.state = Csi8State::Normal;
                    }
                }
                Csi8State::Csi => {
                    self.partial.push(byte);
                    if byte == b'8' {
                        self.state = Csi8State::Csi8;
                    } else {
                        // Not CSI 8, flush partial and continue
                        output.extend_from_slice(&self.partial);
                        self.state = Csi8State::Normal;
                    }
                }
                Csi8State::Csi8 => {
                    self.partial.push(byte);
                    if byte == b';' {
                        self.state = Csi8State::Rows;
                        self.rows = 0;
                    } else {
                        // Not CSI 8 ;, flush partial and continue
                        output.extend_from_slice(&self.partial);
                        self.state = Csi8State::Normal;
                    }
                }
                Csi8State::Rows => {
                    self.partial.push(byte);
                    if byte.is_ascii_digit() {
                        self.rows = self.rows * 10 + (byte - b'0') as u32;
                    } else if byte == b';' {
                        self.state = Csi8State::Cols;
                        self.cols = 0;
                    } else {
                        // Invalid, flush partial
                        output.extend_from_slice(&self.partial);
                        self.state = Csi8State::Normal;
                    }
                }
                Csi8State::Cols => {
                    self.partial.push(byte);
                    if byte.is_ascii_digit() {
                        self.cols = self.cols * 10 + (byte - b'0') as u32;
                    } else if byte == b't' {
                        // Complete CSI 8 sequence - record resize, don't output
                        if self.rows > 0 && self.cols > 0 {
                            resizes.push((self.rows, self.cols));
                        }
                        self.state = Csi8State::Normal;
                    } else {
                        // Invalid, flush partial
                        output.extend_from_slice(&self.partial);
                        self.state = Csi8State::Normal;
                    }
                }
            }
        }

        // If we're mid-sequence at end of buffer, keep state for next parse call
        // Don't flush partial yet - wait for more data

        (output, resizes)
    }

    /// Flush any remaining partial sequence as output.
    ///
    /// Call this when the connection is closing to avoid losing data.
    #[allow(dead_code)]
    fn flush(&mut self) -> Vec<u8> {
        let result = std::mem::take(&mut self.partial);
        self.state = Csi8State::Normal;
        self.rows = 0;
        self.cols = 0;
        result
    }
}

/// Terminal resource wrapping a remote PTY session.
///
/// This resource:
/// - Opens a terminal channel on the remote server
/// - Creates a Unix socket for raw I/O
/// - Bridges socket clients directly to the remote PTY
/// - Supports resize and graceful shutdown
pub struct Terminal {
    /// Resource ID (e.g., "term-0").
    id: String,
    /// Current lifecycle state.
    state: ResourceState,
    /// Resource statistics.
    stats: ResourceStats,
    /// Terminal configuration.
    params: TerminalParams,
    /// The underlying terminal channel (set after start()).
    channel: RwLock<Option<TerminalChannel>>,
    /// Connection for sending control messages (set after start()).
    connection: RwLock<Option<Arc<ChannelConnection>>>,
    /// Current terminal size (uses std lock for sync access in describe).
    term_size: StdRwLock<(u32, u32)>,
    /// Path to the I/O socket (uses std mutex for sync access in describe).
    io_socket_path: StdMutex<Option<PathBuf>>,
    /// I/O socket listener task handle.
    io_listener_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Currently attached client's I/O task handle.
    io_client_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Session directory for socket files.
    session_dir: Mutex<Option<PathBuf>>,
    /// Whether a client is currently attached (sync-safe flag for describe()).
    attached: Arc<AtomicBool>,
}


impl Terminal {
    /// Create a new terminal resource with the given parameters.
    ///
    /// The terminal is created in Pending state and must be started
    /// via the Resource::start() method.
    pub fn new(id: String, params: TerminalParams) -> Self {
        let (cols, rows) = (params.term_size.cols as u32, params.term_size.rows as u32);

        Self {
            id,
            state: ResourceState::Pending,
            stats: ResourceStats::new(),
            params,
            channel: RwLock::new(None),
            connection: RwLock::new(None),
            term_size: StdRwLock::new((cols, rows)),
            io_socket_path: StdMutex::new(None),
            io_listener_task: Mutex::new(None),
            io_client_task: Mutex::new(None),
            session_dir: Mutex::new(None),
            attached: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Create a terminal resource from CLI parameters.
    pub fn from_params(
        id: String,
        cols: Option<u32>,
        rows: Option<u32>,
        term_type: Option<String>,
        shell: Option<String>,
        command: Option<String>,
        env: Vec<(String, String)>,
        output_mode: qsh_core::protocol::OutputMode,
        allocate_pty: bool,
    ) -> Self {
        use qsh_core::protocol::TermSize;

        let cols = cols.unwrap_or(80) as u16;
        let rows = rows.unwrap_or(24) as u16;
        let term_type = term_type.unwrap_or_else(|| "xterm-256color".to_string());

        let params = TerminalParams {
            term_size: TermSize { cols, rows },
            term_type,
            shell,
            command,
            env,
            output_mode,
            allocate_pty,
            ..Default::default()
        };

        Self::new(id, params)
    }

    /// Set the terminal ID.
    ///
    /// This is used when the ID is assigned after creation (e.g., by ResourceManager).
    pub fn set_id(&mut self, id: String) {
        self.id = id;
    }

    /// Set the session directory where I/O sockets will be created.
    pub async fn set_session_dir(&self, dir: PathBuf) {
        *self.session_dir.lock().await = Some(dir);
    }

    /// Get the path to the I/O socket.
    ///
    /// Returns None if the terminal hasn't been started yet.
    pub fn io_socket_path(&self) -> Option<PathBuf> {
        self.io_socket_path.lock().unwrap().clone()
    }

    /// Resize the terminal.
    pub async fn resize(&self, cols: u32, rows: u32) -> Result<(), ResourceError> {
        if !self.state.is_running() {
            return Err(ResourceError::InvalidState {
                current: self.state.clone(),
                expected: "running",
            });
        }

        // Update size tracking
        *self.term_size.write().unwrap() = (cols, rows);

        // Send resize to remote PTY
        let channel = self.channel.read().await;
        let connection = self.connection.read().await;

        if let (Some(ch), Some(conn)) = (&*channel, &*connection) {
            let channel_id = ch.channel_id();
            if let Err(e) = conn.send_resize(channel_id, cols as u16, rows as u16).await {
                warn!(terminal_id = %self.id, error = %e, "Failed to send resize to remote PTY");
                return Err(ResourceError::Internal(format!("resize failed: {}", e)));
            }
            debug!(terminal_id = %self.id, cols, rows, "Terminal resized");
        }

        Ok(())
    }

    /// Check if a client is currently connected to the I/O socket.
    pub fn is_attached(&self) -> bool {
        self.attached.load(Ordering::Relaxed)
    }

    /// Get the terminal's PID (if available).
    pub async fn pid(&self) -> Option<u64> {
        // TODO: Track PID from channel accept data
        None
    }

    /// Start the I/O socket listener.
    ///
    /// Creates a Unix socket at `{session_dir}/{id}.io.sock` and starts
    /// accepting connections. Only one client can be connected at a time.
    async fn start_io_listener(&self) -> Result<(), ResourceError> {
        let session_dir = self.session_dir.lock().await.clone();
        let Some(session_dir) = session_dir else {
            return Err(ResourceError::Internal("session directory not set".to_string()));
        };

        // Create socket path
        let socket_path = session_dir.join(format!("{}.io.sock", self.id));

        // Remove existing socket if present
        let _ = std::fs::remove_file(&socket_path);

        // Create the listener
        let listener = UnixListener::bind(&socket_path)
            .map_err(|e| ResourceError::Internal(format!("failed to bind I/O socket: {}", e)))?;

        info!(
            terminal_id = %self.id,
            socket_path = %socket_path.display(),
            "Terminal I/O socket created"
        );

        // Store the socket path
        *self.io_socket_path.lock().unwrap() = Some(socket_path.clone());

        // Get clones of channel and connection for the listener task
        let channel = self.channel.read().await.clone();
        let Some(channel) = channel else {
            return Err(ResourceError::Internal("channel not available".to_string()));
        };
        let connection = self.connection.read().await.clone();
        let Some(connection) = connection else {
            return Err(ResourceError::Internal("connection not available".to_string()));
        };

        let id = self.id.clone();
        let attached = self.attached.clone();

        // Spawn the listener task
        let listener_task = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _addr)) => {
                        info!(terminal_id = %id, "Client connected to I/O socket");
                        attached.store(true, Ordering::Relaxed);

                        // Handle this client (blocking until disconnected)
                        // Only one client at a time for MVP
                        Self::handle_io_client(
                            id.clone(),
                            stream,
                            channel.clone(),
                            connection.clone(),
                        )
                        .await;

                        attached.store(false, Ordering::Relaxed);
                        info!(terminal_id = %id, "Client disconnected from I/O socket");
                    }
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::Other {
                            // Listener closed, exit gracefully
                            break;
                        }
                        warn!(terminal_id = %id, error = %e, "Error accepting I/O connection");
                    }
                }
            }
            debug!(terminal_id = %id, "I/O listener task stopped");
        });

        *self.io_listener_task.lock().await = Some(listener_task);

        Ok(())
    }

    /// Handle a connected I/O client.
    ///
    /// Bridges raw bytes between the Unix socket and the TerminalChannel.
    /// Parses CSI 8 sequences (xterm window resize) and triggers PTY resize.
    /// Returns when the client disconnects or an error occurs.
    async fn handle_io_client(
        id: String,
        stream: tokio::net::UnixStream,
        channel: TerminalChannel,
        connection: Arc<ChannelConnection>,
    ) {
        let (mut reader, mut writer) = stream.into_split();

        // Spawn output forwarding task (PTY -> client)
        let channel_out = channel.clone();
        let id_out = id.clone();
        let output_task = tokio::spawn(async move {
            loop {
                match channel_out.recv_output().await {
                    Ok(output) => {
                        if let Err(e) = writer.write_all(&output.data).await {
                            debug!(terminal_id = %id_out, error = %e, "Error writing to I/O client");
                            break;
                        }
                        // Flush immediately for low latency
                        if let Err(e) = writer.flush().await {
                            debug!(terminal_id = %id_out, error = %e, "Error flushing to I/O client");
                            break;
                        }
                    }
                    Err(e) => {
                        debug!(terminal_id = %id_out, error = %e, "Error receiving from PTY");
                        break;
                    }
                }
            }
        });

        // Handle input in the current task (client -> PTY)
        // We need to parse CSI 8 sequences for resize
        let mut buf = [0u8; 4096];
        let mut parser = Csi8Parser::new();
        let channel_id = channel.channel_id();

        loop {
            match reader.read(&mut buf).await {
                Ok(0) => {
                    // Client disconnected
                    debug!(terminal_id = %id, "I/O client EOF");
                    break;
                }
                Ok(n) => {
                    // Parse for CSI 8 resize sequences
                    let (filtered, resizes) = parser.parse(&buf[..n]);

                    // Handle any resize commands
                    for (rows, cols) in resizes {
                        debug!(terminal_id = %id, cols, rows, "CSI 8 resize detected");
                        if let Err(e) = connection
                            .send_resize(channel_id, cols as u16, rows as u16)
                            .await
                        {
                            warn!(terminal_id = %id, error = %e, "Failed to send resize");
                        }
                    }

                    // Send filtered input to PTY (with CSI 8 sequences removed)
                    if !filtered.is_empty() {
                        if let Err(e) = channel.queue_input(&filtered, false) {
                            debug!(terminal_id = %id, error = %e, "Error sending input to PTY");
                            break;
                        }
                    }
                }
                Err(e) => {
                    debug!(terminal_id = %id, error = %e, "Error reading from I/O client");
                    break;
                }
            }
        }

        // Stop the output task
        output_task.abort();
    }

    /// Stop the I/O listener and clean up the socket.
    async fn stop_io_listener(&self) {
        // Stop listener task
        if let Some(task) = self.io_listener_task.lock().await.take() {
            task.abort();
        }

        // Stop client task if any
        if let Some(task) = self.io_client_task.lock().await.take() {
            task.abort();
        }

        // Remove socket file
        if let Some(path) = self.io_socket_path.lock().unwrap().take() {
            let _ = std::fs::remove_file(&path);
            debug!(terminal_id = %self.id, path = %path.display(), "Removed I/O socket");
        }
    }
}

#[async_trait]
impl Resource for Terminal {
    async fn start(&mut self, conn: Arc<ChannelConnection>) -> Result<(), ResourceError> {
        if !matches!(self.state, ResourceState::Pending) {
            return Err(ResourceError::InvalidState {
                current: self.state.clone(),
                expected: "pending",
            });
        }
        self.state = ResourceState::Starting;

        info!(
            terminal_id = %self.id,
            cols = self.params.term_size.cols,
            rows = self.params.term_size.rows,
            "Starting terminal resource"
        );

        // Open terminal channel on remote server
        let channel = conn
            .open_terminal(self.params.clone())
            .await
            .map_err(|e| ResourceError::Internal(format!("failed to open terminal: {}", e)))?;

        // Store the channel and connection
        *self.channel.write().await = Some(channel);
        *self.connection.write().await = Some(conn.clone());

        // Start the I/O socket listener
        self.start_io_listener().await?;

        // Transition to running
        self.state = ResourceState::Running;

        info!(terminal_id = %self.id, "Terminal resource started");
        Ok(())
    }

    async fn drain(&mut self, _deadline: Duration) -> Result<(), ResourceError> {
        if self.state.is_terminal() {
            return Err(ResourceError::InvalidState {
                current: self.state.clone(),
                expected: "active",
            });
        }
        self.state = ResourceState::Draining;

        info!(terminal_id = %self.id, "Draining terminal resource");

        // Stop I/O listener (disconnects any attached client)
        self.stop_io_listener().await;

        // Close the channel
        if let Some(ref ch) = *self.channel.read().await {
            ch.mark_closed();
        }

        self.state = ResourceState::Closed;
        info!(terminal_id = %self.id, "Terminal resource drained");
        Ok(())
    }

    async fn close(&mut self) -> Result<(), ResourceError> {
        if self.state.is_terminal() {
            return Err(ResourceError::InvalidState {
                current: self.state.clone(),
                expected: "active",
            });
        }

        info!(terminal_id = %self.id, "Closing terminal resource");

        // Stop I/O listener (disconnects any attached client)
        self.stop_io_listener().await;

        // Mark channel as closed
        if let Some(ref ch) = *self.channel.read().await {
            ch.mark_closed();
        }

        self.state = ResourceState::Closed;
        info!(terminal_id = %self.id, "Terminal resource closed");
        Ok(())
    }

    fn describe(&self) -> ResourceInfo {
        let state = self.state.clone();
        let stats = self.stats.clone();
        let (cols, rows) = *self.term_size.read().unwrap();
        let attached = self.is_attached();

        ResourceInfo {
            id: self.id.clone(),
            kind: ResourceKind::Terminal,
            state,
            stats,
            details: ResourceDetails::Terminal(TerminalDetailsInfo {
                cols,
                rows,
                shell: self.params.shell.clone().unwrap_or_else(|| "/bin/bash".to_string()),
                attached,
                pid: None, // TODO: Track PID
                socket_path: self.io_socket_path().map(|p| p.display().to_string()),
                term_type: self.params.term_type.clone(),
                command: self.params.command.clone(),
                output_mode: self.params.output_mode,
                allocate_pty: self.params.allocate_pty,
            }),
        }
    }

    fn kind(&self) -> ResourceKind {
        ResourceKind::Terminal
    }

    fn id(&self) -> &str {
        &self.id
    }

    fn state(&self) -> &ResourceState {
        &self.state
    }

    fn on_disconnect(&mut self) {
        // Mark as disconnected but don't fail yet - we'll try to resume
        warn!(terminal_id = %self.id, "Terminal disconnected");

        // Stop I/O listener task (client will be disconnected)
        if let Some(handle) = self.io_listener_task.blocking_lock().take() {
            handle.abort();
        }

        // Stop client task if any
        if let Some(handle) = self.io_client_task.blocking_lock().take() {
            handle.abort();
        }
    }

    async fn on_reconnect(&mut self, conn: Arc<ChannelConnection>) -> Result<(), ResourceError> {
        info!(terminal_id = %self.id, "Attempting to resume terminal after reconnect");

        // Try to resume the terminal by re-opening the channel
        let channel = conn
            .open_terminal(self.params.clone())
            .await
            .map_err(|e| {
                ResourceError::Internal(format!("failed to resume terminal: {}", e))
            })?;

        // Store the channel and connection
        *self.channel.write().await = Some(channel);
        *self.connection.write().await = Some(conn.clone());

        // Restart the I/O listener so clients can reconnect
        self.start_io_listener().await?;

        info!(terminal_id = %self.id, "Terminal resumed successfully (I/O socket ready)");
        Ok(())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qsh_core::protocol::TermSize;

    #[test]
    fn test_terminal_creation() {
        let params = TerminalParams {
            term_size: TermSize { cols: 80, rows: 24 },
            term_type: "xterm-256color".to_string(),
            shell: None,
            command: None,
            env: vec![],
            ..Default::default()
        };

        let terminal = Terminal::new("term-0".to_string(), params);
        assert_eq!(terminal.id(), "term-0");
        assert_eq!(terminal.kind(), ResourceKind::Terminal);
    }

    #[test]
    fn test_from_params() {
        use qsh_core::protocol::OutputMode;

        let terminal = Terminal::from_params(
            "term-1".to_string(),
            Some(120),
            Some(40),
            Some("xterm".to_string()),
            Some("/bin/zsh".to_string()),
            None,
            vec![],
            OutputMode::Mosh,
            true, // allocate_pty
        );

        assert_eq!(terminal.id(), "term-1");
        assert_eq!(terminal.params.term_size.cols, 120);
        assert_eq!(terminal.params.term_size.rows, 40);
        assert_eq!(terminal.params.shell, Some("/bin/zsh".to_string()));
        assert_eq!(terminal.params.output_mode, OutputMode::Mosh);
        assert!(terminal.params.allocate_pty);
    }

    #[test]
    fn test_csi8_parser_basic() {
        let mut parser = Csi8Parser::new();

        // Simple resize sequence: ESC [ 8 ; 24 ; 80 t
        let input = b"\x1b[8;24;80t";
        let (output, resizes) = parser.parse(input);

        assert!(output.is_empty(), "CSI 8 should be filtered out");
        assert_eq!(resizes.len(), 1);
        assert_eq!(resizes[0], (24, 80)); // (rows, cols)
    }

    #[test]
    fn test_csi8_parser_passthrough() {
        let mut parser = Csi8Parser::new();

        // Normal text should pass through
        let input = b"hello world";
        let (output, resizes) = parser.parse(input);

        assert_eq!(output, b"hello world");
        assert!(resizes.is_empty());
    }

    #[test]
    fn test_csi8_parser_mixed() {
        let mut parser = Csi8Parser::new();

        // Text mixed with resize
        let input = b"before\x1b[8;30;120tafter";
        let (output, resizes) = parser.parse(input);

        assert_eq!(output, b"beforeafter");
        assert_eq!(resizes.len(), 1);
        assert_eq!(resizes[0], (30, 120));
    }

    #[test]
    fn test_csi8_parser_other_csi() {
        let mut parser = Csi8Parser::new();

        // Other CSI sequences should pass through (e.g., cursor movement)
        let input = b"\x1b[H\x1b[2J"; // Home + clear screen
        let (output, resizes) = parser.parse(input);

        assert_eq!(output, input.as_slice());
        assert!(resizes.is_empty());
    }

    #[test]
    fn test_csi8_parser_multiple() {
        let mut parser = Csi8Parser::new();

        // Multiple resize sequences
        let input = b"\x1b[8;24;80t\x1b[8;48;160t";
        let (output, resizes) = parser.parse(input);

        assert!(output.is_empty());
        assert_eq!(resizes.len(), 2);
        assert_eq!(resizes[0], (24, 80));
        assert_eq!(resizes[1], (48, 160));
    }

    #[test]
    fn test_csi8_parser_partial_sequence() {
        let mut parser = Csi8Parser::new();

        // Sequence split across two parse calls
        let (output1, resizes1) = parser.parse(b"\x1b[8;2");
        let (output2, resizes2) = parser.parse(b"4;80t");

        assert!(output1.is_empty());
        assert!(resizes1.is_empty());
        assert!(output2.is_empty());
        assert_eq!(resizes2.len(), 1);
        assert_eq!(resizes2[0], (24, 80));
    }
}
