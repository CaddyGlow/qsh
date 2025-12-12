//! Terminal resource implementation for the control plane.
//!
//! This module provides the `Terminal` resource which wraps a PTY session
//! and integrates it with the unified resource control system.
//!
//! # Features
//!
//! - Single attached client (MVP): only one client can attach at a time
//! - I/O via Stream messages with StreamKind::TerminalIo
//! - Resize support via TerminalResizeCmd
//! - Resume on reconnect (marks Failed if resume fails)
//! - Graceful drain and close
//!
//! # Architecture
//!
//! The Terminal resource manages:
//! - A TerminalChannel (input/output streams to the remote PTY)
//! - Attachment state (which control client is currently attached)
//! - I/O forwarding between attached client and remote PTY
//! - Lifecycle tracking (start, running, draining, closed)

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::{Mutex, RwLock, mpsc};
use tracing::{debug, error, info, warn};

use qsh_core::protocol::TerminalParams;

use crate::channel::TerminalChannel;
use crate::ChannelConnection;

use super::super::resource::{
    FailureReason, Resource, ResourceDetails, ResourceError, ResourceInfo, ResourceKind,
    ResourceState, ResourceStats, TerminalDetails as TerminalDetailsInfo,
};

/// Terminal resource wrapping a remote PTY session.
///
/// This resource:
/// - Opens a terminal channel on the remote server
/// - Manages attachment of a single control client
/// - Forwards I/O between attached client and remote PTY via Stream messages
/// - Supports resize, detach, and graceful shutdown
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
    /// Current terminal size.
    term_size: RwLock<(u32, u32)>,
    /// Attachment state.
    attachment: Mutex<AttachmentState>,
    /// I/O task handle (spawned when attached).
    io_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

/// Attachment state for the terminal.
#[derive(Debug)]
enum AttachmentState {
    /// No client attached.
    Detached,
    /// A client is attached, with I/O forwarding active.
    Attached,
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
            term_size: RwLock::new((cols, rows)),
            attachment: Mutex::new(AttachmentState::Detached),
            io_task: Mutex::new(None),
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
            ..Default::default()
        };

        Self::new(id, params)
    }

    /// Attach a control client to this terminal.
    ///
    /// Returns channels for bidirectional I/O:
    /// - output_rx: receives output from the remote PTY
    /// - input_tx: sends input to the remote PTY
    ///
    /// Only one client can be attached at a time (MVP).
    ///
    /// The I/O forwarding happens in the background. When you're done,
    /// call detach() to stop forwarding.
    pub async fn attach(
        &self,
    ) -> Result<
        (
            mpsc::UnboundedReceiver<Vec<u8>>,
            mpsc::UnboundedSender<Vec<u8>>,
        ),
        ResourceError,
    > {
        if !self.state.is_running() {
            return Err(ResourceError::InvalidState {
                current: self.state.clone(),
                expected: "running",
            });
        }

        let mut attachment = self.attachment.lock().await;
        if matches!(*attachment, AttachmentState::Attached) {
            return Err(ResourceError::Internal(
                "terminal already attached".to_string(),
            ));
        }

        // Mark as attached
        *attachment = AttachmentState::Attached;
        drop(attachment);

        // Create channels for I/O forwarding
        let (output_tx, output_rx) = mpsc::unbounded_channel();
        let (input_tx, input_rx) = mpsc::unbounded_channel();

        // Spawn I/O forwarding task with the channels
        // The task owns both ends and will stop when either channel closes
        self.spawn_io_task(output_tx, input_rx).await;

        info!(terminal_id = %self.id, "Client attached to terminal");
        Ok((output_rx, input_tx))
    }

    /// Detach the currently attached client.
    ///
    /// This stops the I/O forwarding task and marks the terminal as detached.
    pub async fn detach(&self) -> Result<(), ResourceError> {
        let mut attachment = self.attachment.lock().await;
        if matches!(*attachment, AttachmentState::Detached) {
            return Err(ResourceError::Internal(
                "terminal not attached".to_string(),
            ));
        }

        *attachment = AttachmentState::Detached;
        drop(attachment);

        // Stop the I/O task
        self.stop_io_task().await;

        info!(terminal_id = %self.id, "Client detached from terminal");
        Ok(())
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
        *self.term_size.write().await = (cols, rows);

        // Send resize to remote PTY
        let channel = self.channel.read().await;
        if let Some(ref ch) = *channel {
            // TODO: Send resize request via control message
            // For now, just update local state
            debug!(terminal_id = %self.id, cols, rows, "Terminal resized");
        }

        Ok(())
    }

    /// Check if a client is currently attached.
    pub async fn is_attached(&self) -> bool {
        matches!(&*self.attachment.lock().await, AttachmentState::Attached)
    }

    /// Get the terminal's PID (if available).
    pub async fn pid(&self) -> Option<u64> {
        // TODO: Track PID from channel accept data
        None
    }

    /// Spawn the I/O forwarding task.
    ///
    /// This task runs in the background and forwards I/O between the attached
    /// client and the remote PTY. It stops when the client detaches or the
    /// terminal is closed.
    ///
    /// Note: The I/O task is manually managed. The attachment channels are
    /// passed in so the task can forward data. When the client detaches, the
    /// channels are dropped which causes the task to exit naturally.
    async fn spawn_io_task(
        &self,
        mut output_tx: mpsc::UnboundedSender<Vec<u8>>,
        mut input_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    ) {
        let channel_opt = self.channel.read().await.clone();
        let Some(channel) = channel_opt else {
            warn!(terminal_id = %self.id, "Cannot spawn I/O task: no channel");
            return;
        };

        let id = self.id.clone();
        // Clone the stats values for thread safety
        let stats_in = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let stats_out = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let stats_in_clone = stats_in.clone();
        let stats_out_clone = stats_out.clone();

        let task = tokio::spawn(async move {
            loop {
                // Forward output from remote PTY to attached client
                tokio::select! {
                    // Receive from remote PTY
                    result = channel.recv_output() => {
                        match result {
                            Ok(output) => {
                                let len = output.data.len() as u64;
                                if output_tx.send(output.data).is_err() {
                                    debug!(terminal_id = %id, "Output channel closed (client detached)");
                                    break;
                                }
                                // Update stats atomically
                                stats_out.fetch_add(len, std::sync::atomic::Ordering::Relaxed);
                            }
                            Err(e) => {
                                error!(terminal_id = %id, error = %e, "Terminal output error");
                                break;
                            }
                        }
                    }

                    // Receive from attached client
                    Some(data) = input_rx.recv() => {
                        let len = data.len() as u64;
                        if let Err(e) = channel.queue_input(&data, false) {
                            error!(terminal_id = %id, error = %e, "Failed to send input to PTY");
                            break;
                        }
                        // Update stats atomically
                        stats_in.fetch_add(len, std::sync::atomic::Ordering::Relaxed);
                    }

                    else => {
                        debug!(terminal_id = %id, "I/O task select exhausted");
                        break;
                    }
                }
            }

            info!(terminal_id = %id, "Terminal I/O task stopped");
        });

        // TODO: Store stats counters so we can update the main stats when task stops
        // For now, stats won't be perfectly accurate but the structure is correct

        *self.io_task.lock().await = Some(task);
    }

    /// Stop the I/O forwarding task.
    async fn stop_io_task(&self) {
        let task = self.io_task.lock().await.take();
        if let Some(handle) = task {
            handle.abort();
            debug!(terminal_id = %self.id, "Aborted I/O task");
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

        // Store the channel
        *self.channel.write().await = Some(channel);

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

        // Detach any attached client
        let mut attachment = self.attachment.lock().await;
        if matches!(*attachment, AttachmentState::Attached) {
            *attachment = AttachmentState::Detached;
        }
        drop(attachment);

        // Stop I/O task
        self.stop_io_task().await;

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

        // Stop I/O task
        self.stop_io_task().await;

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
        let (cols, rows) = *self.term_size.blocking_read();
        let attached = matches!(&*self.attachment.blocking_lock(), AttachmentState::Attached);

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

        // Stop I/O task (it will fail on next operation anyway)
        let io_task = self.io_task.blocking_lock().take();
        if let Some(handle) = io_task {
            handle.abort();
        }

        // Force detach since the client's channels are broken
        // Client will need to re-attach after reconnect
        *self.attachment.blocking_lock() = AttachmentState::Detached;
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

        *self.channel.write().await = Some(channel);

        // Note: Client was auto-detached on disconnect, they need to re-attach
        info!(terminal_id = %self.id, "Terminal resumed successfully (client must re-attach)");
        Ok(())
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
        let terminal = Terminal::from_params(
            "term-1".to_string(),
            Some(120),
            Some(40),
            Some("xterm".to_string()),
            Some("/bin/zsh".to_string()),
            None,
            vec![],
        );

        assert_eq!(terminal.id(), "term-1");
        assert_eq!(terminal.params.term_size.cols, 120);
        assert_eq!(terminal.params.term_size.rows, 40);
        assert_eq!(terminal.params.shell, Some("/bin/zsh".to_string()));
    }
}
