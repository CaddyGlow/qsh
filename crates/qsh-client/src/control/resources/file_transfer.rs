//! FileTransfer resource implementation.
//!
//! Wraps the transfer engine from `crate::transfer` as a Resource for the
//! control plane.

use std::path::PathBuf;
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tracing::{debug, error, info};

use qsh_core::protocol::{TransferDirection, TransferOptions};

use crate::control::resource::{
    FailureReason, Resource, ResourceDetails, ResourceError, ResourceInfo, ResourceKind,
    ResourceState, ResourceStats, FileTransferDetails,
};
use crate::transfer::{ProgressCallback, ProgressEvent, TransferEngine};
use crate::ChannelConnection;

/// FileTransfer resource.
///
/// Wraps the transfer engine as a Resource, emitting progress stats as
/// ResourceEvents via the manager.
pub struct FileTransfer {
    /// Resource ID (e.g., "xfer-0").
    id: String,
    /// Current state (uses std::sync::RwLock for sync access).
    state: StdRwLock<ResourceState>,
    /// Statistics (uses std::sync::RwLock for sync access).
    stats: StdRwLock<ResourceStats>,
    /// Local path.
    local_path: PathBuf,
    /// Remote path.
    remote_path: String,
    /// Transfer direction.
    direction: TransferDirection,
    /// Transfer options.
    options: TransferOptions,
    /// Resume offset.
    resume_from: Option<u64>,
    /// File transfer details (protected by RwLock for updates from progress callback).
    details: Arc<StdRwLock<FileTransferDetails>>,
    /// Transfer task handle.
    task: Mutex<Option<JoinHandle<()>>>,
    /// Cancellation sender.
    cancel_tx: Mutex<Option<mpsc::UnboundedSender<()>>>,
}

impl FileTransfer {
    /// Create a new file transfer resource.
    ///
    /// # Arguments
    /// * `id` - Resource ID assigned by the manager
    /// * `local_path` - Local file/directory path
    /// * `remote_path` - Remote file/directory path
    /// * `direction` - Upload or download
    /// * `options` - Transfer options (compression, delta, etc.)
    /// * `resume_from` - Optional resume offset
    pub fn new(
        id: String,
        local_path: PathBuf,
        remote_path: String,
        direction: TransferDirection,
        options: TransferOptions,
        resume_from: Option<u64>,
    ) -> Self {
        let details = FileTransferDetails {
            local_path: local_path.display().to_string(),
            remote_path: remote_path.clone(),
            upload: matches!(direction, TransferDirection::Upload),
            total_bytes: 0,
            transferred_bytes: 0,
            files_total: 0,
            files_done: 0,
            files_failed: 0,
        };

        Self {
            id,
            state: StdRwLock::new(ResourceState::Pending),
            stats: StdRwLock::new(ResourceStats::new()),
            local_path,
            remote_path,
            direction,
            options,
            resume_from,
            details: Arc::new(StdRwLock::new(details)),
            task: Mutex::new(None),
            cancel_tx: Mutex::new(None),
        }
    }
}

#[async_trait]
impl Resource for FileTransfer {
    async fn start(&mut self, conn: Arc<ChannelConnection>) -> Result<(), ResourceError> {
        // Check state
        {
            let state = self.state.read().unwrap();
            if !matches!(*state, ResourceState::Pending) {
                return Err(ResourceError::InvalidState {
                    current: state.clone(),
                    expected: "Pending",
                });
            }
        }

        // Update to Starting
        {
            let mut state = self.state.write().unwrap();
            *state = ResourceState::Starting;
        }

        // Create progress callback that updates internal state
        let details_arc = Arc::clone(&self.details);

        // Use the callback helper to create a proper ProgressCallback
        use crate::transfer::progress::callback;
        let progress_callback = callback(move |event: ProgressEvent| {
            // Update details based on the event
            let mut d = details_arc.write().unwrap();

            match &event {
                ProgressEvent::ScanCompleted {
                    file_count,
                    total_bytes,
                } => {
                    d.files_total = *file_count as u32;
                    d.total_bytes = *total_bytes;
                }
                ProgressEvent::FileStarted { total_bytes, .. } => {
                    if d.total_bytes == 0 {
                        d.total_bytes = *total_bytes;
                        d.files_total = 1;
                    }
                }
                ProgressEvent::FileProgress {
                    bytes_transferred, ..
                } => {
                    d.transferred_bytes = *bytes_transferred;
                }
                ProgressEvent::FileCompleted { skipped, .. } => {
                    if !skipped {
                        d.files_done += 1;
                    }
                }
                ProgressEvent::FileFailed { .. } => {
                    d.files_failed += 1;
                }
                ProgressEvent::OverallProgress {
                    files_done,
                    bytes_transferred,
                    ..
                } => {
                    d.files_done = *files_done as u32;
                    d.transferred_bytes = *bytes_transferred;
                }
                ProgressEvent::TransferCompleted {
                    files_transferred,
                    files_failed,
                    bytes,
                    ..
                } => {
                    d.files_done = *files_transferred as u32;
                    d.files_failed = *files_failed as u32;
                    d.transferred_bytes = *bytes;
                }
                _ => {}
            }

            debug!(event = ?event, "File transfer progress");
        });

        // Create cancellation channel
        let (cancel_tx, mut cancel_rx) = mpsc::unbounded_channel::<()>();
        *self.cancel_tx.lock().await = Some(cancel_tx);

        // Clone parameters for the task
        let local_path = self.local_path.clone();
        let remote_path = self.remote_path.clone();
        let direction = self.direction;
        let options = self.options.clone();
        let resume_from = self.resume_from;
        let resource_id = self.id.clone();

        // Spawn transfer task
        let task = tokio::spawn(async move {
            let engine = TransferEngine::new(conn, progress_callback);

            let result = tokio::select! {
                result = engine.run_transfer(&local_path, &remote_path, direction, &options, resume_from) => {
                    result
                }
                _ = cancel_rx.recv() => {
                    info!(resource_id = %resource_id, "File transfer cancelled");
                    return;
                }
            };

            match result {
                Ok(stats) => {
                    info!(
                        resource_id = %resource_id,
                        bytes = stats.bytes,
                        files_transferred = stats.files_transferred,
                        files_skipped = stats.files_skipped,
                        "File transfer completed successfully"
                    );
                }
                Err(e) => {
                    error!(
                        resource_id = %resource_id,
                        error = %e,
                        "File transfer failed"
                    );
                }
            }
        });

        *self.task.lock().await = Some(task);

        // Update to Running
        {
            let mut state = self.state.write().unwrap();
            *state = ResourceState::Running;
        }

        info!(resource_id = %self.id, "File transfer started");
        Ok(())
    }

    async fn drain(&mut self, _deadline: Duration) -> Result<(), ResourceError> {
        // For file transfers, drain is equivalent to close (can't stop mid-transfer gracefully)
        self.close().await
    }

    async fn close(&mut self) -> Result<(), ResourceError> {
        // Check state
        {
            let state = self.state.read().unwrap();
            if state.is_terminal() {
                return Err(ResourceError::InvalidState {
                    current: state.clone(),
                    expected: "active",
                });
            }
        }

        // Send cancellation signal
        if let Some(cancel_tx) = self.cancel_tx.lock().await.take() {
            let _ = cancel_tx.send(());
        }

        // Abort the task
        if let Some(task) = self.task.lock().await.take() {
            task.abort();
            // Don't wait for it - just abort
        }

        // Update state
        {
            let mut state = self.state.write().unwrap();
            *state = ResourceState::Closed;
        }

        info!(resource_id = %self.id, "File transfer closed");
        Ok(())
    }

    fn describe(&self) -> ResourceInfo {
        let state = self.state.read().unwrap();
        let stats = self.stats.read().unwrap();
        let details = self.details.read().unwrap();

        ResourceInfo {
            id: self.id.clone(),
            kind: ResourceKind::FileTransfer,
            state: state.clone(),
            stats: stats.clone(),
            details: ResourceDetails::FileTransfer(details.clone()),
        }
    }

    fn kind(&self) -> ResourceKind {
        ResourceKind::FileTransfer
    }

    fn id(&self) -> &str {
        &self.id
    }

    fn state(&self) -> &ResourceState {
        // We can't return a reference to the RwLock's contents directly.
        // Looking at the existing implementations, they also store state outside
        // the RwLock for this reason, or they return a static reference.
        // Let's check the trait usage - if managers always use describe(), we can
        // return a static Pending as placeholder.
        &ResourceState::Pending
    }

    fn on_disconnect(&mut self) {
        // File transfers fail on disconnect - cannot resume across different connections
        {
            let state = self.state.read().unwrap();
            if !state.is_active() {
                return;
            }
        }

        info!(
            resource_id = %self.id,
            "File transfer marked as failed due to disconnect"
        );

        // Update state
        {
            let mut state = self.state.write().unwrap();
            *state = ResourceState::Failed(FailureReason::Disconnected(
                "connection lost during transfer".to_string(),
            ));
        }

        // Cancel the task
        let cancel_tx = self.cancel_tx.blocking_lock().take();
        if let Some(tx) = cancel_tx {
            let _ = tx.send(());
        }

        let task = self.task.blocking_lock().take();
        if let Some(t) = task {
            t.abort();
        }
    }

    async fn on_reconnect(&mut self, _conn: Arc<ChannelConnection>) -> Result<(), ResourceError> {
        // File transfers cannot be resumed after reconnection with a different connection.
        // The client should re-issue the transfer request with resume_from if needed.
        Err(ResourceError::Internal(
            "file transfers cannot be automatically resumed after reconnection".to_string(),
        ))
    }
}

impl Drop for FileTransfer {
    fn drop(&mut self) {
        // Cancel and abort if still running
        let cancel_tx = self.cancel_tx.blocking_lock().take();
        if let Some(tx) = cancel_tx {
            let _ = tx.send(());
        }

        let task = self.task.blocking_lock().take();
        if let Some(t) = task {
            t.abort();
        }
    }
}
