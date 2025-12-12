//! Progress event types for file transfers.

use std::sync::Arc;

/// Events emitted during file transfer operations.
#[derive(Debug, Clone)]
pub enum ProgressEvent {
    /// Starting to collect files for recursive transfer.
    ScanningDirectory { path: String },
    /// File collection completed.
    ScanCompleted {
        file_count: usize,
        total_bytes: u64,
    },
    /// Starting transfer of a single file.
    FileStarted {
        local_path: String,
        remote_path: String,
        total_bytes: u64,
    },
    /// Progress update for current file.
    FileProgress {
        local_path: String,
        bytes_transferred: u64,
        total_bytes: u64,
    },
    /// File transfer completed successfully.
    FileCompleted {
        local_path: String,
        bytes: u64,
        skipped: bool,
    },
    /// File transfer failed.
    FileFailed { local_path: String, error: String },
    /// Overall progress for recursive transfers.
    OverallProgress {
        files_done: u64,
        files_total: u64,
        bytes_transferred: u64,
        total_bytes: u64,
    },
    /// Transfer completed.
    TransferCompleted {
        files_transferred: u64,
        files_skipped: u64,
        files_failed: u64,
        bytes: u64,
        elapsed_secs: f64,
    },
}

/// Callback for progress events.
///
/// This trait allows consumers to handle progress events. The callback is
/// invoked synchronously during transfer operations.
pub trait ProgressCallback: Send + Sync {
    fn on_progress(&self, event: ProgressEvent);
}

/// A no-op progress callback that ignores all events.
pub struct NoOpCallback;

impl ProgressCallback for NoOpCallback {
    fn on_progress(&self, _event: ProgressEvent) {}
}

/// A function-based progress callback.
pub struct FnCallback<F>
where
    F: Fn(ProgressEvent) + Send + Sync,
{
    f: F,
}

impl<F> FnCallback<F>
where
    F: Fn(ProgressEvent) + Send + Sync,
{
    pub fn new(f: F) -> Self {
        Self { f }
    }
}

impl<F> ProgressCallback for FnCallback<F>
where
    F: Fn(ProgressEvent) + Send + Sync,
{
    fn on_progress(&self, event: ProgressEvent) {
        (self.f)(event)
    }
}

/// Helper to create an Arc-wrapped callback from a closure.
pub fn callback<F>(f: F) -> Arc<dyn ProgressCallback>
where
    F: Fn(ProgressEvent) + Send + Sync + 'static,
{
    Arc::new(FnCallback::new(f))
}
