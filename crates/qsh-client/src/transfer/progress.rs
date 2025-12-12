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

// =============================================================================
// Indicatif-based progress callback
// =============================================================================

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::sync::Mutex;

/// Progress callback using indicatif progress bars.
///
/// This callback renders progress to the terminal using indicatif's
/// `MultiProgress` for parallel progress tracking.
pub struct IndicatifCallback {
    mp: MultiProgress,
    state: Mutex<IndicatifState>,
}

struct IndicatifState {
    overall_pb: Option<ProgressBar>,
    file_pb: Option<ProgressBar>,
    total_files: u64,
    total_bytes: u64,
}

impl IndicatifCallback {
    /// Create a new indicatif callback.
    pub fn new() -> Self {
        Self {
            mp: MultiProgress::new(),
            state: Mutex::new(IndicatifState {
                overall_pb: None,
                file_pb: None,
                total_files: 0,
                total_bytes: 0,
            }),
        }
    }

    fn file_style() -> ProgressStyle {
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}) {msg}")
            .unwrap()
            .progress_chars("=>-")
    }

    fn overall_style() -> ProgressStyle {
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({percent}%) {msg}")
            .unwrap()
            .progress_chars("=>-")
    }
}

impl Default for IndicatifCallback {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgressCallback for IndicatifCallback {
    fn on_progress(&self, event: ProgressEvent) {
        let mut state = self.state.lock().unwrap();

        match event {
            ProgressEvent::ScanningDirectory { path } => {
                eprintln!("Scanning {}...", path);
            }
            ProgressEvent::ScanCompleted {
                file_count,
                total_bytes,
            } => {
                eprintln!("Found {} files ({} bytes total)", file_count, total_bytes);
                state.total_files = file_count as u64;
                state.total_bytes = total_bytes;

                // Create overall progress bar for recursive transfers
                if file_count > 1 {
                    let pb = self.mp.add(ProgressBar::new(total_bytes));
                    pb.set_style(Self::overall_style());
                    pb.set_message(format!("0/{} files", file_count));
                    state.overall_pb = Some(pb);
                }
            }
            ProgressEvent::FileStarted {
                local_path,
                total_bytes,
                ..
            } => {
                // Extract filename for display
                let filename = std::path::Path::new(&local_path)
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| local_path.clone());

                let pb = self.mp.add(ProgressBar::new(total_bytes));
                pb.set_style(Self::file_style());
                pb.set_message(filename);
                state.file_pb = Some(pb);
            }
            ProgressEvent::FileProgress {
                bytes_transferred, ..
            } => {
                if let Some(ref pb) = state.file_pb {
                    pb.set_position(bytes_transferred);
                }
            }
            ProgressEvent::FileCompleted {
                local_path,
                bytes: _,
                skipped,
            } => {
                if let Some(pb) = state.file_pb.take() {
                    if skipped {
                        pb.finish_with_message("skipped");
                    } else {
                        pb.finish_with_message("done");
                    }
                }

                // For single file transfers without overall bar, print summary
                if state.overall_pb.is_none() && state.total_files <= 1 {
                    let filename = std::path::Path::new(&local_path)
                        .file_name()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_else(|| local_path.clone());

                    if skipped {
                        eprintln!("{}: already up to date", filename);
                    }
                }
            }
            ProgressEvent::FileFailed { local_path, error } => {
                if let Some(pb) = state.file_pb.take() {
                    pb.finish_with_message("failed");
                }
                eprintln!("Error: {} - {}", local_path, error);
            }
            ProgressEvent::OverallProgress {
                files_done,
                files_total,
                bytes_transferred,
                ..
            } => {
                if let Some(ref pb) = state.overall_pb {
                    pb.set_position(bytes_transferred);
                    pb.set_message(format!("{}/{} files", files_done, files_total));
                }
            }
            ProgressEvent::TransferCompleted {
                files_transferred,
                files_skipped,
                files_failed,
                bytes,
                elapsed_secs,
            } => {
                if let Some(pb) = state.overall_pb.take() {
                    pb.finish_with_message("complete");
                }

                let speed = if elapsed_secs > 0.0 {
                    bytes as f64 / elapsed_secs / 1024.0 / 1024.0
                } else {
                    0.0
                };

                // Print summary for recursive transfers
                if files_transferred + files_skipped + files_failed > 1 {
                    eprintln!(
                        "\nTransferred {} files ({} bytes) in {:.2}s ({:.2} MB/s)",
                        files_transferred, bytes, elapsed_secs, speed
                    );
                    if files_skipped > 0 {
                        eprintln!("Skipped {} files (already up to date)", files_skipped);
                    }
                    if files_failed > 0 {
                        eprintln!("Failed {} files", files_failed);
                    }
                } else if files_transferred == 1 {
                    // Single file summary
                    eprintln!(
                        "{} bytes transferred in {:.2}s ({:.2} MB/s)",
                        bytes, elapsed_secs, speed
                    );
                }
            }
        }
    }
}
