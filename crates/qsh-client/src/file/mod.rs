//! File transfer client for qsh.
//!
//! File transfers are now handled via the channel model using ChannelOpen with
//! FileTransferParams. See the `channel::FileChannel` type for the channel-based
//! file transfer API.
//!
//! TODO: Re-implement FileTransfer using ChannelConnection::open_file_transfer()

pub mod progress;

pub use progress::ProgressReporter;

// Stub for legacy API - will be re-implemented using channel model
/// Result of a file transfer.
#[derive(Debug)]
pub struct TransferResult {
    /// Bytes transferred.
    pub bytes: u64,
    /// Transfer duration in seconds.
    pub duration_secs: f64,
    /// Whether delta sync was used.
    pub delta_used: bool,
    /// Whether the transfer was skipped because the file was already up to date.
    pub skipped: bool,
}
