//! File transfer state types.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Instant;

use crate::protocol::{TransferDirection, TransferOptions};

/// Status of a file transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferStatus {
    /// Transfer is pending (not yet started).
    Pending,
    /// Waiting for metadata from remote.
    AwaitingMetadata,
    /// Transfer is in progress.
    InProgress,
    /// Transfer is paused (can be resumed).
    Paused,
    /// Transfer completed successfully.
    Completed,
    /// Transfer failed.
    Failed,
    /// Transfer was cancelled.
    Cancelled,
}

/// State of a file transfer.
#[derive(Debug, Clone)]
pub struct TransferState {
    /// Unique transfer ID.
    pub transfer_id: u64,
    /// Local file path.
    pub local_path: PathBuf,
    /// Remote file path.
    pub remote_path: String,
    /// Transfer direction.
    pub direction: TransferDirection,
    /// Transfer options.
    pub options: TransferOptions,
    /// Current status.
    pub status: TransferStatus,
    /// Total file size (if known).
    pub total_size: Option<u64>,
    /// Bytes transferred so far.
    pub bytes_transferred: u64,
    /// Transfer start time.
    pub started_at: Option<Instant>,
    /// Last progress update time.
    pub last_update: Option<Instant>,
}

impl TransferState {
    /// Create a new transfer state.
    pub fn new(
        transfer_id: u64,
        local_path: PathBuf,
        remote_path: String,
        direction: TransferDirection,
        options: TransferOptions,
    ) -> Self {
        Self {
            transfer_id,
            local_path,
            remote_path,
            direction,
            options,
            status: TransferStatus::Pending,
            total_size: None,
            bytes_transferred: 0,
            started_at: None,
            last_update: None,
        }
    }

    /// Get transfer progress as a percentage (0.0 - 100.0).
    pub fn progress_percent(&self) -> Option<f64> {
        self.total_size.map(|total| {
            if total == 0 {
                100.0
            } else {
                (self.bytes_transferred as f64 / total as f64) * 100.0
            }
        })
    }

    /// Get transfer speed in bytes per second.
    pub fn speed_bps(&self) -> Option<f64> {
        self.started_at.map(|start| {
            let elapsed = start.elapsed().as_secs_f64();
            if elapsed > 0.0 {
                self.bytes_transferred as f64 / elapsed
            } else {
                0.0
            }
        })
    }

    /// Get estimated time remaining in seconds.
    pub fn eta_seconds(&self) -> Option<f64> {
        match (self.total_size, self.speed_bps()) {
            (Some(total), Some(speed)) if speed > 0.0 => {
                let remaining = total.saturating_sub(self.bytes_transferred);
                Some(remaining as f64 / speed)
            }
            _ => None,
        }
    }
}

/// Persistent transfer state for resume support.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistentTransferState {
    /// Transfer ID.
    pub transfer_id: u64,
    /// Local file path.
    pub local_path: String,
    /// Remote file path.
    pub remote_path: String,
    /// Transfer direction.
    pub direction: TransferDirection,
    /// Bytes transferred.
    pub bytes_transferred: u64,
    /// Checksum of transferred portion.
    pub partial_checksum: u64,
    /// Total file size.
    pub total_size: u64,
    /// Unix timestamp when transfer started.
    pub started_at: u64,
}

impl PersistentTransferState {
    /// Get the path for the transfer state file.
    pub fn state_file_path(local_path: &std::path::Path) -> PathBuf {
        let mut path = local_path.to_path_buf();
        let filename = path
            .file_name()
            .map(|s| format!(".{}.qsh-transfer", s.to_string_lossy()))
            .unwrap_or_else(|| ".qsh-transfer".to_string());
        path.set_file_name(filename);
        path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transfer_state_new() {
        let state = TransferState::new(
            1,
            PathBuf::from("/local/file.txt"),
            "/remote/file.txt".to_string(),
            TransferDirection::Upload,
            TransferOptions::default(),
        );

        assert_eq!(state.transfer_id, 1);
        assert_eq!(state.status, TransferStatus::Pending);
        assert_eq!(state.bytes_transferred, 0);
        assert!(state.total_size.is_none());
    }

    #[test]
    fn test_progress_percent() {
        let mut state = TransferState::new(
            1,
            PathBuf::from("/local/file.txt"),
            "/remote/file.txt".to_string(),
            TransferDirection::Upload,
            TransferOptions::default(),
        );

        assert!(state.progress_percent().is_none());

        state.total_size = Some(1000);
        state.bytes_transferred = 500;
        assert_eq!(state.progress_percent(), Some(50.0));

        state.bytes_transferred = 1000;
        assert_eq!(state.progress_percent(), Some(100.0));
    }

    #[test]
    fn test_progress_percent_zero_size() {
        let mut state = TransferState::new(
            1,
            PathBuf::from("/local/file.txt"),
            "/remote/file.txt".to_string(),
            TransferDirection::Upload,
            TransferOptions::default(),
        );

        state.total_size = Some(0);
        assert_eq!(state.progress_percent(), Some(100.0));
    }

    #[test]
    fn test_state_file_path() {
        let path = std::path::Path::new("/home/user/file.txt");
        let state_path = PersistentTransferState::state_file_path(path);
        assert_eq!(
            state_path,
            PathBuf::from("/home/user/.file.txt.qsh-transfer")
        );
    }
}
