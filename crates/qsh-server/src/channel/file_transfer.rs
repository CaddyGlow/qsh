//! File transfer channel implementation.
//!
//! Manages file upload/download operations within a channel.
//!
//! TODO: Reimplement using the channel model. Currently a stub.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use qsh_core::error::{Error, Result};
use qsh_core::protocol::{ChannelId, FileTransferMetadata, FileTransferParams, TransferDirection};
use qsh_core::transport::{QuicConnection, QuicStream};

/// File transfer channel managing upload/download operations.
#[derive(Clone)]
pub struct FileTransferChannel {
    inner: Arc<FileTransferChannelInner>,
}

struct FileTransferChannelInner {
    /// Channel ID.
    channel_id: ChannelId,
    /// QUIC connection.
    #[allow(dead_code)]
    quic: Arc<QuicConnection>,
    /// Transfer parameters.
    params: FileTransferParams,
    /// Whether the channel is closed.
    closed: AtomicBool,
    /// Transfer stream (if active).
    stream: Mutex<Option<QuicStream>>,
}

impl FileTransferChannel {
    /// Create a new file transfer channel.
    ///
    /// Returns the channel and optional file metadata (for downloads).
    pub async fn new(
        channel_id: ChannelId,
        params: FileTransferParams,
        quic: Arc<QuicConnection>,
    ) -> Result<(Self, Option<FileTransferMetadata>)> {
        debug!(
            channel_id = %channel_id,
            path = %params.path,
            direction = ?params.direction,
            "Creating file transfer channel"
        );

        // For downloads, pre-fetch file metadata
        let metadata = if params.direction == TransferDirection::Download {
            // Get metadata for the file
            match std::fs::metadata(&params.path) {
                Ok(meta) => {
                    Some(FileTransferMetadata {
                        size: meta.len(),
                        mtime: meta.modified()
                            .map(|t| t.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs())
                            .unwrap_or(0),
                        mode: 0o644, // Default mode
                        blocks: Vec::new(), // Delta sync not implemented yet
                        is_dir: meta.is_dir(),
                        file_hash: None, // Hash computation not implemented yet
                    })
                }
                Err(e) => {
                    warn!(path = %params.path, error = %e, "Failed to get file metadata");
                    None
                }
            }
        } else {
            None
        };

        let inner = Arc::new(FileTransferChannelInner {
            channel_id,
            quic,
            params,
            closed: AtomicBool::new(false),
            stream: Mutex::new(None),
        });

        Ok((Self { inner }, metadata))
    }

    /// Get the channel ID.
    pub fn channel_id(&self) -> ChannelId {
        self.inner.channel_id
    }

    /// Handle an incoming stream for this channel.
    pub async fn handle_incoming_stream(&self, stream: QuicStream) -> Result<()> {
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(Error::ConnectionClosed);
        }

        // Store the stream for potential use
        *self.inner.stream.lock().await = Some(stream);

        // TODO: Implement actual file transfer using ChannelData messages
        warn!(channel_id = %self.inner.channel_id, "File transfer not fully implemented yet");

        Ok(())
    }

    /// Close the channel.
    pub async fn close(&self) {
        if self.inner.closed.swap(true, Ordering::SeqCst) {
            return;
        }

        // Close any active stream
        if let Some(mut stream) = self.inner.stream.lock().await.take() {
            stream.close();
        }

        info!(channel_id = %self.inner.channel_id, "File transfer channel closed");
    }

    /// Check if the channel is closed.
    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_transfer_channel_structure() {
        // Just verify the struct compiles
        fn _assert_clone<T: Clone>() {}
        _assert_clone::<FileTransferChannel>();
    }
}
