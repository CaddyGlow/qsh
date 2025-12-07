//! File transfer channel implementation.
//!
//! Manages file upload/download operations within a channel.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::Mutex;
use tracing::{debug, info};

use qsh_core::error::{Error, Result};
use qsh_core::protocol::{ChannelId, FileMetadataPayload, FileTransferParams};
use qsh_core::transport::{QuicConnection, QuicStream};

use crate::file::FileHandler;

/// File transfer channel managing upload/download operations.
#[derive(Clone)]
pub struct FileTransferChannel {
    inner: Arc<FileTransferChannelInner>,
}

struct FileTransferChannelInner {
    /// Channel ID.
    channel_id: ChannelId,
    /// QUIC connection.
    quic: Arc<QuicConnection>,
    /// File handler for actual I/O.
    file_handler: Arc<FileHandler<QuicConnection>>,
    /// Transfer parameters.
    #[allow(dead_code)]
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
    ) -> Result<(Self, Option<FileMetadataPayload>)> {
        debug!(
            channel_id = %channel_id,
            path = %params.path,
            direction = ?params.direction,
            "Creating file transfer channel"
        );

        // Get base directory (user's home or current directory)
        let base_dir = std::env::var("HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| {
                std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("/"))
            });

        let file_handler = Arc::new(FileHandler::new(quic.clone(), base_dir));

        // For downloads, we could pre-fetch metadata here
        // For now, metadata is fetched when the transfer actually starts
        let metadata = None;

        let inner = Arc::new(FileTransferChannelInner {
            channel_id,
            quic,
            file_handler,
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

        // The actual file transfer is handled by the FileHandler
        // which processes FileRequest/FileData/FileComplete messages

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

    /// Get access to the underlying file handler.
    pub fn file_handler(&self) -> &Arc<FileHandler<QuicConnection>> {
        &self.inner.file_handler
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
