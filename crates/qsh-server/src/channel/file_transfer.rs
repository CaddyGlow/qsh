//! File transfer channel implementation.
//!
//! Manages file upload/download operations within a channel.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt, AsyncSeekExt};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use qsh_core::error::{Error, Result};
use qsh_core::file::checksum::StreamingHasher;
use qsh_core::file::compress::{Compressor, Decompressor, is_compressed_extension};
use qsh_core::protocol::{
    ChannelData, ChannelId, ChannelPayload, DataFlags, FileAckData, FileCompleteData,
    FileDataData, FileErrorCode, FileTransferMetadata, FileTransferParams,
    FileTransferStatus, Message, TransferDirection,
};
use qsh_core::transport::{QuicConnection, QuicStream, StreamPair};

/// Chunk size for file data (32KB).
const FILE_CHUNK_SIZE: usize = 32 * 1024;

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
    /// Transfer parameters.
    params: FileTransferParams,
    /// Whether the channel is closed.
    closed: AtomicBool,
    /// Transfer stream (if active).
    stream: Mutex<Option<QuicStream>>,
    /// Bytes transferred.
    bytes_transferred: AtomicU64,
    /// File metadata (for downloads).
    metadata: Option<FileTransferMetadata>,
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

        let path = PathBuf::from(&params.path);

        // For downloads, pre-fetch file metadata
        // For uploads, check if existing file exists (for skip-if-unchanged)
        let metadata = match params.direction {
            TransferDirection::Download => {
                // Get metadata for the file to send
                Some(Self::get_file_metadata(&path, params.options.skip_if_unchanged).await?)
            }
            TransferDirection::Upload => {
                // Get metadata for existing file (if any) for skip-if-unchanged
                if params.options.skip_if_unchanged {
                    Self::get_file_metadata(&path, true).await.ok()
                } else {
                    None
                }
            }
        };

        let inner = Arc::new(FileTransferChannelInner {
            channel_id,
            quic,
            params,
            closed: AtomicBool::new(false),
            stream: Mutex::new(None),
            bytes_transferred: AtomicU64::new(0),
            metadata: metadata.clone(),
        });

        Ok((Self { inner }, metadata))
    }

    /// Get file metadata for a path.
    async fn get_file_metadata(path: &PathBuf, compute_hash: bool) -> Result<FileTransferMetadata> {
        let meta = fs::metadata(path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::FileTransfer {
                    message: format!("file not found: {}", path.display()),
                }
            } else {
                Error::FileTransfer {
                    message: format!("failed to get metadata for {}: {}", path.display(), e),
                }
            }
        })?;

        let mtime = meta
            .modified()
            .map(|t| t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs())
            .unwrap_or(0);

        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            meta.permissions().mode()
        };
        #[cfg(not(unix))]
        let mode = 0o644;

        // Compute file hash if requested
        let file_hash = if compute_hash && meta.is_file() {
            Some(Self::compute_file_hash(path).await?)
        } else {
            None
        };

        Ok(FileTransferMetadata {
            size: meta.len(),
            mtime,
            mode,
            blocks: Vec::new(), // Delta sync blocks computed separately
            is_dir: meta.is_dir(),
            file_hash,
            partial_checksum: None, // Computed on demand for resume
        })
    }

    /// Compute xxHash64 for a file.
    async fn compute_file_hash(path: &PathBuf) -> Result<u64> {
        let mut file = File::open(path).await.map_err(|e| Error::FileTransfer {
            message: format!("failed to open file for hashing: {}", e),
        })?;

        let mut hasher = StreamingHasher::new();
        let mut buf = vec![0u8; FILE_CHUNK_SIZE];

        loop {
            let n = file.read(&mut buf).await.map_err(|e| Error::FileTransfer {
                message: format!("failed to read file for hashing: {}", e),
            })?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }

        Ok(hasher.finish())
    }

    /// Compute xxHash64 for the first `len` bytes of a file.
    async fn compute_partial_hash(path: &PathBuf, len: u64) -> Result<u64> {
        let mut file = File::open(path).await.map_err(|e| Error::FileTransfer {
            message: format!("failed to open file for partial hashing: {}", e),
        })?;

        let mut hasher = StreamingHasher::new();
        let mut buf = vec![0u8; FILE_CHUNK_SIZE];
        let mut remaining = len;

        while remaining > 0 {
            let to_read = (remaining as usize).min(FILE_CHUNK_SIZE);
            let n = file.read(&mut buf[..to_read]).await.map_err(|e| Error::FileTransfer {
                message: format!("failed to read file for partial hashing: {}", e),
            })?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            remaining -= n as u64;
        }

        Ok(hasher.finish())
    }

    /// Get the channel ID.
    pub fn channel_id(&self) -> ChannelId {
        self.inner.channel_id
    }

    /// Handle an incoming stream for this channel.
    ///
    /// This is called when the client opens a bidirectional stream.
    /// It stores the stream and spawns the transfer task.
    pub async fn handle_incoming_stream(&self, stream: QuicStream) -> Result<()> {
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(Error::ConnectionClosed);
        }

        // Store the stream
        {
            let mut guard = self.inner.stream.lock().await;
            if guard.is_some() {
                return Err(Error::Protocol {
                    message: "file transfer channel already has a stream".to_string(),
                });
            }
            *guard = Some(stream);
        }

        // Run the transfer
        self.run().await
    }

    /// Run the file transfer.
    async fn run(&self) -> Result<()> {
        let result = match self.inner.params.direction {
            TransferDirection::Upload => self.handle_upload().await,
            TransferDirection::Download => self.handle_download().await,
        };

        // Mark as closed regardless of result
        self.inner.closed.store(true, Ordering::SeqCst);

        result
    }

    /// Handle an upload (receiving file from client).
    async fn handle_upload(&self) -> Result<()> {
        let path = PathBuf::from(&self.inner.params.path);
        let temp_path = path.with_extension("qscp.tmp");
        let resume_offset = self.inner.params.resume_from.unwrap_or(0);

        info!(
            channel_id = %self.inner.channel_id,
            path = %path.display(),
            resume_from = resume_offset,
            "Starting upload receive"
        );

        // Create parent directories if needed
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await.map_err(|e| Error::FileTransfer {
                message: format!("failed to create directory: {}", e),
            })?;
        }

        // Handle resume: check if temp file exists and matches resume offset
        let (mut file, mut hasher, mut total_bytes) = if resume_offset > 0 {
            // Try to open existing temp file for resume
            if let Ok(meta) = fs::metadata(&temp_path).await {
                if meta.len() >= resume_offset {
                    // Hash the existing partial data
                    let partial_hash = Self::compute_partial_hash(&temp_path, resume_offset).await?;
                    debug!(
                        channel_id = %self.inner.channel_id,
                        partial_hash = %format!("{:016x}", partial_hash),
                        resume_offset = resume_offset,
                        "Resuming upload from existing partial file"
                    );

                    // Open for append and seek
                    let mut file = OpenOptions::new()
                        .write(true)
                        .open(&temp_path)
                        .await
                        .map_err(|e| Error::FileTransfer {
                            message: format!("failed to open temp file for resume: {}", e),
                        })?;
                    file.seek(std::io::SeekFrom::Start(resume_offset))
                        .await
                        .map_err(|e| Error::FileTransfer {
                            message: format!("failed to seek in temp file: {}", e),
                        })?;

                    // Initialize hasher with partial data
                    let mut partial_file = File::open(&temp_path).await.map_err(|e| Error::FileTransfer {
                        message: format!("failed to open temp file for hashing: {}", e),
                    })?;
                    let mut hasher = StreamingHasher::new();
                    let mut buf = vec![0u8; FILE_CHUNK_SIZE];
                    let mut remaining = resume_offset;
                    while remaining > 0 {
                        let to_read = (remaining as usize).min(FILE_CHUNK_SIZE);
                        let n = partial_file.read(&mut buf[..to_read]).await.map_err(|e| Error::FileTransfer {
                            message: format!("failed to read partial file: {}", e),
                        })?;
                        if n == 0 {
                            break;
                        }
                        hasher.update(&buf[..n]);
                        remaining -= n as u64;
                    }

                    (file, hasher, resume_offset)
                } else {
                    // Partial file too small, start fresh
                    warn!(
                        channel_id = %self.inner.channel_id,
                        "Partial file smaller than resume offset, starting fresh"
                    );
                    let file = OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(&temp_path)
                        .await
                        .map_err(|e| Error::FileTransfer {
                            message: format!("failed to create temp file: {}", e),
                        })?;
                    (file, StreamingHasher::new(), 0)
                }
            } else {
                // No partial file exists, start fresh
                let file = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(&temp_path)
                    .await
                    .map_err(|e| Error::FileTransfer {
                        message: format!("failed to create temp file: {}", e),
                    })?;
                (file, StreamingHasher::new(), 0)
            }
        } else {
            // No resume, create fresh temp file
            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&temp_path)
                .await
                .map_err(|e| Error::FileTransfer {
                    message: format!("failed to create temp file: {}", e),
                })?;
            (file, StreamingHasher::new(), 0)
        };

        let mut last_ack_bytes: u64 = total_bytes;

        // Create decompressor for compressed data
        let decompressor = Decompressor::new();

        // Get stream
        let mut stream_guard = self.inner.stream.lock().await;
        let stream = stream_guard.as_mut().ok_or_else(|| Error::Protocol {
            message: "no stream for file transfer".to_string(),
        })?;

        loop {
            let msg: Message = stream.recv().await?;

            match msg {
                Message::ChannelDataMsg(ChannelData {
                    channel_id,
                    payload: ChannelPayload::FileData(data),
                }) if channel_id == self.inner.channel_id => {
                    // Seek to offset if not sequential
                    if data.offset != total_bytes {
                        file.seek(std::io::SeekFrom::Start(data.offset))
                            .await
                            .map_err(|e| Error::FileTransfer {
                                message: format!("failed to seek: {}", e),
                            })?;
                    }

                    // Decompress data if needed
                    let write_data = if data.flags.compressed {
                        decompressor.decompress(&data.data)?
                    } else {
                        data.data
                    };

                    // Write data
                    file.write_all(&write_data).await.map_err(|e| {
                        let code = if e.kind() == std::io::ErrorKind::StorageFull {
                            FileErrorCode::DiskFull
                        } else {
                            FileErrorCode::IoError
                        };
                        self.send_error_sync(stream, code, &e.to_string());
                        Error::FileTransfer {
                            message: format!("failed to write: {}", e),
                        }
                    })?;

                    hasher.update(&write_data);
                    total_bytes = data.offset + write_data.len() as u64;
                    self.inner.bytes_transferred.store(total_bytes, Ordering::SeqCst);

                    // Send ack every 1MB
                    if total_bytes - last_ack_bytes >= 1024 * 1024 {
                        self.send_ack(stream, total_bytes).await?;
                        last_ack_bytes = total_bytes;
                    }

                    // Check for final block
                    if data.flags.final_block {
                        break;
                    }
                }

                Message::ChannelDataMsg(ChannelData {
                    channel_id,
                    payload: ChannelPayload::FileComplete(complete),
                }) if channel_id == self.inner.channel_id => {
                    // Client sent early completion (skip-if-unchanged)
                    if complete.status == FileTransferStatus::AlreadyUpToDate {
                        info!(
                            channel_id = %self.inner.channel_id,
                            "File already up to date, skipping transfer"
                        );
                        // Remove temp file if created
                        let _ = fs::remove_file(&temp_path).await;
                        return Ok(());
                    }
                    break;
                }

                Message::ChannelDataMsg(ChannelData {
                    channel_id,
                    payload: ChannelPayload::FileError(err),
                }) if channel_id == self.inner.channel_id => {
                    warn!(
                        channel_id = %self.inner.channel_id,
                        code = ?err.code,
                        message = %err.message,
                        "Client sent file error"
                    );
                    let _ = fs::remove_file(&temp_path).await;
                    return Err(Error::FileTransfer {
                        message: format!("client error: {}", err.message),
                    });
                }

                _ => {
                    warn!(
                        channel_id = %self.inner.channel_id,
                        msg = ?msg,
                        "Unexpected message during upload"
                    );
                }
            }
        }

        // Flush and sync
        file.flush().await.map_err(|e| Error::FileTransfer {
            message: format!("failed to flush: {}", e),
        })?;
        file.sync_all().await.map_err(|e| Error::FileTransfer {
            message: format!("failed to sync: {}", e),
        })?;
        drop(file);

        let checksum = hasher.finish();

        // Rename temp to final
        fs::rename(&temp_path, &path).await.map_err(|e| Error::FileTransfer {
            message: format!("failed to rename temp file: {}", e),
        })?;

        // Preserve mode if requested
        #[cfg(unix)]
        if self.inner.params.options.preserve_mode {
            // Mode preservation would be handled by client sending the mode
            // For now, we keep the default
        }

        // Send completion
        self.send_complete(stream, checksum, total_bytes, FileTransferStatus::Normal)
            .await?;

        info!(
            channel_id = %self.inner.channel_id,
            path = %path.display(),
            bytes = total_bytes,
            checksum = %format!("{:016x}", checksum),
            "Upload complete"
        );

        Ok(())
    }

    /// Handle a download (sending file to client).
    async fn handle_download(&self) -> Result<()> {
        let path = PathBuf::from(&self.inner.params.path);

        info!(
            channel_id = %self.inner.channel_id,
            path = %path.display(),
            "Starting download send"
        );

        // Open file for reading
        let mut file = File::open(&path).await.map_err(|e| Error::FileTransfer {
            message: format!("failed to open file: {}", e),
        })?;

        let metadata = fs::metadata(&path).await.map_err(|e| Error::FileTransfer {
            message: format!("failed to get metadata: {}", e),
        })?;
        let file_size = metadata.len();

        // Handle resume
        let start_offset = self.inner.params.resume_from.unwrap_or(0);
        if start_offset > 0 {
            file.seek(std::io::SeekFrom::Start(start_offset))
                .await
                .map_err(|e| Error::FileTransfer {
                    message: format!("failed to seek for resume: {}", e),
                })?;
        }

        // Determine if we should compress
        let use_compression = self.inner.params.options.compress
            && !is_compressed_extension(&self.inner.params.path);
        let compressor = if use_compression {
            Some(Compressor::with_default_level())
        } else {
            None
        };

        let mut hasher = StreamingHasher::new();
        let mut buf = vec![0u8; FILE_CHUNK_SIZE];
        let mut offset = start_offset;

        // Get stream
        let mut stream_guard = self.inner.stream.lock().await;
        let stream = stream_guard.as_mut().ok_or_else(|| Error::Protocol {
            message: "no stream for file transfer".to_string(),
        })?;

        loop {
            let n = file.read(&mut buf).await.map_err(|e| Error::FileTransfer {
                message: format!("failed to read file: {}", e),
            })?;

            if n == 0 {
                break;
            }

            let data = &buf[..n];
            hasher.update(data);

            let is_final = offset + n as u64 >= file_size;

            // Compress data if enabled
            let (send_data, is_compressed) = if let Some(ref comp) = compressor {
                if comp.should_compress(data) {
                    (comp.compress(data)?, true)
                } else {
                    (data.to_vec(), false)
                }
            } else {
                (data.to_vec(), false)
            };

            // Send file data
            let msg = Message::ChannelDataMsg(ChannelData {
                channel_id: self.inner.channel_id,
                payload: ChannelPayload::FileData(FileDataData {
                    offset,
                    data: send_data,
                    flags: DataFlags {
                        compressed: is_compressed,
                        final_block: is_final,
                        block_ref: false,
                    },
                }),
            });

            stream.send(&msg).await?;

            offset += n as u64;
            self.inner.bytes_transferred.store(offset, Ordering::SeqCst);
        }

        let checksum = hasher.finish();

        // Send completion
        self.send_complete(stream, checksum, offset - start_offset, FileTransferStatus::Normal)
            .await?;

        info!(
            channel_id = %self.inner.channel_id,
            path = %path.display(),
            bytes = offset - start_offset,
            checksum = %format!("{:016x}", checksum),
            "Download complete"
        );

        Ok(())
    }

    /// Send an acknowledgment.
    async fn send_ack(&self, stream: &mut QuicStream, bytes_received: u64) -> Result<()> {
        let msg = Message::ChannelDataMsg(ChannelData {
            channel_id: self.inner.channel_id,
            payload: ChannelPayload::FileAck(FileAckData { bytes_received }),
        });
        stream.send(&msg).await
    }

    /// Send completion message.
    async fn send_complete(
        &self,
        stream: &mut QuicStream,
        checksum: u64,
        total_bytes: u64,
        status: FileTransferStatus,
    ) -> Result<()> {
        let msg = Message::ChannelDataMsg(ChannelData {
            channel_id: self.inner.channel_id,
            payload: ChannelPayload::FileComplete(FileCompleteData {
                checksum,
                total_bytes,
                status,
            }),
        });
        stream.send(&msg).await
    }

    /// Send error message (sync version for error paths).
    fn send_error_sync(&self, _stream: &mut QuicStream, _code: FileErrorCode, _message: &str) {
        // Note: In error paths we can't easily send async messages
        // The error will be propagated through the return value
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

    /// Get bytes transferred.
    pub fn bytes_transferred(&self) -> u64 {
        self.inner.bytes_transferred.load(Ordering::SeqCst)
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
