//! Server-side file transfer handler.
//!
//! Handles FileRequest messages from clients by reading/writing files
//! and sending data/metadata.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use qsh_core::error::{Error, Result};
use qsh_core::file::{
    BLOCK_SIZE, BlockHasher, Compressor, Decompressor, DeltaEncoder, DeltaOp, DeltaSignature,
    hash_xxh64,
};
use qsh_core::protocol::{
    BlockChecksum, DataFlags, FileAckPayload, FileCompletePayload, FileDataPayload, FileErrorCode,
    FileErrorPayload, FileMetadataPayload, FileRequestPayload, Message, TransferDirection,
};
use qsh_core::transport::{Connection, StreamPair, StreamType};

/// Maximum concurrent file transfers per session.
const MAX_TRANSFERS: usize = 16;

/// Buffer size for file I/O.
const FILE_BUFFER_SIZE: usize = 256 * 1024;

/// Server-side file transfer handler.
pub struct FileHandler<C: Connection> {
    /// Connection to the client.
    connection: Arc<C>,
    /// Active transfers keyed by transfer_id.
    active_transfers: Arc<Mutex<HashMap<u64, TransferInfo>>>,
    /// Base directory for file operations (sandbox).
    base_dir: PathBuf,
}

/// Information about an active transfer.
struct TransferInfo {
    path: PathBuf,
    direction: TransferDirection,
    total_size: u64,
    bytes_transferred: u64,
}

/// Directory entry used for recursive transfers.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DirEntry {
    path: String,
    is_dir: bool,
    size: u64,
    mtime: u64,
    mode: u32,
}

impl<C: Connection + 'static> FileHandler<C> {
    /// Create a new file handler.
    pub fn new(connection: Arc<C>, base_dir: PathBuf) -> Self {
        let base_dir = base_dir.canonicalize().unwrap_or_else(|_| base_dir);
        Self {
            connection,
            active_transfers: Arc::new(Mutex::new(HashMap::new())),
            base_dir,
        }
    }

    /// Resolve and validate a path within the base directory.
    fn resolve_path(&self, path: &str) -> Result<PathBuf> {
        let input = Path::new(path);

        // Handle absolute vs relative paths without requiring the leaf to exist
        let resolved = if input.is_absolute() {
            Self::normalize(input)
        } else {
            Self::normalize(&self.base_dir.join(input))
        };

        // Security: ensure path is within base_dir
        if !resolved.starts_with(&self.base_dir) {
            return Err(Error::FileTransfer {
                message: format!("path escapes base directory: {}", input.display()),
            });
        }

        Ok(resolved)
    }

    /// Normalize a path by removing `.` and `..` components without hitting the filesystem.
    fn normalize(path: &Path) -> PathBuf {
        let mut normalized = PathBuf::new();

        for comp in path.components() {
            match comp {
                Component::ParentDir => {
                    normalized.pop();
                }
                Component::CurDir => {}
                Component::RootDir | Component::Prefix(_) | Component::Normal(_) => {
                    normalized.push(comp.as_os_str());
                }
            }
        }

        normalized
    }

    /// Handle a file transfer stream.
    pub async fn handle_stream(&self, stream_type: StreamType, stream: impl StreamPair + 'static) {
        let transfer_id = match stream_type {
            StreamType::FileTransfer(id) => id,
            _ => {
                warn!("Unexpected stream type: {:?}", stream_type);
                return;
            }
        };

        let mut stream = stream;
        match stream.recv().await {
            Ok(Message::FileRequest(request)) => {
                if let Err(e) = self.handle_request(request, stream).await {
                    error!(transfer_id, error = %e, "File request handling failed");
                }
            }
            Ok(other) => {
                warn!(transfer_id, "Expected FileRequest, got: {:?}", other);
            }
            Err(e) => {
                error!(transfer_id, error = %e, "Failed to read file request");
            }
        }
    }

    /// Handle a file request.
    pub async fn handle_request(
        &self,
        request: FileRequestPayload,
        mut stream: impl StreamPair + 'static,
    ) -> Result<()> {
        let transfer_id = request.transfer_id;

        debug!(
            transfer_id,
            path = %request.path,
            direction = ?request.direction,
            "Handling file request"
        );

        // Check limits
        {
            let transfers = self.active_transfers.lock().await;
            if transfers.len() >= MAX_TRANSFERS {
                let error = Message::FileError(FileErrorPayload {
                    transfer_id,
                    code: FileErrorCode::IoError,
                    message: "max concurrent transfers exceeded".into(),
                });
                stream.send(&error).await?;
                return Ok(());
            }
        }

        // Resolve path
        let resolved_path = match self.resolve_path(&request.path) {
            Ok(p) => p,
            Err(e) => {
                let error = Message::FileError(FileErrorPayload {
                    transfer_id,
                    code: FileErrorCode::InvalidPath,
                    message: e.to_string(),
                });
                stream.send(&error).await?;
                return Ok(());
            }
        };

        match request.direction {
            TransferDirection::Download => {
                self.handle_download(transfer_id, resolved_path, request, stream)
                    .await
            }
            TransferDirection::Upload => {
                self.handle_upload(transfer_id, resolved_path, request, stream)
                    .await
            }
        }
    }

    /// Handle a download request (client downloads from server).
    async fn handle_download(
        &self,
        transfer_id: u64,
        path: PathBuf,
        request: FileRequestPayload,
        mut stream: impl StreamPair + 'static,
    ) -> Result<()> {
        // Check file exists
        let metadata = match fs::metadata(&path) {
            Ok(m) => m,
            Err(e) => {
                let code = if e.kind() == std::io::ErrorKind::NotFound {
                    FileErrorCode::NotFound
                } else if e.kind() == std::io::ErrorKind::PermissionDenied {
                    FileErrorCode::PermissionDenied
                } else {
                    FileErrorCode::IoError
                };
                let error = Message::FileError(FileErrorPayload {
                    transfer_id,
                    code,
                    message: e.to_string(),
                });
                stream.send(&error).await?;
                return Ok(());
            }
        };

        if metadata.is_dir() {
            if !request.options.recursive {
                let error = Message::FileError(FileErrorPayload {
                    transfer_id,
                    code: FileErrorCode::IsDirectory,
                    message: "path is a directory (use -r for recursive)".into(),
                });
                stream.send(&error).await?;
                return Ok(());
            }

            let entries = self.collect_dir_entries(&path)?;
            let listing = serde_json::to_vec(&entries).map_err(|e| Error::FileTransfer {
                message: format!("failed to serialize directory listing: {}", e),
            })?;
            let listing_len = listing.len() as u64;
            let checksum = hash_xxh64(&listing);
            let mtime = metadata
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let mode = metadata.mode();

            let metadata_msg = Message::FileMetadata(FileMetadataPayload {
                transfer_id,
                size: listing_len,
                mtime,
                mode,
                blocks: Vec::new(),
                is_dir: true,
            });
            stream.send(&metadata_msg).await?;

            let listing_msg = Message::FileData(FileDataPayload {
                transfer_id,
                offset: 0,
                data: listing,
                flags: DataFlags {
                    compressed: false,
                    final_block: true,
                    block_ref: false,
                },
            });
            stream.send(&listing_msg).await?;

            let complete = Message::FileComplete(FileCompletePayload {
                transfer_id,
                checksum,
                total_bytes: listing_len,
            });
            stream.send(&complete).await?;
            return Ok(());
        }

        let file_size = metadata.len();
        let mtime = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mode = metadata.mode();

        // Compute block checksums if delta enabled
        let blocks = if request.options.delta {
            match self.compute_block_checksums(&path, file_size).await {
                Ok(b) => b,
                Err(e) => {
                    warn!(transfer_id, error = %e, "Failed to compute checksums for download");
                    let error = Message::FileError(FileErrorPayload {
                        transfer_id,
                        code: FileErrorCode::IoError,
                        message: e.to_string(),
                    });
                    stream.send(&error).await?;
                    return Ok(());
                }
            }
        } else {
            Vec::new()
        };

        // Send metadata
        let metadata_msg = Message::FileMetadata(FileMetadataPayload {
            transfer_id,
            size: file_size,
            mtime,
            mode,
            blocks,
            is_dir: false,
        });
        stream.send(&metadata_msg).await?;

        // Register transfer
        {
            let mut transfers = self.active_transfers.lock().await;
            transfers.insert(
                transfer_id,
                TransferInfo {
                    path: path.clone(),
                    direction: TransferDirection::Download,
                    total_size: file_size,
                    bytes_transferred: 0,
                },
            );
        }

        // Spawn sender task
        let active_transfers = Arc::clone(&self.active_transfers);
        let compress = request.options.compress;
        let resume_from = request.resume_from.unwrap_or(0);
        let chunk = request.chunk;
        let use_delta = request.options.delta
            && !request.client_blocks.is_empty()
            && request.resume_from.is_none()
            && chunk.is_none();
        let client_blocks = request.client_blocks.clone();

        tokio::spawn(async move {
            let result = if use_delta {
                Self::send_file_delta(
                    transfer_id,
                    path,
                    file_size,
                    client_blocks,
                    compress,
                    stream,
                )
                .await
            } else {
                Self::send_file(
                    transfer_id,
                    path,
                    file_size,
                    resume_from,
                    chunk,
                    compress,
                    stream,
                )
                .await
            };

            if let Err(e) = result {
                error!(transfer_id, error = %e, "File send failed");
            }

            let mut transfers = active_transfers.lock().await;
            transfers.remove(&transfer_id);
        });

        Ok(())
    }

    /// Compute block checksums for delta transfer.
    async fn compute_block_checksums(&self, path: &Path, _size: u64) -> Result<Vec<BlockChecksum>> {
        let path = path.to_path_buf();

        tokio::task::spawn_blocking(move || {
            let mut file = File::open(&path).map_err(|e| Error::FileTransfer {
                message: format!("failed to open file: {}", e),
            })?;

            let mut checksums = Vec::new();
            let mut buf = vec![0u8; BLOCK_SIZE];
            let mut offset = 0u64;

            loop {
                let n = file.read(&mut buf).map_err(|e| Error::FileTransfer {
                    message: format!("failed to read file: {}", e),
                })?;
                if n == 0 {
                    break;
                }

                let weak = BlockHasher::compute_weak(&buf[..n]);
                let strong = BlockHasher::compute_strong(&buf[..n]);

                checksums.push(BlockChecksum {
                    offset,
                    weak,
                    strong,
                });

                offset += n as u64;
            }

            Ok(checksums)
        })
        .await
        .map_err(|e| Error::FileTransfer {
            message: format!("checksum task failed: {}", e),
        })?
    }

    /// Collect directory entries for recursive transfer.
    fn collect_dir_entries(&self, root: &Path) -> Result<Vec<DirEntry>> {
        let mut entries = Vec::new();
        let root = root.to_path_buf();
        let mut stack = vec![root.clone()];

        while let Some(dir) = stack.pop() {
            for entry in fs::read_dir(&dir).map_err(|e| Error::FileTransfer {
                message: format!("failed to read directory {}: {}", dir.display(), e),
            })? {
                let entry = entry.map_err(|e| Error::FileTransfer {
                    message: format!("failed to read directory entry: {}", e),
                })?;
                let path = entry.path();
                let rel = path
                    .strip_prefix(&root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .to_string();
                let metadata = entry.metadata().map_err(|e| Error::FileTransfer {
                    message: format!("failed to stat {}: {}", path.display(), e),
                })?;
                let mtime = metadata
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                if metadata.is_dir() {
                    entries.push(DirEntry {
                        path: rel.clone(),
                        is_dir: true,
                        size: 0,
                        mtime,
                        mode: metadata.mode(),
                    });
                    stack.push(path);
                } else if metadata.is_file() {
                    entries.push(DirEntry {
                        path: rel,
                        is_dir: false,
                        size: metadata.len(),
                        mtime,
                        mode: metadata.mode(),
                    });
                }
            }
        }

        // Ensure deterministic order
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(entries)
    }

    /// Send file data to client.
    async fn send_file(
        transfer_id: u64,
        path: PathBuf,
        file_size: u64,
        resume_from: u64,
        chunk: Option<qsh_core::protocol::ChunkSpec>,
        compress: bool,
        mut stream: impl StreamPair,
    ) -> Result<()> {
        let (start, end) = if let Some(ref c) = chunk {
            (c.offset, (c.offset + c.length).min(file_size))
        } else {
            (resume_from, file_size)
        };

        let mut file = std::fs::File::open(&path).map_err(|e| Error::FileTransfer {
            message: format!("failed to open file: {}", e),
        })?;

        file.seek(SeekFrom::Start(start))
            .map_err(|e| Error::FileTransfer {
                message: format!("seek failed: {}", e),
            })?;

        let buf_size = FILE_BUFFER_SIZE.min((end - start).max(1) as usize);
        let mut buf = vec![0u8; buf_size];
        let mut offset = start;
        let mut total_hash = 0u64;

        let compressor = if compress {
            Some(Compressor::with_default_level())
        } else {
            None
        };

        while offset < end {
            let to_read = buf.len().min((end - offset) as usize);
            let n = file
                .read(&mut buf[..to_read])
                .map_err(|e| Error::FileTransfer {
                    message: format!("read failed: {}", e),
                })?;
            if n == 0 {
                break;
            }

            let data = &buf[..n];
            total_hash ^= hash_xxh64(data);

            let (send_data, compressed) = if let Some(ref comp) = compressor {
                if comp.should_compress(data) {
                    match comp.compress(data) {
                        Ok(c) if c.len() < data.len() => (c, true),
                        _ => (data.to_vec(), false),
                    }
                } else {
                    (data.to_vec(), false)
                }
            } else {
                (data.to_vec(), false)
            };

            let current_offset = offset;
            offset += n as u64;
            let is_final = offset >= end;

            let msg = Message::FileData(FileDataPayload {
                transfer_id,
                offset: current_offset,
                data: send_data,
                flags: DataFlags {
                    compressed,
                    final_block: is_final,
                    block_ref: false,
                },
            });
            stream.send(&msg).await?;

            // Wait for ack periodically (every ~1MB)
            if offset % (1024 * 1024) < FILE_BUFFER_SIZE as u64 || is_final {
                // Could wait for FileAck here for flow control
            }
        }

        // Send complete
        let complete = Message::FileComplete(FileCompletePayload {
            transfer_id,
            checksum: total_hash,
            total_bytes: offset - start,
        });
        stream.send(&complete).await?;

        info!(
            transfer_id,
            bytes = offset - start,
            "File download complete"
        );
        Ok(())
    }

    /// Send file using delta operations based on client block checksums.
    async fn send_file_delta(
        transfer_id: u64,
        path: PathBuf,
        file_size: u64,
        client_blocks: Vec<BlockChecksum>,
        compress: bool,
        mut stream: impl StreamPair,
    ) -> Result<()> {
        let signature = DeltaSignature::new(&client_blocks, BLOCK_SIZE);
        let mut encoder = DeltaEncoder::new(signature);

        let mut file = std::fs::File::open(&path).map_err(|e| Error::FileTransfer {
            message: format!("failed to open file: {}", e),
        })?;

        let mut buf = vec![0u8; FILE_BUFFER_SIZE];
        let mut total_hash = 0u64;
        let mut out_offset = 0u64;
        let mut bytes_sent = 0u64;
        let mut compressor = if compress {
            Some(Compressor::with_default_level())
        } else {
            None
        };

        loop {
            let n = file.read(&mut buf).map_err(|e| Error::FileTransfer {
                message: format!("read failed: {}", e),
            })?;
            if n == 0 {
                break;
            }

            total_hash ^= hash_xxh64(&buf[..n]);
            encoder.process(&buf[..n]);

            let ops = encoder.take_ops();
            Self::send_delta_ops(
                transfer_id,
                &mut stream,
                &mut compressor,
                ops,
                &mut out_offset,
                false,
                &mut bytes_sent,
            )
            .await?;
        }

        let final_ops = encoder.finish();
        Self::send_delta_ops(
            transfer_id,
            &mut stream,
            &mut compressor,
            final_ops,
            &mut out_offset,
            true,
            &mut bytes_sent,
        )
        .await?;

        if out_offset != file_size {
            warn!(
                transfer_id,
                expected = file_size,
                produced = out_offset,
                "Delta output size mismatch"
            );
        }

        let complete = Message::FileComplete(FileCompletePayload {
            transfer_id,
            checksum: total_hash,
            total_bytes: file_size,
        });
        stream.send(&complete).await?;

        info!(
            transfer_id,
            bytes = file_size,
            sent = bytes_sent,
            "File download complete (delta)"
        );

        Ok(())
    }

    /// Send delta operations as file data messages.
    async fn send_delta_ops(
        transfer_id: u64,
        stream: &mut impl StreamPair,
        compressor: &mut Option<Compressor>,
        ops: Vec<DeltaOp>,
        out_offset: &mut u64,
        final_batch: bool,
        bytes_sent: &mut u64,
    ) -> Result<()> {
        if ops.is_empty() {
            return Ok(());
        }

        let op_len = ops.len();
        for (i, op) in ops.into_iter().enumerate() {
            let is_last = final_batch && i == op_len - 1;

            let (data, flags, advance_by, data_len) = match op {
                DeltaOp::Copy {
                    source_offset,
                    length,
                } => {
                    let mut ref_data = Vec::with_capacity(16);
                    ref_data.extend_from_slice(&source_offset.to_le_bytes());
                    ref_data.extend_from_slice(&length.to_le_bytes());
                    (
                        ref_data,
                        DataFlags {
                            compressed: false,
                            final_block: is_last,
                            block_ref: true,
                        },
                        length,
                        16usize,
                    )
                }
                DeltaOp::Literal { data } => {
                    let (send, compressed) = if let Some(comp) = compressor.as_ref() {
                        if comp.should_compress(&data) {
                            match comp.compress(&data) {
                                Ok(c) if c.len() < data.len() => (c, true),
                                _ => (data.clone(), false),
                            }
                        } else {
                            (data.clone(), false)
                        }
                    } else {
                        (data.clone(), false)
                    };

                    let data_len = send.len();

                    (
                        send,
                        DataFlags {
                            compressed,
                            final_block: is_last,
                            block_ref: false,
                        },
                        data.len() as u64,
                        data_len,
                    )
                }
            };

            let msg = Message::FileData(FileDataPayload {
                transfer_id,
                offset: *out_offset,
                data,
                flags,
            });
            stream.send(&msg).await?;

            *bytes_sent += data_len as u64;
            *out_offset = out_offset.saturating_add(advance_by);
        }

        Ok(())
    }

    /// Handle an upload request (client uploads to server).
    async fn handle_upload(
        &self,
        transfer_id: u64,
        path: PathBuf,
        request: FileRequestPayload,
        mut stream: impl StreamPair + 'static,
    ) -> Result<()> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                let error = Message::FileError(FileErrorPayload {
                    transfer_id,
                    code: FileErrorCode::IoError,
                    message: format!(
                        "failed to create parent directory {}: {}",
                        parent.display(),
                        e
                    ),
                });
                stream.send(&error).await?;
                return Ok(());
            }
        }

        // Check if path exists (for delta)
        let (existing_size, existing_blocks) = if path.exists() && request.options.delta {
            match fs::metadata(&path) {
                Ok(m) if m.is_file() => {
                    let len = m.len();
                    match self.compute_block_checksums(&path, len).await {
                        Ok(blocks) => (len, blocks),
                        Err(e) => {
                            warn!(transfer_id, error = %e, "Failed to compute existing file checksums for upload");
                            let _ = Self::send_transfer_error(
                                transfer_id,
                                FileErrorCode::IoError,
                                format!("failed to read existing file for delta: {}", e),
                                &mut stream,
                            )
                            .await;
                            return Ok(());
                        }
                    }
                }
                _ => (0, Vec::new()),
            }
        } else {
            (0, Vec::new())
        };

        // Send metadata (with block checksums for delta)
        let metadata_msg = Message::FileMetadata(FileMetadataPayload {
            transfer_id,
            size: existing_size,
            mtime: 0,
            mode: 0o644,
            blocks: existing_blocks,
            is_dir: false,
        });
        stream.send(&metadata_msg).await?;

        // Register transfer
        {
            let mut transfers = self.active_transfers.lock().await;
            transfers.insert(
                transfer_id,
                TransferInfo {
                    path: path.clone(),
                    direction: TransferDirection::Upload,
                    total_size: 0, // Unknown until complete
                    bytes_transferred: 0,
                },
            );
        }

        // Spawn receiver task
        let active_transfers = Arc::clone(&self.active_transfers);
        let decompress = request.options.compress;

        tokio::spawn(async move {
            if let Err(e) = Self::receive_file(transfer_id, path, decompress, stream).await {
                error!(transfer_id, error = %e, "File receive failed");
            }

            let mut transfers = active_transfers.lock().await;
            transfers.remove(&transfer_id);
        });

        Ok(())
    }

    /// Receive file data from client.
    async fn receive_file(
        transfer_id: u64,
        path: PathBuf,
        decompress: bool,
        mut stream: impl StreamPair,
    ) -> Result<()> {
        let decompressor = if decompress {
            Some(Decompressor::new())
        } else {
            None
        };

        // Existing file (for delta block references)
        let mut source_file = File::open(&path).ok();

        // Create temporary file
        let temp_path = path.with_extension("qsh-tmp");
        let mut file = File::create(&temp_path).map_err(|e| Error::FileTransfer {
            message: format!("failed to create file: {}", e),
        })?;
        info!(
            transfer_id,
            tmp = %temp_path.display(),
            dest = %path.display(),
            "Receiving upload into temporary file"
        );

        let mut total_hash = 0u64;
        let mut bytes_received = 0u64;
        let mut saw_final_block = false;

        loop {
            match stream.recv().await {
                Ok(Message::FileData(data)) if data.transfer_id == transfer_id => {
                    let content = if data.flags.block_ref {
                        if data.flags.compressed {
                            let _ = fs::remove_file(&temp_path);
                            return Err(Error::FileTransfer {
                                message: "block references cannot be compressed".into(),
                            });
                        }
                        if data.data.len() != 16 {
                            let _ = fs::remove_file(&temp_path);
                            return Err(Error::FileTransfer {
                                message: "invalid block reference".into(),
                            });
                        }

                        let mut offset_bytes = [0u8; 8];
                        offset_bytes.copy_from_slice(&data.data[..8]);
                        let mut len_bytes = [0u8; 8];
                        len_bytes.copy_from_slice(&data.data[8..]);

                        let source_offset = u64::from_le_bytes(offset_bytes);
                        let length = u64::from_le_bytes(len_bytes) as usize;

                        let src = source_file.as_mut().ok_or_else(|| Error::FileTransfer {
                            message: "received block reference but no source file exists".into(),
                        })?;

                        src.seek(SeekFrom::Start(source_offset)).map_err(|e| {
                            Error::FileTransfer {
                                message: format!("seek source failed: {}", e),
                            }
                        })?;

                        let mut buf = vec![0u8; length];
                        let n = src.read(&mut buf).map_err(|e| Error::FileTransfer {
                            message: format!("read source failed: {}", e),
                        })?;
                        if n < length {
                            let _ = fs::remove_file(&temp_path);
                            return Err(Error::FileTransfer {
                                message: format!(
                                    "block reference out of bounds at {}",
                                    source_offset
                                ),
                            });
                        }
                        buf
                    } else if data.flags.compressed {
                        if let Some(ref decomp) = decompressor {
                            decomp.decompress(&data.data)?
                        } else {
                            data.data
                        }
                    } else {
                        data.data
                    };

                    file.seek(SeekFrom::Start(data.offset))
                        .map_err(|e| Error::FileTransfer {
                            message: format!("seek failed: {}", e),
                        })?;

                    file.write_all(&content).map_err(|e| Error::FileTransfer {
                        message: format!("write failed: {}", e),
                    })?;

                    total_hash ^= hash_xxh64(&content);
                    bytes_received += content.len() as u64;

                    // Send ack periodically
                    if bytes_received % (1024 * 1024) < FILE_BUFFER_SIZE as u64
                        || data.flags.final_block
                    {
                        let ack = Message::FileAck(FileAckPayload {
                            transfer_id,
                            bytes_received,
                        });
                        stream.send(&ack).await?;
                    }

                    saw_final_block |= data.flags.final_block;
                }
                Ok(Message::FileComplete(complete)) if complete.transfer_id == transfer_id => {
                    // Verify checksum
                    if complete.checksum != total_hash {
                        warn!(
                            transfer_id,
                            expected = complete.checksum,
                            got = total_hash,
                            "Checksum mismatch"
                        );
                        let _ = fs::remove_file(&temp_path);
                        let _ = Self::send_transfer_error(
                            transfer_id,
                            FileErrorCode::ChecksumMismatch,
                            "checksum mismatch on upload".into(),
                            &mut stream,
                        )
                        .await;
                        warn!(
                            transfer_id,
                            tmp = %temp_path.display(),
                            "Temporary upload file removed after checksum mismatch"
                        );
                        return Err(Error::FileTransfer {
                            message: "checksum mismatch".into(),
                        });
                    }
                    if !saw_final_block {
                        warn!(
                            transfer_id,
                            "FileComplete received without final data block"
                        );
                    }
                    break;
                }
                Ok(Message::FileError(error)) if error.transfer_id == transfer_id => {
                    warn!(transfer_id, code = ?error.code, msg = %error.message, "Transfer error from client");
                    let _ = fs::remove_file(&temp_path);
                    return Err(Error::FileTransfer {
                        message: error.message,
                    });
                }
                Ok(other) => {
                    warn!(transfer_id, "Unexpected message: {:?}", other);
                }
                Err(e) => {
                    error!(
                        transfer_id,
                        error = %e,
                        bytes_received,
                        saw_final_block,
                        "Stream error during upload"
                    );
                    if let Err(send_err) = Self::send_transfer_error(
                        transfer_id,
                        FileErrorCode::IoError,
                        format!("stream error during upload: {}", e),
                        &mut stream,
                    )
                    .await
                    {
                        warn!(
                            transfer_id,
                            error = %send_err,
                            "Failed to notify client about upload stream error"
                        );
                    }
                    warn!(
                        transfer_id,
                        tmp = %temp_path.display(),
                        "Preserving temporary upload file after stream error"
                    );
                    return Err(e);
                }
            }
        }

        // Sync and rename
        file.sync_all().map_err(|e| Error::FileTransfer {
            message: format!("sync failed: {}", e),
        })?;
        drop(file);

        if let Err(e) = fs::rename(&temp_path, &path) {
            let _ = fs::remove_file(&temp_path);
            let err = Error::FileTransfer {
                message: format!(
                    "rename failed (tmp: {}, dest: {}): {}",
                    temp_path.display(),
                    path.display(),
                    e
                ),
            };
            warn!(
                transfer_id,
                error = %err,
                bytes_received,
                tmp = %temp_path.display(),
                dest = %path.display(),
                "Failed to finalize upload"
            );
            let _ = Self::send_transfer_error(
                transfer_id,
                FileErrorCode::IoError,
                err.to_string(),
                &mut stream,
            )
            .await;
            return Err(err);
        }

        // Notify client of successful upload
        let complete = Message::FileComplete(FileCompletePayload {
            transfer_id,
            checksum: total_hash,
            total_bytes: bytes_received,
        });
        if let Err(e) = stream.send(&complete).await {
            warn!(
                transfer_id,
                error = %e,
                "Failed to send upload completion to client"
            );
        }

        info!(
            transfer_id,
            bytes = bytes_received,
            tmp = %temp_path.display(),
            path = %path.display(),
            "File upload complete"
        );
        Ok(())
    }

    /// Get the number of active transfers.
    pub async fn active_count(&self) -> usize {
        self.active_transfers.lock().await.len()
    }

    /// Send a transfer error to the peer (best effort).
    async fn send_transfer_error(
        transfer_id: u64,
        code: FileErrorCode,
        message: String,
        stream: &mut impl StreamPair,
    ) -> Result<()> {
        let msg = Message::FileError(FileErrorPayload {
            transfer_id,
            code,
            message: message.clone(),
        });
        if let Err(e) = stream.send(&msg).await {
            warn!(
                transfer_id,
                error = %e,
                msg = %message,
                "Failed to send FileError to client"
            );
            return Err(e);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_handler_constants() {
        assert!(MAX_TRANSFERS > 0);
        assert!(FILE_BUFFER_SIZE > 0);
    }
}
