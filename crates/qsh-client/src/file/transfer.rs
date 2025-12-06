//! File transfer client implementation.

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use serde_json;
use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use qsh_core::error::{Error, Result};
use qsh_core::file::{
    BLOCK_SIZE, BlockHasher, Compressor, Decompressor, DeltaEncoder, DeltaOp, DeltaSignature,
    StreamingHasher, hash_xxh64,
};
use qsh_core::protocol::{
    BlockChecksum, DataFlags, FileCompletePayload, FileDataPayload, FileErrorCode,
    FileMetadataPayload, FileRequestPayload, FileTransferStatus, Message, TransferDirection,
    TransferOptions,
};
use qsh_core::transport::{Connection, StreamPair, StreamType};

use super::progress::ProgressReporter;

/// Entry in a directory listing for recursive transfers.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct DirEntry {
    path: String,
    is_dir: bool,
    size: u64,
    mtime: u64,
    mode: u32,
}

/// Buffer size for file I/O.
const FILE_BUFFER_SIZE: usize = 256 * 1024;

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

/// Resolve the final remote path for an upload (scp-style semantics).
///
/// - If `remote_path` is empty (e.g. `host:`), use the local file name.
/// - If `remote_path` refers to a directory, append the local file name.
/// - Otherwise, use `remote_path` as-is.
pub fn resolve_remote_upload_path(
    local_path: &Path,
    remote_path: &str,
    remote_is_directory: bool,
) -> String {
    if remote_path.is_empty() {
        if let Some(name) = local_path.file_name() {
            return name.to_string_lossy().to_string();
        }
        return remote_path.to_string();
    }

    if remote_is_directory {
        if let Some(name) = local_path.file_name() {
            let base = remote_path.trim_end_matches('/');
            if base.is_empty() {
                return name.to_string_lossy().to_string();
            } else {
                return format!("{}/{}", base, name.to_string_lossy());
            }
        }
    }

    remote_path.to_string()
}

/// File transfer client.
#[derive(Clone)]
pub struct FileTransfer<C: Connection> {
    /// Connection to the server.
    connection: Arc<C>,
    /// Next transfer ID.
    next_transfer_id: Arc<Mutex<u64>>,
}

impl<C: Connection + 'static> FileTransfer<C> {
    /// Create a new file transfer client.
    pub fn new(connection: Arc<C>) -> Self {
        Self {
            connection,
            next_transfer_id: Arc::new(Mutex::new(1)),
        }
    }

    /// Get the next transfer ID.
    async fn next_id(&self) -> u64 {
        let mut id = self.next_transfer_id.lock().await;
        let current = *id;
        *id += 1;
        current
    }

    /// Check if a remote path refers to an existing directory (scp-style semantics).
    ///
    /// Returns:
    /// - Ok(true) if the path is an existing directory
    /// - Ok(false) if it is a file or does not exist
    /// - Err(_) for other errors (permission denied, invalid path, etc.)
    pub async fn remote_is_directory(&self, remote_path: &str) -> Result<bool> {
        let transfer_id = self.next_id().await;

        let mut stream = self
            .connection
            .open_stream(StreamType::FileTransfer(transfer_id))
            .await?;

        // Use minimal options: no recursion, compression or delta.
        let opts = TransferOptions {
            compress: false,
            delta: false,
            recursive: false,
            preserve_mode: false,
            parallel: 1,
            skip_if_unchanged: false,
        };

        let request = Message::FileRequest(FileRequestPayload {
            transfer_id,
            path: remote_path.to_string(),
            direction: TransferDirection::Download,
            resume_from: None,
            options: opts,
            chunk: None,
            client_blocks: Vec::new(),
            source_mtime: None,
            source_mtime_nsec: None,
            source_atime: None,
            source_atime_nsec: None,
            source_size: None,
        });
        stream.send(&request).await?;

        let is_dir = match stream.recv().await? {
            Message::FileMetadata(_) => false,
            Message::FileError(e) => match e.code {
                FileErrorCode::IsDirectory => true,
                FileErrorCode::NotFound => false,
                other => {
                    return Err(Error::FileTransfer {
                        message: format!("{}: {}", other, e.message),
                    });
                }
            },
            other => {
                return Err(Error::FileTransfer {
                    message: format!("unexpected response: {:?}", other),
                });
            }
        };

        // Best-effort close; server may still attempt to send, but will handle errors.
        stream.close();
        Ok(is_dir)
    }

    /// Collect all files under a directory (relative paths).
    fn collect_local_files(dir: &Path) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        let mut stack = vec![PathBuf::from(dir)];

        while let Some(path) = stack.pop() {
            for entry in fs::read_dir(&path).map_err(|e| Error::FileTransfer {
                message: format!("failed to read directory {}: {}", path.display(), e),
            })? {
                let entry = entry.map_err(|e| Error::FileTransfer {
                    message: format!("failed to read directory entry: {}", e),
                })?;
                let entry_path = entry.path();
                let rel = entry_path
                    .strip_prefix(dir)
                    .unwrap_or(&entry_path)
                    .to_path_buf();

                if entry_path.is_dir() {
                    stack.push(entry_path);
                } else if entry_path.is_file() {
                    files.push(rel);
                }
            }
        }

        files.sort();
        Ok(files)
    }

    /// Upload a file to the server.
    pub async fn upload(
        &self,
        local_path: &Path,
        remote_path: &str,
        options: TransferOptions,
    ) -> Result<TransferResult> {
        let metadata = fs::metadata(local_path).map_err(|e| Error::FileTransfer {
            message: format!("cannot read local file: {}", e),
        })?;

        if metadata.is_dir() {
            if !options.recursive {
                return Err(Error::FileTransfer {
                    message: "path is a directory (use -r for recursive)".into(),
                });
            }
            return self
                .upload_directory(local_path, remote_path, options)
                .await;
        }

        self.upload_file(local_path, remote_path, options).await
    }

    /// Send file using delta sync.
    async fn send_delta(
        &self,
        transfer_id: u64,
        local_path: &Path,
        server_metadata: &FileMetadataPayload,
        compress: bool,
        stream: &mut impl StreamPair,
        progress: &mut ProgressReporter,
    ) -> Result<u64> {
        // Build signature from server's blocks (existing remote file).
        let signature = DeltaSignature::new(&server_metadata.blocks, BLOCK_SIZE);
        let mut encoder = DeltaEncoder::new(signature);

        // Read the new local file in chunks to avoid loading it entirely into memory.
        let mut file = File::open(local_path).map_err(|e| Error::FileTransfer {
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
                message: format!("failed to read file: {}", e),
            })?;
            if n == 0 {
                break;
            }

            let chunk = &buf[..n];
            // Hash the new file contents for checksum.
            total_hash ^= hash_xxh64(chunk);
            encoder.process(chunk);

            let ops = encoder.take_ops();
            Self::send_delta_ops(
                transfer_id,
                stream,
                &mut compressor,
                ops,
                &mut out_offset,
                false,
                &mut bytes_sent,
                progress,
            )
            .await?;
        }

        let final_ops = encoder.finish();
        Self::send_delta_ops(
            transfer_id,
            stream,
            &mut compressor,
            final_ops,
            &mut out_offset,
            true,
            &mut bytes_sent,
            progress,
        )
        .await?;

        // Send complete
        let complete = Message::FileComplete(FileCompletePayload {
            transfer_id,
            checksum: total_hash,
            total_bytes: out_offset,
            status: FileTransferStatus::Normal,
        });
        stream.send(&complete).await?;

        Ok(bytes_sent)
    }

    /// Send delta operations as file data messages for uploads.
    async fn send_delta_ops(
        transfer_id: u64,
        stream: &mut impl StreamPair,
        compressor: &mut Option<Compressor>,
        ops: Vec<DeltaOp>,
        out_offset: &mut u64,
        final_batch: bool,
        bytes_sent: &mut u64,
        progress: &mut ProgressReporter,
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
            progress.update(*out_offset);
        }

        Ok(())
    }

    /// Send file without delta sync.
    async fn send_full(
        &self,
        transfer_id: u64,
        local_path: &Path,
        file_size: u64,
        compress: bool,
        stream: &mut impl StreamPair,
        progress: &mut ProgressReporter,
    ) -> Result<u64> {
        let mut file = File::open(local_path).map_err(|e| Error::FileTransfer {
            message: format!("failed to open file: {}", e),
        })?;

        let compressor = if compress {
            Some(Compressor::with_default_level())
        } else {
            None
        };

        let mut buf = vec![0u8; FILE_BUFFER_SIZE];
        let mut offset = 0u64;
        let mut total_hash = 0u64;
        let mut bytes_sent = 0u64;

        while offset < file_size {
            let to_read = buf.len().min((file_size - offset) as usize);
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
            bytes_sent += send_data.len() as u64;
            let is_final = offset >= file_size;

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

            progress.update(offset);
        }

        // Send complete
        let complete = Message::FileComplete(FileCompletePayload {
            transfer_id,
            checksum: total_hash,
            total_bytes: offset,
            status: FileTransferStatus::Normal,
        });
        stream.send(&complete).await?;

        Ok(bytes_sent)
    }

    /// Download a file from the server.
    pub async fn download(
        &self,
        remote_path: &str,
        local_path: &Path,
        options: TransferOptions,
    ) -> Result<TransferResult> {
        let start = std::time::Instant::now();
        let transfer_id = self.next_id().await;

        debug!(
            transfer_id,
            remote = %remote_path,
            local = %local_path.display(),
            "Starting download"
        );

        // Open stream
        let mut stream = self
            .connection
            .open_stream(StreamType::FileTransfer(transfer_id))
            .await?;

        // Check if local file exists (for delta)
        let (local_blocks, mut source_file) = if options.delta && local_path.exists() {
            match fs::metadata(local_path) {
                Ok(m) if m.is_file() => {
                    let size = m.len();
                    let mut file = File::open(local_path).map_err(|e| Error::FileTransfer {
                        message: format!("failed to open local file: {}", e),
                    })?;

                    let mut blocks: Vec<BlockChecksum> = Vec::new();
                    let mut buf = vec![0u8; BLOCK_SIZE];
                    let mut offset = 0u64;

                    let report_interval = if size > 0 { (size / 20).max(1) } else { 0 };
                    let mut next_report = report_interval;

                    if size > 0 {
                        info!(
                            transfer_id,
                            local_size = size,
                            "Computing local checksums for delta download"
                        );
                    }

                    loop {
                        let n = file.read(&mut buf).map_err(|e| Error::FileTransfer {
                            message: format!("failed to read local file: {}", e),
                        })?;
                        if n == 0 {
                            break;
                        }

                        let weak = BlockHasher::compute_weak(&buf[..n]);
                        let strong = BlockHasher::compute_strong(&buf[..n]);

                        blocks.push(BlockChecksum {
                            offset,
                            weak,
                            strong,
                        });

                        offset += n as u64;

                        if size > 0 && offset >= next_report {
                            let pct = ((offset as f64 / size as f64) * 100.0).min(100.0);
                            let filled = (pct / 5.0).round() as usize;
                            let total_slots = 20usize;
                            let filled_slots = filled.min(total_slots);
                            let empty_slots = total_slots.saturating_sub(filled_slots);
                            let bar = format!(
                                "[{}{}]",
                                "#".repeat(filled_slots),
                                "-".repeat(empty_slots)
                            );

                            info!(
                                transfer_id,
                                progress = %bar,
                                bytes_scanned = offset,
                                local_size = size,
                                pct = pct as u32,
                                "Local checksum scan in progress"
                            );

                            next_report = offset.saturating_add(report_interval);
                        }
                    }

                    if size > 0 {
                        info!(
                            transfer_id,
                            bytes_scanned = offset,
                            local_size = size,
                            "Local checksum scan complete"
                        );
                    }

                    // Rewind for block_ref use during download
                    file.seek(SeekFrom::Start(0))
                        .map_err(|e| Error::FileTransfer {
                            message: format!("failed to rewind local file: {}", e),
                        })?;

                    (blocks, Some(file))
                }
                _ => (Vec::new(), None),
            }
        } else {
            (Vec::new(), None)
        };

        // Send request
        let request = Message::FileRequest(FileRequestPayload {
            transfer_id,
            path: remote_path.to_string(),
            direction: TransferDirection::Download,
            resume_from: None,
            options: options.clone(),
            chunk: None,
            client_blocks: local_blocks.clone(),
            source_mtime: None,
            source_mtime_nsec: None,
            source_atime: None,
            source_atime_nsec: None,
            source_size: None,
        });
        stream.send(&request).await?;

        // Wait for metadata
        let metadata = match stream.recv().await? {
            Message::FileMetadata(m) => m,
            Message::FileError(e) => {
                return Err(Error::FileTransfer {
                    message: format!("{}: {}", e.code, e.message),
                });
            }
            other => {
                return Err(Error::FileTransfer {
                    message: format!("unexpected response: {:?}", other),
                });
            }
        };

        if metadata.is_dir {
            if !options.recursive {
                return Err(Error::FileTransfer {
                    message: "path is a directory (use -r for recursive)".into(),
                });
            }
            return self
                .download_directory(remote_path, local_path, metadata, options, stream, start)
                .await;
        }

        // Set up progress
        let filename = local_path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".to_string());
        let mut progress = ProgressReporter::new(filename, Some(metadata.size));

        // Create parent directories
        if let Some(parent) = local_path.parent() {
            fs::create_dir_all(parent).map_err(|e| Error::FileTransfer {
                message: format!("failed to create directory: {}", e),
            })?;
        }

        // Create temporary file
        let temp_path = local_path.with_extension("qsh-tmp");
        let mut file = File::create(&temp_path).map_err(|e| Error::FileTransfer {
            message: format!("failed to create file: {}", e),
        })?;

        let decompressor = if options.compress {
            Some(Decompressor::new())
        } else {
            None
        };

        let mut total_hash = 0u64;
        let mut bytes_received = 0u64;
        let mut saw_final_block = false;
        let mut delta_used = false;
        let mut checksum_ok = true;

        // Receive data
        loop {
            match stream.recv().await {
                Ok(Message::FileData(data)) if data.transfer_id == transfer_id => {
                    let content = if data.flags.block_ref {
                        delta_used = true;
                        if data.flags.compressed {
                            let _ = fs::remove_file(&temp_path);
                            return Err(Error::FileTransfer {
                                message: "block references cannot be compressed".into(),
                            });
                        }
                        if data.data.len() != 16 {
                            let _ = fs::remove_file(&temp_path);
                            return Err(Error::FileTransfer {
                                message: "invalid block reference payload".into(),
                            });
                        }

                        let mut offset_bytes = [0u8; 8];
                        offset_bytes.copy_from_slice(&data.data[..8]);
                        let mut len_bytes = [0u8; 8];
                        len_bytes.copy_from_slice(&data.data[8..]);

                        let source_offset = u64::from_le_bytes(offset_bytes);
                        let length = u64::from_le_bytes(len_bytes) as usize;

                        let src = source_file.as_mut().ok_or_else(|| Error::FileTransfer {
                            message: "received block reference but no local source file exists"
                                .into(),
                        })?;

                        let mut buf = vec![0u8; length];
                        src.seek(SeekFrom::Start(source_offset)).map_err(|e| {
                            Error::FileTransfer {
                                message: format!("seek local source failed: {}", e),
                            }
                        })?;
                        let n = src.read(&mut buf).map_err(|e| Error::FileTransfer {
                            message: format!("read local source failed: {}", e),
                        })?;
                        if n < length {
                            let _ = fs::remove_file(&temp_path);
                            return Err(Error::FileTransfer {
                                message: format!(
                                    "block reference beyond local file: offset {} length {}",
                                    source_offset, length
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
                    progress.update(bytes_received);

                    saw_final_block |= data.flags.final_block;
                }
                Ok(Message::FileComplete(complete)) if complete.transfer_id == transfer_id => {
                    if complete.checksum != total_hash {
                        warn!(
                            transfer_id,
                            expected = complete.checksum,
                            got = total_hash,
                            "Checksum mismatch"
                        );
                        checksum_ok = false;
                    }
                    if !saw_final_block {
                        warn!(
                            transfer_id,
                            "FileComplete received without final data block"
                        );
                    }
                    break;
                }
                Ok(Message::FileError(e)) if e.transfer_id == transfer_id => {
                    let _ = fs::remove_file(&temp_path);
                    return Err(Error::FileTransfer {
                        message: format!("{}: {}", e.code, e.message),
                    });
                }
                Ok(other) => {
                    warn!(transfer_id, "Unexpected message: {:?}", other);
                }
                Err(e) => {
                    let _ = fs::remove_file(&temp_path);
                    return Err(e);
                }
            }
        }

        progress.finish();

        if !checksum_ok {
            // Do not overwrite the existing file with corrupt data.
            drop(file);
            let _ = fs::remove_file(&temp_path);
            return Err(Error::FileTransfer {
                message: "checksum mismatch during download".into(),
            });
        }

        // Sync and rename
        file.sync_all().map_err(|e| Error::FileTransfer {
            message: format!("sync failed: {}", e),
        })?;
        drop(file);

        fs::rename(&temp_path, local_path).map_err(|e| Error::FileTransfer {
            message: format!("rename failed: {}", e),
        })?;

        // Set permissions if preserving
        if options.preserve_mode && metadata.mode != 0 {
            let perms = std::fs::Permissions::from_mode(metadata.mode);
            let _ = fs::set_permissions(local_path, perms);
        }

        let duration = start.elapsed().as_secs_f64();
        info!(
            transfer_id,
            bytes = bytes_received,
            duration_secs = duration,
            delta = delta_used,
            "Download complete"
        );

        Ok(TransferResult {
            bytes: bytes_received,
            duration_secs: duration,
            delta_used,
            skipped: false,
        })
    }

    /// Upload a single file.
    async fn upload_file(
        &self,
        local_path: &Path,
        remote_path: &str,
        options: TransferOptions,
    ) -> Result<TransferResult> {
        let start = std::time::Instant::now();
        let transfer_id = self.next_id().await;

        let metadata = fs::metadata(local_path).map_err(|e| Error::FileTransfer {
            message: format!("cannot read local file: {}", e),
        })?;
        let file_size = metadata.len();

        // Get the local file's mtime and atime to preserve on the server
        let (source_mtime, source_mtime_nsec) = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| (Some(d.as_secs()), Some(d.subsec_nanos())))
            .unwrap_or((None, None));

        let (source_atime, source_atime_nsec) = metadata
            .accessed()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| (Some(d.as_secs()), Some(d.subsec_nanos())))
            .unwrap_or((None, None));

        debug!(
            transfer_id,
            local = %local_path.display(),
            remote = %remote_path,
            source_mtime = ?source_mtime,
            source_mtime_nsec = ?source_mtime_nsec,
            source_atime = ?source_atime,
            "Starting upload"
        );

        // Open stream
        let mut stream = self
            .connection
            .open_stream(StreamType::FileTransfer(transfer_id))
            .await?;

        // Send request
        let request = Message::FileRequest(FileRequestPayload {
            transfer_id,
            path: remote_path.to_string(),
            direction: TransferDirection::Upload,
            resume_from: None,
            options: options.clone(),
            chunk: None,
            client_blocks: Vec::new(),
            source_mtime,
            source_mtime_nsec,
            source_atime,
            source_atime_nsec,
            source_size: Some(file_size),
        });
        stream.send(&request).await?;

        // Wait for metadata (server sends existing file info for delta)
        let server_metadata = match stream.recv().await? {
            Message::FileMetadata(m) => m,
            Message::FileError(e) => {
                return Err(Error::FileTransfer {
                    message: format!("{}: {}", e.code, e.message),
                });
            }
            other => {
                return Err(Error::FileTransfer {
                    message: format!("unexpected response: {:?}", other),
                });
            }
        };

        info!(
            transfer_id,
            remote_size = server_metadata.size,
            remote_blocks = server_metadata.blocks.len(),
            remote_hash = ?server_metadata.file_hash,
            "Received server metadata for upload"
        );

        // Check for skip_if_unchanged: if enabled and hashes match, skip transfer
        if options.skip_if_unchanged {
            if let Some(remote_hash) = server_metadata.file_hash {
                // Fast pre-check: sizes must match before computing hash.
                // Note: We don't check mtime because uploaded files will have a different
                // mtime than the local file (the server creates them with current time).
                if file_size == server_metadata.size {
                    info!(
                        transfer_id,
                        local_size = file_size,
                        remote_size = server_metadata.size,
                        "Size matches, computing local hash for skip_if_unchanged"
                    );

                    // Compute local file hash
                    let local_hash = Self::compute_file_hash(local_path, file_size).await?;

                    if local_hash == remote_hash {
                        info!(
                            transfer_id,
                            hash = local_hash,
                            "File already up to date, skipping transfer"
                        );

                        // Send AlreadyUpToDate completion
                        let complete = Message::FileComplete(FileCompletePayload {
                            transfer_id,
                            checksum: local_hash,
                            total_bytes: 0,
                            status: FileTransferStatus::AlreadyUpToDate,
                        });
                        stream.send(&complete).await?;

                        // Wait for server acknowledgment
                        self.await_upload_complete(&mut stream, transfer_id).await?;

                        let duration = start.elapsed().as_secs_f64();
                        return Ok(TransferResult {
                            bytes: 0,
                            duration_secs: duration,
                            delta_used: false,
                            skipped: true,
                        });
                    } else {
                        info!(
                            transfer_id,
                            local_hash,
                            remote_hash,
                            "Hash mismatch despite same size, proceeding with upload"
                        );
                    }
                } else {
                    debug!(
                        transfer_id,
                        local_size = file_size,
                        remote_size = server_metadata.size,
                        "Size mismatch, skipping hash computation"
                    );
                }
            }
        }

        // Set up progress
        let filename = local_path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".to_string());
        let mut progress = ProgressReporter::new(filename, Some(file_size));

        // Determine if we should use delta
        let use_delta = options.delta && !server_metadata.blocks.is_empty();
        let delta_used = use_delta;

        info!(transfer_id, use_delta, "Upload delta decision");

        // Send file data
        let _bytes_sent = if use_delta {
            self.send_delta(
                transfer_id,
                local_path,
                &server_metadata,
                options.compress,
                &mut stream,
                &mut progress,
            )
            .await?
        } else {
            self.send_full(
                transfer_id,
                local_path,
                file_size,
                options.compress,
                &mut stream,
                &mut progress,
            )
            .await?
        };

        progress.finish();

        // Wait for server confirmation
        self.await_upload_complete(&mut stream, transfer_id).await?;

        let duration = start.elapsed().as_secs_f64();
        info!(
            transfer_id,
            bytes = file_size,
            duration_secs = duration,
            delta = delta_used,
            "Upload complete"
        );

        Ok(TransferResult {
            bytes: file_size,
            duration_secs: duration,
            delta_used,
            skipped: false,
        })
    }

    /// Compute the full file hash (xxHash64) for skip_if_unchanged negotiation.
    ///
    /// Uses xxHash64 with streaming to hash the entire file content.
    async fn compute_file_hash(path: &Path, size: u64) -> Result<u64> {
        let path = path.to_path_buf();

        tokio::task::spawn_blocking(move || {
            let mut file = File::open(&path).map_err(|e| Error::FileTransfer {
                message: format!("failed to open file for hashing: {}", e),
            })?;

            let mut hasher = StreamingHasher::new();
            let mut buf = vec![0u8; FILE_BUFFER_SIZE];
            let mut offset = 0u64;

            let report_interval = if size > 0 { (size / 20).max(1) } else { 0 };
            let mut next_report = report_interval;

            if size > 0 {
                info!(
                    total_bytes = size,
                    "Computing file hash for skip_if_unchanged"
                );
            }

            loop {
                let n = file.read(&mut buf).map_err(|e| Error::FileTransfer {
                    message: format!("failed to read file: {}", e),
                })?;
                if n == 0 {
                    break;
                }

                hasher.update(&buf[..n]);
                offset += n as u64;

                if size > 0 && offset >= next_report {
                    let pct = ((offset as f64 / size as f64) * 100.0).min(100.0);
                    debug!(
                        bytes_hashed = offset,
                        total_bytes = size,
                        pct = pct as u32,
                        "File hash computation in progress"
                    );
                    next_report = offset.saturating_add(report_interval);
                }
            }

            let hash = hasher.finish();

            if size > 0 {
                debug!(
                    bytes_hashed = offset,
                    total_bytes = size,
                    hash,
                    "File hash computation complete"
                );
            }

            Ok(hash)
        })
        .await
        .map_err(|e| Error::FileTransfer {
            message: format!("hash task failed: {}", e),
        })?
    }

    /// Wait for server acknowledgment of upload completion.
    async fn await_upload_complete(
        &self,
        stream: &mut impl StreamPair,
        transfer_id: u64,
    ) -> Result<()> {
        loop {
            match stream.recv().await {
                Ok(Message::FileAck(ack)) if ack.transfer_id == transfer_id => {
                    // Flow-control ack; keep waiting for completion.
                }
                Ok(Message::FileComplete(complete)) if complete.transfer_id == transfer_id => {
                    if complete.total_bytes == 0 {
                        warn!(
                            transfer_id,
                            "Server reported zero bytes in upload completion"
                        );
                    }
                    break;
                }
                Ok(Message::FileError(err)) if err.transfer_id == transfer_id => {
                    return Err(Error::FileTransfer {
                        message: format!("server error: {}", err.message),
                    });
                }
                Ok(other) => {
                    warn!(
                        transfer_id,
                        "Unexpected message while awaiting upload complete: {:?}", other
                    );
                }
                Err(e) => {
                    return Err(Error::FileTransfer {
                        message: format!("failed waiting for server confirmation: {}", e),
                    });
                }
            }
        }
        Ok(())
    }

    /// Download a directory recursively using server-provided listing.
    async fn download_directory(
        &self,
        remote_path: &str,
        local_path: &Path,
        metadata: FileMetadataPayload,
        options: TransferOptions,
        mut stream: impl StreamPair,
        start: std::time::Instant,
    ) -> Result<TransferResult> {
        fs::create_dir_all(local_path).map_err(|e| Error::FileTransfer {
            message: format!("failed to create directory: {}", e),
        })?;

        let decompressor = if options.compress {
            Some(Decompressor::new())
        } else {
            None
        };

        let mut listing_bytes = Vec::new();

        let expected_checksum = loop {
            match stream.recv().await {
                Ok(Message::FileData(data)) if data.transfer_id == metadata.transfer_id => {
                    if data.flags.block_ref {
                        return Err(Error::FileTransfer {
                            message: "unexpected block reference in directory listing".into(),
                        });
                    }
                    let content = if data.flags.compressed {
                        if let Some(ref decomp) = decompressor {
                            decomp.decompress(&data.data)?
                        } else {
                            data.data
                        }
                    } else {
                        data.data
                    };
                    listing_bytes.extend_from_slice(&content);
                }
                Ok(Message::FileComplete(complete))
                    if complete.transfer_id == metadata.transfer_id =>
                {
                    break Some(complete.checksum);
                }
                Ok(Message::FileError(e)) if e.transfer_id == metadata.transfer_id => {
                    return Err(Error::FileTransfer {
                        message: format!("{}: {}", e.code, e.message),
                    });
                }
                Ok(other) => {
                    warn!(
                        transfer_id = metadata.transfer_id,
                        "Unexpected message during directory listing: {:?}", other
                    );
                }
                Err(e) => return Err(e),
            }
        };

        if let Some(expected) = expected_checksum {
            let got = hash_xxh64(&listing_bytes);
            if expected != got {
                warn!(
                    transfer_id = metadata.transfer_id,
                    expected, got, "Directory listing checksum mismatch"
                );
            }
        }

        let entries: Vec<DirEntry> =
            serde_json::from_slice(&listing_bytes).map_err(|e| Error::FileTransfer {
                message: format!("failed to parse directory listing: {}", e),
            })?;

        // Create directories first
        for entry in entries.iter().filter(|e| e.is_dir) {
            let dir_path = local_path.join(&entry.path);
            fs::create_dir_all(&dir_path).map_err(|e| Error::FileTransfer {
                message: format!("failed to create directory {}: {}", dir_path.display(), e),
            })?;

            if options.preserve_mode && entry.mode != 0 {
                let perms = std::fs::Permissions::from_mode(entry.mode);
                let _ = fs::set_permissions(&dir_path, perms);
            }
        }

        let remote_base = Path::new(remote_path).to_path_buf();
        let parallel = options.parallel.max(1);
        let semaphore = Arc::new(Semaphore::new(parallel));
        let mut set = JoinSet::new();
        let connection = Arc::clone(&self.connection);
        let next_transfer_id = Arc::clone(&self.next_transfer_id);

        for entry in entries.into_iter().filter(|e| !e.is_dir) {
            let local_base = local_path.to_path_buf();
            let remote_base = remote_base.clone();
            let opts = options.clone();
            let connection = Arc::clone(&connection);
            let next_transfer_id = Arc::clone(&next_transfer_id);
            let permit =
                semaphore
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|e| Error::FileTransfer {
                        message: format!("semaphore closed: {}", e),
                    })?;
            set.spawn(async move {
                let _permit = permit;
                let local_file = local_base.join(&entry.path);
                if let Some(parent) = local_file.parent() {
                    fs::create_dir_all(parent).map_err(|e| Error::FileTransfer {
                        message: format!("failed to create directory {}: {}", parent.display(), e),
                    })?;
                }

                let remote_file = remote_base.join(&entry.path);
                let remote_str = remote_file.to_string_lossy().to_string();
                let ft = FileTransfer {
                    connection: Arc::clone(&connection),
                    next_transfer_id: Arc::clone(&next_transfer_id),
                };
                let result = ft
                    .download_file_simple(&remote_str, &local_file, opts)
                    .await?;
                Ok::<(u64, bool), Error>((result.bytes, result.delta_used))
            });
        }

        let mut file_bytes = 0u64;
        let mut delta_used = false;
        while let Some(res) = set.join_next().await {
            let (bytes, delta) = res.map_err(|e| Error::FileTransfer {
                message: format!("download task failed: {}", e),
            })??;
            file_bytes += bytes;
            delta_used |= delta;
        }

        let total_bytes = listing_bytes.len() as u64 + file_bytes;

        let duration = start.elapsed().as_secs_f64();
        info!(
            transfer_id = metadata.transfer_id,
            bytes = total_bytes,
            duration_secs = duration,
            delta = delta_used,
            "Directory download complete"
        );

        Ok(TransferResult {
            bytes: total_bytes,
            duration_secs: duration,
            delta_used,
            skipped: false,
        })
    }

    /// Download a single file (non-directory) from scratch.
    async fn download_file_simple(
        &self,
        remote_path: &str,
        local_path: &Path,
        options: TransferOptions,
    ) -> Result<TransferResult> {
        let start = std::time::Instant::now();
        let transfer_id = self.next_id().await;

        let (local_blocks, mut source_file) = if options.delta && local_path.exists() {
            match fs::metadata(local_path) {
                Ok(m) if m.is_file() => {
                    let mut file = File::open(local_path).map_err(|e| Error::FileTransfer {
                        message: format!("failed to open local file: {}", e),
                    })?;
                    let mut data = Vec::new();
                    file.read_to_end(&mut data)
                        .map_err(|e| Error::FileTransfer {
                            message: format!("failed to read local file: {}", e),
                        })?;
                    let hasher = BlockHasher::new(BLOCK_SIZE);
                    let blocks = hasher.compute_checksums(&data);

                    file.seek(SeekFrom::Start(0))
                        .map_err(|e| Error::FileTransfer {
                            message: format!("failed to rewind local file: {}", e),
                        })?;

                    (blocks, Some(file))
                }
                _ => (Vec::new(), None),
            }
        } else {
            (Vec::new(), None)
        };

        let mut stream = self
            .connection
            .open_stream(StreamType::FileTransfer(transfer_id))
            .await?;

        let request = Message::FileRequest(FileRequestPayload {
            transfer_id,
            path: remote_path.to_string(),
            direction: TransferDirection::Download,
            resume_from: None,
            options: options.clone(),
            chunk: None,
            client_blocks: local_blocks.clone(),
            source_mtime: None,
            source_mtime_nsec: None,
            source_atime: None,
            source_atime_nsec: None,
            source_size: None,
        });
        stream.send(&request).await?;

        let metadata = match stream.recv().await? {
            Message::FileMetadata(m) => m,
            Message::FileError(e) => {
                return Err(Error::FileTransfer {
                    message: format!("{}: {}", e.code, e.message),
                });
            }
            other => {
                return Err(Error::FileTransfer {
                    message: format!("unexpected response: {:?}", other),
                });
            }
        };

        if metadata.is_dir {
            return Err(Error::FileTransfer {
                message: "unexpected directory metadata during file download".into(),
            });
        }

        // Set up progress
        let filename = local_path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".to_string());
        let mut progress = ProgressReporter::new(filename, Some(metadata.size));

        if let Some(parent) = local_path.parent() {
            fs::create_dir_all(parent).map_err(|e| Error::FileTransfer {
                message: format!("failed to create directory: {}", e),
            })?;
        }

        let temp_path = local_path.with_extension("qsh-tmp");
        let mut file = File::create(&temp_path).map_err(|e| Error::FileTransfer {
            message: format!("failed to create file: {}", e),
        })?;

        let decompressor = if options.compress {
            Some(Decompressor::new())
        } else {
            None
        };

        let mut total_hash = 0u64;
        let mut bytes_received = 0u64;
        let mut saw_final_block = false;
        let mut delta_used = false;
        let mut checksum_ok = true;

        loop {
            match stream.recv().await {
                Ok(Message::FileData(data)) if data.transfer_id == transfer_id => {
                    let content = if data.flags.block_ref {
                        delta_used = true;
                        if data.flags.compressed {
                            let _ = fs::remove_file(&temp_path);
                            return Err(Error::FileTransfer {
                                message: "block references cannot be compressed".into(),
                            });
                        }
                        if data.data.len() != 16 {
                            let _ = fs::remove_file(&temp_path);
                            return Err(Error::FileTransfer {
                                message: "invalid block reference payload".into(),
                            });
                        }

                        let mut offset_bytes = [0u8; 8];
                        offset_bytes.copy_from_slice(&data.data[..8]);
                        let mut len_bytes = [0u8; 8];
                        len_bytes.copy_from_slice(&data.data[8..]);

                        let source_offset = u64::from_le_bytes(offset_bytes);
                        let length = u64::from_le_bytes(len_bytes) as usize;

                        let src = source_file.as_mut().ok_or_else(|| Error::FileTransfer {
                            message: "received block reference but no local source file exists"
                                .into(),
                        })?;

                        let mut buf = vec![0u8; length];
                        src.seek(SeekFrom::Start(source_offset)).map_err(|e| {
                            Error::FileTransfer {
                                message: format!("seek local source failed: {}", e),
                            }
                        })?;
                        let n = src.read(&mut buf).map_err(|e| Error::FileTransfer {
                            message: format!("read local source failed: {}", e),
                        })?;
                        if n < length {
                            let _ = fs::remove_file(&temp_path);
                            return Err(Error::FileTransfer {
                                message: format!(
                                    "block reference beyond local file: offset {} length {}",
                                    source_offset, length
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
                    progress.update(bytes_received);

                    saw_final_block |= data.flags.final_block;
                }
                Ok(Message::FileComplete(complete)) if complete.transfer_id == transfer_id => {
                    if complete.checksum != total_hash {
                        warn!(
                            transfer_id,
                            expected = complete.checksum,
                            got = total_hash,
                            "Checksum mismatch"
                        );
                        checksum_ok = false;
                    }
                    if !saw_final_block {
                        warn!(
                            transfer_id,
                            "FileComplete received without final data block"
                        );
                    }
                    break;
                }
                Ok(Message::FileError(e)) if e.transfer_id == transfer_id => {
                    let _ = fs::remove_file(&temp_path);
                    return Err(Error::FileTransfer {
                        message: format!("{}: {}", e.code, e.message),
                    });
                }
                Ok(other) => {
                    warn!(transfer_id, "Unexpected message: {:?}", other);
                }
                Err(e) => {
                    let _ = fs::remove_file(&temp_path);
                    return Err(e);
                }
            }
        }

        progress.finish();

        if !checksum_ok {
            // Avoid overwriting the target with corrupt data.
            drop(file);
            let _ = fs::remove_file(&temp_path);
            return Err(Error::FileTransfer {
                message: "checksum mismatch during download".into(),
            });
        }

        file.sync_all().map_err(|e| Error::FileTransfer {
            message: format!("sync failed: {}", e),
        })?;
        drop(file);

        fs::rename(&temp_path, local_path).map_err(|e| Error::FileTransfer {
            message: format!("rename failed: {}", e),
        })?;

        if options.preserve_mode && metadata.mode != 0 {
            let perms = std::fs::Permissions::from_mode(metadata.mode);
            let _ = fs::set_permissions(local_path, perms);
        }

        let duration = start.elapsed().as_secs_f64();
        info!(
            transfer_id,
            bytes = bytes_received,
            duration_secs = duration,
            "Download complete"
        );

        Ok(TransferResult {
            bytes: bytes_received,
            duration_secs: duration,
            delta_used,
            skipped: false,
        })
    }

    /// Upload a directory recursively.
    async fn upload_directory(
        &self,
        local_dir: &Path,
        remote_path: &str,
        options: TransferOptions,
    ) -> Result<TransferResult> {
        let start = std::time::Instant::now();
        let files = Self::collect_local_files(local_dir)?;
        let remote_base = Path::new(remote_path);

        // Always create the root locally so remote parents exist
        let parallel = options.parallel.max(1);
        let local_root = local_dir.to_path_buf();
        let remote_root = remote_base.to_path_buf();
        let semaphore = Arc::new(Semaphore::new(parallel));
        let mut set = JoinSet::new();
        let connection = Arc::clone(&self.connection);
        let next_transfer_id = Arc::clone(&self.next_transfer_id);

        for rel in files {
            let local_root = local_root.clone();
            let remote_root = remote_root.clone();
            let opts = options.clone();
            let connection = Arc::clone(&connection);
            let next_transfer_id = Arc::clone(&next_transfer_id);
            let permit =
                semaphore
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|e| Error::FileTransfer {
                        message: format!("semaphore closed: {}", e),
                    })?;
            set.spawn(async move {
                let _permit = permit;
                let local_file = local_root.join(&rel);
                let remote_file = remote_root.join(&rel);
                let remote_str = remote_file.to_string_lossy().to_string();
                let ft = FileTransfer {
                    connection: Arc::clone(&connection),
                    next_transfer_id: Arc::clone(&next_transfer_id),
                };
                let result = ft.upload_file(&local_file, &remote_str, opts).await?;
                Ok::<(u64, bool), Error>((result.bytes, result.delta_used))
            });
        }

        let mut total_bytes = 0u64;
        let mut delta_used = false;
        while let Some(res) = set.join_next().await {
            let (bytes, delta) = res.map_err(|e| Error::FileTransfer {
                message: format!("upload task failed: {}", e),
            })??;
            total_bytes += bytes;
            delta_used |= delta;
        }

        let duration = start.elapsed().as_secs_f64();
        Ok(TransferResult {
            bytes: total_bytes,
            duration_secs: duration,
            delta_used,
            skipped: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_transfer_result() {
        let result = TransferResult {
            bytes: 1000,
            duration_secs: 1.0,
            delta_used: false,
            skipped: false,
        };
        assert_eq!(result.bytes, 1000);
        assert!(!result.skipped);
    }

    #[test]
    fn resolve_upload_empty_remote_uses_basename() {
        let local = Path::new("/tmp/testfile_5gb.bin");
        let resolved = resolve_remote_upload_path(local, "", false);
        assert_eq!(resolved, "testfile_5gb.bin");
    }

    #[test]
    fn resolve_upload_directory_appends_basename() {
        let local = Path::new("/tmp/testfile_5gb.bin");
        let resolved = resolve_remote_upload_path(local, "folder", true);
        assert_eq!(resolved, "folder/testfile_5gb.bin");
    }

    #[test]
    fn resolve_upload_directory_trailing_slash() {
        let local = Path::new("/tmp/testfile_5gb.bin");
        let resolved = resolve_remote_upload_path(local, "folder/", true);
        assert_eq!(resolved, "folder/testfile_5gb.bin");
    }

    #[test]
    fn resolve_upload_non_directory_keeps_path() {
        let local = Path::new("/tmp/testfile_5gb.bin");
        let resolved = resolve_remote_upload_path(local, "folder", false);
        assert_eq!(resolved, "folder");
    }
}
