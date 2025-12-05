//! File transfer client implementation.

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json;
use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use qsh_core::error::{Error, Result};
use qsh_core::file::{
    BLOCK_SIZE, BlockHasher, Compressor, Decompressor, DeltaEncoder, DeltaOp, DeltaSignature,
    hash_xxh64,
};
use qsh_core::protocol::{
    DataFlags, FileCompletePayload, FileDataPayload, FileMetadataPayload, FileRequestPayload,
    Message, TransferDirection, TransferOptions,
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
        // Read local file
        let mut file = File::open(local_path).map_err(|e| Error::FileTransfer {
            message: format!("failed to open file: {}", e),
        })?;

        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .map_err(|e| Error::FileTransfer {
                message: format!("failed to read file: {}", e),
            })?;

        // Build signature from server's blocks
        let signature = DeltaSignature::new(&server_metadata.blocks, BLOCK_SIZE);

        // Compute delta
        let ops = DeltaEncoder::encode(signature, &data);

        let compressor = if compress {
            Some(Compressor::with_default_level())
        } else {
            None
        };

        let mut bytes_sent = 0u64;
        let mut total_hash = 0u64;
        let mut offset = 0u64;

        // Send delta operations
        for (i, op) in ops.iter().enumerate() {
            let is_final = i == ops.len() - 1;

            let (send_data, flags, advance_by) = match op {
                DeltaOp::Copy {
                    source_offset,
                    length,
                } => {
                    let start = offset as usize;
                    let len = (*length) as usize;
                    let end = start.checked_add(len).ok_or_else(|| Error::FileTransfer {
                        message: "delta copy offset overflow".into(),
                    })?;

                    if end > data.len() {
                        return Err(Error::FileTransfer {
                            message: "delta copy exceeds local file size".into(),
                        });
                    }

                    total_hash ^= hash_xxh64(&data[start..end]);

                    // Send block reference
                    let mut ref_data = Vec::with_capacity(16);
                    ref_data.extend_from_slice(&source_offset.to_le_bytes());
                    ref_data.extend_from_slice(&length.to_le_bytes());
                    (
                        ref_data,
                        DataFlags {
                            compressed: false,
                            final_block: is_final,
                            block_ref: true,
                        },
                        *length,
                    )
                }
                DeltaOp::Literal { data: lit_data } => {
                    total_hash ^= hash_xxh64(lit_data);

                    let (send, compressed) = if let Some(ref comp) = compressor {
                        if comp.should_compress(lit_data) {
                            match comp.compress(lit_data) {
                                Ok(c) if c.len() < lit_data.len() => (c, true),
                                _ => (lit_data.clone(), false),
                            }
                        } else {
                            (lit_data.clone(), false)
                        }
                    } else {
                        (lit_data.clone(), false)
                    };

                    (
                        send,
                        DataFlags {
                            compressed,
                            final_block: is_final,
                            block_ref: false,
                        },
                        lit_data.len() as u64,
                    )
                }
            };

            let msg = Message::FileData(FileDataPayload {
                transfer_id,
                offset,
                data: send_data.clone(),
                flags,
            });
            stream.send(&msg).await?;

            bytes_sent += send_data.len() as u64;
            offset += advance_by;
            progress.update(offset);
        }

        // Send complete
        let complete = Message::FileComplete(FileCompletePayload {
            transfer_id,
            checksum: total_hash,
            total_bytes: offset,
        });
        stream.send(&complete).await?;

        Ok(bytes_sent)
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

        debug!(
            transfer_id,
            local = %local_path.display(),
            remote = %remote_path,
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

        // Set up progress
        let filename = local_path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".to_string());
        let mut progress = ProgressReporter::new(filename, Some(file_size));

        // Determine if we should use delta
        let use_delta = options.delta && !server_metadata.blocks.is_empty();
        let delta_used = use_delta;

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
        })
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
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transfer_result() {
        let result = TransferResult {
            bytes: 1000,
            duration_secs: 1.0,
            delta_used: false,
        };
        assert_eq!(result.bytes, 1000);
    }
}
