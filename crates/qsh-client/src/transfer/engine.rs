//! Core file transfer engine extracted from qscp.
//!
//! Provides upload/download functionality with progress callbacks instead of
//! direct UI rendering.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use qsh_core::file::checksum::StreamingHasher;
use qsh_core::file::compress::{Compressor, Decompressor, is_compressed_extension};
use qsh_core::file::delta::{DeltaEncoder, DeltaOp, DeltaSignature};
use qsh_core::protocol::{
    ChannelData, ChannelPayload, DataFlags, DeltaAlgo, FileTransferMetadata, FileTransferParams,
    FileTransferStatus, Message, TransferDirection, TransferOptions,
};
use qsh_core::Result;

use crate::{ChannelConnection, FileChannel};

use super::progress::{ProgressCallback, ProgressEvent};

/// Chunk size for file data (32KB).
const FILE_CHUNK_SIZE: usize = 32 * 1024;

/// Block size for delta sync (128KB) - must match server.
const DELTA_BLOCK_SIZE: usize = 128 * 1024;

/// Transfer statistics.
#[derive(Debug, Clone, Default)]
pub struct TransferStats {
    /// Total bytes transferred.
    pub bytes: u64,
    /// Whether the transfer was skipped (already up to date).
    pub skipped: bool,
    /// Number of files transferred.
    pub files_transferred: u64,
    /// Number of files skipped.
    pub files_skipped: u64,
    /// Number of files that failed.
    pub files_failed: u64,
}

/// File entry for recursive transfer.
#[derive(Debug, Clone)]
struct FileEntry {
    /// Local path to the file.
    local_path: PathBuf,
    /// Relative path from the source directory.
    relative_path: PathBuf,
    /// File size in bytes.
    size: u64,
}

/// File transfer engine.
///
/// Handles upload/download operations with progress reporting via callbacks.
pub struct TransferEngine {
    conn: Arc<ChannelConnection>,
    progress: Arc<dyn ProgressCallback>,
}

impl TransferEngine {
    /// Create a new transfer engine.
    ///
    /// # Arguments
    /// * `conn` - The channel connection to use for transfers
    /// * `progress` - Callback for progress events
    pub fn new(conn: Arc<ChannelConnection>, progress: Arc<dyn ProgressCallback>) -> Self {
        Self { conn, progress }
    }

    /// Run a file transfer operation.
    ///
    /// This is the main entry point for transfers, handling both single files
    /// and recursive directory operations.
    pub async fn run_transfer(
        &self,
        local_path: &Path,
        remote_path: &str,
        direction: TransferDirection,
        options: &TransferOptions,
        resume_from: Option<u64>,
    ) -> Result<TransferStats> {
        let start_time = Instant::now();

        // Check if this is a directory transfer
        let local_meta = fs::metadata(local_path).await;
        let is_directory = local_meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);

        if is_directory && !options.recursive {
            return Err(qsh_core::Error::FileTransfer {
                message: format!(
                    "{} is a directory (use -r for recursive)",
                    local_path.display()
                ),
            });
        }

        if is_directory && matches!(direction, TransferDirection::Upload) {
            // Recursive directory upload
            return self
                .do_recursive_upload(local_path, remote_path, options)
                .await;
        }

        // Single file transfer
        let transfer_params = FileTransferParams {
            path: remote_path.to_string(),
            direction,
            options: options.clone(),
            resume_from,
        };

        info!(
            direction = ?direction,
            local = %local_path.display(),
            remote = %remote_path,
            "Opening file transfer channel"
        );

        let file_channel = self.conn.open_file_transfer(transfer_params).await?;
        debug!(channel_id = ?file_channel.channel_id(), "File transfer channel opened");

        // Run the transfer
        let result = match direction {
            TransferDirection::Upload => {
                self.do_upload(&file_channel, local_path, remote_path, options)
                    .await
            }
            TransferDirection::Download => {
                self.do_download(&file_channel, local_path, file_channel.metadata(), options)
                    .await
            }
        };

        // Close the channel
        file_channel.mark_closed();

        match result {
            Ok(stats) => {
                let elapsed = start_time.elapsed().as_secs_f64();
                self.progress.on_progress(ProgressEvent::TransferCompleted {
                    files_transferred: if stats.skipped { 0 } else { 1 },
                    files_skipped: if stats.skipped { 1 } else { 0 },
                    files_failed: 0,
                    bytes: stats.bytes,
                    elapsed_secs: elapsed,
                });
                Ok(stats)
            }
            Err(e) => Err(e),
        }
    }

    /// Recursively collect all files in a directory.
    async fn collect_files(&self, base_path: &Path) -> Result<Vec<FileEntry>> {
        self.progress
            .on_progress(ProgressEvent::ScanningDirectory {
                path: base_path.display().to_string(),
            });

        let mut files = Vec::new();
        let mut stack = vec![base_path.to_path_buf()];

        while let Some(dir_path) = stack.pop() {
            let mut entries = fs::read_dir(&dir_path).await.map_err(|e| {
                qsh_core::Error::FileTransfer {
                    message: format!("failed to read directory {}: {}", dir_path.display(), e),
                }
            })?;

            while let Some(entry) = entries.next_entry().await.map_err(|e| {
                qsh_core::Error::FileTransfer {
                    message: format!("failed to read entry: {}", e),
                }
            })? {
                let path = entry.path();
                let metadata = entry.metadata().await.map_err(|e| {
                    qsh_core::Error::FileTransfer {
                        message: format!("failed to get metadata for {}: {}", path.display(), e),
                    }
                })?;

                if metadata.is_dir() {
                    stack.push(path);
                } else if metadata.is_file() {
                    let relative_path =
                        path.strip_prefix(base_path)
                            .map_err(|_| qsh_core::Error::FileTransfer {
                                message: "failed to compute relative path".to_string(),
                            })?
                            .to_path_buf();

                    files.push(FileEntry {
                        local_path: path,
                        relative_path,
                        size: metadata.len(),
                    });
                }
            }
        }

        // Sort for consistent ordering
        files.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));

        let total_bytes: u64 = files.iter().map(|f| f.size).sum();
        self.progress.on_progress(ProgressEvent::ScanCompleted {
            file_count: files.len(),
            total_bytes,
        });

        Ok(files)
    }

    /// Perform recursive directory upload with parallel transfers.
    async fn do_recursive_upload(
        &self,
        local_base: &Path,
        remote_base: &str,
        options: &TransferOptions,
    ) -> Result<TransferStats> {
        let start_time = Instant::now();

        // Collect all files
        let files = self.collect_files(local_base).await?;

        if files.is_empty() {
            return Ok(TransferStats::default());
        }

        let total_files = files.len();
        let total_bytes: u64 = files.iter().map(|f| f.size).sum();

        // Setup parallel transfer semaphore
        let semaphore = Arc::new(Semaphore::new(options.parallel.max(1)));
        let transferred_bytes = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let transferred_files = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let skipped_files = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let failed_files = Arc::new(std::sync::atomic::AtomicU64::new(0));

        // Process files in parallel
        use futures::stream::{self, StreamExt};

        let results: Vec<_> = stream::iter(files)
            .map(|file| {
                let conn = Arc::clone(&self.conn);
                let semaphore = Arc::clone(&semaphore);
                let options = options.clone();
                let remote_base = remote_base.to_string();
                let transferred_bytes = Arc::clone(&transferred_bytes);
                let transferred_files = Arc::clone(&transferred_files);
                let skipped_files = Arc::clone(&skipped_files);
                let failed_files = Arc::clone(&failed_files);
                let progress = Arc::clone(&self.progress);

                async move {
                    // Acquire semaphore permit
                    let _permit = semaphore.acquire().await.unwrap();

                    // Build remote path
                    let remote_path = format!(
                        "{}/{}",
                        remote_base.trim_end_matches('/'),
                        file.relative_path.to_string_lossy().replace('\\', "/")
                    );

                    // Create transfer params
                    let transfer_params = FileTransferParams {
                        path: remote_path.clone(),
                        direction: TransferDirection::Upload,
                        options: options.clone(),
                        resume_from: None,
                    };

                    // Open channel and transfer
                    match conn.open_file_transfer(transfer_params).await {
                        Ok(channel) => {
                            // Create a mini-engine for this file (no recursive callback)
                            let engine = TransferEngine::new(conn, progress.clone());
                            let result = engine
                                .do_upload(&channel, &file.local_path, &remote_path, &options)
                                .await;
                            channel.mark_closed();

                            match result {
                                Ok(stats) => {
                                    if stats.skipped {
                                        skipped_files.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                    } else {
                                        transferred_bytes
                                            .fetch_add(stats.bytes, std::sync::atomic::Ordering::SeqCst);
                                    }
                                    transferred_files.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                }
                                Err(e) => {
                                    warn!(path = %file.local_path.display(), error = %e, "Transfer failed");
                                    progress.on_progress(ProgressEvent::FileFailed {
                                        local_path: file.local_path.display().to_string(),
                                        error: e.to_string(),
                                    });
                                    failed_files.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                }
                            }
                        }
                        Err(e) => {
                            warn!(path = %file.local_path.display(), error = %e, "Failed to open channel");
                            progress.on_progress(ProgressEvent::FileFailed {
                                local_path: file.local_path.display().to_string(),
                                error: e.to_string(),
                            });
                            failed_files.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        }
                    }

                    // Update overall progress
                    let done = transferred_files.load(std::sync::atomic::Ordering::SeqCst)
                        + skipped_files.load(std::sync::atomic::Ordering::SeqCst)
                        + failed_files.load(std::sync::atomic::Ordering::SeqCst);
                    let bytes = transferred_bytes.load(std::sync::atomic::Ordering::SeqCst);

                    progress.on_progress(ProgressEvent::OverallProgress {
                        files_done: done,
                        files_total: total_files as u64,
                        bytes_transferred: bytes,
                        total_bytes,
                    });
                }
            })
            .buffer_unordered(options.parallel.max(1))
            .collect()
            .await;

        // Consume results to ensure all futures completed
        drop(results);

        let elapsed = start_time.elapsed().as_secs_f64();
        let bytes = transferred_bytes.load(std::sync::atomic::Ordering::SeqCst);
        let transferred = transferred_files.load(std::sync::atomic::Ordering::SeqCst);
        let skipped = skipped_files.load(std::sync::atomic::Ordering::SeqCst);
        let failed = failed_files.load(std::sync::atomic::Ordering::SeqCst);

        self.progress
            .on_progress(ProgressEvent::TransferCompleted {
                files_transferred: transferred,
                files_skipped: skipped,
                files_failed: failed,
                bytes,
                elapsed_secs: elapsed,
            });

        if failed > 0 {
            return Err(qsh_core::Error::FileTransfer {
                message: format!("{} files failed to transfer", failed),
            });
        }

        Ok(TransferStats {
            bytes,
            skipped: false,
            files_transferred: transferred,
            files_skipped: skipped,
            files_failed: failed,
        })
    }

    /// Upload a file to the remote server.
    async fn do_upload(
        &self,
        channel: &FileChannel,
        local_path: &Path,
        remote_path: &str,
        options: &TransferOptions,
    ) -> Result<TransferStats> {
        // Get local file metadata
        let local_meta = fs::metadata(local_path).await.map_err(|e| {
            qsh_core::Error::FileTransfer {
                message: format!("failed to stat local file: {}", e),
            }
        })?;

        if local_meta.is_dir() {
            return Err(qsh_core::Error::FileTransfer {
                message: "directory transfer not yet implemented (use -r flag)".to_string(),
            });
        }

        let file_size = local_meta.len();

        self.progress.on_progress(ProgressEvent::FileStarted {
            local_path: local_path.display().to_string(),
            remote_path: remote_path.to_string(),
            total_bytes: file_size,
        });

        // Check if we can skip (server sends existing file metadata if skip_if_unchanged)
        if let Some(server_meta) = channel.metadata() {
            if should_skip_transfer(&local_meta, server_meta, local_path).await? {
                // Send early completion
                channel
                    .send_complete(0, 0, FileTransferStatus::AlreadyUpToDate)
                    .await?;

                self.progress.on_progress(ProgressEvent::FileCompleted {
                    local_path: local_path.display().to_string(),
                    bytes: 0,
                    skipped: true,
                });

                return Ok(TransferStats {
                    bytes: 0,
                    skipped: true,
                    files_transferred: 0,
                    files_skipped: 1,
                    files_failed: 0,
                });
            }
        }

        // Check if server provided block checksums for delta sync
        let use_delta = options.delta_algo != DeltaAlgo::None
            && channel
                .metadata()
                .map(|m| !m.blocks.is_empty())
                .unwrap_or(false);

        let result = if use_delta {
            self.do_upload_delta(channel, local_path, remote_path, options, file_size)
                .await
        } else {
            self.do_upload_full(channel, local_path, remote_path, options, file_size)
                .await
        };

        match &result {
            Ok(stats) => {
                self.progress.on_progress(ProgressEvent::FileCompleted {
                    local_path: local_path.display().to_string(),
                    bytes: stats.bytes,
                    skipped: stats.skipped,
                });
            }
            Err(e) => {
                self.progress.on_progress(ProgressEvent::FileFailed {
                    local_path: local_path.display().to_string(),
                    error: e.to_string(),
                });
            }
        }

        result
    }

    /// Upload a file using full transfer (no delta).
    async fn do_upload_full(
        &self,
        channel: &FileChannel,
        local_path: &Path,
        _remote_path: &str,
        options: &TransferOptions,
        file_size: u64,
    ) -> Result<TransferStats> {
        // Open local file
        let mut file = File::open(local_path).await.map_err(|e| {
            qsh_core::Error::FileTransfer {
                message: format!("failed to open local file: {}", e),
            }
        })?;

        // Setup compression if enabled and file isn't already compressed
        let local_path_str = local_path.to_string_lossy();
        let use_compression = options.compress && !is_compressed_extension(&local_path_str);
        let compressor = if use_compression {
            Some(Compressor::with_default_level())
        } else {
            None
        };

        let mut hasher = StreamingHasher::new();
        let mut buf = vec![0u8; FILE_CHUNK_SIZE];
        let mut offset: u64 = 0;

        // Send file data
        loop {
            let n = file.read(&mut buf).await.map_err(|e| {
                qsh_core::Error::FileTransfer {
                    message: format!("failed to read local file: {}", e),
                }
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

            channel
                .send_data_with_flags(
                    offset,
                    send_data,
                    DataFlags {
                        compressed: is_compressed,
                        final_block: is_final,
                        block_ref: false,
                    },
                )
                .await?;

            offset += n as u64;

            self.progress.on_progress(ProgressEvent::FileProgress {
                local_path: local_path.display().to_string(),
                bytes_transferred: offset,
                total_bytes: file_size,
            });
        }

        let checksum = hasher.finish();

        // Wait for server completion
        wait_for_upload_complete(channel, checksum, offset).await
    }

    /// Upload a file using delta encoding.
    async fn do_upload_delta(
        &self,
        channel: &FileChannel,
        local_path: &Path,
        _remote_path: &str,
        options: &TransferOptions,
        file_size: u64,
    ) -> Result<TransferStats> {
        let server_meta = channel.metadata().ok_or_else(|| {
            qsh_core::Error::FileTransfer {
                message: "delta upload requires server metadata".to_string(),
            }
        })?;

        info!(
            blocks = server_meta.blocks.len(),
            "Using delta sync with {} blocks from server",
            server_meta.blocks.len()
        );

        // Build delta signature from server blocks
        let signature = DeltaSignature::new(&server_meta.blocks, DELTA_BLOCK_SIZE);

        // Read local file into memory for delta encoding
        // TODO: For very large files, implement streaming delta
        let local_data = fs::read(local_path).await.map_err(|e| {
            qsh_core::Error::FileTransfer {
                message: format!("failed to read local file: {}", e),
            }
        })?;

        // Compute delta operations
        let ops = DeltaEncoder::encode(signature, &local_data);

        // Calculate how much data we'll send
        let literal_bytes: usize = ops
            .iter()
            .filter_map(|op| match op {
                DeltaOp::Literal { data } => Some(data.len()),
                _ => None,
            })
            .sum();
        let copy_count = ops
            .iter()
            .filter(|op| matches!(op, DeltaOp::Copy { .. }))
            .count();

        info!(
            ops = ops.len(),
            literal_bytes = literal_bytes,
            copy_ops = copy_count,
            savings = format!(
                "{:.1}%",
                (1.0 - literal_bytes as f64 / file_size as f64) * 100.0
            ),
            "Delta computed"
        );

        // Setup compression if enabled
        let local_path_str = local_path.to_string_lossy();
        let use_compression = options.compress && !is_compressed_extension(&local_path_str);
        let compressor = if use_compression {
            Some(Compressor::with_default_level())
        } else {
            None
        };

        // Compute checksum of full file (server will verify this)
        let mut hasher = StreamingHasher::new();
        hasher.update(&local_data);
        let checksum = hasher.finish();

        // Send delta operations
        let mut bytes_sent = 0u64;
        let mut offset = 0u64;

        for (i, op) in ops.iter().enumerate() {
            let is_final = i == ops.len() - 1;

            match op {
                DeltaOp::Copy {
                    source_offset,
                    length,
                } => {
                    // Send a block reference - the server will copy from existing file
                    // Encode block ref as: source_offset (8 bytes) + length (8 bytes)
                    let mut ref_data = Vec::with_capacity(16);
                    ref_data.extend_from_slice(&source_offset.to_le_bytes());
                    ref_data.extend_from_slice(&length.to_le_bytes());

                    channel
                        .send_data_with_flags(
                            offset,
                            ref_data,
                            DataFlags {
                                compressed: false,
                                final_block: is_final,
                                block_ref: true,
                            },
                        )
                        .await?;

                    offset += *length;
                }
                DeltaOp::Literal { data } => {
                    // Send literal data
                    let (send_data, is_compressed) = if let Some(ref comp) = compressor {
                        if comp.should_compress(data) {
                            (comp.compress(data)?, true)
                        } else {
                            (data.clone(), false)
                        }
                    } else {
                        (data.clone(), false)
                    };

                    channel
                        .send_data_with_flags(
                            offset,
                            send_data,
                            DataFlags {
                                compressed: is_compressed,
                                final_block: is_final,
                                block_ref: false,
                            },
                        )
                        .await?;

                    bytes_sent += data.len() as u64;
                    offset += data.len() as u64;

                    self.progress.on_progress(ProgressEvent::FileProgress {
                        local_path: local_path.display().to_string(),
                        bytes_transferred: bytes_sent,
                        total_bytes: literal_bytes as u64,
                    });
                }
            }
        }

        // Wait for server completion
        wait_for_upload_complete(channel, checksum, file_size).await
    }

    /// Download a file from the remote server.
    async fn do_download(
        &self,
        channel: &FileChannel,
        local_path: &Path,
        server_meta: Option<&FileTransferMetadata>,
        _options: &TransferOptions,
    ) -> Result<TransferStats> {
        let file_size = server_meta.map(|m| m.size).unwrap_or(0);

        self.progress.on_progress(ProgressEvent::FileStarted {
            local_path: local_path.display().to_string(),
            remote_path: "".to_string(), // Server doesn't know remote path
            total_bytes: file_size,
        });

        // Check if local file exists and matches
        if let Some(meta) = server_meta {
            if let Ok(local_meta) = fs::metadata(local_path).await {
                if should_skip_download(&local_meta, meta, local_path).await? {
                    self.progress.on_progress(ProgressEvent::FileCompleted {
                        local_path: local_path.display().to_string(),
                        bytes: 0,
                        skipped: true,
                    });

                    return Ok(TransferStats {
                        bytes: 0,
                        skipped: true,
                        files_transferred: 0,
                        files_skipped: 1,
                        files_failed: 0,
                    });
                }
            }
        }

        // Create parent directories
        if let Some(parent) = local_path.parent() {
            fs::create_dir_all(parent).await.map_err(|e| {
                qsh_core::Error::FileTransfer {
                    message: format!("failed to create directory: {}", e),
                }
            })?;
        }

        // Use .qscp.partial for partial downloads
        let partial_path = local_path.with_extension("qscp.partial");

        // Check if we're resuming from a partial file
        let resume_offset = channel.resume_offset();
        let (mut file, mut hasher, mut total_bytes) = if resume_offset > 0 {
            // Open existing partial file for append
            if let Ok(partial_meta) = fs::metadata(&partial_path).await {
                if partial_meta.len() >= resume_offset {
                    debug!(
                        resume_offset = resume_offset,
                        "Resuming download from partial file"
                    );

                    // Read existing partial file to initialize hasher
                    let mut partial_file = File::open(&partial_path).await.map_err(|e| {
                        qsh_core::Error::FileTransfer {
                            message: format!("failed to open partial file for hashing: {}", e),
                        }
                    })?;
                    let mut hasher = StreamingHasher::new();
                    let mut buf = vec![0u8; FILE_CHUNK_SIZE];
                    let mut remaining = resume_offset;
                    while remaining > 0 {
                        let to_read = (remaining as usize).min(FILE_CHUNK_SIZE);
                        let n = partial_file.read(&mut buf[..to_read]).await.map_err(|e| {
                            qsh_core::Error::FileTransfer {
                                message: format!("failed to read partial file: {}", e),
                            }
                        })?;
                        if n == 0 {
                            break;
                        }
                        hasher.update(&buf[..n]);
                        remaining -= n as u64;
                    }

                    // Open for append
                    let mut file = OpenOptions::new()
                        .write(true)
                        .open(&partial_path)
                        .await
                        .map_err(|e| qsh_core::Error::FileTransfer {
                            message: format!("failed to open partial file for resume: {}", e),
                        })?;
                    file.seek(std::io::SeekFrom::Start(resume_offset))
                        .await
                        .map_err(|e| qsh_core::Error::FileTransfer {
                            message: format!("failed to seek in partial file: {}", e),
                        })?;

                    (file, hasher, resume_offset)
                } else {
                    // Partial file too small, start fresh
                    warn!("Partial file smaller than resume offset, starting fresh");
                    let file = OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(&partial_path)
                        .await
                        .map_err(|e| qsh_core::Error::FileTransfer {
                            message: format!("failed to create partial file: {}", e),
                        })?;
                    (file, StreamingHasher::new(), 0)
                }
            } else {
                // No partial file, start fresh
                let file = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(&partial_path)
                    .await
                    .map_err(|e| qsh_core::Error::FileTransfer {
                        message: format!("failed to create partial file: {}", e),
                    })?;
                (file, StreamingHasher::new(), 0)
            }
        } else {
            // No resume, create fresh partial file
            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&partial_path)
                .await
                .map_err(|e| qsh_core::Error::FileTransfer {
                    message: format!("failed to create partial file: {}", e),
                })?;
            (file, StreamingHasher::new(), 0)
        };

        // Setup decompressor for compressed data
        let decompressor = Decompressor::new();

        // Receive file data
        loop {
            let msg = channel.recv().await?;

            match msg {
                Message::ChannelDataMsg(ChannelData {
                    payload: ChannelPayload::FileData(data),
                    ..
                }) => {
                    // Seek if not sequential
                    if data.offset != total_bytes {
                        file.seek(std::io::SeekFrom::Start(data.offset))
                            .await
                            .map_err(|e| qsh_core::Error::FileTransfer {
                                message: format!("failed to seek: {}", e),
                            })?;
                    }

                    // Decompress data if needed
                    let write_data = if data.flags.compressed {
                        decompressor.decompress(&data.data)?
                    } else {
                        data.data
                    };

                    file.write_all(&write_data).await.map_err(|e| {
                        qsh_core::Error::FileTransfer {
                            message: format!("failed to write: {}", e),
                        }
                    })?;

                    hasher.update(&write_data);
                    total_bytes = data.offset + write_data.len() as u64;

                    self.progress.on_progress(ProgressEvent::FileProgress {
                        local_path: local_path.display().to_string(),
                        bytes_transferred: total_bytes,
                        total_bytes: file_size,
                    });

                    if data.flags.final_block {
                        // Don't break yet, wait for FileComplete
                    }
                }
                Message::ChannelDataMsg(ChannelData {
                    payload: ChannelPayload::FileComplete(complete),
                    ..
                }) => {
                    // Flush and close
                    file.flush().await.map_err(|e| {
                        qsh_core::Error::FileTransfer {
                            message: format!("failed to flush: {}", e),
                        }
                    })?;
                    file.sync_all().await.map_err(|e| {
                        qsh_core::Error::FileTransfer {
                            message: format!("failed to sync: {}", e),
                        }
                    })?;
                    drop(file);

                    // Verify checksum
                    let local_checksum = hasher.finish();
                    if complete.checksum != local_checksum {
                        let _ = fs::remove_file(&partial_path).await;
                        return Err(qsh_core::Error::FileTransfer {
                            message: format!(
                                "checksum mismatch: local={:016x} remote={:016x}",
                                local_checksum, complete.checksum
                            ),
                        });
                    }

                    // Rename partial to final
                    fs::rename(&partial_path, local_path)
                        .await
                        .map_err(|e| qsh_core::Error::FileTransfer {
                            message: format!("failed to rename partial file: {}", e),
                        })?;

                    self.progress.on_progress(ProgressEvent::FileCompleted {
                        local_path: local_path.display().to_string(),
                        bytes: total_bytes,
                        skipped: false,
                    });

                    return Ok(TransferStats {
                        bytes: total_bytes,
                        skipped: false,
                        files_transferred: 1,
                        files_skipped: 0,
                        files_failed: 0,
                    });
                }
                Message::ChannelDataMsg(ChannelData {
                    payload: ChannelPayload::FileError(err),
                    ..
                }) => {
                    // Keep partial file for resume support
                    info!(
                        partial_path = %partial_path.display(),
                        bytes_received = total_bytes,
                        "Transfer failed, partial file preserved for resume"
                    );

                    let error = qsh_core::Error::FileTransfer {
                        message: format!("server error: {:?} - {}", err.code, err.message),
                    };

                    self.progress.on_progress(ProgressEvent::FileFailed {
                        local_path: local_path.display().to_string(),
                        error: error.to_string(),
                    });

                    return Err(error);
                }
                _ => {
                    debug!(msg = ?msg, "Ignoring unexpected message");
                }
            }
        }
    }
}

/// Check if we should skip the upload (file already up to date).
async fn should_skip_transfer(
    local_meta: &std::fs::Metadata,
    server_meta: &FileTransferMetadata,
    local_path: &Path,
) -> Result<bool> {
    // Quick checks first
    if local_meta.len() != server_meta.size {
        return Ok(false);
    }

    let local_mtime = local_meta
        .modified()
        .map(|t| {
            t.duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        })
        .unwrap_or(0);

    if local_mtime != server_meta.mtime {
        return Ok(false);
    }

    // If server provided hash, compare it
    if let Some(server_hash) = server_meta.file_hash {
        let local_hash = compute_file_hash(local_path).await?;
        return Ok(local_hash == server_hash);
    }

    // Size and mtime match, no hash to compare
    Ok(true)
}

/// Check if we should skip the download (local file already up to date).
async fn should_skip_download(
    local_meta: &std::fs::Metadata,
    server_meta: &FileTransferMetadata,
    local_path: &Path,
) -> Result<bool> {
    // Quick checks first
    if local_meta.len() != server_meta.size {
        return Ok(false);
    }

    let local_mtime = local_meta
        .modified()
        .map(|t| {
            t.duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        })
        .unwrap_or(0);

    if local_mtime != server_meta.mtime {
        return Ok(false);
    }

    // If server provided hash, compare it
    if let Some(server_hash) = server_meta.file_hash {
        let local_hash = compute_file_hash(local_path).await?;
        return Ok(local_hash == server_hash);
    }

    Ok(true)
}

/// Compute xxHash64 for a local file.
async fn compute_file_hash(path: &Path) -> Result<u64> {
    let mut file = File::open(path).await.map_err(|e| {
        qsh_core::Error::FileTransfer {
            message: format!("failed to open file for hashing: {}", e),
        }
    })?;

    let mut hasher = StreamingHasher::new();
    let mut buf = vec![0u8; FILE_CHUNK_SIZE];

    loop {
        let n = file.read(&mut buf).await.map_err(|e| {
            qsh_core::Error::FileTransfer {
                message: format!("failed to read file for hashing: {}", e),
            }
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    Ok(hasher.finish())
}

/// Wait for server to confirm upload completion.
async fn wait_for_upload_complete(
    channel: &FileChannel,
    checksum: u64,
    total_bytes: u64,
) -> Result<TransferStats> {
    loop {
        let msg = channel.recv().await?;
        match msg {
            Message::ChannelDataMsg(ChannelData {
                payload: ChannelPayload::FileComplete(complete),
                ..
            }) => {
                if complete.checksum != checksum {
                    return Err(qsh_core::Error::FileTransfer {
                        message: format!(
                            "checksum mismatch: local={:016x} remote={:016x}",
                            checksum, complete.checksum
                        ),
                    });
                }
                return Ok(TransferStats {
                    bytes: total_bytes,
                    skipped: false,
                    files_transferred: 1,
                    files_skipped: 0,
                    files_failed: 0,
                });
            }
            Message::ChannelDataMsg(ChannelData {
                payload: ChannelPayload::FileAck(_),
                ..
            }) => {
                // Ignore acks for now
            }
            Message::ChannelDataMsg(ChannelData {
                payload: ChannelPayload::FileError(err),
                ..
            }) => {
                return Err(qsh_core::Error::FileTransfer {
                    message: format!("server error: {:?} - {}", err.code, err.message),
                });
            }
            _ => {
                debug!(msg = ?msg, "Ignoring unexpected message");
            }
        }
    }
}
