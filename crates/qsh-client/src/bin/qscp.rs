//! qscp: File transfer utility for qsh.
//!
//! Transfers files to/from remote hosts using the qsh protocol.

use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use clap::Parser;
use futures::stream::{self, StreamExt};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

use qsh_client::{ChannelConnection, CpCli, FileChannel, FilePath, random_local_port};

#[cfg(not(feature = "standalone"))]
use qsh_client::{BootstrapMode, SshConfig, bootstrap};
use qsh_core::file::checksum::StreamingHasher;
use qsh_core::file::compress::{Compressor, Decompressor, is_compressed_extension};
use qsh_core::file::delta::{DeltaEncoder, DeltaOp, DeltaSignature};
use qsh_core::protocol::{
    ChannelData, ChannelPayload, DataFlags, DeltaAlgo, FileTransferMetadata, FileTransferStatus,
    Message, TransferOptions,
};

#[cfg(feature = "standalone")]
use qsh_client::standalone::authenticate as standalone_authenticate;
#[cfg(feature = "standalone")]
use qsh_client::{DirectAuthenticator, DirectConfig, establish_quic_connection};

/// Chunk size for file data (32KB).
const FILE_CHUNK_SIZE: usize = 32 * 1024;

/// Block size for delta sync (128KB) - must match server.
const DELTA_BLOCK_SIZE: usize = 128 * 1024;

fn main() {
    let cli = CpCli::parse();

    // Initialize logging
    let level = match cli.verbose {
        0 => tracing::Level::WARN,
        1 => tracing::Level::INFO,
        2 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };

    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .init();

    info!(version = env!("CARGO_PKG_VERSION"), "qscp starting");

    // Validate source and dest
    let source = cli.source_path();
    let dest = cli.dest_path();

    // Must be one local and one remote
    if !cli.is_upload() && !cli.is_download() {
        eprintln!("qscp: one path must be remote ([user@]host:path)");
        std::process::exit(1);
    }

    // Get remote info
    let (host, user) = match cli.remote_host() {
        Some((h, u)) => (h, u),
        None => {
            eprintln!("qscp: no remote host specified");
            std::process::exit(1);
        }
    };

    info!(host = %host, user = ?user, "Connecting to remote host");

    // Create tokio runtime
    let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");

    let result =
        rt.block_on(async { run_transfer(&cli, &host, user.as_deref(), &source, &dest).await });

    if let Err(e) = result {
        error!(error = %e, "Transfer failed");
        eprintln!("qscp: {}", e);
        std::process::exit(1);
    }
}

async fn run_transfer(
    cli: &CpCli,
    host: &str,
    user: Option<&str>,
    source: &FilePath,
    dest: &FilePath,
) -> qsh_core::Result<()> {
    // Connect using the channel model
    let conn = Arc::new(connect(cli, host, user).await?);

    // Determine transfer direction
    let is_upload = cli.is_upload();

    // Get local and remote paths
    let (local_path, remote_path) = if is_upload {
        let local = match source {
            FilePath::Local(p) => p.clone(),
            _ => unreachable!(),
        };
        let remote = match dest {
            FilePath::Remote { path, .. } => path.clone(),
            _ => unreachable!(),
        };
        (local, remote)
    } else {
        let remote = match source {
            FilePath::Remote { path, .. } => path.clone(),
            _ => unreachable!(),
        };
        let local = match dest {
            FilePath::Local(p) => p.clone(),
            _ => unreachable!(),
        };
        (local, remote)
    };

    // Build transfer options
    let options = cli.transfer_options();

    // Check if this is a directory transfer
    let local_meta = fs::metadata(&local_path).await;
    let is_directory = local_meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);

    if is_directory && !options.recursive {
        return Err(qsh_core::Error::FileTransfer {
            message: format!(
                "{} is a directory (use -r for recursive)",
                local_path.display()
            ),
        });
    }

    let start_time = Instant::now();

    if is_directory && is_upload {
        // Recursive directory upload
        let result = do_recursive_upload(&conn, &local_path, &remote_path, &options).await;
        if let Ok(conn) = Arc::try_unwrap(conn) {
            conn.close().await?;
        }
        return result;
    }

    // Check for resume support
    let resume_from = if cli.resume {
        if is_upload {
            // For uploads, we'll check server metadata after opening channel
            None
        } else {
            // For downloads, check for partial file
            let partial_path = local_path.with_extension("qscp.partial");
            if let Ok(partial_meta) = fs::metadata(&partial_path).await {
                let partial_size = partial_meta.len();
                if partial_size > 0 {
                    info!(
                        partial_size = partial_size,
                        path = %partial_path.display(),
                        "Found partial file, attempting resume"
                    );
                    Some(partial_size)
                } else {
                    None
                }
            } else {
                None
            }
        }
    } else {
        None
    };

    // Single file transfer
    let transfer_params = qsh_core::protocol::FileTransferParams {
        path: remote_path.clone(),
        direction: if is_upload {
            qsh_core::protocol::TransferDirection::Upload
        } else {
            qsh_core::protocol::TransferDirection::Download
        },
        options: options.clone(),
        resume_from,
    };

    info!(
        direction = if is_upload { "upload" } else { "download" },
        local = %local_path.display(),
        remote = %remote_path,
        "Opening file transfer channel"
    );

    let file_channel = conn.open_file_transfer(transfer_params).await?;
    debug!(channel_id = ?file_channel.channel_id(), "File transfer channel opened");

    // Run the transfer
    let result = if is_upload {
        do_upload(&file_channel, &local_path, &remote_path, &options).await
    } else {
        do_download(
            &file_channel,
            &local_path,
            file_channel.metadata(),
            &options,
        )
        .await
    };

    // Close the channel and connection
    file_channel.mark_closed();
    if let Ok(conn) = Arc::try_unwrap(conn) {
        conn.close().await?;
    }

    match result {
        Ok(stats) => {
            let elapsed = start_time.elapsed();
            let speed = if elapsed.as_secs_f64() > 0.0 {
                stats.bytes as f64 / elapsed.as_secs_f64() / 1024.0 / 1024.0
            } else {
                0.0
            };

            if stats.skipped {
                eprintln!("{}: already up to date", local_path.display());
            } else {
                eprintln!(
                    "{}: {} bytes transferred in {:.2}s ({:.2} MB/s)",
                    local_path.display(),
                    stats.bytes,
                    elapsed.as_secs_f64(),
                    speed
                );
            }
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Transfer statistics.
struct TransferStats {
    bytes: u64,
    skipped: bool,
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

/// Recursively collect all files in a directory.
async fn collect_files(base_path: &Path) -> qsh_core::Result<Vec<FileEntry>> {
    let mut files = Vec::new();
    let mut stack = vec![base_path.to_path_buf()];

    while let Some(dir_path) = stack.pop() {
        let mut entries =
            fs::read_dir(&dir_path)
                .await
                .map_err(|e| qsh_core::Error::FileTransfer {
                    message: format!("failed to read directory {}: {}", dir_path.display(), e),
                })?;

        while let Some(entry) =
            entries
                .next_entry()
                .await
                .map_err(|e| qsh_core::Error::FileTransfer {
                    message: format!("failed to read entry: {}", e),
                })?
        {
            let path = entry.path();
            let metadata = entry
                .metadata()
                .await
                .map_err(|e| qsh_core::Error::FileTransfer {
                    message: format!("failed to get metadata for {}: {}", path.display(), e),
                })?;

            if metadata.is_dir() {
                stack.push(path);
            } else if metadata.is_file() {
                let relative_path = path
                    .strip_prefix(base_path)
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
    Ok(files)
}

/// Perform recursive directory upload with parallel transfers.
async fn do_recursive_upload(
    conn: &Arc<ChannelConnection>,
    local_base: &Path,
    remote_base: &str,
    options: &TransferOptions,
) -> qsh_core::Result<()> {
    let start_time = Instant::now();

    // Collect all files
    eprintln!("Scanning {}...", local_base.display());
    let files = collect_files(local_base).await?;

    if files.is_empty() {
        eprintln!("No files to transfer");
        return Ok(());
    }

    let total_files = files.len();
    let total_bytes: u64 = files.iter().map(|f| f.size).sum();
    eprintln!("Found {} files ({} bytes total)", total_files, total_bytes);

    // Setup progress tracking
    let mp = MultiProgress::new();
    let overall_pb = mp.add(ProgressBar::new(total_bytes));
    overall_pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({percent}%) {msg}",
            )
            .unwrap()
            .progress_chars("=>-"),
    );
    overall_pb.set_message(format!("0/{} files", total_files));

    // Setup parallel transfer semaphore
    let semaphore = Arc::new(Semaphore::new(options.parallel.max(1)));
    let transferred_bytes = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let transferred_files = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let skipped_files = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let failed_files = Arc::new(std::sync::atomic::AtomicU64::new(0));

    // Process files in parallel
    let results: Vec<_> = stream::iter(files)
        .map(|file| {
            let conn = Arc::clone(conn);
            let semaphore = Arc::clone(&semaphore);
            let options = options.clone();
            let remote_base = remote_base.to_string();
            let transferred_bytes = Arc::clone(&transferred_bytes);
            let transferred_files = Arc::clone(&transferred_files);
            let skipped_files = Arc::clone(&skipped_files);
            let failed_files = Arc::clone(&failed_files);
            let overall_pb = overall_pb.clone();
            let total_files = total_files;

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
                let transfer_params = qsh_core::protocol::FileTransferParams {
                    path: remote_path.clone(),
                    direction: qsh_core::protocol::TransferDirection::Upload,
                    options: options.clone(),
                    resume_from: None,
                };

                // Open channel and transfer
                match conn.open_file_transfer(transfer_params).await {
                    Ok(channel) => {
                        let result = do_upload(&channel, &file.local_path, &remote_path, &options).await;
                        channel.mark_closed();

                        match result {
                            Ok(stats) => {
                                if stats.skipped {
                                    skipped_files.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                } else {
                                    transferred_bytes.fetch_add(stats.bytes, std::sync::atomic::Ordering::SeqCst);
                                }
                                transferred_files.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            }
                            Err(e) => {
                                warn!(path = %file.local_path.display(), error = %e, "Transfer failed");
                                failed_files.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            }
                        }
                    }
                    Err(e) => {
                        warn!(path = %file.local_path.display(), error = %e, "Failed to open channel");
                        failed_files.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                }

                // Update overall progress
                let done = transferred_files.load(std::sync::atomic::Ordering::SeqCst)
                    + skipped_files.load(std::sync::atomic::Ordering::SeqCst)
                    + failed_files.load(std::sync::atomic::Ordering::SeqCst);
                let bytes = transferred_bytes.load(std::sync::atomic::Ordering::SeqCst);
                overall_pb.set_position(bytes);
                overall_pb.set_message(format!("{}/{} files", done, total_files));
            }
        })
        .buffer_unordered(options.parallel.max(1))
        .collect()
        .await;

    overall_pb.finish_with_message("complete");

    // Print summary
    let elapsed = start_time.elapsed();
    let bytes = transferred_bytes.load(std::sync::atomic::Ordering::SeqCst);
    let transferred = transferred_files.load(std::sync::atomic::Ordering::SeqCst);
    let skipped = skipped_files.load(std::sync::atomic::Ordering::SeqCst);
    let failed = failed_files.load(std::sync::atomic::Ordering::SeqCst);

    let speed = if elapsed.as_secs_f64() > 0.0 {
        bytes as f64 / elapsed.as_secs_f64() / 1024.0 / 1024.0
    } else {
        0.0
    };

    eprintln!(
        "\nTransferred {} files ({} bytes) in {:.2}s ({:.2} MB/s)",
        transferred,
        bytes,
        elapsed.as_secs_f64(),
        speed
    );
    if skipped > 0 {
        eprintln!("Skipped {} files (already up to date)", skipped);
    }
    if failed > 0 {
        eprintln!("Failed {} files", failed);
        return Err(qsh_core::Error::FileTransfer {
            message: format!("{} files failed to transfer", failed),
        });
    }

    // Consume results to ensure all futures completed
    drop(results);

    Ok(())
}

/// Upload a file to the remote server.
async fn do_upload(
    channel: &FileChannel,
    local_path: &Path,
    remote_path: &str,
    options: &TransferOptions,
) -> qsh_core::Result<TransferStats> {
    // Get local file metadata
    let local_meta = fs::metadata(local_path)
        .await
        .map_err(|e| qsh_core::Error::FileTransfer {
            message: format!("failed to stat local file: {}", e),
        })?;

    if local_meta.is_dir() {
        return Err(qsh_core::Error::FileTransfer {
            message: "directory transfer not yet implemented (use -r flag)".to_string(),
        });
    }

    let file_size = local_meta.len();

    // Check if we can skip (server sends existing file metadata if skip_if_unchanged)
    if let Some(server_meta) = channel.metadata() {
        if should_skip_transfer(&local_meta, server_meta, local_path).await? {
            // Send early completion
            channel
                .send_complete(0, 0, FileTransferStatus::AlreadyUpToDate)
                .await?;
            return Ok(TransferStats {
                bytes: 0,
                skipped: true,
            });
        }
    }

    // Check if server provided block checksums for delta sync
    let use_delta = options.delta_algo != DeltaAlgo::None
        && channel
            .metadata()
            .map(|m| !m.blocks.is_empty())
            .unwrap_or(false);

    if use_delta {
        do_upload_delta(channel, local_path, remote_path, options, file_size).await
    } else {
        do_upload_full(channel, local_path, remote_path, options, file_size).await
    }
}

/// Upload a file using full transfer (no delta).
async fn do_upload_full(
    channel: &FileChannel,
    local_path: &Path,
    remote_path: &str,
    options: &TransferOptions,
    file_size: u64,
) -> qsh_core::Result<TransferStats> {
    // Open local file
    let mut file = File::open(local_path)
        .await
        .map_err(|e| qsh_core::Error::FileTransfer {
            message: format!("failed to open local file: {}", e),
        })?;

    // Setup compression if enabled and file isn't already compressed
    let local_path_str = local_path.to_string_lossy();
    let use_compression = options.compress && !is_compressed_extension(&local_path_str);
    let compressor = if use_compression {
        Some(Compressor::with_default_level())
    } else {
        None
    };

    // Setup progress bar
    let pb = create_progress_bar(file_size, remote_path);

    let mut hasher = StreamingHasher::new();
    let mut buf = vec![0u8; FILE_CHUNK_SIZE];
    let mut offset: u64 = 0;

    // Send file data
    loop {
        let n = file
            .read(&mut buf)
            .await
            .map_err(|e| qsh_core::Error::FileTransfer {
                message: format!("failed to read local file: {}", e),
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
        pb.set_position(offset);
    }

    pb.finish_with_message("sent");

    let checksum = hasher.finish();

    // Wait for server completion
    wait_for_upload_complete(channel, checksum, offset).await
}

/// Upload a file using delta encoding.
async fn do_upload_delta(
    channel: &FileChannel,
    local_path: &Path,
    remote_path: &str,
    options: &TransferOptions,
    file_size: u64,
) -> qsh_core::Result<TransferStats> {
    let server_meta = channel
        .metadata()
        .ok_or_else(|| qsh_core::Error::FileTransfer {
            message: "delta upload requires server metadata".to_string(),
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
    let local_data = fs::read(local_path)
        .await
        .map_err(|e| qsh_core::Error::FileTransfer {
            message: format!("failed to read local file: {}", e),
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

    // Setup progress bar (based on literal bytes we'll send)
    let pb = create_progress_bar(literal_bytes as u64, remote_path);
    pb.set_message(format!("{} (delta)", remote_path));

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
                pb.set_position(bytes_sent);
            }
        }
    }

    pb.finish_with_message("sent (delta)");

    // Wait for server completion
    wait_for_upload_complete(channel, checksum, file_size).await
}

/// Wait for server to confirm upload completion.
async fn wait_for_upload_complete(
    channel: &FileChannel,
    checksum: u64,
    total_bytes: u64,
) -> qsh_core::Result<TransferStats> {
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

/// Download a file from the remote server.
async fn do_download(
    channel: &FileChannel,
    local_path: &Path,
    server_meta: Option<&FileTransferMetadata>,
    _options: &TransferOptions,
) -> qsh_core::Result<TransferStats> {
    let file_size = server_meta.map(|m| m.size).unwrap_or(0);

    // Check if local file exists and matches
    if let Some(meta) = server_meta {
        if let Ok(local_meta) = fs::metadata(local_path).await {
            if should_skip_download(&local_meta, meta, local_path).await? {
                return Ok(TransferStats {
                    bytes: 0,
                    skipped: true,
                });
            }
        }
    }

    // Create parent directories
    if let Some(parent) = local_path.parent() {
        fs::create_dir_all(parent)
            .await
            .map_err(|e| qsh_core::Error::FileTransfer {
                message: format!("failed to create directory: {}", e),
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
                let mut partial_file =
                    File::open(&partial_path)
                        .await
                        .map_err(|e| qsh_core::Error::FileTransfer {
                            message: format!("failed to open partial file for hashing: {}", e),
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

    // Setup progress bar
    let filename = local_path.file_name().unwrap_or_default().to_string_lossy();
    let pb = create_progress_bar(file_size, &filename);
    if total_bytes > 0 {
        pb.set_position(total_bytes);
    }

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

                file.write_all(&write_data)
                    .await
                    .map_err(|e| qsh_core::Error::FileTransfer {
                        message: format!("failed to write: {}", e),
                    })?;

                hasher.update(&write_data);
                total_bytes = data.offset + write_data.len() as u64;
                pb.set_position(total_bytes);

                if data.flags.final_block {
                    // Don't break yet, wait for FileComplete
                }
            }
            Message::ChannelDataMsg(ChannelData {
                payload: ChannelPayload::FileComplete(complete),
                ..
            }) => {
                pb.finish_with_message("received");

                // Flush and close
                file.flush()
                    .await
                    .map_err(|e| qsh_core::Error::FileTransfer {
                        message: format!("failed to flush: {}", e),
                    })?;
                file.sync_all()
                    .await
                    .map_err(|e| qsh_core::Error::FileTransfer {
                        message: format!("failed to sync: {}", e),
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
                fs::rename(&partial_path, local_path).await.map_err(|e| {
                    qsh_core::Error::FileTransfer {
                        message: format!("failed to rename partial file: {}", e),
                    }
                })?;

                return Ok(TransferStats {
                    bytes: total_bytes,
                    skipped: false,
                });
            }
            Message::ChannelDataMsg(ChannelData {
                payload: ChannelPayload::FileError(err),
                ..
            }) => {
                pb.finish_with_message("error");
                // Keep partial file for resume support
                info!(
                    partial_path = %partial_path.display(),
                    bytes_received = total_bytes,
                    "Transfer failed, partial file preserved for resume"
                );
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

/// Check if we should skip the upload (file already up to date).
async fn should_skip_transfer(
    local_meta: &std::fs::Metadata,
    server_meta: &FileTransferMetadata,
    local_path: &Path,
) -> qsh_core::Result<bool> {
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
) -> qsh_core::Result<bool> {
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
async fn compute_file_hash(path: &Path) -> qsh_core::Result<u64> {
    let mut file = File::open(path)
        .await
        .map_err(|e| qsh_core::Error::FileTransfer {
            message: format!("failed to open file for hashing: {}", e),
        })?;

    let mut hasher = StreamingHasher::new();
    let mut buf = vec![0u8; FILE_CHUNK_SIZE];

    loop {
        let n = file
            .read(&mut buf)
            .await
            .map_err(|e| qsh_core::Error::FileTransfer {
                message: format!("failed to read file for hashing: {}", e),
            })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    Ok(hasher.finish())
}

/// Create a progress bar for file transfer.
fn create_progress_bar(total: u64, filename: &str) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}) {msg}")
            .unwrap()
            .progress_chars("=>-"),
    );
    pb.set_message(filename.to_string());
    pb
}

#[cfg(feature = "standalone")]
async fn connect(
    cli: &CpCli,
    host: &str,
    _user: Option<&str>,
) -> qsh_core::Result<ChannelConnection> {
    use rand::RngCore;

    // Determine server address
    let server_addr_str = if let Some(ref server) = cli.server {
        server.clone()
    } else {
        format!("{}:4433", host)
    };

    let direct_config = DirectConfig {
        server_addr: server_addr_str.clone(),
        key_path: cli.key.clone(),
        known_hosts_path: cli.known_hosts.clone(),
        accept_unknown_host: cli.accept_unknown_host,
        no_agent: cli.no_agent,
    };

    // Build authenticator
    let mut authenticator = DirectAuthenticator::new(&direct_config).await?;

    // Resolve address
    let server_sock_addr = server_addr_str
        .to_socket_addrs()
        .map_err(|e| qsh_core::Error::Transport {
            message: format!("failed to resolve server address: {}", e),
        })?
        .next()
        .ok_or_else(|| qsh_core::Error::Transport {
            message: "no addresses found for server".to_string(),
        })?;

    // Generate session key
    let mut session_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut session_key);

    // Build connection config
    let config = qsh_client::ConnectionConfig {
        server_addr: server_sock_addr,
        session_key,
        cert_hash: None,
        term_size: qsh_core::protocol::TermSize { cols: 80, rows: 24 },
        term_type: "xterm-256color".to_string(),
        env: Vec::new(),
        predictive_echo: false,
        connect_timeout: std::time::Duration::from_secs(30),
        zero_rtt_available: false,
        keep_alive_interval: Some(std::time::Duration::from_millis(500)),
        max_idle_timeout: std::time::Duration::from_secs(15),
        session_data: None,
        local_port: Some(random_local_port()),
    };

    info!(addr = %config.server_addr, "Connecting to server");

    // Connect and authenticate
    let quic_conn = establish_quic_connection(&config).await?;

    // Authenticate
    let (mut send, mut recv) =
        quic_conn
            .accept_bi()
            .await
            .map_err(|e| qsh_core::Error::Transport {
                message: format!("failed to accept auth stream: {}", e),
            })?;

    standalone_authenticate(&mut authenticator, &mut send, &mut recv).await?;
    info!("Authentication succeeded");

    // Complete qsh handshake using channel model
    let conn = ChannelConnection::from_quic(quic_conn, config).await?;
    info!(rtt = ?conn.rtt().await, session_id = ?conn.session_id(), "Connected");

    Ok(conn)
}

#[cfg(not(feature = "standalone"))]
async fn connect(
    cli: &CpCli,
    host: &str,
    user: Option<&str>,
) -> qsh_core::Result<ChannelConnection> {
    // Bootstrap via SSH
    let ssh_config = SshConfig {
        connect_timeout: std::time::Duration::from_secs(30),
        identity_file: cli.identity.first().cloned(),
        skip_host_key_check: false,
        port_range: None,
        server_args: None,
        server_env: Vec::new(),
        mode: BootstrapMode::SshCli,
    };

    let handle = bootstrap(host, cli.port, user, &ssh_config).await?;
    let server_info = &handle.server_info;

    // Use bootstrap info to connect
    let connect_host = if server_info.address == "0.0.0.0"
        || server_info.address == "::"
        || server_info.address.starts_with("0.")
    {
        host.to_string()
    } else {
        server_info.address.clone()
    };

    let addr = format!("{}:{}", connect_host, server_info.port)
        .to_socket_addrs()
        .map_err(|e| qsh_core::Error::Transport {
            message: format!("failed to resolve server address: {}", e),
        })?
        .next()
        .ok_or_else(|| qsh_core::Error::Transport {
            message: "no addresses found for server".to_string(),
        })?;

    let session_key = server_info.decode_session_key()?;
    let cert_hash = server_info.decode_cert_hash().ok();

    let config = qsh_client::ConnectionConfig {
        server_addr: addr,
        session_key,
        cert_hash,
        term_size: qsh_core::protocol::TermSize { cols: 80, rows: 24 },
        term_type: "xterm-256color".to_string(),
        env: Vec::new(),
        predictive_echo: false,
        connect_timeout: std::time::Duration::from_secs(30),
        zero_rtt_available: false,
        keep_alive_interval: Some(std::time::Duration::from_millis(500)),
        max_idle_timeout: std::time::Duration::from_secs(15),
        session_data: None,
        local_port: Some(random_local_port()),
    };

    // Connect using the channel model
    let conn = ChannelConnection::connect(config).await?;
    info!(rtt = ?conn.rtt().await, session_id = ?conn.session_id(), "Connected");

    // Drop bootstrap handle after connection
    drop(handle);

    Ok(conn)
}
