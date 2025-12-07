//! qscp: File transfer utility for qsh.
//!
//! Transfers files to/from remote hosts using the qsh protocol.

use std::net::ToSocketAddrs;
use std::path::Path;
use std::time::Instant;

use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tracing::{debug, error, info};

use qsh_client::{BootstrapMode, ChannelConnection, CpCli, FileChannel, FilePath, SshConfig, bootstrap};
use qsh_core::file::checksum::StreamingHasher;
use qsh_core::file::compress::{Compressor, Decompressor, is_compressed_extension};
use qsh_core::protocol::{
    ChannelData, ChannelPayload, DataFlags, FileTransferMetadata, FileTransferStatus, Message,
    TransferOptions,
};

#[cfg(feature = "standalone")]
use qsh_client::standalone::authenticate as standalone_authenticate;
#[cfg(feature = "standalone")]
use qsh_client::{DirectAuthenticator, DirectConfig, connect_quic};

/// Chunk size for file data (32KB).
const FILE_CHUNK_SIZE: usize = 32 * 1024;

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

    let result = rt.block_on(async {
        run_transfer(&cli, &host, user.as_deref(), &source, &dest).await
    });

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
    let conn = connect(cli, host, user).await?;

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

    // Open a file transfer channel
    let transfer_params = qsh_core::protocol::FileTransferParams {
        path: remote_path.clone(),
        direction: if is_upload {
            qsh_core::protocol::TransferDirection::Upload
        } else {
            qsh_core::protocol::TransferDirection::Download
        },
        options: options.clone(),
        resume_from: None,
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
    let start_time = Instant::now();
    let result = if is_upload {
        do_upload(&file_channel, &local_path, &remote_path, &options).await
    } else {
        do_download(&file_channel, &local_path, file_channel.metadata(), &options).await
    };

    // Close the channel and connection
    file_channel.mark_closed();
    conn.close().await?;

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

/// Upload a file to the remote server.
async fn do_upload(
    channel: &FileChannel,
    local_path: &Path,
    remote_path: &str,
    options: &TransferOptions,
) -> qsh_core::Result<TransferStats> {
    // Get local file metadata
    let local_meta = fs::metadata(local_path).await.map_err(|e| qsh_core::Error::FileTransfer {
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
            channel.send_complete(0, 0, FileTransferStatus::AlreadyUpToDate).await?;
            return Ok(TransferStats { bytes: 0, skipped: true });
        }
    }

    // Open local file
    let mut file = File::open(local_path).await.map_err(|e| qsh_core::Error::FileTransfer {
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
        let n = file.read(&mut buf).await.map_err(|e| qsh_core::Error::FileTransfer {
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

        channel.send_data_with_flags(
            offset,
            send_data,
            DataFlags {
                compressed: is_compressed,
                final_block: is_final,
                block_ref: false,
            },
        ).await?;

        offset += n as u64;
        pb.set_position(offset);
    }

    pb.finish_with_message("sent");

    let checksum = hasher.finish();

    // Wait for server completion
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
                return Ok(TransferStats { bytes: offset, skipped: false });
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
                return Ok(TransferStats { bytes: 0, skipped: true });
            }
        }
    }

    // Create parent directories
    if let Some(parent) = local_path.parent() {
        fs::create_dir_all(parent).await.map_err(|e| qsh_core::Error::FileTransfer {
            message: format!("failed to create directory: {}", e),
        })?;
    }

    // Open temp file for writing
    let temp_path = local_path.with_extension("qscp.tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temp_path)
        .await
        .map_err(|e| qsh_core::Error::FileTransfer {
            message: format!("failed to create temp file: {}", e),
        })?;

    // Setup decompressor for compressed data
    let decompressor = Decompressor::new();

    // Setup progress bar
    let filename = local_path.file_name().unwrap_or_default().to_string_lossy();
    let pb = create_progress_bar(file_size, &filename);

    let mut hasher = StreamingHasher::new();
    let mut total_bytes: u64 = 0;

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

                file.write_all(&write_data).await.map_err(|e| qsh_core::Error::FileTransfer {
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
                file.flush().await.map_err(|e| qsh_core::Error::FileTransfer {
                    message: format!("failed to flush: {}", e),
                })?;
                file.sync_all().await.map_err(|e| qsh_core::Error::FileTransfer {
                    message: format!("failed to sync: {}", e),
                })?;
                drop(file);

                // Verify checksum
                let local_checksum = hasher.finish();
                if complete.checksum != local_checksum {
                    let _ = fs::remove_file(&temp_path).await;
                    return Err(qsh_core::Error::FileTransfer {
                        message: format!(
                            "checksum mismatch: local={:016x} remote={:016x}",
                            local_checksum, complete.checksum
                        ),
                    });
                }

                // Rename temp to final
                fs::rename(&temp_path, local_path).await.map_err(|e| qsh_core::Error::FileTransfer {
                    message: format!("failed to rename temp file: {}", e),
                })?;

                return Ok(TransferStats { bytes: total_bytes, skipped: false });
            }
            Message::ChannelDataMsg(ChannelData {
                payload: ChannelPayload::FileError(err),
                ..
            }) => {
                pb.finish_with_message("error");
                let _ = fs::remove_file(&temp_path).await;
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
        .map(|t| t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs())
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
        .map(|t| t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs())
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
    let mut file = File::open(path).await.map_err(|e| qsh_core::Error::FileTransfer {
        message: format!("failed to open file for hashing: {}", e),
    })?;

    let mut hasher = StreamingHasher::new();
    let mut buf = vec![0u8; FILE_CHUNK_SIZE];

    loop {
        let n = file.read(&mut buf).await.map_err(|e| qsh_core::Error::FileTransfer {
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
    };

    info!(addr = %config.server_addr, "Connecting to server");

    // Connect and authenticate
    let quic_conn = connect_quic(&config).await?;

    // Authenticate
    let (mut send, mut recv) = quic_conn
        .accept_bi()
        .await
        .map_err(|e| qsh_core::Error::Transport {
            message: format!("failed to accept auth stream: {}", e),
        })?;

    standalone_authenticate(&mut authenticator, &mut send, &mut recv).await?;
    info!("Authentication succeeded");

    // Complete qsh handshake using channel model
    let conn = ChannelConnection::from_quic(quic_conn, config).await?;
    info!(rtt = ?conn.rtt(), session_id = ?conn.session_id(), "Connected");

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
    };

    // Connect using the channel model
    let conn = ChannelConnection::connect(config).await?;
    info!(rtt = ?conn.rtt(), session_id = ?conn.session_id(), "Connected");

    // Drop bootstrap handle after connection
    drop(handle);

    Ok(conn)
}
