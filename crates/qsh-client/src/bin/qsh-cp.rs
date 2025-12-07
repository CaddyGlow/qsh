//! qsh-cp: File transfer utility for qsh.
//!
//! Transfers files to/from remote hosts using the qsh protocol.

use std::net::ToSocketAddrs;
use std::sync::Arc;

use clap::Parser;
use tracing::{error, info};

use qsh_client::file::transfer::resolve_remote_upload_path;
use qsh_client::{ChannelConnection, ClientConnection, CpCli, FilePath, FileTransfer};
use qsh_core::transport::QuicConnection;

#[cfg(feature = "standalone")]
use qsh_client::standalone::authenticate as standalone_authenticate;
#[cfg(feature = "standalone")]
use qsh_client::{DirectAuthenticator, DirectConfig};

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

    info!(version = env!("CARGO_PKG_VERSION"), "qsh-cp starting");

    // Validate source and dest
    let source = cli.source_path();
    let dest = cli.dest_path();

    // Must be one local and one remote
    if !cli.is_upload() && !cli.is_download() {
        eprintln!("qsh-cp: one path must be remote ([user@]host:path)");
        std::process::exit(1);
    }

    // Get remote info
    let (remote_host, remote_user) = match cli.remote_host() {
        Some((h, u)) => (h, u),
        None => {
            eprintln!("qsh-cp: no remote host specified");
            std::process::exit(1);
        }
    };

    info!(host = %remote_host, user = ?remote_user, "Connecting to remote host");

    // Create tokio runtime
    let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");

    let result = rt.block_on(async {
        if cli.channel_model {
            run_transfer_channel_model(&cli, &remote_host, remote_user.as_deref(), &source, &dest)
                .await
        } else {
            run_transfer(&cli, &remote_host, remote_user.as_deref(), &source, &dest).await
        }
    });

    if let Err(e) = result {
        error!(error = %e, "Transfer failed");
        eprintln!("qsh-cp: {}", e);
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
    // Connect to server. For SSH-bootstrap mode we keep the
    // ClientConnection alive for the lifetime of the transfer to
    // ensure the control stream stays open.
    #[cfg(not(feature = "standalone"))]
    let (_session, conn) = connect(cli, host, user).await?;
    #[cfg(feature = "standalone")]
    let conn = connect(cli, host, user).await?;

    // Create file transfer client
    let transfer = FileTransfer::new(conn);
    let options = cli.transfer_options();

    // Perform transfer
    if cli.is_upload() {
        let local_path = match source {
            FilePath::Local(p) => p,
            _ => unreachable!(),
        };
        let raw_remote_path: &str = match dest {
            FilePath::Remote { path, .. } => path.as_str(),
            _ => unreachable!(),
        };

        // For scp-style semantics we first determine whether the raw remote
        // path refers to an existing directory (when specified), then resolve
        // the final upload path accordingly.
        let remote_is_dir = if !raw_remote_path.is_empty() {
            match transfer.remote_is_directory(raw_remote_path).await {
                Ok(is_dir) => is_dir,
                Err(_) => false,
            }
        } else {
            false
        };

        let remote_path = resolve_remote_upload_path(local_path, raw_remote_path, remote_is_dir);

        info!(local = %local_path.display(), remote = %remote_path, "Starting upload");
        let result = transfer.upload(local_path, &remote_path, options).await?;

        if result.skipped {
            eprintln!("File already up to date, skipped transfer");
        } else {
            eprintln!(
                "Uploaded {} in {:.1}s ({}/s){}",
                format_bytes(result.bytes),
                result.duration_secs,
                format_bytes((result.bytes as f64 / result.duration_secs) as u64),
                if result.delta_used { " [delta]" } else { "" }
            );
        }
    } else {
        let remote_path = match source {
            FilePath::Remote { path, .. } => path.as_str(),
            _ => unreachable!(),
        };
        let local_path = match dest {
            FilePath::Local(p) => p,
            _ => unreachable!(),
        };

        info!(remote = %remote_path, local = %local_path.display(), "Starting download");
        let result = transfer.download(remote_path, local_path, options).await?;

        if result.skipped {
            eprintln!("File already up to date, skipped transfer");
        } else {
            eprintln!(
                "Downloaded {} in {:.1}s ({}/s){}",
                format_bytes(result.bytes),
                result.duration_secs,
                format_bytes((result.bytes as f64 / result.duration_secs) as u64),
                if result.delta_used { " [delta]" } else { "" }
            );
        }
    }

    Ok(())
}

#[cfg(feature = "standalone")]
async fn connect(
    cli: &CpCli,
    host: &str,
    _user: Option<&str>,
) -> qsh_core::Result<Arc<QuicConnection>> {
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

    // Build QUIC config
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
    let quinn_conn = ClientConnection::connect_quic(&config).await?;

    // Authenticate
    let (mut send, mut recv) =
        quinn_conn
            .accept_bi()
            .await
            .map_err(|e| qsh_core::Error::Transport {
                message: format!("failed to accept auth stream: {}", e),
            })?;

    standalone_authenticate(&mut authenticator, &mut send, &mut recv).await?;
    info!("Authentication succeeded");

    // Wrap in QuicConnection
    let quic_conn = QuicConnection::new(quinn_conn);
    Ok(Arc::new(quic_conn))
}

#[cfg(not(feature = "standalone"))]
async fn connect(
    cli: &CpCli,
    host: &str,
    user: Option<&str>,
) -> qsh_core::Result<(ClientConnection, Arc<QuicConnection>)> {
    use qsh_client::{BootstrapMode, SshConfig, bootstrap};

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

    // Connect and perform full qsh handshake. We keep the
    // ClientConnection alive so the control stream remains open
    // while file-transfer streams are in use.
    let conn = ClientConnection::connect(config).await?;
    info!(rtt = ?conn.rtt(), "Connected to server");

    // Drop bootstrap handle after connection
    drop(handle);

    let quic = conn.quic_connection();
    Ok((conn, quic))
}

/// Run file transfer using the SSH-style channel model (experimental).
async fn run_transfer_channel_model(
    cli: &CpCli,
    host: &str,
    user: Option<&str>,
    source: &FilePath,
    dest: &FilePath,
) -> qsh_core::Result<()> {
    use qsh_client::{BootstrapMode, SshConfig, bootstrap};

    info!("Using channel model for file transfer");

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

    // Connect using the channel model (no implicit terminal opened)
    let conn = ChannelConnection::connect(config).await?;
    info!(rtt = ?conn.rtt(), session_id = ?conn.session_id(), "Channel model connection established");

    // Drop bootstrap handle after connection
    drop(handle);

    // Use the underlying QUIC connection for file transfer
    // The channel model handshake is complete, but file transfers still use
    // direct streams on the QuicConnection for now
    let quic = Arc::clone(conn.quic());

    // Create file transfer client
    let transfer = FileTransfer::new(quic);
    let options = cli.transfer_options();

    // Perform transfer
    if cli.is_upload() {
        let local_path = match source {
            FilePath::Local(p) => p,
            _ => unreachable!(),
        };
        let raw_remote_path: &str = match dest {
            FilePath::Remote { path, .. } => path.as_str(),
            _ => unreachable!(),
        };

        // For scp-style semantics we first determine whether the raw remote
        // path refers to an existing directory (when specified), then resolve
        // the final upload path accordingly.
        let remote_is_dir = if !raw_remote_path.is_empty() {
            match transfer.remote_is_directory(raw_remote_path).await {
                Ok(is_dir) => is_dir,
                Err(_) => false,
            }
        } else {
            false
        };

        let remote_path = resolve_remote_upload_path(local_path, raw_remote_path, remote_is_dir);

        info!(local = %local_path.display(), remote = %remote_path, "Starting upload (channel model)");
        let result = transfer.upload(local_path, &remote_path, options).await?;

        if result.skipped {
            eprintln!("File already up to date, skipped transfer");
        } else {
            eprintln!(
                "Uploaded {} in {:.1}s ({}/s){}",
                format_bytes(result.bytes),
                result.duration_secs,
                format_bytes((result.bytes as f64 / result.duration_secs) as u64),
                if result.delta_used { " [delta]" } else { "" }
            );
        }
    } else {
        let remote_path = match source {
            FilePath::Remote { path, .. } => path.as_str(),
            _ => unreachable!(),
        };
        let local_path = match dest {
            FilePath::Local(p) => p,
            _ => unreachable!(),
        };

        info!(remote = %remote_path, local = %local_path.display(), "Starting download (channel model)");
        let result = transfer.download(remote_path, local_path, options).await?;

        if result.skipped {
            eprintln!("File already up to date, skipped transfer");
        } else {
            eprintln!(
                "Downloaded {} in {:.1}s ({}/s){}",
                format_bytes(result.bytes),
                result.duration_secs,
                format_bytes((result.bytes as f64 / result.duration_secs) as u64),
                if result.delta_used { " [delta]" } else { "" }
            );
        }
    }

    // Close the channel connection gracefully
    conn.close().await?;

    Ok(())
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}
