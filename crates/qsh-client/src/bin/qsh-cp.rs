//! qsh-cp: File transfer utility for qsh.
//!
//! Transfers files to/from remote hosts using the qsh protocol.
//!
//! TODO: Re-implement using the channel model's open_file_transfer() method.
//! The legacy FileTransfer struct has been removed.

use std::net::ToSocketAddrs;

use clap::Parser;
use tracing::{error, info};

use qsh_client::{BootstrapMode, ChannelConnection, CpCli, FilePath, SshConfig, bootstrap};

#[cfg(feature = "standalone")]
use qsh_client::standalone::authenticate as standalone_authenticate;
#[cfg(feature = "standalone")]
use qsh_client::{DirectAuthenticator, DirectConfig, connect_quic};

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
        run_transfer(&cli, &remote_host, remote_user.as_deref(), &source, &dest).await
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

    // Open a file transfer channel
    let transfer_params = qsh_core::protocol::FileTransferParams {
        path: remote_path.clone(),
        direction: if is_upload {
            qsh_core::protocol::TransferDirection::Upload
        } else {
            qsh_core::protocol::TransferDirection::Download
        },
        options: qsh_core::protocol::TransferOptions::default(),
        resume_from: None,
    };

    info!(
        direction = if is_upload { "upload" } else { "download" },
        local = %local_path.display(),
        remote = %remote_path,
        "Opening file transfer channel"
    );

    let file_channel = conn.open_file_transfer(transfer_params).await?;
    info!(channel_id = ?file_channel.channel_id(), "File transfer channel opened");

    // TODO: Implement actual file transfer using FileChannel
    // For now, just print a message
    eprintln!(
        "qsh-cp: File transfer via channel model not yet implemented.\n\
         Channel opened successfully (channel_id={:?}).\n\
         Use --help for options.",
        file_channel.channel_id()
    );

    // Close the channel and connection
    file_channel.mark_closed();
    conn.close().await?;

    Ok(())
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
