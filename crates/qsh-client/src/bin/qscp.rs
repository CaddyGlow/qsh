//! qscp: File transfer utility for qsh.
//!
//! Transfers files to/from remote hosts using the qsh protocol.
//! This binary uses the shared TransferEngine for file transfer operations.

use std::sync::Arc;

use clap::Parser;
use tracing::{error, info};

use qsh_client::{ChannelConnection, CpCli, FilePath, random_local_port};
use qsh_client::transfer::{IndicatifCallback, TransferEngine};

#[cfg(not(feature = "standalone"))]
use qsh_client::{ConnectionConfig, SshConfig, bootstrap};

#[cfg(feature = "standalone")]
use qsh_client::standalone::authenticate as standalone_authenticate;
#[cfg(feature = "standalone")]
use qsh_client::{ConnectionConfig, DirectAuthenticator, DirectConfig, SshConfig, bootstrap};

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
    let direction = if is_upload {
        qsh_core::protocol::TransferDirection::Upload
    } else {
        qsh_core::protocol::TransferDirection::Download
    };

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

    // Check for resume (for downloads, check if partial file exists)
    let resume_from = if cli.options.resume && !is_upload {
        let partial_path = local_path.with_extension("qscp.partial");
        if let Ok(partial_meta) = tokio::fs::metadata(&partial_path).await {
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
    } else {
        None
    };

    // Create progress callback
    let progress = Arc::new(IndicatifCallback::new());

    // Create transfer engine and run transfer
    let engine = TransferEngine::new(conn.clone(), progress);
    let stats = engine
        .run_transfer(&local_path, &remote_path, direction, &options, resume_from)
        .await?;

    // Close connection
    if let Ok(conn) = Arc::try_unwrap(conn) {
        conn.close().await?;
    }

    if stats.files_failed > 0 {
        std::process::exit(1);
    }

    Ok(())
}

// =============================================================================
// Connection helpers
// =============================================================================

#[cfg(not(feature = "standalone"))]
async fn connect(cli: &CpCli, host: &str, user: Option<&str>) -> qsh_core::Result<ChannelConnection> {
    use std::net::ToSocketAddrs;

    // SSH bootstrap mode
    let ssh_config = SshConfig {
        identity_file: cli.identity.first().cloned(),
        ..Default::default()
    };

    let bootstrap_handle = bootstrap(host, cli.port, user, &ssh_config).await?;
    let endpoint = &bootstrap_handle.endpoint_info;

    info!(
        quic_port = endpoint.port,
        "Bootstrap complete, connecting via QUIC"
    );

    // Decode session key and cert hash from base64
    let session_key = endpoint.decode_session_key()?;
    let cert_hash = endpoint.decode_cert_hash()?;

    // Connect to QUIC server
    let server_addr = format!("{}:{}", endpoint.address, endpoint.port)
        .to_socket_addrs()
        .map_err(|e| qsh_core::Error::Transport {
            message: format!("failed to resolve server address: {}", e),
        })?
        .next()
        .ok_or_else(|| qsh_core::Error::Transport {
            message: "no addresses found for server".to_string(),
        })?;

    let config = ConnectionConfig {
        server_addr,
        session_key,
        cert_hash: Some(cert_hash),
        local_port: Some(random_local_port()),
        ..Default::default()
    };

    ChannelConnection::connect(config).await
}

#[cfg(feature = "standalone")]
async fn connect(cli: &CpCli, host: &str, user: Option<&str>) -> qsh_core::Result<ChannelConnection> {
    use std::net::ToSocketAddrs;

    if cli.direct {
        // Direct mode: connect to server directly with SSH key auth
        let server = cli.server.as_ref().ok_or_else(|| qsh_core::Error::Config {
            message: "--server is required in direct mode".to_string(),
        })?;

        let server_addr = server
            .to_socket_addrs()
            .map_err(|e| qsh_core::Error::Transport {
                message: format!("failed to resolve server address: {}", e),
            })?
            .next()
            .ok_or_else(|| qsh_core::Error::Transport {
                message: "no addresses found for server".to_string(),
            })?;

        let direct_config = DirectConfig {
            server_addr,
            username: user.unwrap_or("root").to_string(),
            key_path: cli.key.clone(),
            known_hosts_path: cli.known_hosts.clone(),
            accept_unknown_host: cli.accept_unknown_host,
            use_agent: !cli.no_agent,
        };

        let authenticator = DirectAuthenticator::new(direct_config)?;

        let conn_config = ConnectionConfig {
            server_addr,
            session_key: [0; 32],  // Will be set during auth
            cert_hash: None,
            local_port: Some(random_local_port()),
            ..Default::default()
        };

        let conn = ChannelConnection::connect(conn_config).await?;

        // Authenticate the connection
        standalone_authenticate(&conn, &authenticator).await?;

        Ok(conn)
    } else {
        // SSH bootstrap mode (same as non-standalone)
        let ssh_config = SshConfig {
            identity_file: cli.identity.first().cloned(),
            ..Default::default()
        };

        let bootstrap_handle = bootstrap(host, cli.port, user, &ssh_config).await?;
        let endpoint = &bootstrap_handle.endpoint_info;

        info!(
            quic_port = endpoint.port,
            "Bootstrap complete, connecting via QUIC"
        );

        // Decode session key and cert hash from base64
        let session_key = endpoint.decode_session_key()?;
        let cert_hash = endpoint.decode_cert_hash()?;

        let server_addr = format!("{}:{}", endpoint.address, endpoint.port)
            .to_socket_addrs()
            .map_err(|e| qsh_core::Error::Transport {
                message: format!("failed to resolve server address: {}", e),
            })?
            .next()
            .ok_or_else(|| qsh_core::Error::Transport {
                message: "no addresses found for server".to_string(),
            })?;

        let config = ConnectionConfig {
            server_addr,
            session_key,
            cert_hash: Some(cert_hash),
            local_port: Some(random_local_port()),
            ..Default::default()
        };

        ChannelConnection::connect(config).await
    }
}
