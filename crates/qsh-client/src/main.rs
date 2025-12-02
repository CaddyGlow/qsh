//! qsh client binary entry point.
//!
//! Modern roaming-capable remote terminal client.

use std::net::ToSocketAddrs;

use clap::Parser;
use tracing::{error, info, warn};

use qsh_client::{Cli, ClientConnection, ConnectionConfig, bootstrap_via_ssh};
use qsh_core::protocol::TermSize;

fn main() {
    // Parse CLI arguments
    let cli = Cli::parse();

    // Initialize logging
    let log_format = cli.log_format.into();
    if let Err(e) = qsh_core::init_logging(cli.verbose, cli.log_file.as_deref(), log_format) {
        eprintln!("Failed to initialize logging: {}", e);
        std::process::exit(1);
    }

    // Log startup
    info!(version = env!("CARGO_PKG_VERSION"), "qsh client starting");

    // Extract connection info
    let Some(host) = cli.host() else {
        error!("No destination specified");
        eprintln!("Usage: qsh [user@]host[:port] [command]");
        std::process::exit(1);
    };

    let user = cli.effective_user();

    info!(host = host, user = user, port = cli.port, "Connecting");

    // Parse forward specifications
    for spec in &cli.local_forward {
        info!(spec = spec.as_str(), "Local forward requested");
    }
    for spec in &cli.remote_forward {
        info!(spec = spec.as_str(), "Remote forward requested");
    }
    for spec in &cli.dynamic_forward {
        info!(spec = spec.as_str(), "Dynamic forward requested");
    }

    // Create tokio runtime
    let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");

    // Run the async connection logic
    let result = rt.block_on(async { run_client(&cli, host, user).await });

    if let Err(e) = result {
        error!(error = %e, "Connection failed");
        eprintln!("qsh: {}", e);
        std::process::exit(1);
    }
}

async fn run_client(cli: &Cli, host: &str, user: Option<&str>) -> qsh_core::Result<()> {
    // Step 1: Bootstrap via SSH to get QUIC endpoint info
    info!("Bootstrapping via SSH...");

    let server_info = match bootstrap_via_ssh(host, cli.port, user).await {
        Ok(info) => info,
        Err(e) => {
            // For now, fall back to direct QUIC connection attempt
            warn!(error = %e, "SSH bootstrap failed, attempting direct QUIC connection");

            // Try to resolve the address directly
            // Default QUIC port is 4500
            let quic_port = 4500;
            let addr = format!("{}:{}", host, quic_port)
                .to_socket_addrs()
                .map_err(|e| qsh_core::Error::Transport {
                    message: format!("failed to resolve address: {}", e),
                })?
                .next()
                .ok_or_else(|| qsh_core::Error::Transport {
                    message: "no addresses found".to_string(),
                })?;

            // Use a placeholder session key (in real use, this would come from bootstrap)
            let session_key = [0u8; 32];

            let config = ConnectionConfig {
                server_addr: addr,
                session_key,
                cert_hash: None,
                term_size: get_terminal_size(),
                term_type: std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string()),
                predictive_echo: !cli.no_prediction,
                connect_timeout: std::time::Duration::from_secs(10),
            };

            // Try to connect
            let conn = ClientConnection::connect(config).await?;
            info!(rtt = ?conn.rtt(), "Connected to server");

            // Run the session
            run_session(conn, cli).await?;
            return Ok(());
        }
    };

    // Use bootstrap info to connect
    let addr = format!("{}:{}", server_info.address, server_info.port)
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

    let config = ConnectionConfig {
        server_addr: addr,
        session_key,
        cert_hash,
        term_size: get_terminal_size(),
        term_type: std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string()),
        predictive_echo: !cli.no_prediction,
        connect_timeout: std::time::Duration::from_secs(10),
    };

    let conn = ClientConnection::connect(config).await?;
    info!(rtt = ?conn.rtt(), "Connected to server");

    run_session(conn, cli).await
}

async fn run_session(conn: ClientConnection, _cli: &Cli) -> qsh_core::Result<()> {
    // For now, just print connection info and close
    info!(
        predictive_echo = conn.server_capabilities().predictive_echo,
        compression = conn.server_capabilities().compression,
        max_forwards = conn.server_capabilities().max_forwards,
        "Server capabilities"
    );

    // In a full implementation, we would:
    // 1. Set up raw terminal mode
    // 2. Open terminal input/output streams
    // 3. Start forwarding loops for stdin -> server and server -> stdout
    // 4. Handle signals (SIGWINCH for resize, SIGINT, etc.)
    // 5. Set up port forwards if requested
    // 6. Monitor for reconnection needs

    eprintln!("Session established. Full terminal I/O not yet implemented.");
    eprintln!("Press Ctrl+C to exit.");

    // Wait for interrupt
    tokio::signal::ctrl_c().await.ok();

    info!("Shutting down...");
    conn.close().await?;

    Ok(())
}

fn get_terminal_size() -> TermSize {
    // Try to get actual terminal size
    // For now, use defaults
    TermSize { cols: 80, rows: 24 }
}
