//! qsh client binary entry point.
//!
//! Modern roaming-capable remote terminal client.

use std::net::ToSocketAddrs;

use clap::Parser;
use tracing::{debug, error, info, warn};

use qsh_client::cli::SshBootstrapMode;
use qsh_client::{
    BootstrapMode, Cli, ClientConnection, ConnectionConfig, LocalForwarder, RawModeGuard,
    Socks5Proxy, SshConfig, StdinReader, StdoutWriter, bootstrap, get_terminal_size,
    restore_terminal,
};
use qsh_core::forward::ForwardSpec;
use qsh_core::protocol::{Message, TermSize};

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

    // Build SSH config from CLI options
    let ssh_config = SshConfig {
        connect_timeout: std::time::Duration::from_secs(30),
        identity_file: cli.identity.first().cloned(),
        skip_host_key_check: false,
        mode: match cli.ssh_bootstrap_mode {
            SshBootstrapMode::Ssh => BootstrapMode::SshCli,
            SshBootstrapMode::Russh => BootstrapMode::Russh,
        },
    };

    // Bootstrap returns a handle that keeps the SSH process alive
    // We need to hold onto it until after QUIC connection is established
    let bootstrap_handle = match bootstrap(host, cli.port, user, &ssh_config).await {
        Ok(handle) => Some(handle),
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
                term_size: get_term_size(),
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

    let server_info = &bootstrap_handle.as_ref().unwrap().server_info;

    // Use bootstrap info to connect
    // If the server reports 0.0.0.0 or an unspecified address, use the original host
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

    let config = ConnectionConfig {
        server_addr: addr,
        session_key,
        cert_hash,
        term_size: get_term_size(),
        term_type: std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string()),
        predictive_echo: !cli.no_prediction,
        connect_timeout: std::time::Duration::from_secs(10),
    };

    let conn = ClientConnection::connect(config).await?;
    info!(rtt = ?conn.rtt(), "Connected to server");

    // Drop the bootstrap handle now that QUIC connection is established
    // This will terminate the SSH process / russh session
    drop(bootstrap_handle);

    run_session(conn, cli).await
}

async fn run_session(mut conn: ClientConnection, cli: &Cli) -> qsh_core::Result<()> {
    info!(
        predictive_echo = conn.server_capabilities().predictive_echo,
        compression = conn.server_capabilities().compression,
        max_forwards = conn.server_capabilities().max_forwards,
        "Server capabilities"
    );

    // Start port forwarders
    let quic_conn = conn.quic_connection();
    let mut forward_handles = Vec::new();

    // Start local forwarders (-L)
    for spec_str in &cli.local_forward {
        match ForwardSpec::parse_local(spec_str) {
            Ok(spec) => match LocalForwarder::new(spec, quic_conn.clone()).await {
                Ok(mut forwarder) => {
                    info!(spec = spec_str.as_str(), "Local forward started");
                    forward_handles.push(tokio::spawn(async move {
                        if let Err(e) = forwarder.run().await {
                            error!(error = %e, "Local forwarder error");
                        }
                    }));
                }
                Err(e) => {
                    warn!(spec = spec_str.as_str(), error = %e, "Failed to start local forward");
                }
            },
            Err(e) => {
                warn!(spec = spec_str.as_str(), error = %e, "Invalid local forward spec");
            }
        }
    }

    // Start dynamic forwarders (-D)
    for spec_str in &cli.dynamic_forward {
        match ForwardSpec::parse_dynamic(spec_str) {
            Ok(spec) => {
                let bind_addr = spec.bind_addr();
                match Socks5Proxy::new(bind_addr, quic_conn.clone()).await {
                    Ok(mut proxy) => {
                        info!(addr = %bind_addr, "SOCKS5 proxy started");
                        forward_handles.push(tokio::spawn(async move {
                            if let Err(e) = proxy.run().await {
                                error!(error = %e, "SOCKS5 proxy error");
                            }
                        }));
                    }
                    Err(e) => {
                        warn!(spec = spec_str.as_str(), error = %e, "Failed to start SOCKS5 proxy");
                    }
                }
            }
            Err(e) => {
                warn!(spec = spec_str.as_str(), error = %e, "Invalid dynamic forward spec");
            }
        }
    }

    // Note: Remote forwards (-R) are server-initiated and handled differently
    // They would be sent as ForwardSetup messages during handshake

    // Enter raw terminal mode
    let _raw_guard = match RawModeGuard::enter() {
        Ok(guard) => guard,
        Err(e) => {
            warn!(error = %e, "Failed to enter raw mode, continuing with cooked mode");
            // Continue without raw mode - useful for debugging
            return run_session_cooked(conn, forward_handles).await;
        }
    };

    debug!("Entered raw terminal mode");

    // Create stdin/stdout handlers
    let mut stdin = StdinReader::new();
    let mut stdout = StdoutWriter::new();

    // Set up SIGWINCH signal handler for terminal resize
    #[cfg(unix)]
    let mut sigwinch =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
            .map_err(qsh_core::Error::Io)?;

    // Main session loop
    loop {
        // Platform-specific select with SIGWINCH handling
        #[cfg(unix)]
        let resize_event = sigwinch.recv();
        #[cfg(not(unix))]
        let resize_event = std::future::pending::<Option<()>>();

        tokio::select! {
            // Use biased selection to prioritize input handling for low latency
            biased;

            // Handle stdin -> server (highest priority for responsiveness)
            // Use spawn to avoid blocking the select loop on QUIC send
            input = stdin.read() => {
                match input {
                    Some(data) if !data.is_empty() => {
                        debug!(len = data.len(), "Sending input to server");
                        // Queue the send without waiting - don't block on network I/O
                        match conn.queue_input(&data) {
                            Ok(_seq) => {
                                // Input queued successfully
                            }
                            Err(e) => {
                                error!(error = %e, "Failed to queue input");
                                break;
                            }
                        }
                    }
                    Some(_) => {
                        // Empty data, continue
                    }
                    None => {
                        // stdin closed (EOF)
                        info!("stdin closed");
                        break;
                    }
                }
            }

            // Handle server -> stdout
            msg = conn.recv() => {
                match msg {
                    Ok(Message::StateUpdate(update)) => {
                        // Record latency from confirmed sequence
                        if let Some(latency) = conn.record_confirmation(update.confirmed_input_seq) {
                            debug!(
                                latency_ms = latency.as_secs_f64() * 1000.0,
                                seq = update.confirmed_input_seq,
                                "Input latency"
                            );
                        }
                    }
                    Ok(Message::TerminalOutput(output)) => {
                        // Record latency from confirmed sequence
                        if let Some(latency) = conn.record_confirmation(output.confirmed_input_seq) {
                            debug!(
                                latency_ms = latency.as_secs_f64() * 1000.0,
                                seq = output.confirmed_input_seq,
                                "Input latency"
                            );
                        }
                        // Direct terminal output
                        if let Err(e) = stdout.write(&output.data).await {
                            error!(error = %e, "Failed to write output");
                            break;
                        }
                    }
                    Ok(Message::Pong(_)) => {
                        // Pong response, ignore
                    }
                    Ok(Message::Shutdown(shutdown)) => {
                        info!(reason = ?shutdown.reason, msg = ?shutdown.message, "Server initiated shutdown");
                        if let Some(msg) = &shutdown.message {
                            // Print shutdown message (e.g., "shell exited with code 0")
                            eprintln!("\r\n{}", msg);
                        }
                        break;
                    }
                    Ok(other) => {
                        debug!(msg = ?other, "Unexpected message from server");
                    }
                    Err(qsh_core::Error::ConnectionClosed) => {
                        info!("Connection closed by server");
                        break;
                    }
                    Err(e) => {
                        error!(error = %e, "Error receiving from server");
                        break;
                    }
                }
            }

            // Handle Ctrl+C (SIGINT)
            _ = tokio::signal::ctrl_c() => {
                info!("Received interrupt, shutting down...");
                break;
            }

            // Handle SIGWINCH (terminal resize)
            _ = resize_event => {
                let size = get_term_size();
                debug!(cols = size.cols, rows = size.rows, "Terminal resized");
                if let Err(e) = conn.send_resize(size.cols, size.rows).await {
                    warn!(error = %e, "Failed to send resize");
                }
            }
        }
    }

    // Restore terminal before closing
    restore_terminal();

    // Print latency statistics
    let stats = conn.latency_stats();
    if stats.sample_count > 0 {
        eprintln!("\nLatency statistics: {}", stats);
    }

    // Abort any running forwarders
    for handle in forward_handles {
        handle.abort();
    }

    info!("Shutting down connection...");
    conn.close().await?;

    Ok(())
}

/// Fallback session for when raw mode isn't available.
async fn run_session_cooked(
    conn: ClientConnection,
    mut forward_handles: Vec<tokio::task::JoinHandle<()>>,
) -> qsh_core::Result<()> {
    eprintln!("Running in cooked mode (raw terminal unavailable).");
    eprintln!("Press Ctrl+C to exit.");

    // Wait for interrupt
    tokio::signal::ctrl_c().await.ok();

    info!("Shutting down...");

    // Abort any running forwarders
    for handle in forward_handles.drain(..) {
        handle.abort();
    }

    conn.close().await?;

    Ok(())
}

fn get_term_size() -> TermSize {
    match get_terminal_size() {
        Ok(size) => size,
        Err(_) => TermSize { cols: 80, rows: 24 },
    }
}
