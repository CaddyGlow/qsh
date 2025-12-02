//! qsh server binary entry point.
//!
//! QUIC endpoint for qsh connections.

use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use quinn::{Endpoint, ServerConfig};
use tracing::{error, info, warn};

use qsh_core::protocol::{Capabilities, Message, ResizePayload};
use qsh_core::transport::{Connection, StreamType, server_crypto_config};
use qsh_server::{
    BootstrapServer, Cli, ForwardHandler, Pty, PtyRelay, ServerSession, SessionConfig,
};

fn main() {
    // Parse CLI arguments
    let cli = Cli::parse();

    // Bootstrap mode: minimal logging to stderr, JSON output to stdout
    if cli.bootstrap {
        // Only log errors in bootstrap mode (to stderr)
        if let Err(e) = qsh_core::init_logging(0, None, qsh_core::LogFormat::Text) {
            eprintln!("Failed to initialize logging: {}", e);
            std::process::exit(1);
        }

        let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
        let result = rt.block_on(run_bootstrap(&cli));

        if let Err(e) = result {
            // Output error as JSON
            let resp = qsh_core::bootstrap::BootstrapResponse::error(e.to_string());
            if let Ok(json) = resp.to_json() {
                println!("{}", json);
            } else {
                eprintln!("qsh-server: {}", e);
            }
            std::process::exit(1);
        }
        return;
    }

    // Normal server mode
    // Initialize logging
    let log_format = cli.log_format.into();
    if let Err(e) = qsh_core::init_logging(cli.verbose, cli.log_file.as_deref(), log_format) {
        eprintln!("Failed to initialize logging: {}", e);
        std::process::exit(1);
    }

    // Log startup
    info!(version = env!("CARGO_PKG_VERSION"), "qsh-server starting");

    // Check TLS configuration
    if !cli.has_tls_config() && !cli.self_signed {
        warn!("No TLS certificate configured. Use --cert/--key or --self-signed");
        warn!("Generating self-signed certificate for this session");
    }

    let bind_addr = cli.socket_addr();
    info!(
        addr = %bind_addr,
        max_connections = cli.max_connections,
        max_forwards = cli.max_forwards,
        "Binding server"
    );

    if let Some(ipv6_addr) = cli.ipv6_socket_addr() {
        info!(addr = %ipv6_addr, "Also binding IPv6");
    }

    // Log configuration
    if cli.allow_remote_forwards {
        info!("Remote forwards enabled");
    }

    if cli.compress {
        info!("Compression enabled");
    }

    // Log environment variables
    for (name, value) in cli.parse_env_vars() {
        info!(
            name = name.as_str(),
            value = value.as_str(),
            "Environment variable"
        );
    }

    // Create tokio runtime
    let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");

    // Run the server
    let result = rt.block_on(run_server(&cli, bind_addr));

    if let Err(e) = result {
        error!(error = %e, "Server error");
        eprintln!("qsh-server: {}", e);
        std::process::exit(1);
    }
}

/// Run the server in bootstrap mode.
///
/// This mode:
/// 1. Generates session key and self-signed certificate
/// 2. Binds to an available port (or specified port)
/// 3. Outputs JSON with connection info to stdout
/// 4. Accepts a single connection
/// 5. Handles that session then exits
async fn run_bootstrap(cli: &Cli) -> qsh_core::Result<()> {
    // Use port 0 to auto-select from range, or specified port
    let port = if cli.port == 4433 { 0 } else { cli.port };

    // Create bootstrap server
    let bootstrap = BootstrapServer::new(cli.bind_addr, port).await?;

    // Output connection info to stdout
    bootstrap.print_response(None)?;

    // Accept single connection
    let conn = bootstrap.accept().await?;
    let session_key = bootstrap.session_key();

    // Create QUIC connection wrapper
    let quic = qsh_core::transport::QuicConnection::new(conn);

    // Build session config
    let session_config = SessionConfig {
        capabilities: Capabilities {
            predictive_echo: true,
            compression: cli.compress,
            max_forwards: cli.max_forwards,
            tunnel: false,
        },
        idle_timeout: std::time::Duration::from_secs(300),
        max_forwards: cli.max_forwards,
        allow_remote_forwards: cli.allow_remote_forwards,
    };

    // Accept session with expected key
    let session = ServerSession::accept(quic, Some(session_key), session_config).await?;

    // Handle the session
    handle_session(session).await?;

    // Clean up
    bootstrap.close();

    Ok(())
}

async fn run_server(cli: &Cli, bind_addr: SocketAddr) -> qsh_core::Result<()> {
    // Generate or load TLS certificate
    let (cert, key) = if cli.has_tls_config() {
        // Load from files
        let cert_path = cli.cert_file.as_ref().unwrap();
        let key_path = cli.key_file.as_ref().unwrap();

        let cert = tokio::fs::read(cert_path)
            .await
            .map_err(|e| qsh_core::Error::Transport {
                message: format!("failed to read certificate: {}", e),
            })?;
        let key = tokio::fs::read(key_path)
            .await
            .map_err(|e| qsh_core::Error::Transport {
                message: format!("failed to read key: {}", e),
            })?;

        (cert, key)
    } else {
        // Generate self-signed certificate
        info!("Generating self-signed certificate");
        let cert =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).map_err(|e| {
                qsh_core::Error::Transport {
                    message: format!("failed to generate certificate: {}", e),
                }
            })?;

        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.key_pair.serialize_der();

        (cert_der, key_der)
    };

    // Create TLS config
    let crypto = server_crypto_config(cert, key)?;
    let server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto).map_err(|e| {
            qsh_core::Error::Transport {
                message: format!("failed to create QUIC config: {}", e),
            }
        })?,
    ));

    // Create QUIC endpoint
    let endpoint =
        Endpoint::server(server_config, bind_addr).map_err(|e| qsh_core::Error::Transport {
            message: format!("failed to bind server: {}", e),
        })?;

    info!(addr = %bind_addr, "Server listening");

    // Build session config
    let session_config = SessionConfig {
        capabilities: Capabilities {
            predictive_echo: true,
            compression: cli.compress,
            max_forwards: cli.max_forwards,
            tunnel: false,
        },
        idle_timeout: std::time::Duration::from_secs(300),
        max_forwards: cli.max_forwards,
        allow_remote_forwards: cli.allow_remote_forwards,
    };

    // Accept connections
    loop {
        let incoming = match endpoint.accept().await {
            Some(inc) => inc,
            None => {
                info!("Endpoint closed");
                break;
            }
        };

        let config = session_config.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(incoming, config).await {
                error!(error = %e, "Connection handler error");
            }
        });
    }

    Ok(())
}

async fn handle_connection(
    incoming: quinn::Incoming,
    config: SessionConfig,
) -> qsh_core::Result<()> {
    let addr = incoming.remote_address();
    info!(addr = %addr, "Incoming connection");

    let conn = incoming.await.map_err(|e| qsh_core::Error::Transport {
        message: format!("connection failed: {}", e),
    })?;

    let quic = qsh_core::transport::QuicConnection::new(conn);

    // Accept session (no expected key for now - would come from bootstrap)
    let session = ServerSession::accept(quic, None, config).await?;

    // Handle the session
    handle_session(session).await
}

/// Handle an established session (shared between bootstrap and normal modes).
async fn handle_session(mut session: ServerSession) -> qsh_core::Result<()> {
    info!(
        addr = %session.remote_addr(),
        rtt = ?session.rtt(),
        "Session established"
    );

    // Get terminal size from session
    let (cols, rows) = session.term_size();

    // Spawn PTY with user's shell
    let pty = match Pty::spawn(cols, rows, None, &[]) {
        Ok(pty) => Arc::new(pty),
        Err(e) => {
            error!(error = %e, "Failed to spawn PTY");
            session.close();
            return Err(e);
        }
    };

    info!(cols, rows, "PTY spawned");

    // Start PTY relay
    let mut relay = PtyRelay::start(pty.clone());

    // Create forward handler with shared connection
    let quic_conn = session.quic_connection();
    let forward_handler = Arc::new(ForwardHandler::new(
        quic_conn.clone(),
        session.max_forwards(),
    ));

    // Spawn a task to accept forward streams
    let accept_quic = quic_conn.clone();
    let accept_handler = Arc::clone(&forward_handler);
    let accept_task = tokio::spawn(async move {
        loop {
            match accept_quic.accept_stream().await {
                Ok((stream_type, stream)) => {
                    if matches!(stream_type, StreamType::Forward(_)) {
                        let handler = Arc::clone(&accept_handler);
                        tokio::spawn(async move {
                            handler.handle_stream(stream_type, stream).await;
                        });
                    } else {
                        warn!(stream_type = ?stream_type, "Unexpected stream type from accept");
                    }
                }
                Err(e) => {
                    // Stream accept error - might be connection closing
                    if !matches!(e, qsh_core::Error::ConnectionClosed) {
                        warn!(error = %e, "Failed to accept stream");
                    }
                    break;
                }
            }
        }
    });

    // Track input sequence for confirmation
    let mut last_input_seq = 0u64;

    // Main session loop
    loop {
        tokio::select! {
            // Handle PTY output -> send to client
            output = relay.recv_output() => {
                match output {
                    Some(data) if !data.is_empty() => {
                        if let Err(e) = session.send_output(data, last_input_seq).await {
                            error!(error = %e, "Failed to send output");
                            break;
                        }
                    }
                    Some(_) => {
                        // Empty data, continue
                    }
                    None => {
                        // PTY closed
                        if let Ok(Some(code)) = pty.try_wait() {
                            info!(exit_code = code, "PTY closed");
                        } else {
                            info!("PTY closed");
                        }
                        break;
                    }
                }
            }

            // Handle client messages
            msg = session.process_control() => {
                match msg {
                    Ok(Some(Message::TerminalInput(input))) => {
                        last_input_seq = input.sequence;
                        if let Err(e) = relay.send_input(input.data).await {
                            error!(error = %e, "Failed to send input to PTY");
                            break;
                        }
                    }
                    Ok(Some(Message::Resize(ResizePayload { cols, rows }))) => {
                        info!(cols, rows, "Terminal resize");
                        // Note: resize is tracked but not fully implemented
                        // Would need to resize PTY here
                    }
                    Ok(Some(Message::Ping(timestamp))) => {
                        if let Err(e) = session.send_pong(timestamp).await {
                            warn!(error = %e, "Failed to send pong");
                        }
                    }
                    Ok(Some(Message::Shutdown(_))) => {
                        info!("Client requested shutdown");
                        break;
                    }
                    Ok(Some(other)) => {
                        warn!(msg = ?other, "Unexpected message");
                    }
                    Ok(None) => {
                        // Connection closed
                        info!("Connection closed");
                        break;
                    }
                    Err(e) => {
                        error!(error = %e, "Control stream error");
                        break;
                    }
                }
            }

            // Check if PTY child exited
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                if let Ok(Some(code)) = pty.try_wait() {
                    info!(exit_code = code, "Shell exited");
                    break;
                }
            }
        }
    }

    // Stop the accept task
    accept_task.abort();

    // Clean up
    drop(relay); // Stop relay tasks by dropping it
    let _ = pty.kill();
    session.close();

    Ok(())
}
