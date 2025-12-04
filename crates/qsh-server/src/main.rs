//! qsh server binary entry point.
//!
//! QUIC endpoint for qsh connections.

use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use quinn::{Endpoint, IdleTimeout, ServerConfig, TransportConfig};
use tracing::{debug, error, info, warn};

use qsh_core::protocol::{Capabilities, Message, ResizePayload, ShutdownReason};
use qsh_core::transport::{Connection, StreamPair, StreamType, server_crypto_config};
use qsh_server::{
    BootstrapServer, Cli, ForwardHandler, PendingSession, RealSessionSpawner, ServerSession,
    SessionAuthorizer, SessionConfig, SessionRegistry,
};

#[cfg(feature = "standalone")]
use qsh_server::{StandaloneAuthenticator, StandaloneConfig};

#[cfg(feature = "standalone")]
type StandaloneAuth = Arc<StandaloneAuthenticator>;

#[cfg(not(feature = "standalone"))]
type StandaloneAuth = ();

fn main() {
    // Parse CLI arguments
    let cli = Cli::parse();

    // Standalone mode is incompatible with bootstrap mode (they use different auth flows).
    #[cfg(feature = "standalone")]
    if cli.standalone && cli.bootstrap {
        eprintln!("qsh-server: --standalone cannot be used with --bootstrap");
        std::process::exit(1);
    }

    // Bootstrap mode: minimal logging to stderr, JSON output to stdout
    if cli.bootstrap {
        // Only log errors in bootstrap mode (to stderr)
        let log_path = cli.log_file.as_deref();
        if let Err(e) = qsh_core::init_logging(cli.verbose, log_path, cli.log_format.into()) {
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
    // First, see if an instance is already running for this user and ask it
    // for a new session key via the pipe.
    let pipe_path = qsh_server::bootstrap::bootstrap_pipe_path();
    if let Some(json) = qsh_server::bootstrap::try_existing_bootstrap(&pipe_path).await? {
        println!("{}", json);
        return Ok(());
    }

    // Use port 0 to auto-select from range, or specified port
    let port = if cli.port == 4433 { 0 } else { cli.port };

    // Create bootstrap server
    let bootstrap = Arc::new(BootstrapServer::new(cli.bind_addr, port, cli.port_range).await?);

    // Authorize the initial session key and keep registry aligned.
    let authorizer = Arc::new(SessionAuthorizer::new());
    authorizer.allow(bootstrap.session_key()).await;

    // Create pipe for subsequent bootstrap requests and start listener.
    let _pipe_guard =
        qsh_server::bootstrap::create_pipe(&pipe_path).map_err(|e| qsh_core::Error::Transport {
            message: format!("failed to create bootstrap pipe: {}", e),
        })?;
    let _pipe_task = qsh_server::bootstrap::spawn_pipe_listener(
        pipe_path,
        bootstrap.clone(),
        authorizer.clone(),
    );

    // Output connection info to stdout
    bootstrap.print_response(None)?;

    let endpoint = bootstrap.endpoint();
    let registry = build_registry(cli);

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

    serve_endpoint(endpoint, session_config, registry, Some(authorizer), None).await
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
    let mut server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto).map_err(|e| {
            qsh_core::Error::Transport {
                message: format!("failed to create QUIC config: {}", e),
            }
        })?,
    ));

    // Configure transport (keepalive + idle timeout)
    // Use aggressive keepalive (500ms) for fast disconnection detection (mosh uses RTT/2)
    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(Some(std::time::Duration::from_millis(500)));
    transport.max_idle_timeout(IdleTimeout::try_from(std::time::Duration::from_secs(30)).ok());
    server_config.transport_config(Arc::new(transport));

    // Create QUIC endpoint
    let endpoint =
        Endpoint::server(server_config, bind_addr).map_err(|e| qsh_core::Error::Transport {
            message: format!("failed to bind server: {}", e),
        })?;

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

    let registry = build_registry(cli);

    // Optional standalone authenticator (feature-gated)
    #[cfg(feature = "standalone")]
    let standalone_auth: Option<StandaloneAuth> = if cli.standalone {
        let config = StandaloneConfig {
            host_key_path: cli.host_key.clone(),
            authorized_keys_path: cli.authorized_keys.clone(),
        };
        match StandaloneAuthenticator::new(config) {
            Ok(auth) => Some(Arc::new(auth)),
            Err(e) => {
                error!(error = %e, "Failed to initialize standalone authenticator");
                return Err(e);
            }
        }
    } else {
        None
    };

    #[cfg(not(feature = "standalone"))]
    let standalone_auth: Option<StandaloneAuth> = None;

    serve_endpoint(endpoint, session_config, registry, None, standalone_auth).await
}

fn build_registry(cli: &Cli) -> Arc<SessionRegistry> {
    let env_vars = cli.parse_env_vars();
    let shell = cli.shell.as_ref().map(|p| p.to_string_lossy().into_owned());
    let spawner = Arc::new(RealSessionSpawner {
        shell,
        env: env_vars,
    });
    Arc::new(SessionRegistry::new(cli.session_linger_duration(), spawner))
}

async fn serve_endpoint(
    endpoint: Endpoint,
    session_config: SessionConfig,
    registry: Arc<SessionRegistry>,
    authorizer: Option<Arc<SessionAuthorizer>>,
    standalone_auth: Option<StandaloneAuth>,
) -> qsh_core::Result<()> {
    let addr = endpoint.local_addr().ok();
    info!(?addr, "Server listening");

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
        let registry = registry.clone();
        let authorizer = authorizer.clone();
        let standalone_auth = standalone_auth.clone();
        tokio::spawn(async move {
            if let Err(e) =
                handle_connection(incoming, config, registry, authorizer, standalone_auth).await
            {
                error!(error = %e, "Connection handler error");
            }
        });
    }

    Ok(())
}

async fn handle_connection(
    incoming: quinn::Incoming,
    config: SessionConfig,
    registry: Arc<SessionRegistry>,
    authorizer: Option<Arc<SessionAuthorizer>>,
    standalone_auth: Option<StandaloneAuth>,
) -> qsh_core::Result<()> {
    let addr = incoming.remote_address();
    info!(addr = %addr, "Incoming connection");

    let conn = incoming.await.map_err(|e| qsh_core::Error::Transport {
        message: format!("connection failed: {}", e),
    })?;

    // If standalone mode is enabled, perform mutual SSH key authentication
    // before proceeding to the normal session Hello/HelloAck handshake.
    #[cfg(feature = "standalone")]
    if let Some(auth) = standalone_auth {
        use qsh_server::standalone::{AuthResult, authenticate_connection, send_auth_failure};

        // Open a dedicated bidirectional stream for auth handshake (server-initiated).
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| qsh_core::Error::Transport {
                message: format!("failed to open auth stream: {}", e),
            })?;

        match authenticate_connection(auth.as_ref(), &mut send, &mut recv).await {
            AuthResult::Success {
                client_fingerprint,
            } => {
                info!(%client_fingerprint, "Standalone client authenticated");
            }
            AuthResult::Failure {
                code,
                internal_message,
            } => {
                error!(
                    code = ?code,
                    message = %internal_message,
                    "Standalone authentication failed"
                );

                // Best-effort attempt to send AuthFailure to the client.
                if let Err(e) = send_auth_failure(&mut send, code, &internal_message).await {
                    warn!(error = %e, "Failed to send AuthFailure to client");
                }

                return Err(qsh_core::Error::AuthenticationFailed);
            }
        }
    }

    let quic = qsh_core::transport::QuicConnection::new(conn);

    let pending = PendingSession::new(quic, authorizer, config).await?;
    let attach = registry.prepare(pending.hello()).await?;
    let parser = attach.parser.clone();
    let initial_state = attach.initial_state.clone();
    let session = pending.accept(parser, initial_state).await?;

    // Handle the session
    handle_session(session, attach, registry).await
}

/// Handle an established session (shared between bootstrap and normal modes).
async fn handle_session(
    mut session: ServerSession,
    mut attach: qsh_server::registry::SessionAttach,
    registry: Arc<SessionRegistry>,
) -> qsh_core::Result<()> {
    info!(
        addr = %session.remote_addr(),
        rtt = ?session.rtt(),
        "Session attached"
    );

    // Channel for terminal input messages (from client -> server)
    let (input_tx, mut input_rx) =
        tokio::sync::mpsc::unbounded_channel::<qsh_core::protocol::TerminalInputPayload>();

    // Create forward handler with shared connection
    let quic_conn = session.quic_connection();
    let forward_handler = Arc::new(ForwardHandler::new(
        quic_conn.clone(),
        session.max_forwards(),
    ));

    // Spawn a task to accept forward streams and terminal input stream
    let accept_quic = quic_conn.clone();
    let accept_handler = Arc::clone(&forward_handler);
    let terminal_input_tx = input_tx.clone();
    let accept_task = tokio::spawn(async move {
        loop {
            match accept_quic.accept_stream().await {
                Ok((stream_type, stream)) => match stream_type {
                    StreamType::Forward(_) => {
                        let handler = Arc::clone(&accept_handler);
                        tokio::spawn(async move {
                            handler.handle_stream(stream_type, stream).await;
                        });
                    }
                    StreamType::TerminalIn => {
                        let mut stream = stream;
                        let tx = terminal_input_tx.clone();
                        tokio::spawn(async move {
                            loop {
                                match stream.recv().await {
                                    Ok(Message::TerminalInput(input)) => {
                                        if tx.send(input).is_err() {
                                            break;
                                        }
                                    }
                                    Ok(other) => {
                                        tracing::warn!(
                                            ?other,
                                            "Unexpected message on terminal input stream"
                                        );
                                    }
                                    Err(qsh_core::Error::ConnectionClosed) => break,
                                    Err(e) => {
                                        tracing::warn!(error = %e, "Terminal input stream error");
                                        break;
                                    }
                                }
                            }
                        });
                    }
                    other => {
                        warn!(stream_type = ?other, "Unexpected stream type from accept");
                    }
                },
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

    let mut last_input_seq = attach.last_input_seq;
    let mut output_rx = attach.output_rx;
    let entry = attach.entry.clone();
    let stop_fut = attach.guard.stopped();
    tokio::pin!(stop_fut);

    // Main session loop
    loop {
        tokio::select! {
            // Use biased selection to prioritize client input for low latency
            biased;

            // Handle terminal input stream (client -> server)
            input = input_rx.recv() => {
                match input {
                    Some(input) => {
                        debug!(
                            seq = input.sequence,
                            len = input.data.len(),
                            data = ?&input.data[..input.data.len().min(32)],
                            "Received terminal input from client"
                        );
                        last_input_seq = input.sequence;
                        entry.record_input_seq(last_input_seq).await;
                        if let Err(e) = entry.send_input(input.data).await {
                            error!(error = %e, "Failed to send input to PTY");
                            break;
                        }
                    }
                    None => {
                        info!("Terminal input stream closed");
                        break;
                    }
                }
            }

            // Handle control messages (resize, shutdown)
            msg = session.process_control() => {
                match msg {
                    Ok(Some(Message::Resize(ResizePayload { cols, rows }))) => {
                        debug!(cols, rows, "Terminal resize requested");
                        if let Err(e) = entry.resize(cols, rows) {
                            warn!(error = %e, "Failed to resize PTY");
                        } else {
                            entry.touch().await;
                        }
                    }
                    Ok(Some(Message::Shutdown(payload))) => {
                        info!(reason = ?payload.reason, "Client requested shutdown");
                        if matches!(payload.reason, ShutdownReason::UserRequested) {
                            entry.touch().await;
                        } else {
                            let key = entry.key();
                            registry.close_entry(&key).await;
                        }
                        break;
                    }
                    Ok(Some(Message::TerminalInput(input))) => {
                        debug!(
                            seq = input.sequence,
                            len = input.data.len(),
                            data = ?&input.data[..input.data.len().min(32)],
                            "Terminal input received on control stream (legacy)"
                        );
                        last_input_seq = input.sequence;
                        entry.record_input_seq(last_input_seq).await;
                        if let Err(e) = entry.send_input(input.data).await {
                            error!(error = %e, "Failed to send input to PTY");
                            break;
                        }
                    }
                    Ok(Some(other)) => {
                        warn!(msg = ?other, "Unexpected control message");
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

            // Handle PTY output -> send to client (state-based for prediction support)
            output = output_rx.recv() => {
                match output {
                    Ok(data) if !data.is_empty() => {
                        debug!(
                            len = data.len(),
                            data = ?&data[..data.len().min(32)],
                            confirmed_seq = last_input_seq,
                            "Sending state update to client"
                        );
                        if let Err(e) = session.send_state_update(data, last_input_seq).await {
                            error!(error = %e, "Failed to send state update");
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        info!("Output stream closed (shell exited)");
                        // Send shutdown before breaking so client knows shell exited
                        if let Err(e) = session.send_shutdown(
                            ShutdownReason::ShellExited,
                            Some("shell exited".to_string()),
                        ).await {
                            warn!(error = %e, "Failed to send shutdown message");
                        }
                        break;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        warn!(skipped, "Terminal output lagged");
                    }
                }
            }

            stop_reason = &mut stop_fut => {
                if let Some(reason) = stop_reason {
                    match reason {
                        qsh_server::registry::AttachmentStopReason::PtyExited => {
                            if let Err(e) = session.send_shutdown(ShutdownReason::ShellExited, Some("shell exited".to_string())).await {
                                warn!(error = %e, "Failed to send shutdown message");
                            }
                        }
                        qsh_server::registry::AttachmentStopReason::Replaced => {
                            let _ = session.send_shutdown(
                                ShutdownReason::ServerShutdown,
                                Some("Session replaced by another client".to_string()),
                            ).await;
                        }
                        qsh_server::registry::AttachmentStopReason::RegistryShutdown |
                        qsh_server::registry::AttachmentStopReason::ExplicitClose => {
                            let _ = session.send_shutdown(
                                ShutdownReason::ServerShutdown,
                                Some("Session closed".to_string()),
                            ).await;
                        }
                    }
                }
                break;
            }
        }
    }

    // Stop the accept task
    accept_task.abort();

    entry.touch().await;
    session.close().await;

    Ok(())
}
