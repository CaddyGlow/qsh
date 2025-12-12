//! qsh server binary entry point.
//!
//! QUIC endpoint for qsh connections using the SSH-style channel model.

use std::net::SocketAddr;
use std::sync::Arc;

/// Enable the single-instance-per-user singleton via named pipe.
/// When enabled, bootstrap mode will reuse an existing server instance if one is running.
/// Set to false to allow multiple independent bootstrap instances (useful for debugging).
const ENABLE_BOOTSTRAP_SINGLETON: bool = false;

use clap::Parser;
use tracing::{debug, error, info, warn};

use qsh_core::error::Error;
use qsh_core::protocol::{Capabilities, HeartbeatPayload, Message};
use qsh_core::transport::generate_self_signed_cert;
use qsh_server::listener::{QshListener, ServerConfig};
use qsh_server::{BootstrapServer, Cli, ConnectionConfig, ServerControlHandler, ServerInfo, SessionAuthorizer, SessionConfig};

#[cfg(feature = "standalone")]
use qsh_server::{StandaloneAuthenticator, StandaloneConfig};

// For initiator mode
use qsh_core::ConnectMode;
use qsh_core::handshake::{HandshakeConfig, handshake_initiate};
use qsh_core::transport::{ConnectConfig, connect_quic};

fn main() {
    // Parse CLI arguments
    let cli = Cli::parse();

    // Validate CLI arguments and infer connect mode before doing anything else
    let effective_connect_mode = match cli.validate_and_infer_connect_mode() {
        Ok(mode) => mode,
        Err(e) => {
            eprintln!("qsh-server: {}", e);
            std::process::exit(1);
        }
    };

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

    // Check for initiator mode (using inferred mode, not cli.connect_mode directly)
    if effective_connect_mode == qsh_server::cli::ConnectModeArg::Initiate {
        info!("Running in initiator mode (SSH-out to client)");

        // Create tokio runtime for initiator mode
        let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");

        // Run the initiator
        let result = rt.block_on(run_server_initiate(&cli));

        if let Err(e) = result {
            error!(error = %e, "Initiator mode failed");
            eprintln!("qsh-server: {}", e);
            std::process::exit(1);
        }
        return;
    }

    debug!(connect_mode = ?effective_connect_mode, "Connect mode");

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
    // Singleton mode: try to reuse an existing server instance via named pipe.
    if ENABLE_BOOTSTRAP_SINGLETON {
        let pipe_path = qsh_server::bootstrap::bootstrap_pipe_path();
        if let Some(json) = qsh_server::bootstrap::try_existing_bootstrap(&pipe_path).await? {
            println!("{}", json);
            return Ok(());
        }
    }

    // Use port 0 to auto-select from range, or specified port
    let port = if cli.port == 4433 { 0 } else { cli.port };

    // Create bootstrap server
    let bootstrap = Arc::new(BootstrapServer::new(cli.bind_addr, port, cli.port_range).await?);

    // Authorize the initial session key and keep registry aligned.
    let authorizer = Arc::new(SessionAuthorizer::new());
    authorizer.allow(bootstrap.session_key()).await;

    // Singleton mode: create pipe for subsequent bootstrap requests.
    let _pipe_guard;
    let _pipe_task;
    if ENABLE_BOOTSTRAP_SINGLETON {
        let pipe_path = qsh_server::bootstrap::bootstrap_pipe_path();
        _pipe_guard = Some(qsh_server::bootstrap::create_pipe(&pipe_path).map_err(|e| {
            qsh_core::Error::Transport {
                message: format!("failed to create bootstrap pipe: {}", e),
            }
        })?);
        _pipe_task = Some(qsh_server::bootstrap::spawn_pipe_listener(
            pipe_path,
            bootstrap.clone(),
            authorizer.clone(),
        ));
    } else {
        _pipe_guard = None;
        _pipe_task = None;
    }

    // Output connection info to stdout
    bootstrap.print_response(None)?;

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
        connect_mode: cli.connect_mode.into(),
    };

    // Build connection config
    let conn_config = ConnectionConfig {
        max_forwards: cli.max_forwards,
        allow_remote_forwards: cli.allow_remote_forwards,
        output_mode: cli.output_mode,
        ..Default::default()
    };

    // Build server config
    let server_config = ServerConfig {
        bind_addr: bootstrap.local_addr(),
        cert_pem: bootstrap.cert_pem().to_vec(),
        key_pem: bootstrap.key_pem().to_vec(),
        session_config,
        conn_config,
        bootstrap_mode: true,
    };

    // Create listener
    // For quiche backend, we share the socket that bootstrap already bound
    // For s2n backend, we let the listener bind its own socket
    #[cfg(feature = "quiche-backend")]
    let listener = QshListener::with_socket(bootstrap.socket(), server_config)
        .await?
        .with_authorizer(authorizer);

    #[cfg(not(feature = "quiche-backend"))]
    let listener = QshListener::bind(server_config)
        .await?
        .with_authorizer(authorizer);

    // Bootstrap mode: run until session expires
    listener.run(true).await
}

async fn run_server(cli: &Cli, bind_addr: SocketAddr) -> qsh_core::Result<()> {
    // Generate or load TLS certificate (now expects PEM format)
    let (cert_pem, key_pem) = if cli.has_tls_config() {
        // Load from files (expect PEM format)
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
        // Generate self-signed certificate (returns PEM)
        info!("Generating self-signed certificate");
        generate_self_signed_cert()?
    };

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
        connect_mode: cli.connect_mode.into(),
    };

    // Build connection config
    let conn_config = ConnectionConfig {
        max_forwards: cli.max_forwards,
        allow_remote_forwards: cli.allow_remote_forwards,
        output_mode: cli.output_mode,
        ..Default::default()
    };

    // Build server config
    let server_config = ServerConfig {
        bind_addr,
        cert_pem: cert_pem.clone(),
        key_pem,
        session_config,
        conn_config,
        bootstrap_mode: false,
    };

    // Create session authorizer for control socket enrollment
    let authorizer = Arc::new(SessionAuthorizer::new());

    // Create listener with authorizer
    let listener = QshListener::bind(server_config).await?.with_authorizer(Arc::clone(&authorizer));
    let local_addr = listener.local_addr();
    let registry = Arc::clone(listener.registry());
    info!("Server listening on {}", local_addr);

    // Compute certificate hash for enrollment responses
    let cert_hash = qsh_core::transport::cert_hash(&cert_pem);

    // Build server info for control socket
    let server_info = ServerInfo {
        server_addr: local_addr.ip().to_string(),
        server_port: local_addr.port() as u32,
        cert_hash,
        connect_mode: format!("{:?}", cli.connect_mode).to_lowercase(),
    };

    // Try to bind control socket (non-fatal if it fails)
    let control_handler = match ServerControlHandler::bind(
        Arc::clone(&registry),
        authorizer,
        server_info,
    ) {
        Ok(handler) => Some(handler),
        Err(e) => {
            warn!("Failed to bind control socket: {} (continuing without control interface)", e);
            None
        }
    };

    // Set up signal handlers for graceful shutdown
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| qsh_core::Error::Transport {
            message: format!("failed to install SIGTERM handler: {}", e),
        })?;

    // Run listener and control handler concurrently with signal handling
    let result = if let Some(control) = control_handler {
        tokio::select! {
            biased;

            _ = tokio::signal::ctrl_c() => {
                eprintln!("qsh-server: received SIGINT, shutting down...");
                info!("Received SIGINT (Ctrl-C), initiating graceful shutdown");
                Ok(())
            }
            _ = sigterm.recv() => {
                eprintln!("qsh-server: received SIGTERM, shutting down...");
                info!("Received SIGTERM, initiating graceful shutdown");
                Ok(())
            }
            result = listener.run(false) => result,
            result = control.run() => {
                // Control handler exiting is unexpected but not fatal
                warn!("Control handler exited: {:?}", result);
                Ok(())
            }
        }
    } else {
        tokio::select! {
            biased;

            _ = tokio::signal::ctrl_c() => {
                eprintln!("qsh-server: received SIGINT, shutting down...");
                info!("Received SIGINT (Ctrl-C), initiating graceful shutdown");
                Ok(())
            }
            _ = sigterm.recv() => {
                eprintln!("qsh-server: received SIGTERM, shutting down...");
                info!("Received SIGTERM, initiating graceful shutdown");
                Ok(())
            }
            result = listener.run(false) => result,
        }
    };

    // Graceful shutdown: notify all connected clients and close sessions
    let session_count = registry.session_count().await;
    eprintln!("qsh-server: notifying {} connected client(s)...", session_count);
    info!(session_count, "Shutting down server, notifying connected clients");
    registry.shutdown().await;
    eprintln!("qsh-server: shutdown complete");
    info!("Server shutdown complete");

    result
}

/// Run the server in initiator mode (SSH-out to client).
///
/// This mode:
/// 1. SSHs to the target client machine
/// 2. Executes `qsh --bootstrap` to get QUIC endpoint info
/// 3. Connects to the client's QUIC endpoint as initiator
/// 4. Performs handshake as initiator
/// 5. Handles the connection like a normal server session
async fn run_server_initiate(cli: &Cli) -> qsh_core::Result<()> {
    use std::net::ToSocketAddrs;
    use qsh_server::connection::ConnectionHandler;

    // Parse target
    let (host, ssh_port, user) = cli.parse_target().ok_or_else(|| qsh_core::Error::Transport {
        message: "invalid target specification".to_string(),
    })?;

    info!(
        host = %host,
        port = ssh_port,
        user = ?user,
        "Initiating SSH bootstrap to client"
    );

    // Build SSH config for bootstrap
    let ssh_config = qsh_server::ssh::SshConfig {
        connect_timeout: std::time::Duration::from_secs(30),
        identity_file: cli.identity_file.clone(),
        skip_host_key_check: cli.skip_host_key_check,
        port_range: Some(cli.port_range),
        extra_args: cli.bootstrap_client_args.clone(),
        extra_env: cli.parse_bootstrap_client_env(),
    };

    // Bootstrap via SSH to get client's QUIC endpoint
    let bootstrap_handle = qsh_server::ssh::bootstrap(&host, ssh_port, user.as_deref(), &ssh_config).await?;
    let endpoint_info = &bootstrap_handle.endpoint_info;

    info!(
        address = %endpoint_info.address,
        port = endpoint_info.port,
        connect_mode = ?endpoint_info.connect_mode,
        "Client bootstrap successful"
    );

    // Surface attach pipe hint (reverse/attach workflow) to the operator.
    if let Some(ref pipe) = endpoint_info.attach_pipe {
        info!(
            attach_pipe = pipe.as_str(),
            "Client exposed attach pipe; run `ssh{}{} -t qsh --attach {}` from the target host",
            user.as_ref().map(|u| format!(" {}@", u)).unwrap_or_default(),
            host,
            pipe
        );
    }

    // Validate that client is in respond mode
    if endpoint_info.connect_mode != ConnectMode::Respond {
        return Err(qsh_core::Error::Protocol {
            message: format!(
                "client returned connect_mode {:?}, expected Respond",
                endpoint_info.connect_mode
            ),
        });
    }

    // Resolve client address for QUIC connection
    let connect_host = if endpoint_info.address == "0.0.0.0"
        || endpoint_info.address == "::"
        || endpoint_info.address.starts_with("0.")
    {
        host.clone()
    } else {
        endpoint_info.address.clone()
    };

    let server_addr = format!("{}:{}", connect_host, endpoint_info.port)
        .to_socket_addrs()
        .map_err(|e| qsh_core::Error::Transport {
            message: format!("failed to resolve client address: {}", e),
        })?
        .next()
        .ok_or_else(|| qsh_core::Error::Transport {
            message: "no addresses found for client".to_string(),
        })?;

    let session_key = endpoint_info.decode_session_key()?;
    let cert_hash = endpoint_info.decode_cert_hash().ok();

    // Perform handshake as initiator
    let capabilities = Capabilities {
        predictive_echo: true,
        compression: cli.compress,
        max_forwards: cli.max_forwards,
        tunnel: false,
    };

    use qsh_core::transport::{Connection, StreamType};

    async fn connect_and_handshake(
        server_addr: SocketAddr,
        cert_hash: Option<Vec<u8>>,
        session_key: [u8; 32],
        capabilities: &Capabilities,
    ) -> qsh_core::Result<(
        qsh_core::transport::QuicConnection,
        qsh_core::transport::QuicStream,
        qsh_core::protocol::SessionId,
    )> {
        info!(addr = %server_addr, "Connecting to client via QUIC");

        // Establish QUIC connection as initiator
        // In reverse-attach mode: QUIC client (us) = logical server
        let connect_config = ConnectConfig {
            server_addr,
            local_port: None,
            max_idle_timeout: std::time::Duration::from_secs(300),
            connect_timeout: std::time::Duration::from_secs(30),
            keep_alive_interval: None,
            cert_hash,
            session_data: None,
            // Reverse mode: server initiates connection, so QUIC client = logical server
            logical_role: qsh_core::transport::EndpointRole::Server,
        };

        let connect_result = connect_quic(&connect_config).await?;
        let quic_conn = connect_result.connection;

        info!(
            addr = ?quic_conn.remote_addr(),
            "QUIC connection established, performing handshake"
        );

        // Open control stream for handshake (using StreamType::Control)
        let mut control_stream = quic_conn
            .open_stream(StreamType::Control)
            .await
            .map_err(|e| qsh_core::Error::Transport {
                message: format!("failed to open control stream: {}", e),
            })?;

        let handshake_config = HandshakeConfig::new_initiate(
            session_key,
            capabilities.clone(),
            qsh_core::protocol::TermSize { cols: 80, rows: 24 }, // Dummy size, server doesn't have terminal
            "server".to_string(),
            vec![],
            false,
        );

        let handshake_result = handshake_initiate(&mut control_stream, &handshake_config).await?;
        info!(
            session_id = ?handshake_result.session_id,
            "Handshake complete as initiator"
        );

        Ok((quic_conn, control_stream, handshake_result.session_id))
    }

    // Build connection config
    let conn_config = ConnectionConfig {
        max_forwards: cli.max_forwards,
        allow_remote_forwards: cli.allow_remote_forwards,
        output_mode: cli.output_mode,
        ..Default::default()
    };

    // Keep the bootstrap SSH session alive for the lifetime of this function so
    // the remote `qsh --bootstrap` process (and its attach pipe) stay available.
    let _bootstrap_handle = bootstrap_handle;

    // Initial connect/handshake
    let (quic_conn, control_stream, initial_session_id) =
        connect_and_handshake(server_addr, cert_hash.clone(), session_key, &capabilities).await?;

    // Create connection handler (persists across reconnects)
    // Note: control_stream is moved here; ConnectionHandler will manage it
    let (handler, mut shutdown_rx) = ConnectionHandler::new(
        quic_conn,
        control_stream,
        initial_session_id,
        conn_config,
    );

    info!("Server initiator mode active, handling connection");

    let mut reconnect_handler = qsh_core::session::ReconnectionHandler::new();
    reconnect_handler.start(0, 0, false);
    let mut last_rtt: Option<std::time::Duration> = None;

    enum LoopExit {
        Reconnect,
        Shutdown,
    }

    loop {
        // Spawn stream acceptor (mirrors listener.rs) so we consume streams sent by the responder.
        let quic_for_accept = handler.quic().await;
        let accept_handler = handler.clone();
        let accept_task = tokio::spawn(async move {
            loop {
                match quic_for_accept.accept_stream().await {
                    Ok((stream_type, stream)) => {
                        let h = accept_handler.clone();
                        tokio::spawn(async move {
                            if let Err(e) = h.handle_incoming_stream(stream_type, stream).await {
                                warn!(error = %e, "Failed to handle incoming stream");
                            }
                        });
                    }
                    Err(Error::ConnectionClosed) => break,
                    Err(e) => {
                        warn!(error = %e, "Failed to accept stream");
                        break;
                    }
                }
            }
        });

        // Heartbeat timer to keep connection alive (server sends heartbeats in initiator mode)
        let mut heartbeat_timer = tokio::time::interval(std::time::Duration::from_secs(5));
        heartbeat_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut heartbeat_seq: u32 = 0;

        // Run the control message processing loop (same as listener.rs)
        let exit_reason: LoopExit = loop {
            tokio::select! {
                biased;

                // Handle shutdown signal
                reason = shutdown_rx.recv() => {
                    match reason {
                        Some(reason) => {
                            info!(?reason, "Shutdown signal received");
                        }
                        None => {
                            info!("Shutdown channel closed");
                        }
                    }
                    break LoopExit::Shutdown;
                }

                // Handle control messages from the client
                msg = handler.recv_control() => {
                    match msg {
                        Ok(Message::ChannelOpen(payload)) => {
                            if let Err(e) = handler.handle_channel_open(payload).await {
                                error!(error = %e, "Failed to handle ChannelOpen");
                            }
                        }
                        Ok(Message::ChannelClose(payload)) => {
                            if let Err(e) = handler.handle_channel_close(payload).await {
                                error!(error = %e, "Failed to handle ChannelClose");
                            }
                        }
                        Ok(Message::ChannelAccept(payload)) => {
                            if let Err(e) = handler.handle_channel_accept(payload).await {
                                error!(error = %e, "Failed to handle ChannelAccept");
                            }
                        }
                        Ok(Message::ChannelReject(payload)) => {
                            if let Err(e) = handler.handle_channel_reject(payload).await {
                                error!(error = %e, "Failed to handle ChannelReject");
                            }
                        }
                        Ok(Message::GlobalRequest(payload)) => {
                            if let Err(e) = handler.handle_global_request(payload).await {
                                error!(error = %e, "Failed to handle GlobalRequest");
                            }
                        }
                        Ok(Message::Resize(payload)) => {
                            if let Err(e) = handler.handle_resize(payload).await {
                                warn!(error = %e, "Failed to handle Resize");
                            }
                        }
                        Ok(Message::StateAck(payload)) => {
                            if let Err(e) = handler.handle_state_ack(payload).await {
                                warn!(error = %e, "Failed to handle StateAck");
                            }
                        }
                        Ok(Message::Heartbeat(payload)) => {
                            // Echo heartbeat immediately for RTT measurement
                            let now_ms = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| (d.as_millis() % 65536) as u16)
                                .unwrap_or(0);
                            let reply = Message::Heartbeat(HeartbeatPayload::reply(now_ms, payload.timestamp, payload.seq));
                            if let Err(e) = handler.send_control(&reply).await {
                                warn!(error = %e, "Failed to send heartbeat reply");
                                break LoopExit::Reconnect;
                            }
                        }
                        Ok(Message::Shutdown(payload)) => {
                            info!(reason = ?payload.reason, "Client requested shutdown");
                            break LoopExit::Shutdown;
                        }
                        Ok(other) => {
                            warn!(msg = ?other, "Unexpected control message");
                        }
                        Err(Error::ConnectionClosed) => {
                            info!("Connection closed, reconnecting");
                            break LoopExit::Reconnect;
                        }
                        Err(e) if e.is_transient() => {
                            warn!(error = %e, "Transient control stream error, reconnecting");
                            break LoopExit::Reconnect;
                        }
                        Err(e) => {
                            warn!(error = %e, "Control stream error");
                            break LoopExit::Shutdown;
                        }
                    }
                }

                // Send heartbeat to keep connection alive
                _ = heartbeat_timer.tick() => {
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| (d.as_millis() % 65536) as u16)
                        .unwrap_or(0);
                    let heartbeat = Message::Heartbeat(HeartbeatPayload::new(now_ms, heartbeat_seq as u16));
                    heartbeat_seq = heartbeat_seq.wrapping_add(1);
                    if let Err(e) = handler.send_control(&heartbeat).await {
                        warn!(error = %e, "Failed to send heartbeat");
                        break LoopExit::Reconnect;
                    }
                }
            }
        };

        accept_task.abort();

        match exit_reason {
            LoopExit::Shutdown => break,
            LoopExit::Reconnect => {
                // Cache RTT for Mosh-style retry delay.
                last_rtt = Some(handler.rtt().await);

                loop {
                    let delay = reconnect_handler.next_delay(last_rtt);
                    let attempt = reconnect_handler.attempt();
                    info!(attempt, delay_ms = delay.as_millis(), "Reconnection attempt (initiator mode)");
                    tokio::time::sleep(delay).await;

                    match connect_and_handshake(server_addr, cert_hash.clone(), session_key, &capabilities).await {
                        Ok((new_quic, new_control, _new_session_id)) => {
                            let (shutdown_tx, new_shutdown_rx) = tokio::sync::mpsc::channel::<qsh_server::connection::ShutdownReason>(1);
                            handler.reconnect(new_quic, new_control, shutdown_tx).await;
                            shutdown_rx = new_shutdown_rx;
                            reconnect_handler.reset();
                            break;
                        }
                        Err(e) if e.is_fatal() => {
                            error!(error = %e, "Reconnection failed with fatal error");
                            return Err(e);
                        }
                        Err(e) => {
                            warn!(error = %e, "Reconnection attempt failed");
                            continue;
                        }
                    }
                }
            }
        }
    }

    // Cleanup
    handler.shutdown().await;
    info!("Server initiator mode connection closed");

    Ok(())
}
