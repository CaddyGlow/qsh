//! qsh server binary entry point.
//!
//! QUIC endpoint for qsh connections using the SSH-style channel model.

use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use quinn::{Endpoint, IdleTimeout, ServerConfig, TransportConfig};
use tracing::{debug, error, info, warn};

use qsh_core::protocol::{Capabilities, Message};
use qsh_core::transport::{Connection, server_crypto_config};
use qsh_server::{
    BootstrapServer, Cli, ConnectionConfig, PendingSession, SessionAuthorizer, SessionConfig,
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

    // Build connection config
    let conn_config = ConnectionConfig {
        max_forwards: cli.max_forwards,
        allow_remote_forwards: cli.allow_remote_forwards,
        ..Default::default()
    };

    serve_endpoint(endpoint, session_config, conn_config, Some(authorizer), None).await
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

    // Build connection config
    let conn_config = ConnectionConfig {
        max_forwards: cli.max_forwards,
        allow_remote_forwards: cli.allow_remote_forwards,
        ..Default::default()
    };

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

    serve_endpoint(endpoint, session_config, conn_config, None, standalone_auth).await
}

async fn serve_endpoint(
    endpoint: Endpoint,
    session_config: SessionConfig,
    conn_config: ConnectionConfig,
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
        let conn_config = conn_config.clone();
        let authorizer = authorizer.clone();
        let standalone_auth = standalone_auth.clone();
        tokio::spawn(async move {
            if let Err(e) =
                handle_connection(incoming, config, conn_config, authorizer, standalone_auth).await
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
    conn_config: ConnectionConfig,
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
        let (mut send, mut recv) =
            conn.open_bi()
                .await
                .map_err(|e| qsh_core::Error::Transport {
                    message: format!("failed to open auth stream: {}", e),
                })?;

        match authenticate_connection(auth.as_ref(), &mut send, &mut recv).await {
            AuthResult::Success { client_fingerprint } => {
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

    // Accept the session and create the connection handler (channel model only)
    let (handler, shutdown_rx) = pending.accept_channel_model(conn_config).await?;

    // Run the channel model session loop
    handle_channel_model_session(handler, shutdown_rx).await
}

/// Handle a channel-model session.
///
/// This processes control messages (ChannelOpen, ChannelClose, GlobalRequest, etc.)
/// and routes streams to appropriate channels.
async fn handle_channel_model_session(
    handler: std::sync::Arc<qsh_server::ConnectionHandler>,
    mut shutdown_rx: tokio::sync::mpsc::Receiver<()>,
) -> qsh_core::Result<()> {
    info!(
        session_id = ?handler.session_id(),
        addr = %handler.remote_addr(),
        rtt = ?handler.rtt(),
        "Channel model session started"
    );

    let quic = handler.quic().clone();
    let handler_clone = handler.clone();

    // Spawn stream acceptor task
    let accept_handler = handler.clone();
    let accept_task = tokio::spawn(async move {
        loop {
            match quic.accept_stream().await {
                Ok((stream_type, stream)) => {
                    let h = accept_handler.clone();
                    tokio::spawn(async move {
                        if let Err(e) = h.handle_incoming_stream(stream_type, stream).await {
                            warn!(error = %e, "Failed to handle incoming stream");
                        }
                    });
                }
                Err(qsh_core::Error::ConnectionClosed) => break,
                Err(e) => {
                    warn!(error = %e, "Failed to accept stream");
                    break;
                }
            }
        }
    });

    // Main control message loop
    loop {
        tokio::select! {
            biased;

            // Handle shutdown signal
            _ = shutdown_rx.recv() => {
                debug!("Shutdown signal received");
                break;
            }

            // Handle control messages
            msg = handler_clone.recv_control() => {
                match msg {
                    Ok(Message::ChannelOpen(payload)) => {
                        if let Err(e) = handler_clone.handle_channel_open(payload).await {
                            error!(error = %e, "Failed to handle ChannelOpen");
                        }
                    }
                    Ok(Message::ChannelClose(payload)) => {
                        if let Err(e) = handler_clone.handle_channel_close(payload).await {
                            error!(error = %e, "Failed to handle ChannelClose");
                        }
                    }
                    Ok(Message::GlobalRequest(payload)) => {
                        if let Err(e) = handler_clone.handle_global_request(payload).await {
                            error!(error = %e, "Failed to handle GlobalRequest");
                        }
                    }
                    Ok(Message::Resize(payload)) => {
                        if let Err(e) = handler_clone.handle_resize(payload).await {
                            warn!(error = %e, "Failed to handle Resize");
                        }
                    }
                    Ok(Message::StateAck(payload)) => {
                        if let Err(e) = handler_clone.handle_state_ack(payload).await {
                            warn!(error = %e, "Failed to handle StateAck");
                        }
                    }
                    Ok(Message::Shutdown(payload)) => {
                        info!(reason = ?payload.reason, "Client requested shutdown");
                        break;
                    }
                    Ok(other) => {
                        warn!(msg = ?other, "Unexpected control message");
                    }
                    Err(qsh_core::Error::ConnectionClosed) => {
                        info!("Connection closed");
                        break;
                    }
                    Err(e) => {
                        error!(error = %e, "Control stream error");
                        break;
                    }
                }
            }
        }
    }

    // Cleanup
    accept_task.abort();
    handler.shutdown().await;

    info!(
        session_id = ?handler.session_id(),
        "Channel model session ended"
    );

    Ok(())
}
