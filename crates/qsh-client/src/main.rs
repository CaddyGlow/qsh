//! qsh client binary entry point.
//!
//! Modern roaming-capable remote terminal client.

use std::net::ToSocketAddrs;
use std::time::Duration;

use clap::Parser;
use tracing::{debug, error, info, warn};

use qsh_client::cli::SshBootstrapMode;
use qsh_client::{
    BootstrapMode, ChannelConnection, Cli, ConnectionConfig, EscapeCommand, EscapeHandler,
    EscapeResult, ForwarderHandle, HeartbeatTracker, LocalForwarder, ProxyHandle, RawModeGuard,
    ReconnectableConnection, RemoteForwarder, RemoteForwarderHandle, Session, SessionContext,
    Socks5Proxy, SshConfig, StdinReader, StdoutWriter, TerminalSessionState, bootstrap,
    get_terminal_size, parse_dynamic_forward, parse_escape_key, parse_local_forward,
    parse_remote_forward, random_local_port, restore_terminal,
};
use qsh_core::protocol::Message;
use qsh_core::terminal::TerminalParser;
use qsh_core::transport::TransportSender;

#[cfg(feature = "standalone")]
use qsh_client::standalone::authenticate as standalone_authenticate;
#[cfg(feature = "standalone")]
use qsh_client::{DirectAuthenticator, DirectConfig, establish_quic_connection};

use qsh_core::protocol::TermSize;

fn main() {
    // Parse CLI arguments
    let cli = Cli::parse();

    // Validate CLI arguments and infer connect mode before doing anything else
    let _effective_connect_mode = match cli.validate_and_infer_connect_mode() {
        Ok(mode) => mode,
        Err(e) => {
            eprintln!("qsh: {}", e);
            std::process::exit(1);
        }
    };

    // Initialize logging
    let log_format = cli.log_format.into();
    if let Err(e) = qsh_core::init_logging(cli.verbose, cli.log_file.as_deref(), log_format) {
        eprintln!("Failed to initialize logging: {}", e);
        std::process::exit(1);
    }

    // Log startup
    info!(version = env!("CARGO_PKG_VERSION"), "qsh client starting");

    // Check for bootstrap mode
    if cli.bootstrap {
        // Run in bootstrap/responder mode
        let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
        let result = rt.block_on(async { run_bootstrap_mode(&cli).await });

        match result {
            Ok(exit_code) => std::process::exit(exit_code),
            Err(e) => {
                error!(error = %e, "Bootstrap mode failed");
                eprintln!("qsh: {}", e);
                std::process::exit(1);
            }
        }
    }

    // Check for attach mode
    if cli.attach.is_some() {
        // Run in attach mode - connect to existing bootstrap session
        let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
        let result = rt.block_on(async { run_attach_mode(cli.attach.as_deref()).await });

        match result {
            Ok(exit_code) => std::process::exit(exit_code),
            Err(e) => {
                error!(error = %e, "Attach mode failed");
                eprintln!("qsh: {}", e);
                std::process::exit(1);
            }
        }
    }

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

    match result {
        Ok(exit_code) => std::process::exit(exit_code),
        Err(e) => {
            error!(error = %e, "Connection failed");
            eprintln!("qsh: {}", e);
            std::process::exit(1);
        }
    }
}

/// Run client in bootstrap/responder mode.
///
/// This is invoked by a remote qsh-server via SSH. The client:
/// 1. Creates a named pipe for attach (stdin/stdout/stderr)
/// 2. Creates a BootstrapEndpoint (generates session key, cert, binds port)
/// 3. Prints bootstrap JSON to stdout (with attach_pipe path)
/// 4. Creates a QUIC acceptor and waits for a single connection
/// 5. Performs handshake as responder
/// 6. Waits for attach client to connect to pipe
/// 7. Runs the Session with pipe as stdin/stdout
async fn run_bootstrap_mode(cli: &Cli) -> qsh_core::Result<i32> {
    use std::net::IpAddr;
    use qsh_client::attach::{create_pipe, pipe_path, accept_attach};
    use qsh_core::bootstrap::{BootstrapEndpoint, BootstrapOptions};
    use qsh_core::ConnectMode;
    use qsh_core::transport::{ListenerConfig, QuicAcceptor};

    info!("Starting bootstrap/responder mode");

    // Create named pipe for attach (handles stdin, stdout, stderr)
    let attach_pipe_path = pipe_path();
    let (_pipe_guard, pipe_listener) = create_pipe(&attach_pipe_path)?;
    info!(pipe = %attach_pipe_path.display(), "Created attach pipe");

    // Parse bind IP
    let bind_ip: IpAddr = cli
        .bootstrap_bind_ip
        .parse()
        .map_err(|e| qsh_core::Error::Transport {
            message: format!("invalid bind IP '{}': {}", cli.bootstrap_bind_ip, e),
        })?;

    // Create bootstrap options
    let mut bootstrap_options = BootstrapOptions::default();
    bootstrap_options.port_range = cli.bootstrap_port_range;
    bootstrap_options.timeout = Duration::from_secs(cli.bootstrap_timeout_secs);

    // Create bootstrap endpoint
    let endpoint = BootstrapEndpoint::new(bind_ip, &bootstrap_options).await?;
    info!(addr = %endpoint.bind_addr, "Bootstrap endpoint created");

    // Print bootstrap response to stdout (with attach_pipe path)
    endpoint.print_response_with_pipe(
        ConnectMode::Respond,
        attach_pipe_path.to_string_lossy().as_ref(),
    )?;
    info!("Bootstrap response sent");

    // Create QUIC acceptor with the endpoint's certificate and key
    let listener_config = ListenerConfig {
        cert_pem: endpoint.cert_pem.clone(),
        key_pem: endpoint.key_pem.clone(),
        idle_timeout: cli.max_idle_timeout(),
        ticket_key: None,
    };

    let mut acceptor = QuicAcceptor::bind(endpoint.bind_addr, listener_config).await?;
    info!(local_addr = %acceptor.local_addr(), "QUIC acceptor bound, waiting for connection");

    // Accept a single QUIC connection with timeout
    let timeout = Duration::from_secs(cli.bootstrap_timeout_secs);
    let (quic_conn, peer_addr) = tokio::time::timeout(timeout, acceptor.accept())
        .await
        .map_err(|_| qsh_core::Error::Transport {
            message: format!("bootstrap timeout after {}s", cli.bootstrap_timeout_secs),
        })??;

    info!(peer = %peer_addr, "Accepted QUIC connection from initiator (server)");

    // Build connection config for responder mode
    let config = ConnectionConfig {
        server_addr: peer_addr,
        session_key: endpoint.session_key,
        cert_hash: None,
        term_size: TermSize { cols: 80, rows: 24 }, // Placeholder, will be set by attach client
        term_type: "xterm-256color".to_string(),
        env: vec![],
        predictive_echo: false, // No prediction in bootstrap mode
        connect_timeout: Duration::from_secs(5),
        zero_rtt_available: false,
        keep_alive_interval: cli.keep_alive_interval(),
        max_idle_timeout: cli.max_idle_timeout(),
        session_data: None,
        local_port: None,
        connect_mode: ConnectMode::Respond,
    };

    // Complete qsh protocol handshake as responder
    let conn = std::sync::Arc::new(ChannelConnection::from_quic(quic_conn, config.clone()).await?);
    info!(
        rtt = ?conn.rtt().await,
        session_id = ?conn.session_id(),
        "Bootstrap handshake complete"
    );

    // Open terminal channel IMMEDIATELY after handshake
    // This starts the shell on the server side so it's ready when attach connects
    let terminal_params = qsh_core::protocol::TerminalParams {
        term_size: TermSize { cols: 80, rows: 24 }, // Default size, attach client can resize
        term_type: std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string()),
        env: vec![],
        shell: None,
        command: None,
        allocate_pty: true,
        last_generation: 0,
        last_input_seq: 0,
        output_mode: cli.output_mode(),
    };

    let terminal = conn.open_terminal(terminal_params).await?;
    info!(channel_id = ?terminal.channel_id(), "Terminal channel opened, shell is running");

    // Buffer for terminal output received before attach connects
    let mut output_buffer: Vec<u8> = Vec::new();

    // Wait for attach client to connect.
    // We must process control messages (heartbeats) AND terminal output from the server
    // to keep the connection alive and buffer any shell output.
    info!("Waiting for attach client on {}", attach_pipe_path.display());

    // Use a channel to signal when attach client connects
    let (attach_tx, attach_rx) = tokio::sync::oneshot::channel();

    // Spawn task to accept attach client
    let attach_task = tokio::spawn(async move {
        let result = accept_attach(&pipe_listener).await;
        let _ = attach_tx.send(result);
    });

    // Process control messages and terminal output until attach client connects
    let mut attach_rx = attach_rx;
    let attach_result = loop {
        tokio::select! {
            biased;

            // Check if attach client connected
            result = &mut attach_rx => {
                match result {
                    Ok(r) => break r,
                    Err(_) => {
                        return Err(qsh_core::Error::Transport {
                            message: "attach accept task failed".to_string(),
                        });
                    }
                }
            }

            // Read terminal output and buffer it
            event = terminal.recv_event() => {
                match event {
                    Ok(qsh_client::channel::TerminalEvent::Output(output)) => {
                        debug!(len = output.data.len(), "Buffering terminal output while waiting for attach");
                        output_buffer.extend_from_slice(&output.data);
                    }
                    Ok(qsh_client::channel::TerminalEvent::StateSync(_)) => {
                        debug!("Received state sync while waiting for attach");
                    }
                    Err(e) => {
                        warn!(error = %e, "Terminal output error while waiting for attach");
                        // Terminal may have closed - continue waiting for attach
                    }
                }
            }

            // Process control messages from server (mainly heartbeats)
            msg = conn.recv_control() => {
                match msg {
                    Ok(Message::Heartbeat(hb)) => {
                        // Echo heartbeat back to server
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| (d.as_millis() % 65536) as u16)
                            .unwrap_or(0);
                        let reply = Message::Heartbeat(qsh_core::protocol::HeartbeatPayload::reply(
                            now_ms,
                            hb.timestamp,
                            hb.seq,
                        ));
                        if let Err(e) = conn.send_control(&reply).await {
                            warn!(error = %e, "Failed to send heartbeat reply while waiting for attach");
                        } else {
                            debug!(seq = hb.seq, "Replied to heartbeat while waiting for attach");
                        }
                    }
                    Ok(msg) => {
                        debug!(?msg, "Received control message while waiting for attach");
                    }
                    Err(e) => {
                        warn!(error = %e, "Control stream error while waiting for attach");
                    }
                }
            }
        }
    };

    // Clean up attach task if it's still running
    attach_task.abort();

    let attach_stream = attach_result?;
    info!(
        buffered_output = output_buffer.len(),
        "Attach client connected"
    );

    // Flush buffered output to attach client
    use tokio::io::AsyncWriteExt;
    let (mut attach_rx, mut attach_tx) = attach_stream.into_split();
    if !output_buffer.is_empty() {
        info!(len = output_buffer.len(), "Flushing buffered terminal output to attach client");
        attach_tx.write_all(&output_buffer).await.map_err(|e| qsh_core::Error::Io(e))?;
    }

    // Simple relay loop: attach <-> terminal channel
    // Also process heartbeats to keep connection alive
    info!("Starting bootstrap relay loop");

    let mut attach_buf = [0u8; 4096];
    let mut heartbeat_interval = tokio::time::interval(Duration::from_secs(5));
    heartbeat_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            biased;

            // Attach client input -> terminal channel
            result = tokio::io::AsyncReadExt::read(&mut attach_rx, &mut attach_buf) => {
                match result {
                    Ok(0) => {
                        info!("Attach client disconnected");
                        break;
                    }
                    Ok(n) => {
                        // send_input takes (data, predictable) - not predictable for bootstrap relay
                        if let Err(e) = terminal.send_input(&attach_buf[..n], false).await {
                            warn!(error = %e, "Failed to send to terminal channel");
                            break;
                        } else {
                            debug!(len = n, "Forwarded attach input to terminal");
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to read from attach client");
                        break;
                    }
                }
            }

            // Terminal channel output -> attach client
            event = terminal.recv_event() => {
                match event {
                    Ok(qsh_client::channel::TerminalEvent::Output(output)) => {
                        if let Err(e) = attach_tx.write_all(&output.data).await {
                            warn!(error = %e, "Failed to write to attach client");
                            break;
                        }
                    }
                    Ok(qsh_client::channel::TerminalEvent::StateSync(_)) => {
                        // State sync is for reconnection, not relevant for bootstrap relay
                        debug!("Ignoring state sync in bootstrap relay");
                    }
                    Err(e) => {
                        warn!(error = %e, "Terminal channel closed");
                        break;
                    }
                }
            }

            // Process control messages (heartbeats)
            msg = conn.recv_control() => {
                match msg {
                    Ok(Message::Heartbeat(hb)) => {
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| (d.as_millis() % 65536) as u16)
                            .unwrap_or(0);
                        let reply = Message::Heartbeat(qsh_core::protocol::HeartbeatPayload::reply(
                            now_ms,
                            hb.timestamp,
                            hb.seq,
                        ));
                        if let Err(e) = conn.send_control(&reply).await {
                            warn!(error = %e, "Failed to send heartbeat reply");
                        }
                    }
                    Ok(Message::ChannelClose(_)) => {
                        info!("Server closed terminal channel");
                        break;
                    }
                    Ok(msg) => {
                        debug!(?msg, "Received control message");
                    }
                    Err(e) => {
                        warn!(error = %e, "Control stream error");
                        break;
                    }
                }
            }
        }
    }

    info!("Bootstrap session ended");
    Ok(0)
}

/// Run client in attach mode.
///
/// Connects to an existing bootstrap session via named pipe.
/// Provides stdin/stdout/stderr access to the remote shell.
async fn run_attach_mode(pipe_path: Option<&str>) -> qsh_core::Result<i32> {
    use std::path::Path;
    use qsh_client::attach::{connect_attach, find_latest_pipe};
    use qsh_client::terminal::RawModeGuard;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let resolved_path = match pipe_path {
        Some(p) if !p.is_empty() => Path::new(p).to_path_buf(),
        _ => find_latest_pipe()?,
    };

    info!(pipe = %resolved_path.display(), "Attaching to bootstrap session");

    // Connect to the pipe
    let mut pipe = connect_attach(&resolved_path).await?;
    info!("Connected to bootstrap session");

    // Put terminal in raw mode
    let _raw_guard = RawModeGuard::enter()?;

    // Get stdin and stdout/stderr
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();

    // Relay I/O between local terminal and pipe
    // Pipe output goes to both stdout and stderr (PTY merges them)
    let mut stdin_buf = [0u8; 4096];
    let mut pipe_buf = [0u8; 4096];

    loop {
        tokio::select! {
            // Local stdin -> Pipe
            result = stdin.read(&mut stdin_buf) => {
                match result {
                    Ok(0) => {
                        info!("Stdin closed");
                        break;
                    }
                    Ok(n) => {
                        debug!(len = n, "Attach stdin read");
                        if let Err(e) = pipe.write_all(&stdin_buf[..n]).await {
                            warn!(error = %e, "Failed to write to pipe");
                            break;
                        }
                        let _ = pipe.flush().await;
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to read from stdin");
                        break;
                    }
                }
            }

            // Pipe -> Local stdout (PTY output includes both stdout and stderr)
            result = pipe.read(&mut pipe_buf) => {
                match result {
                    Ok(0) => {
                        info!("Pipe closed");
                        break;
                    }
                    Ok(n) => {
                        // Write to stdout (PTY merges stdout/stderr)
                        if let Err(e) = stdout.write_all(&pipe_buf[..n]).await {
                            warn!(error = %e, "Failed to write to stdout");
                            break;
                        }
                        let _ = stdout.flush().await;
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to read from pipe");
                        break;
                    }
                }
            }
        }
    }

    // Suppress unused variable warning
    let _ = stderr;

    info!("Attach session ended");
    Ok(0)
}

#[cfg(feature = "standalone")]
async fn run_client_standalone(cli: &Cli, host: &str, user: Option<&str>) -> qsh_core::Result<i32> {
    use rand::RngCore;

    // Determine server address for direct mode
    let server_addr_str = if let Some(ref server) = cli.server {
        server.clone()
    } else {
        // Default to host:4433 if not specified
        format!("{}:4433", host)
    };

    let direct_config = DirectConfig {
        server_addr: server_addr_str.clone(),
        key_path: cli.key.clone(),
        known_hosts_path: cli.known_hosts.clone(),
        accept_unknown_host: cli.accept_unknown_host,
        no_agent: cli.no_agent,
    };

    // Build direct authenticator (loads known_hosts and signing key)
    let mut authenticator = DirectAuthenticator::new(&direct_config).await?;

    // Resolve server address for QUIC
    let server_sock_addr = server_addr_str
        .to_socket_addrs()
        .map_err(|e| qsh_core::Error::Transport {
            message: format!("failed to resolve server address: {}", e),
        })?
        .next()
        .ok_or_else(|| qsh_core::Error::Transport {
            message: "no addresses found for server".to_string(),
        })?;

    // Generate a fresh session key (not authenticated by standalone auth;
    // used for session identification and reconnection).
    let mut session_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut session_key);

    let conn_config = ConnectionConfig {
        server_addr: server_sock_addr,
        session_key,
        cert_hash: None,
        term_size: get_term_size(),
        term_type: std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string()),
        env: collect_terminal_env(),
        predictive_echo: !cli.no_prediction,
        connect_timeout: cli.connect_timeout(),
        zero_rtt_available: false,
        keep_alive_interval: cli.keep_alive_interval(),
        max_idle_timeout: cli.max_idle_timeout(),
        session_data: None,
        local_port: Some(random_local_port()),
        connect_mode: cli.connect_mode.into(),
    };

    info!(addr = %conn_config.server_addr, local_port = ?conn_config.local_port, "Connecting directly to server");
    let quic_conn = establish_quic_connection(&conn_config).await?;

    // Perform standalone authentication on a dedicated server-initiated stream.
    // Server opens the stream and sends AuthChallenge; client accepts and responds.
    let (mut send, mut recv) =
        quic_conn
            .accept_bi()
            .await
            .map_err(|e| qsh_core::Error::Transport {
                message: format!("failed to accept auth stream: {}", e),
            })?;

    standalone_authenticate(&mut authenticator, &mut send, &mut recv).await?;
    info!("Standalone authentication succeeded");

    // Complete qsh protocol handshake using channel model.
    let conn = ChannelConnection::from_quic(quic_conn, conn_config.clone()).await?;
    info!(rtt = ?conn.rtt().await, session_id = ?conn.session_id(), "Connected to server");

    // Create session context for reconnection support (with authenticator for re-auth)
    let context =
        SessionContext::new(conn_config, conn.session_id()).with_authenticator(authenticator);

    // Create reconnectable connection wrapper
    let reconnectable = std::sync::Arc::new(ReconnectableConnection::new(conn, context));

    // Cache session data for 0-RTT reconnection (critical for Mosh-style fast recovery)
    reconnectable.store_session_data().await;

    // Build and run unified session (handles both terminal and forwards)
    let user_host = format_user_host(user, host);
    let session = Session::from_cli(reconnectable, cli, Some(user_host))?;
    session.run().await
}

/// Run client using SSH bootstrap mode.
///
/// This uses SSH to bootstrap the qsh server, then connects via QUIC.
/// Uses `ChannelConnection` which does not open a terminal automatically.
/// Instead, we explicitly open a terminal channel after the handshake.
async fn run_client_ssh_bootstrap(
    cli: &Cli,
    host: &str,
    user: Option<&str>,
) -> qsh_core::Result<i32> {
    info!("Using channel model...");

    // Build server args, adding --mode if requested
    let mut server_args = cli.bootstrap_server_args.clone().unwrap_or_default();

    // Pass output mode to server
    let output_mode = cli.output_mode();
    if !server_args.is_empty() {
        server_args.push(' ');
    }
    server_args.push_str("--mode ");
    server_args.push_str(match output_mode {
        qsh_core::protocol::OutputMode::Direct => "direct",
        qsh_core::protocol::OutputMode::Mosh => "mosh",
        qsh_core::protocol::OutputMode::StateDiff => "state-diff",
    });

    // Build SSH config from CLI options
    let mut bootstrap_options = qsh_core::bootstrap::BootstrapOptions::default();
    bootstrap_options.port_range = cli.bootstrap_port_range;
    bootstrap_options.extra_env = cli.parse_bootstrap_server_env()?;
    bootstrap_options.extra_args = if server_args.is_empty() {
        None
    } else {
        Some(server_args)
    };
    bootstrap_options.timeout = std::time::Duration::from_secs(30);

    let ssh_config = SshConfig {
        connect_timeout: std::time::Duration::from_secs(30),
        identity_file: cli.identity.first().cloned(),
        skip_host_key_check: false,
        bootstrap_options,
        mode: match cli.ssh_bootstrap_mode {
            SshBootstrapMode::Ssh => BootstrapMode::SshCli,
            SshBootstrapMode::Russh => BootstrapMode::Russh,
        },
    };

    // Bootstrap returns a handle that keeps the SSH process alive
    let bootstrap_handle = bootstrap(host, cli.port, user, &ssh_config).await?;
    let endpoint_info = &bootstrap_handle.endpoint_info;

    // Use bootstrap info to connect
    let connect_host = if endpoint_info.address == "0.0.0.0"
        || endpoint_info.address == "::"
        || endpoint_info.address.starts_with("0.")
    {
        host.to_string()
    } else {
        endpoint_info.address.clone()
    };

    let addr = format!("{}:{}", connect_host, endpoint_info.port)
        .to_socket_addrs()
        .map_err(|e| qsh_core::Error::Transport {
            message: format!("failed to resolve server address: {}", e),
        })?
        .next()
        .ok_or_else(|| qsh_core::Error::Transport {
            message: "no addresses found for server".to_string(),
        })?;

    let session_key = endpoint_info.decode_session_key()?;
    let cert_hash = endpoint_info.decode_cert_hash().ok();

    let config = ConnectionConfig {
        server_addr: addr,
        session_key,
        cert_hash,
        term_size: get_term_size(),
        term_type: std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string()),
        env: collect_terminal_env(),
        predictive_echo: !cli.no_prediction,
        connect_timeout: cli.connect_timeout(),
        zero_rtt_available: false,
        keep_alive_interval: cli.keep_alive_interval(),
        max_idle_timeout: cli.max_idle_timeout(),
        session_data: None,
        local_port: Some(random_local_port()), // Mosh-style port range
        connect_mode: cli.connect_mode.into(),
    };

    // Connect using the channel model (no implicit terminal)
    let conn = ChannelConnection::connect(config.clone()).await?;
    info!(
        rtt = ?conn.rtt().await,
        session_id = ?conn.session_id(),
        "Channel model connection established"
    );

    // Drop the bootstrap handle now that QUIC connection is established
    drop(bootstrap_handle);

    // Create session context for reconnection support
    let context = SessionContext::new(config, conn.session_id());

    // Create reconnectable connection wrapper
    let reconnectable = std::sync::Arc::new(ReconnectableConnection::new(conn, context));

    // Cache session data for 0-RTT reconnection (critical for Mosh-style fast recovery)
    reconnectable.store_session_data().await;

    // Build and run unified session (handles both terminal and forwards)
    let user_host = format_user_host(user, host);
    let session = Session::from_cli(reconnectable, cli, Some(user_host))?;
    session.run().await
}

async fn run_client(cli: &Cli, host: &str, user: Option<&str>) -> qsh_core::Result<i32> {
    #[cfg(feature = "standalone")]
    if cli.direct {
        return run_client_standalone(cli, host, user).await;
    }

    // Use SSH bootstrap mode
    run_client_ssh_bootstrap(cli, host, user).await
}

fn get_term_size() -> TermSize {
    match get_terminal_size() {
        Ok(size) => size,
        Err(_) => TermSize { cols: 80, rows: 24 },
    }
}

/// Collect terminal-related environment variables to pass to the remote PTY.
///
/// Note: TERM is handled separately as part of the PTY request (like SSH does),
/// not as an environment variable here.
fn collect_terminal_env() -> Vec<(String, String)> {
    let mut env = Vec::new();

    // COLORTERM indicates true color support (truecolor/24bit)
    if let Ok(val) = std::env::var("COLORTERM") {
        env.push(("COLORTERM".to_string(), val));
    }

    // NO_COLOR disables color output (https://no-color.org/)
    if let Ok(val) = std::env::var("NO_COLOR") {
        env.push(("NO_COLOR".to_string(), val));
    }

    // Locale variables (LANG and LC_*)
    if let Ok(val) = std::env::var("LANG") {
        env.push(("LANG".to_string(), val));
    }
    for (key, val) in std::env::vars() {
        if key.starts_with("LC_") {
            env.push((key, val));
        }
    }

    env
}

/// Format user@host string for overlay display.
fn format_user_host(user: Option<&str>, host: &str) -> String {
    match user {
        Some(u) => format!("{}@{}", u, host),
        None => host.to_string(),
    }
}
