//! qsh client binary entry point.
//!
//! Modern roaming-capable remote terminal client.

use std::net::ToSocketAddrs;
use std::time::Duration;

use clap::Parser;
use tokio::time::MissedTickBehavior;
use tracing::{debug, error, info, warn};

use qsh_client::cli::{OverlayPosition as CliOverlayPosition, SshBootstrapMode};
use qsh_client::overlay::{ConnectionStatus, OverlayPosition, StatusOverlay};
use qsh_client::prediction::{DisplayPreference, PredictedStyle};
use qsh_client::{
    BootstrapMode, ChannelConnection, Cli, ConnectionConfig, ConnectionState, EscapeCommand,
    EscapeHandler, EscapeResult, ForwarderHandle, LocalForwarder, ProxyHandle, RawModeGuard,
    ReconnectableConnection, RemoteForwarder, RemoteForwarderHandle, SessionContext, Socks5Proxy,
    SshConfig, StdinReader, StdoutWriter, TerminalSessionState, bootstrap,
    connect_quic, get_terminal_size, parse_dynamic_forward, parse_escape_key, parse_local_forward,
    parse_remote_forward, restore_terminal,
};

#[cfg(feature = "standalone")]
use qsh_client::standalone::authenticate as standalone_authenticate;
#[cfg(feature = "standalone")]
use qsh_client::{DirectAuthenticator, DirectConfig};

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

/// Handle control messages in forwarding-only mode.
///
/// Processes server-initiated channels (ForwardedTcpIp) and shutdown requests.
async fn handle_control_message(
    conn: &std::sync::Arc<ChannelConnection>,
    msg: qsh_core::protocol::Message,
) -> qsh_core::Result<()> {
    use qsh_core::protocol::{ChannelParams, Message};

    match msg {
        Message::ChannelOpen(open) => match open.params {
            ChannelParams::ForwardedTcpIp(params) => {
                conn.handle_forwarded_channel_open(open.channel_id, params)
                    .await?;
            }
            other => {
                debug!(?other, "Ignoring unexpected ChannelOpen type");
            }
        },
        Message::Shutdown(payload) => {
            info!(reason = ?payload.reason, "Server requested shutdown");
            return Err(qsh_core::Error::ConnectionClosed);
        }
        other => {
            debug!(?other, "Ignoring control message in forward-only mode");
        }
    }
    Ok(())
}

#[cfg(feature = "standalone")]
async fn run_client_direct(cli: &Cli, host: &str, user: Option<&str>) -> qsh_core::Result<()> {
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
    };

    info!(addr = %conn_config.server_addr, "Connecting directly to server");
    let quic_conn = connect_quic(&conn_config).await?;

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
    info!(rtt = ?conn.rtt(), session_id = ?conn.session_id(), "Connected to server");

    // Open a terminal channel (unless -N forwarding-only mode)
    if cli.is_forward_only() {
        info!("Forwarding-only mode (-N), no terminal channel");

        // Wrap connection in Arc for sharing with forwards
        let conn = std::sync::Arc::new(conn);

        // Start forwards
        let _forward_handles = start_forwards(cli, &conn).await?;

        // Spawn control message handler for server-initiated channels (remote forwards)
        let conn_clone = std::sync::Arc::clone(&conn);
        let control_task = tokio::spawn(async move {
            info!("Control message handler started");
            loop {
                debug!("Waiting for control message...");
                match conn_clone.recv_control().await {
                    Ok(msg) => {
                        info!(?msg, "Received control message");
                        if let Err(e) = handle_control_message(&conn_clone, msg).await {
                            warn!(error = %e, "Error handling control message");
                            break;
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "Control stream ended");
                        break;
                    }
                }
            }
        });

        // Wait for Ctrl+C
        info!("Press Ctrl+C to exit");
        tokio::signal::ctrl_c()
            .await
            .map_err(qsh_core::Error::Io)?;

        info!("Shutting down...");
        control_task.abort();
        conn.shutdown().await?;
        return Ok(());
    }

    // Create session context for reconnection support (with authenticator for re-auth)
    let context = SessionContext::new(conn_config, conn.session_id())
        .with_authenticator(authenticator);

    // Create reconnectable connection wrapper
    let reconnectable = std::sync::Arc::new(ReconnectableConnection::new(conn, context));

    // Run the channel session with reconnection support
    let user_host = format_user_host(user, host);
    run_reconnectable_session(reconnectable, cli, Some(user_host)).await
}

/// Run client using the SSH-style channel model (experimental).
///
/// This uses `ChannelConnection` which does not open a terminal automatically.
/// Instead, we explicitly open a terminal channel after the handshake.
async fn run_client_channel_model(
    cli: &Cli,
    host: &str,
    user: Option<&str>,
) -> qsh_core::Result<()> {
    info!("Using channel model...");

    // Build SSH config from CLI options
    let ssh_config = SshConfig {
        connect_timeout: std::time::Duration::from_secs(30),
        identity_file: cli.identity.first().cloned(),
        skip_host_key_check: false,
        port_range: cli.bootstrap_port_range,
        server_args: cli.bootstrap_server_args.clone(),
        mode: match cli.ssh_bootstrap_mode {
            SshBootstrapMode::Ssh => BootstrapMode::SshCli,
            SshBootstrapMode::Russh => BootstrapMode::Russh,
        },
    };

    // Bootstrap returns a handle that keeps the SSH process alive
    let bootstrap_handle = bootstrap(host, cli.port, user, &ssh_config).await?;
    let server_info = &bootstrap_handle.server_info;

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
    };

    // Connect using the channel model (no implicit terminal)
    let conn = ChannelConnection::connect(config.clone()).await?;
    info!(
        rtt = ?conn.rtt(),
        session_id = ?conn.session_id(),
        "Channel model connection established"
    );

    // Drop the bootstrap handle now that QUIC connection is established
    drop(bootstrap_handle);

    // Open a terminal channel (unless -N forwarding-only mode)
    if cli.is_forward_only() {
        info!("Forwarding-only mode (-N), no terminal channel");

        // Wrap connection in Arc for sharing with forwards
        let conn = std::sync::Arc::new(conn);

        // Start forwards
        let _forward_handles = start_forwards(cli, &conn).await?;

        // Spawn control message handler for server-initiated channels (remote forwards)
        let conn_clone = std::sync::Arc::clone(&conn);
        let control_task = tokio::spawn(async move {
            info!("Control message handler started");
            loop {
                debug!("Waiting for control message...");
                match conn_clone.recv_control().await {
                    Ok(msg) => {
                        info!(?msg, "Received control message");
                        if let Err(e) = handle_control_message(&conn_clone, msg).await {
                            warn!(error = %e, "Error handling control message");
                            break;
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "Control stream ended");
                        break;
                    }
                }
            }
        });

        // Wait for Ctrl+C
        info!("Press Ctrl+C to exit");
        tokio::signal::ctrl_c()
            .await
            .map_err(qsh_core::Error::Io)?;

        info!("Shutting down...");
        control_task.abort();
        conn.shutdown().await?;
        return Ok(());
    }

    // Create session context for reconnection support
    let context = SessionContext::new(config, conn.session_id());

    // Create reconnectable connection wrapper
    let reconnectable = std::sync::Arc::new(ReconnectableConnection::new(conn, context));

    // Run the channel session with reconnection support
    let user_host = format_user_host(user, host);
    run_reconnectable_session(reconnectable, cli, Some(user_host)).await
}

async fn run_client(cli: &Cli, host: &str, user: Option<&str>) -> qsh_core::Result<()> {
    #[cfg(feature = "standalone")]
    if cli.direct {
        return run_client_direct(cli, host, user).await;
    }

    // Use channel model (SSH-style multiplexing)
    run_client_channel_model(cli, host, user).await
}


async fn render_overlay_if_visible(overlay: &StatusOverlay, stdout: &mut StdoutWriter) {
    // render() handles visibility logic including force-show during reconnection
    let term_size = get_term_size();
    let overlay_output = overlay.render(term_size.cols);
    if !overlay_output.is_empty() {
        let _ = stdout.write(overlay_output.as_bytes()).await;
    }
}

/// Render a predicted character with the appropriate style.
fn render_predicted_char(ch: char, style: PredictedStyle) -> Vec<u8> {
    match style {
        PredictedStyle::Normal => {
            // Just the character, no special styling
            ch.to_string().into_bytes()
        }
        PredictedStyle::Underline => {
            // Underline SGR, char, reset
            format!("\x1b[4m{}\x1b[24m", ch).into_bytes()
        }
        PredictedStyle::Dim => {
            // Dim SGR, char, reset
            format!("\x1b[2m{}\x1b[22m", ch).into_bytes()
        }
    }
}

/// Check if a byte represents a predictable (printable ASCII) character.
fn is_predictable_char(b: u8) -> bool {
    // Printable ASCII: 0x20 (space) through 0x7E (~)
    (0x20..=0x7E).contains(&b)
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

/// Convert CLI overlay position to overlay module position.
fn map_overlay_position(cli_pos: CliOverlayPosition) -> Option<OverlayPosition> {
    match cli_pos {
        CliOverlayPosition::Top => Some(OverlayPosition::Top),
        CliOverlayPosition::Bottom => Some(OverlayPosition::Bottom),
        CliOverlayPosition::TopRight => Some(OverlayPosition::TopRight),
        CliOverlayPosition::None => None,
    }
}

/// Parse toggle key specification (e.g., "ctrl+o", "ctrl+t").
fn parse_toggle_key(spec: &str) -> Option<u8> {
    let spec = spec.to_lowercase();
    if spec.starts_with("ctrl+") {
        let ch = spec.chars().last()?;
        if ch.is_ascii_lowercase() {
            // ctrl+a = 0x01, ctrl+b = 0x02, ..., ctrl+z = 0x1a
            Some((ch as u8) - b'a' + 1)
        } else {
            None
        }
    } else {
        None
    }
}

/// Forward handles for all active forwards.
pub struct ForwardHandles {
    pub local: Vec<ForwarderHandle>,
    pub socks: Vec<ProxyHandle>,
    pub remote: Vec<RemoteForwarderHandle>,
}

/// Start all forwards specified in CLI.
///
/// Returns handles that keep the forwards running. Drop them to stop.
async fn start_forwards(
    cli: &Cli,
    conn: &std::sync::Arc<ChannelConnection>,
) -> qsh_core::Result<ForwardHandles> {
    let mut local_handles = Vec::new();
    let mut socks_handles = Vec::new();
    let mut remote_handles = Vec::new();

    // Start local forwards (-L)
    for spec in &cli.local_forward {
        match parse_local_forward(spec) {
            Ok((bind_addr, target_host, target_port)) => {
                info!(
                    bind = %bind_addr,
                    target = %format!("{}:{}", target_host, target_port),
                    "Starting local forward"
                );
                let forwarder = LocalForwarder::new(
                    bind_addr,
                    target_host,
                    target_port,
                    std::sync::Arc::clone(conn),
                );
                match forwarder.start().await {
                    Ok(handle) => {
                        info!(addr = %handle.local_addr(), "Local forward listening");
                        local_handles.push(handle);
                    }
                    Err(e) => {
                        error!(spec = spec.as_str(), error = %e, "Failed to start local forward");
                        return Err(e);
                    }
                }
            }
            Err(e) => {
                error!(spec = spec.as_str(), error = %e, "Invalid local forward spec");
                return Err(e);
            }
        }
    }

    // Start dynamic forwards (-D)
    for spec in &cli.dynamic_forward {
        match parse_dynamic_forward(spec) {
            Ok(bind_addr) => {
                info!(bind = %bind_addr, "Starting SOCKS5 proxy");
                let proxy = Socks5Proxy::new(bind_addr, std::sync::Arc::clone(conn));
                match proxy.start().await {
                    Ok(handle) => {
                        info!(addr = %handle.local_addr(), "SOCKS5 proxy listening");
                        socks_handles.push(handle);
                    }
                    Err(e) => {
                        error!(spec = spec.as_str(), error = %e, "Failed to start SOCKS5 proxy");
                        return Err(e);
                    }
                }
            }
            Err(e) => {
                error!(spec = spec.as_str(), error = %e, "Invalid dynamic forward spec");
                return Err(e);
            }
        }
    }

    // Start remote forwards (-R)
    for spec in &cli.remote_forward {
        match parse_remote_forward(spec) {
            Ok((bind_host, bind_port, target_host, target_port)) => {
                info!(
                    bind = %format!("{}:{}", bind_host, bind_port),
                    target = %format!("{}:{}", target_host, target_port),
                    "Starting remote forward"
                );
                let forwarder = RemoteForwarder::new(
                    std::sync::Arc::clone(conn),
                    bind_host,
                    bind_port,
                    target_host,
                    target_port,
                );
                match forwarder.start().await {
                    Ok(handle) => {
                        info!(
                            bind_host = %handle.bind_host(),
                            bound_port = handle.bound_port(),
                            "Remote forward established on server"
                        );
                        remote_handles.push(handle);
                    }
                    Err(e) => {
                        error!(spec = spec.as_str(), error = %e, "Failed to start remote forward");
                        return Err(e);
                    }
                }
            }
            Err(e) => {
                error!(spec = spec.as_str(), error = %e, "Invalid remote forward spec");
                return Err(e);
            }
        }
    }

    Ok(ForwardHandles {
        local: local_handles,
        socks: socks_handles,
        remote: remote_handles,
    })
}

/// Create and configure status overlay from CLI options.
fn create_status_overlay(cli: &Cli, user_host: Option<String>) -> StatusOverlay {
    let mut overlay = StatusOverlay::new();

    // Set position
    if let Some(pos) = map_overlay_position(cli.overlay_position) {
        overlay.set_position(pos);
    }

    // Set initial visibility (--status enables, --no-overlay disables)
    let visible =
        cli.show_status && !cli.no_overlay && cli.overlay_position != CliOverlayPosition::None;
    overlay.set_visible(visible);

    // Set user@host if available
    if let Some(uh) = user_host {
        overlay.set_user_host(uh);
    }

    overlay
}

/// Run a terminal session with reconnection support.
///
/// This wraps the terminal session in a reconnection loop. When the connection
/// is lost, it waits for reconnection and reopens the terminal channel with
/// state recovery (last_generation/last_input_seq).
async fn run_reconnectable_session(
    reconnectable: std::sync::Arc<ReconnectableConnection>,
    cli: &Cli,
    user_host: Option<String>,
) -> qsh_core::Result<()> {
    // Track terminal state for recovery after reconnection
    let mut terminal_state = TerminalSessionState::new();

    // Create status overlay
    let mut overlay = create_status_overlay(cli, user_host.clone());

    // Determine if we're in interactive mode (PTY allocated)
    let is_interactive = cli.should_allocate_pty();

    // Enter raw terminal mode only for interactive sessions
    let _raw_guard = if is_interactive {
        match RawModeGuard::enter() {
            Ok(guard) => {
                debug!("Entered raw terminal mode (interactive)");
                Some(guard)
            }
            Err(e) => {
                warn!(error = %e, "Failed to enter raw mode");
                return Err(e.into());
            }
        }
    } else {
        debug!("Command mode (non-interactive), skipping raw terminal mode");
        None
    };

    // Overlay refresh interval
    let mut overlay_refresh = tokio::time::interval(Duration::from_secs(2));
    overlay_refresh.set_missed_tick_behavior(MissedTickBehavior::Delay);

    // Parse toggle key
    let toggle_key = parse_toggle_key(&cli.overlay_key);

    // Parse escape key and create handler
    let escape_key = parse_escape_key(&cli.escape_key);
    let mut escape_handler = EscapeHandler::new(escape_key);

    // Create stdin/stdout handlers
    let mut stdin = StdinReader::new();
    let mut stdout = StdoutWriter::new();

    // Prediction settings
    let prediction_enabled = !cli.no_prediction && is_interactive;

    // Reconnection loop
    loop {
        // Wait for connection to be available
        overlay.set_status(match reconnectable.state() {
            ConnectionState::Connected => ConnectionStatus::Connected,
            ConnectionState::Reconnecting => ConnectionStatus::Reconnecting,
            ConnectionState::Disconnected => ConnectionStatus::Disconnected,
        });
        render_overlay_if_visible(&overlay, &mut stdout).await;

        let conn = match reconnectable.wait_connected().await {
            Ok(conn) => conn,
            Err(e) => {
                error!(error = %e, "Connection permanently lost");
                overlay.set_status(ConnectionStatus::Disconnected);
                render_overlay_if_visible(&overlay, &mut stdout).await;
                return Err(e);
            }
        };

        info!(
            session_id = ?conn.session_id(),
            last_gen = terminal_state.last_generation,
            last_seq = terminal_state.last_input_seq,
            "Opening terminal channel"
        );

        // Get terminal channel: either restored from session resume or newly opened
        let term_size = get_term_size();
        let terminal = if let Some(restored) = conn.get_restored_terminal().await {
            // Mosh-style reconnection: reuse the existing terminal channel
            info!(channel_id = ?restored.channel_id(), "Using restored terminal from session resume");

            // Render the restored terminal state to the screen
            if let Some(state) = restored.take_initial_state().await {
                info!("Rendering restored terminal state");
                let ansi_data = state.render_to_ansi();
                if let Err(e) = stdout.write(&ansi_data).await {
                    warn!(error = %e, "Failed to render restored terminal state");
                }
            }

            // Send resize in case terminal size changed while disconnected
            let current_size = restored.term_size().await;
            let term_size_tuple = (term_size.cols, term_size.rows);
            if current_size != term_size_tuple {
                debug!(
                    old_size = ?current_size,
                    new_size = ?term_size_tuple,
                    "Sending resize after reconnection"
                );
                // Resize will be sent via the control stream when we enter the I/O loop
            }

            restored
        } else {
            // New terminal: open a fresh channel
            let terminal_params = qsh_core::protocol::TerminalParams {
                term_size,
                term_type: std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string()),
                env: collect_terminal_env(),
                shell: None,
                command: cli.command_string(),
                allocate_pty: cli.should_allocate_pty(),
                last_generation: terminal_state.last_generation,
                last_input_seq: terminal_state.last_input_seq,
            };

            match conn.open_terminal(terminal_params).await {
                Ok(t) => t,
                Err(e) => {
                    if e.is_transient() {
                        warn!(error = %e, "Failed to open terminal, triggering reconnect");
                        reconnectable.handle_error(&e).await;
                        continue;
                    } else {
                        error!(error = %e, "Fatal error opening terminal");
                        return Err(e);
                    }
                }
            }
        };

        info!(channel_id = ?terminal.channel_id(), "Terminal channel ready");

        // Update overlay for connected state
        overlay.set_status(ConnectionStatus::Connected);
        overlay.metrics_mut().update_rtt(conn.rtt());
        overlay.metrics_mut().record_heard();

        // Initialize prediction engine with current RTT
        if prediction_enabled {
            let mut prediction = terminal.prediction_mut().await;
            prediction.update_rtt(conn.rtt());
            // Set display preference to adaptive (mosh-style)
            prediction.set_display_preference(DisplayPreference::Adaptive);
        }

        // Start forwards (only on first connection)
        // TODO: Handle forward reconnection

        // Set up SIGWINCH signal handler
        #[cfg(unix)]
        let mut sigwinch =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
                .map_err(qsh_core::Error::Io)?;

        // Inner I/O loop
        let session_result: Result<(), qsh_core::Error> = loop {
            #[cfg(unix)]
            let resize_event = sigwinch.recv();
            #[cfg(not(unix))]
            let resize_event = std::future::pending::<Option<()>>();

            tokio::select! {
                biased;

                // Handle terminal resize
                _ = resize_event => {
                    if let Ok(new_size) = get_terminal_size() {
                        debug!(cols = new_size.cols, rows = new_size.rows, "Terminal resized");
                        // TODO: Send resize message to server through channel
                    }
                }

                // Handle user input
                result = stdin.read() => {
                    let data = match result {
                        Some(data) => data,
                        None => {
                            info!("EOF on stdin");
                            break Ok(());
                        }
                    };

                    // Check toggle key (only if overlay is allowed)
                    if let (Some(key), true) = (toggle_key, data.len() == 1) {
                        if data[0] == key {
                            let visible = overlay.is_visible();
                            overlay.set_visible(!visible);
                            render_overlay_if_visible(&overlay, &mut stdout).await;
                            continue;
                        }
                    }

                    // Check escape sequence
                    match escape_handler.process(&data) {
                        EscapeResult::Command(EscapeCommand::Disconnect) => {
                            info!("Escape sequence: disconnect");
                            break Ok(());
                        }
                        EscapeResult::Command(EscapeCommand::ToggleOverlay) => {
                            let visible = overlay.is_visible();
                            overlay.set_visible(!visible);
                            render_overlay_if_visible(&overlay, &mut stdout).await;
                            continue;
                        }
                        EscapeResult::Command(EscapeCommand::SendEscapeKey) => {
                            // Send the escape character itself
                            let _ = terminal.queue_input(&[escape_key.unwrap_or(0x1e)], false);
                            continue;
                        }
                        EscapeResult::Waiting => {
                            // Waiting for command key, don't send anything yet
                            continue;
                        }
                        EscapeResult::PassThrough(pass_data) => {
                            // Check if input contains predictable characters
                            let has_predictable = prediction_enabled
                                && pass_data.iter().any(|&b| is_predictable_char(b));

                            // Queue the input (mark as predictable if it has printable chars)
                            let seq = match terminal.queue_input(&pass_data, has_predictable) {
                                Ok(seq) => seq,
                                Err(e) => {
                                    warn!(error = %e, "Failed to queue input");
                                    break Err(e);
                                }
                            };

                            // If prediction enabled and input is predictable, echo immediately
                            if has_predictable {
                                let mut prediction = terminal.prediction_mut().await;

                                // Only render if prediction engine says we should display
                                if prediction.should_display() {
                                    let mut predicted_count = 0u32;
                                    for &byte in &pass_data {
                                        if is_predictable_char(byte) {
                                            let ch = byte as char;
                                            // Note: We use (0, 0) for position since we're doing
                                            // simple inline echo, not position-based overlay
                                            if let Some(echo) = prediction.predict(ch, 0, 0, seq) {
                                                let rendered = render_predicted_char(echo.char, echo.style);
                                                let _ = stdout.write(&rendered).await;
                                                predicted_count += 1;
                                            }
                                        }
                                    }
                                    // Move cursor back so server output overwrites predictions
                                    // Use CUB (Cursor Back) escape sequence
                                    if predicted_count > 0 {
                                        let cursor_back = format!("\x1b[{}D", predicted_count);
                                        let _ = stdout.write(cursor_back.as_bytes()).await;
                                    }
                                }
                            }
                        }
                    }
                }

                // Handle terminal events (output or state sync)
                result = terminal.recv_event() => {
                    match result {
                        Ok(qsh_client::TerminalEvent::Output(output)) => {
                            overlay.metrics_mut().record_heard();

                            // Track confirmed input seq for recovery
                            terminal_state.last_input_seq = output.confirmed_input_seq;

                            // Confirm predictions up to this sequence
                            if prediction_enabled {
                                let mut prediction = terminal.prediction_mut().await;
                                prediction.confirm(output.confirmed_input_seq);
                            }

                            // Output the data
                            if let Err(e) = stdout.write(&output.data).await {
                                warn!(error = %e, "stdout write error");
                                break Err(e.into());
                            }

                            // Render status overlay
                            render_overlay_if_visible(&overlay, &mut stdout).await;
                        }
                        Ok(qsh_client::TerminalEvent::StateSync(update)) => {
                            overlay.metrics_mut().record_heard();

                            // Track confirmed input seq
                            terminal_state.last_input_seq = update.confirmed_input_seq;

                            // Reset prediction engine on full state sync
                            if prediction_enabled {
                                let mut prediction = terminal.prediction_mut().await;
                                prediction.reset();
                            }

                            // Render the full state to the terminal (mosh-style resync)
                            if let qsh_core::terminal::StateDiff::Full(state) = update.diff {
                                info!("Received state sync after reconnection");
                                let ansi_data = state.render_to_ansi();
                                if let Err(e) = stdout.write(&ansi_data).await {
                                    warn!(error = %e, "stdout write error during state sync");
                                    break Err(e.into());
                                }
                            }

                            // Render status overlay
                            render_overlay_if_visible(&overlay, &mut stdout).await;
                        }
                        Err(qsh_core::Error::ConnectionClosed) => {
                            info!("Channel closed");
                            break Ok(());
                        }
                        Err(e) => {
                            warn!(error = %e, "recv_event error");
                            break Err(e);
                        }
                    }
                }

                // Overlay refresh
                _ = overlay_refresh.tick() => {
                    if let Some(rtt) = reconnectable.rtt() {
                        overlay.metrics_mut().update_rtt(rtt);

                        // Update prediction engine RTT for adaptive display
                        if prediction_enabled {
                            let mut prediction = terminal.prediction_mut().await;
                            prediction.update_rtt(rtt);
                            prediction.check_glitches();
                        }
                    }
                    render_overlay_if_visible(&overlay, &mut stdout).await;
                }
            }
        };

        // Handle session result
        match session_result {
            Ok(()) => {
                // Clean exit (EOF, user disconnect, channel closed)
                info!("Session ended cleanly");
                terminal.mark_closed();
                break;
            }
            Err(e) if e.is_transient() => {
                // Transient error - trigger reconnection and continue loop
                warn!(error = %e, "Transient error, attempting reconnection");
                overlay.set_status(ConnectionStatus::Reconnecting);
                render_overlay_if_visible(&overlay, &mut stdout).await;
                reconnectable.handle_error(&e).await;
                // Continue outer loop - will wait for reconnection
            }
            Err(e) => {
                // Fatal error
                error!(error = %e, "Fatal session error");
                terminal.mark_closed();
                return Err(e);
            }
        }
    }

    // Restore terminal
    restore_terminal();

    // Final shutdown
    if let Some(conn) = reconnectable.connection() {
        info!("Shutting down connection...");
        let _ = conn.shutdown().await;
    }

    Ok(())
}
