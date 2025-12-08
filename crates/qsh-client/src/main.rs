//! qsh client binary entry point.
//!
//! Modern roaming-capable remote terminal client.

use std::net::ToSocketAddrs;
use std::time::Duration;

use clap::Parser;
use tokio::time::MissedTickBehavior;
use tracing::{debug, error, info, warn};

use qsh_client::cli::{
    NotificationStyle as CliNotificationStyle, OverlayPosition as CliOverlayPosition,
    SshBootstrapMode,
};
use qsh_client::overlay::{
    ConnectionStatus, NotificationEngine, NotificationStyle, OverlayPosition, PredictionOverlay,
    StatusOverlay,
};
use qsh_client::prediction::{DisplayPreference, Prediction};
use qsh_client::render::StateRenderer;
use qsh_core::terminal::TerminalParser;
use qsh_client::{
    BootstrapMode, ChannelConnection, Cli, ConnectionConfig, ConnectionState, EscapeCommand,
    EscapeHandler, EscapeResult, ForwarderHandle, LocalForwarder, ProxyHandle, RawModeGuard,
    ReconnectableConnection, RemoteForwarder, RemoteForwarderHandle, SessionContext, Socks5Proxy,
    SshConfig, StdinReader, StdoutWriter, TerminalSessionState, bootstrap, get_terminal_size,
    parse_dynamic_forward, parse_escape_key, parse_local_forward, parse_remote_forward,
    restore_terminal,
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
    info!(rtt = ?conn.rtt().await, session_id = ?conn.session_id(), "Connected to server");

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
        rtt = ?conn.rtt().await,
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

/// Render the mosh-style notification bar.
///
/// This auto-shows when the connection is stale (>6.5s without server contact).
async fn render_notification(notification: &NotificationEngine, stdout: &mut StdoutWriter) {
    let term_size = get_term_size();
    let bar_output = notification.render(term_size.cols);
    if !bar_output.is_empty() {
        let _ = stdout.write(bar_output.as_bytes()).await;
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

/// Convert CLI notification style to overlay module style.
fn map_notification_style(cli_style: CliNotificationStyle) -> NotificationStyle {
    match cli_style {
        CliNotificationStyle::Minimal => NotificationStyle::Minimal,
        CliNotificationStyle::Enhanced => NotificationStyle::Enhanced,
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

/// Create and configure mosh-style notification engine from CLI options.
fn create_notification_engine(cli: &Cli, user_host: Option<String>) -> NotificationEngine {
    let mut notification = NotificationEngine::new();

    // Set escape key for quit hint
    notification.set_escape_key(&cli.escape_key);

    // Set display style
    notification.set_style(map_notification_style(cli.notification_style));

    // Set user@host for enhanced display
    if let Some(uh) = user_host {
        notification.set_user_host(uh);
    }

    notification
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

    // Create status overlay (legacy, for --status flag)
    let mut overlay = create_status_overlay(cli, user_host.clone());

    // Create mosh-style notification engine (auto-shows on connection issues)
    let mut notification = create_notification_engine(cli, user_host);

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

    // Track current reconnect error for notification updates
    let mut reconnect_error: Option<String> = None;

    // Create stdin/stdout handlers
    let mut stdin = StdinReader::new();
    let mut stdout = StdoutWriter::new();

    // Prediction settings
    let prediction_mode = cli.effective_prediction_mode();
    let prediction_enabled = prediction_mode != qsh_client::cli::PredictionMode::Off && is_interactive;

    // Mosh-style state tracking
    // StateRenderer maintains local framebuffer for differential rendering
    let mut renderer = StateRenderer::new();
    // PredictionOverlay for displaying predicted characters
    let mut prediction_overlay = PredictionOverlay::new();
    // Client-side terminal state (tracks what we think server looks like)
    // Initialized inside loop when terminal is opened and we know the size
    #[allow(unused_assignments)]
    let mut client_parser: Option<TerminalParser> = None;

    // Reconnection loop
    loop {
        // Wait for connection to be available, with periodic refresh of notification bar
        overlay.set_status(match reconnectable.state() {
            ConnectionState::Connected => ConnectionStatus::Connected,
            ConnectionState::Reconnecting => ConnectionStatus::Reconnecting,
            ConnectionState::Disconnected => ConnectionStatus::Disconnected,
        });
        render_overlay_if_visible(&overlay, &mut stdout).await;
        render_notification(&notification, &mut stdout).await;

        // Use select to allow refreshing notification while waiting for reconnection
        // Pin the future so we don't lose progress on each select iteration
        let wait_future = reconnectable.wait_connected();
        tokio::pin!(wait_future);

        let conn = loop {
            tokio::select! {
                result = &mut wait_future => {
                    match result {
                        Ok(conn) => break conn,
                        Err(e) => {
                            error!(error = %e, "Connection permanently lost");
                            overlay.set_status(ConnectionStatus::Disconnected);
                            render_overlay_if_visible(&overlay, &mut stdout).await;
                            return Err(e);
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(1)) => {
                    // Update reconnecting notification with current duration
                    if let Some(ref error) = reconnect_error {
                        notification.update_reconnecting(error);
                        render_notification(&notification, &mut stdout).await;
                    }
                }
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
        let initial_rtt = conn.rtt().await;
        overlay.metrics_mut().update_rtt(initial_rtt);
        overlay.metrics_mut().record_heard();

        // Update notification engine for connected state
        notification.server_heard(std::time::Instant::now());
        notification.server_acked(std::time::Instant::now());
        notification.update_rtt(initial_rtt);
        notification.clear_network_error();

        // Clear reconnect error tracking
        reconnect_error = None;

        // Initialize/reset client-side terminal state tracking
        client_parser = Some(TerminalParser::new(term_size.cols, term_size.rows));
        prediction_overlay.clear_all();
        renderer.invalidate();

        // Frame rate tracking (for info display)
        let mut frame_count: u64 = 0;
        let frame_rate_start = std::time::Instant::now();

        // Initialize prediction engine with current RTT and cursor
        if prediction_enabled {
            let mut prediction = terminal.prediction_mut().await;
            prediction.update_rtt(initial_rtt);

            // Set display preference based on prediction mode
            let display_pref = match prediction_mode {
                qsh_client::cli::PredictionMode::Adaptive => DisplayPreference::Adaptive,
                qsh_client::cli::PredictionMode::Always => DisplayPreference::Always,
                qsh_client::cli::PredictionMode::Experimental => DisplayPreference::Experimental,
                qsh_client::cli::PredictionMode::Off => DisplayPreference::Never, // Should not reach
            };
            prediction.set_display_preference(display_pref);

            // Initialize cursor position from terminal state (start at 0,0 for new sessions)
            prediction.init_cursor(0, 0);
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
                            notification.clear_message(); // Clear info bar
                            break Ok(());
                        }
                        EscapeResult::Command(EscapeCommand::ToggleOverlay) => {
                            notification.clear_message(); // Clear info bar
                            let visible = overlay.is_visible();
                            overlay.set_visible(!visible);
                            render_overlay_if_visible(&overlay, &mut stdout).await;
                            continue;
                        }
                        EscapeResult::Command(EscapeCommand::SendEscapeKey) => {
                            notification.clear_message(); // Clear info bar
                            // Send the escape character itself
                            let _ = terminal.queue_input(&[escape_key.unwrap_or(0x1e)], false);
                            continue;
                        }
                        EscapeResult::Waiting => {
                            // Waiting for command key - show connection info (like mosh)
                            // Calculate frame rate
                            let elapsed = frame_rate_start.elapsed().as_secs_f64();
                            let fps = if elapsed > 0.0 {
                                Some(frame_count as f64 / elapsed)
                            } else {
                                None
                            };
                            // Show as permanent while waiting (will be cleared on command/timeout)
                            notification.show_info(fps, true);
                            render_notification(&notification, &mut stdout).await;
                            continue;
                        }
                        EscapeResult::PassThrough(pass_data) => {
                            // Clear info bar (escape sequence resolved or timed out)
                            notification.clear_message();

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

                            // If prediction enabled, process input with mosh-style tracking
                            if prediction_enabled {
                                let mut prediction = terminal.prediction_mut().await;

                                // Get current cursor position (from client parser or predicted)
                                let cursor = if let Some(pred_cursor) = prediction.get_predicted_cursor() {
                                    pred_cursor
                                } else if let Some(ref parser) = client_parser {
                                    let state = parser.state();
                                    (state.cursor.col, state.cursor.row)
                                } else {
                                    (0, 0)
                                };

                                // Only render if prediction engine says we should display
                                if prediction.should_display() {
                                    // Process each byte with position tracking
                                    for &byte in &pass_data {
                                        if let Some(echo) = prediction.new_user_byte(byte, cursor, term_size.cols, seq) {
                                            // Add to overlay for position-based rendering
                                            let pred_cursor = prediction.get_predicted_cursor().unwrap_or(cursor);
                                            // The cursor after new_user_byte points to the next position,
                                            // so the character was placed at pred_cursor - 1 (wrapping handled)
                                            let char_col = if pred_cursor.0 == 0 && pred_cursor.1 > cursor.1 {
                                                // Wrapped to next line, char was at end of previous line
                                                term_size.cols.saturating_sub(1)
                                            } else {
                                                pred_cursor.0.saturating_sub(1)
                                            };
                                            let char_row = if pred_cursor.0 == 0 && pred_cursor.1 > cursor.1 {
                                                pred_cursor.1.saturating_sub(1)
                                            } else {
                                                pred_cursor.1
                                            };

                                            // Render prediction at position using position-based overlay
                                            let pred = Prediction {
                                                sequence: echo.sequence,
                                                char: echo.char,
                                                col: char_col,
                                                row: char_row,
                                                timestamp: std::time::Instant::now(),
                                            };
                                            prediction_overlay.add(&pred, echo.style);
                                        }
                                    }

                                    // Render the prediction overlay
                                    let overlay_output = prediction_overlay.render();
                                    if !overlay_output.is_empty() {
                                        let _ = stdout.write(overlay_output.as_bytes()).await;
                                    }
                                } else {
                                    // Still process bytes for cursor tracking even if not displaying
                                    for &byte in &pass_data {
                                        let _ = prediction.new_user_byte(byte, cursor, term_size.cols, seq);
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

                            // Update notification engine (mosh-style)
                            let now = std::time::Instant::now();
                            notification.server_heard(now);
                            notification.server_acked(now);
                            notification.adjust_message();

                            // Track frame rate
                            frame_count += 1;

                            // Track confirmed input seq for recovery
                            terminal_state.last_input_seq = output.confirmed_input_seq;

                            // Update client-side terminal state
                            if let Some(ref mut parser) = client_parser {
                                parser.process(&output.data);
                            }

                            // Validate and confirm predictions
                            if prediction_enabled {
                                let mut prediction = terminal.prediction_mut().await;

                                // Validate predictions against client state
                                if let Some(ref parser) = client_parser {
                                    let client_state = parser.state();
                                    prediction.validate(client_state);
                                    // Update predicted cursor to match server
                                    prediction.init_cursor(
                                        client_state.cursor.col,
                                        client_state.cursor.row
                                    );
                                }

                                // Confirm predictions up to this sequence
                                prediction.confirm(output.confirmed_input_seq);
                                prediction.confirm_cells(output.confirmed_input_seq);

                                // Clear confirmed predictions from overlay
                                prediction_overlay.clear_confirmed(output.confirmed_input_seq);
                            }

                            // Output the data (server output is authoritative)
                            if let Err(e) = stdout.write(&output.data).await {
                                warn!(error = %e, "stdout write error");
                                break Err(e.into());
                            }

                            // Render status overlay (legacy) and notification bar (mosh-style)
                            render_overlay_if_visible(&overlay, &mut stdout).await;
                            render_notification(&notification, &mut stdout).await;
                        }
                        Ok(qsh_client::TerminalEvent::StateSync(update)) => {
                            overlay.metrics_mut().record_heard();

                            // Update notification engine (mosh-style)
                            let now = std::time::Instant::now();
                            notification.server_heard(now);
                            notification.server_acked(now);
                            notification.adjust_message();

                            // Track confirmed input seq
                            terminal_state.last_input_seq = update.confirmed_input_seq;

                            // Reset prediction engine on full state sync
                            if prediction_enabled {
                                let mut prediction = terminal.prediction_mut().await;
                                prediction.reset();
                                prediction_overlay.clear_all();
                            }

                            // Render the full state to the terminal (mosh-style resync)
                            if let qsh_core::terminal::StateDiff::Full(ref state) = update.diff {
                                info!("Received state sync after reconnection");

                                // Update client parser to match server state
                                if let Some(ref mut parser) = client_parser {
                                    *parser = TerminalParser::new(
                                        state.screen().cols(),
                                        state.screen().rows()
                                    );
                                }

                                // Update predicted cursor from synced state
                                if prediction_enabled {
                                    let mut prediction = terminal.prediction_mut().await;
                                    prediction.init_cursor(state.cursor.col, state.cursor.row);
                                }

                                let ansi_data = state.render_to_ansi();
                                if let Err(e) = stdout.write(&ansi_data).await {
                                    warn!(error = %e, "stdout write error during state sync");
                                    break Err(e.into());
                                }
                            }

                            // Render status overlay (legacy) and notification bar (mosh-style)
                            render_overlay_if_visible(&overlay, &mut stdout).await;
                            render_notification(&notification, &mut stdout).await;
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
                    if let Some(rtt) = reconnectable.rtt().await {
                        overlay.metrics_mut().update_rtt(rtt);
                        notification.update_rtt(rtt);

                        // Update prediction engine RTT for adaptive display
                        if prediction_enabled {
                            let mut prediction = terminal.prediction_mut().await;
                            prediction.update_rtt(rtt);
                            prediction.check_glitches();
                        }
                    }

                    // Update notification engine (expire messages, etc.)
                    notification.adjust_message();

                    // If reconnecting, update the duration in the notification
                    if let Some(ref error) = reconnect_error {
                        notification.update_reconnecting(error);
                    }

                    // If escape handler is waiting, refresh the info bar with current stats
                    if escape_handler.is_waiting() {
                        let elapsed = frame_rate_start.elapsed().as_secs_f64();
                        let fps = if elapsed > 0.0 {
                            Some(frame_count as f64 / elapsed)
                        } else {
                            None
                        };
                        // Keep permanent while waiting
                        notification.show_info(fps, true);
                    }

                    // Render overlays
                    render_overlay_if_visible(&overlay, &mut stdout).await;
                    render_notification(&notification, &mut stdout).await;
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

                // Store error and set reconnecting notification with duration
                let error_msg = format!("{}", e);
                reconnect_error = Some(error_msg.clone());
                notification.set_reconnecting(&error_msg);

                render_overlay_if_visible(&overlay, &mut stdout).await;
                render_notification(&notification, &mut stdout).await;
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
