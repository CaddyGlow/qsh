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
use qsh_client::{
    BootstrapMode, ChannelConnection, Cli, ConnectionConfig, EscapeCommand, EscapeHandler,
    EscapeResult, RawModeGuard, SshConfig, StdinReader, StdoutWriter, TerminalChannel, bootstrap,
    connect_quic, get_terminal_size, parse_escape_key, restore_terminal,
};

#[cfg(feature = "standalone")]
use qsh_client::standalone::authenticate as standalone_authenticate;
#[cfg(feature = "standalone")]
use qsh_client::{DirectAuthenticator, DirectConfig};

use qsh_core::protocol::{StateDiff, TermSize};

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

fn extract_generation(diff: &StateDiff) -> Option<u64> {
    match diff {
        StateDiff::Full(state) => Some(state.generation),
        StateDiff::Incremental { to_gen, .. } => Some(*to_gen),
        StateDiff::CursorOnly { generation, .. } => Some(*generation),
    }
}

/// Extract cursor position from a state diff.
fn extract_cursor(diff: &StateDiff) -> Option<(u16, u16)> {
    match diff {
        StateDiff::Full(state) => Some((state.cursor.col, state.cursor.row)),
        StateDiff::Incremental { cursor, .. } => cursor.as_ref().map(|c| (c.col, c.row)),
        StateDiff::CursorOnly { cursor, .. } => Some((cursor.col, cursor.row)),
    }
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
    let conn = ChannelConnection::from_quic(quic_conn, conn_config).await?;
    info!(rtt = ?conn.rtt(), session_id = ?conn.session_id(), "Connected to server");

    // Open a terminal channel
    let term_size = get_term_size();
    let terminal_params = qsh_core::protocol::TerminalParams {
        term_size,
        term_type: std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string()),
        env: collect_terminal_env(),
        shell: cli.command_string(),
        last_generation: 0,
        last_input_seq: 0,
    };

    let terminal = conn.open_terminal(terminal_params).await?;
    info!(channel_id = ?terminal.channel_id(), "Terminal channel opened");

    let user_host = format_user_host(user, host);
    run_channel_session(conn, terminal, cli, Some(user_host)).await
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
    };

    // Connect using the channel model (no implicit terminal)
    let conn = ChannelConnection::connect(config).await?;
    info!(
        rtt = ?conn.rtt(),
        session_id = ?conn.session_id(),
        "Channel model connection established"
    );

    // Drop the bootstrap handle now that QUIC connection is established
    drop(bootstrap_handle);

    // Open a terminal channel
    let term_size = get_term_size();
    let terminal_params = qsh_core::protocol::TerminalParams {
        term_size,
        term_type: std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string()),
        env: collect_terminal_env(),
        shell: cli.command_string(),
        last_generation: 0,
        last_input_seq: 0,
    };

    let terminal = conn.open_terminal(terminal_params).await?;
    info!(channel_id = ?terminal.channel_id(), "Terminal channel opened");

    // Run the channel session
    let user_host = format_user_host(user, host);
    run_channel_session(conn, terminal, cli, Some(user_host)).await
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
    if overlay.is_visible() {
        let term_size = get_term_size();
        let overlay_output = overlay.render(term_size.cols);
        if !overlay_output.is_empty() {
            let _ = stdout.write(overlay_output.as_bytes()).await;
        }
    }
}

/// Clear overlay line from terminal (best-effort).
async fn clear_overlay(stdout: &mut StdoutWriter, _position: OverlayPosition) {
    // Overlays draw on first row today; clear that row to hide artifacts.
    let _ = stdout.write(b"\x1b[s\x1b[1;1H\x1b[2K\x1b[u").await;
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

/// Run a terminal session using the channel model (experimental).
///
/// This is a simplified version of run_session that works with TerminalChannel
/// instead of ClientConnection.
async fn run_channel_session(
    conn: ChannelConnection,
    terminal: TerminalChannel,
    cli: &Cli,
    user_host: Option<String>,
) -> qsh_core::Result<()> {
    info!(
        caps = ?conn.server_capabilities(),
        "Server capabilities"
    );

    // Create status overlay
    let mut overlay = create_status_overlay(cli, user_host);
    overlay.set_status(ConnectionStatus::Connected);

    // Initialize RTT from connection
    overlay.metrics_mut().update_rtt(conn.rtt());
    overlay.metrics_mut().record_heard();

    // Overlay refresh interval
    let mut overlay_refresh = tokio::time::interval(Duration::from_secs(2));
    overlay_refresh.set_missed_tick_behavior(MissedTickBehavior::Delay);

    // Parse toggle key
    let toggle_key = parse_toggle_key(&cli.overlay_key);

    // Parse escape key and create handler
    let escape_key = parse_escape_key(&cli.escape_key);
    let mut escape_handler = EscapeHandler::new(escape_key);

    // Enter raw terminal mode
    let _raw_guard = match RawModeGuard::enter() {
        Ok(guard) => guard,
        Err(e) => {
            warn!(error = %e, "Failed to enter raw mode");
            return Err(e.into());
        }
    };

    debug!("Entered raw terminal mode (channel model)");

    // Create stdin/stdout handlers
    let mut stdin = StdinReader::new();
    let mut stdout = StdoutWriter::new();

    // Set up SIGWINCH signal handler
    #[cfg(unix)]
    let mut sigwinch =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
            .map_err(qsh_core::Error::Io)?;

    // Main session loop
    loop {
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
                        break;
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
                        break;
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
                        // Queue the input
                        if let Err(e) = terminal.queue_input(&pass_data, false) {
                            warn!(error = %e, "Failed to queue input");
                            break;
                        }
                    }
                }
            }

            // Handle terminal output
            result = terminal.recv_output() => {
                match result {
                    Ok(output) => {
                        overlay.metrics_mut().record_heard();

                        // Output the data
                        if let Err(e) = stdout.write(&output.data).await {
                            warn!(error = %e, "stdout write error");
                            break;
                        }

                        // Render status overlay
                        render_overlay_if_visible(&overlay, &mut stdout).await;
                    }
                    Err(qsh_core::Error::ConnectionClosed) => {
                        info!("Channel closed");
                        break;
                    }
                    Err(e) => {
                        warn!(error = %e, "recv_output error");
                        break;
                    }
                }
            }

            // Overlay refresh
            _ = overlay_refresh.tick() => {
                overlay.metrics_mut().update_rtt(conn.rtt());
                render_overlay_if_visible(&overlay, &mut stdout).await;
            }
        }
    }

    // Restore terminal
    restore_terminal();

    // Close the terminal channel
    terminal.mark_closed();

    // Close the connection
    info!("Shutting down channel model connection...");
    conn.close().await?;

    Ok(())
}
