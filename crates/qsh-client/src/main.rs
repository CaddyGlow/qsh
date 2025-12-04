//! qsh client binary entry point.
//!
//! Modern roaming-capable remote terminal client.

use std::net::ToSocketAddrs;
use std::sync::Arc;

use clap::Parser;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tracing::{debug, error, info, warn};

use qsh_client::cli::{OverlayPosition as CliOverlayPosition, SshBootstrapMode};
use qsh_client::overlay::{ConnectionStatus, OverlayPosition, PredictionOverlay, StatusOverlay};
use qsh_client::render::StateRenderer;
use qsh_client::{
    BootstrapMode, Cli, ClientConnection, ConnectionConfig, EscapeCommand, EscapeHandler,
    EscapeResult, LocalForwarder, RawModeGuard, Socks5Proxy, SshConfig, StdinReader, StdoutWriter,
    bootstrap, get_terminal_size, parse_escape_key, restore_terminal,
};
use qsh_core::constants::DEFAULT_QUIC_PORT_RANGE;
use qsh_core::forward::ForwardSpec;
use qsh_core::protocol::{Message, StateDiff, TermSize};
use qsh_core::terminal::TerminalState;
use qsh_core::transport::QuicConnection;

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

async fn run_client(cli: &Cli, host: &str, user: Option<&str>) -> qsh_core::Result<()> {
    // Step 1: Bootstrap via SSH to get QUIC endpoint info
    info!("Bootstrapping via SSH...");

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
    // We need to hold onto it until after QUIC connection is established
    let bootstrap_handle = match bootstrap(host, cli.port, user, &ssh_config).await {
        Ok(handle) => Some(handle),
        Err(e) => {
            // For now, fall back to direct QUIC connection attempt
            warn!(error = %e, "SSH bootstrap failed, attempting direct QUIC connection");

            // Try to resolve the address directly
            let (default_port, _) = cli.bootstrap_port_range.unwrap_or(DEFAULT_QUIC_PORT_RANGE);
            let quic_port = default_port;
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
                env: collect_terminal_env(),
                predictive_echo: !cli.no_prediction,
                connect_timeout: cli.connect_timeout(),
                zero_rtt_available: false,
                keep_alive_interval: cli.keep_alive_interval(),
                max_idle_timeout: cli.max_idle_timeout(),
            };

            // Try to connect
            let conn = ClientConnection::connect(config).await?;
            info!(rtt = ?conn.rtt(), "Connected to server");

            // Run the session
            let user_host = format_user_host(user, host);
            run_session(conn, cli, Some(user_host)).await?;
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

    let conn = ClientConnection::connect(ConnectionConfig {
        server_addr: addr,
        session_key,
        cert_hash,
        term_size: get_term_size(),
        term_type: std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string()),
        env: collect_terminal_env(),
        predictive_echo: !cli.no_prediction,
        connect_timeout: cli.connect_timeout(),
        zero_rtt_available: false, // updated after HelloAck inside connect
        keep_alive_interval: cli.keep_alive_interval(),
        max_idle_timeout: cli.max_idle_timeout(),
    })
    .await?;
    info!(rtt = ?conn.rtt(), "Connected to server");

    // Drop the bootstrap handle now that QUIC connection is established
    // This will terminate the SSH process / russh session
    drop(bootstrap_handle);

    let user_host = format_user_host(user, host);
    run_session(conn, cli, Some(user_host)).await
}

async fn run_session(
    mut conn: ClientConnection,
    cli: &Cli,
    user_host: Option<String>,
) -> qsh_core::Result<()> {
    info!(
        predictive_echo = conn.server_capabilities().predictive_echo,
        compression = conn.server_capabilities().compression,
        max_forwards = conn.server_capabilities().max_forwards,
        "Server capabilities"
    );

    // Create status overlay
    let mut overlay = create_status_overlay(cli, user_host);
    overlay.set_status(ConnectionStatus::Connected);

    // Create prediction overlay for local echo display
    let mut pred_overlay = PredictionOverlay::new();

    // Client-side terminal state (for mosh-style state-based rendering)
    // Use initial state from server if available, otherwise create empty
    let term_size = get_terminal_size().unwrap_or(TermSize { cols: 80, rows: 24 });
    let mut local_state = conn
        .take_initial_state()
        .unwrap_or_else(|| TerminalState::new(term_size.cols, term_size.rows));
    let mut renderer = StateRenderer::new();
    // Don't enable state rendering until we've received at least one StateUpdate
    // This ensures local_state is synchronized with what's actually on screen
    let mut use_state_rendering = false;
    let state_rendering_available = conn.server_capabilities().predictive_echo;

    // Initialize RTT and packet loss from connection
    overlay.metrics_mut().update_rtt(conn.rtt());
    overlay.metrics_mut().update_packet_loss(conn.packet_loss());

    // Overlay refresh interval (2 seconds) - also updates metrics from QUIC
    let mut overlay_refresh = tokio::time::interval(Duration::from_secs(2));
    overlay_refresh.set_missed_tick_behavior(MissedTickBehavior::Delay);

    // Initialize last_heard to now
    overlay.metrics_mut().record_heard();

    // Parse toggle key (default ctrl+shift+o, parsed as ctrl+o = 0x0f)
    let toggle_key = parse_toggle_key(&cli.overlay_key);

    // Parse escape key and create handler (default ctrl+^, like mosh)
    let escape_key = parse_escape_key(&cli.escape_key);
    let mut escape_handler = EscapeHandler::new(escape_key);

    // Start port forwarders
    let mut forward_handles = spawn_forwarders(cli, conn.quic_connection()).await;

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
            biased;

            // Handle stdin -> server
            input = stdin.read() => {
                match input {
                    Some(data) if !data.is_empty() => {
                        // Process through escape handler first (mosh-style ctrl+^ sequences)
                        let data = match escape_handler.process(&data) {
                            EscapeResult::Waiting => {
                                // Escape key pressed, waiting for command
                                continue;
                            }
                            EscapeResult::Command(EscapeCommand::Disconnect) => {
                                info!("Disconnect requested via escape sequence");
                                break;
                            }
                            EscapeResult::Command(EscapeCommand::ToggleOverlay) => {
                                overlay.toggle();
                                if overlay.is_visible() {
                                    let term_size = get_term_size();
                                    let overlay_output = overlay.render(term_size.cols);
                                    if !overlay_output.is_empty() {
                                        let _ = stdout.write(overlay_output.as_bytes()).await;
                                    }
                                } else {
                                    clear_overlay(&mut stdout, overlay.position()).await;
                                }
                                continue;
                            }
                            EscapeResult::Command(EscapeCommand::SendEscapeKey) => {
                                // User pressed escape twice, send the escape key
                                if let Some(key) = escape_handler.escape_key() {
                                    vec![key]
                                } else {
                                    continue;
                                }
                            }
                            EscapeResult::PassThrough(data) => data,
                        };

                        if data.is_empty() {
                            continue;
                        }

                        // Check for overlay toggle key
                                if let Some(key) = toggle_key {
                                    if data.len() == 1 && data[0] == key {
                                        overlay.toggle();
                                        // Re-render overlay after toggle
                                        if overlay.is_visible() {
                                            let term_size = get_term_size();
                                            let overlay_output = overlay.render(term_size.cols);
                                            if !overlay_output.is_empty() {
                                        let _ = stdout.write(overlay_output.as_bytes()).await;
                                    }
                                } else {
                                    clear_overlay(&mut stdout, overlay.position()).await;
                                }
                                continue;
                            }
                        }

                        debug!(len = data.len(), "Sending input to server");
                        // Queue the send without waiting - don't block on network I/O
                        match conn.queue_input(&data) {
                            Ok(seq) => {
                                // Only predict after we've synced state from server
                                // (cursor position in initial_state may be stale)
                                if use_state_rendering && conn.server_capabilities().predictive_echo {
                                    let mut made_predictions = false;
                                    for &byte in &data {
                                        let c = byte as char;
                                        let (col, row) = conn.cursor();
                                        if let Some(echo) = conn.prediction_mut().predict(c, col, row, seq) {
                                            // Only add to overlay if we should display predictions
                                            // (mosh-style adaptive: only when RTT > 30ms)
                                            if conn.prediction().should_display() {
                                                if let Some(pred) = conn.prediction().pending().back() {
                                                    pred_overlay.add(pred, echo.style);
                                                }
                                                made_predictions = true;
                                            }
                                            conn.advance_cursor();
                                        }
                                    }
                                    // Re-render with predictions composited (mosh-style local echo)
                                    if made_predictions {
                                        let rendered = renderer.render(&local_state, &pred_overlay);
                                        if !rendered.is_empty() {
                                            let _ = stdout.write(rendered.as_bytes()).await;
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                debug!(error = %e, "Failed to queue input");
                                attempt_reconnect(&mut conn, cli, &mut overlay, &mut stdout, &mut forward_handles).await?;
                                continue;
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

            // Handle server -> stdout/control (terminal preferred)
            msg = conn.recv_any() => {
                match msg {
                    Ok(Message::StateUpdate(update)) => {
                        // Record that we heard from the server (for stale detection)
                        overlay.metrics_mut().record_heard();
                        if let Some(latency) = conn.record_confirmation(update.confirmed_input_seq) {
                            debug!(
                                latency_ms = latency.as_secs_f64() * 1000.0,
                                seq = update.confirmed_input_seq,
                                "Input latency"
                            );
                            overlay.metrics_mut().update_rtt(latency);
                            // Update prediction engine RTT for adaptive display
                            conn.prediction_mut().update_rtt(latency);
                        }

                        // Update cursor from state diff
                        if let Some((col, row)) = extract_cursor(&update.diff) {
                            conn.set_cursor(col, row);
                        }

                        // Handle prediction confirmation/reset based on diff type
                        match &update.diff {
                            StateDiff::Full(_) => {
                                // Full state sync - reset prediction engine and overlay
                                conn.prediction_mut().reset();
                                pred_overlay.clear_all();
                                renderer.invalidate(); // Force full redraw
                                debug!("Prediction engine reset on full state sync");
                            }
                            StateDiff::Incremental { changes, .. } => {
                                // Check for mispredictions by comparing cell changes to predictions
                                let mut mispredicted = false;
                                for change in changes {
                                    for pred in pred_overlay.iter() {
                                        if pred.col == change.col && pred.row == change.row
                                            && pred.char != change.cell.ch
                                        {
                                            debug!(
                                                col = change.col, row = change.row,
                                                predicted = %pred.char, actual = %change.cell.ch,
                                                "Misprediction detected"
                                            );
                                            mispredicted = true;
                                            break;
                                        }
                                    }
                                    if mispredicted { break; }
                                }

                                if mispredicted {
                                    conn.prediction_mut().misprediction();
                                    pred_overlay.clear_all();
                                } else {
                                    conn.prediction_mut().confirm(update.confirmed_input_seq);
                                    pred_overlay.clear_confirmed(update.confirmed_input_seq);
                                }
                            }
                            StateDiff::CursorOnly { .. } => {
                                // Cursor-only change, just confirm predictions
                                conn.prediction_mut().confirm(update.confirmed_input_seq);
                                pred_overlay.clear_confirmed(update.confirmed_input_seq);
                            }
                        }

                        // Apply diff to local terminal state for tracking only
                        // (raw output is already sent via TerminalOutput, so don't render here)
                        if state_rendering_available && !use_state_rendering {
                            use_state_rendering = true;
                            debug!("State tracking enabled");
                        }

                        if use_state_rendering {
                            match local_state.apply_diff(&update.diff) {
                                Ok(new_state) => {
                                    local_state = new_state;
                                    // Don't render - raw output already displayed via TerminalOutput
                                    // State is tracked for reconnection and prediction only
                                }
                                Err(e) => {
                                    debug!(error = %e, "Failed to apply diff");
                                    use_state_rendering = false;
                                    renderer.invalidate();
                                }
                            }
                        }

                        if let Some(r#gen) = extract_generation(&update.diff) {
                            conn.record_generation(r#gen);
                        }
                    }
                    Ok(Message::TerminalOutput(output)) => {
                        overlay.metrics_mut().record_heard();
                        if let Some(latency) = conn.record_confirmation(output.confirmed_input_seq) {
                            debug!(
                                latency_ms = latency.as_secs_f64() * 1000.0,
                                seq = output.confirmed_input_seq,
                                "Input latency"
                            );
                            overlay.metrics_mut().update_rtt(latency);
                        }

                        // Confirm predictions for this input sequence
                        conn.prediction_mut().confirm(output.confirmed_input_seq);
                        pred_overlay.clear_confirmed(output.confirmed_input_seq);

                        if let Err(e) = stdout.write(&output.data).await {
                            debug!(error = %e, "Failed to write output");
                            break;
                        }

                        if overlay.is_visible() {
                            let term_size = get_term_size();
                            let overlay_output = overlay.render(term_size.cols);
                            if !overlay_output.is_empty() {
                                let _ = stdout.write(overlay_output.as_bytes()).await;
                            }
                        }
                    }
                    Ok(Message::Shutdown(shutdown)) => {
                        overlay.metrics_mut().record_heard();
                        info!(reason = ?shutdown.reason, msg = ?shutdown.message, "Server initiated shutdown");
                        if let Some(msg) = &shutdown.message {
                            eprintln!("\r\n{}", msg);
                        }
                        break;
                    }
                    Ok(other) => {
                        overlay.metrics_mut().record_heard();
                        debug!(msg = ?other, "Unexpected message");
                    }
                    Err(qsh_core::Error::ConnectionClosed) => {
                        info!("Stream closed by server, attempting reconnect");
                        attempt_reconnect(&mut conn, cli, &mut overlay, &mut stdout, &mut forward_handles).await?;
                        continue;
                    }
                    Err(e) => {
                        // Use debug instead of error to avoid breaking raw terminal output
                        // The overlay already shows the error state to the user
                        debug!(error = %e, "Error receiving from server");
                        if should_attempt_reconnect(&e) {
                            attempt_reconnect(&mut conn, cli, &mut overlay, &mut stdout, &mut forward_handles).await?;
                            continue;
                        } else {
                            break;
                        }
                    }
                }
            }

            // Periodic overlay refresh (update RTT/loss display)
            _ = overlay_refresh.tick() => {
                if overlay.is_visible() {
                    // Refresh metrics from connection
                    overlay.metrics_mut().update_rtt(conn.rtt());
                    overlay.metrics_mut().update_packet_loss(conn.packet_loss());
                    render_overlay_if_visible(&overlay, &mut stdout).await;
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

async fn attempt_reconnect(
    conn: &mut ClientConnection,
    cli: &Cli,
    overlay: &mut StatusOverlay,
    stdout: &mut StdoutWriter,
    forward_handles: &mut Vec<JoinHandle<()>>,
) -> qsh_core::Result<()> {
    // Stop existing forwarders; they'll be recreated after reconnect.
    for handle in forward_handles.drain(..) {
        handle.abort();
    }

    let overlay_was_visible = overlay.is_visible();
    overlay.set_visible(true);
    overlay.set_status(ConnectionStatus::Reconnecting);
    render_overlay_if_visible(overlay, stdout).await;

    // Reset backoff window relative to this loss event.
    conn.reset_reconnect_backoff();

    // Reconnect loop with overlay updates
    loop {
        if !conn.should_retry_reconnect() {
            overlay.set_status(ConnectionStatus::Disconnected);
            overlay.set_message(Some("reconnect attempts exhausted".to_string()));
            render_overlay_if_visible(overlay, stdout).await;
            return Err(qsh_core::Error::Transport {
                message: "reconnection attempts exhausted".to_string(),
            });
        }

        let delay = conn.next_reconnect_delay();
        let attempt = conn.reconnect_attempt();

        // Update overlay with attempt info
        overlay.set_message(Some(format!(
            "attempt {} (waiting {}ms)...",
            attempt,
            delay.as_millis()
        )));
        render_overlay_if_visible(overlay, stdout).await;

        info!(
            attempt,
            delay_ms = delay.as_millis(),
            "Attempting reconnection after transport loss"
        );

        tokio::time::sleep(delay).await;

        match conn.reconnect().await {
            Ok(()) => {
                // Reset reconnect state for next time
                conn.reset_reconnect_backoff();
                break;
            }
            Err(qsh_core::Error::AuthenticationFailed) => {
                overlay.set_status(ConnectionStatus::Disconnected);
                overlay.set_message(Some("authentication failed".to_string()));
                render_overlay_if_visible(overlay, stdout).await;
                return Err(qsh_core::Error::AuthenticationFailed);
            }
            Err(qsh_core::Error::SessionExpired) => {
                overlay.set_status(ConnectionStatus::Disconnected);
                overlay.set_message(Some("session expired".to_string()));
                render_overlay_if_visible(overlay, stdout).await;
                return Err(qsh_core::Error::SessionExpired);
            }
            Err(e) => {
                warn!(error = %e, attempt, "Reconnect attempt failed");
                // Continue to next attempt
            }
        }
    }

    // Record successful reconnection
    overlay.metrics_mut().record_heard(); // Reset last_heard timer
    overlay.metrics_mut().record_reconnect();
    overlay.metrics_mut().update_rtt(conn.rtt());
    overlay.metrics_mut().update_packet_loss(conn.packet_loss());
    overlay.set_status(ConnectionStatus::Connected);
    overlay.clear_message();
    if !overlay_was_visible {
        overlay.set_visible(false);
        clear_overlay(stdout, overlay.position()).await;
    }

    *forward_handles = spawn_forwarders(cli, conn.quic_connection()).await;
    render_overlay_if_visible(overlay, stdout).await;

    Ok(())
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

fn should_attempt_reconnect(err: &qsh_core::Error) -> bool {
    matches!(
        err,
        qsh_core::Error::Transport { .. }
            | qsh_core::Error::ConnectionClosed
            | qsh_core::Error::Timeout
    )
}

async fn spawn_forwarders(cli: &Cli, quic_conn: Arc<QuicConnection>) -> Vec<JoinHandle<()>> {
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

    forward_handles
}

/// Fallback session for when raw mode isn't available.
async fn run_session_cooked(
    conn: ClientConnection,
    mut forward_handles: Vec<JoinHandle<()>>,
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
