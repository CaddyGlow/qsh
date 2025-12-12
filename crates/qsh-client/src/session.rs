//! Session context for reconnection support.
//!
//! Provides abstractions for managing connection state across reconnections:
//! - `SessionContext`: Cached connection info for transparent reconnection
//! - `TerminalSessionState`: Terminal-specific state for recovery (re-exported from qsh-core)
//! - `ConnectionState`: Current connection status (re-exported from qsh-core)

use std::net::SocketAddr;

use qsh_core::protocol::SessionId;
use qsh_core::terminal::TerminalParser;
use qsh_core::transport::TransportSender;

// Re-export shared session types from qsh-core
pub use qsh_core::session::{ConnectionState, TerminalSessionState};

#[cfg(feature = "standalone")]
use crate::standalone::DirectAuthenticator;

use crate::ConnectionConfig;

/// Cached connection info for reconnection.
///
/// Populated after initial connection succeeds. Used to re-establish
/// connection without re-running bootstrap or re-authenticating.
pub struct SessionContext {
    /// Server address (from bootstrap or direct).
    pub server_addr: SocketAddr,
    /// Session key (from bootstrap or generated).
    pub session_key: [u8; 32],
    /// Certificate hash for pinning (optional).
    pub cert_hash: Option<Vec<u8>>,
    /// Connection config template.
    pub config: ConnectionConfig,
    /// Session ID from server (for resume).
    pub session_id: Option<SessionId>,
    /// For standalone mode: authenticator for re-auth.
    #[cfg(feature = "standalone")]
    pub authenticator: Option<DirectAuthenticator>,
}

impl std::fmt::Debug for SessionContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionContext")
            .field("server_addr", &self.server_addr)
            .field("session_key", &"[REDACTED]")
            .field("cert_hash", &self.cert_hash.as_ref().map(|_| "[PRESENT]"))
            .field("config", &self.config)
            .field("session_id", &self.session_id)
            .finish()
    }
}

impl SessionContext {
    /// Create a new session context from a successful connection.
    pub fn new(config: ConnectionConfig, session_id: SessionId) -> Self {
        Self {
            server_addr: config.server_addr,
            session_key: config.session_key,
            cert_hash: config.cert_hash.clone(),
            config,
            session_id: Some(session_id),
            #[cfg(feature = "standalone")]
            authenticator: None,
        }
    }

    /// Create a session context with a standalone authenticator.
    #[cfg(feature = "standalone")]
    pub fn with_authenticator(mut self, authenticator: DirectAuthenticator) -> Self {
        self.authenticator = Some(authenticator);
        self
    }

    /// Get the session ID for reconnection.
    pub fn session_id(&self) -> Option<SessionId> {
        self.session_id
    }

    /// Update the session ID after reconnection.
    pub fn set_session_id(&mut self, session_id: SessionId) {
        self.session_id = Some(session_id);
    }

    /// Get a connection config for reconnection.
    ///
    /// Returns a config with the cached server address and session key.
    pub fn reconnect_config(&self) -> ConnectionConfig {
        ConnectionConfig {
            server_addr: self.server_addr,
            session_key: self.session_key,
            cert_hash: self.cert_hash.clone(),
            ..self.config.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qsh_core::protocol::TermSize;

    fn test_config() -> ConnectionConfig {
        ConnectionConfig {
            server_addr: "127.0.0.1:4500".parse().unwrap(),
            session_key: [0xAB; 32],
            cert_hash: Some(vec![1, 2, 3]),
            term_size: TermSize { cols: 80, rows: 24 },
            term_type: "xterm".to_string(),
            env: vec![],
            predictive_echo: true,
            connect_timeout: std::time::Duration::from_secs(5),
            zero_rtt_available: false,
            keep_alive_interval: None,
            max_idle_timeout: std::time::Duration::from_secs(30),
            session_data: None,
            local_port: None,
            connect_mode: qsh_core::ConnectMode::Initiate,
        }
    }

    #[test]
    fn session_context_creation() {
        let config = test_config();
        let session_id = SessionId::from_bytes([0x42; 16]);
        let ctx = SessionContext::new(config.clone(), session_id);

        assert_eq!(ctx.server_addr, config.server_addr);
        assert_eq!(ctx.session_key, config.session_key);
        assert_eq!(ctx.session_id(), Some(session_id));
    }

    #[test]
    fn session_context_reconnect_config() {
        let config = test_config();
        let session_id = SessionId::from_bytes([0x42; 16]);
        let ctx = SessionContext::new(config.clone(), session_id);

        let reconnect = ctx.reconnect_config();
        assert_eq!(reconnect.server_addr, config.server_addr);
        assert_eq!(reconnect.session_key, config.session_key);
        assert_eq!(reconnect.cert_hash, config.cert_hash);
    }

    #[test]
    fn terminal_session_state_update() {
        let mut state = TerminalSessionState::new();
        assert_eq!(state.last_generation, 0);
        assert_eq!(state.last_input_seq, 0);

        state.update(42, 100);
        assert_eq!(state.last_generation, 42);
        assert_eq!(state.last_input_seq, 100);
    }

    #[test]
    fn connection_state_variants() {
        assert_ne!(ConnectionState::Connected, ConnectionState::Reconnecting);
        assert_ne!(ConnectionState::Reconnecting, ConnectionState::Disconnected);
    }
}

// ============================================================================
// Session Management with Composable Components
// ============================================================================
//
// Session management with composable components.
//
// This provides a unified session architecture that eliminates code duplication
// between forwarding-only mode and terminal mode by using optional components in a
// single event loop.
//
// ## Architecture
//
// - `Session`: Main session manager with unified select! loop
// - `SessionParts`: Container for optional components (terminal, forwards)
// - `TerminalComponent`: Handles terminal I/O, prediction, overlays
// - `ForwardComponent`: Handles local, remote, and SOCKS5 forwards
//
// ## Component Lifecycle
//
// 1. Construction: Components built from CLI args
// 2. `on_connect()`: Initialize on connection (or reconnection)
// 3. Event loop: Components emit events via `next_event()`
// 4. `on_disconnect()`: Cleanup on connection loss (preserving state)
// 5. `shutdown()`: Graceful cleanup on exit

use std::time::Duration;

use bytes::Bytes;

use crate::{
    ChannelConnection, Cli, HeartbeatTracker, ReconnectableConnection,
};
use qsh_core::protocol::{Message, TermSize};
use qsh_core::Result;

/// Optional components that make up a session.
#[derive(Default)]
pub struct SessionParts {
    pub terminal: Option<TerminalComponent>,
    pub forwards: Option<ForwardComponent>,
}

/// Events emitted by session components.
#[derive(Debug)]
pub enum SessionEvent {
    // Terminal events
    StdinInput(Bytes),
    TerminalOutput(TerminalOutputEvent),
    WindowResize(TermSize),
    TransportFlush,
    OverlayRefresh,
    EscapeInfo,
    InputQueued,  // Input was queued in transport sender, will flush on timer
    Exit,         // User requested exit (EOF or escape sequence)
    Error(qsh_core::Error),  // Terminal event error
}

/// Terminal-specific event wrapper.
#[derive(Debug)]
pub enum TerminalOutputEvent {
    Output(Bytes),
    StateSync(Vec<u8>),
}

/// Terminal component encapsulating all terminal I/O and state.
pub struct TerminalComponent {
    // Core terminal channel (restored or opened fresh)
    channel: Option<crate::TerminalChannel>,

    // I/O handlers
    stdin: crate::StdinReader,
    stdout: crate::StdoutWriter,

    // Prediction engine (optional, enabled for interactive mode)
    prediction_enabled: bool,
    prediction_mode: crate::cli::PredictionMode,

    // Mosh-style state tracking
    renderer: crate::render::StateRenderer,
    prediction_overlay: crate::overlay::PredictionOverlay,
    client_parser: Option<TerminalParser>,

    // Terminal state for recovery (tracks last confirmed sequence)
    terminal_state: TerminalSessionState,

    // Notification engine (mosh-style connection info)
    notification: crate::overlay::NotificationEngine,

    // Escape sequence handler
    escape_handler: crate::EscapeHandler,

    // Transport sender (Mosh-style keystroke batching)
    transport_sender: TransportSender,
    pending_seq: Option<u64>,
    pending_predictable: bool,
    paste_threshold: usize,

    // Refresh timers
    overlay_refresh: tokio::time::Interval,
    escape_info_refresh: tokio::time::Interval,

    // Connection tracking
    is_first_connection: bool,
    reconnect_error: Option<String>,
    #[allow(dead_code)]
    disconnect_requested: bool,

    // CLI flags
    is_interactive: bool,
    cli_command: Option<String>,
    cli_output_mode: qsh_core::protocol::OutputMode,

    // Raw terminal mode guard (lifetime tied to component)
    _raw_guard: Option<crate::RawModeGuard>,
}

impl TerminalComponent {
    pub fn new(cli: &Cli, user_host: Option<String>) -> Result<Self> {
        use std::time::Duration;
        use tokio::time::MissedTickBehavior;

        // Parse escape key
        let escape_key = crate::parse_escape_key(&cli.escape_key);
        let escape_handler = crate::EscapeHandler::new(escape_key);

        // Determine if we're in interactive mode (PTY allocated)
        let is_interactive = cli.should_allocate_pty();

        // Enter raw terminal mode only for interactive sessions
        let _raw_guard = if is_interactive {
            match crate::RawModeGuard::enter() {
                Ok(guard) => {
                    tracing::debug!("Entered raw terminal mode (interactive)");
                    Some(guard)
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to enter raw mode");
                    return Err(e.into());
                }
            }
        } else {
            tracing::debug!("Command mode (non-interactive), skipping raw terminal mode");
            None
        };

        // Prediction settings
        let prediction_mode = cli.effective_prediction_mode();
        let prediction_enabled =
            prediction_mode != crate::cli::PredictionMode::Off && is_interactive;

        // Overlay refresh interval (for periodic RTT/stats updates)
        let mut overlay_refresh = tokio::time::interval(Duration::from_secs(2));
        overlay_refresh.set_missed_tick_behavior(MissedTickBehavior::Delay);

        // Fast refresh interval for escape info bar (when showing stats)
        let mut escape_info_refresh = tokio::time::interval(Duration::from_millis(250));
        escape_info_refresh.set_missed_tick_behavior(MissedTickBehavior::Delay);

        // Create notification engine
        let notification = create_notification_engine(cli, user_host);

        Ok(Self {
            channel: None,
            stdin: crate::StdinReader::new(),
            stdout: crate::StdoutWriter::new(),
            prediction_enabled,
            prediction_mode,
            renderer: crate::render::StateRenderer::new(),
            prediction_overlay: crate::overlay::PredictionOverlay::new(),
            client_parser: None,
            terminal_state: TerminalSessionState::new(),
            notification,
            escape_handler,
            transport_sender: TransportSender::new(cli.sender_config()),
            pending_seq: None,
            pending_predictable: false,
            paste_threshold: cli.paste_threshold,
            overlay_refresh,
            escape_info_refresh,
            is_first_connection: true,
            reconnect_error: None,
            disconnect_requested: false,
            is_interactive,
            cli_command: cli.command_string(),
            cli_output_mode: cli.output_mode(),
            _raw_guard,
        })
    }

    /// Create a terminal component for bootstrap/responder mode.
    ///
    /// In bootstrap mode, stdin/stdout are replaced with a Unix socket (attach pipe).
    /// The attach client connects and provides the actual terminal I/O.
    pub fn new_bootstrap(
        stdin_fd: std::os::unix::io::RawFd,
        stdout_fd: std::os::unix::io::RawFd,
        output_mode: qsh_core::protocol::OutputMode,
    ) -> Result<Self> {
        use std::time::Duration;
        use tokio::time::MissedTickBehavior;

        // No escape key in bootstrap mode (pass-through)
        let escape_handler = crate::EscapeHandler::new(None);

        // Bootstrap mode is always interactive (PTY on remote side)
        let is_interactive = true;

        // No raw mode guard needed - the attach client handles raw mode
        let _raw_guard = None;

        // No prediction in bootstrap mode (server is the one with the shell)
        let prediction_enabled = false;
        let prediction_mode = crate::cli::PredictionMode::Off;

        // Overlay refresh interval
        let mut overlay_refresh = tokio::time::interval(Duration::from_secs(2));
        overlay_refresh.set_missed_tick_behavior(MissedTickBehavior::Delay);

        let mut escape_info_refresh = tokio::time::interval(Duration::from_millis(250));
        escape_info_refresh.set_missed_tick_behavior(MissedTickBehavior::Delay);

        // Minimal notification engine (default style is Minimal)
        let notification = crate::overlay::NotificationEngine::new();

        Ok(Self {
            channel: None,
            stdin: crate::StdinReader::from_fd(stdin_fd),
            stdout: crate::StdoutWriter::from_fd(stdout_fd),
            prediction_enabled,
            prediction_mode,
            renderer: crate::render::StateRenderer::new(),
            prediction_overlay: crate::overlay::PredictionOverlay::new(),
            client_parser: None,
            terminal_state: TerminalSessionState::new(),
            notification,
            escape_handler,
            transport_sender: TransportSender::new(qsh_core::transport::SenderConfig::client()),
            pending_seq: None,
            pending_predictable: false,
            paste_threshold: 64,
            overlay_refresh,
            escape_info_refresh,
            is_first_connection: true,
            reconnect_error: None,
            disconnect_requested: false,
            is_interactive,
            cli_command: None,
            cli_output_mode: output_mode,
            _raw_guard,
        })
    }

    pub async fn on_connect(&mut self, conn: &std::sync::Arc<ChannelConnection>) -> Result<()> {
        tracing::info!(
            session_id = ?conn.session_id(),
            last_gen = self.terminal_state.last_generation,
            last_seq = self.terminal_state.last_input_seq,
            "Opening terminal channel"
        );

        // Get terminal size
        let term_size = crate::get_terminal_size()?;

        // Get terminal channel: either restored from session resume or newly opened
        let terminal = if let Some(restored) = conn.get_restored_terminal().await {
            // Mosh-style reconnection: reuse the existing terminal channel
            tracing::info!(channel_id = ?restored.channel_id(), "Using restored terminal from session resume");

            // Render the restored terminal state to the screen
            if let Some(state) = restored.take_initial_state().await {
                tracing::info!("Rendering restored terminal state");
                let ansi_data = state.render_to_ansi();
                if let Err(e) = self.stdout.write(&ansi_data).await {
                    tracing::warn!(error = %e, "Failed to render restored terminal state");
                }
            }

            // Send resize in case terminal size changed while disconnected
            let current_size = restored.term_size().await;
            let term_size_tuple = (term_size.cols, term_size.rows);
            if current_size != term_size_tuple {
                tracing::debug!(
                    old_size = ?current_size,
                    new_size = ?term_size_tuple,
                    "Sending resize after reconnection"
                );
                // Resize will be sent via control stream when we enter the I/O loop
            }

            restored
        } else if !self.is_first_connection {
            // Reconnection with no restored terminal means the shell exited while
            // we were disconnected. Return error to signal exit.
            tracing::info!("Shell exited during network interruption, exiting cleanly");
            return Err(qsh_core::Error::Protocol {
                message: "Shell exited during disconnection".to_string(),
            });
        } else {
            // First connection: open a fresh terminal channel
            let terminal_params = qsh_core::protocol::TerminalParams {
                term_size,
                term_type: std::env::var("TERM")
                    .unwrap_or_else(|_| "xterm-256color".to_string()),
                env: collect_terminal_env(),
                shell: None,
                command: self.cli_command.clone(),
                allocate_pty: self.is_interactive,
                last_generation: self.terminal_state.last_generation,
                last_input_seq: self.terminal_state.last_input_seq,
                output_mode: self.cli_output_mode,
            };

            conn.open_terminal(terminal_params).await?
        };

        // Mark that we've completed first connection
        self.is_first_connection = false;

        tracing::info!(channel_id = ?terminal.channel_id(), "Terminal channel ready");

        // Get initial RTT from QUIC connection
        let initial_rtt = conn.rtt().await;

        // Update notification engine for connected state
        self.notification
            .server_heard(std::time::Instant::now());
        self.notification
            .server_acked(std::time::Instant::now());
        self.notification.clear_network_error();

        // Clear reconnect error tracking
        self.reconnect_error = None;

        // Initialize/reset client-side terminal state tracking
        self.client_parser = Some(TerminalParser::new(term_size.cols, term_size.rows));
        self.prediction_overlay.clear_all();
        self.renderer.invalidate();

        // Initialize prediction engine with current RTT and cursor
        if self.prediction_enabled {
            let mut prediction = terminal.prediction_mut().await;
            prediction.update_rtt(initial_rtt);

            // Set display preference based on prediction mode
            let display_pref = match self.prediction_mode {
                crate::cli::PredictionMode::Adaptive => {
                    crate::prediction::DisplayPreference::Adaptive
                }
                crate::cli::PredictionMode::Always => {
                    crate::prediction::DisplayPreference::Always
                }
                crate::cli::PredictionMode::Experimental => {
                    crate::prediction::DisplayPreference::Experimental
                }
                crate::cli::PredictionMode::Off => crate::prediction::DisplayPreference::Never, // Should not reach
            };
            prediction.set_display_preference(display_pref);

            // Initialize cursor position from terminal state (start at 0,0 for new sessions)
            prediction.init_cursor(0, 0);
        }

        // Store the channel
        self.channel = Some(terminal);

        Ok(())
    }

    pub fn on_disconnect(&mut self) {
        // Preserve terminal state for reconnection
        tracing::debug!("TerminalComponent disconnected, preserving state");
    }

    pub async fn shutdown(self) -> Result<()> {
        // Restore terminal to normal mode
        crate::restore_terminal();
        tracing::debug!("TerminalComponent shutdown complete");
        Ok(())
    }

    pub async fn next_event(&mut self) -> SessionEvent {
        // Set up SIGWINCH signal handler for resize events
        #[cfg(unix)]
        let mut sigwinch = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
            .expect("Failed to setup SIGWINCH handler");

        loop {
            #[cfg(unix)]
            let resize_event = sigwinch.recv();
            #[cfg(not(unix))]
            let resize_event = std::future::pending::<Option<()>>();

            // Get terminal reference for this iteration
            let terminal = self.channel.as_mut().expect("Terminal channel not initialized");

            tokio::select! {
                biased;

                // Handle terminal resize
                _ = resize_event => {
                    if let Ok(new_size) = crate::get_terminal_size() {
                        tracing::debug!(cols = new_size.cols, rows = new_size.rows, "Terminal resized");

                        // Update client-side parser with new size
                        if let Some(ref mut parser) = self.client_parser {
                            *parser = TerminalParser::new(new_size.cols, new_size.rows);
                            self.renderer.invalidate(); // Force full redraw
                        }

                        // Clear prediction overlay on resize
                        if self.prediction_enabled {
                            let mut prediction = terminal.prediction_mut().await;
                            prediction.reset();
                            self.prediction_overlay.clear_all();
                        }

                        return SessionEvent::WindowResize(new_size);
                    }
                }

                // Handle user input from stdin
                result = self.stdin.read() => {
                    let data = match result {
                        Some(data) => data,
                        None => {
                            tracing::info!("EOF on stdin");
                            return SessionEvent::Exit;
                        }
                    };

                    // Process escape sequences
                    match self.escape_handler.process(&data) {
                        crate::EscapeResult::Command(crate::EscapeCommand::Disconnect) => {
                            tracing::info!("Escape sequence: disconnect");
                            self.notification.clear_message();
                            return SessionEvent::Exit;
                        }
                        crate::EscapeResult::Command(crate::EscapeCommand::ToggleOverlay) => {
                            // Overlay removed, command is now a no-op
                            self.notification.clear_message();
                            continue;
                        }
                        crate::EscapeResult::Command(crate::EscapeCommand::SendEscapeKey) => {
                            self.notification.clear_message();
                            // Send the escape character itself - flush immediately
                            let escape_key = self.escape_handler.escape_key().unwrap_or(0x1e);
                            let esc = [escape_key];

                            // Reserve sequence for this batch
                            if self.pending_seq.is_none() {
                                self.pending_seq = Some(terminal.reserve_sequence());
                            }
                            self.transport_sender.push(&esc);

                            // Force flush immediately (user action)
                            return SessionEvent::TransportFlush;
                        }
                        crate::EscapeResult::Waiting => {
                            // Waiting for command key - show connection info
                            self.notification.show_info(None, true);
                            return SessionEvent::EscapeInfo;
                        }
                        crate::EscapeResult::PassThrough(pass_data) => {
                            // Clear info bar (escape sequence resolved or timed out)
                            self.notification.clear_message();

                            // Handle the actual input
                            return self.handle_user_input(bytes::Bytes::from(pass_data)).await;
                        }
                    }
                }

                // TransportSender timer: flush pending input when timing allows
                _ = tokio::time::sleep_until(self.transport_sender.next_send_time().into()),
                    if self.transport_sender.has_pending() => {
                    // Timer fired with pending data - should be ready to send
                    if self.transport_sender.should_send_now() {
                        return SessionEvent::TransportFlush;
                    }
                    // Spurious wakeup or timing race - continue loop
                }

                // Handle terminal events (output or state sync)
                result = terminal.recv_event() => {
                    match result {
                        Ok(event) => {
                            return self.handle_terminal_event(event).await;
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "recv_event returned error");
                            return SessionEvent::Error(e);
                        }
                    }
                }

                // Periodic refresh for RTT/metrics updates
                _ = self.overlay_refresh.tick() => {
                    return SessionEvent::OverlayRefresh;
                }

                // Fast refresh for escape info bar (only active when waiting)
                _ = self.escape_info_refresh.tick(), if self.escape_handler.is_waiting() => {
                    return SessionEvent::EscapeInfo;
                }
            }
        }
    }

    // Handle user input with prediction and transport batching
    async fn handle_user_input(&mut self, data: bytes::Bytes) -> SessionEvent {
        let terminal = self.channel.as_mut().expect("Terminal channel not initialized");
        // Mosh-style paste detection: >threshold bytes triggers immediate flush
        let is_paste = data.len() > self.paste_threshold;
        if is_paste {
            tracing::debug!(
                len = data.len(),
                threshold = self.paste_threshold,
                "Paste detected, will flush immediately"
            );
        }

        // Check if input contains predictable characters
        let has_predictable = self.prediction_enabled
            && !is_paste
            && data.iter().any(|&b| is_predictable_char(b));

        // Track predictable flag for batch
        self.pending_predictable |= has_predictable;

        // Reserve sequence for this batch (first push assigns sequence)
        if self.pending_seq.is_none() {
            self.pending_seq = Some(terminal.reserve_sequence());
        }
        let seq = self.pending_seq.unwrap();

        // Mosh-style: prediction runs IMMEDIATELY (before send timing)
        if self.prediction_enabled {
            let mut prediction = terminal.prediction_mut().await;

            // Reset prediction on paste (Mosh stmclient.cc:333-335)
            if is_paste {
                prediction.reset();
                self.prediction_overlay.clear_all();
            } else {
                // Get current cursor position (from client parser or predicted)
                let cursor = if let Some(pred_cursor) = prediction.get_predicted_cursor() {
                    pred_cursor
                } else if let Some(ref parser) = self.client_parser {
                    let state = parser.state();
                    (state.cursor.col, state.cursor.row)
                } else {
                    (0, 0)
                };

                // Get terminal size for wrap calculation
                let term_size = crate::get_terminal_size().unwrap_or(qsh_core::protocol::TermSize { cols: 80, rows: 24 });

                // Only render if prediction engine says we should display
                if prediction.should_display() {
                    // Process each byte with position tracking
                    for &byte in data.iter() {
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
                            let pred = crate::prediction::Prediction {
                                sequence: echo.sequence,
                                char: echo.char,
                                col: char_col,
                                row: char_row,
                                timestamp: std::time::Instant::now(),
                            };
                            self.prediction_overlay.add(&pred, echo.style);
                        }
                    }
                } else {
                    // Still process bytes for cursor tracking even if not displaying
                    for &byte in data.iter() {
                        let _ = prediction.new_user_byte(byte, cursor, term_size.cols, seq);
                    }
                }
            }
        }

        // Accumulate in TransportSender (Mosh-style batching)
        self.transport_sender.push(&data);
        tracing::trace!(
            input_len = data.len(),
            pending_len = self.transport_sender.pending_len(),
            seq = seq,
            "Pushed input to TransportSender"
        );

        // Check for quit/suspend sequences that should flush immediately
        let has_quit_signal = data.iter().any(|&b| b == 0x03 || b == 0x1A);
        if has_quit_signal {
            tracing::debug!("Quit/suspend signal detected, will flush immediately");
        }

        // Determine if we should flush now
        let should_flush = is_paste || has_quit_signal;

        if should_flush || self.transport_sender.should_send_now() {
            // Ready to send: paste/quit signal or timer satisfied
            SessionEvent::TransportFlush
        } else {
            // Input queued, will flush on timer
            SessionEvent::InputQueued
        }
    }

    // Handle terminal output events
    async fn handle_terminal_event(
        &mut self,
        event: crate::TerminalEvent,
    ) -> SessionEvent {
        let terminal = self.channel.as_mut().expect("Terminal channel not initialized");
        match event {
            crate::TerminalEvent::Output(output) => {
                tracing::trace!(
                    len = output.data.len(),
                    confirmed_seq = output.confirmed_input_seq,
                    "Received terminal output"
                );

                // Update notification engine (mosh-style)
                let now = std::time::Instant::now();
                self.notification.server_heard(now);
                self.notification.server_acked(now);
                self.notification.adjust_message();

                // Track frame rate (rolling average)
                self.notification.record_frame(now);

                // Track confirmed input seq for recovery
                self.terminal_state.last_input_seq = output.confirmed_input_seq;

                // Update client-side terminal state
                if let Some(ref mut parser) = self.client_parser {
                    parser.process(&output.data);
                }

                // Validate and confirm predictions
                if self.prediction_enabled {
                    let mut prediction = terminal.prediction_mut().await;

                    // Validate predictions against client state
                    if let Some(ref parser) = self.client_parser {
                        let client_state = parser.state();
                        prediction.validate(client_state);
                        // Update predicted cursor to match server
                        prediction.init_cursor(client_state.cursor.col, client_state.cursor.row);
                    }

                    // Confirm predictions up to this sequence
                    prediction.confirm(output.confirmed_input_seq);
                    prediction.confirm_cells(output.confirmed_input_seq);

                    // Clear confirmed predictions from overlay
                    self.prediction_overlay.clear_confirmed(output.confirmed_input_seq);
                }

                SessionEvent::TerminalOutput(TerminalOutputEvent::Output(bytes::Bytes::from(output.data)))
            }
            crate::TerminalEvent::StateSync(update) => {
                tracing::debug!("Received state sync");

                // Update notification engine (mosh-style)
                let now = std::time::Instant::now();
                self.notification.server_heard(now);
                self.notification.server_acked(now);
                self.notification.adjust_message();

                // Track confirmed input seq
                self.terminal_state.last_input_seq = update.confirmed_input_seq;

                // Reset prediction engine on full state sync
                if self.prediction_enabled {
                    let mut prediction = terminal.prediction_mut().await;
                    prediction.reset();
                    self.prediction_overlay.clear_all();
                }

                // Render the full state to the terminal (mosh-style resync)
                if let qsh_core::terminal::StateDiff::Full(ref state) = update.diff {
                    tracing::debug!("Full state sync (resync or large change)");

                    // Update client parser to match server state
                    if let Some(ref mut parser) = self.client_parser {
                        *parser = TerminalParser::new(state.screen().cols(), state.screen().rows());
                    }

                    // Update predicted cursor from synced state
                    if self.prediction_enabled {
                        let mut prediction = terminal.prediction_mut().await;
                        prediction.init_cursor(state.cursor.col, state.cursor.row);
                    }

                    let ansi_data = state.render_to_ansi();
                    SessionEvent::TerminalOutput(TerminalOutputEvent::StateSync(ansi_data))
                } else {
                    // Incremental update - shouldn't happen in current protocol
                    SessionEvent::InputQueued // No-op
                }
            }
        }
    }

    /// Flush any pending transport data and return the data to send
    pub fn flush_transport(&mut self) -> Option<(bytes::Bytes, u64, bool)> {
        if self.transport_sender.has_pending() {
            let data = self.transport_sender.flush();
            if !data.is_empty() {
                if let Some(seq) = self.pending_seq.take() {
                    let predictable = self.pending_predictable;
                    self.pending_predictable = false;
                    return Some((bytes::Bytes::from(data), seq, predictable));
                }
            }
        }
        None
    }

    /// Get mutable reference to notification engine for RTT updates
    pub fn notification_mut(&mut self) -> &mut crate::overlay::NotificationEngine {
        &mut self.notification
    }

    /// Render notification bar to stdout
    pub async fn render_notification(&mut self) {
        render_notification(&self.notification, &mut self.stdout).await;
    }

    /// Get terminal channel ID (if connected)
    pub fn channel_id(&self) -> Option<qsh_core::protocol::ChannelId> {
        self.channel.as_ref().map(|ch| ch.channel_id())
    }

    /// Get current terminal size.
    ///
    /// Returns the current terminal size, falling back to 80x24 if unavailable.
    pub fn terminal_size(&self) -> TermSize {
        crate::get_terminal_size().unwrap_or(TermSize { cols: 80, rows: 24 })
    }

    /// Write data to stdout
    pub async fn stdout_write(&mut self, data: &[u8]) -> Result<()> {
        self.stdout.write(data).await.map_err(|e| e.into())
    }

    /// Render prediction overlay to stdout
    pub async fn render_prediction_overlay(&mut self) {
        let overlay_output = self.prediction_overlay.render();
        if !overlay_output.is_empty() {
            let _ = self.stdout.write(overlay_output.as_bytes()).await;
        }
    }

    /// Update transport sender RTT for adaptive send interval
    pub fn update_transport_rtt(&mut self, rtt: std::time::Duration) {
        self.transport_sender.set_rtt(rtt);
    }

    /// Update prediction engine RTT for adaptive display
    pub async fn update_prediction_rtt(&mut self, rtt: std::time::Duration) {
        if self.prediction_enabled {
            if let Some(ref mut terminal) = self.channel {
                let mut prediction = terminal.prediction_mut().await;
                prediction.update_rtt(rtt);
                prediction.check_glitches();
            }
        }
    }

    /// Queue input to terminal channel
    pub fn queue_input(&mut self, data: &[u8], seq: u64, predictable: bool) -> Result<()> {
        if let Some(ref terminal) = self.channel {
            terminal.queue_input_with_seq(data, seq, predictable)
        } else {
            Ok(())
        }
    }

    pub async fn handle_control(&mut self, msg: &Message) -> Result<()> {
        match msg {
            Message::ChannelClose(close) => {
                if let Some(ref terminal) = self.channel {
                    if close.channel_id == terminal.channel_id() {
                        tracing::info!(
                            channel_id = %close.channel_id,
                            reason = %close.reason,
                            "Server closed terminal channel - exiting"
                        );
                        return Err(qsh_core::Error::Protocol {
                            message: "Terminal channel closed".to_string(),
                        });
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
}

// Helper function to check if a character is predictable (from main.rs:443)
fn is_predictable_char(b: u8) -> bool {
    // Printable ASCII: 0x20 (space) through 0x7E (~)
    (0x20..=0x7E).contains(&b)
}

// Helper function to render notification bar (from main.rs)
async fn render_notification(
    notification: &crate::overlay::NotificationEngine,
    stdout: &mut crate::StdoutWriter,
) {
    // Get terminal width for rendering (default to 80 if unavailable)
    let term_width = crate::get_terminal_size()
        .map(|size| size.cols)
        .unwrap_or(80);

    let notification_output = notification.render(term_width);
    if !notification_output.is_empty() {
        let _ = stdout.write(notification_output.as_bytes()).await;
    }
}

// Helper function to create notification engine (from main.rs:622)
fn create_notification_engine(
    cli: &Cli,
    user_host: Option<String>,
) -> crate::overlay::NotificationEngine {
    let mut notification = crate::overlay::NotificationEngine::new();

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

// Helper to map CLI notification style to overlay style (from main.rs:494)
fn map_notification_style(
    cli_style: crate::cli::NotificationStyle,
) -> crate::overlay::NotificationStyle {
    match cli_style {
        crate::cli::NotificationStyle::Minimal => crate::overlay::NotificationStyle::Minimal,
        crate::cli::NotificationStyle::Enhanced => crate::overlay::NotificationStyle::Enhanced,
    }
}

// Helper function to collect terminal environment variables (from main.rs:459)
fn collect_terminal_env() -> Vec<(String, String)> {
    let mut env = Vec::new();
    // Collect common terminal-related environment variables
    for key in &["LANG", "LC_ALL", "LC_CTYPE"] {
        if let Ok(val) = std::env::var(key) {
            env.push((key.to_string(), val));
        }
    }
    env
}

/// Forward component managing port forwards and SOCKS5 proxies.
pub struct ForwardComponent {
    // Forward configurations from CLI
    local_specs: Vec<String>,
    remote_specs: Vec<String>,
    dynamic_specs: Vec<String>,

    // Active forward handles (populated on connect)
    local_handles: Vec<crate::ForwarderHandle>,
    remote_handles: Vec<crate::RemoteForwarderHandle>,
    socks_handles: Vec<crate::ProxyHandle>,
}

impl ForwardComponent {
    pub fn new(cli: &Cli) -> Result<Self> {
        Ok(Self {
            local_specs: cli.local_forward.clone(),
            remote_specs: cli.remote_forward.clone(),
            dynamic_specs: cli.dynamic_forward.clone(),
            local_handles: Vec::new(),
            remote_handles: Vec::new(),
            socks_handles: Vec::new(),
        })
    }

    pub async fn on_connect(&mut self, conn: &std::sync::Arc<ChannelConnection>) -> Result<()> {
        use tracing::{error, info};

        // Start local forwards (-L)
        for spec in &self.local_specs {
            match crate::parse_local_forward(spec) {
                Ok((bind_addr, target_host, target_port)) => {
                    info!(
                        bind = %bind_addr,
                        target = %format!("{}:{}", target_host, target_port),
                        "Starting local forward"
                    );
                    let forwarder = crate::LocalForwarder::new(
                        bind_addr,
                        target_host,
                        target_port,
                        std::sync::Arc::clone(conn),
                    );
                    match forwarder.start().await {
                        Ok(handle) => {
                            info!(addr = %handle.local_addr(), "Local forward listening");
                            self.local_handles.push(handle);
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
        for spec in &self.dynamic_specs {
            match crate::parse_dynamic_forward(spec) {
                Ok(bind_addr) => {
                    info!(bind = %bind_addr, "Starting SOCKS5 proxy");
                    let proxy = crate::Socks5Proxy::new(bind_addr, std::sync::Arc::clone(conn));
                    match proxy.start().await {
                        Ok(handle) => {
                            info!(addr = %handle.local_addr(), "SOCKS5 proxy listening");
                            self.socks_handles.push(handle);
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
        for spec in &self.remote_specs {
            match crate::parse_remote_forward(spec) {
                Ok((bind_host, bind_port, target_host, target_port)) => {
                    info!(
                        bind = %format!("{}:{}", bind_host, bind_port),
                        target = %format!("{}:{}", target_host, target_port),
                        "Starting remote forward"
                    );
                    let forwarder = crate::RemoteForwarder::new(
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
                            self.remote_handles.push(handle);
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

        Ok(())
    }

    pub fn on_disconnect(&mut self) {
        // Drop all handles (stops forwarder tasks)
        self.local_handles.clear();
        self.remote_handles.clear();
        self.socks_handles.clear();
    }

    pub async fn shutdown(self) -> Result<()> {
        // Handles will be dropped automatically
        Ok(())
    }

    pub async fn next_event(&mut self) -> SessionEvent {
        // Forwards are fire-and-forget, so return pending
        std::future::pending().await
    }

    pub async fn handle_control(&mut self, msg: &Message, conn: &std::sync::Arc<ChannelConnection>) -> Result<()> {
        use tracing::debug;

        // Handle OpenForwardedChannel messages (server-initiated remote forwards)
        match msg {
            Message::ChannelOpen(open) => {
                if let qsh_core::protocol::ChannelParams::ForwardedTcpIp(params) = &open.params {
                    debug!(?params, "Accepting forwarded channel from server");
                    conn.handle_forwarded_channel_open(open.channel_id, params.clone()).await?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

/// Main session manager with unified event loop.
pub struct Session {
    connection: std::sync::Arc<ReconnectableConnection>,
    parts: SessionParts,
    control: Option<crate::control::ControlSocket>,
    session_name: Option<String>,
    /// Forward registry for tracking runtime-added forwards.
    forward_registry: std::sync::Arc<std::sync::Mutex<crate::forward::ForwardRegistry>>,
    /// Connection start time (for uptime tracking).
    connected_at: Option<std::time::Instant>,
    /// Resource manager for unified resource tracking (Phase 2).
    resource_manager: Option<crate::control::ResourceManager>,
    /// Resource event receiver for broadcasting to control clients.
    resource_event_rx: Option<tokio::sync::broadcast::Receiver<crate::control::ResourceEvent>>,
    /// Attachment registry for terminal I/O bindings.
    attachment_registry: crate::control::AttachmentRegistry,
    /// Channel for terminal output forwarding tasks to send messages back.
    #[allow(dead_code)]
    control_output_tx: tokio::sync::mpsc::UnboundedSender<(usize, crate::control::proto::Message)>,
    /// Receiver for messages from terminal output forwarding tasks.
    control_output_rx: tokio::sync::mpsc::UnboundedReceiver<(usize, crate::control::proto::Message)>,
}

impl Session {
    pub fn new(connection: std::sync::Arc<ReconnectableConnection>, parts: SessionParts) -> Self {
        let (control_output_tx, control_output_rx) = tokio::sync::mpsc::unbounded_channel();
        Self {
            connection,
            parts,
            control: None,
            session_name: None,
            forward_registry: std::sync::Arc::new(std::sync::Mutex::new(crate::forward::ForwardRegistry::new())),
            connected_at: None,
            resource_manager: None,
            resource_event_rx: None,
            attachment_registry: crate::control::AttachmentRegistry::new(),
            control_output_tx,
            control_output_rx,
        }
    }

    /// Attach a resource manager for unified resource tracking.
    ///
    /// Also stores the event receiver for broadcasting resource events to control clients.
    pub fn with_resource_manager(
        mut self,
        manager: crate::control::ResourceManager,
        event_rx: tokio::sync::broadcast::Receiver<crate::control::ResourceEvent>,
    ) -> Self {
        self.resource_manager = Some(manager);
        self.resource_event_rx = Some(event_rx);
        self
    }

    /// Get a reference to the resource manager, if set.
    pub fn resource_manager(&self) -> Option<&crate::control::ResourceManager> {
        self.resource_manager.as_ref()
    }

    /// Attach a control socket to this session.
    ///
    /// The control socket allows separate terminal sessions to manage this
    /// connection (query status, add/remove port forwards, etc.).
    pub fn with_control_socket(mut self, socket: crate::control::ControlSocket) -> Self {
        self.control = Some(socket);
        self
    }

    /// Set the session name for this connection.
    ///
    /// The session name is used for identifying the control socket and
    /// for display purposes.
    pub fn with_session_name(mut self, name: String) -> Self {
        self.session_name = Some(name);
        self
    }

    /// Handle TerminalAttach command.
    ///
    /// Returns the Unix socket path for raw terminal I/O.
    /// Clients connect directly to this socket for low-latency terminal access.
    async fn handle_terminal_attach(
        &mut self,
        _client_id: usize,
        request_id: u32,
        resource_id: &str,
    ) -> crate::control::proto::Message {
        use crate::control::proto;

        // Check if resource manager exists
        let rm = match self.resource_manager.as_ref() {
            Some(rm) => rm,
            None => {
                return command_error(request_id, 0, proto::ErrorCode::Internal, "Resource manager not initialized");
            }
        };

        let event_seq = rm.next_event_seq().await;

        // Verify it exists and is a terminal
        let info = match rm.describe(resource_id).await {
            Some(info) if matches!(info.kind, crate::control::ResourceKind::Terminal) => info,
            Some(_) => {
                return command_error(request_id, event_seq, proto::ErrorCode::InvalidArgument, "Resource is not a terminal");
            }
            None => {
                return command_error(request_id, event_seq, proto::ErrorCode::NotFound, "Terminal not found");
            }
        };

        // Get the I/O socket path
        let socket_path = match rm.terminal_io_socket(resource_id).await {
            Ok(path) => path,
            Err(e) => {
                return command_error(request_id, event_seq, proto::ErrorCode::Internal, &e.to_string());
            }
        };

        tracing::info!(
            resource_id = %resource_id,
            socket_path = %socket_path.display(),
            "Returning terminal I/O socket path"
        );

        // Return success with socket path
        proto::Message {
            kind: Some(proto::message::Kind::Event(proto::Event {
                event_seq,
                evt: Some(proto::event::Evt::CommandResult(proto::CommandResult {
                    request_id,
                    result: Some(proto::command_result::Result::Ok(proto::CommandOk {
                        data: Some(proto::command_ok::Data::TerminalAttach(
                            proto::TerminalAttachResult {
                                resource_id: info.id.clone(),
                                io_socket_path: socket_path.to_string_lossy().to_string(),
                            },
                        )),
                    })),
                })),
            })),
        }
    }

    /// Handle TerminalDetach command.
    ///
    /// With raw I/O sockets, detach is essentially a no-op on the server side.
    /// Clients just disconnect from the I/O socket directly.
    async fn handle_terminal_detach(
        &mut self,
        _client_id: usize,
        request_id: u32,
        resource_id: &str,
    ) -> crate::control::proto::Message {
        use crate::control::proto;

        let event_seq = match self.resource_manager.as_ref() {
            Some(rm) => rm.next_event_seq().await,
            None => 0,
        };

        // Verify the resource exists
        if let Some(ref rm) = self.resource_manager {
            if rm.describe(resource_id).await.is_none() {
                return command_error(request_id, event_seq, proto::ErrorCode::NotFound, "Terminal not found");
            }
        }

        tracing::info!(
            resource_id = %resource_id,
            "Terminal detach acknowledged (client disconnects from I/O socket directly)"
        );

        // Return success
        proto::Message {
            kind: Some(proto::message::Kind::Event(proto::Event {
                event_seq,
                evt: Some(proto::event::Evt::CommandResult(proto::CommandResult {
                    request_id,
                    result: Some(proto::command_result::Result::Ok(proto::CommandOk {
                        data: None,
                    })),
                })),
            })),
        }
    }

    /// Handle TerminalResize command.
    async fn handle_terminal_resize(
        &mut self,
        request_id: u32,
        resource_id: &str,
        cols: u32,
        rows: u32,
    ) -> crate::control::proto::Message {
        use crate::control::proto;

        let event_seq = match self.resource_manager.as_ref() {
            Some(rm) => rm.next_event_seq().await,
            None => 0,
        };

        // Call terminal_resize on the resource manager
        if let Some(ref rm) = self.resource_manager {
            if let Err(e) = rm.terminal_resize(resource_id, cols, rows).await {
                return command_error(request_id, event_seq, proto::ErrorCode::NotFound, &e.to_string());
            }
        } else {
            return command_error(request_id, event_seq, proto::ErrorCode::Internal, "Resource manager not initialized");
        }

        tracing::debug!(
            resource_id = %resource_id,
            cols,
            rows,
            "Terminal resized via control socket"
        );

        // Return success
        proto::Message {
            kind: Some(proto::message::Kind::Event(proto::Event {
                event_seq,
                evt: Some(proto::event::Evt::CommandResult(proto::CommandResult {
                    request_id,
                    result: Some(proto::command_result::Result::Ok(proto::CommandOk {
                        data: None,
                    })),
                })),
            })),
        }
    }

    /// Construct session from CLI arguments.
    pub fn from_cli(
        connection: std::sync::Arc<ReconnectableConnection>,
        cli: &Cli,
        user_host: Option<String>,
    ) -> Result<Self> {
        let has_forwards = !cli.local_forward.is_empty()
            || !cli.remote_forward.is_empty()
            || !cli.dynamic_forward.is_empty();

        let is_forward_only = cli.is_forward_only();

        let terminal = if !is_forward_only {
            Some(TerminalComponent::new(cli, user_host.clone())?)
        } else {
            None
        };

        let forwards = if has_forwards {
            Some(ForwardComponent::new(cli)?)
        } else {
            None
        };

        // Note: -N without forwards is allowed - useful for control-socket-only sessions
        // where forwards/terminals can be added dynamically via the control socket

        let mut session = Self::new(connection, SessionParts { terminal, forwards });

        // Create resource manager for unified resource tracking
        let (resource_manager, event_rx) = crate::control::ResourceManager::new();
        session.resource_manager = Some(resource_manager);
        session.resource_event_rx = Some(event_rx);

        // Create control socket for session management
        // Session name: use -S flag, or derive from user@host
        let session_name = cli.session.clone().or(user_host).unwrap_or_else(|| "qsh".to_string());
        let socket_path = crate::control::socket_path(&session_name);

        match crate::control::ControlSocket::new(&socket_path) {
            Ok(control_socket) => {
                tracing::info!(path = %socket_path.display(), name = %session_name, "Control socket created");
                session.control = Some(control_socket);
                session.session_name = Some(session_name);
            }
            Err(e) => {
                // Non-fatal: log warning but continue without control socket
                tracing::warn!(error = %e, path = %socket_path.display(), "Failed to create control socket");
            }
        }

        Ok(session)
    }

    /// Construct session for bootstrap/responder mode.
    ///
    /// In bootstrap mode, stdin/stdout come from an attach pipe (Unix socket)
    /// rather than the real terminal. The attach client connects and provides
    /// the actual terminal I/O.
    pub fn from_bootstrap(
        connection: std::sync::Arc<ReconnectableConnection>,
        stdin_fd: std::os::unix::io::RawFd,
        stdout_fd: std::os::unix::io::RawFd,
        output_mode: qsh_core::protocol::OutputMode,
    ) -> Result<Self> {
        let terminal = TerminalComponent::new_bootstrap(stdin_fd, stdout_fd, output_mode)?;
        Ok(Self::new(
            connection,
            SessionParts {
                terminal: Some(terminal),
                forwards: None,
            },
        ))
    }

    /// Run the unified session event loop.
    pub async fn run(mut self) -> Result<i32> {
        use tracing::{debug, error, info, trace, warn};

        loop {
            let conn = self.connection.wait_connected().await?;

            // Track connection start time
            self.connected_at = Some(std::time::Instant::now());

            // Initialize components
            if let Some(ref mut term) = self.parts.terminal {
                term.on_connect(&conn).await?;
            }
            if let Some(ref mut fwd) = self.parts.forwards {
                fwd.on_connect(&conn).await?;
            }

            let mut heartbeat = HeartbeatState::new(Duration::from_secs(1));

            // Create channel for forward commands from control socket
            let (_forward_cmd_tx, mut forward_cmd_rx) = tokio::sync::mpsc::channel::<crate::control::ForwardAddCommand>(16);

            // Create channel for terminal commands from control socket
            let (_terminal_cmd_tx, mut terminal_cmd_rx) = tokio::sync::mpsc::channel::<crate::control::TerminalCommand>(16);

            // Create channel for control responses (allows spawned tasks to send responses back)
            let (_control_response_tx, mut control_response_rx) = tokio::sync::mpsc::channel::<(usize, crate::control::Message)>(16);

            // Unified event loop
            let res: Result<i32> = loop {
                tokio::select! {
                    biased;

                    // Ctrl+C handler
                    _ = tokio::signal::ctrl_c() => {
                        info!("Shutting down...");
                        break Ok(0);
                    }

                    // Forward command from control socket
                    Some(cmd) = forward_cmd_rx.recv() => {
                        use crate::control::ForwardAddCommand;
                        match cmd {
                            ForwardAddCommand::Local { bind_addr, bind_port, dest_host, dest_port, response_tx } => {
                                let bind_addr_str = bind_addr.as_deref().unwrap_or("0.0.0.0");
                                let bind_socket: std::net::SocketAddr = format!("{}:{}", bind_addr_str, bind_port)
                                    .parse()
                                    .unwrap_or_else(|_| std::net::SocketAddr::from(([0, 0, 0, 0], bind_port as u16)));

                                let forwarder = crate::LocalForwarder::new(
                                    bind_socket,
                                    dest_host.clone(),
                                    dest_port as u16,
                                    std::sync::Arc::clone(&conn),
                                );

                                match forwarder.start().await {
                                    Ok(handle) => {
                                        let local_addr = handle.local_addr();
                                        let target = format!("{}:{}", dest_host, dest_port);
                                        let spec = format!("{}:{}", local_addr, target);
                                        info!(bind = %local_addr, target = %target, "Local forward started");

                                        // Register in registry (passing handle to keep forwarder alive)
                                        let id = {
                                            let mut registry = self.forward_registry.lock().unwrap();
                                            registry.add_local(&spec, local_addr, target, Some(handle))
                                        };

                                        let _ = response_tx.send(Ok(id));
                                    }
                                    Err(e) => {
                                        error!(error = %e, "Failed to start local forward");
                                        let _ = response_tx.send(Err(e.to_string()));
                                    }
                                }
                            }
                            ForwardAddCommand::Dynamic { bind_addr, bind_port, response_tx } => {
                                let bind_addr_str = bind_addr.as_deref().unwrap_or("0.0.0.0");
                                let bind_socket: std::net::SocketAddr = format!("{}:{}", bind_addr_str, bind_port)
                                    .parse()
                                    .unwrap_or_else(|_| std::net::SocketAddr::from(([0, 0, 0, 0], bind_port as u16)));

                                let proxy = crate::Socks5Proxy::new(bind_socket, std::sync::Arc::clone(&conn));

                                match proxy.start().await {
                                    Ok(handle) => {
                                        let local_addr = handle.local_addr();
                                        let spec = local_addr.to_string();
                                        info!(bind = %local_addr, "SOCKS5 proxy started");

                                        // Register in registry (passing handle to keep proxy alive)
                                        let id = {
                                            let mut registry = self.forward_registry.lock().unwrap();
                                            registry.add_dynamic(&spec, local_addr, Some(handle))
                                        };

                                        let _ = response_tx.send(Ok(id));
                                    }
                                    Err(e) => {
                                        error!(error = %e, "Failed to start SOCKS5 proxy");
                                        let _ = response_tx.send(Err(e.to_string()));
                                    }
                                }
                            }
                            ForwardAddCommand::Remote { bind_addr: _, bind_port: _, dest_host: _, dest_port: _, response_tx } => {
                                // Remote forwards require server-side support
                                // For now, return not implemented
                                let _ = response_tx.send(Err("remote forwards not yet implemented".to_string()));
                            }
                        }
                    }

                    // Terminal command from control socket
                    Some(cmd) = terminal_cmd_rx.recv() => {
                        use crate::control::TerminalCommand;
                        use crate::control::resources::Terminal;
                        match cmd {
                            TerminalCommand::Open { cols, rows, term_type, shell, command, env, output_mode, allocate_pty, response_tx } => {
                                // Create a Terminal resource and start it via ResourceManager
                                info!(cols, rows, term_type = %term_type, shell = ?shell, command = ?command, "Terminal open requested");

                                if let Some(ref rm) = self.resource_manager {
                                    // Create Terminal resource with params
                                    let terminal = Terminal::from_params(
                                        "pending".to_string(), // ID will be assigned by ResourceManager
                                        Some(cols),
                                        Some(rows),
                                        Some(term_type.clone()),
                                        shell.clone(),
                                        command.clone(),
                                        env,
                                        output_mode,
                                        allocate_pty,
                                    );

                                    // Add to resource manager (gets assigned ID like "term-0")
                                    let id = rm.add(Box::new(terminal)).await;
                                    info!(resource_id = %id, "Terminal resource added");

                                    // Start the resource (opens channel on server)
                                    match rm.start(&id, conn.clone()).await {
                                        Ok(()) => {
                                            info!(resource_id = %id, "Terminal resource started");
                                            // Return the resource ID (parsed as u64 for backwards compat)
                                            // Format is "term-N", extract N
                                            let term_num = id.strip_prefix("term-")
                                                .and_then(|s| s.parse::<u64>().ok())
                                                .unwrap_or(0);
                                            let _ = response_tx.send(Ok(term_num));
                                        }
                                        Err(e) => {
                                            error!(resource_id = %id, error = %e, "Failed to start terminal resource");
                                            let _ = response_tx.send(Err(format!("failed to start terminal: {}", e)));
                                        }
                                    }
                                } else {
                                    let _ = response_tx.send(Err("resource manager not available".to_string()));
                                }
                            }
                            TerminalCommand::Close { terminal_id, response_tx } => {
                                info!(terminal_id, "Terminal close requested");
                                // Close via ResourceManager
                                if let Some(ref rm) = self.resource_manager {
                                    let id = format!("term-{}", terminal_id);
                                    match rm.close(&id).await {
                                        Ok(()) => {
                                            info!(resource_id = %id, "Terminal resource closed");
                                            // Return None for exit code (not tracked yet)
                                            let _ = response_tx.send(Ok(None));
                                        }
                                        Err(e) => {
                                            let _ = response_tx.send(Err(format!("failed to close terminal: {}", e)));
                                        }
                                    }
                                } else {
                                    let _ = response_tx.send(Err("resource manager not available".to_string()));
                                }
                            }
                            TerminalCommand::Resize { terminal_id, cols, rows, response_tx } => {
                                info!(terminal_id, cols, rows, "Terminal resize requested");
                                // Resize the main terminal if ID is 0
                                if terminal_id == 0 {
                                    if let Some(ref term) = self.parts.terminal {
                                        if let Some(channel_id) = term.channel_id() {
                                            // Send resize to the server
                                            match conn.send_resize(channel_id, cols as u16, rows as u16).await {
                                                Ok(_) => {
                                                    let _ = response_tx.send(Ok(()));
                                                }
                                                Err(e) => {
                                                    let _ = response_tx.send(Err(format!("failed to resize: {}", e)));
                                                }
                                            }
                                        } else {
                                            let _ = response_tx.send(Err("terminal channel not open".to_string()));
                                        }
                                    } else {
                                        let _ = response_tx.send(Err("no terminal available".to_string()));
                                    }
                                } else {
                                    // TODO: Resize via ResourceManager for dynamic terminals
                                    let _ = response_tx.send(Err(format!("terminal {} resize not yet supported via resource manager", terminal_id)));
                                }
                            }
                            TerminalCommand::Attach { terminal_id, response_tx } => {
                                info!(terminal_id, "Terminal attach requested");
                                // TODO: Implement attach via ResourceManager
                                // For now, return an error
                                let _ = response_tx.send(Err("terminal attach not yet implemented".to_string()));
                            }
                            TerminalCommand::Detach { terminal_id, response_tx } => {
                                info!(terminal_id, "Terminal detach requested");
                                // TODO: Implement detach via ResourceManager
                                // For now, return an error
                                let _ = response_tx.send(Err("terminal detach not yet implemented".to_string()));
                            }
                        }
                    }

                    // Control response from spawned task
                    Some((client_id, response)) = control_response_rx.recv() => {
                        if let Some(ctl) = self.control.as_mut() {
                            if let Err(e) = ctl.send_message(client_id, response).await {
                                tracing::warn!(error = %e, "Failed to send control response");
                            }
                        }
                    }

                    // Heartbeat timer
                    _ = tokio::time::sleep_until(heartbeat.next_deadline) => {
                        let hb = heartbeat.tracker.send_heartbeat();
                        trace!(seq = hb.seq, "Sending heartbeat");

                        match conn.send_control(&Message::Heartbeat(hb)).await {
                            Ok(_) => {
                                heartbeat.next_deadline = tokio::time::Instant::now() + heartbeat.tracker.send_interval();
                            }
                            Err(e) if e.is_transient() => break Err(e.into()),
                            Err(e) => return Err(e.into()),
                        }
                    }

                    // Control messages from server
                    msg = conn.recv_control() => {
                        match msg {
                            Ok(msg) => {
                                trace!(?msg, "Received control message");

                                // Update heartbeat tracker
                                if let Message::Heartbeat(ref hb) = msg {
                                    if let Some(_rtt) = heartbeat.tracker.receive_heartbeat(hb) {
                                        // RTT sample recorded
                                    }
                                }

                                // Dispatch to components
                                if let Some(ref mut term) = self.parts.terminal {
                                    term.handle_control(&msg).await?;
                                }
                                if let Some(ref mut fwd) = self.parts.forwards {
                                    fwd.handle_control(&msg, &conn).await?;
                                }

                                // Handle session-level messages
                                match msg {
                                    Message::Shutdown(payload) => {
                                        info!(reason = ?payload.reason, "Server requested shutdown");
                                        break Ok(0);
                                    }
                                    Message::ChannelAccept(ref accept) => {
                                        // Dispatch to waiting channel open tasks
                                        if let Some(tx) = conn.pending_channel_accepts.lock().await.remove(&accept.channel_id) {
                                            let _ = tx.send(Ok(accept.data.clone()));
                                        }
                                    }
                                    Message::ChannelReject(ref reject) => {
                                        // Dispatch rejection to waiting channel open tasks
                                        if let Some(tx) = conn.pending_channel_accepts.lock().await.remove(&reject.channel_id) {
                                            let err = qsh_core::Error::Protocol {
                                                message: format!("Channel rejected: {}", reject.message),
                                            };
                                            let _ = tx.send(Err(err));
                                        }
                                    }
                                    Message::GlobalReply(ref reply) => {
                                        // Dispatch to waiting global request tasks
                                        if let Some(tx) = conn.pending_global_requests.lock().await.remove(&reply.request_id) {
                                            let _ = tx.send(reply.result.clone());
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            Err(e) if e.is_transient() => break Err(e.into()),
                            Err(e) => return Err(e.into()),
                        }
                    }

                    // Terminal events (guarded)
                    ev = async {
                        match self.parts.terminal.as_mut() {
                            Some(term) => term.next_event().await,
                            None => std::future::pending().await,
                        }
                    } => {
                        match ev {
                            SessionEvent::Exit => {
                                info!("Terminal exit requested");
                                break Ok(0);
                            }
                            SessionEvent::Error(e) => {
                                if e.is_transient() {
                                    debug!(error = %e, "Terminal transient error");
                                    break Err(e.into());
                                } else {
                                    error!(error = %e, "Terminal fatal error");
                                    return Err(e.into());
                                }
                            }
                            SessionEvent::WindowResize(size) => {
                                // Send resize to server
                                if let Some(ref term) = self.parts.terminal {
                                    if let Some(channel_id) = term.channel_id() {
                                        if let Err(e) = conn.send_resize(channel_id, size.cols, size.rows).await {
                                            debug!(error = %e, "Failed to send resize");
                                            // Non-fatal - server will sync on next state update
                                        }
                                    }
                                }
                            }
                            SessionEvent::TransportFlush => {
                                // Flush pending transport data to server
                                if let Some(ref mut term) = self.parts.terminal {
                                    if let Some((data, seq, predictable)) = term.flush_transport() {
                                        if let Err(e) = term.queue_input(&data, seq, predictable) {
                                            warn!(error = %e, "Failed to queue input");
                                            break Err(e.into());
                                        }
                                    }
                                }
                            }
                            SessionEvent::TerminalOutput(output_event) => {
                                // Write terminal output to stdout and render notification
                                if let Some(ref mut term) = self.parts.terminal {
                                    match output_event {
                                        TerminalOutputEvent::Output(data) => {
                                            // Write server output (already handled in event processing)
                                            // The data was already written to stdout in handle_terminal_event
                                            // Just need to write it here since we extracted the event
                                            if let Err(e) = term.stdout_write(&data).await {
                                                warn!(error = %e, "stdout write error");
                                                break Err(e.into());
                                            }

                                            // Render prediction overlay if enabled
                                            term.render_prediction_overlay().await;

                                            // Render notification bar
                                            term.render_notification().await;
                                        }
                                        TerminalOutputEvent::StateSync(ansi_data) => {
                                            // Full state sync - write to stdout
                                            if let Err(e) = term.stdout_write(&ansi_data).await {
                                                warn!(error = %e, "stdout write error during state sync");
                                                break Err(e.into());
                                            }

                                            // Render notification bar
                                            term.render_notification().await;
                                        }
                                    }
                                }
                            }
                            SessionEvent::OverlayRefresh => {
                                // Periodic RTT/metrics update
                                if let Some(ref mut term) = self.parts.terminal {
                                    // Update RTT from heartbeat tracker (SRTT like mosh)
                                    if let Some(srtt) = heartbeat.tracker.srtt() {
                                        term.notification_mut().update_rtt(srtt);

                                        // Update TransportSender RTT for adaptive send_interval
                                        term.update_transport_rtt(srtt);

                                        // Update prediction engine RTT for adaptive display
                                        term.update_prediction_rtt(srtt).await;
                                    }

                                    // Update quiche RTT (QUIC transport-level) with smoothing
                                    let quiche_rtt = conn.rtt().await;
                                    term.notification_mut().update_quiche_rtt(quiche_rtt);

                                    // Update packet loss metric from QUIC stats
                                    let loss = conn.quic().packet_loss().await;
                                    term.notification_mut().update_packet_loss(loss);

                                    // Update notification engine (expire messages, etc.)
                                    term.notification_mut().adjust_message();

                                    // Render notification bar
                                    term.render_notification().await;
                                }
                            }
                            SessionEvent::EscapeInfo => {
                                // Fast refresh for escape info bar
                                if let Some(ref mut term) = self.parts.terminal {
                                    // Update RTT from heartbeat tracker (SRTT like mosh)
                                    if let Some(srtt) = heartbeat.tracker.srtt() {
                                        term.notification_mut().update_rtt(srtt);
                                    }

                                    // Update quiche RTT (QUIC transport-level) with smoothing
                                    let quiche_rtt = conn.rtt().await;
                                    term.notification_mut().update_quiche_rtt(quiche_rtt);

                                    // Render notification bar with current stats
                                    term.render_notification().await;
                                }
                            }
                            SessionEvent::InputQueued => {
                                // Input queued in transport sender, no action needed
                            }
                            SessionEvent::StdinInput(_) => {
                                // StdinInput is handled internally by TerminalComponent
                                // via flush_transport - should not reach here
                            }
                        }
                    }

                    // Forward events (guarded, mostly pending)
                    _ev = async {
                        match self.parts.forwards.as_mut() {
                            Some(fwd) => fwd.next_event().await,
                            None => std::future::pending().await,
                        }
                    } => {
                        // Forwards typically don't emit events
                    }

                    // Resource events from ResourceManager (Phase 2)
                    // Broadcast resource state changes to connected control clients
                    resource_event = async {
                        match self.resource_event_rx.as_mut() {
                            Some(rx) => rx.recv().await,
                            None => std::future::pending().await,
                        }
                    } => {
                        match resource_event {
                            Ok(event) => {
                                // Broadcast resource event to all connected control clients
                                if let Some(ref mut ctl) = self.control {
                                    // Convert ResourceEvent to protocol message and broadcast
                                    // The event already contains event_seq from ResourceManager
                                    let proto_event = crate::control::resource_event_to_proto(&event, event.event_seq);
                                    let message = crate::control::proto::Message {
                                        kind: Some(crate::control::proto::message::Kind::Event(proto_event)),
                                    };
                                    if let Ok(bytes) = crate::control::encode_message(&message) {
                                        // Broadcast to all clients
                                        if let Err(e) = ctl.broadcast(&bytes).await {
                                            debug!(error = %e, "Failed to broadcast resource event");
                                        } else {
                                            trace!(
                                                resource_id = %event.id,
                                                state = %event.state,
                                                "Broadcasted resource event to control clients"
                                            );
                                        }
                                    }
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                warn!(lagged = n, "Resource event receiver lagged, missed events");
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                // Channel closed, resource manager dropped - this shouldn't happen
                                debug!("Resource event channel closed");
                            }
                        }
                    }

                    // Control socket events (guarded)
                    ev = async {
                        match self.control.as_mut() {
                            Some(ctl) => ctl.next_event().await,
                            None => std::future::pending().await,
                        }
                    } => {
                        if let Ok(Some(event)) = ev {
                            use crate::control::{ControlEvent, proto};

                            match event {
                                ControlEvent::ClientConnected { client_id } => {
                                    tracing::debug!(client_id, "Control client connected");
                                }
                                ControlEvent::Command { client_id, request_id, cmd } => {
                                    // Handle terminal attachment commands specially since they need
                                    // access to the attachment registry
                                    let response = match &cmd {
                                        proto::command::Cmd::TerminalAttach(attach) => {
                                            self.handle_terminal_attach(client_id, request_id, &attach.resource_id).await
                                        }
                                        proto::command::Cmd::TerminalDetach(detach) => {
                                            self.handle_terminal_detach(client_id, request_id, &detach.resource_id).await
                                        }
                                        proto::command::Cmd::TerminalResize(resize) => {
                                            self.handle_terminal_resize(request_id, &resize.resource_id, resize.cols, resize.rows).await
                                        }
                                        _ => {
                                            // Handle other unified protocol commands
                                            let heartbeat_srtt = heartbeat.tracker.srtt();
                                            let server_addr = self.connection.server_addr().to_string();
                                            let connected_at_secs = self.connected_at
                                                .map(|t| t.elapsed().as_secs())
                                                .unwrap_or(0);

                                            handle_unified_command(
                                                request_id,
                                                cmd,
                                                self.resource_manager.as_ref(),
                                                &conn,
                                                &server_addr,
                                                connected_at_secs,
                                                heartbeat_srtt,
                                                self.session_name.as_deref(),
                                            ).await
                                        }
                                    };

                                    if let Some(ctl) = self.control.as_mut() {
                                        if let Err(e) = ctl.send_message(client_id, response).await {
                                            tracing::warn!(error = %e, "Failed to send control response");
                                        }
                                    }
                                }
                                ControlEvent::Stream { client_id, stream } => {
                                    // Handle terminal I/O streams
                                    if stream.stream_kind == proto::StreamKind::TerminalIo as i32 {
                                        let data = stream.data;

                                        // Forward input to the terminal via attachment registry
                                        if let Err(e) = self.attachment_registry.send_input(client_id, data) {
                                            tracing::warn!(
                                                client_id,
                                                error = %e,
                                                "Failed to forward terminal input"
                                            );
                                        }
                                    }
                                }
                                ControlEvent::ClientDisconnected { client_id, error } => {
                                    if let Some(e) = error {
                                        tracing::debug!(client_id, error = %e, "Control client disconnected");
                                    } else {
                                        tracing::debug!(client_id, "Control client disconnected");
                                    }
                                    // Note: Terminal I/O uses raw Unix sockets, so clients
                                    // disconnect directly from the I/O socket. No cleanup needed here.
                                }
                            }
                        }
                    }

                    // Terminal output forwarding - messages from output_rx tasks
                    Some((client_id, message)) = self.control_output_rx.recv() => {
                        if let Some(ref mut ctl) = self.control {
                            if let Err(e) = ctl.send_message(client_id, message).await {
                                tracing::warn!(client_id, error = %e, "Failed to send terminal output to control client");
                            }
                        }
                    }
                }
            };

            // Disconnect components
            if let Some(ref mut term) = self.parts.terminal {
                term.on_disconnect();
            }
            if let Some(ref mut fwd) = self.parts.forwards {
                fwd.on_disconnect();
            }

            // Handle loop result
            match res {
                Ok(code) => {
                    // Graceful shutdown
                    if let Some(term) = self.parts.terminal.take() {
                        term.shutdown().await?;
                    }
                    if let Some(fwd) = self.parts.forwards.take() {
                        fwd.shutdown().await?;
                    }
                    return Ok(code);
                }
                Err(e) if e.is_transient() => {
                    warn!(error = %e, "Connection error, reconnecting");
                    self.connection.handle_error(&e).await;
                    continue; // Reconnect
                }
                Err(e) => return Err(e),
            }
        }
    }
}

/// Helper struct for heartbeat tracking.
struct HeartbeatState {
    tracker: HeartbeatTracker,
    next_deadline: tokio::time::Instant,
}

impl HeartbeatState {
    fn new(interval: Duration) -> Self {
        let tracker = HeartbeatTracker::new();
        Self {
            tracker,
            next_deadline: tokio::time::Instant::now() + interval,
        }
    }
}

/// Handle unified protocol commands and return a response Message.
async fn handle_unified_command(
    request_id: u32,
    cmd: crate::control::proto::command::Cmd,
    resource_manager: Option<&crate::control::ResourceManager>,
    conn: &std::sync::Arc<ChannelConnection>,
    server_addr: &str,
    connected_at: u64,
    srtt: Option<Duration>,
    session_name: Option<&str>,
) -> crate::control::Message {
    use crate::control::{proto, resource_info_to_proto, Forward, ForwardParams, ForwardType, Message, ResourceKind};

    let event_seq = 0; // TODO: Track event sequence numbers

    match cmd {
        proto::command::Cmd::ResourceCreate(create) => {
            let Some(rm) = resource_manager else {
                return command_error(request_id, event_seq, proto::ErrorCode::Unavailable, "Resource manager not available");
            };

            match create.params {
                Some(proto::resource_create::Params::Forward(params)) => {
                    // Convert proto forward type to internal type
                    let forward_type = match proto::ForwardType::try_from(params.forward_type) {
                        Ok(proto::ForwardType::Local) => ForwardType::Local,
                        Ok(proto::ForwardType::Remote) => ForwardType::Remote,
                        Ok(proto::ForwardType::Dynamic) => ForwardType::Dynamic,
                        _ => return command_error(request_id, event_seq, proto::ErrorCode::InvalidArgument, "Invalid forward type"),
                    };

                    let forward_params = ForwardParams {
                        forward_type,
                        bind_addr: if params.bind_addr.is_empty() { "127.0.0.1".to_string() } else { params.bind_addr },
                        bind_port: params.bind_port,
                        dest_host: if params.dest_host.is_empty() { None } else { Some(params.dest_host) },
                        dest_port: if params.dest_port == 0 { None } else { Some(params.dest_port) },
                    };

                    // Create and register the forward resource
                    let id = match rm.add_with_factory(ResourceKind::Forward, |id| Box::new(Forward::new(id, forward_params))).await {
                        Ok(id) => id,
                        Err(e) => return command_error(request_id, event_seq, proto::ErrorCode::Internal, &format!("Failed to create forward: {}", e)),
                    };

                    // Start the forward
                    if let Err(e) = rm.start(&id, conn.clone()).await {
                        // Clean up on failure
                        let _ = rm.close(&id).await;
                        return command_error(request_id, event_seq, proto::ErrorCode::BindFailed, &format!("Failed to start forward: {}", e));
                    }

                    // Get the resource info to return
                    if let Some(info) = rm.describe(&id).await {
                        return Message {
                            kind: Some(proto::message::Kind::Event(proto::Event {
                                event_seq,
                                evt: Some(proto::event::Evt::CommandResult(proto::CommandResult {
                                    request_id,
                                    result: Some(proto::command_result::Result::Ok(proto::CommandOk {
                                        data: Some(proto::command_ok::Data::ResourceCreated(
                                            proto::ResourceCreateResult {
                                                resource_id: id,
                                                info: Some(resource_info_to_proto(&info)),
                                            },
                                        )),
                                    })),
                                })),
                            })),
                        };
                    }

                    command_error(request_id, event_seq, proto::ErrorCode::Internal, "Forward created but info unavailable")
                }
                Some(proto::resource_create::Params::Terminal(params)) => {
                    use crate::control::resources::Terminal;
                    use qsh_core::protocol::OutputMode;

                    // Convert protobuf output mode to core enum
                    let output_mode = match proto::OutputMode::try_from(params.output_mode) {
                        Ok(proto::OutputMode::Mosh) => OutputMode::Mosh,
                        Ok(proto::OutputMode::StateDiff) => OutputMode::StateDiff,
                        Ok(proto::OutputMode::Direct) | Ok(proto::OutputMode::Unspecified) | Err(_) => OutputMode::Direct,
                    };

                    // Create the terminal resource
                    let terminal = Terminal::from_params(
                        String::new(), // ID will be assigned by add_with_factory
                        if params.cols > 0 { Some(params.cols) } else { None },
                        if params.rows > 0 { Some(params.rows) } else { None },
                        if params.term_type.is_empty() { None } else { Some(params.term_type) },
                        if params.shell.is_empty() { None } else { Some(params.shell) },
                        if params.command.is_empty() { None } else { Some(params.command) },
                        params.env.into_iter().map(|e| (e.key, e.value)).collect(),
                        output_mode,
                        params.allocate_pty,
                    );

                    // Get session directory for terminal I/O socket
                    let sess_dir = session_name
                        .map(|name| crate::control::session_dir(name))
                        .unwrap_or_else(|| std::path::PathBuf::from("/tmp"));

                    // Register with manager
                    let id = match rm.add_with_factory(ResourceKind::Terminal, |id| {
                        let mut t = terminal;
                        t.set_id(id.to_string());
                        Box::new(t)
                    }).await {
                        Ok(id) => id,
                        Err(e) => return command_error(request_id, event_seq, proto::ErrorCode::Internal, &format!("Failed to create terminal: {}", e)),
                    };

                    // Set session directory on the terminal for I/O socket
                    if let Err(e) = rm.terminal_set_session_dir(&id, sess_dir).await {
                        tracing::warn!(error = %e, "Failed to set terminal session dir");
                    }

                    // Start the terminal
                    if let Err(e) = rm.start(&id, conn.clone()).await {
                        let _ = rm.close(&id).await;
                        return command_error(request_id, event_seq, proto::ErrorCode::Internal, &format!("Failed to start terminal: {}", e));
                    }

                    // Get the resource info to return
                    if let Some(info) = rm.describe(&id).await {
                        return Message {
                            kind: Some(proto::message::Kind::Event(proto::Event {
                                event_seq,
                                evt: Some(proto::event::Evt::CommandResult(proto::CommandResult {
                                    request_id,
                                    result: Some(proto::command_result::Result::Ok(proto::CommandOk {
                                        data: Some(proto::command_ok::Data::ResourceCreated(
                                            proto::ResourceCreateResult {
                                                resource_id: id,
                                                info: Some(resource_info_to_proto(&info)),
                                            },
                                        )),
                                    })),
                                })),
                            })),
                        };
                    }

                    command_error(request_id, event_seq, proto::ErrorCode::Internal, "Terminal created but info unavailable")
                }
                Some(proto::resource_create::Params::FileTransfer(_params)) => {
                    // File transfer creation - not yet implemented
                    command_error(request_id, event_seq, proto::ErrorCode::Unspecified, "File transfer creation not yet implemented")
                }
                None => {
                    command_error(request_id, event_seq, proto::ErrorCode::InvalidArgument, "Missing resource create params")
                }
            }
        }

        proto::command::Cmd::Status(_) => {
            let resource_count = if let Some(ref rm) = resource_manager {
                rm.list(None).await.len() as u32
            } else {
                0
            };

            Message {
                kind: Some(proto::message::Kind::Event(proto::Event {
                    event_seq,
                    evt: Some(proto::event::Evt::CommandResult(proto::CommandResult {
                        request_id,
                        result: Some(proto::command_result::Result::Ok(proto::CommandOk {
                            data: Some(proto::command_ok::Data::Status(proto::StatusResult {
                                state: "connected".to_string(),
                                server_addr: server_addr.to_string(),
                                uptime_secs: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_secs().saturating_sub(connected_at))
                                    .unwrap_or(0),
                                bytes_sent: 0,     // TODO
                                bytes_received: 0, // TODO
                                rtt_ms: srtt.map(|d| d.as_millis() as u32).unwrap_or(0),
                                resource_count,
                            })),
                        })),
                    })),
                })),
            }
        }

        proto::command::Cmd::Ping(ping) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);

            Message {
                kind: Some(proto::message::Kind::Event(proto::Event {
                    event_seq,
                    evt: Some(proto::event::Evt::CommandResult(proto::CommandResult {
                        request_id,
                        result: Some(proto::command_result::Result::Ok(proto::CommandOk {
                            data: Some(proto::command_ok::Data::Pong(proto::PongResult {
                                timestamp: ping.timestamp,
                                server_time: now,
                            })),
                        })),
                    })),
                })),
            }
        }

        proto::command::Cmd::ResourceList(list) => {
            let kind_filter = match proto::ResourceKind::try_from(list.kind) {
                Ok(proto::ResourceKind::Terminal) => Some(ResourceKind::Terminal),
                Ok(proto::ResourceKind::Forward) => Some(ResourceKind::Forward),
                Ok(proto::ResourceKind::FileTransfer) => Some(ResourceKind::FileTransfer),
                _ => None,
            };

            let resources = if let Some(ref rm) = resource_manager {
                rm.list(kind_filter)
                    .await
                    .into_iter()
                    .map(|info| resource_info_to_proto(&info))
                    .collect()
            } else {
                vec![]
            };

            Message {
                kind: Some(proto::message::Kind::Event(proto::Event {
                    event_seq,
                    evt: Some(proto::event::Evt::CommandResult(proto::CommandResult {
                        request_id,
                        result: Some(proto::command_result::Result::Ok(proto::CommandOk {
                            data: Some(proto::command_ok::Data::ResourceList(
                                proto::ResourceListResult { resources },
                            )),
                        })),
                    })),
                })),
            }
        }

        proto::command::Cmd::ResourceDescribe(describe) => {
            if let Some(ref rm) = resource_manager {
                if let Some(info) = rm.describe(&describe.resource_id).await {
                    return Message {
                        kind: Some(proto::message::Kind::Event(proto::Event {
                            event_seq,
                            evt: Some(proto::event::Evt::CommandResult(proto::CommandResult {
                                request_id,
                                result: Some(proto::command_result::Result::Ok(proto::CommandOk {
                                    data: Some(proto::command_ok::Data::ResourceDescribe(
                                        proto::ResourceDescribeResult {
                                            info: Some(resource_info_to_proto(&info)),
                                        },
                                    )),
                                })),
                            })),
                        })),
                    };
                }
            }

            command_error(request_id, event_seq, proto::ErrorCode::NotFound, "Resource not found")
        }

        proto::command::Cmd::ResourceClose(close) => {
            if let Some(ref rm) = resource_manager {
                if rm.close(&close.resource_id).await.is_ok() {
                    return Message {
                        kind: Some(proto::message::Kind::Event(proto::Event {
                            event_seq,
                            evt: Some(proto::event::Evt::CommandResult(proto::CommandResult {
                                request_id,
                                result: Some(proto::command_result::Result::Ok(proto::CommandOk {
                                    data: None,
                                })),
                            })),
                        })),
                    };
                }
            }

            command_error(request_id, event_seq, proto::ErrorCode::NotFound, "Resource not found")
        }

        // TerminalAttach, TerminalDetach, TerminalResize are handled directly in Session
        // since they need access to the attachment registry
        proto::command::Cmd::TerminalAttach(_)
        | proto::command::Cmd::TerminalDetach(_)
        | proto::command::Cmd::TerminalResize(_) => {
            unreachable!("Terminal attachment commands are handled in Session::handle_terminal_*")
        }

        // Commands not yet implemented
        _ => command_error(
            request_id,
            event_seq,
            proto::ErrorCode::Unspecified,
            "Command not implemented",
        ),
    }
}

/// Helper to create a command error response.
fn command_error(
    request_id: u32,
    event_seq: u64,
    code: crate::control::proto::ErrorCode,
    message: &str,
) -> crate::control::Message {
    use crate::control::proto;

    crate::control::Message {
        kind: Some(proto::message::Kind::Event(proto::Event {
            event_seq,
            evt: Some(proto::event::Evt::CommandResult(proto::CommandResult {
                request_id,
                result: Some(proto::command_result::Result::Error(proto::CommandError {
                    code: code.into(),
                    message: message.to_string(),
                    details: String::new(),
                })),
            })),
        })),
    }
}
