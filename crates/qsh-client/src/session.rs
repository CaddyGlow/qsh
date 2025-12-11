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
        todo!("Select over terminal event sources")
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
}

impl Session {
    pub fn new(connection: std::sync::Arc<ReconnectableConnection>, parts: SessionParts) -> Self {
        Self { connection, parts }
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
            Some(TerminalComponent::new(cli, user_host)?)
        } else {
            None
        };

        let forwards = if has_forwards {
            Some(ForwardComponent::new(cli)?)
        } else {
            None
        };

        // Validate configuration
        if is_forward_only && !has_forwards {
            return Err(qsh_core::Error::Protocol {
                message: "Forward-only mode (-N) requires at least one forward".to_string(),
            });
        }

        Ok(Self::new(connection, SessionParts { terminal, forwards }))
    }

    /// Run the unified session event loop.
    pub async fn run(mut self) -> Result<i32> {
        use tracing::{debug, info, trace, warn};

        loop {
            let conn = self.connection.wait_connected().await?;

            // Initialize components
            if let Some(ref mut term) = self.parts.terminal {
                term.on_connect(&conn).await?;
            }
            if let Some(ref mut fwd) = self.parts.forwards {
                fwd.on_connect(&conn).await?;
            }

            let mut heartbeat = HeartbeatState::new(Duration::from_secs(1));

            // Unified event loop
            let res: Result<i32> = loop {
                tokio::select! {
                    biased;

                    // Ctrl+C handler
                    _ = tokio::signal::ctrl_c() => {
                        info!("Shutting down...");
                        break Ok(0);
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
                        // TODO: Handle terminal events
                        debug!(?ev, "Terminal event");
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
