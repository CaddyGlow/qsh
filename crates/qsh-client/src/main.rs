//! qsh client binary entry point.
//!
//! Modern roaming-capable remote terminal client.

use std::net::ToSocketAddrs;
use std::time::Duration;

use clap::Parser;
use tokio::time::MissedTickBehavior;
use tracing::{debug, error, info, trace, warn};

use qsh_client::cli::{NotificationStyle as CliNotificationStyle, SshBootstrapMode};
use qsh_client::overlay::{NotificationEngine, NotificationStyle, PredictionOverlay};
use qsh_client::prediction::{DisplayPreference, Prediction};
use qsh_client::render::StateRenderer;
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
use qsh_core::transport::{Connection, TransportSender};

#[cfg(feature = "standalone")]
use qsh_client::standalone::authenticate as standalone_authenticate;
#[cfg(feature = "standalone")]
use qsh_client::{DirectAuthenticator, DirectConfig, establish_quic_connection};

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

    match result {
        Ok(exit_code) => std::process::exit(exit_code),
        Err(e) => {
            error!(error = %e, "Connection failed");
            eprintln!("qsh: {}", e);
            std::process::exit(1);
        }
    }
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
    let ssh_config = SshConfig {
        connect_timeout: std::time::Duration::from_secs(30),
        identity_file: cli.identity.first().cloned(),
        skip_host_key_check: false,
        port_range: cli.bootstrap_port_range,
        server_env: cli.parse_bootstrap_server_env()?,
        server_args: if server_args.is_empty() {
            None
        } else {
            Some(server_args)
        },
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
        local_port: Some(random_local_port()), // Mosh-style port range
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

/// Convert CLI notification style to overlay module style.
fn map_notification_style(cli_style: CliNotificationStyle) -> NotificationStyle {
    match cli_style {
        CliNotificationStyle::Minimal => NotificationStyle::Minimal,
        CliNotificationStyle::Enhanced => NotificationStyle::Enhanced,
    }
}
