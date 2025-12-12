//! CLI types and struct definitions.

use std::path::PathBuf;
#[cfg(feature = "tunnel")]
use std::str::FromStr;

use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use qsh_core::protocol::OutputMode;

/// Log output format for CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum CliLogFormat {
    /// Human-readable text output.
    #[default]
    Text,
    /// Structured JSON output.
    Json,
}

impl From<CliLogFormat> for qsh_core::LogFormat {
    fn from(fmt: CliLogFormat) -> Self {
        match fmt {
            CliLogFormat::Text => qsh_core::LogFormat::Text,
            CliLogFormat::Json => qsh_core::LogFormat::Json,
        }
    }
}

/// Overlay placement for the status widget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum OverlayPosition {
    #[default]
    Top,
    Bottom,
    #[clap(name = "top-right")]
    TopRight,
    None,
}

/// Notification bar display style.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum NotificationStyle {
    /// Mosh-compatible minimal display.
    /// Only shows on timeout/errors with "Last contact Xs ago" format.
    #[default]
    Minimal,
    /// Enhanced display with RTT and metrics when visible.
    Enhanced,
}

/// SSH bootstrap implementation to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SshBootstrapMode {
    /// Use the system `ssh` client.
    #[clap(name = "ssh")]
    Ssh,
    /// Use the Rust `russh` client.
    #[clap(name = "russh")]
    Russh,
}

/// Connect mode argument for CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum ConnectModeArg {
    /// Initiate connection: actively connect to a listening peer (default)
    #[default]
    Initiate,
    /// Respond mode: listen for and accept connections from an initiating peer
    Respond,
}

impl From<ConnectModeArg> for qsh_core::ConnectMode {
    fn from(arg: ConnectModeArg) -> Self {
        match arg {
            ConnectModeArg::Initiate => qsh_core::ConnectMode::Initiate,
            ConnectModeArg::Respond => qsh_core::ConnectMode::Respond,
        }
    }
}

/// Prediction mode for local echo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum PredictionMode {
    /// Adaptive: Show predictions based on RTT thresholds (mosh-style).
    /// Uses SRTT triggers: show predictions when RTT > 30ms,
    /// underline when RTT > 80ms or glitches occur.
    #[default]
    Adaptive,
    /// Always show predictions with underline styling.
    Always,
    /// Experimental: Always predict with mosh-style cell tracking.
    /// More aggressive prediction with position-based validation.
    Experimental,
    /// Disable prediction entirely.
    Off,
}

/// Tunnel argument with optional IP assignment (feature-gated).
#[cfg(feature = "tunnel")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelArg {
    Auto,
    Address(String),
}

#[cfg(feature = "tunnel")]
impl FromStr for TunnelArg {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("auto") {
            Ok(TunnelArg::Auto)
        } else if s.is_empty() {
            Err("tunnel IP must not be empty".to_string())
        } else {
            Ok(TunnelArg::Address(s.to_string()))
        }
    }
}

// Import terminal types from terminal module to avoid duplication
pub use super::terminal::{
    TerminalAction, TerminalAddArgs, TerminalAttachArgs, TerminalCloseArgs, TerminalCommand,
    TerminalDetachArgs, TerminalResizeArgs,
};

/// Control subcommands for managing existing qsh sessions.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Manage port forwards
    Forward(ForwardCommand),
    /// Manage terminals
    Terminal(TerminalCommand),
    /// Query session status
    Status(StatusArgs),
    /// Interactive control REPL
    Ctl(CtlArgs),
    /// List active sessions
    Sessions,
}

/// Port forward subcommands.
#[derive(Debug, Parser)]
pub struct ForwardCommand {
    #[command(subcommand)]
    pub action: ForwardAction,
}

/// Forward actions.
#[derive(Debug, Subcommand)]
pub enum ForwardAction {
    /// Add a new port forward
    Add(ForwardAddArgs),
    /// List active port forwards
    List,
    /// Remove a port forward
    Remove(ForwardRemoveArgs),
    /// Gracefully drain a forward (stop accepting new connections, wait for in-flight to complete)
    Drain(ForwardDrainArgs),
    /// Close a forward immediately
    Close(ForwardCloseArgs),
    /// Force close a forward (ignore errors)
    ForceClose(ForwardForceCloseArgs),
}

/// Arguments for adding a port forward.
#[derive(Debug, Parser)]
pub struct ForwardAddArgs {
    /// Local forward: [bind_addr:]port:host:hostport
    /// Binds locally and forwards to remote target through the server.
    #[arg(short = 'L', long = "local", value_name = "SPEC", group = "forward_type")]
    pub local: Option<String>,

    /// Remote forward: [bind_addr:]port:host:hostport
    /// Server binds and forwards to local target.
    #[arg(short = 'R', long = "remote", value_name = "SPEC", group = "forward_type")]
    pub remote: Option<String>,

    /// Dynamic SOCKS5 forward: [bind_addr:]port
    /// Creates a SOCKS5 proxy.
    #[arg(short = 'D', long = "dynamic", value_name = "SPEC", group = "forward_type")]
    pub dynamic: Option<String>,
}

/// Arguments for removing a port forward.
#[derive(Debug, Parser)]
pub struct ForwardRemoveArgs {
    /// Forward ID to remove
    #[arg(value_name = "ID")]
    pub forward_id: String,
}

/// Arguments for draining a port forward.
#[derive(Debug, Parser)]
pub struct ForwardDrainArgs {
    /// Forward ID to drain
    #[arg(value_name = "ID")]
    pub forward_id: String,

    /// Drain timeout in seconds (default: 30)
    #[arg(short = 't', long = "timeout", value_name = "SECS")]
    pub timeout: Option<u64>,
}

/// Arguments for closing a port forward.
#[derive(Debug, Parser)]
pub struct ForwardCloseArgs {
    /// Forward ID to close
    #[arg(value_name = "ID")]
    pub forward_id: String,
}

/// Arguments for force-closing a port forward.
#[derive(Debug, Parser)]
pub struct ForwardForceCloseArgs {
    /// Forward ID to force close
    #[arg(value_name = "ID")]
    pub forward_id: String,
}

/// Arguments for status query.
#[derive(Debug, Parser)]
pub struct StatusArgs {
    /// Show detailed information
    #[arg(short = 'd', long)]
    pub detailed: bool,
}

/// Arguments for interactive REPL.
#[derive(Debug, Parser)]
pub struct CtlArgs {
    // No arguments for now
}

/// Modern roaming-capable remote terminal.
#[derive(Debug, Parser)]
#[command(
    name = "qsh",
    version,
    about = "Modern roaming-capable remote terminal"
)]
pub struct Cli {
    /// Control subcommand (forward, status, ctl, sessions)
    #[command(subcommand)]
    pub subcommand: Option<Command>,

    /// Remote host (user@host or host)
    pub destination: Option<String>,

    /// Command to execute on remote host (optional)
    #[arg(trailing_var_arg = true)]
    pub command: Vec<String>,

    /// Session name for control socket (default: auto-discover latest)
    #[arg(short = 'S', long = "session", global = true, value_name = "NAME")]
    pub session: Option<String>,

    /// SSH port to connect to
    #[arg(short = 'p', long, default_value_t = 22)]
    pub port: u16,

    /// SSH bootstrap implementation to use
    #[arg(long = "ssh-bootstrap-mode", default_value = "ssh", value_enum)]
    pub ssh_bootstrap_mode: SshBootstrapMode,

    /// Login user name (overrides user@ in destination)
    #[arg(short = 'l', long, value_name = "USER")]
    pub login: Option<String>,

    /// Local port forward: [bind_addr:]port:host:hostport
    #[arg(short = 'L', long = "local", action = ArgAction::Append, value_name = "SPEC")]
    pub local_forward: Vec<String>,

    /// Remote port forward: [bind_addr:]port:host:hostport
    #[arg(short = 'R', long = "remote", action = ArgAction::Append, value_name = "SPEC")]
    pub remote_forward: Vec<String>,

    /// Dynamic SOCKS5 forward: [bind_addr:]port
    #[arg(short = 'D', long = "dynamic", action = ArgAction::Append, value_name = "SPEC")]
    pub dynamic_forward: Vec<String>,

    /// Enable IP tunnel (optional IP/MASK, Linux-only)
    #[cfg(feature = "tunnel")]
    #[arg(
        long = "tun",
        value_name = "IP/MASK",
        num_args = 0..=1,
        default_missing_value = "auto",
        require_equals = true
    )]
    pub tunnel: Option<TunnelArg>,

    /// Route subnet through tunnel (repeatable)
    #[cfg(feature = "tunnel")]
    #[arg(long = "route", value_name = "CIDR", action = ArgAction::Append)]
    pub route: Vec<String>,

    /// Tunnel MTU
    #[cfg(feature = "tunnel")]
    #[arg(long = "tun-mtu", default_value_t = 1280)]
    pub tun_mtu: u16,

    /// Do not allocate a pseudo-terminal
    #[arg(short = 'N', long = "no-pty", conflicts_with = "force_pty")]
    pub no_pty: bool,

    /// Go to background after authentication
    #[arg(short = 'f', long = "background")]
    pub background: bool,

    /// Force PTY allocation
    #[arg(short = 't', conflicts_with_all = ["no_pty", "disable_pty"])]
    pub force_pty: bool,

    /// Disable PTY allocation
    #[arg(short = 'T', conflicts_with_all = ["force_pty"])]
    pub disable_pty: bool,

    /// Increase verbosity (can be repeated: -v, -vv, -vvv)
    #[arg(short = 'v', long = "verbose", action = ArgAction::Count)]
    pub verbose: u8,

    /// Log to file instead of stderr
    #[arg(long = "log-file", value_name = "PATH")]
    pub log_file: Option<PathBuf>,

    /// Log output format
    #[arg(long = "log-format", default_value = "text")]
    pub log_format: CliLogFormat,

    /// Identity file for authentication
    #[arg(short = 'i', long = "identity", action = ArgAction::Append, value_name = "FILE")]
    pub identity: Vec<PathBuf>,

    /// SSH config file
    #[arg(short = 'F', long = "config", value_name = "FILE")]
    pub config_file: Option<PathBuf>,

    /// SSH-style options (repeatable)
    #[arg(short = 'o', value_name = "OPTION", action = ArgAction::Append)]
    pub ssh_option: Vec<String>,

    /// Enable compression
    #[arg(short = 'C', long = "compress")]
    pub compress: bool,

    /// Port range to request for bootstrap QUIC listener (START-END)
    #[arg(
        long = "bootstrap-port-range",
        value_parser = super::parsing::parse_port_range,
        value_name = "START-END"
    )]
    pub bootstrap_port_range: Option<(u16, u16)>,

    /// Additional arguments to pass to `qsh-server --bootstrap` (quoted as a single string)
    #[arg(
        long = "bootstrap-server-args",
        value_name = "ARGS",
        allow_hyphen_values = true
    )]
    pub bootstrap_server_args: Option<String>,

    /// Environment variables to pass to `qsh-server --bootstrap` (repeatable VAR=VALUE)
    #[arg(
        long = "bootstrap-server-env",
        action = ArgAction::Append,
        value_name = "VAR=VALUE"
    )]
    pub bootstrap_server_env: Vec<String>,

    /// Force predictive echo off (safer for password prompts)
    /// Shorthand for --prediction=off
    #[arg(long = "no-prediction", conflicts_with = "prediction_mode")]
    pub no_prediction: bool,

    /// Prediction mode for local echo
    #[arg(long = "prediction", value_enum, default_value = "adaptive")]
    pub prediction_mode: PredictionMode,

    /// Show connection status overlay
    #[arg(long = "status")]
    pub show_status: bool,

    /// Overlay position
    #[arg(long = "overlay-position", default_value = "top")]
    pub overlay_position: OverlayPosition,

    /// Disable status overlay
    #[arg(long = "no-overlay")]
    pub no_overlay: bool,

    /// Custom overlay toggle key
    #[arg(
        long = "overlay-key",
        default_value = "ctrl+shift+o",
        value_name = "KEY"
    )]
    pub overlay_key: String,

    /// Escape key for client commands (e.g., ctrl+^ then . to disconnect).
    /// Use "none" to disable escape sequences.
    #[arg(long = "escape-key", default_value = "ctrl+^", value_name = "KEY")]
    pub escape_key: String,

    // === TransportSender (Mosh-style keystroke batching) ===
    /// Minimum delay before sending input (milliseconds).
    /// Mosh uses 1ms for client, allowing very short coalescing windows.
    #[arg(long = "send-mindelay", default_value = "1", value_name = "MS")]
    pub send_mindelay_ms: u64,

    /// Terminal output mode (direct/mosh/statediff)
    #[arg(long = "mode", value_enum, conflicts_with = "no_batching")]
    pub output_mode: Option<OutputMode>,

    /// Disable output batching on server (deprecated - use --mode=direct)
    #[arg(long = "no-batching", conflicts_with = "output_mode")]
    pub no_batching: bool,

    /// Minimum send interval (milliseconds).
    /// Mosh uses 20ms as the floor for adaptive timing.
    #[arg(long = "send-interval-min", default_value = "20", value_name = "MS")]
    pub send_interval_min_ms: u64,

    /// Maximum send interval (milliseconds).
    /// Mosh uses 250ms as the ceiling for adaptive timing.
    #[arg(long = "send-interval-max", default_value = "250", value_name = "MS")]
    pub send_interval_max_ms: u64,

    /// Paste detection threshold (bytes).
    /// Input larger than this resets prediction and flushes immediately.
    #[arg(long = "paste-threshold", default_value = "100", value_name = "BYTES")]
    pub paste_threshold: usize,

    /// Notification bar display style (mosh-style auto-showing bar).
    #[arg(long = "notification-style", value_enum, default_value = "minimal")]
    pub notification_style: NotificationStyle,

    /// QUIC keep-alive interval in milliseconds (0 disables).
    #[arg(
        long = "keep-alive",
        default_value = "500",
        value_name = "MILLISECONDS"
    )]
    pub keep_alive_ms: u64,

    /// QUIC max idle timeout in seconds (connection closes after this).
    #[arg(
        long = "max-idle-timeout",
        default_value = "15",
        value_name = "SECONDS"
    )]
    pub max_idle_timeout_secs: u64,

    /// Connection timeout in seconds (per connection attempt).
    #[arg(long = "connect-timeout", default_value = "5", value_name = "SECONDS")]
    pub connect_timeout_secs: u64,

    /// Connection mode: 'initiate' to connect to peer (default), 'respond' to listen for peer (used with --bootstrap)
    #[arg(long = "connect-mode", default_value = "initiate", value_enum)]
    pub connect_mode: ConnectModeArg,

    // Direct/standalone mode options (feature-gated)
    /// Connect directly to server (skip SSH bootstrap)
    #[cfg(feature = "standalone")]
    #[arg(long = "direct")]
    pub direct: bool,

    /// Server address for direct mode (host:port)
    #[cfg(feature = "standalone")]
    #[arg(long = "server", value_name = "HOST:PORT")]
    pub server: Option<String>,

    /// Path to client private key for direct mode
    #[cfg(feature = "standalone")]
    #[arg(long = "key", value_name = "PATH")]
    pub key: Option<PathBuf>,

    /// Path to known_hosts file for direct mode
    #[cfg(feature = "standalone")]
    #[arg(long = "known-hosts", value_name = "PATH")]
    pub known_hosts: Option<PathBuf>,

    /// Accept unknown host keys (TOFU - Trust On First Use)
    #[cfg(feature = "standalone")]
    #[arg(long = "accept-unknown-host")]
    pub accept_unknown_host: bool,

    /// Disable SSH agent for key operations
    #[cfg(feature = "standalone")]
    #[arg(long = "no-agent")]
    pub no_agent: bool,

    /// Run as bootstrap responder: generate session key, bind QUIC listener, output JSON connection info, and wait for one connection (invoked by remote qsh-server in reverse mode)
    #[arg(long = "bootstrap", conflicts_with = "destination")]
    pub bootstrap: bool,

    /// Bootstrap mode timeout in seconds (default: 30)
    #[arg(long = "bootstrap-timeout", default_value = "30", value_name = "SECONDS")]
    pub bootstrap_timeout_secs: u64,

    /// Bootstrap mode bind IP (default: 0.0.0.0)
    #[arg(long = "bootstrap-bind-ip", default_value = "0.0.0.0", value_name = "IP")]
    pub bootstrap_bind_ip: String,

    /// Attach to a bootstrap session via named pipe.
    /// The pipe path is output in the bootstrap JSON response.
    #[arg(
        long = "attach",
        value_name = "PIPE",
        num_args = 0..=1,
        default_missing_value = "",
        conflicts_with_all = ["destination", "bootstrap"]
    )]
    pub attach: Option<String>,
}

impl Cli {
    /// Get the requested output mode, handling backward compatibility with --no-batching.
    pub fn output_mode(&self) -> OutputMode {
        if let Some(mode) = self.output_mode {
            mode
        } else if self.no_batching {
            OutputMode::Direct
        } else {
            OutputMode::Direct // Default to direct mode
        }
    }

    /// Parse bootstrap server env assignments (VAR=VALUE).
    pub fn parse_bootstrap_server_env(&self) -> qsh_core::Result<Vec<(String, String)>> {
        self.bootstrap_server_env
            .iter()
            .map(|s| parse_env_assignment(s))
            .collect()
    }
}

fn parse_env_assignment(s: &str) -> qsh_core::Result<(String, String)> {
    if let Some((k, v)) = s.split_once('=') {
        if k.is_empty() {
            return Err(qsh_core::Error::Transport {
                message: "env var key cannot be empty".to_string(),
            });
        }
        Ok((k.to_string(), v.to_string()))
    } else {
        Err(qsh_core::Error::Transport {
            message: format!("invalid env assignment (expected VAR=VALUE): {}", s),
        })
    }
}

// =============================================================================
// File Transfer CLI (qscp)
// =============================================================================

/// File transfer command (qscp).
#[derive(Debug, Parser)]
#[command(
    name = "qscp",
    version,
    about = "Copy files to/from remote hosts via qsh"
)]
pub struct CpCli {
    /// Source path ([user@]host:path or local path)
    #[arg(required = true)]
    pub source: String,

    /// Destination path ([user@]host:path or local path)
    #[arg(required = true)]
    pub dest: String,

    /// Recursive copy (directories)
    #[arg(short = 'r', long)]
    pub recursive: bool,

    /// Disable delta sync (always transfer full files)
    #[arg(long = "no-delta")]
    pub no_delta: bool,

    /// Disable compression
    #[arg(long = "no-compress")]
    pub no_compress: bool,

    /// Resume interrupted transfer
    #[arg(long = "resume")]
    pub resume: bool,

    /// Skip transfer if file is already up to date (size + mtime + hash match)
    #[arg(long = "skip-if-unchanged", short = 'u')]
    pub skip_if_unchanged: bool,

    /// Number of parallel transfers
    #[arg(short = 'j', long = "parallel", default_value = "4")]
    pub parallel: usize,

    /// Preserve file permissions
    #[arg(short = 'p', long = "preserve")]
    pub preserve: bool,

    /// SSH port
    #[arg(short = 'P', long = "port", default_value = "22")]
    pub port: u16,

    /// Increase verbosity
    #[arg(short = 'v', long = "verbose", action = ArgAction::Count)]
    pub verbose: u8,

    /// Log to file
    #[arg(long = "log-file", value_name = "PATH")]
    pub log_file: Option<PathBuf>,

    /// Identity file
    #[arg(short = 'i', long = "identity", action = ArgAction::Append)]
    pub identity: Vec<PathBuf>,

    // Direct mode options
    #[cfg(feature = "standalone")]
    #[arg(long = "direct")]
    pub direct: bool,

    #[cfg(feature = "standalone")]
    #[arg(long = "server", value_name = "HOST:PORT")]
    pub server: Option<String>,

    #[cfg(feature = "standalone")]
    #[arg(long = "key", value_name = "PATH")]
    pub key: Option<PathBuf>,

    #[cfg(feature = "standalone")]
    #[arg(long = "known-hosts", value_name = "PATH")]
    pub known_hosts: Option<PathBuf>,

    #[cfg(feature = "standalone")]
    #[arg(long = "accept-unknown-host")]
    pub accept_unknown_host: bool,

    #[cfg(feature = "standalone")]
    #[arg(long = "no-agent")]
    pub no_agent: bool,
}
