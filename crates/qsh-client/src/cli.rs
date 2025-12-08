//! Client CLI implementation.
//!
//! Provides command-line argument parsing using clap.

#[cfg(feature = "tunnel")]
use std::str::FromStr;
use std::{borrow::Cow, path::PathBuf};

use clap::{ArgAction, Parser, ValueEnum};

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

/// Modern roaming-capable remote terminal.
#[derive(Debug, Parser)]
#[command(
    name = "qsh",
    version,
    about = "Modern roaming-capable remote terminal"
)]
pub struct Cli {
    /// Remote host (user@host or host)
    #[arg(required_unless_present = "version")]
    pub destination: Option<String>,

    /// Command to execute on remote host (optional)
    #[arg(trailing_var_arg = true)]
    pub command: Vec<String>,

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
        value_parser = parse_port_range,
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
}

impl Cli {
    /// Parse the destination into user and host components.
    pub fn parse_destination(&self) -> Option<(Option<&str>, &str)> {
        let dest = self.destination.as_ref()?;

        if let Some(at_pos) = dest.find('@') {
            let user = &dest[..at_pos];
            let host = &dest[at_pos + 1..];
            Some((Some(user), host))
        } else {
            Some((None, dest.as_str()))
        }
    }

    /// Get the effective user (from -l option or destination).
    pub fn effective_user(&self) -> Option<&str> {
        if let Some(ref login) = self.login {
            return Some(login.as_str());
        }
        self.parse_destination()?.0
    }

    /// Get the host from the destination.
    pub fn host(&self) -> Option<&str> {
        self.parse_destination().map(|(_, host)| host)
    }

    /// QUIC keep-alive interval (None disables).
    pub fn keep_alive_interval(&self) -> Option<std::time::Duration> {
        if self.keep_alive_ms == 0 {
            None
        } else {
            Some(std::time::Duration::from_millis(self.keep_alive_ms))
        }
    }

    /// QUIC max idle timeout.
    pub fn max_idle_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.max_idle_timeout_secs)
    }

    /// Connection timeout (per attempt).
    pub fn connect_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.connect_timeout_secs)
    }

    /// Get the command to execute, if any, shell-escaped for remote execution.
    pub fn command_string(&self) -> Option<String> {
        if self.command.is_empty() {
            None
        } else {
            Some(
                self.command
                    .iter()
                    .map(|arg| shell_escape::escape(Cow::Borrowed(arg.as_str())).into_owned())
                    .collect::<Vec<_>>()
                    .join(" "),
            )
        }
    }

    /// Get the effective prediction mode, considering both --prediction and --no-prediction flags.
    pub fn effective_prediction_mode(&self) -> PredictionMode {
        if self.no_prediction {
            PredictionMode::Off
        } else {
            self.prediction_mode
        }
    }

    /// Check if prediction is enabled (any mode except Off).
    pub fn prediction_enabled(&self) -> bool {
        self.effective_prediction_mode() != PredictionMode::Off
    }

    /// Determine if PTY should be allocated based on flags and command.
    ///
    /// Follows SSH semantics:
    /// - No command + no flags -> PTY (interactive shell)
    /// - Command + no flags -> no PTY (capture output)
    /// - `-t` flag -> force PTY (interactive commands like vim)
    /// - `-T` flag -> no PTY (scripted sessions)
    /// - `-N` flag -> no PTY, no shell (forwarding only)
    pub fn should_allocate_pty(&self) -> bool {
        if self.no_pty || self.disable_pty {
            // -N or -T: explicitly no PTY
            return false;
        }
        if self.force_pty {
            // -t: force PTY even with command
            return true;
        }
        // Default: PTY for interactive shell, no PTY for commands
        self.command.is_empty()
    }

    /// Check if this is forwarding-only mode (-N with no command).
    pub fn is_forward_only(&self) -> bool {
        self.no_pty && self.command.is_empty()
    }
}

fn parse_port_range(s: &str) -> Result<(u16, u16), String> {
    let (start_str, end_str) = s
        .split_once('-')
        .ok_or_else(|| "port range must be in START-END form".to_string())?;

    let start: u16 = start_str
        .parse()
        .map_err(|e| format!("invalid start port: {}", e))?;
    let end: u16 = end_str
        .parse()
        .map_err(|e| format!("invalid end port: {}", e))?;

    if start == 0 || end == 0 {
        return Err("ports must be greater than 0".to_string());
    }
    if start > end {
        return Err("start port must be <= end port".to_string());
    }
    Ok((start, end))
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

/// Parsed file path (local or remote).
#[derive(Debug, Clone)]
pub enum FilePath {
    /// Local file path.
    Local(PathBuf),
    /// Remote file path: (user, host, path).
    Remote {
        user: Option<String>,
        host: String,
        path: String,
    },
}

impl CpCli {
    /// Parse a source/dest string into a FilePath.
    pub fn parse_path(s: &str) -> FilePath {
        // Check for remote path: [user@]host:path
        // Be careful: Windows paths like C:\foo are not remote
        if let Some(colon_pos) = s.find(':') {
            let before_colon = &s[..colon_pos];

            // Check if this looks like a remote spec (contains @ or no path separator before :)
            let is_remote = before_colon.contains('@')
                || (!before_colon.contains('/') && !before_colon.contains('\\'));

            if is_remote {
                let host_part = before_colon;
                let path = if colon_pos + 1 < s.len() {
                    s[colon_pos + 1..].to_string()
                } else {
                    String::new()
                };

                if let Some(at_pos) = host_part.find('@') {
                    let user = host_part[..at_pos].to_string();
                    let host = host_part[at_pos + 1..].to_string();
                    return FilePath::Remote {
                        user: Some(user),
                        host,
                        path,
                    };
                } else {
                    return FilePath::Remote {
                        user: None,
                        host: host_part.to_string(),
                        path,
                    };
                }
            }
        }

        FilePath::Local(PathBuf::from(s))
    }

    /// Get parsed source path.
    pub fn source_path(&self) -> FilePath {
        Self::parse_path(&self.source)
    }

    /// Get parsed destination path.
    pub fn dest_path(&self) -> FilePath {
        Self::parse_path(&self.dest)
    }

    /// Check if this is an upload (local -> remote).
    pub fn is_upload(&self) -> bool {
        matches!(self.source_path(), FilePath::Local(_))
            && matches!(self.dest_path(), FilePath::Remote { .. })
    }

    /// Check if this is a download (remote -> local).
    pub fn is_download(&self) -> bool {
        matches!(self.source_path(), FilePath::Remote { .. })
            && matches!(self.dest_path(), FilePath::Local(_))
    }

    /// Get the remote host for this transfer (host, user).
    pub fn remote_host(&self) -> Option<(String, Option<String>)> {
        match self.source_path() {
            FilePath::Remote { host, user, .. } => Some((host, user)),
            FilePath::Local(_) => match self.dest_path() {
                FilePath::Remote { host, user, .. } => Some((host, user)),
                FilePath::Local(_) => None,
            },
        }
    }

    /// Build TransferOptions from CLI args.
    pub fn transfer_options(&self) -> qsh_core::protocol::TransferOptions {
        use qsh_core::protocol::DeltaAlgo;

        // Map deprecated delta flag to delta_algo
        let delta_algo = if self.no_delta {
            DeltaAlgo::None
        } else {
            // Default to RollingStreaming for best performance
            DeltaAlgo::RollingStreaming
        };

        qsh_core::protocol::TransferOptions {
            compress: !self.no_compress,
            delta: !self.no_delta,
            delta_algo,
            recursive: self.recursive,
            preserve_mode: self.preserve,
            parallel: self.parallel.max(1),
            skip_if_unchanged: self.skip_if_unchanged,
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn verify_cli() {
        // Verify the CLI configuration is valid
        Cli::command().debug_assert();
    }

    #[test]
    fn parse_simple_destination() {
        let cli = Cli::try_parse_from(["qsh", "example.com"]).unwrap();
        assert_eq!(cli.destination, Some("example.com".to_string()));
        assert_eq!(cli.parse_destination(), Some((None, "example.com")));
        assert_eq!(cli.host(), Some("example.com"));
        assert!(cli.effective_user().is_none());
    }

    #[test]
    fn parse_user_at_host() {
        let cli = Cli::try_parse_from(["qsh", "user@example.com"]).unwrap();
        assert_eq!(cli.parse_destination(), Some((Some("user"), "example.com")));
        assert_eq!(cli.effective_user(), Some("user"));
        assert_eq!(cli.host(), Some("example.com"));
    }

    #[test]
    fn login_overrides_destination_user() {
        let cli = Cli::try_parse_from(["qsh", "-l", "admin", "user@example.com"]).unwrap();
        assert_eq!(cli.effective_user(), Some("admin"));
    }

    #[test]
    fn parse_port() {
        let cli = Cli::try_parse_from(["qsh", "-p", "2222", "example.com"]).unwrap();
        assert_eq!(cli.port, 2222);
    }

    #[test]
    fn parse_bootstrap_port_range_flag() {
        let cli = Cli::try_parse_from([
            "qsh",
            "--bootstrap-port-range",
            "15000-15100",
            "example.com",
        ])
        .unwrap();
        assert_eq!(cli.bootstrap_port_range, Some((15000, 15100)));
    }

    #[test]
    fn parse_bootstrap_port_range_invalid() {
        assert!(
            Cli::try_parse_from(["qsh", "--bootstrap-port-range", "150-100", "example.com"])
                .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "qsh",
                "--bootstrap-port-range",
                "not-a-range",
                "example.com"
            ])
            .is_err()
        );
    }

    #[test]
    fn parse_bootstrap_server_args() {
        let cli = Cli::try_parse_from([
            "qsh",
            "--bootstrap-server-args",
            "--log-file /tmp/qsh.log -vvv",
            "example.com",
        ])
        .unwrap();
        assert_eq!(
            cli.bootstrap_server_args,
            Some("--log-file /tmp/qsh.log -vvv".to_string())
        );
    }

    #[test]
    fn parse_local_forward() {
        let cli = Cli::try_parse_from(["qsh", "-L", "8080:localhost:80", "example.com"]).unwrap();
        assert_eq!(cli.local_forward, vec!["8080:localhost:80"]);
    }

    #[test]
    fn parse_multiple_forwards() {
        let cli = Cli::try_parse_from([
            "qsh",
            "-L",
            "8080:localhost:80",
            "-L",
            "9090:localhost:90",
            "-R",
            "3000:localhost:3000",
            "example.com",
        ])
        .unwrap();
        assert_eq!(cli.local_forward.len(), 2);
        assert_eq!(cli.remote_forward.len(), 1);
    }

    #[test]
    fn parse_dynamic_forward() {
        let cli = Cli::try_parse_from(["qsh", "-D", "1080", "example.com"]).unwrap();
        assert_eq!(cli.dynamic_forward, vec!["1080"]);
    }

    #[cfg(feature = "tunnel")]
    #[test]
    fn parse_tunnel_auto_ip() {
        let cli = Cli::try_parse_from(["qsh", "--tun", "example.com"]).unwrap();
        assert!(matches!(cli.tunnel, Some(TunnelArg::Auto)));
    }

    #[cfg(feature = "tunnel")]
    #[test]
    fn parse_tunnel_with_ip() {
        let cli = Cli::try_parse_from(["qsh", "--tun=10.0.0.2/24", "--route", "0.0.0.0/0", "host"])
            .unwrap();
        assert!(matches!(
            cli.tunnel,
            Some(TunnelArg::Address(ref s)) if s == "10.0.0.2/24"
        ));
        assert_eq!(cli.route, vec!["0.0.0.0/0".to_string()]);
        assert_eq!(cli.tun_mtu, 1280);
    }

    #[test]
    fn parse_verbosity() {
        let cli = Cli::try_parse_from(["qsh", "-vvv", "example.com"]).unwrap();
        assert_eq!(cli.verbose, 3);
    }

    #[test]
    fn parse_command() {
        let cli = Cli::try_parse_from(["qsh", "example.com", "ls", "-la"]).unwrap();
        assert_eq!(cli.command, vec!["ls", "-la"]);
        assert_eq!(cli.command_string(), Some("ls -la".to_string()));
    }

    #[test]
    fn command_string_preserves_spaces_with_escaping() {
        let cli = Cli::try_parse_from(["qsh", "example.com", "echo", "hi there"]).unwrap();
        assert_eq!(cli.command_string(), Some("echo 'hi there'".to_string()));
    }

    #[test]
    fn parse_no_pty() {
        let cli = Cli::try_parse_from(["qsh", "-N", "example.com"]).unwrap();
        assert!(cli.no_pty);
    }

    #[test]
    fn parse_force_pty() {
        let cli = Cli::try_parse_from(["qsh", "-t", "example.com"]).unwrap();
        assert!(cli.force_pty);
        assert!(!cli.disable_pty);
    }

    #[test]
    fn parse_disable_pty() {
        let cli = Cli::try_parse_from(["qsh", "-T", "example.com"]).unwrap();
        assert!(cli.disable_pty);
        assert!(!cli.force_pty);
    }

    #[test]
    fn parse_background() {
        let cli = Cli::try_parse_from(["qsh", "-f", "example.com"]).unwrap();
        assert!(cli.background);
    }

    #[test]
    fn parse_identity_files() {
        let cli = Cli::try_parse_from([
            "qsh",
            "-i",
            "~/.ssh/id_rsa",
            "-i",
            "~/.ssh/id_ed25519",
            "example.com",
        ])
        .unwrap();
        assert_eq!(cli.identity.len(), 2);
    }

    #[test]
    fn parse_log_format() {
        let cli = Cli::try_parse_from(["qsh", "--log-format", "json", "example.com"]).unwrap();
        assert_eq!(cli.log_format, CliLogFormat::Json);
    }

    #[test]
    fn parse_overlay_options() {
        let cli = Cli::try_parse_from([
            "qsh",
            "--overlay-position",
            "top-right",
            "--overlay-key",
            "ctrl+o",
            "--no-overlay",
            "example.com",
        ])
        .unwrap();
        assert_eq!(cli.overlay_position, OverlayPosition::TopRight);
        assert_eq!(cli.overlay_key, "ctrl+o");
        assert!(cli.no_overlay);
    }

    #[test]
    fn parse_ssh_options() {
        let cli = Cli::try_parse_from([
            "qsh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "example.com",
        ])
        .unwrap();
        assert_eq!(cli.ssh_option.len(), 2);
    }

    #[test]
    fn parse_ssh_bootstrap_mode() {
        let cli =
            Cli::try_parse_from(["qsh", "--ssh-bootstrap-mode", "russh", "example.com"]).unwrap();
        assert_eq!(cli.ssh_bootstrap_mode, SshBootstrapMode::Russh);
    }

    #[test]
    fn parse_escape_key() {
        let cli = Cli::try_parse_from(["qsh", "--escape-key", "ctrl+]", "example.com"]).unwrap();
        assert_eq!(cli.escape_key, "ctrl+]");
    }

    #[test]
    fn parse_escape_key_none() {
        let cli = Cli::try_parse_from(["qsh", "--escape-key", "none", "example.com"]).unwrap();
        assert_eq!(cli.escape_key, "none");
    }

    #[test]
    fn parse_notification_style() {
        let cli =
            Cli::try_parse_from(["qsh", "--notification-style", "enhanced", "example.com"]).unwrap();
        assert_eq!(cli.notification_style, NotificationStyle::Enhanced);

        let cli =
            Cli::try_parse_from(["qsh", "--notification-style", "minimal", "example.com"]).unwrap();
        assert_eq!(cli.notification_style, NotificationStyle::Minimal);
    }

    #[test]
    fn default_values() {
        let cli = Cli::try_parse_from(["qsh", "example.com"]).unwrap();
        assert_eq!(cli.port, 22);
        assert_eq!(cli.ssh_bootstrap_mode, SshBootstrapMode::Ssh);
        assert_eq!(cli.verbose, 0);
        assert!(!cli.no_pty);
        assert!(!cli.background);
        assert!(!cli.compress);
        assert!(!cli.no_prediction);
        assert!(!cli.show_status);
        assert_eq!(cli.log_format, CliLogFormat::Text);
        assert_eq!(cli.overlay_position, OverlayPosition::Top);
        assert_eq!(cli.overlay_key, "ctrl+shift+o");
        assert_eq!(cli.escape_key, "ctrl+^");
        assert_eq!(cli.notification_style, NotificationStyle::Minimal);
        assert!(!cli.no_overlay);
        assert!(!cli.force_pty);
        assert!(!cli.disable_pty);
        assert!(cli.ssh_option.is_empty());
        #[cfg(feature = "tunnel")]
        {
            assert!(cli.tunnel.is_none());
            assert!(cli.route.is_empty());
            assert_eq!(cli.tun_mtu, 1280);
        }
        #[cfg(feature = "standalone")]
        {
            assert!(!cli.direct);
            assert!(cli.server.is_none());
            assert!(cli.key.is_none());
            assert!(cli.known_hosts.is_none());
            assert!(!cli.accept_unknown_host);
            assert!(!cli.no_agent);
        }
    }

    // =========================================================================
    // PTY Allocation Tests
    // =========================================================================

    #[test]
    fn pty_allocation_interactive_shell() {
        // Interactive shell: PTY allocated
        let cli = Cli::try_parse_from(["qsh", "example.com"]).unwrap();
        assert!(cli.should_allocate_pty());
        assert!(!cli.is_forward_only());
    }

    #[test]
    fn pty_allocation_command_no_pty() {
        // Command without flags: no PTY (SSH semantics)
        let cli = Cli::try_parse_from(["qsh", "example.com", "ls", "-la"]).unwrap();
        assert!(!cli.should_allocate_pty());
        assert!(!cli.is_forward_only());
    }

    #[test]
    fn pty_allocation_force_pty_with_command() {
        // -t flag forces PTY even with command
        let cli = Cli::try_parse_from(["qsh", "-t", "example.com", "vim", "file.txt"]).unwrap();
        assert!(cli.should_allocate_pty());
        assert!(!cli.is_forward_only());
    }

    #[test]
    fn pty_allocation_disable_pty() {
        // -T flag disables PTY for interactive shell
        let cli = Cli::try_parse_from(["qsh", "-T", "example.com"]).unwrap();
        assert!(!cli.should_allocate_pty());
        assert!(!cli.is_forward_only());
    }

    #[test]
    fn pty_allocation_forward_only() {
        // -N flag: no PTY, no shell, forwarding only
        let cli = Cli::try_parse_from(["qsh", "-N", "example.com"]).unwrap();
        assert!(!cli.should_allocate_pty());
        assert!(cli.is_forward_only());
    }

    #[test]
    fn pty_allocation_forward_only_with_forward() {
        // -N with local forward: forwarding only mode
        let cli =
            Cli::try_parse_from(["qsh", "-N", "-L", "8080:localhost:80", "example.com"]).unwrap();
        assert!(!cli.should_allocate_pty());
        assert!(cli.is_forward_only());
    }

    // =========================================================================
    // CpCli Tests
    // =========================================================================

    #[test]
    fn verify_cp_cli() {
        CpCli::command().debug_assert();
    }

    #[test]
    fn cp_parse_local_path() {
        let path = CpCli::parse_path("/home/user/file.txt");
        assert!(matches!(path, FilePath::Local(p) if p.to_str() == Some("/home/user/file.txt")));
    }

    #[test]
    fn cp_parse_remote_path_with_user() {
        let path = CpCli::parse_path("user@host:/path/to/file");
        match path {
            FilePath::Remote { user, host, path } => {
                assert_eq!(user, Some("user".to_string()));
                assert_eq!(host, "host");
                assert_eq!(path, "/path/to/file");
            }
            _ => panic!("expected remote path"),
        }
    }

    #[test]
    fn cp_parse_remote_path_no_user() {
        let path = CpCli::parse_path("host:/path/to/file");
        match path {
            FilePath::Remote { user, host, path } => {
                assert!(user.is_none());
                assert_eq!(host, "host");
                assert_eq!(path, "/path/to/file");
            }
            _ => panic!("expected remote path"),
        }
    }

    #[test]
    fn cp_parse_remote_path_relative_with_user() {
        let path = CpCli::parse_path("user@host:relative/path");
        match path {
            FilePath::Remote { user, host, path } => {
                assert_eq!(user, Some("user".to_string()));
                assert_eq!(host, "host");
                assert_eq!(path, "relative/path");
            }
            _ => panic!("expected remote path"),
        }
    }

    #[test]
    fn cp_parse_remote_path_relative_no_user() {
        let path = CpCli::parse_path("host:relative/path");
        match path {
            FilePath::Remote { user, host, path } => {
                assert!(user.is_none());
                assert_eq!(host, "host");
                assert_eq!(path, "relative/path");
            }
            _ => panic!("expected remote path"),
        }
    }

    #[test]
    fn cp_parse_remote_path_trailing_colon_with_user() {
        let path = CpCli::parse_path("user@host:");
        match path {
            FilePath::Remote { user, host, path } => {
                assert_eq!(user, Some("user".to_string()));
                assert_eq!(host, "host");
                assert_eq!(path, "");
            }
            _ => panic!("expected remote path"),
        }
    }

    #[test]
    fn cp_parse_remote_path_trailing_colon_no_user() {
        let path = CpCli::parse_path("host:");
        match path {
            FilePath::Remote { user, host, path } => {
                assert!(user.is_none());
                assert_eq!(host, "host");
                assert_eq!(path, "");
            }
            _ => panic!("expected remote path"),
        }
    }

    #[test]
    fn cp_parse_relative_path() {
        let path = CpCli::parse_path("./relative/path");
        assert!(matches!(path, FilePath::Local(p) if p.to_str() == Some("./relative/path")));
    }

    #[test]
    fn cp_is_upload() {
        let cli =
            CpCli::try_parse_from(["qscp", "/local/file.txt", "user@host:/remote/file.txt"])
                .unwrap();
        assert!(cli.is_upload());
        assert!(!cli.is_download());
    }

    #[test]
    fn cp_is_download() {
        let cli =
            CpCli::try_parse_from(["qscp", "user@host:/remote/file.txt", "/local/file.txt"])
                .unwrap();
        assert!(cli.is_download());
        assert!(!cli.is_upload());
    }

    #[test]
    fn cp_remote_host_upload() {
        let cli = CpCli::try_parse_from([
            "qscp",
            "/local/file.txt",
            "admin@server.example.com:/remote/path",
        ])
        .unwrap();
        let (host, user) = cli.remote_host().unwrap();
        assert_eq!(host, "server.example.com");
        assert_eq!(user, Some("admin".to_string()));
    }

    #[test]
    fn cp_remote_host_download() {
        let cli =
            CpCli::try_parse_from(["qscp", "server.example.com:/remote/path", "/local/path"])
                .unwrap();
        let (host, user) = cli.remote_host().unwrap();
        assert_eq!(host, "server.example.com");
        assert!(user.is_none());
    }

    #[test]
    fn cp_transfer_options_defaults() {
        let cli = CpCli::try_parse_from(["qscp", "/local/file", "host:/remote/file"]).unwrap();
        let opts = cli.transfer_options();
        assert!(opts.compress);
        assert!(opts.delta);
        assert!(!opts.recursive);
        assert!(!opts.preserve_mode);
        assert_eq!(opts.parallel, 4);
    }

    #[test]
    fn cp_transfer_options_custom() {
        let cli = CpCli::try_parse_from([
            "qscp",
            "-r",
            "-p",
            "--no-delta",
            "--no-compress",
            "/local/dir",
            "host:/remote/dir",
        ])
        .unwrap();
        let opts = cli.transfer_options();
        assert!(!opts.compress);
        assert!(!opts.delta);
        assert!(opts.recursive);
        assert!(opts.preserve_mode);
        assert_eq!(opts.parallel, 4);
    }

    #[test]
    fn cp_parallel_flag() {
        let cli = CpCli::try_parse_from(["qscp", "-j", "8", "/local/file", "host:/remote/file"])
            .unwrap();
        assert_eq!(cli.parallel, 8);
    }

    #[test]
    fn cp_port_flag() {
        let cli =
            CpCli::try_parse_from(["qscp", "-P", "2222", "/local/file", "host:/remote/file"])
                .unwrap();
        assert_eq!(cli.port, 2222);
    }

    #[test]
    fn cp_verbose_flag() {
        let cli =
            CpCli::try_parse_from(["qscp", "-vvv", "/local/file", "host:/remote/file"]).unwrap();
        assert_eq!(cli.verbose, 3);
    }

    #[test]
    fn cp_identity_files() {
        let cli = CpCli::try_parse_from([
            "qscp",
            "-i",
            "~/.ssh/id_rsa",
            "-i",
            "~/.ssh/id_ed25519",
            "/local/file",
            "host:/remote/file",
        ])
        .unwrap();
        assert_eq!(cli.identity.len(), 2);
    }

    #[test]
    fn cp_resume_flag() {
        let cli = CpCli::try_parse_from(["qscp", "--resume", "/local/file", "host:/remote/file"])
            .unwrap();
        assert!(cli.resume);
    }

    #[test]
    fn cp_defaults() {
        let cli = CpCli::try_parse_from(["qscp", "/local/file", "host:/remote/file"]).unwrap();
        assert_eq!(cli.port, 22);
        assert_eq!(cli.parallel, 4);
        assert_eq!(cli.verbose, 0);
        assert!(!cli.recursive);
        assert!(!cli.no_delta);
        assert!(!cli.no_compress);
        assert!(!cli.resume);
        assert!(!cli.preserve);
        assert!(!cli.skip_if_unchanged);
        assert!(cli.identity.is_empty());
        assert!(cli.log_file.is_none());
        #[cfg(feature = "standalone")]
        {
            assert!(!cli.direct);
            assert!(cli.server.is_none());
            assert!(cli.key.is_none());
            assert!(cli.known_hosts.is_none());
            assert!(!cli.accept_unknown_host);
            assert!(!cli.no_agent);
        }
    }

    #[test]
    fn cp_skip_if_unchanged_flag() {
        let cli = CpCli::try_parse_from([
            "qscp",
            "--skip-if-unchanged",
            "/local/file",
            "host:/remote/file",
        ])
        .unwrap();
        assert!(cli.skip_if_unchanged);

        let cli2 =
            CpCli::try_parse_from(["qscp", "-u", "/local/file", "host:/remote/file"]).unwrap();
        assert!(cli2.skip_if_unchanged);
    }

    #[test]
    fn cp_skip_if_unchanged_in_options() {
        let cli = CpCli::try_parse_from([
            "qscp",
            "--skip-if-unchanged",
            "/local/file",
            "host:/remote/file",
        ])
        .unwrap();
        let opts = cli.transfer_options();
        assert!(opts.skip_if_unchanged);
    }
}
