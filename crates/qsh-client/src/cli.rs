//! Client CLI implementation.
//!
//! Provides command-line argument parsing using clap.

use std::{borrow::Cow, path::PathBuf};
#[cfg(feature = "tunnel")]
use std::str::FromStr;

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
#[command(name = "qsh", version, about = "Modern roaming-capable remote terminal")]
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

    /// Force predictive echo off (safer for password prompts)
    #[arg(long = "no-prediction")]
    pub no_prediction: bool,

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
    #[arg(long = "overlay-key", default_value = "ctrl+shift+s", value_name = "KEY")]
    pub overlay_key: String,
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
        assert_eq!(
            cli.parse_destination(),
            Some((Some("user"), "example.com"))
        );
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
    fn parse_local_forward() {
        let cli =
            Cli::try_parse_from(["qsh", "-L", "8080:localhost:80", "example.com"]).unwrap();
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
        let cli =
            Cli::try_parse_from(["qsh", "--tun=10.0.0.2/24", "--route", "0.0.0.0/0", "host"])
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
        assert_eq!(
            cli.command_string(),
            Some("echo 'hi there'".to_string())
        );
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
    fn default_values() {
        let cli = Cli::try_parse_from(["qsh", "example.com"]).unwrap();
        assert_eq!(cli.port, 22);
        assert_eq!(cli.verbose, 0);
        assert!(!cli.no_pty);
        assert!(!cli.background);
        assert!(!cli.compress);
        assert!(!cli.no_prediction);
        assert!(!cli.show_status);
        assert_eq!(cli.log_format, CliLogFormat::Text);
        assert_eq!(cli.overlay_position, OverlayPosition::Top);
        assert_eq!(cli.overlay_key, "ctrl+shift+s");
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
    }
}
