//! Server CLI implementation.
//!
//! Provides command-line argument parsing for the qsh server.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use clap::{ArgAction, Parser, ValueEnum};
use qsh_core::constants::DEFAULT_QUIC_PORT_RANGE;

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

/// qsh server - QUIC endpoint for qsh connections.
#[derive(Debug, Parser)]
#[command(
    name = "qsh-server",
    version,
    about = "qsh server - QUIC endpoint for qsh connections"
)]
pub struct Cli {
    /// Run in bootstrap mode (output JSON with connection info, accept single connection)
    #[arg(long = "bootstrap")]
    pub bootstrap: bool,

    /// Address to listen on
    #[arg(short = 'b', long = "bind", default_value = "0.0.0.0")]
    pub bind_addr: IpAddr,

    /// Port to listen on (0 = auto-select from range 4500-4600 in bootstrap mode)
    #[arg(short = 'p', long = "port", default_value = "4433")]
    pub port: u16,

    /// Port range to use in bootstrap mode (START-END, inclusive)
    #[arg(
        long = "port-range",
        value_parser = parse_port_range,
        default_value = "4500-4600",
        value_name = "START-END"
    )]
    pub port_range: (u16, u16),

    /// TLS certificate file (PEM format)
    #[arg(short = 'c', long = "cert", value_name = "FILE")]
    pub cert_file: Option<PathBuf>,

    /// TLS private key file (PEM format)
    #[arg(short = 'k', long = "key", value_name = "FILE")]
    pub key_file: Option<PathBuf>,

    /// Generate self-signed certificate if none provided
    #[arg(long = "self-signed")]
    pub self_signed: bool,

    /// Maximum concurrent connections
    #[arg(long = "max-connections", default_value = "100")]
    pub max_connections: u32,

    /// Maximum forwards per connection (0 = unlimited)
    #[arg(long = "max-forwards", default_value = "10")]
    pub max_forwards: u16,

    /// Allow remote forwards
    #[arg(long = "allow-remote-forwards")]
    pub allow_remote_forwards: bool,

    /// Increase verbosity (can be repeated: -v, -vv, -vvv)
    #[arg(short = 'v', long = "verbose", action = ArgAction::Count)]
    pub verbose: u8,

    /// Log to file instead of stderr
    #[arg(long = "log-file", value_name = "PATH")]
    pub log_file: Option<PathBuf>,

    /// Log output format
    #[arg(long = "log-format", default_value = "text")]
    pub log_format: CliLogFormat,

    /// PID file location
    #[arg(long = "pid-file", value_name = "PATH")]
    pub pid_file: Option<PathBuf>,

    /// Run in foreground (don't daemonize)
    #[arg(short = 'f', long = "foreground")]
    pub foreground: bool,

    /// Shell to spawn (default: user's login shell)
    #[arg(long = "shell", value_name = "PATH")]
    pub shell: Option<PathBuf>,

    /// Environment variables to set (NAME=VALUE)
    #[arg(long = "env", action = ArgAction::Append, value_name = "VAR")]
    pub env_vars: Vec<String>,

    /// Enable compression
    #[arg(short = 'C', long = "compress")]
    pub compress: bool,

    /// Also listen on IPv6 (dual-stack)
    #[arg(short = '6', long = "ipv6")]
    pub ipv6: bool,

    /// Tunnel configuration file (feature-gated)
    #[cfg(feature = "tunnel")]
    #[arg(long = "tunnel-config", value_name = "FILE")]
    pub tunnel_config: Option<PathBuf>,

    /// Allow tunnel connections (feature-gated)
    #[cfg(feature = "tunnel")]
    #[arg(long = "allow-tunnel")]
    pub allow_tunnel: bool,

    /// Linger duration for detached sessions (seconds).
    #[arg(
        long = "session-linger",
        default_value = "172800",
        value_name = "SECONDS",
        env = "QSH_SESSION_LINGER_SECS"
    )]
    pub session_linger_secs: u64,
}

impl Cli {
    /// Get the socket address to bind to.
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.bind_addr, self.port)
    }

    /// Get the IPv6 socket address if dual-stack is enabled.
    pub fn ipv6_socket_addr(&self) -> Option<SocketAddr> {
        if self.ipv6 {
            Some(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                self.port,
            ))
        } else {
            None
        }
    }

    /// Parse environment variables from the --env arguments.
    pub fn parse_env_vars(&self) -> Vec<(String, String)> {
        self.env_vars
            .iter()
            .filter_map(|s| {
                let (name, value) = s.split_once('=')?;
                Some((name.to_string(), value.to_string()))
            })
            .collect()
    }

    /// Check if TLS credentials are provided or should be generated.
    pub fn has_tls_config(&self) -> bool {
        self.cert_file.is_some() && self.key_file.is_some()
    }

    /// Get the session linger as a [`Duration`].
    pub fn session_linger_duration(&self) -> Duration {
        Duration::from_secs(self.session_linger_secs)
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

impl Default for Cli {
    fn default() -> Self {
        Self {
            bootstrap: false,
            bind_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: 4433,
            port_range: DEFAULT_QUIC_PORT_RANGE,
            cert_file: None,
            key_file: None,
            self_signed: false,
            max_connections: 100,
            max_forwards: 10,
            allow_remote_forwards: false,
            verbose: 0,
            log_file: None,
            log_format: CliLogFormat::Text,
            pid_file: None,
            foreground: false,
            shell: None,
            env_vars: Vec::new(),
            compress: false,
            ipv6: false,
            #[cfg(feature = "tunnel")]
            tunnel_config: None,
            #[cfg(feature = "tunnel")]
            allow_tunnel: false,
            session_linger_secs: 172_800,
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
    fn default_values() {
        let cli = Cli::try_parse_from(["qsh-server"]).unwrap();
        assert!(!cli.bootstrap);
        assert_eq!(cli.bind_addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(cli.port, 4433);
        assert_eq!(cli.port_range, DEFAULT_QUIC_PORT_RANGE);
        assert_eq!(cli.max_connections, 100);
        assert_eq!(cli.max_forwards, 10);
        assert!(!cli.allow_remote_forwards);
        assert_eq!(cli.verbose, 0);
        assert!(!cli.foreground);
        assert!(!cli.compress);
        assert!(!cli.ipv6);
        assert_eq!(cli.session_linger_secs, 172_800);
    }

    #[test]
    fn parse_bootstrap() {
        let cli = Cli::try_parse_from(["qsh-server", "--bootstrap"]).unwrap();
        assert!(cli.bootstrap);
    }

    #[test]
    fn parse_bind_and_port() {
        let cli = Cli::try_parse_from(["qsh-server", "-b", "127.0.0.1", "-p", "8443"]).unwrap();
        assert_eq!(cli.bind_addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(cli.port, 8443);
        assert_eq!(
            cli.socket_addr(),
            "127.0.0.1:8443".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn parse_port_range_flag() {
        let cli = Cli::try_parse_from(["qsh-server", "--port-range", "15000-15100"]).unwrap();
        assert_eq!(cli.port_range, (15000, 15100));
    }

    #[test]
    fn parse_invalid_port_range() {
        assert!(Cli::try_parse_from(["qsh-server", "--port-range", "15100-15000"]).is_err());
        assert!(Cli::try_parse_from(["qsh-server", "--port-range", "0-10"]).is_err());
        assert!(Cli::try_parse_from(["qsh-server", "--port-range", "not-a-range"]).is_err());
    }

    #[test]
    fn parse_tls_files() {
        let cli = Cli::try_parse_from([
            "qsh-server",
            "-c",
            "/etc/qsh/cert.pem",
            "-k",
            "/etc/qsh/key.pem",
        ])
        .unwrap();
        assert_eq!(cli.cert_file, Some(PathBuf::from("/etc/qsh/cert.pem")));
        assert_eq!(cli.key_file, Some(PathBuf::from("/etc/qsh/key.pem")));
        assert!(cli.has_tls_config());
    }

    #[test]
    fn parse_self_signed() {
        let cli = Cli::try_parse_from(["qsh-server", "--self-signed"]).unwrap();
        assert!(cli.self_signed);
        assert!(!cli.has_tls_config());
    }

    #[test]
    fn parse_verbosity() {
        let cli = Cli::try_parse_from(["qsh-server", "-vvv"]).unwrap();
        assert_eq!(cli.verbose, 3);
    }

    #[test]
    fn parse_env_vars() {
        let cli =
            Cli::try_parse_from(["qsh-server", "--env", "FOO=bar", "--env", "BAZ=qux"]).unwrap();
        let env = cli.parse_env_vars();
        assert_eq!(env.len(), 2);
        assert_eq!(env[0], ("FOO".to_string(), "bar".to_string()));
        assert_eq!(env[1], ("BAZ".to_string(), "qux".to_string()));
    }

    #[test]
    fn parse_limits() {
        let cli = Cli::try_parse_from([
            "qsh-server",
            "--max-connections",
            "50",
            "--max-forwards",
            "5",
        ])
        .unwrap();
        assert_eq!(cli.max_connections, 50);
        assert_eq!(cli.max_forwards, 5);
    }

    #[test]
    fn parse_ipv6() {
        let cli = Cli::try_parse_from(["qsh-server", "-6"]).unwrap();
        assert!(cli.ipv6);
        assert!(cli.ipv6_socket_addr().is_some());
    }

    #[test]
    fn parse_log_format() {
        let cli = Cli::try_parse_from(["qsh-server", "--log-format", "json"]).unwrap();
        assert_eq!(cli.log_format, CliLogFormat::Json);
    }

    #[test]
    fn parse_allow_remote_forwards() {
        let cli = Cli::try_parse_from(["qsh-server", "--allow-remote-forwards"]).unwrap();
        assert!(cli.allow_remote_forwards);
    }
}
