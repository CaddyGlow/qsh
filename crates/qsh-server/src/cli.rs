//! Server CLI implementation.
//!
//! Provides command-line argument parsing for the qsh server.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use clap::{ArgAction, Parser, ValueEnum};
use qsh_core::constants::{
    DEFAULT_MAX_CONNECTIONS, DEFAULT_MAX_FORWARDS, DEFAULT_QUIC_PORT_RANGE,
    DEFAULT_SESSION_LINGER_SECS,
};
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

/// Connect mode argument for CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum ConnectModeArg {
    /// Initiate connection: SSH to client and connect to its QUIC listener (reverse mode)
    Initiate,
    /// Respond mode: listen for and accept QUIC connections from clients (default)
    #[default]
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

    /// Port to listen on (0 = auto-select from Mosh port range in bootstrap mode)
    #[arg(short = 'p', long = "port", default_value = "4433")]
    pub port: u16,

    /// Port range to use in bootstrap mode (START-END, inclusive, Mosh-style)
    #[arg(
        long = "port-range",
        value_parser = parse_port_range,
        default_value = "60001-60999",
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
    #[arg(long = "max-connections", default_value_t = DEFAULT_MAX_CONNECTIONS)]
    pub max_connections: u32,

    /// Maximum forwards per connection (0 = unlimited)
    #[arg(long = "max-forwards", default_value_t = DEFAULT_MAX_FORWARDS)]
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
        default_value_t = DEFAULT_SESSION_LINGER_SECS,
        value_name = "SECONDS",
        env = "QSH_SESSION_LINGER_SECS"
    )]
    pub session_linger_secs: u64,

    // === TransportSender (Mosh-style output batching) ===
    /// Terminal output mode (direct/mosh/statediff)
    #[arg(long = "mode", default_value = "direct", value_enum)]
    pub output_mode: OutputMode,

    /// Minimum delay before sending output (milliseconds).
    /// Mosh uses 8ms for server, allowing efficient output coalescing.
    #[arg(long = "send-mindelay", default_value = "8", value_name = "MS")]
    pub send_mindelay_ms: u64,

    /// Minimum send interval (milliseconds).
    /// Mosh uses 20ms as the floor for adaptive timing.
    #[arg(long = "send-interval-min", default_value = "20", value_name = "MS")]
    pub send_interval_min_ms: u64,

    /// Maximum send interval (milliseconds).
    /// Mosh uses 250ms as the ceiling for adaptive timing.
    #[arg(long = "send-interval-max", default_value = "250", value_name = "MS")]
    pub send_interval_max_ms: u64,

    /// Connection mode: 'respond' to listen for clients (default), 'initiate' to SSH out and connect to client (reverse mode)
    #[arg(long = "connect-mode", default_value = "respond", value_enum)]
    pub connect_mode: ConnectModeArg,

    // Initiator mode options (when --connect-mode initiate)
    /// Target client for initiator mode in format `[user@]host[:port]`. Required when --connect-mode=initiate
    #[arg(long = "target", value_name = "DESTINATION")]
    pub target: Option<String>,

    /// SSH port for initiator mode
    #[arg(long = "ssh-port", default_value = "22", value_name = "PORT")]
    pub ssh_port: u16,

    /// SSH identity file for initiator mode
    #[arg(short = 'i', long = "identity", value_name = "FILE")]
    pub identity_file: Option<PathBuf>,

    /// Skip SSH host key verification (insecure, for initiator mode)
    #[arg(long = "skip-host-key-check")]
    pub skip_host_key_check: bool,

    // Standalone mode options (feature-gated)
    /// Run in standalone mode with SSH key authentication
    #[cfg(feature = "standalone")]
    #[arg(long = "standalone")]
    pub standalone: bool,

    /// Path to host private key for standalone mode
    #[cfg(feature = "standalone")]
    #[arg(long = "host-key", value_name = "PATH")]
    pub host_key: Option<PathBuf>,

    /// Path to authorized_keys file for standalone mode
    #[cfg(feature = "standalone")]
    #[arg(long = "authorized-keys", value_name = "PATH")]
    pub authorized_keys: Option<PathBuf>,
}

impl Cli {
    /// Validate CLI arguments and auto-infer connect_mode where appropriate.
    ///
    /// Returns the effective connect mode to use, or an error if the flags are incompatible.
    pub fn validate_and_infer_connect_mode(&self) -> Result<ConnectModeArg, String> {
        // Bootstrap mode validation
        if self.bootstrap {
            // --bootstrap is incompatible with --connect-mode initiate
            if self.connect_mode == ConnectModeArg::Initiate {
                return Err(
                    "--bootstrap cannot be used with --connect-mode initiate\n\
                     Hint: --bootstrap mode accepts incoming connections (respond mode)\n\
                     Remove --connect-mode initiate or remove --bootstrap"
                        .to_string(),
                );
            }

            // --bootstrap is incompatible with --target
            if self.target.is_some() {
                return Err(
                    "--bootstrap cannot be used with --target\n\
                     Hint: --bootstrap mode accepts incoming connections, it doesn't initiate them\n\
                     Remove --target or remove --bootstrap"
                        .to_string(),
                );
            }

            // Auto-infer: bootstrap implies respond mode
            return Ok(ConnectModeArg::Respond);
        }

        // Initiate mode validation
        if self.connect_mode == ConnectModeArg::Initiate {
            // --connect-mode initiate requires --target
            if self.target.is_none() {
                return Err(
                    "--connect-mode initiate requires --target\n\
                     Hint: specify which client to connect to\n\
                     Example: qsh-server --connect-mode initiate --target user@client-host"
                        .to_string(),
                );
            }

            // Auto-infer success: initiate mode with target
            return Ok(ConnectModeArg::Initiate);
        }

        // Respond mode (default) validation
        if self.connect_mode == ConnectModeArg::Respond {
            // Auto-infer: --target implies initiate mode
            if self.target.is_some() {
                return Ok(ConnectModeArg::Initiate);
            }

            // Respond mode is valid
            return Ok(ConnectModeArg::Respond);
        }

        // Default to respond mode if nothing specified
        Ok(ConnectModeArg::Respond)
    }

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

    /// Create SenderConfig from CLI options (Mosh-style output batching).
    pub fn sender_config(&self) -> qsh_core::transport::SenderConfig {
        qsh_core::transport::SenderConfig {
            send_mindelay: Duration::from_millis(self.send_mindelay_ms),
            send_interval_min: Duration::from_millis(self.send_interval_min_ms),
            send_interval_max: Duration::from_millis(self.send_interval_max_ms),
            // ACK delay/interval are not exposed via CLI (use Mosh defaults)
            ..qsh_core::transport::SenderConfig::server()
        }
    }

    /// Parse target destination for initiator mode.
    ///
    /// Returns (host, port, user) from target string like `[user@]host[:port]`.
    /// Falls back to ssh_port if port not specified in target.
    pub fn parse_target(&self) -> Option<(String, u16, Option<String>)> {
        let target = self.target.as_ref()?;

        // Split user@host
        let (user, host_port) = if let Some(idx) = target.rfind('@') {
            let user = target[..idx].to_string();
            let host_port = &target[idx + 1..];
            (Some(user), host_port)
        } else {
            (None, target.as_str())
        };

        // Split host:port
        let (host, port) = if let Some(idx) = host_port.rfind(':') {
            let host = host_port[..idx].to_string();
            let port_str = &host_port[idx + 1..];
            let port = port_str.parse().unwrap_or(self.ssh_port);
            (host, port)
        } else {
            (host_port.to_string(), self.ssh_port)
        };

        Some((host, port, user))
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
            max_forwards: 1024,
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
            output_mode: OutputMode::Direct,
            send_mindelay_ms: 8,       // Mosh server default
            send_interval_min_ms: 20,  // Mosh SEND_INTERVAL_MIN
            send_interval_max_ms: 250, // Mosh SEND_INTERVAL_MAX
            connect_mode: ConnectModeArg::Respond,
            target: None,
            ssh_port: 22,
            identity_file: None,
            skip_host_key_check: false,
            #[cfg(feature = "standalone")]
            standalone: false,
            #[cfg(feature = "standalone")]
            host_key: None,
            #[cfg(feature = "standalone")]
            authorized_keys: None,
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
        assert_eq!(cli.max_connections, DEFAULT_MAX_CONNECTIONS);
        assert_eq!(cli.max_forwards, DEFAULT_MAX_FORWARDS);
        assert!(!cli.allow_remote_forwards);
        assert_eq!(cli.verbose, 0);
        assert!(!cli.foreground);
        assert!(!cli.compress);
        assert!(!cli.ipv6);
        assert_eq!(cli.session_linger_secs, DEFAULT_SESSION_LINGER_SECS);
        assert_eq!(cli.connect_mode, ConnectModeArg::Respond);
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

    #[test]
    fn parse_connect_mode_default_respond() {
        let cli = Cli::try_parse_from(["qsh-server"]).unwrap();
        assert_eq!(cli.connect_mode, ConnectModeArg::Respond);
    }

    #[test]
    fn parse_connect_mode_respond() {
        let cli = Cli::try_parse_from(["qsh-server", "--connect-mode", "respond"]).unwrap();
        assert_eq!(cli.connect_mode, ConnectModeArg::Respond);
    }

    #[test]
    fn parse_connect_mode_initiate() {
        let cli = Cli::try_parse_from(["qsh-server", "--connect-mode", "initiate"]).unwrap();
        assert_eq!(cli.connect_mode, ConnectModeArg::Initiate);
    }

    #[test]
    fn parse_connect_mode_invalid() {
        let result = Cli::try_parse_from(["qsh-server", "--connect-mode", "invalid"]);
        assert!(result.is_err());
    }

    #[test]
    fn connect_mode_converts_to_core_type() {
        let initiate: qsh_core::ConnectMode = ConnectModeArg::Initiate.into();
        assert_eq!(initiate, qsh_core::ConnectMode::Initiate);

        let respond: qsh_core::ConnectMode = ConnectModeArg::Respond.into();
        assert_eq!(respond, qsh_core::ConnectMode::Respond);
    }
}
