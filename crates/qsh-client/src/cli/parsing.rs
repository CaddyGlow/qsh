//! CLI parsing functions and methods.

use std::borrow::Cow;

use super::types::{Cli, ConnectModeArg, PredictionMode};

impl Cli {
    /// Validate CLI arguments and auto-infer connect_mode where appropriate.
    ///
    /// Returns the effective connect mode to use, or an error if the flags are incompatible.
    pub fn validate_and_infer_connect_mode(&self) -> Result<ConnectModeArg, String> {
        // Bootstrap mode validation
        if self.bootstrap {
            // --bootstrap is incompatible with specifying a destination host
            // (checked via clap conflicts_with, but we double-check here for clarity)
            if self.destination.is_some() {
                return Err(
                    "--bootstrap cannot be used with a destination host\n\
                     Hint: --bootstrap mode waits for incoming connections and doesn't connect out\n\
                     Remove the destination argument or remove --bootstrap"
                        .to_string(),
                );
            }

            // Auto-infer: bootstrap always implies respond mode, regardless of explicit flag
            // (The default is Initiate, so we override it here)
            return Ok(ConnectModeArg::Respond);
        }

        // Attach mode validation
        if self.attach.is_some() {
            // --attach is incompatible with specifying a destination host
            // (checked via clap conflicts_with, but we double-check here for clarity)
            if self.destination.is_some() {
                return Err(
                    "--attach cannot be used with a destination host\n\
                     Hint: --attach mode connects to an existing bootstrap session\n\
                     Remove the destination argument or remove --attach"
                        .to_string(),
                );
            }

            // Attach mode doesn't participate in QUIC handshake; it's just pipe I/O
            // Return Initiate as a placeholder (won't actually be used)
            return Ok(ConnectModeArg::Initiate);
        }

        // Normal mode (with destination) validation
        if let Some(_host) = self.destination.as_ref() {
            // Destination requires --connect-mode initiate (or we auto-infer it)
            if self.connect_mode == ConnectModeArg::Respond {
                return Err(
                    "specifying a destination is incompatible with --connect-mode respond\n\
                     Hint: use --connect-mode initiate when connecting to a remote host\n\
                     Remove --connect-mode respond or use --connect-mode initiate"
                        .to_string(),
                );
            }

            // Auto-infer: destination implies initiate mode
            return Ok(ConnectModeArg::Initiate);
        }

        // No bootstrap, no destination, no attach - this is invalid
        Err(
            "either --bootstrap or a destination host must be specified\n\
             Usage: qsh [user@]host[:port]  (connect to remote host)\n\
             Or:    qsh --bootstrap         (wait for incoming connection)"
                .to_string(),
        )
    }

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

    /// Create SenderConfig from CLI options (Mosh-style keystroke batching).
    pub fn sender_config(&self) -> qsh_core::transport::SenderConfig {
        qsh_core::transport::SenderConfig {
            send_mindelay: std::time::Duration::from_millis(self.send_mindelay_ms),
            send_interval_min: std::time::Duration::from_millis(self.send_interval_min_ms),
            send_interval_max: std::time::Duration::from_millis(self.send_interval_max_ms),
            // ACK delay/interval are not exposed via CLI (use Mosh defaults)
            ..qsh_core::transport::SenderConfig::client()
        }
    }
}

pub fn parse_port_range(s: &str) -> Result<(u16, u16), String> {
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
