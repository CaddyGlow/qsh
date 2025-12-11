//! SSH bootstrap module for server initiator mode.
//!
//! When qsh-server runs with `--connect-mode initiate`, it needs to SSH to
//! a client machine and run `qsh --bootstrap` to discover the client's QUIC
//! endpoint. This module provides that functionality.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tracing::{debug, info};

use qsh_core::bootstrap::{BootstrapResponse, EndpointInfo};
use qsh_core::error::{Error, Result};

/// Handle to a bootstrap session that keeps the SSH connection alive.
///
/// When the server runs in initiator mode, it SSHes to a client and executes
/// `qsh --bootstrap`. This handle keeps that SSH process alive to maintain the
/// control connection while the QUIC session is established.
///
/// # Lifecycle
///
/// 1. Server SSHes to client and launches `qsh --bootstrap`
/// 2. Reads bootstrap JSON from stdout
/// 3. Returns `BootstrapHandle` with endpoint info
/// 4. Server connects to client's QUIC endpoint
/// 5. Drop handle to terminate SSH connection
///
/// The SSH process must remain alive until the QUIC connection is established,
/// otherwise the client's bootstrap listener will exit.
pub struct BootstrapHandle {
    /// Connection information parsed from the client's bootstrap response.
    ///
    /// Contains address, port, session key, cert hash, and connect mode.
    pub endpoint_info: EndpointInfo,

    /// SSH process handle.
    ///
    /// Kept alive until this handle is dropped. When dropped, the SSH connection
    /// terminates, signaling the client that bootstrap is complete.
    _ssh_process: Option<Child>,
}

/// SSH client configuration for server initiator mode.
///
/// Used when `qsh-server` runs with `--connect-mode initiate` to configure
/// the SSH connection to the remote client.
#[derive(Debug, Clone)]
pub struct SshConfig {
    /// SSH connection timeout.
    ///
    /// Maximum time to wait for SSH connection establishment and bootstrap response.
    pub connect_timeout: Duration,

    /// Path to SSH identity file (private key).
    ///
    /// If `None`, SSH will use default key discovery (agent, ~/.ssh/id_rsa, etc.).
    pub identity_file: Option<PathBuf>,

    /// Skip SSH host key verification (insecure).
    ///
    /// When `true`, disables StrictHostKeyChecking. Only use for testing or
    /// when connecting to ephemeral/known-trusted hosts.
    pub skip_host_key_check: bool,

    /// Port range to request for client's bootstrap listener.
    ///
    /// Passed to `qsh --bootstrap --port-range START-END`. Typically Mosh-style
    /// range (60001-60999) for firewall compatibility.
    pub port_range: Option<(u16, u16)>,

    /// Extra arguments to pass to the bootstrap client.
    ///
    /// Appended to the `qsh --bootstrap` command. Can include logging flags,
    /// debug options, etc. Example: "--log-file /tmp/qsh.log -vvv"
    pub extra_args: Option<String>,

    /// Extra environment variables for the bootstrap client.
    ///
    /// Set as env vars in the remote shell before running the bootstrap command.
    /// Example: [("RUST_LOG", "debug")]
    pub extra_env: Vec<(String, String)>,
}

impl Default for SshConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(30),
            identity_file: None,
            skip_host_key_check: false,
            port_range: None,
            extra_args: None,
            extra_env: Vec::new(),
        }
    }
}

/// Bootstrap via SSH to discover client QUIC endpoint.
///
/// Connects to the remote client via SSH, executes `qsh --bootstrap`,
/// and parses the JSON response to get connection information.
///
/// Returns a `BootstrapHandle` that keeps the SSH session alive until dropped.
/// The caller should establish the QUIC connection before dropping the handle.
pub async fn bootstrap(
    host: &str,
    port: u16,
    user: Option<&str>,
    config: &SshConfig,
) -> Result<BootstrapHandle> {
    let addr = format!("{}:{}", host, port);
    info!(addr = %addr, user = ?user, "Bootstrapping client via SSH");

    let handle = bootstrap_via_ssh_cli(host, port, user, config).await?;

    info!(
        address = %handle.endpoint_info.address,
        port = handle.endpoint_info.port,
        connect_mode = ?handle.endpoint_info.connect_mode,
        "Bootstrap successful"
    );

    Ok(handle)
}

/// Bootstrap using the system `ssh` client.
///
/// Spawns SSH, reads the JSON response from stdout (without waiting for exit),
/// and returns a handle that keeps the SSH process alive.
async fn bootstrap_via_ssh_cli(
    host: &str,
    port: u16,
    user: Option<&str>,
    config: &SshConfig,
) -> Result<BootstrapHandle> {
    let remote = user
        .map(|u| format!("{}@{}", u, host))
        .unwrap_or_else(|| host.to_string());

    let mut cmd = Command::new("ssh");
    cmd.arg("-p").arg(port.to_string());

    let timeout_secs = config.connect_timeout.as_secs().max(1);
    cmd.arg("-o")
        .arg(format!("ConnectTimeout={}", timeout_secs));

    if let Some(identity) = &config.identity_file {
        cmd.arg("-i").arg(identity);
    }

    if config.skip_host_key_check {
        cmd.arg("-o").arg("StrictHostKeyChecking=no");
        cmd.arg("-o").arg("UserKnownHostsFile=/dev/null");
    }

    // Force no TTY allocation - we're running a bootstrap command that outputs JSON
    cmd.arg("-T");

    cmd.arg(remote);

    // Build the remote command: either just "qsh --bootstrap ..." or with env vars prefix
    let mut bootstrap_cmd = String::from("qsh --bootstrap");

    if let Some((start, end)) = config.port_range {
        bootstrap_cmd.push_str(&format!(" --bootstrap-port-range {}-{}", start, end));
    }

    // Add extra arguments if provided
    if let Some(ref extra_args) = config.extra_args {
        bootstrap_cmd.push(' ');
        bootstrap_cmd.push_str(extra_args);
    }

    // If we have env vars, prefix the command with them
    if !config.extra_env.is_empty() {
        let env_prefix: String = config
            .extra_env
            .iter()
            .map(|(k, v)| format!("{}={}", k, shell_escape(v)))
            .collect::<Vec<_>>()
            .join(" ");
        cmd.arg(format!("{} {}", env_prefix, bootstrap_cmd));
    } else {
        // No env vars, pass command and args directly
        cmd.args(bootstrap_cmd.split_whitespace());
    }

    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    debug!(
        port = port,
        skip_host_key_check = config.skip_host_key_check,
        identity = config
            .identity_file
            .as_ref()
            .map(|p| p.display().to_string()),
        command = ?cmd.as_std(),
        "Executing ssh bootstrap via CLI"
    );

    let mut child = cmd.spawn().map_err(|e| Error::Transport {
        message: format!("failed to spawn ssh: {}", e),
    })?;

    // Take stdout and stderr to read the response and any error messages
    let stdout = child.stdout.take().ok_or_else(|| Error::Transport {
        message: "failed to capture ssh stdout".to_string(),
    })?;
    let stderr = child.stderr.take();

    // Read until we get a complete JSON line
    // The client outputs a single JSON line to stdout
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();

    let read_result = tokio::time::timeout(config.connect_timeout, async {
        reader.read_line(&mut line).await
    })
    .await
    .map_err(|_| Error::Timeout)?
    .map_err(|e| Error::Transport {
        message: format!("failed to read ssh output: {}", e),
    })?;

    if read_result == 0 {
        // EOF without reading anything - check if process died
        let status = child.try_wait().map_err(|e| Error::Transport {
            message: format!("failed to check ssh status: {}", e),
        })?;

        // Try to read stderr for diagnostic info
        let stderr_output = if let Some(mut stderr) = stderr {
            let mut stderr_reader = BufReader::new(&mut stderr);
            let mut stderr_content = String::new();
            let _ = stderr_reader.read_line(&mut stderr_content).await;
            stderr_content.trim().to_string()
        } else {
            String::new()
        };

        if let Some(exit_status) = status {
            let code = exit_status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "terminated by signal".to_string());
            let stderr_msg = if stderr_output.is_empty() {
                String::new()
            } else {
                format!(" ({})", stderr_output)
            };
            return Err(Error::Transport {
                message: format!(
                    "ssh bootstrap failed with code {}: no output received{}",
                    code, stderr_msg
                ),
            });
        }

        return Err(Error::Transport {
            message: "ssh bootstrap produced no output".to_string(),
        });
    }

    debug!(response = %line.trim(), "Bootstrap response received");

    // Parse the JSON response
    let endpoint_info = parse_bootstrap_response(line.into_bytes())?;

    // Return handle that keeps SSH process alive
    Ok(BootstrapHandle {
        endpoint_info,
        _ssh_process: Some(child),
    })
}

/// Simple shell escaping for environment variable values.
/// Wraps values with special characters in single quotes.
fn shell_escape(s: &str) -> String {
    if s.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '/' || c == '.') {
        s.to_string()
    } else {
        // Escape single quotes by ending the string, adding escaped quote, and restarting
        let escaped = s.replace('\'', "'\"'\"'");
        format!("'{}'", escaped)
    }
}

fn parse_bootstrap_response(output: Vec<u8>) -> Result<EndpointInfo> {
    let json = String::from_utf8(output).map_err(|e| Error::Protocol {
        message: format!("invalid UTF-8 in bootstrap response: {}", e),
    })?;

    debug!(response = %json, "Bootstrap response received");

    let response = BootstrapResponse::parse(&json)?;
    let endpoint_info = response.get_endpoint_info()?.clone();

    Ok(endpoint_info)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_config_default() {
        let config = SshConfig::default();
        assert_eq!(config.connect_timeout, Duration::from_secs(30));
        assert!(config.identity_file.is_none());
        assert!(!config.skip_host_key_check);
        assert!(config.port_range.is_none());
    }
}
