//! SSH bootstrap module.
//!
//! Implements SSH-based discovery of QUIC endpoints:
//! 1. Connect to remote host via SSH
//! 2. Execute `qsh-server --bootstrap`
//! 3. Parse JSON response to get QUIC endpoint info

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use russh::client;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tracing::{debug, info, warn};

use qsh_core::bootstrap::{BootstrapResponse, ServerInfo};
use qsh_core::error::{Error, Result};

/// Handle to a bootstrap session that keeps the SSH process alive.
///
/// The SSH process running `qsh-server --bootstrap` will stay alive until
/// this handle is dropped, allowing the QUIC client to connect before the
/// server exits.
pub struct BootstrapHandle {
    /// The server info parsed from bootstrap response.
    pub server_info: ServerInfo,
    /// SSH process handle - kept alive until dropped.
    _ssh_process: Option<Child>,
    /// Russh session handle - kept alive until dropped.
    _russh_session: Option<client::Handle<SshHandler>>,
}

/// Which SSH implementation to use for bootstrap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapMode {
    /// Use the system `ssh` binary.
    SshCli,
    /// Use the embedded `russh` client.
    Russh,
}

/// SSH client configuration.
#[derive(Debug, Clone)]
pub struct SshConfig {
    /// SSH connection timeout.
    pub connect_timeout: Duration,
    /// Path to identity file (private key).
    pub identity_file: Option<PathBuf>,
    /// Skip host key verification (insecure).
    pub skip_host_key_check: bool,
    /// Requested bootstrap QUIC port range.
    pub port_range: Option<(u16, u16)>,
    /// SSH implementation to use for bootstrap.
    pub mode: BootstrapMode,
}

impl Default for SshConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(30),
            identity_file: None,
            skip_host_key_check: false,
            port_range: None,
            mode: BootstrapMode::SshCli,
        }
    }
}

/// SSH client handler.
struct SshHandler {
    /// Whether to skip host key verification.
    skip_host_key_check: bool,
}

#[async_trait::async_trait]
impl client::Handler for SshHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh_keys::key::PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        if self.skip_host_key_check {
            warn!("Skipping SSH host key verification (insecure)");
            Ok(true)
        } else {
            // In a full implementation, we would check against known_hosts
            // For now, accept all keys with a warning
            warn!("Host key verification not implemented, accepting key");
            Ok(true)
        }
    }
}

/// Bootstrap via SSH to discover QUIC endpoint.
///
/// Connects to the remote host via SSH, executes `qsh-server --bootstrap`,
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
    info!(addr = %addr, user = ?user, mode = ?config.mode, "Bootstrapping via SSH");

    let handle = match config.mode {
        BootstrapMode::SshCli => bootstrap_via_ssh_cli(host, port, user, config).await?,
        BootstrapMode::Russh => bootstrap_via_russh(&addr, user, config).await?,
    };

    info!(
        address = %handle.server_info.address,
        port = handle.server_info.port,
        mode = ?config.mode,
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
    cmd.arg("-o").arg("BatchMode=yes");

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

    cmd.arg(remote);
    cmd.arg("qsh-server").arg("--bootstrap");
    if let Some((start, end)) = config.port_range {
        cmd.arg("--port-range").arg(format!("{}-{}", start, end));
    }
    cmd.stdin(Stdio::null()); // Don't inherit stdin - we need it for terminal input
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    debug!(
        port = port,
        skip_host_key_check = config.skip_host_key_check,
        identity = config
            .identity_file
            .as_ref()
            .map(|p| p.display().to_string()),
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
    // The server outputs a single JSON line to stdout
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
    let server_info = parse_bootstrap_response(line.into_bytes())?;

    // Return handle that keeps SSH process alive
    Ok(BootstrapHandle {
        server_info,
        _ssh_process: Some(child),
        _russh_session: None,
    })
}

/// Bootstrap using the embedded `russh` client.
///
/// Connects via russh, reads the JSON response, and keeps the session alive.
async fn bootstrap_via_russh(
    addr: &str,
    user: Option<&str>,
    config: &SshConfig,
) -> Result<BootstrapHandle> {
    // Create SSH config
    let ssh_config = client::Config {
        inactivity_timeout: Some(config.connect_timeout),
        keepalive_interval: Some(Duration::from_secs(30)),
        keepalive_max: 3,
        ..Default::default()
    };

    let ssh_config = Arc::new(ssh_config);
    let handler = SshHandler {
        skip_host_key_check: config.skip_host_key_check,
    };

    // Connect to SSH server
    let mut session = tokio::time::timeout(config.connect_timeout, async {
        client::connect(ssh_config, addr, handler).await
    })
    .await
    .map_err(|_| Error::Timeout)?
    .map_err(|e| Error::Transport {
        message: format!("SSH connection failed: {}", e),
    })?;

    debug!("SSH connection established");

    // Authenticate
    let username: String = user
        .map(String::from)
        .or_else(|| std::env::var("USER").ok())
        .or_else(|| std::env::var("USERNAME").ok())
        .unwrap_or_else(|| "root".to_string());

    // Try to load identity file
    let authenticated = if let Some(ref identity_path) = config.identity_file {
        debug!(path = %identity_path.display(), "Loading identity file");
        match load_and_auth_key(&mut session, &username, identity_path).await {
            Ok(true) => true,
            Ok(false) => {
                warn!("Key authentication failed, trying agent");
                try_agent_auth(&mut session, &username).await?
            }
            Err(e) => {
                warn!(error = %e, "Failed to load identity file, trying agent");
                try_agent_auth(&mut session, &username).await?
            }
        }
    } else {
        // Try SSH agent first
        try_agent_auth(&mut session, &username).await?
    };

    if !authenticated {
        return Err(Error::AuthenticationFailed);
    }

    info!("SSH authentication successful");

    // Open a channel and execute bootstrap command
    let mut channel = session
        .channel_open_session()
        .await
        .map_err(|e| Error::Transport {
            message: format!("failed to open SSH channel: {}", e),
        })?;

    // Execute qsh-server --bootstrap
    let mut bootstrap_cmd = "qsh-server --bootstrap".to_string();
    if let Some((start, end)) = config.port_range {
        bootstrap_cmd.push_str(&format!(" --port-range {}-{}", start, end));
    }

    channel
        .exec(true, bootstrap_cmd.as_str())
        .await
        .map_err(|e| Error::Transport {
            message: format!("failed to execute bootstrap command: {}", e),
        })?;

    debug!("Bootstrap command executed");

    // Read output until we get a complete JSON line (contains newline or looks complete)
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    // Read first data message which should contain the JSON response
    let read_timeout = tokio::time::timeout(config.connect_timeout, async {
        loop {
            let msg = channel.wait().await;
            match msg {
                Some(russh::ChannelMsg::Data { data }) => {
                    stdout.extend_from_slice(&data);
                    // Check if we have a complete JSON line
                    if let Ok(s) = std::str::from_utf8(&stdout) {
                        if s.contains('\n') || (s.contains('{') && s.contains('}')) {
                            return Ok::<_, Error>(());
                        }
                    }
                }
                Some(russh::ChannelMsg::ExtendedData { data, ext: 1 }) => {
                    if let Ok(stderr_str) = std::str::from_utf8(&data) {
                        debug!(stderr = %stderr_str, "Bootstrap stderr");
                    }
                    stderr.extend_from_slice(&data);
                }
                Some(russh::ChannelMsg::ExitStatus { exit_status }) => {
                    if exit_status != 0 {
                        return Err(Error::Transport {
                            message: format!(
                                "bootstrap command failed with code {}: {}",
                                exit_status,
                                String::from_utf8_lossy(&stderr)
                            ),
                        });
                    }
                }
                Some(russh::ChannelMsg::Eof) | None => {
                    // If we got some output, try to parse it
                    if !stdout.is_empty() {
                        return Ok(());
                    }
                    return Err(Error::Transport {
                        message: "bootstrap command produced no output".to_string(),
                    });
                }
                _ => {}
            }
        }
    })
    .await
    .map_err(|_| Error::Timeout)?;

    read_timeout?;

    debug!(response = %String::from_utf8_lossy(&stdout).trim(), "Bootstrap response received");

    // Parse the JSON response
    let server_info = parse_bootstrap_response(stdout)?;

    // Return handle that keeps russh session alive
    Ok(BootstrapHandle {
        server_info,
        _ssh_process: None,
        _russh_session: Some(session),
    })
}

fn parse_bootstrap_response(output: Vec<u8>) -> Result<ServerInfo> {
    let json = String::from_utf8(output).map_err(|e| Error::Protocol {
        message: format!("invalid UTF-8 in bootstrap response: {}", e),
    })?;

    debug!(response = %json, "Bootstrap response received");

    let response = BootstrapResponse::parse(&json)?;
    let server_info = response.get_server_info()?.clone();

    Ok(server_info)
}

/// Load a private key and authenticate with it.
async fn load_and_auth_key(
    session: &mut client::Handle<SshHandler>,
    username: &str,
    path: &PathBuf,
) -> Result<bool> {
    let key_data = tokio::fs::read(path).await.map_err(|e| Error::Transport {
        message: format!("failed to read identity file: {}", e),
    })?;

    let key_pair = russh_keys::decode_secret_key(&String::from_utf8_lossy(&key_data), None)
        .map_err(|e| Error::Transport {
            message: format!("failed to decode private key: {}", e),
        })?;

    let auth_result = session
        .authenticate_publickey(username, Arc::new(key_pair))
        .await
        .map_err(|e| Error::Transport {
            message: format!("public key auth failed: {}", e),
        })?;

    Ok(auth_result)
}

/// Try to authenticate using SSH agent.
async fn try_agent_auth(session: &mut client::Handle<SshHandler>, username: &str) -> Result<bool> {
    // Try to connect to SSH agent
    let agent_path = std::env::var("SSH_AUTH_SOCK").ok();

    if agent_path.is_none() {
        debug!("SSH_AUTH_SOCK not set, agent auth unavailable");
        return Ok(false);
    }

    debug!("Attempting SSH agent authentication");

    // russh doesn't have built-in agent support in all versions
    // For now, we'll try without agent
    // A full implementation would use russh-keys::agent

    // Try "none" auth first to see what methods are available
    let _ = session.authenticate_none(username).await;

    // Return false to indicate we couldn't authenticate via agent
    // The caller should try other methods or fail
    Ok(false)
}

/// Find default identity files.
pub fn default_identity_files() -> Vec<PathBuf> {
    let home = std::env::var("HOME").ok();

    let mut files = Vec::new();

    if let Some(home) = home {
        let ssh_dir = PathBuf::from(&home).join(".ssh");

        // Common key names in preference order
        for name in &["id_ed25519", "id_ecdsa", "id_rsa", "id_dsa"] {
            let path = ssh_dir.join(name);
            if path.exists() {
                files.push(path);
            }
        }
    }

    files
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
        assert!(matches!(config.mode, BootstrapMode::SshCli));
    }

    #[test]
    fn default_identity_files_returns_vec() {
        // Just verify it doesn't panic
        let files = default_identity_files();
        // May or may not have files depending on environment
        let _ = files;
    }
}
