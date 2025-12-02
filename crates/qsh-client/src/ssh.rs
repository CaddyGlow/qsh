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
use tokio::process::Command;
use tracing::{debug, info, warn};

use qsh_core::bootstrap::{BootstrapResponse, ServerInfo};
use qsh_core::error::{Error, Result};

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
    /// SSH implementation to use for bootstrap.
    pub mode: BootstrapMode,
}

impl Default for SshConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(30),
            identity_file: None,
            skip_host_key_check: false,
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
pub async fn bootstrap(
    host: &str,
    port: u16,
    user: Option<&str>,
    config: &SshConfig,
) -> Result<ServerInfo> {
    let addr = format!("{}:{}", host, port);
    info!(addr = %addr, user = ?user, mode = ?config.mode, "Bootstrapping via SSH");

    let output = match config.mode {
        BootstrapMode::SshCli => bootstrap_via_ssh_cli(host, port, user, config).await?,
        BootstrapMode::Russh => bootstrap_via_russh(&addr, user, config).await?,
    };

    let server_info = parse_bootstrap_response(output)?;
    info!(
        address = %server_info.address,
        port = server_info.port,
        mode = ?config.mode,
        "Bootstrap successful"
    );

    Ok(server_info)
}

/// Bootstrap using the system `ssh` client.
async fn bootstrap_via_ssh_cli(
    host: &str,
    port: u16,
    user: Option<&str>,
    config: &SshConfig,
) -> Result<Vec<u8>> {
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

    let child = cmd.spawn().map_err(|e| Error::Transport {
        message: format!("failed to spawn ssh: {}", e),
    })?;

    let output = tokio::time::timeout(config.connect_timeout, child.wait_with_output())
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|e| Error::Transport {
            message: format!("ssh command failed: {}", e),
        })?;

    if !output.status.success() {
        let code = output
            .status
            .code()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "terminated by signal".to_string());
        return Err(Error::Transport {
            message: format!(
                "ssh bootstrap failed with code {}: {}",
                code,
                String::from_utf8_lossy(&output.stderr)
            ),
        });
    }

    if !output.stderr.is_empty() {
        debug!(
            stderr = %String::from_utf8_lossy(&output.stderr),
            "ssh bootstrap command stderr"
        );
    }

    Ok(output.stdout)
}

/// Bootstrap using the embedded `russh` client.
async fn bootstrap_via_russh(
    addr: &str,
    user: Option<&str>,
    config: &SshConfig,
) -> Result<Vec<u8>> {
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
    channel
        .exec(true, "qsh-server --bootstrap")
        .await
        .map_err(|e| Error::Transport {
            message: format!("failed to execute bootstrap command: {}", e),
        })?;

    debug!("Bootstrap command executed");

    // Read output
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit_code = None;

    loop {
        let msg = channel.wait().await;
        match msg {
            Some(russh::ChannelMsg::Data { data }) => stdout.extend_from_slice(&data),
            Some(russh::ChannelMsg::ExtendedData { data, ext: 1 }) => {
                if let Ok(stderr_str) = std::str::from_utf8(&data) {
                    debug!(stderr = %stderr_str, "Bootstrap stderr");
                }
                stderr.extend_from_slice(&data);
            }
            Some(russh::ChannelMsg::ExitStatus { exit_status }) => {
                exit_code = Some(exit_status);
            }
            Some(russh::ChannelMsg::Eof) | None => {
                break;
            }
            _ => {}
        }
    }

    // Check exit code
    if let Some(code) = exit_code
        && code != 0
    {
        return Err(Error::Transport {
            message: format!(
                "bootstrap command failed with code {}: {}",
                code,
                String::from_utf8_lossy(&stderr)
            ),
        });
    }

    // Close SSH connection
    let _ = session
        .disconnect(russh::Disconnect::ByApplication, "", "")
        .await;

    Ok(stdout)
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
