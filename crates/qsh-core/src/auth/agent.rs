//! SSH agent client for key listing and signing.
//!
//! Uses the system SSH agent pointed to by `SSH_AUTH_SOCK` via the
//! `ssh-agent-client-rs` crate. This provides a synchronous protocol
//! implementation; we wrap it in `spawn_blocking` so that qsh's async
//! runtime is not blocked during agent operations.

use std::path::PathBuf;

use ssh_key::public::PublicKey;
use tracing::{debug, warn};

use crate::error::{Error, Result};

/// SSH agent connection.
pub struct Agent {
    /// Path to the SSH agent socket.
    socket_path: PathBuf,
    /// Public keys currently available from the agent.
    keys: Vec<PublicKey>,
}

impl Agent {
    /// Connect to the SSH agent via SSH_AUTH_SOCK.
    ///
    /// Returns `Ok(None)` if `SSH_AUTH_SOCK` is not set or if the agent
    /// cannot be contacted. On success, eagerly fetches the list of
    /// available public keys so that subsequent calls to `list_keys`
    /// are cheap.
    pub async fn connect() -> Result<Option<Self>> {
        // Check if SSH_AUTH_SOCK is set.
        let sock = match std::env::var_os("SSH_AUTH_SOCK") {
            Some(v) => v,
            None => {
                debug!("SSH_AUTH_SOCK not set, agent unavailable");
                return Ok(None);
            }
        };

        let socket_path = PathBuf::from(sock);

        // Use a blocking task to talk to the agent so we don't block
        // the async runtime.
        let keys: Vec<PublicKey> = match tokio::task::spawn_blocking({
            let socket_path = socket_path.clone();
            move || -> Result<Vec<PublicKey>> {
                use ssh_agent_client_rs::{Client, Identity};

                let mut client = Client::connect(&socket_path).map_err(|e| Error::Protocol {
                    message: format!("failed to connect to SSH agent: {}", e),
                })?;

                let identities = client
                    .list_all_identities()
                    .map_err(|e| Error::Protocol {
                        message: format!("failed to list identities from SSH agent: {}", e),
                    })?;

                let mut keys = Vec::new();
                for identity in identities {
                    match identity {
                        Identity::PublicKey(pk_cow) => {
                            keys.push(pk_cow.into_owned());
                        }
                        Identity::Certificate(_) => {
                            // Certificate auth is out of scope for v1; skip.
                            debug!("skipping certificate identity from SSH agent");
                        }
                    }
                }

                Ok(keys)
            }
        })
        .await
        {
            Ok(Ok(k)) => k,
            Ok(Err(e)) => {
                warn!(error = %e, "failed to initialize SSH agent client");
                return Ok(None);
            }
            Err(e) => {
                warn!(error = %e, "SSH agent task panicked during connect");
                return Ok(None);
            }
        };

        if keys.is_empty() {
            debug!(
                path = %socket_path.display(),
                "SSH agent has no usable public keys"
            );
            debug!("SSH_AUTH_SOCK not set, agent unavailable");
            return Ok(None);
        }

        debug!(
            path = %socket_path.display(),
            keys = keys.len(),
            "SSH agent available"
        );

        Ok(Some(Self { socket_path, keys }))
    }

    /// List all keys held by the agent.
    pub fn list_keys(&self) -> &[PublicKey] {
        &self.keys
    }

    /// Sign data with a specific key.
    pub async fn sign(&mut self, key: &PublicKey, data: &[u8]) -> Result<Vec<u8>> {
        use ssh_agent_client_rs::{Client, Identity};

        let socket_path = self.socket_path.clone();
        let key_clone = key.clone();
        let data_vec = data.to_vec();

        let sig_bytes: Vec<u8> = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
            let mut client = Client::connect(&socket_path).map_err(|e| Error::Protocol {
                message: format!("failed to connect to SSH agent: {}", e),
            })?;

            let signature = client
                .sign(Identity::from(&key_clone), &data_vec)
                .map_err(|e| Error::Protocol {
                    message: format!("SSH agent sign failed: {}", e),
                })?;

            Ok(signature.as_bytes().to_vec())
        })
        .await
        .map_err(|e| Error::Protocol {
            message: format!("SSH agent sign task panicked: {}", e),
        })??;

        Ok(sig_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_agent_connect_returns_none() {
        // Should always return None since not implemented
        // SAFETY: This test is single-threaded and doesn't access SSH_AUTH_SOCK
        // from other threads concurrently
        unsafe {
            std::env::remove_var("SSH_AUTH_SOCK");
        }
        let result = Agent::connect().await.unwrap();
        assert!(result.is_none());
    }
}
