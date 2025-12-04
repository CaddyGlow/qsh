//! Standalone client mode with SSH key authentication.
//!
//! In direct mode, the client:
//! 1. Connects directly to the qsh server via QUIC
//! 2. Verifies server identity against known_hosts
//! 3. Proves client identity via SSH key signature
//!
//! This mirrors SSH's trust model without requiring an SSH connection.

use std::path::PathBuf;

use qsh_core::auth::{
    build_client_sign_data, default_client_key_paths, default_known_hosts_paths, key_fingerprint,
    load_private_key, prompt_passphrase, sign_client, verify_server, Agent, HostStatus, KnownHosts,
    LocalSigner, Signer,
};
use qsh_core::constants::MAX_PASSPHRASE_ATTEMPTS;
use qsh_core::protocol::{AuthChallengePayload, AuthResponsePayload, Codec, Message};
use qsh_core::{Error, Result};
use ssh_key::public::PublicKey;
use tracing::{debug, error, info, warn};

/// Standalone client configuration.
#[derive(Debug, Clone)]
pub struct DirectConfig {
    /// Server address (host:port).
    pub server_addr: String,
    /// Path to client private key (optional, uses defaults if not specified).
    pub key_path: Option<PathBuf>,
    /// Path to known_hosts file (optional, uses defaults if not specified).
    pub known_hosts_path: Option<PathBuf>,
    /// Accept unknown hosts (TOFU).
    pub accept_unknown_host: bool,
    /// Disable SSH agent.
    pub no_agent: bool,
}

impl DirectConfig {
    /// Parse the server address into host and port.
    pub fn parse_addr(&self) -> Result<(&str, u16)> {
        if let Some(colon_pos) = self.server_addr.rfind(':') {
            let host = &self.server_addr[..colon_pos];
            let port_str = &self.server_addr[colon_pos + 1..];
            let port = port_str.parse::<u16>().map_err(|_| Error::Protocol {
                message: format!("invalid port: {}", port_str),
            })?;
            Ok((host, port))
        } else {
            // Default to port 4433 if not specified
            Ok((&self.server_addr, 4433))
        }
    }
}

/// Client authenticator for standalone mode.
pub struct DirectAuthenticator {
    /// Known hosts database.
    known_hosts: KnownHosts,
    /// Path to known_hosts file for TOFU.
    known_hosts_path: PathBuf,
    /// Client signer (from file or agent).
    signer: Option<Box<dyn Signer>>,
    /// SSH agent (if available).
    agent: Option<Agent>,
    /// Accept unknown hosts.
    accept_unknown_host: bool,
    /// Target hostname.
    hostname: String,
    /// Target port.
    port: u16,
}

impl DirectAuthenticator {
    /// Create a new direct authenticator.
    pub async fn new(config: &DirectConfig) -> Result<Self> {
        let (hostname, port) = config.parse_addr()?;

        // Load known_hosts
        let known_hosts_paths = if let Some(path) = &config.known_hosts_path {
            vec![path.clone()]
        } else {
            default_known_hosts_paths()
        };

        let known_hosts = KnownHosts::load(&known_hosts_paths)?;
        let known_hosts_path = known_hosts_paths
            .into_iter()
            .next()
            .unwrap_or_else(|| PathBuf::from("~/.ssh/known_hosts"));

        // Try to get a signer
        let (signer, agent) = if !config.no_agent {
            // Try SSH agent first
            match Agent::connect().await {
                Ok(Some(agent)) => {
                    debug!(keys = agent.list_keys().len(), "connected to SSH agent");
                    (None, Some(agent))
                }
                Ok(None) => {
                    debug!("SSH agent not available");
                    (load_file_signer(&config.key_path)?, None)
                }
                Err(e) => {
                    warn!(error = %e, "failed to connect to SSH agent, falling back to file");
                    (load_file_signer(&config.key_path)?, None)
                }
            }
        } else {
            (load_file_signer(&config.key_path)?, None)
        };

        Ok(Self {
            known_hosts,
            known_hosts_path,
            signer,
            agent,
            accept_unknown_host: config.accept_unknown_host,
            hostname: hostname.to_string(),
            port,
        })
    }

    /// Verify the server's identity from an AuthChallenge.
    pub fn verify_server(&mut self, challenge: &AuthChallengePayload) -> Result<()> {
        // Parse server's public key
        let server_key =
            PublicKey::from_openssh(&challenge.server_public_key).map_err(|e| {
                Error::Protocol {
                    message: format!("invalid server public key: {}", e),
                }
            })?;

        let fingerprint = key_fingerprint(&server_key);
        debug!(fingerprint = %fingerprint, "verifying server key");

        // Check known_hosts
        match self.known_hosts.verify_host(&self.hostname, self.port, &server_key) {
            HostStatus::Known => {
                info!(fingerprint = %fingerprint, "server key verified");
            }
            HostStatus::Unknown => {
                if self.accept_unknown_host {
                    warn!(
                        fingerprint = %fingerprint,
                        hostname = %self.hostname,
                        port = self.port,
                        "accepting unknown host key (TOFU)"
                    );
                    // Persist the key
                    KnownHosts::persist_host(
                        &self.known_hosts_path,
                        &self.hostname,
                        self.port,
                        &server_key,
                    )?;
                } else {
                    error!(
                        fingerprint = %fingerprint,
                        hostname = %self.hostname,
                        "unknown host key, connection refused"
                    );
                    return Err(Error::Protocol {
                        message: format!(
                            "unknown host key for {}:{} (fingerprint: {}). Use --accept-unknown-host to accept.",
                            self.hostname, self.port, fingerprint
                        ),
                    });
                }
            }
            HostStatus::Changed { expected_fingerprint, actual_fingerprint } => {
                error!(
                    hostname = %self.hostname,
                    expected = %expected_fingerprint,
                    actual = %actual_fingerprint,
                    "HOST KEY CHANGED - possible MITM attack"
                );
                return Err(Error::Protocol {
                    message: format!(
                        "HOST KEY CHANGED for {}:{}! Expected {}, got {}. \
                        This could indicate a man-in-the-middle attack.",
                        self.hostname, self.port, expected_fingerprint, actual_fingerprint
                    ),
                });
            }
            HostStatus::Revoked => {
                error!(
                    fingerprint = %fingerprint,
                    hostname = %self.hostname,
                    "server key is revoked"
                );
                return Err(Error::Protocol {
                    message: format!(
                        "server key for {}:{} is revoked",
                        self.hostname, self.port
                    ),
                });
            }
        }

        // Verify server signature (SSH-style: no hostname in signature)
        let valid = verify_server(
            &server_key,
            &challenge.server_signature,
            &challenge.challenge,
            &challenge.server_nonce,
        )?;

        if !valid {
            error!("server signature verification failed");
            return Err(Error::Protocol {
                message: "server signature verification failed".into(),
            });
        }

        debug!("server signature verified");
        Ok(())
    }

    /// Generate the client's authentication response.
    pub async fn generate_response(
        &mut self,
        challenge: &AuthChallengePayload,
    ) -> Result<AuthResponsePayload> {
        use qsh_core::auth::generate_nonce;

        let client_nonce = generate_nonce();

        // Get signer and sign (SSH-style: no hostname in signature)
        let (signature, public_key_openssh) = if let Some(ref mut agent) = self.agent {
            // Try agent keys
            let keys = agent.list_keys().to_vec();
            let mut last_error = None;

            for key in &keys {
                let data = build_client_sign_data(
                    &challenge.challenge,
                    &challenge.server_nonce,
                    &client_nonce,
                );

                match agent.sign(key, &data).await {
                    Ok(sig) => {
                        let pk_openssh = key.to_openssh().map_err(|e| Error::Protocol {
                            message: format!("failed to encode public key: {}", e),
                        })?;
                        debug!(fingerprint = %key_fingerprint(key), "signed with agent key");
                        return Ok(AuthResponsePayload {
                            client_public_key: pk_openssh,
                            client_nonce,
                            signature: sig,
                        });
                    }
                    Err(e) => {
                        debug!(
                            fingerprint = %key_fingerprint(key),
                            error = %e,
                            "agent key signing failed, trying next"
                        );
                        last_error = Some(e);
                    }
                }
            }

            // Fall back to file signer if agent failed
            if let Some(ref signer) = self.signer {
                let sig = sign_client(
                    signer.as_ref(),
                    &challenge.challenge,
                    &challenge.server_nonce,
                    &client_nonce,
                )?;
                let pk_openssh = signer.public_key().to_openssh().map_err(|e| Error::Protocol {
                    message: format!("failed to encode public key: {}", e),
                })?;
                (sig, pk_openssh)
            } else if let Some(e) = last_error {
                return Err(e);
            } else {
                return Err(Error::Protocol {
                    message: "no signing key available".into(),
                });
            }
        } else if let Some(ref signer) = self.signer {
            let sig = sign_client(
                signer.as_ref(),
                &challenge.challenge,
                &challenge.server_nonce,
                &client_nonce,
            )?;
            let pk_openssh = signer.public_key().to_openssh().map_err(|e| Error::Protocol {
                message: format!("failed to encode public key: {}", e),
            })?;
            (sig, pk_openssh)
        } else {
            return Err(Error::Protocol {
                message: "no signing key available".into(),
            });
        };

        Ok(AuthResponsePayload {
            client_public_key: public_key_openssh,
            client_nonce,
            signature,
        })
    }

    /// Get the target host and port.
    pub fn target(&self) -> (&str, u16) {
        (&self.hostname, self.port)
    }
}

/// Load a file-based signer.
fn load_file_signer(key_path: &Option<PathBuf>) -> Result<Option<Box<dyn Signer>>> {
    let paths = if let Some(path) = key_path {
        vec![path.clone()]
    } else {
        default_client_key_paths()
    };

    for path in paths {
        if !path.exists() {
            continue;
        }

        debug!(path = %path.display(), "trying to load private key");

        let prompt = || {
            prompt_passphrase(&format!("Enter passphrase for {}: ", path.display()))
        };

        match load_private_key(&path, prompt, MAX_PASSPHRASE_ATTEMPTS) {
            Ok(key) => {
                info!(
                    path = %path.display(),
                    fingerprint = %key_fingerprint(&key.public_key().clone()),
                    "loaded private key"
                );
                return Ok(Some(Box::new(LocalSigner::new(key))));
            }
            Err(e) => {
                debug!(path = %path.display(), error = %e, "failed to load key");
            }
        }
    }

    Ok(None)
}


/// Perform the authentication handshake with the server.
pub async fn authenticate<S, R>(
    authenticator: &mut DirectAuthenticator,
    send: &mut S,
    recv: &mut R,
) -> Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
    R: tokio::io::AsyncRead + Unpin,
{
    use bytes::BytesMut;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Read AuthChallenge
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await.map_err(|e| Error::Io(e))?;
    let len = u32::from_le_bytes(len_buf) as usize;

    if len > qsh_core::constants::MAX_MESSAGE_SIZE {
        return Err(Error::Protocol {
            message: "message too large".into(),
        });
    }

    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await.map_err(|e| Error::Io(e))?;

    // Prepend length for decoding
    let mut full_buf = BytesMut::with_capacity(4 + len);
    full_buf.extend_from_slice(&len_buf);
    full_buf.extend_from_slice(&buf);

    let msg = Codec::decode(&mut full_buf)?.ok_or_else(|| Error::Protocol {
        message: "incomplete message".into(),
    })?;

    let challenge = match msg {
        Message::AuthChallenge(c) => c,
        Message::AuthFailure(f) => {
            return Err(Error::Protocol {
                message: format!("server sent auth failure: {} - {}", f.code, f.message),
            });
        }
        _ => {
            return Err(Error::Protocol {
                message: format!(
                    "expected AuthChallenge, got {:?}",
                    std::mem::discriminant(&msg)
                ),
            });
        }
    };

    // Verify server
    authenticator.verify_server(&challenge)?;

    // Generate and send response
    let response = authenticator.generate_response(&challenge).await?;
    let response_msg = Message::AuthResponse(response);
    let encoded = Codec::encode(&response_msg)?;

    send.write_all(&encoded).await.map_err(|e| Error::Io(e))?;

    // Check for AuthFailure response
    // Note: If successful, server will send Hello/HelloAck next
    // We don't wait for explicit success - the next message determines outcome

    debug!("authentication response sent");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_direct_config_parse_addr() {
        let config = DirectConfig {
            server_addr: "example.com:4433".into(),
            key_path: None,
            known_hosts_path: None,
            accept_unknown_host: false,
            no_agent: false,
        };
        let (host, port) = config.parse_addr().unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 4433);
    }

    #[test]
    fn test_direct_config_parse_addr_default_port() {
        let config = DirectConfig {
            server_addr: "example.com".into(),
            key_path: None,
            known_hosts_path: None,
            accept_unknown_host: false,
            no_agent: false,
        };
        let (host, port) = config.parse_addr().unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 4433);
    }

    #[test]
    fn test_build_client_sign_data() {
        let challenge = [1u8; 32];
        let server_nonce = [2u8; 32];
        let client_nonce = [3u8; 32];

        let data = build_client_sign_data(&challenge, &server_nonce, &client_nonce);

        // Should contain: AUTH_CTX(21) + "client"(6) + challenge(32) + server_nonce(32) + client_nonce(32)
        assert!(data.len() > 90);
    }
}
