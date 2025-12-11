//! Server bootstrap mode implementation.
//!
//! When run with `--bootstrap`, the server:
//! 1. Generates a random session key
//! 2. Generates a self-signed certificate
//! 3. Binds to an available port
//! 4. Outputs JSON with connection info to stdout
//! 5. Accepts a single client connection
//! 6. Transitions to normal session mode

use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rand::Rng;
use tokio::fs::OpenOptions;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tracing::{debug, info};

use crate::session::SessionAuthorizer;
use libc;
use nix::sys::stat::Mode;
use nix::unistd::mkfifo;
use qsh_core::bootstrap::{BootstrapResponse, ServerInfo};
use qsh_core::constants::SESSION_KEY_LEN;
use qsh_core::error::{Error, Result};
use qsh_core::transport::{cert_hash, generate_self_signed_cert};

/// Bootstrap server that handles single-connection bootstrap mode.
pub struct BootstrapServer {
    /// Generated session key.
    session_key: [u8; SESSION_KEY_LEN],
    /// Self-signed certificate PEM.
    cert_pem: Vec<u8>,
    /// Certificate hash for pinning (SHA256 of first cert DER).
    cert_hash_bytes: Vec<u8>,
    /// Private key PEM.
    key_pem: Vec<u8>,
    /// Bound address.
    bind_addr: SocketAddr,
    /// UDP socket (only used with quiche backend for socket sharing).
    #[cfg(feature = "quiche-backend")]
    socket: Arc<UdpSocket>,
}

impl BootstrapServer {
    /// Create a new bootstrap server.
    ///
    /// Generates a session key and self-signed certificate, then binds to
    /// an available port in the specified range.
    pub async fn new(bind_ip: IpAddr, port: u16, port_range: (u16, u16)) -> Result<Self> {
        // Generate random session key
        let mut session_key = [0u8; SESSION_KEY_LEN];
        rand::thread_rng().fill(&mut session_key);
        debug!("Generated session key");

        // Generate self-signed certificate (returns PEM)
        let (cert_pem, key_pem) = generate_self_signed_cert()?;

        // Extract DER from PEM for hash computation
        let cert_der = extract_first_cert_der(&cert_pem)?;
        let cert_hash_bytes = cert_hash(&cert_der);
        debug!(
            hash_len = cert_hash_bytes.len(),
            "Computed certificate hash"
        );

        // Find an available port and create socket
        // For quiche backend, we pre-bind the socket for sharing with QshListener
        #[cfg(feature = "quiche-backend")]
        let (bind_addr, socket) = {
            let socket = if port == 0 {
                find_available_socket(bind_ip, port_range).await?
            } else {
                let addr = SocketAddr::new(bind_ip, port);
                UdpSocket::bind(addr).await.map_err(|e| Error::Transport {
                    message: format!("failed to bind to {}: {}", addr, e),
                })?
            };
            let addr = socket.local_addr().map_err(|e| Error::Transport {
                message: format!("failed to get local address: {}", e),
            })?;
            (addr, Arc::new(socket))
        };

        // For s2n-quic backend, we just determine the bind address
        // The socket will be managed by the acceptor
        #[cfg(not(feature = "quiche-backend"))]
        let bind_addr = {
            // Find an available port by briefly binding and releasing
            let socket = if port == 0 {
                find_available_socket(bind_ip, port_range).await?
            } else {
                let addr = SocketAddr::new(bind_ip, port);
                UdpSocket::bind(addr).await.map_err(|e| Error::Transport {
                    message: format!("failed to bind to {}: {}", addr, e),
                })?
            };
            let addr = socket.local_addr().map_err(|e| Error::Transport {
                message: format!("failed to get local address: {}", e),
            })?;
            drop(socket); // Release for the acceptor to bind
            addr
        };

        info!(addr = %bind_addr, "Bootstrap server bound");

        Ok(Self {
            session_key,
            cert_pem,
            cert_hash_bytes,
            key_pem,
            bind_addr,
            #[cfg(feature = "quiche-backend")]
            socket,
        })
    }

    /// Get the session key.
    pub fn session_key(&self) -> [u8; SESSION_KEY_LEN] {
        self.session_key
    }

    /// Get the certificate PEM.
    pub fn cert_pem(&self) -> &[u8] {
        &self.cert_pem
    }

    /// Get the certificate hash.
    pub fn cert_hash(&self) -> &[u8] {
        &self.cert_hash_bytes
    }

    /// Get the private key PEM.
    pub fn key_pem(&self) -> &[u8] {
        &self.key_pem
    }

    /// Get the bound address.
    pub fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    /// Get the bound port.
    pub fn port(&self) -> u16 {
        self.bind_addr.port()
    }

    /// Clone the socket (keeps the listener alive while self is held).
    /// Only available with the quiche backend.
    #[cfg(feature = "quiche-backend")]
    pub fn socket(&self) -> Arc<UdpSocket> {
        Arc::clone(&self.socket)
    }

    /// Generate the bootstrap response JSON.
    pub fn response(&self, external_addr: Option<&str>) -> BootstrapResponse {
        self.response_for_key(self.session_key, external_addr)
    }

    /// Build a response for a specific session key (used for additional bootstrap requests).
    pub fn response_for_key(
        &self,
        session_key: [u8; SESSION_KEY_LEN],
        external_addr: Option<&str>,
    ) -> BootstrapResponse {
        let address = external_addr
            .map(|s| s.to_string())
            .unwrap_or_else(|| self.bind_addr.ip().to_string());

        let server_info = ServerInfo::new(address, self.port(), session_key, &self.cert_hash_bytes);

        BootstrapResponse::ok(server_info)
    }

    /// Output the bootstrap response to stdout.
    pub fn print_response(&self, external_addr: Option<&str>) -> Result<()> {
        let response = self.response(external_addr);
        let json = response.to_json()?;
        println!("{}", json);
        // When invoked via SSH the stdout is a pipe, so force a flush to ensure
        // the client sees the JSON before we block waiting for QUIC.
        io::stdout().flush()?;
        Ok(())
    }

    /// Get the local address.
    pub fn local_addr(&self) -> SocketAddr {
        self.bind_addr
    }
}

/// Extract the first certificate DER from PEM data.
fn extract_first_cert_der(pem_data: &[u8]) -> Result<Vec<u8>> {
    let mut reader = std::io::BufReader::new(pem_data);
    for cert in rustls_pemfile::certs(&mut reader) {
        match cert {
            Ok(c) => return Ok(c.to_vec()),
            Err(_) => continue,
        }
    }
    Err(Error::CertificateError {
        message: "no certificate found in PEM data".to_string(),
    })
}

/// Find an available port in the given range and return a bound socket.
async fn find_available_socket(ip: IpAddr, port_range: (u16, u16)) -> Result<UdpSocket> {
    for port in port_range.0..=port_range.1 {
        let addr = SocketAddr::new(ip, port);
        match UdpSocket::bind(addr).await {
            Ok(socket) => return Ok(socket),
            Err(_) => continue,
        }
    }

    Err(Error::Transport {
        message: format!(
            "no available port in range {}-{}",
            port_range.0, port_range.1
        ),
    })
}

/// Compute the per-UID bootstrap pipe path.
pub fn bootstrap_pipe_path() -> PathBuf {
    let uid = unsafe { libc::geteuid() as u32 };
    PathBuf::from(format!("/tmp/qsh-server-{}.pipe", uid))
}

/// Try to use an existing bootstrap instance by sending a request down the pipe.
/// Returns the JSON response if successful.
pub async fn try_existing_bootstrap(pipe_path: &Path) -> Result<Option<String>> {
    if !pipe_path.exists() {
        return Ok(None);
    }

    let open_result = tokio::time::timeout(
        Duration::from_secs(1),
        OpenOptions::new().read(true).write(true).open(pipe_path),
    )
    .await;

    let file = match open_result {
        Ok(Ok(f)) => f,
        Ok(Err(e)) => {
            tracing::debug!(error = %e, "Failed to open existing bootstrap pipe");
            return Ok(None);
        }
        Err(_) => {
            tracing::debug!("Timed out opening existing bootstrap pipe");
            return Ok(None);
        }
    };

    let (reader, mut writer) = tokio::io::split(file);
    let mut reader = BufReader::new(reader);

    if let Err(e) = writer.write_all(b"new\n").await {
        tracing::debug!(error = %e, "Failed to write request to bootstrap pipe");
        return Ok(None);
    }

    let mut line = String::new();
    match tokio::time::timeout(Duration::from_secs(2), reader.read_line(&mut line)).await {
        Ok(Ok(0)) => Ok(None),
        Ok(Ok(_)) => {
            let trimmed = line.trim_end();
            // Ignore self-echoes or garbage; only accept valid JSON.
            if trimmed.is_empty() || serde_json::from_str::<BootstrapResponse>(trimmed).is_err() {
                tracing::debug!("Bootstrap pipe returned non-JSON response, ignoring");
                Ok(None)
            } else {
                Ok(Some(trimmed.to_string()))
            }
        }
        Ok(Err(e)) => {
            tracing::debug!(error = %e, "Failed to read bootstrap response");
            Ok(None)
        }
        Err(_) => {
            tracing::debug!("Timed out waiting for bootstrap response");
            Ok(None)
        }
    }
}

/// Ensure the pipe exists for the current server instance.
pub fn create_pipe(path: &Path) -> io::Result<PipeGuard> {
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    mkfifo(path, Mode::from_bits_truncate(0o600))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    Ok(PipeGuard {
        path: path.to_path_buf(),
    })
}

/// RAII guard that cleans up the pipe on drop.
pub struct PipeGuard {
    path: PathBuf,
}

impl Drop for PipeGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Spawn a background task to serve bootstrap requests via the named pipe.
pub fn spawn_pipe_listener(
    pipe_path: PathBuf,
    bootstrap: Arc<BootstrapServer>,
    authorizer: Arc<SessionAuthorizer>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let file = match OpenOptions::new()
                .read(true)
                .write(true)
                .open(&pipe_path)
                .await
            {
                Ok(f) => f,
                Err(e) => {
                    tracing::warn!(error = %e, "Bootstrap pipe open failed");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
            };

            let (reader, mut writer) = tokio::io::split(file);
            let mut reader = BufReader::new(reader);
            let mut line = String::new();

            match reader.read_line(&mut line).await {
                Ok(0) => {
                    // Writer closed
                    continue;
                }
                Ok(_) => {
                    let key = authorizer.allow_random().await;
                    let response = bootstrap.response_for_key(key, None);
                    match response.to_json() {
                        Ok(json) => {
                            if let Err(e) = writer.write_all(json.as_bytes()).await {
                                tracing::warn!(error = %e, "Failed to write pipe response");
                            } else {
                                let _ = writer.write_all(b"\n").await;
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "Failed to serialize bootstrap response");
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to read bootstrap pipe request");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    })
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_key_is_random() {
        // Can't really test randomness, but verify length
        let mut key = [0u8; SESSION_KEY_LEN];
        rand::thread_rng().fill(&mut key);
        assert_eq!(key.len(), 32);
        // Should not be all zeros (extremely unlikely with random)
        assert!(key.iter().any(|&b| b != 0));
    }

    #[test]
    fn cert_hash_length() {
        // SHA256 produces 32 bytes
        let data = b"test certificate data";
        let hash = cert_hash(data);
        assert_eq!(hash.len(), 32);
    }
}
