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
use std::sync::Arc;

use quinn::{Endpoint, ServerConfig};
use rand::Rng;
use ring::digest::{self, SHA256};
use tracing::{debug, info};

use qsh_core::bootstrap::{BootstrapResponse, ServerInfo};
use qsh_core::constants::{DEFAULT_QUIC_PORT_RANGE, SESSION_KEY_LEN};
use qsh_core::error::{Error, Result};
use qsh_core::transport::server_crypto_config;

/// Bootstrap server that handles single-connection bootstrap mode.
pub struct BootstrapServer {
    /// Generated session key.
    session_key: [u8; SESSION_KEY_LEN],
    /// Self-signed certificate DER.
    cert_der: Vec<u8>,
    /// Certificate hash for pinning.
    cert_hash: Vec<u8>,
    /// Private key DER.
    key_der: Vec<u8>,
    /// Bound address.
    bind_addr: SocketAddr,
    /// QUIC endpoint.
    endpoint: Endpoint,
}

impl BootstrapServer {
    /// Create a new bootstrap server.
    ///
    /// Generates a session key and self-signed certificate, then binds to
    /// an available port in the specified range.
    pub async fn new(bind_ip: IpAddr, port: u16) -> Result<Self> {
        // Generate random session key
        let mut session_key = [0u8; SESSION_KEY_LEN];
        rand::thread_rng().fill(&mut session_key);
        debug!("Generated session key");

        // Generate self-signed certificate
        let cert =
            rcgen::generate_simple_self_signed(vec!["qsh-server".to_string()]).map_err(|e| {
                Error::Transport {
                    message: format!("failed to generate certificate: {}", e),
                }
            })?;

        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.key_pair.serialize_der();

        // Compute certificate hash for pinning
        let cert_hash = digest::digest(&SHA256, &cert_der).as_ref().to_vec();
        debug!(hash_len = cert_hash.len(), "Computed certificate hash");

        // Create TLS config
        let crypto = server_crypto_config(cert_der.clone(), key_der.clone())?;
        let server_config = ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(crypto).map_err(|e| {
                Error::Transport {
                    message: format!("failed to create QUIC config: {}", e),
                }
            })?,
        ));

        // Find an available port and create endpoint
        let endpoint = if port == 0 {
            // Auto-select from port range
            find_available_endpoint(bind_ip, DEFAULT_QUIC_PORT_RANGE, server_config)?
        } else {
            // Use specified port
            let addr = SocketAddr::new(bind_ip, port);
            Endpoint::server(server_config, addr).map_err(|e| Error::Transport {
                message: format!("failed to bind to {}: {}", addr, e),
            })?
        };

        let actual_addr = endpoint.local_addr().map_err(|e| Error::Transport {
            message: format!("failed to get local address: {}", e),
        })?;

        info!(addr = %actual_addr, "Bootstrap server bound");

        Ok(Self {
            session_key,
            cert_der,
            cert_hash,
            key_der,
            bind_addr: actual_addr,
            endpoint,
        })
    }

    /// Get the session key.
    pub fn session_key(&self) -> [u8; SESSION_KEY_LEN] {
        self.session_key
    }

    /// Get the certificate DER.
    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    /// Get the certificate hash.
    pub fn cert_hash(&self) -> &[u8] {
        &self.cert_hash
    }

    /// Get the private key DER.
    pub fn key_der(&self) -> &[u8] {
        &self.key_der
    }

    /// Get the bound address.
    pub fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    /// Get the bound port.
    pub fn port(&self) -> u16 {
        self.bind_addr.port()
    }

    /// Generate the bootstrap response JSON.
    pub fn response(&self, external_addr: Option<&str>) -> BootstrapResponse {
        let address = external_addr
            .map(|s| s.to_string())
            .unwrap_or_else(|| self.bind_addr.ip().to_string());

        let server_info = ServerInfo::new(address, self.port(), self.session_key, &self.cert_hash);

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

    /// Accept a single incoming connection.
    pub async fn accept(&self) -> Result<quinn::Connection> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or(Error::ConnectionClosed)?;

        let conn = incoming.await.map_err(|e| Error::Transport {
            message: format!("connection failed: {}", e),
        })?;

        info!(addr = %conn.remote_address(), "Bootstrap connection accepted");
        Ok(conn)
    }

    /// Close the endpoint.
    pub fn close(&self) {
        self.endpoint
            .close(quinn::VarInt::from_u32(0), b"bootstrap complete");
    }
}

/// Find an available port in the given range and return a bound endpoint.
fn find_available_endpoint(
    ip: IpAddr,
    port_range: (u16, u16),
    server_config: ServerConfig,
) -> Result<Endpoint> {
    for port in port_range.0..=port_range.1 {
        let addr = SocketAddr::new(ip, port);
        match Endpoint::server(server_config.clone(), addr) {
            Ok(endpoint) => {
                // Successfully bound, return the endpoint
                return Ok(endpoint);
            }
            Err(_) => {
                // Port in use, try next
                continue;
            }
        }
    }

    Err(Error::Transport {
        message: format!(
            "no available port in range {}-{}",
            port_range.0, port_range.1
        ),
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
        let hash = digest::digest(&SHA256, data);
        assert_eq!(hash.as_ref().len(), 32);
    }
}
