//! Bootstrap protocol for qsh server discovery.
//!
//! The bootstrap protocol uses SSH to:
//! 1. Verify the server supports qsh
//! 2. Get QUIC connection parameters (address, port)
//! 3. Exchange a session key for secure reconnection
//!
//! Protocol flow:
//! 1. Client SSH's to server and runs `qsh-server --bootstrap`
//! 2. Server outputs JSON bootstrap response
//! 3. Client parses response and connects via QUIC

use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use rand::Rng;
use tokio::net::UdpSocket;

use crate::connect_mode::ConnectMode;
use crate::constants::SESSION_KEY_LEN;
use crate::error::{Error, Result};
use crate::transport::{cert_hash, generate_self_signed_cert};

mod response;

pub use response::{BootstrapResponse, EndpointInfo};

// =============================================================================
// Bootstrap Options
// =============================================================================

/// Configuration options for bootstrap mode.
///
/// Used by both `qsh` and `qsh-server` when running in bootstrap/responder mode
/// to configure listener behavior and connection parameters.
#[derive(Debug, Clone, Default)]
pub struct BootstrapOptions {
    /// Port range for QUIC listener (start, end).
    ///
    /// If `None`, the OS will assign any available ephemeral port.
    /// Typically set to Mosh-style range (60001-60999) for firewall compatibility.
    pub port_range: Option<(u16, u16)>,

    /// Additional arguments to pass to the remote bootstrap command.
    ///
    /// Only used when invoking `qsh-server --bootstrap` or `qsh --bootstrap` via SSH.
    /// The initiator can use this to pass flags to the remote responder.
    pub extra_args: Option<String>,

    /// Environment variables to pass to the remote bootstrap command.
    ///
    /// Only used when invoking bootstrap via SSH. Format: vec![("KEY", "VALUE"), ...].
    pub extra_env: Vec<(String, String)>,

    /// External address to advertise in bootstrap response.
    ///
    /// When set, overrides the bind address in the JSON output. Useful when
    /// the listener is behind NAT and needs to advertise a public IP.
    pub external_addr: Option<String>,

    /// Timeout for bootstrap connection.
    ///
    /// Maximum time to wait for the initiator to connect after bootstrap info is sent.
    /// Typically 30 seconds.
    pub timeout: Duration,
}

impl BootstrapOptions {
    /// Create a new BootstrapOptions with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the port range.
    pub fn with_port_range(mut self, start: u16, end: u16) -> Self {
        self.port_range = Some((start, end));
        self
    }

    /// Set additional arguments.
    pub fn with_extra_args(mut self, args: impl Into<String>) -> Self {
        self.extra_args = Some(args.into());
        self
    }

    /// Add an environment variable.
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra_env.push((key.into(), value.into()));
        self
    }

    /// Set the external address.
    pub fn with_external_addr(mut self, addr: impl Into<String>) -> Self {
        self.external_addr = Some(addr.into());
        self
    }

    /// Set the timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

// =============================================================================
// Session Key Generation
// =============================================================================

/// Generate a random session key.
///
/// This creates a cryptographically secure random key for session authentication.
pub fn generate_session_key() -> [u8; SESSION_KEY_LEN] {
    let mut key = [0u8; SESSION_KEY_LEN];
    rand::rng().fill(&mut key);
    key
}

// =============================================================================
// Bootstrap Endpoint
// =============================================================================

/// Prepared bootstrap endpoint ready to accept a connection.
///
/// Created by calling `BootstrapEndpoint::new()`, which:
/// 1. Generates an ephemeral session key
/// 2. Creates a self-signed TLS certificate
/// 3. Finds an available port (or binds to a specified range)
///
/// This struct is used by both `qsh` and `qsh-server` when running in
/// bootstrap/responder mode.
///
/// # Lifecycle
///
/// 1. Create endpoint with `new()`
/// 2. Print bootstrap JSON to stdout with `print_response()`
/// 3. Create QUIC acceptor using `cert_pem` and `key_pem`
/// 4. Accept a single connection
/// 5. Perform handshake using `session_key`
pub struct BootstrapEndpoint {
    /// Ephemeral session key for authentication (32 bytes).
    ///
    /// Generated randomly. Must be transmitted to the initiator via the bootstrap JSON
    /// and used during handshake for mutual authentication.
    pub session_key: [u8; SESSION_KEY_LEN],

    /// Self-signed TLS certificate in PEM format.
    ///
    /// Used to configure the QUIC listener. Valid for a short time window.
    pub cert_pem: Vec<u8>,

    /// Private key for the certificate in PEM format.
    ///
    /// Used to configure the QUIC listener.
    pub key_pem: Vec<u8>,

    /// SHA-256 hash of the certificate (DER encoding).
    ///
    /// Transmitted to the initiator for certificate pinning. The initiator
    /// verifies this hash to prevent MITM attacks.
    pub cert_hash: Vec<u8>,

    /// Address the QUIC listener will bind to.
    ///
    /// Determined during `new()` by finding an available port in the specified range.
    pub bind_addr: SocketAddr,
}

impl BootstrapEndpoint {
    /// Create a new bootstrap endpoint.
    ///
    /// This generates a session key and self-signed certificate, then binds to
    /// an available port in the specified range (or any available port if no range).
    pub async fn new(bind_ip: IpAddr, options: &BootstrapOptions) -> Result<Self> {
        // Generate random session key
        let session_key = generate_session_key();

        // Generate self-signed certificate (returns PEM)
        let (cert_pem, key_pem) = generate_self_signed_cert()?;

        // Extract DER from PEM for hash computation
        let cert_der = extract_first_cert_der(&cert_pem)?;
        let cert_hash_bytes = cert_hash(&cert_der);

        // Determine bind address
        // We bind temporarily to verify port availability, then release the socket
        // The actual acceptor will bind when it starts
        let bind_addr = if let Some((start, end)) = options.port_range {
            find_available_port(bind_ip, (start, end)).await?
        } else {
            // Use any available port
            let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
                .await
                .map_err(|e| Error::Transport {
                    message: format!("failed to bind to any port: {}", e),
                })?;
            let addr = socket.local_addr().map_err(|e| Error::Transport {
                message: format!("failed to get local address: {}", e),
            })?;
            drop(socket); // Release for the acceptor to bind
            addr
        };

        Ok(Self {
            session_key,
            cert_pem,
            key_pem,
            cert_hash: cert_hash_bytes,
            bind_addr,
        })
    }

    /// Generate the bootstrap response JSON.
    pub fn response(&self, connect_mode: ConnectMode) -> BootstrapResponse {
        let address = self.bind_addr.ip().to_string();
        let port = self.bind_addr.port();

        let endpoint_info = EndpointInfo::with_connect_mode(
            address,
            port,
            self.session_key,
            &self.cert_hash,
            connect_mode,
        );

        BootstrapResponse::ok(endpoint_info)
    }

    /// Generate a bootstrap response with an attach pipe path.
    pub fn response_with_pipe(
        &self,
        connect_mode: ConnectMode,
        attach_pipe: &str,
    ) -> BootstrapResponse {
        let address = self.bind_addr.ip().to_string();
        let port = self.bind_addr.port();

        let endpoint_info = EndpointInfo::with_attach_pipe(
            address,
            port,
            self.session_key,
            &self.cert_hash,
            connect_mode,
            attach_pipe,
        );

        BootstrapResponse::ok(endpoint_info)
    }

    /// Generate a bootstrap response with an external address override.
    pub fn response_with_external(
        &self,
        external_addr: &str,
        connect_mode: ConnectMode,
    ) -> BootstrapResponse {
        let port = self.bind_addr.port();

        let endpoint_info = EndpointInfo::with_connect_mode(
            external_addr.to_string(),
            port,
            self.session_key,
            &self.cert_hash,
            connect_mode,
        );

        BootstrapResponse::ok(endpoint_info)
    }

    /// Print the bootstrap response to stdout.
    pub fn print_response(&self, connect_mode: ConnectMode) -> Result<()> {
        let response = self.response(connect_mode);
        let json = response.to_json()?;
        println!("{}", json);
        // Force a flush to ensure the client sees the JSON immediately
        io::stdout().flush()?;
        Ok(())
    }

    /// Print the bootstrap response with attach pipe to stdout.
    pub fn print_response_with_pipe(
        &self,
        connect_mode: ConnectMode,
        attach_pipe: &str,
    ) -> Result<()> {
        let response = self.response_with_pipe(connect_mode, attach_pipe);
        let json = response.to_json()?;
        println!("{}", json);
        // Force a flush to ensure the client sees the JSON immediately
        io::stdout().flush()?;
        Ok(())
    }

    /// Print the bootstrap response with external address to stdout.
    pub fn print_response_with_external(
        &self,
        external_addr: &str,
        connect_mode: ConnectMode,
    ) -> Result<()> {
        let response = self.response_with_external(external_addr, connect_mode);
        let json = response.to_json()?;
        println!("{}", json);
        // Force a flush to ensure the client sees the JSON immediately
        io::stdout().flush()?;
        Ok(())
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

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

/// Find an available port in the given range and return its address.
async fn find_available_port(ip: IpAddr, port_range: (u16, u16)) -> Result<SocketAddr> {
    for port in port_range.0..=port_range.1 {
        let addr = SocketAddr::new(ip, port);
        match UdpSocket::bind(addr).await {
            Ok(socket) => {
                let addr = socket.local_addr().map_err(|e| Error::Transport {
                    message: format!("failed to get local address: {}", e),
                })?;
                drop(socket); // Release for the acceptor to bind
                return Ok(addr);
            }
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

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_key_is_random() {
        let key1 = generate_session_key();
        let key2 = generate_session_key();

        // Verify length
        assert_eq!(key1.len(), SESSION_KEY_LEN);
        assert_eq!(key2.len(), SESSION_KEY_LEN);

        // Should not be all zeros (extremely unlikely with random)
        assert!(key1.iter().any(|&b| b != 0));
        assert!(key2.iter().any(|&b| b != 0));

        // Two generated keys should be different (extremely unlikely to be same)
        assert_ne!(key1, key2);
    }

    #[test]
    fn bootstrap_options_builder() {
        let opts = BootstrapOptions::new()
            .with_port_range(4000, 5000)
            .with_extra_args("--verbose")
            .with_env("FOO", "bar")
            .with_env("BAZ", "qux")
            .with_external_addr("example.com")
            .with_timeout(Duration::from_secs(60));

        assert_eq!(opts.port_range, Some((4000, 5000)));
        assert_eq!(opts.extra_args, Some("--verbose".to_string()));
        assert_eq!(opts.extra_env.len(), 2);
        assert_eq!(opts.extra_env[0], ("FOO".to_string(), "bar".to_string()));
        assert_eq!(opts.extra_env[1], ("BAZ".to_string(), "qux".to_string()));
        assert_eq!(opts.external_addr, Some("example.com".to_string()));
        assert_eq!(opts.timeout, Duration::from_secs(60));
    }

    #[test]
    fn bootstrap_options_default() {
        let opts = BootstrapOptions::default();
        assert!(opts.port_range.is_none());
        assert!(opts.extra_args.is_none());
        assert!(opts.extra_env.is_empty());
        assert!(opts.external_addr.is_none());
        assert_eq!(opts.timeout, Duration::default());
    }

    #[tokio::test]
    async fn bootstrap_endpoint_creates_successfully() {
        let opts = BootstrapOptions::new();
        let endpoint = BootstrapEndpoint::new("127.0.0.1".parse().unwrap(), &opts)
            .await
            .unwrap();

        // Verify session key is not all zeros
        assert!(endpoint.session_key.iter().any(|&b| b != 0));
        assert_eq!(endpoint.session_key.len(), SESSION_KEY_LEN);

        // Verify cert and key are not empty
        assert!(!endpoint.cert_pem.is_empty());
        assert!(!endpoint.key_pem.is_empty());

        // Verify cert hash is SHA256 (32 bytes)
        assert_eq!(endpoint.cert_hash.len(), 32);

        // Verify bind address is valid
        assert_eq!(endpoint.bind_addr.ip(), "127.0.0.1".parse::<IpAddr>().unwrap());
        assert!(endpoint.bind_addr.port() > 0);
    }

    #[tokio::test]
    async fn bootstrap_endpoint_with_port_range() {
        let opts = BootstrapOptions::new().with_port_range(50000, 50010);
        let endpoint = BootstrapEndpoint::new("127.0.0.1".parse().unwrap(), &opts)
            .await
            .unwrap();

        let port = endpoint.bind_addr.port();
        assert!(port >= 50000 && port <= 50010);
    }

    #[test]
    fn bootstrap_endpoint_response() {
        let endpoint = BootstrapEndpoint {
            session_key: [0xAB; 32],
            cert_pem: b"cert".to_vec(),
            key_pem: b"key".to_vec(),
            cert_hash: vec![0xCD; 32],
            bind_addr: "127.0.0.1:4242".parse().unwrap(),
        };

        let response = endpoint.response(ConnectMode::Respond);
        assert!(response.is_ok());

        let info = response.endpoint_info.unwrap();
        assert_eq!(info.address, "127.0.0.1");
        assert_eq!(info.port, 4242);
        assert_eq!(info.connect_mode, ConnectMode::Respond);
    }

    #[test]
    fn bootstrap_endpoint_response_with_external() {
        let endpoint = BootstrapEndpoint {
            session_key: [0xAB; 32],
            cert_pem: b"cert".to_vec(),
            key_pem: b"key".to_vec(),
            cert_hash: vec![0xCD; 32],
            bind_addr: "127.0.0.1:4242".parse().unwrap(),
        };

        let response = endpoint.response_with_external("example.com", ConnectMode::Initiate);
        assert!(response.is_ok());

        let info = response.endpoint_info.unwrap();
        assert_eq!(info.address, "example.com");
        assert_eq!(info.port, 4242);
        assert_eq!(info.connect_mode, ConnectMode::Initiate);
    }

    #[test]
    fn extract_cert_der_from_pem() {
        // Generate a real cert for testing
        let (cert_pem, _key_pem) = generate_self_signed_cert().unwrap();
        let der = extract_first_cert_der(&cert_pem).unwrap();

        // Should be non-empty
        assert!(!der.is_empty());

        // DER encoding typically starts with 0x30 (SEQUENCE tag)
        assert_eq!(der[0], 0x30);
    }
}
