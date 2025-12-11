//! Library-agnostic QUIC transport configuration.
//!
//! This module provides `TransportConfigBuilder`, a builder pattern for configuring
//! QUIC transport settings that can be compiled to backend-specific configurations
//! (quiche, s2n-quic, etc.).

use std::time::Duration;

/// Default idle timeout for QUIC connections.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Default max stream data for bidirectional local streams.
pub const DEFAULT_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 1_000_000;

/// Default max stream data for bidirectional remote streams.
pub const DEFAULT_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 1_000_000;

/// Default max stream data for unidirectional streams.
pub const DEFAULT_MAX_STREAM_DATA_UNI: u64 = 1_000_000;

/// Default max connection data.
pub const DEFAULT_MAX_DATA: u64 = 10_000_000;

/// Default max bidirectional streams.
pub const DEFAULT_MAX_STREAMS_BIDI: u64 = 100;

/// Default max unidirectional streams.
pub const DEFAULT_MAX_STREAMS_UNI: u64 = 100;

/// Default max receive UDP payload size.
pub const DEFAULT_MAX_RECV_UDP_PAYLOAD_SIZE: u64 = 65535;

/// Default max send UDP payload size.
pub const DEFAULT_MAX_SEND_UDP_PAYLOAD_SIZE: u64 = 1350;

/// Role of the QUIC endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointRole {
    /// Client endpoint.
    Client,
    /// Server endpoint.
    Server,
}

/// TLS credentials for server endpoints.
#[derive(Debug, Clone)]
pub struct TlsCredentials {
    /// Certificate chain in PEM format.
    pub cert_pem: Vec<u8>,
    /// Private key in PEM format.
    pub key_pem: Vec<u8>,
    /// Optional session ticket encryption key for 0-RTT.
    /// Should be 48 bytes for AES-256-GCM.
    pub ticket_key: Option<Vec<u8>>,
}

impl TlsCredentials {
    /// Create new TLS credentials from certificate and key PEM data.
    pub fn new(cert_pem: Vec<u8>, key_pem: Vec<u8>) -> Self {
        Self {
            cert_pem,
            key_pem,
            ticket_key: None,
        }
    }

    /// Set a custom session ticket key for 0-RTT resumption.
    pub fn with_ticket_key(mut self, key: Vec<u8>) -> Self {
        self.ticket_key = Some(key);
        self
    }
}

/// Library-agnostic QUIC transport configuration builder.
///
/// This builder creates configurations that can be compiled to backend-specific
/// formats (quiche::Config, s2n_quic::provider::*, etc.).
///
/// # Example
///
/// ```ignore
/// use qsh_core::transport::config::{TransportConfigBuilder, EndpointRole};
///
/// // Client config
/// let client_config = TransportConfigBuilder::new(EndpointRole::Client)
///     .with_alpn(b"qsh/1")
///     .with_idle_timeout(Duration::from_secs(30))
///     .verify_peer(false)
///     .build()?;
///
/// // Server config
/// let server_config = TransportConfigBuilder::new(EndpointRole::Server)
///     .with_alpn(b"qsh/1")
///     .with_credentials(TlsCredentials::new(cert_pem, key_pem))
///     .build()?;
/// ```
#[derive(Debug, Clone)]
pub struct TransportConfigBuilder {
    /// Endpoint role (client or server).
    role: EndpointRole,
    /// ALPN protocols.
    alpn: Vec<Vec<u8>>,
    /// TLS credentials (required for server).
    credentials: Option<TlsCredentials>,
    /// Whether to verify peer certificates (client only).
    verify_peer: bool,
    /// Maximum idle timeout.
    idle_timeout: Duration,
    /// Enable 0-RTT early data.
    early_data: bool,
    /// Max receive UDP payload size.
    max_recv_udp_payload_size: u64,
    /// Max send UDP payload size.
    max_send_udp_payload_size: u64,
    /// Max connection data.
    max_data: u64,
    /// Max stream data for bidirectional local streams.
    max_stream_data_bidi_local: u64,
    /// Max stream data for bidirectional remote streams.
    max_stream_data_bidi_remote: u64,
    /// Max stream data for unidirectional streams.
    max_stream_data_uni: u64,
    /// Max bidirectional streams.
    max_streams_bidi: u64,
    /// Max unidirectional streams.
    max_streams_uni: u64,
}

impl TransportConfigBuilder {
    /// Create a new transport configuration builder.
    pub fn new(role: EndpointRole) -> Self {
        Self {
            role,
            alpn: vec![crate::constants::ALPN.to_vec()],
            credentials: None,
            verify_peer: role == EndpointRole::Client,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            early_data: true,
            max_recv_udp_payload_size: DEFAULT_MAX_RECV_UDP_PAYLOAD_SIZE,
            max_send_udp_payload_size: DEFAULT_MAX_SEND_UDP_PAYLOAD_SIZE,
            max_data: DEFAULT_MAX_DATA,
            max_stream_data_bidi_local: DEFAULT_MAX_STREAM_DATA_BIDI_LOCAL,
            max_stream_data_bidi_remote: DEFAULT_MAX_STREAM_DATA_BIDI_REMOTE,
            max_stream_data_uni: DEFAULT_MAX_STREAM_DATA_UNI,
            max_streams_bidi: DEFAULT_MAX_STREAMS_BIDI,
            max_streams_uni: DEFAULT_MAX_STREAMS_UNI,
        }
    }

    /// Create a client configuration builder with sensible defaults.
    pub fn client() -> Self {
        Self::new(EndpointRole::Client)
    }

    /// Create a server configuration builder with sensible defaults.
    pub fn server() -> Self {
        Self::new(EndpointRole::Server)
    }

    /// Set the ALPN protocols.
    pub fn with_alpn(mut self, alpn: &[u8]) -> Self {
        self.alpn = vec![alpn.to_vec()];
        self
    }

    /// Add an ALPN protocol.
    pub fn add_alpn(mut self, alpn: &[u8]) -> Self {
        self.alpn.push(alpn.to_vec());
        self
    }

    /// Set TLS credentials (required for server).
    pub fn with_credentials(mut self, credentials: TlsCredentials) -> Self {
        self.credentials = Some(credentials);
        self
    }

    /// Set whether to verify peer certificates (client only).
    pub fn verify_peer(mut self, verify: bool) -> Self {
        self.verify_peer = verify;
        self
    }

    /// Set the maximum idle timeout.
    pub fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Enable or disable 0-RTT early data.
    pub fn with_early_data(mut self, enabled: bool) -> Self {
        self.early_data = enabled;
        self
    }

    /// Set max receive UDP payload size.
    pub fn with_max_recv_udp_payload_size(mut self, size: u64) -> Self {
        self.max_recv_udp_payload_size = size;
        self
    }

    /// Set max send UDP payload size.
    pub fn with_max_send_udp_payload_size(mut self, size: u64) -> Self {
        self.max_send_udp_payload_size = size;
        self
    }

    /// Set max connection data.
    pub fn with_max_data(mut self, size: u64) -> Self {
        self.max_data = size;
        self
    }

    /// Set max stream data for bidirectional local streams.
    pub fn with_max_stream_data_bidi_local(mut self, size: u64) -> Self {
        self.max_stream_data_bidi_local = size;
        self
    }

    /// Set max stream data for bidirectional remote streams.
    pub fn with_max_stream_data_bidi_remote(mut self, size: u64) -> Self {
        self.max_stream_data_bidi_remote = size;
        self
    }

    /// Set max stream data for unidirectional streams.
    pub fn with_max_stream_data_uni(mut self, size: u64) -> Self {
        self.max_stream_data_uni = size;
        self
    }

    /// Set max bidirectional streams.
    pub fn with_max_streams_bidi(mut self, count: u64) -> Self {
        self.max_streams_bidi = count;
        self
    }

    /// Set max unidirectional streams.
    pub fn with_max_streams_uni(mut self, count: u64) -> Self {
        self.max_streams_uni = count;
        self
    }

    /// Get the endpoint role.
    pub fn role(&self) -> EndpointRole {
        self.role
    }

    /// Get the ALPN protocols.
    pub fn alpn(&self) -> &[Vec<u8>] {
        &self.alpn
    }

    /// Get the TLS credentials.
    pub fn credentials(&self) -> Option<&TlsCredentials> {
        self.credentials.as_ref()
    }

    /// Get whether to verify peer certificates.
    pub fn should_verify_peer(&self) -> bool {
        self.verify_peer
    }

    /// Get the idle timeout.
    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    /// Get whether early data is enabled.
    pub fn early_data_enabled(&self) -> bool {
        self.early_data
    }

    /// Get max receive UDP payload size.
    pub fn max_recv_udp_payload_size(&self) -> u64 {
        self.max_recv_udp_payload_size
    }

    /// Get max send UDP payload size.
    pub fn max_send_udp_payload_size(&self) -> u64 {
        self.max_send_udp_payload_size
    }

    /// Get max connection data.
    pub fn max_data(&self) -> u64 {
        self.max_data
    }

    /// Get max stream data for bidirectional local streams.
    pub fn max_stream_data_bidi_local(&self) -> u64 {
        self.max_stream_data_bidi_local
    }

    /// Get max stream data for bidirectional remote streams.
    pub fn max_stream_data_bidi_remote(&self) -> u64 {
        self.max_stream_data_bidi_remote
    }

    /// Get max stream data for unidirectional streams.
    pub fn max_stream_data_uni(&self) -> u64 {
        self.max_stream_data_uni
    }

    /// Get max bidirectional streams.
    pub fn max_streams_bidi(&self) -> u64 {
        self.max_streams_bidi
    }

    /// Get max unidirectional streams.
    pub fn max_streams_uni(&self) -> u64 {
        self.max_streams_uni
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_builder_defaults() {
        let builder = TransportConfigBuilder::client();
        assert_eq!(builder.role(), EndpointRole::Client);
        assert!(builder.should_verify_peer());
        assert!(builder.early_data_enabled());
        assert_eq!(builder.idle_timeout(), DEFAULT_IDLE_TIMEOUT);
    }

    #[test]
    fn server_builder_defaults() {
        let builder = TransportConfigBuilder::server();
        assert_eq!(builder.role(), EndpointRole::Server);
        assert!(!builder.should_verify_peer()); // Server verifies client certs via other means
        assert!(builder.early_data_enabled());
    }

    #[test]
    fn builder_with_credentials() {
        let creds = TlsCredentials::new(b"cert".to_vec(), b"key".to_vec());
        let builder = TransportConfigBuilder::server().with_credentials(creds);
        assert!(builder.credentials().is_some());
    }

    #[test]
    fn builder_with_custom_timeout() {
        let timeout = Duration::from_secs(60);
        let builder = TransportConfigBuilder::client().with_idle_timeout(timeout);
        assert_eq!(builder.idle_timeout(), timeout);
    }

    #[test]
    fn builder_disable_verify_peer() {
        let builder = TransportConfigBuilder::client().verify_peer(false);
        assert!(!builder.should_verify_peer());
    }

    #[test]
    fn tls_credentials_with_ticket_key() {
        let creds =
            TlsCredentials::new(b"cert".to_vec(), b"key".to_vec()).with_ticket_key(vec![0x42; 48]);
        assert!(creds.ticket_key.is_some());
        assert_eq!(creds.ticket_key.unwrap().len(), 48);
    }
}
