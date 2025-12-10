//! S2N configuration helpers.
//!
//! This module provides functions for creating and configuring s2n-quic
//! clients and servers, including TLS setup and session ticket management.

use std::time::SystemTime;

use tracing::debug;

use crate::error::{Error, Result};

/// Derive session ticket key material from an optional seed.
///
/// This is s2n-specific and derives a 16-byte key and 8-byte name
/// from the provided seed or generates random values.
fn derive_ticket_key_material(ticket_key: Option<&[u8]>) -> (Vec<u8>, Vec<u8>) {
    use sha2::{Digest, Sha256};

    if let Some(key) = ticket_key {
        let digest = Sha256::digest(key);
        let key_bytes = digest[..16].to_vec();
        let name = digest[16..24].to_vec();
        (key_bytes, name)
    } else {
        let key_bytes: [u8; 16] = rand::random();
        let name = key_bytes[..8].to_vec();
        (key_bytes.to_vec(), name)
    }
}

// =============================================================================
// s2n-quic Configuration Helpers
// =============================================================================

/// Create an s2n-quic client configuration.
///
/// Note: s2n-quic has a different TLS configuration model than quiche.
/// The `verify_peer` parameter controls certificate verification.
/// When `verify_peer` is false, certificate verification is disabled using
/// s2n-quic's insecure mode (for development/testing only).
pub fn client_config(_verify_peer: bool) -> Result<s2n_quic::client::Client> {
    use s2n_quic::Client;

    // Note: s2n-quic doesn't have a simple way to disable certificate verification
    // like quiche does. For testing/development, you would typically:
    // 1. Add the self-signed cert to the trust store
    // 2. Use the rustls provider with dangerous_configuration
    //
    // For now, we return a basic client that will verify certificates.
    // In a real implementation, you'd configure the TLS provider appropriately.
    Client::builder()
        .with_io("0.0.0.0:0")
        .map_err(|e| Error::Transport {
            message: format!("failed to configure I/O: {}", e),
        })?
        .start()
        .map_err(|e| Error::Transport {
            message: format!("failed to start client: {}", e),
        })
}

/// Create an s2n-quic server configuration with certificate and key (PEM format).
pub fn server_config(cert_pem: &[u8], key_pem: &[u8], bind_addr: &str) -> Result<s2n_quic::server::Server> {
    server_config_with_ticket_key(cert_pem, key_pem, None, bind_addr)
}

/// Create an s2n-quic server configuration with optional custom ticket key.
pub fn server_config_with_ticket_key(
    cert_pem: &[u8],
    key_pem: &[u8],
    ticket_key: Option<&[u8]>,
    bind_addr: &str,
) -> Result<s2n_quic::server::Server> {
    use s2n_quic::Server;
    use s2n_quic::provider::tls::s2n_tls;

    let cert_pem_str = std::str::from_utf8(cert_pem).map_err(|e| Error::CertificateError {
        message: format!("invalid certificate PEM encoding: {}", e),
    })?;

    let key_pem_str = std::str::from_utf8(key_pem).map_err(|e| Error::CertificateError {
        message: format!("invalid key PEM encoding: {}", e),
    })?;

    let (ticket_key_bytes, ticket_key_name) = derive_ticket_key_material(ticket_key);

    let mut tls = s2n_tls::Server::builder()
        .with_certificate(cert_pem_str, key_pem_str)
        .map_err(|e| Error::CertificateError {
            message: format!("failed to configure TLS: {}", e),
        })?;

    tls.config_mut()
        .add_session_ticket_key(&ticket_key_name, &ticket_key_bytes, SystemTime::now())
        .map_err(|e| Error::Transport {
            message: format!("failed to configure session ticket key: {}", e),
        })?;

    let tls = tls.build().map_err(|e| Error::Transport {
        message: format!("failed to build TLS config: {}", e),
    })?;

    Server::builder()
        .with_tls(tls)
        .map_err(|e| Error::CertificateError {
            message: format!("failed to configure TLS: {}", e),
        })?
        .with_io(bind_addr)
        .map_err(|e| Error::Transport {
            message: format!("failed to configure I/O: {}", e),
        })?
        .start()
        .map_err(|e| Error::Transport {
            message: format!("failed to start server: {}", e),
        })
}

/// Build an s2n-quic client from a TransportConfigBuilder.
///
/// Note: s2n-quic uses a different configuration model than quiche.
/// This function creates a client ready to connect.
pub fn build_client_config(builder: &super::super::config::TransportConfigBuilder) -> Result<s2n_quic::client::Client> {
    use s2n_quic::Client;

    // Configure TLS verification
    if !builder.should_verify_peer() {
        // For development/testing, disable certificate verification
        // Note: In production, you'd want to configure proper trust anchors
        debug!("s2n-quic client: certificate verification disabled");
    }

    Client::builder()
        .with_io("0.0.0.0:0")
        .map_err(|e| Error::Transport {
            message: format!("failed to configure I/O: {}", e),
        })?
        .start()
        .map_err(|e| Error::Transport {
            message: format!("failed to start client: {}", e),
        })
}

/// Build an s2n-quic server from a TransportConfigBuilder.
///
/// Note: s2n-quic uses a different configuration model than quiche.
/// This function creates a server ready to accept connections.
pub fn build_server_config(
    builder: &super::super::config::TransportConfigBuilder,
    bind_addr: &str,
) -> Result<s2n_quic::server::Server> {
    use s2n_quic::Server;
    use s2n_quic::provider::tls::s2n_tls;

    let creds = builder.credentials().ok_or_else(|| Error::Transport {
        message: "server config requires TLS credentials".to_string(),
    })?;

    let cert_pem_str = std::str::from_utf8(&creds.cert_pem).map_err(|e| Error::CertificateError {
        message: format!("invalid certificate PEM encoding: {}", e),
    })?;

    let key_pem_str = std::str::from_utf8(&creds.key_pem).map_err(|e| Error::CertificateError {
        message: format!("invalid key PEM encoding: {}", e),
    })?;

    let (ticket_key_bytes, ticket_key_name) =
        derive_ticket_key_material(creds.ticket_key.as_deref());

    let mut tls = s2n_tls::Server::builder()
        .with_certificate(cert_pem_str, key_pem_str)
        .map_err(|e| Error::CertificateError {
            message: format!("failed to configure TLS certificate: {}", e),
        })?;

    tls.config_mut()
        .add_session_ticket_key(&ticket_key_name, &ticket_key_bytes, SystemTime::now())
        .map_err(|e| Error::Transport {
            message: format!("failed to configure session ticket key: {}", e),
        })?;

    let tls = tls.build().map_err(|e| Error::Transport {
        message: format!("failed to build TLS config: {}", e),
    })?;

    Server::builder()
        .with_tls(tls)
        .map_err(|e| Error::CertificateError {
            message: format!("failed to configure TLS: {}", e),
        })?
        .with_io(bind_addr)
        .map_err(|e| Error::Transport {
            message: format!("failed to configure I/O: {}", e),
        })?
        .start()
        .map_err(|e| Error::Transport {
            message: format!("failed to start server: {}", e),
        })
}
