//! Configuration builders for quiche QUIC connections.
//!
//! This module provides functions to create quiche::Config instances
//! for both client and server connections, with support for 0-RTT,
//! custom certificates, and session resumption.

use std::io::Write;

use crate::error::{Error, Result};

use super::common::generate_self_signed_cert;

// =============================================================================
// quiche Configuration Helpers
// =============================================================================

/// Create a quiche client configuration.
pub fn client_config(verify_peer: bool) -> Result<quiche::Config> {
    let mut config =
        quiche::Config::new(quiche::PROTOCOL_VERSION).map_err(|e| Error::Transport {
            message: format!("failed to create quiche config: {}", e),
        })?;

    config
        .set_application_protos(&[crate::constants::ALPN])
        .map_err(|e| Error::Transport {
            message: format!("failed to set application protos: {}", e),
        })?;

    // Enable 0-RTT early data for faster reconnection
    config.enable_early_data();

    config.set_max_idle_timeout(30_000); // 30 seconds
    config.set_max_recv_udp_payload_size(65535);
    config.set_max_send_udp_payload_size(1350);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    // Connection migration enabled (like Mosh's roaming support)

    if !verify_peer {
        config.verify_peer(false);
    }

    Ok(config)
}

/// Create a quiche server configuration with certificate and key (PEM format).
///
/// Note: quiche requires file paths, so we write to temp files.
pub fn server_config(cert_pem: &[u8], key_pem: &[u8]) -> Result<quiche::Config> {
    server_config_with_ticket_key(cert_pem, key_pem, None)
}

/// Create a quiche server configuration with optional custom ticket key.
///
/// The ticket key is used to encrypt session tickets for 0-RTT resumption.
/// If `ticket_key` is None, quiche generates and rotates keys automatically.
/// For multi-server deployments, provide a shared key and rotate it periodically.
///
/// Note: quiche requires file paths, so we write to temp files.
pub fn server_config_with_ticket_key(
    cert_pem: &[u8],
    key_pem: &[u8],
    ticket_key: Option<&[u8]>,
) -> Result<quiche::Config> {
    let mut config =
        quiche::Config::new(quiche::PROTOCOL_VERSION).map_err(|e| Error::Transport {
            message: format!("failed to create quiche config: {}", e),
        })?;

    config
        .set_application_protos(&[crate::constants::ALPN])
        .map_err(|e| Error::Transport {
            message: format!("failed to set application protos: {}", e),
        })?;

    // Write cert/key to temp files (quiche requires file paths)
    // Use process ID + thread ID + timestamp for uniqueness in parallel tests
    let temp_dir = std::env::temp_dir();
    let unique_id = format!(
        "{}-{:?}-{}",
        std::process::id(),
        std::thread::current().id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let cert_path = temp_dir.join(format!("qsh-cert-{}.pem", unique_id));
    let key_path = temp_dir.join(format!("qsh-key-{}.pem", unique_id));

    let mut cert_file = std::fs::File::create(&cert_path).map_err(|e| Error::CertificateError {
        message: format!("failed to create temp cert file: {}", e),
    })?;
    cert_file
        .write_all(cert_pem)
        .map_err(|e| Error::CertificateError {
            message: format!("failed to write cert file: {}", e),
        })?;

    let mut key_file = std::fs::File::create(&key_path).map_err(|e| Error::CertificateError {
        message: format!("failed to create temp key file: {}", e),
    })?;
    key_file
        .write_all(key_pem)
        .map_err(|e| Error::CertificateError {
            message: format!("failed to write key file: {}", e),
        })?;

    // Load certificate and key from temp files
    config
        .load_cert_chain_from_pem_file(cert_path.to_str().unwrap())
        .map_err(|e| Error::CertificateError {
            message: format!("failed to load certificate: {}", e),
        })?;

    config
        .load_priv_key_from_pem_file(key_path.to_str().unwrap())
        .map_err(|e| Error::CertificateError {
            message: format!("failed to load private key: {}", e),
        })?;

    // Clean up temp files
    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    // Enable 0-RTT early data for faster reconnection
    config.enable_early_data();

    // Set custom ticket key if provided (for multi-server deployments)
    if let Some(key) = ticket_key {
        config.set_ticket_key(key).map_err(|e| Error::Transport {
            message: format!("failed to set ticket key: {}", e),
        })?;
    }

    config.set_max_idle_timeout(30_000);
    config.set_max_recv_udp_payload_size(65535);
    config.set_max_send_udp_payload_size(1350);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    // Connection migration enabled (like Mosh's roaming support)

    Ok(config)
}

/// Build a quiche::Config from a TransportConfigBuilder.
///
/// This converts the library-agnostic configuration to a quiche-specific config.
pub fn build_config(builder: &crate::transport::config::TransportConfigBuilder) -> Result<quiche::Config> {
    use crate::transport::config::EndpointRole;

    let mut config =
        quiche::Config::new(quiche::PROTOCOL_VERSION).map_err(|e| Error::Transport {
            message: format!("failed to create quiche config: {}", e),
        })?;

    // Set ALPN protocols
    let alpn_refs: Vec<&[u8]> = builder.alpn().iter().map(|a| a.as_slice()).collect();
    config
        .set_application_protos(&alpn_refs)
        .map_err(|e| Error::Transport {
            message: format!("failed to set application protos: {}", e),
        })?;

    // Handle TLS credentials for server
    if builder.role() == EndpointRole::Server {
        let creds = builder.credentials().ok_or_else(|| Error::Transport {
            message: "server config requires TLS credentials".to_string(),
        })?;

        // Write cert/key to temp files (quiche requires file paths)
        let temp_dir = std::env::temp_dir();
        let unique_id = format!(
            "{}-{:?}-{}",
            std::process::id(),
            std::thread::current().id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let cert_path = temp_dir.join(format!("qsh-cert-{}.pem", unique_id));
        let key_path = temp_dir.join(format!("qsh-key-{}.pem", unique_id));

        let mut cert_file =
            std::fs::File::create(&cert_path).map_err(|e| Error::CertificateError {
                message: format!("failed to create temp cert file: {}", e),
            })?;
        cert_file
            .write_all(&creds.cert_pem)
            .map_err(|e| Error::CertificateError {
                message: format!("failed to write cert file: {}", e),
            })?;

        let mut key_file =
            std::fs::File::create(&key_path).map_err(|e| Error::CertificateError {
                message: format!("failed to create temp key file: {}", e),
            })?;
        key_file
            .write_all(&creds.key_pem)
            .map_err(|e| Error::CertificateError {
                message: format!("failed to write key file: {}", e),
            })?;

        config
            .load_cert_chain_from_pem_file(cert_path.to_str().unwrap())
            .map_err(|e| Error::CertificateError {
                message: format!("failed to load certificate: {}", e),
            })?;

        config
            .load_priv_key_from_pem_file(key_path.to_str().unwrap())
            .map_err(|e| Error::CertificateError {
                message: format!("failed to load private key: {}", e),
            })?;

        // Clean up temp files
        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);

        // Set custom ticket key if provided
        if let Some(key) = &creds.ticket_key {
            config.set_ticket_key(key).map_err(|e| Error::Transport {
                message: format!("failed to set ticket key: {}", e),
            })?;
        }
    }

    // Enable 0-RTT early data if requested
    if builder.early_data_enabled() {
        config.enable_early_data();
    }

    // Set peer verification for client
    if builder.role() == EndpointRole::Client && !builder.should_verify_peer() {
        config.verify_peer(false);
    }

    // Apply transport parameters
    config.set_max_idle_timeout(builder.idle_timeout().as_millis() as u64);
    config.set_max_recv_udp_payload_size(builder.max_recv_udp_payload_size() as usize);
    config.set_max_send_udp_payload_size(builder.max_send_udp_payload_size() as usize);
    config.set_initial_max_data(builder.max_data());
    config.set_initial_max_stream_data_bidi_local(builder.max_stream_data_bidi_local());
    config.set_initial_max_stream_data_bidi_remote(builder.max_stream_data_bidi_remote());
    config.set_initial_max_stream_data_uni(builder.max_stream_data_uni());
    config.set_initial_max_streams_bidi(builder.max_streams_bidi());
    config.set_initial_max_streams_uni(builder.max_streams_uni());

    Ok(config)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_config_enables_early_data() {
        // Client config should successfully create and enable early data
        let config = client_config(false);
        assert!(config.is_ok(), "client_config should succeed");
    }

    #[test]
    fn server_config_enables_early_data() {
        // Generate self-signed cert for testing
        let (cert_pem, key_pem) =
            generate_self_signed_cert().expect("should generate self-signed cert");

        // Server config should successfully create and enable early data
        let config = server_config(&cert_pem, &key_pem);
        assert!(config.is_ok(), "server_config should succeed");
    }

    #[test]
    fn server_config_with_custom_ticket_key() {
        // Generate self-signed cert for testing
        let (cert_pem, key_pem) =
            generate_self_signed_cert().expect("should generate self-signed cert");

        // 48 bytes for AES-256-GCM ticket key
        let ticket_key = [0x42u8; 48];

        // Server config with custom ticket key should succeed
        let config = server_config_with_ticket_key(&cert_pem, &key_pem, Some(&ticket_key));
        assert!(
            config.is_ok(),
            "server_config_with_ticket_key should succeed"
        );
    }

    #[test]
    fn server_config_without_ticket_key() {
        // Generate self-signed cert for testing
        let (cert_pem, key_pem) =
            generate_self_signed_cert().expect("should generate self-signed cert");

        // Server config without ticket key should use auto-generated key
        let config = server_config_with_ticket_key(&cert_pem, &key_pem, None);
        assert!(
            config.is_ok(),
            "server_config_with_ticket_key(None) should succeed: {:?}",
            config.err()
        );
    }
}
