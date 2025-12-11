//! S2N server connection acceptance.
//!
//! This module provides the S2nAcceptor type for accepting incoming
//! QUIC connections using s2n-quic.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tracing::{debug, info};

use crate::error::{Error, Result};

use super::ListenerConfig;
use super::connection::S2nConnection;
use super::stats::{ConnectionStats, HandshakeState, SessionTicketState};

/// Derive session ticket key material from an optional seed.
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
// S2nAcceptor - Server Connection Acceptance
// =============================================================================

/// A QUIC server acceptor using s2n-quic.
///
/// This wraps the s2n-quic Server and provides a simpler accept interface
/// that returns `S2nConnection` instances.
pub struct S2nAcceptor {
    /// The s2n-quic server.
    server: s2n_quic::Server,
    /// Local address.
    local_addr: SocketAddr,
}

impl S2nAcceptor {
    /// Create a new QUIC acceptor bound to the specified address.
    pub async fn bind(addr: SocketAddr, config: ListenerConfig) -> Result<Self> {
        use s2n_quic::Server;
        use s2n_quic::provider::tls::s2n_tls;

        let cert_pem_str =
            std::str::from_utf8(&config.cert_pem).map_err(|e| Error::CertificateError {
                message: format!("invalid certificate PEM encoding: {}", e),
            })?;

        let key_pem_str =
            std::str::from_utf8(&config.key_pem).map_err(|e| Error::CertificateError {
                message: format!("invalid key PEM encoding: {}", e),
            })?;

        let (ticket_key_bytes, ticket_key_name) =
            derive_ticket_key_material(config.ticket_key.as_deref());

        // Configure limits including idle timeout
        let idle_timeout = config.idle_timeout;
        let limits = s2n_quic::provider::limits::Limits::new()
            .with_max_idle_timeout(idle_timeout)
            .map_err(|e| Error::Transport {
                message: format!("failed to configure idle timeout: {}", e),
            })?;

        // Build TLS config with a stable session ticket key for 0-RTT.
        let mut tls_builder = s2n_tls::Server::builder()
            .with_certificate(cert_pem_str, key_pem_str)
            .map_err(|e| Error::CertificateError {
                message: format!("failed to configure TLS certificate: {}", e),
            })?;

        tls_builder
            .config_mut()
            .add_session_ticket_key(&ticket_key_name, &ticket_key_bytes, SystemTime::now())
            .map_err(|e| Error::Transport {
                message: format!("failed to configure session ticket key: {}", e),
            })?;

        let tls = tls_builder.build().map_err(|e| Error::Transport {
            message: format!("failed to build TLS config: {}", e),
        })?;

        let server = Server::builder()
            .with_tls(tls)
            .map_err(|e| Error::CertificateError {
                message: format!("failed to configure TLS: {}", e),
            })?
            .with_limits(limits)
            .map_err(|e| Error::Transport {
                message: format!("failed to configure limits: {}", e),
            })?
            .with_io(addr)
            .map_err(|e| Error::Transport {
                message: format!("failed to configure I/O: {}", e),
            })?
            .start()
            .map_err(|e| Error::Transport {
                message: format!("failed to start server: {}", e),
            })?;

        let local_addr = server.local_addr().map_err(|e| Error::Transport {
            message: format!("failed to get local address: {}", e),
        })?;

        Ok(Self { server, local_addr })
    }

    /// Get the local address this acceptor is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Set the idle timeout for new connections.
    ///
    /// Note: s2n-quic configures idle timeout at server creation time.
    /// This method is a no-op for API compatibility with QuicheAcceptor.
    pub fn set_idle_timeout(&mut self, _timeout: Duration) {
        // s2n-quic doesn't support changing timeout after server creation
        // This would require rebuilding the server
        debug!("set_idle_timeout called but s2n-quic doesn't support dynamic timeout changes");
    }

    /// Accept the next established QUIC connection.
    ///
    /// Returns the connection and peer address when a client connects.
    pub async fn accept(&mut self) -> Result<(S2nConnection, SocketAddr)> {
        // Accept the next connection
        let connection = self.server.accept().await.ok_or_else(|| Error::Transport {
            message: "server closed".to_string(),
        })?;

        let remote_addr = connection.remote_addr().map_err(|e| Error::Transport {
            message: format!("failed to get remote address: {}", e),
        })?;

        info!(addr = %remote_addr, "Connection established");

        // Create stats for this connection
        // Note: For server-side connections, we don't have access to the event subscriber
        // system since the Server is already running. Stats will be updated manually
        // or remain at default values. For full stats on server side, we'd need to
        // rebuild the Server with an event subscriber, but that's complex for per-connection stats.
        let stats = Arc::new(ConnectionStats::default());
        let handshake = Arc::new(HandshakeState::default());
        handshake.mark_confirmed();
        let session_state = SessionTicketState::new(None);

        // Wrap in S2nConnection
        let s2n_conn = S2nConnection::from_server_connection(
            connection,
            self.local_addr,
            stats,
            handshake,
            session_state,
        )
        .await?;

        Ok((s2n_conn, remote_addr))
    }
}
