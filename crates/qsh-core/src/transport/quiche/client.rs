//! QUIC client connection establishment for the quiche backend.
//!
//! This module provides the connect_quic() function for establishing
//! client connections with support for 0-RTT session resumption.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tracing::{debug, info};

use crate::error::{Error, Result};

use super::common::{cert_hash, classify_io_error, enable_error_queue};
use super::config::client_config;
use super::connection::QuicheConnection;
use crate::transport::{ConnectConfig, ConnectResult};

// =============================================================================
// connect_quic - Client Connection Establishment
// =============================================================================

/// Establish a QUIC client connection using the provided configuration.
///
/// This performs the full QUIC/TLS handshake and returns a connected
/// `QuicheConnection`. If `config.session_data` is provided, attempts
/// 0-RTT session resumption for faster reconnection.
///
/// # Arguments
/// * `config` - Connection configuration including server address, timeouts, and optional session data
///
/// # Returns
/// * `Ok(ConnectResult)` - Contains the connection, resume status, and new session data
/// * `Err(Error)` - On connection failure (timeout, handshake failure, certificate mismatch)
pub async fn connect_quic(config: &ConnectConfig) -> Result<ConnectResult<QuicheConnection>> {
    // Bind UDP socket (use specified port or OS-assigned random port)
    let bind_addr: std::net::SocketAddr = if config.server_addr.is_ipv4() {
        format!("0.0.0.0:{}", config.local_port.unwrap_or(0))
            .parse()
            .unwrap()
    } else {
        format!("[::]:{}", config.local_port.unwrap_or(0))
            .parse()
            .unwrap()
    };

    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| classify_io_error(e))?;

    // Connect socket for ICMP error delivery
    socket
        .connect(config.server_addr)
        .await
        .map_err(|e| classify_io_error(e))?;

    // Enable IP_RECVERR (Linux) for immediate ICMP error delivery
    enable_error_queue(&socket)?;

    let local_addr = socket.local_addr().map_err(|e| classify_io_error(e))?;

    // Create quiche client config
    let mut quiche_config = client_config(config.cert_hash.is_none())?;

    // Set idle timeout
    quiche_config.set_max_idle_timeout(config.max_idle_timeout.as_millis() as u64);

    // Generate connection ID
    let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut scid);
    let scid = quiche::ConnectionId::from_ref(&scid);

    // Create quiche connection
    let mut conn = quiche::connect(
        Some("qsh-server"),
        &scid,
        local_addr,
        config.server_addr,
        &mut quiche_config,
    )
    .map_err(|e| Error::HandshakeFailed {
        message: format!("failed to create connection: {}", e),
    })?;

    // Apply cached session data for 0-RTT resumption (must be done immediately
    // after creating the connection, before any packets are sent/received)
    let has_session_data = config.session_data.is_some();
    if let Some(session_data) = &config.session_data {
        if let Err(e) = conn.set_session(session_data) {
            // Non-fatal: fall back to regular 1-RTT handshake
            debug!(error = %e, "Failed to set session data for 0-RTT, falling back to 1-RTT");
        } else {
            debug!("Set session data for 0-RTT resumption");
        }
    }

    let socket = Arc::new(socket);

    // Perform handshake
    let mut out = [0u8; 65535];
    let mut buf = [0u8; 65535];

    // Initial handshake packet
    let (write, send_info) = conn.send(&mut out).map_err(|e| Error::HandshakeFailed {
        message: format!("failed to generate initial packet: {}", e),
    })?;

    socket
        .send_to(&out[..write], send_info.to)
        .await
        .map_err(|e| classify_io_error(e))?;

    // Handshake loop
    let start = Instant::now();
    while !conn.is_established() {
        if start.elapsed() > config.connect_timeout {
            return Err(Error::Timeout);
        }

        // Receive response
        let recv_result =
            tokio::time::timeout(Duration::from_millis(100), socket.recv_from(&mut buf)).await;

        match recv_result {
            Ok(Ok((len, from))) => {
                let recv_info = quiche::RecvInfo {
                    from,
                    to: local_addr,
                };
                if let Err(e) = conn.recv(&mut buf[..len], recv_info) {
                    if e != quiche::Error::Done {
                        return Err(Error::HandshakeFailed {
                            message: format!("handshake recv failed: {}", e),
                        });
                    }
                }
            }
            Ok(Err(e)) => {
                return Err(classify_io_error(e));
            }
            Err(_) => {
                // Timeout, continue
            }
        }

        // Send pending packets
        loop {
            match conn.send(&mut out) {
                Ok((write, send_info)) => {
                    socket
                        .send_to(&out[..write], send_info.to)
                        .await
                        .map_err(|e| classify_io_error(e))?;
                }
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    return Err(Error::HandshakeFailed {
                        message: format!("handshake send failed: {}", e),
                    });
                }
            }
        }
    }

    // Verify certificate hash if provided
    if let Some(expected_hash) = &config.cert_hash {
        if let Some(peer_cert) = conn.peer_cert() {
            let actual_hash = cert_hash(peer_cert);
            if actual_hash.as_slice() != expected_hash.as_slice() {
                return Err(Error::CertificateError {
                    message: "certificate hash mismatch".to_string(),
                });
            }
        }
    }

    let rtt = conn
        .path_stats()
        .find(|p| p.active)
        .or_else(|| conn.path_stats().next())
        .map(|p| p.rtt);
    let resumed = conn.is_resumed();
    debug!(
        addr = %config.server_addr,
        rtt = ?rtt,
        resumed,
        had_session_data = has_session_data,
        "QUIC handshake completed"
    );

    if resumed {
        info!(addr = %config.server_addr, "0-RTT session resumed");
    }

    let quic_conn = QuicheConnection::new(
        conn,
        socket,
        config.server_addr,
        local_addr,
        false, // is_server = false for client
    );

    // Get session data for future 0-RTT resumption
    let session_data = quic_conn.session_data().await;

    Ok(ConnectResult {
        connection: quic_conn,
        resumed,
        session_data,
    })
}
