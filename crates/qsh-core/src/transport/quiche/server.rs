//! QUIC server connection acceptor for the quiche backend.
//!
//! This module provides QuicheAcceptor for accepting incoming
//! QUIC connections on the server side.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tracing::{debug, info};

use crate::error::{Error, Result};

use super::common::enable_error_queue;
use super::config::server_config_with_ticket_key;
use super::connection::QuicheConnection;
use crate::transport::ListenerConfig;

// =============================================================================
// QuicheAcceptor - Server Connection Acceptance
// =============================================================================

/// A QUIC server acceptor using quiche.
///
/// This handles the low-level packet parsing and connection acceptance,
/// returning fully established `QuicheConnection` instances.
pub struct QuicheAcceptor {
    /// UDP socket for receiving packets.
    socket: Arc<UdpSocket>,
    /// Local address.
    local_addr: std::net::SocketAddr,
    /// quiche configuration.
    quiche_config: quiche::Config,
    /// Pending connections (connection ID -> (connection, peer address)).
    connections: HashMap<Vec<u8>, (quiche::Connection, Option<std::net::SocketAddr>)>,
    /// Receive buffer.
    recv_buf: [u8; 65535],
    /// Send buffer.
    send_buf: [u8; 65535],
}

impl QuicheAcceptor {
    /// Create a new QUIC acceptor bound to the specified address.
    pub async fn bind(addr: std::net::SocketAddr, config: ListenerConfig) -> Result<Self> {
        // Create quiche config with certificates
        let mut quiche_config = server_config_with_ticket_key(
            &config.cert_pem,
            &config.key_pem,
            config.ticket_key.as_deref(),
        )?;

        // Set idle timeout
        quiche_config.set_max_idle_timeout(config.idle_timeout.as_millis() as u64);

        // Bind UDP socket
        let socket = UdpSocket::bind(addr)
            .await
            .map_err(|e| Error::Transport {
                message: format!("failed to bind server: {}", e),
            })?;

        let local_addr = socket.local_addr().map_err(|e| Error::Transport {
            message: format!("failed to get local address: {}", e),
        })?;

        // Enable IP_RECVERR for fast error detection (Linux-specific)
        if let Err(e) = enable_error_queue(&socket) {
            debug!(error = %e, "Failed to enable IP_RECVERR (non-fatal)");
        }

        Ok(Self {
            socket: Arc::new(socket),
            local_addr,
            quiche_config,
            connections: HashMap::new(),
            recv_buf: [0u8; 65535],
            send_buf: [0u8; 65535],
        })
    }

    /// Create a new acceptor with an existing UDP socket.
    pub async fn with_socket(socket: Arc<UdpSocket>, config: ListenerConfig) -> Result<Self> {
        let mut quiche_config = server_config_with_ticket_key(
            &config.cert_pem,
            &config.key_pem,
            config.ticket_key.as_deref(),
        )?;

        quiche_config.set_max_idle_timeout(config.idle_timeout.as_millis() as u64);

        let local_addr = socket.local_addr().map_err(|e| Error::Transport {
            message: format!("failed to get local address: {}", e),
        })?;

        if let Err(e) = enable_error_queue(&socket) {
            debug!(error = %e, "Failed to enable IP_RECVERR (non-fatal)");
        }

        Ok(Self {
            socket,
            local_addr,
            quiche_config,
            connections: HashMap::new(),
            recv_buf: [0u8; 65535],
            send_buf: [0u8; 65535],
        })
    }

    /// Get the local address this acceptor is bound to.
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.local_addr
    }

    /// Get a clone of the underlying socket (for sharing with connection handlers).
    pub fn socket(&self) -> Arc<UdpSocket> {
        Arc::clone(&self.socket)
    }

    /// Set the idle timeout for new connections.
    pub fn set_idle_timeout(&mut self, timeout: Duration) {
        self.quiche_config.set_max_idle_timeout(timeout.as_millis() as u64);
    }

    /// Accept the next established QUIC connection.
    ///
    /// This loops internally until a connection completes its handshake,
    /// then returns it along with the peer's address.
    pub async fn accept(&mut self) -> Result<(QuicheConnection, std::net::SocketAddr)> {
        loop {
            // Wait for a packet with a short timeout to allow checking pending connections
            let recv_result = tokio::time::timeout(
                Duration::from_millis(50),
                self.socket.recv_from(&mut self.recv_buf),
            )
            .await;

            match recv_result {
                Ok(Ok((len, from))) => {
                    // Parse QUIC header to get connection ID
                    let hdr = match quiche::Header::from_slice(
                        &mut self.recv_buf[..len],
                        quiche::MAX_CONN_ID_LEN,
                    ) {
                        Ok(h) => h,
                        Err(e) => {
                            debug!(error = %e, "Failed to parse QUIC header");
                            continue;
                        }
                    };

                    let dcid = hdr.dcid.to_vec();

                    // Look up or create connection
                    let conn_key = if self.connections.contains_key(&dcid) {
                        dcid.clone()
                    } else if hdr.ty == quiche::Type::Initial {
                        // New connection - generate scid and store
                        let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
                        rand::RngCore::fill_bytes(&mut rand::rng(), &mut scid);
                        let scid_vec = scid.to_vec();
                        let scid = quiche::ConnectionId::from_vec(scid_vec.clone());

                        let conn = quiche::accept(
                            &scid,
                            None,
                            self.local_addr,
                            from,
                            &mut self.quiche_config,
                        )
                        .map_err(|e| Error::Transport {
                            message: format!("failed to accept connection: {}", e),
                        })?;

                        self.connections.insert(scid_vec.clone(), (conn, Some(from)));
                        scid_vec
                    } else {
                        // Unknown connection
                        continue;
                    };

                    // Get mutable reference to the connection
                    let Some((conn, _peer)) = self.connections.get_mut(&conn_key) else {
                        continue;
                    };

                    let recv_info = quiche::RecvInfo {
                        from,
                        to: self.local_addr,
                    };

                    if let Err(e) = conn.recv(&mut self.recv_buf[..len], recv_info) {
                        if e != quiche::Error::Done {
                            debug!(error = %e, "recv failed");
                        }
                    }

                    // Check if connection is established
                    if conn.is_established() {
                        // Take ownership of connection
                        if let Some((conn, peer_addr)) = self.connections.remove(&conn_key) {
                            let peer = peer_addr.unwrap_or(from);
                            info!(addr = %peer, "Connection established");

                            // Wrap in QuicheConnection
                            let quic_conn = QuicheConnection::new(
                                conn,
                                Arc::clone(&self.socket),
                                peer,
                                self.local_addr,
                                true, // is_server = true
                            );

                            return Ok((quic_conn, peer));
                        }
                    }
                }
                Ok(Err(e)) => {
                    // Check if this is an ICMP error (from IP_RECVERR)
                    if let Some(errno) = e.raw_os_error() {
                        #[cfg(target_os = "linux")]
                        if errno == libc::ECONNREFUSED
                            || errno == libc::ENETUNREACH
                            || errno == libc::EHOSTUNREACH
                        {
                            debug!(error = %e, "ICMP error received (fast disconnect detection)");
                            continue;
                        }
                    }
                    debug!(error = %e, "Socket recv error");
                }
                Err(_) => {
                    // Timeout - continue to send pending packets
                }
            }

            // Send pending packets for all pending connections
            let conn_ids: Vec<Vec<u8>> = self.connections.keys().cloned().collect();
            for conn_id in conn_ids {
                if let Some((conn, _peer)) = self.connections.get_mut(&conn_id) {
                    loop {
                        match conn.send(&mut self.send_buf) {
                            Ok((write, send_info)) => {
                                if let Err(e) = self.socket.send_to(&self.send_buf[..write], send_info.to).await {
                                    debug!(error = %e, "send failed");
                                }
                            }
                            Err(quiche::Error::Done) => break,
                            Err(e) => {
                                debug!(error = %e, "send failed");
                                break;
                            }
                        }
                    }

                    // Remove closed connections
                    if conn.is_closed() {
                        self.connections.remove(&conn_id);
                    }
                }
            }
        }
    }
}
