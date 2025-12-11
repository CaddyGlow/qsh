//! SOCKS5 proxy (-D) implementation.
//!
//! Listens on a local address and handles SOCKS5 protocol, forwarding
//! connections through the qsh connection to the resolved target.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use qsh_core::error::{Error, Result};
use qsh_core::protocol::{ChannelCloseReason, DynamicForwardParams};

use crate::connection::ChannelConnection;

/// Buffer size for forwarding.
const FORWARD_BUFFER_SIZE: usize = 32 * 1024;

// SOCKS5 constants
const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_NO_AUTH: u8 = 0x00;
const SOCKS5_CMD_CONNECT: u8 = 0x01;
const SOCKS5_ATYP_IPV4: u8 = 0x01;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
const SOCKS5_ATYP_IPV6: u8 = 0x04;
const SOCKS5_REP_SUCCESS: u8 = 0x00;
const SOCKS5_REP_GENERAL_FAILURE: u8 = 0x01;
const SOCKS5_REP_CONN_NOT_ALLOWED: u8 = 0x02;
const SOCKS5_REP_HOST_UNREACHABLE: u8 = 0x04;
const SOCKS5_REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const SOCKS5_REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

/// SOCKS5 proxy for dynamic forwarding (-D).
///
/// Listens on a local address, handles SOCKS5 handshake, and opens
/// DynamicForward channels for each connection.
pub struct Socks5Proxy {
    /// Local bind address.
    bind_addr: SocketAddr,
    /// Connection to qsh server.
    connection: Arc<ChannelConnection>,
}

impl Socks5Proxy {
    /// Create a new SOCKS5 proxy.
    pub fn new(bind_addr: SocketAddr, connection: Arc<ChannelConnection>) -> Self {
        Self {
            bind_addr,
            connection,
        }
    }

    /// Start the proxy, accepting connections until shutdown.
    pub async fn start(self) -> Result<ProxyHandle> {
        let listener = TcpListener::bind(self.bind_addr)
            .await
            .map_err(|e| Error::Forward {
                message: format!("failed to bind to {}: {}", self.bind_addr, e),
            })?;

        let actual_addr = listener.local_addr().map_err(|e| Error::Forward {
            message: format!("failed to get local address: {}", e),
        })?;

        info!(bind = %actual_addr, "SOCKS5 proxy listening");

        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        let connection = self.connection;

        // Spawn accept loop
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        debug!(bind = %actual_addr, "SOCKS5 proxy shutdown");
                        break;
                    }
                    accept = listener.accept() => {
                        match accept {
                            Ok((stream, peer_addr)) => {
                                debug!(peer = %peer_addr, "Accepted SOCKS5 connection");
                                let conn = Arc::clone(&connection);
                                tokio::spawn(async move {
                                    if let Err(e) = Self::handle_connection(stream, peer_addr, conn).await {
                                        debug!(peer = %peer_addr, error = %e, "SOCKS5 connection failed");
                                    }
                                });
                            }
                            Err(e) => {
                                warn!(error = %e, "Failed to accept connection");
                            }
                        }
                    }
                }
            }
        });

        Ok(ProxyHandle {
            shutdown_tx,
            task: Some(task),
            local_addr: actual_addr,
        })
    }

    /// Handle a single SOCKS5 connection.
    async fn handle_connection(
        mut stream: TcpStream,
        peer_addr: SocketAddr,
        connection: Arc<ChannelConnection>,
    ) -> Result<()> {
        // SOCKS5 greeting
        let (target_host, target_port) = Self::socks5_handshake(&mut stream).await?;

        debug!(
            peer = %peer_addr,
            target = %format!("{}:{}", target_host, target_port),
            "SOCKS5 target resolved"
        );

        // Open a DynamicForward channel
        let params = DynamicForwardParams {
            target_host: target_host.clone(),
            target_port,
        };

        let channel = match connection.open_dynamic(params).await {
            Ok(ch) => {
                // Send success reply
                Self::send_socks5_reply(&mut stream, SOCKS5_REP_SUCCESS).await?;
                ch
            }
            Err(e) => {
                warn!(target = %format!("{}:{}", target_host, target_port), error = %e, "Failed to open channel");
                // Map error to appropriate SOCKS5 reply code
                let reply = Self::error_to_socks5_reply(&e);
                Self::send_socks5_reply(&mut stream, reply).await?;
                return Err(e);
            }
        };

        debug!(
            channel_id = %channel.channel_id(),
            target = %format!("{}:{}", target_host, target_port),
            "Opened SOCKS5 forward channel"
        );

        // Split the local stream
        let (mut local_read, mut local_write) = stream.into_split();

        // Relay: local -> QUIC
        let channel_clone = channel.clone();
        let local_to_quic = tokio::spawn(async move {
            let mut buf = vec![0u8; FORWARD_BUFFER_SIZE];
            loop {
                match local_read.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Err(e) = channel_clone.send(&buf[..n]).await {
                            debug!(error = %e, "Failed to send to channel");
                            break;
                        }
                    }
                    Err(e) => {
                        debug!(error = %e, "Local read error");
                        break;
                    }
                }
            }
        });

        // Relay: QUIC -> local
        let channel_clone = channel.clone();
        let quic_to_local = tokio::spawn(async move {
            let mut buf = vec![0u8; FORWARD_BUFFER_SIZE];
            loop {
                match channel_clone.recv(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Err(e) = local_write.write_all(&buf[..n]).await {
                            debug!(error = %e, "Local write error");
                            break;
                        }
                    }
                    Err(e) => {
                        debug!(error = %e, "QUIC recv error");
                        break;
                    }
                }
            }
            let _ = local_write.shutdown().await;
        });

        // Wait for either direction to complete
        tokio::select! {
            _ = local_to_quic => {}
            _ = quic_to_local => {}
        }

        // Close the channel properly to release server resources
        let channel_id = channel.channel_id();
        if let Err(e) = connection
            .close_channel(channel_id, ChannelCloseReason::Normal)
            .await
        {
            warn!(channel_id = %channel_id, error = %e, "Failed to close channel");
        }
        debug!(channel_id = %channel_id, "SOCKS5 connection completed");

        Ok(())
    }

    /// Perform SOCKS5 handshake, returning (target_host, target_port).
    async fn socks5_handshake(stream: &mut TcpStream) -> Result<(String, u16)> {
        // Read version and auth method count
        let mut header = [0u8; 2];
        stream
            .read_exact(&mut header)
            .await
            .map_err(|e| Error::Protocol {
                message: format!("failed to read SOCKS5 header: {}", e),
            })?;

        if header[0] != SOCKS5_VERSION {
            return Err(Error::Protocol {
                message: format!("unsupported SOCKS version: {}", header[0]),
            });
        }

        let nmethods = header[1] as usize;
        let mut methods = vec![0u8; nmethods];
        stream
            .read_exact(&mut methods)
            .await
            .map_err(|e| Error::Protocol {
                message: format!("failed to read auth methods: {}", e),
            })?;

        // We only support no-auth
        if !methods.contains(&SOCKS5_NO_AUTH) {
            // Send "no acceptable methods"
            stream.write_all(&[SOCKS5_VERSION, 0xFF]).await.ok();
            return Err(Error::Protocol {
                message: "no acceptable auth method".to_string(),
            });
        }

        // Send auth method selection (no auth)
        stream
            .write_all(&[SOCKS5_VERSION, SOCKS5_NO_AUTH])
            .await
            .map_err(|e| Error::Protocol {
                message: format!("failed to send auth response: {}", e),
            })?;

        // Read connection request
        let mut request = [0u8; 4];
        stream
            .read_exact(&mut request)
            .await
            .map_err(|e| Error::Protocol {
                message: format!("failed to read request: {}", e),
            })?;

        if request[0] != SOCKS5_VERSION {
            return Err(Error::Protocol {
                message: format!("invalid request version: {}", request[0]),
            });
        }

        if request[1] != SOCKS5_CMD_CONNECT {
            Self::send_socks5_reply(stream, SOCKS5_REP_CMD_NOT_SUPPORTED).await?;
            return Err(Error::Protocol {
                message: format!("unsupported command: {}", request[1]),
            });
        }

        // Parse address type
        let atyp = request[3];
        let (target_host, target_port) = match atyp {
            SOCKS5_ATYP_IPV4 => {
                let mut addr = [0u8; 4];
                stream
                    .read_exact(&mut addr)
                    .await
                    .map_err(|e| Error::Protocol {
                        message: format!("failed to read IPv4 address: {}", e),
                    })?;
                let ip = Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);

                let mut port_bytes = [0u8; 2];
                stream
                    .read_exact(&mut port_bytes)
                    .await
                    .map_err(|e| Error::Protocol {
                        message: format!("failed to read port: {}", e),
                    })?;
                let port = u16::from_be_bytes(port_bytes);

                (ip.to_string(), port)
            }
            SOCKS5_ATYP_DOMAIN => {
                let mut len = [0u8; 1];
                stream
                    .read_exact(&mut len)
                    .await
                    .map_err(|e| Error::Protocol {
                        message: format!("failed to read domain length: {}", e),
                    })?;

                let mut domain = vec![0u8; len[0] as usize];
                stream
                    .read_exact(&mut domain)
                    .await
                    .map_err(|e| Error::Protocol {
                        message: format!("failed to read domain: {}", e),
                    })?;

                let host = String::from_utf8(domain).map_err(|e| Error::Protocol {
                    message: format!("invalid domain encoding: {}", e),
                })?;

                let mut port_bytes = [0u8; 2];
                stream
                    .read_exact(&mut port_bytes)
                    .await
                    .map_err(|e| Error::Protocol {
                        message: format!("failed to read port: {}", e),
                    })?;
                let port = u16::from_be_bytes(port_bytes);

                (host, port)
            }
            SOCKS5_ATYP_IPV6 => {
                let mut addr = [0u8; 16];
                stream
                    .read_exact(&mut addr)
                    .await
                    .map_err(|e| Error::Protocol {
                        message: format!("failed to read IPv6 address: {}", e),
                    })?;
                let ip = Ipv6Addr::from(addr);

                let mut port_bytes = [0u8; 2];
                stream
                    .read_exact(&mut port_bytes)
                    .await
                    .map_err(|e| Error::Protocol {
                        message: format!("failed to read port: {}", e),
                    })?;
                let port = u16::from_be_bytes(port_bytes);

                (ip.to_string(), port)
            }
            _ => {
                Self::send_socks5_reply(stream, SOCKS5_REP_ATYP_NOT_SUPPORTED).await?;
                return Err(Error::Protocol {
                    message: format!("unsupported address type: {}", atyp),
                });
            }
        };

        Ok((target_host, target_port))
    }

    /// Send a SOCKS5 reply.
    async fn send_socks5_reply(stream: &mut TcpStream, reply: u8) -> Result<()> {
        // Reply format: VER | REP | RSV | ATYP | BND.ADDR | BND.PORT
        // We use a dummy bind address of 0.0.0.0:0
        let response = [
            SOCKS5_VERSION,
            reply,
            0x00, // reserved
            SOCKS5_ATYP_IPV4,
            0,
            0,
            0,
            0, // 0.0.0.0
            0,
            0, // port 0
        ];
        stream
            .write_all(&response)
            .await
            .map_err(|e| Error::Protocol {
                message: format!("failed to send reply: {}", e),
            })?;
        Ok(())
    }

    /// Map a qsh error to SOCKS5 reply code.
    fn error_to_socks5_reply(err: &Error) -> u8 {
        match err {
            // Connection/network errors -> host unreachable
            Error::Forward { .. } => SOCKS5_REP_HOST_UNREACHABLE,
            Error::Transport { .. } => SOCKS5_REP_HOST_UNREACHABLE,
            Error::ConnectionClosed => SOCKS5_REP_HOST_UNREACHABLE,

            // Permission/auth errors -> connection not allowed
            Error::AuthenticationFailed => SOCKS5_REP_CONN_NOT_ALLOWED,
            Error::Channel { message } if message.contains("denied") => SOCKS5_REP_CONN_NOT_ALLOWED,

            // Everything else -> general failure
            _ => SOCKS5_REP_GENERAL_FAILURE,
        }
    }
}

/// Handle for a running SOCKS5 proxy.
pub struct ProxyHandle {
    shutdown_tx: mpsc::Sender<()>,
    task: Option<tokio::task::JoinHandle<()>>,
    local_addr: SocketAddr,
}

impl ProxyHandle {
    /// Get the local address the proxy is listening on.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Stop the proxy.
    pub async fn stop(mut self) {
        let _ = self.shutdown_tx.send(()).await;
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_structure() {
        fn _assert_send<T: Send>() {}
        _assert_send::<ProxyHandle>();
    }
}
