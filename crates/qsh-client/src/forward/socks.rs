//! SOCKS5 dynamic forwarding proxy (-D).
//!
//! Implements RFC 1928 SOCKS5 protocol with:
//! - No authentication (method 0x00)
//! - CONNECT command only
//! - IPv4, IPv6, and domain name addresses

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};

use qsh_core::protocol::{
    ForwardAcceptPayload, ForwardClosePayload, ForwardDataPayload, ForwardEofPayload,
    ForwardRejectPayload, ForwardRequestPayload, Message,
};
use qsh_core::transport::{Connection, StreamPair, StreamType};
use qsh_core::{Error, Result};

// SOCKS5 constants
const SOCKS_VERSION: u8 = 0x05;
const AUTH_NO_AUTH: u8 = 0x00;
const AUTH_NO_ACCEPTABLE: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;
const ADDR_IPV4: u8 = 0x01;
const ADDR_DOMAIN: u8 = 0x03;
const ADDR_IPV6: u8 = 0x04;
const REPLY_SUCCESS: u8 = 0x00;
const REPLY_GENERAL_FAILURE: u8 = 0x01;
const REPLY_CONNECTION_REFUSED: u8 = 0x05;
const REPLY_CMD_NOT_SUPPORTED: u8 = 0x07;
const REPLY_ADDR_NOT_SUPPORTED: u8 = 0x08;

/// Maximum buffer size for forwarding data.
const FORWARD_BUFFER_SIZE: usize = 32 * 1024;

/// SOCKS5 proxy for dynamic forwarding.
pub struct Socks5Proxy<C: Connection> {
    /// TCP listener for local SOCKS5 connections.
    listener: TcpListener,
    /// Connection to the qsh server.
    connection: Arc<C>,
    /// Forward ID counter.
    next_forward_id: AtomicU64,
    /// Shutdown signal receiver.
    shutdown_rx: Option<oneshot::Receiver<()>>,
}

impl<C: Connection + 'static> Socks5Proxy<C> {
    /// Create a new SOCKS5 proxy.
    pub async fn new(bind_addr: SocketAddr, connection: Arc<C>) -> Result<Self> {
        let listener = TcpListener::bind(bind_addr).await.map_err(Error::Io)?;

        info!(addr = %bind_addr, "SOCKS5 proxy bound");

        Ok(Self {
            listener,
            connection,
            next_forward_id: AtomicU64::new(0),
            shutdown_rx: None,
        })
    }

    /// Get the local address the proxy is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.listener.local_addr().map_err(Error::Io)
    }

    /// Set a shutdown signal for graceful termination.
    pub fn set_shutdown(&mut self, rx: oneshot::Receiver<()>) {
        self.shutdown_rx = Some(rx);
    }

    /// Run the proxy, accepting connections until shutdown.
    pub async fn run(&mut self) -> Result<()> {
        loop {
            tokio::select! {
                accept_result = self.listener.accept() => {
                    match accept_result {
                        Ok((stream, peer_addr)) => {
                            debug!(peer = %peer_addr, "Accepted SOCKS5 connection");
                            self.handle_connection(stream, peer_addr).await;
                        }
                        Err(e) => {
                            error!(error = %e, "Accept failed");
                        }
                    }
                }
                _ = async {
                    if let Some(ref mut rx) = self.shutdown_rx {
                        let _ = rx.await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {
                    info!("SOCKS5 proxy shutting down");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Handle a single SOCKS5 connection.
    async fn handle_connection(&self, stream: TcpStream, peer_addr: SocketAddr) {
        let forward_id = self.next_forward_id.fetch_add(1, Ordering::SeqCst);
        let connection = Arc::clone(&self.connection);

        tokio::spawn(async move {
            if let Err(e) = Self::process_socks5(forward_id, stream, peer_addr, connection).await {
                debug!(
                    forward_id,
                    peer = %peer_addr,
                    error = %e,
                    "SOCKS5 connection failed"
                );
            }
        });
    }

    /// Process a SOCKS5 connection through the handshake and relay.
    async fn process_socks5(
        forward_id: u64,
        mut stream: TcpStream,
        peer_addr: SocketAddr,
        connection: Arc<C>,
    ) -> Result<()> {
        // Step 1: Authentication negotiation
        let mut buf = [0u8; 258]; // Max: 1 version + 1 nmethods + 255 methods

        // Read version and number of methods
        stream.read_exact(&mut buf[..2]).await.map_err(Error::Io)?;

        if buf[0] != SOCKS_VERSION {
            return Err(Error::Protocol {
                message: format!("unsupported SOCKS version: {}", buf[0]),
            });
        }

        let nmethods = buf[1] as usize;
        stream.read_exact(&mut buf[..nmethods]).await.map_err(Error::Io)?;

        // Check if no-auth is supported
        let supports_no_auth = buf[..nmethods].contains(&AUTH_NO_AUTH);

        if supports_no_auth {
            // Accept no-auth
            stream
                .write_all(&[SOCKS_VERSION, AUTH_NO_AUTH])
                .await
                .map_err(Error::Io)?;
        } else {
            // No acceptable method
            stream
                .write_all(&[SOCKS_VERSION, AUTH_NO_ACCEPTABLE])
                .await
                .map_err(Error::Io)?;
            return Err(Error::Protocol {
                message: "no acceptable authentication method".into(),
            });
        }

        // Step 2: Request
        stream.read_exact(&mut buf[..4]).await.map_err(Error::Io)?;

        if buf[0] != SOCKS_VERSION {
            return Err(Error::Protocol {
                message: "invalid SOCKS version in request".into(),
            });
        }

        let cmd = buf[1];
        // buf[2] is reserved
        let atyp = buf[3];

        // Only support CONNECT
        if cmd != CMD_CONNECT {
            Self::send_reply(&mut stream, REPLY_CMD_NOT_SUPPORTED).await?;
            return Err(Error::Protocol {
                message: format!("unsupported command: {}", cmd),
            });
        }

        // Parse destination address
        let (target_host, target_port) = match atyp {
            ADDR_IPV4 => {
                let mut addr = [0u8; 4];
                stream.read_exact(&mut addr).await.map_err(Error::Io)?;
                let ip = Ipv4Addr::from(addr);
                let mut port_buf = [0u8; 2];
                stream.read_exact(&mut port_buf).await.map_err(Error::Io)?;
                let port = u16::from_be_bytes(port_buf);
                (ip.to_string(), port)
            }
            ADDR_IPV6 => {
                let mut addr = [0u8; 16];
                stream.read_exact(&mut addr).await.map_err(Error::Io)?;
                let ip = Ipv6Addr::from(addr);
                let mut port_buf = [0u8; 2];
                stream.read_exact(&mut port_buf).await.map_err(Error::Io)?;
                let port = u16::from_be_bytes(port_buf);
                (ip.to_string(), port)
            }
            ADDR_DOMAIN => {
                let mut len_buf = [0u8; 1];
                stream.read_exact(&mut len_buf).await.map_err(Error::Io)?;
                let len = len_buf[0] as usize;
                let mut domain = vec![0u8; len];
                stream.read_exact(&mut domain).await.map_err(Error::Io)?;
                let domain = String::from_utf8(domain).map_err(|_| Error::Protocol {
                    message: "invalid domain name encoding".into(),
                })?;
                let mut port_buf = [0u8; 2];
                stream.read_exact(&mut port_buf).await.map_err(Error::Io)?;
                let port = u16::from_be_bytes(port_buf);
                (domain, port)
            }
            _ => {
                Self::send_reply(&mut stream, REPLY_ADDR_NOT_SUPPORTED).await?;
                return Err(Error::Protocol {
                    message: format!("unsupported address type: {}", atyp),
                });
            }
        };

        debug!(
            forward_id,
            target = %format!("{}:{}", target_host, target_port),
            "SOCKS5 CONNECT request"
        );

        // Step 3: Connect through qsh server
        let mut server_stream = match connection.open_stream(StreamType::Forward(forward_id as u32)).await {
            Ok(s) => s,
            Err(e) => {
                Self::send_reply(&mut stream, REPLY_GENERAL_FAILURE).await?;
                return Err(e);
            }
        };

        // Send forward request
        let request = Message::ForwardRequest(ForwardRequestPayload {
            forward_id,
            spec: qsh_core::protocol::ForwardSpec::Dynamic,
            target: target_host.clone(),
            target_port,
        });

        if let Err(e) = server_stream.send(&request).await {
            Self::send_reply(&mut stream, REPLY_GENERAL_FAILURE).await?;
            return Err(e);
        }

        // Wait for accept/reject
        let response = match server_stream.recv().await {
            Ok(r) => r,
            Err(e) => {
                Self::send_reply(&mut stream, REPLY_GENERAL_FAILURE).await?;
                return Err(e);
            }
        };

        match response {
            Message::ForwardAccept(ForwardAcceptPayload { forward_id: id }) if id == forward_id => {
                debug!(forward_id, "Forward accepted");
                // Send success reply
                Self::send_reply(&mut stream, REPLY_SUCCESS).await?;
            }
            Message::ForwardReject(ForwardRejectPayload { forward_id: id, reason })
                if id == forward_id =>
            {
                warn!(forward_id, %reason, "Forward rejected");
                Self::send_reply(&mut stream, REPLY_CONNECTION_REFUSED).await?;
                return Err(Error::Protocol {
                    message: format!("forward rejected: {}", reason),
                });
            }
            other => {
                Self::send_reply(&mut stream, REPLY_GENERAL_FAILURE).await?;
                return Err(Error::Protocol {
                    message: format!("unexpected response: {:?}", other),
                });
            }
        }

        // Step 4: Data relay
        Self::relay_data(forward_id, stream, server_stream).await?;

        debug!(
            forward_id,
            peer = %peer_addr,
            target = %format!("{}:{}", target_host, target_port),
            "SOCKS5 connection closed"
        );

        Ok(())
    }

    /// Send a SOCKS5 reply.
    async fn send_reply(stream: &mut TcpStream, reply: u8) -> Result<()> {
        // Reply format: VER REP RSV ATYP BND.ADDR BND.PORT
        // We use 0.0.0.0:0 as the bound address (not meaningful for CONNECT)
        let response = [
            SOCKS_VERSION,
            reply,
            0x00,                       // Reserved
            ADDR_IPV4,                  // Address type
            0x00, 0x00, 0x00, 0x00,     // 0.0.0.0
            0x00, 0x00,                 // Port 0
        ];
        stream.write_all(&response).await.map_err(Error::Io)
    }

    /// Relay data between local socket and server stream.
    async fn relay_data<S: StreamPair>(
        forward_id: u64,
        stream: TcpStream,
        mut server_stream: S,
    ) -> Result<()> {
        let (mut tcp_read, mut tcp_write) = stream.into_split();
        let (tx, mut rx) = mpsc::channel::<Message>(32);

        // Main relay task: handles server_stream and tcp_write
        let relay_task = async {
            loop {
                tokio::select! {
                    // Read from server stream
                    msg_result = server_stream.recv() => {
                        match msg_result {
                            Ok(Message::ForwardData(ForwardDataPayload { forward_id: id, data }))
                                if id == forward_id =>
                            {
                                if let Err(e) = tcp_write.write_all(&data).await {
                                    error!(forward_id, error = %e, "Local write error");
                                    break;
                                }
                            }
                            Ok(Message::ForwardEof(ForwardEofPayload { forward_id: id }))
                                if id == forward_id =>
                            {
                                debug!(forward_id, "Server EOF");
                                let _ = tcp_write.shutdown().await;
                            }
                            Ok(Message::ForwardClose(ForwardClosePayload { forward_id: id, reason }))
                                if id == forward_id =>
                            {
                                debug!(forward_id, ?reason, "Forward closed by server");
                                break;
                            }
                            Ok(other) => {
                                warn!(forward_id, "Unexpected message: {:?}", other);
                            }
                            Err(e) => {
                                debug!(forward_id, error = %e, "Server stream error");
                                break;
                            }
                        }
                    }
                    // Forward messages from TCP reader to server
                    Some(msg) = rx.recv() => {
                        if let Err(e) = server_stream.send(&msg).await {
                            debug!(forward_id, error = %e, "Failed to send to server");
                            break;
                        }
                        if matches!(msg, Message::ForwardEof(_) | Message::ForwardClose(_)) {
                            break;
                        }
                    }
                }
            }

            // Send close
            let close = Message::ForwardClose(ForwardClosePayload {
                forward_id,
                reason: None,
            });
            let _ = server_stream.send(&close).await;
            server_stream.close();
        };

        // TCP reader task: reads from local, sends via channel
        let tcp_reader = async {
            let mut buf = vec![0u8; FORWARD_BUFFER_SIZE];
            loop {
                match tcp_read.read(&mut buf).await {
                    Ok(0) => {
                        debug!(forward_id, "Local client EOF");
                        let eof = Message::ForwardEof(ForwardEofPayload { forward_id });
                        let _ = tx.send(eof).await;
                        break;
                    }
                    Ok(n) => {
                        let data = Message::ForwardData(ForwardDataPayload {
                            forward_id,
                            data: buf[..n].to_vec(),
                        });
                        if tx.send(data).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        error!(forward_id, error = %e, "Local read error");
                        break;
                    }
                }
            }
        };

        // Run both tasks
        tokio::join!(relay_task, tcp_reader);

        Ok(())
    }
}
