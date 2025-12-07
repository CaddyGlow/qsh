//! QUIC transport implementation using Quinn.
//!
//! Provides concrete implementations of the Connection and StreamPair traits
//! for real QUIC connections.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use quinn::{RecvStream, SendStream};
use tokio::io::AsyncWriteExt;
use tokio::select;
use tokio::sync::Mutex;

use crate::error::{Error, Result};
use crate::protocol::{ChannelId, Codec, Message};

use super::{Connection, StreamPair, StreamType};

// =============================================================================
// Channel Stream Header
// =============================================================================

/// Magic byte identifying a channel model unidirectional stream.
const CHANNEL_STREAM_MAGIC: u8 = 0xC1;

/// Create the 9-byte header for channel unidirectional streams.
///
/// Format: [magic (1 byte)] [encoded channel_id (8 bytes LE)]
fn channel_stream_header(channel_id: ChannelId) -> [u8; 9] {
    let mut header = [0u8; 9];
    header[0] = CHANNEL_STREAM_MAGIC;
    header[1..9].copy_from_slice(&channel_id.encode().to_le_bytes());
    header
}

/// Read and parse a channel stream header from a unidirectional stream.
///
/// Returns the StreamType (ChannelIn or ChannelOut based on initiator).
async fn read_channel_stream_header(recv: &mut RecvStream) -> Result<StreamType> {
    let mut header = [0u8; 9];
    recv.read_exact(&mut header).await.map_err(|e| Error::Transport {
        message: format!("failed to read channel header: {}", e),
    })?;

    if header[0] != CHANNEL_STREAM_MAGIC {
        return Err(Error::Protocol {
            message: format!("invalid channel stream magic: {:#x}", header[0]),
        });
    }

    let encoded = u64::from_le_bytes(header[1..9].try_into().unwrap());
    let channel_id = ChannelId::decode(encoded);

    // Determine In vs Out based on QUIC stream initiator bit
    // bit 0 = initiator (0 = client, 1 = server)
    let stream_id: u64 = recv.id().into();
    if stream_id & 0x1 == 1 {
        Ok(StreamType::ChannelOut(channel_id)) // Server-initiated
    } else {
        Ok(StreamType::ChannelIn(channel_id)) // Client-initiated
    }
}

// =============================================================================
// Quinn Stream Pair
// =============================================================================

/// A bidirectional QUIC stream pair.
pub struct QuicStream {
    send: Option<Arc<Mutex<SendStream>>>,
    recv: Option<Arc<Mutex<RecvStream>>>,
    recv_buf: Arc<Mutex<BytesMut>>,
}

/// Magic byte identifying a channel bidi stream.
const CHANNEL_BIDI_MAGIC: u8 = 0xC2;

/// Create the 9-byte header for channel bidirectional streams.
///
/// Format: [magic (1 byte)] [encoded channel_id (8 bytes LE)]
fn channel_bidi_header(channel_id: ChannelId) -> [u8; 9] {
    let mut header = [0u8; 9];
    header[0] = CHANNEL_BIDI_MAGIC;
    header[1..9].copy_from_slice(&channel_id.encode().to_le_bytes());
    header
}

/// Read and parse a channel bidi stream header.
///
/// Returns the ChannelId for this stream.
async fn read_channel_bidi_header(recv: &mut RecvStream) -> Result<ChannelId> {
    let mut header = [0u8; 9];
    recv.read_exact(&mut header).await.map_err(|e| Error::Transport {
        message: format!("failed to read channel bidi header: {}", e),
    })?;

    if header[0] != CHANNEL_BIDI_MAGIC {
        return Err(Error::Protocol {
            message: format!("invalid channel bidi stream magic: {:#x}", header[0]),
        });
    }

    let encoded = u64::from_le_bytes(header[1..9].try_into().unwrap());
    Ok(ChannelId::decode(encoded))
}


impl QuicStream {
    /// Create a new stream pair from Quinn streams.
    pub fn new(send: SendStream, recv: RecvStream) -> Self {
        Self {
            send: Some(Arc::new(Mutex::new(send))),
            recv: Some(Arc::new(Mutex::new(recv))),
            recv_buf: Arc::new(Mutex::new(BytesMut::with_capacity(8192))),
        }
    }

    /// Create from a bidirectional stream.
    pub fn from_bi(streams: (SendStream, RecvStream)) -> Self {
        Self::new(streams.0, streams.1)
    }

    /// Create a send-only stream (unidirectional).
    pub fn from_send(send: SendStream) -> Self {
        Self {
            send: Some(Arc::new(Mutex::new(send))),
            recv: None,
            recv_buf: Arc::new(Mutex::new(BytesMut::with_capacity(8192))),
        }
    }

    /// Create a recv-only stream (unidirectional).
    pub fn from_recv(recv: RecvStream) -> Self {
        Self {
            send: None,
            recv: Some(Arc::new(Mutex::new(recv))),
            recv_buf: Arc::new(Mutex::new(BytesMut::with_capacity(8192))),
        }
    }

    /// Get a cloneable sender handle for spawning background send tasks.
    ///
    /// This allows non-blocking sends by spawning tasks that don't block
    /// the main event loop.
    pub fn sender(&self) -> QuicSender {
        QuicSender {
            send: self.send.as_ref().map(Arc::clone),
        }
    }
}

/// A cloneable sender handle for a QUIC stream.
///
/// Can be used to send messages from spawned tasks without blocking
/// the main event loop.
#[derive(Clone)]
pub struct QuicSender {
    send: Option<Arc<Mutex<SendStream>>>,
}

impl QuicSender {
    /// Send a message (includes flush for low latency).
    pub async fn send(&self, msg: &Message) -> Result<()> {
        use tokio::io::AsyncWriteExt;

        let Some(send) = &self.send else {
            return Err(Error::Transport {
                message: "stream is receive-only".to_string(),
            });
        };

        let data = Codec::encode(msg)?;
        let mut send = send.lock().await;
        send.write_all(&data).await.map_err(|e| Error::Transport {
            message: format!("failed to send message: {}", e),
        })?;
        send.flush().await.map_err(|e| Error::Transport {
            message: format!("failed to flush stream: {}", e),
        })?;
        Ok(())
    }

    /// Send raw bytes without message framing.
    ///
    /// Used for forwarding raw TCP data where we don't want the overhead
    /// of message encoding.
    pub async fn send_raw(&self, data: &[u8]) -> Result<()> {
        use tokio::io::AsyncWriteExt;

        let Some(send) = &self.send else {
            return Err(Error::Transport {
                message: "stream is receive-only".to_string(),
            });
        };

        let mut send = send.lock().await;
        send.write_all(data).await.map_err(|e| Error::Transport {
            message: format!("failed to send raw data: {}", e),
        })?;
        send.flush().await.map_err(|e| Error::Transport {
            message: format!("failed to flush stream: {}", e),
        })?;
        Ok(())
    }
}

impl StreamPair for QuicStream {
    fn send(&mut self, msg: &Message) -> impl std::future::Future<Output = Result<()>> + Send {
        let data = Codec::encode(msg);

        let send_opt = self.send.as_ref().map(Arc::clone);

        async move {
            let data = data?;
            let Some(send) = send_opt else {
                return Err(Error::Transport {
                    message: "stream is receive-only".to_string(),
                });
            };

            use tokio::io::AsyncWriteExt;
            let mut send = send.lock().await;
            send.write_all(&data).await.map_err(|e| Error::Transport {
                message: format!("failed to send message: {}", e),
            })?;
            send.flush().await.map_err(|e| Error::Transport {
                message: format!("failed to flush stream: {}", e),
            })?;
            Ok(())
        }
    }

    fn recv(&mut self) -> impl std::future::Future<Output = Result<Message>> + Send {
        let recv_opt = self.recv.as_ref().map(Arc::clone);
        let recv_buf = Arc::clone(&self.recv_buf);

        async move {
            let Some(recv) = recv_opt else {
                return Err(Error::Transport {
                    message: "stream is send-only".to_string(),
                });
            };

            let mut recv = recv.lock().await;
            let mut recv_buf = recv_buf.lock().await;

            loop {
                if let Some(msg) = Codec::decode(&mut recv_buf)? {
                    return Ok(msg);
                }

                let mut chunk = [0u8; 4096];
                match recv.read(&mut chunk).await {
                    Ok(Some(n)) => {
                        recv_buf.extend_from_slice(&chunk[..n]);
                    }
                    Ok(None) => {
                        if let Some(msg) = Codec::decode(&mut recv_buf)? {
                            return Ok(msg);
                        }
                        return Err(Error::ConnectionClosed);
                    }
                    Err(e) => {
                        return Err(Error::Transport {
                            message: format!("failed to read from stream: {}", e),
                        });
                    }
                }
            }
        }
    }

    fn close(&mut self) {
        // Closing is handled by dropping the streams
        // For explicit close, we could store a flag or send FIN
    }
}

impl QuicStream {
    /// Gracefully finish the send side of the stream.
    ///
    /// This sends a FIN and waits for all data to be acknowledged,
    /// ensuring the remote peer receives all pending data before the
    /// stream closes.
    pub async fn finish(&mut self) -> Result<()> {
        if let Some(send) = &self.send {
            let mut guard = send.lock().await;
            guard.finish().map_err(|e| Error::Transport {
                message: format!("failed to finish stream: {}", e),
            })?;
            // Wait for the stream to be fully closed (all data ACKed)
            guard.stopped().await.map_err(|e| Error::Transport {
                message: format!("stream stopped with error: {}", e),
            })?;
        }
        Ok(())
    }

    /// Send raw bytes without message framing.
    ///
    /// Used for forwarding raw TCP data where we don't want the overhead
    /// of message encoding. Takes `&self` to allow concurrent send/recv.
    pub async fn send_raw(&self, data: &[u8]) -> Result<()> {
        use tokio::io::AsyncWriteExt;

        let Some(send) = &self.send else {
            return Err(Error::Transport {
                message: "stream is receive-only".to_string(),
            });
        };

        let mut send = send.lock().await;
        send.write_all(data).await.map_err(|e| Error::Transport {
            message: format!("failed to send raw data: {}", e),
        })?;
        send.flush().await.map_err(|e| Error::Transport {
            message: format!("failed to flush stream: {}", e),
        })?;
        Ok(())
    }

    /// Receive raw bytes without message framing.
    ///
    /// Used for forwarding raw TCP data. Returns the number of bytes read,
    /// or 0 if the stream has ended. Takes `&self` to allow concurrent send/recv.
    pub async fn recv_raw(&self, buf: &mut [u8]) -> Result<usize> {
        let Some(recv) = &self.recv else {
            return Err(Error::Transport {
                message: "stream is send-only".to_string(),
            });
        };

        let mut recv = recv.lock().await;
        // quinn's RecvStream::read returns Option<usize> where None = EOF
        match recv.read(buf).await {
            Ok(Some(n)) => Ok(n),
            Ok(None) => Ok(0), // EOF
            Err(e) => Err(Error::Transport {
                message: format!("failed to receive raw data: {}", e),
            }),
        }
    }

    /// Close the stream.
    pub fn close(&mut self) {
        // Drop the stream handles, which will send FIN
        self.send.take();
        self.recv.take();
    }
}

// =============================================================================
// Quinn Connection
// =============================================================================

/// A QUIC connection wrapper.
pub struct QuicConnection {
    inner: quinn::Connection,
}

impl QuicConnection {
    /// Create a new connection wrapper.
    pub fn new(conn: quinn::Connection) -> Self {
        Self { inner: conn }
    }

    /// Get the underlying Quinn connection.
    pub fn inner(&self) -> &quinn::Connection {
        &self.inner
    }

    /// Open a unidirectional send stream.
    pub async fn open_uni(&self) -> Result<SendStream> {
        self.inner.open_uni().await.map_err(|e| Error::Transport {
            message: format!("failed to open unidirectional stream: {}", e),
        })
    }

    /// Accept a unidirectional receive stream.
    pub async fn accept_uni(&self) -> Result<RecvStream> {
        self.inner.accept_uni().await.map_err(|e| Error::Transport {
            message: format!("failed to accept unidirectional stream: {}", e),
        })
    }
}

impl Connection for QuicConnection {
    type Stream = QuicStream;

    async fn open_stream(&self, stream_type: StreamType) -> Result<Self::Stream> {
        match stream_type {
            StreamType::Control => {
                // Control stream: no header needed (first bidi stream)
                let (send, recv) = self.inner.open_bi().await.map_err(|e| Error::Transport {
                    message: format!("failed to open control stream: {}", e),
                })?;
                Ok(QuicStream::new(send, recv))
            }
            StreamType::ChannelBidi(channel_id) => {
                // Channel bidi stream: write header to identify channel
                let (mut send, recv) = self.inner.open_bi().await.map_err(|e| Error::Transport {
                    message: format!("failed to open channel bidi stream: {}", e),
                })?;
                let header = channel_bidi_header(channel_id);
                send.write_all(&header).await.map_err(|e| Error::Transport {
                    message: format!("failed to write channel bidi header: {}", e),
                })?;
                // Flush to ensure header is sent immediately
                send.flush().await.map_err(|e| Error::Transport {
                    message: format!("failed to flush channel bidi header: {}", e),
                })?;
                Ok(QuicStream::new(send, recv))
            }
            StreamType::ChannelIn(channel_id) | StreamType::ChannelOut(channel_id) => {
                // Unidirectional channel stream: write header
                let mut send = self.inner.open_uni().await.map_err(|e| Error::Transport {
                    message: format!("failed to open channel stream: {}", e),
                })?;
                let header = channel_stream_header(channel_id);
                send.write_all(&header).await.map_err(|e| Error::Transport {
                    message: format!("failed to write channel header: {}", e),
                })?;
                Ok(QuicStream::from_send(send))
            }
        }
    }

    async fn accept_stream(&self) -> Result<(StreamType, Self::Stream)> {
        select! {
            bi = self.inner.accept_bi() => {
                let (send, mut recv) = bi.map_err(|e| Error::Transport {
                    message: format!("failed to accept stream: {}", e),
                })?;
                // QUIC stream ID 0 is the control stream (no header)
                let stream_id: u64 = send.id().into();
                if stream_id == 0 {
                    Ok((StreamType::Control, QuicStream::new(send, recv)))
                } else {
                    // Non-control bidi streams have a channel header
                    let channel_id = read_channel_bidi_header(&mut recv).await?;
                    Ok((StreamType::ChannelBidi(channel_id), QuicStream::new(send, recv)))
                }
            }
            uni = self.inner.accept_uni() => {
                let mut recv = uni.map_err(|e| Error::Transport {
                    message: format!("failed to accept unidirectional stream: {}", e),
                })?;
                // Read channel header to determine stream type
                let stream_type = read_channel_stream_header(&mut recv).await?;
                Ok((stream_type, QuicStream::from_recv(recv)))
            }
        }
    }

    fn remote_addr(&self) -> SocketAddr {
        self.inner.remote_address()
    }

    fn local_addr(&self) -> SocketAddr {
        // Quinn doesn't directly expose local address, use a placeholder
        // In practice, this would come from the endpoint
        "0.0.0.0:0".parse().unwrap()
    }

    fn is_connected(&self) -> bool {
        self.inner.close_reason().is_none()
    }

    fn rtt(&self) -> Duration {
        self.inner.rtt()
    }
}

impl QuicConnection {
    /// Get packet loss ratio (0.0 - 1.0).
    ///
    /// Calculated as lost_packets / sent_packets from QUIC path stats.
    pub fn packet_loss(&self) -> f64 {
        let stats = self.inner.stats();
        let sent = stats.path.sent_packets;
        let lost = stats.path.lost_packets;
        if sent == 0 {
            0.0
        } else {
            (lost as f64 / sent as f64).clamp(0.0, 1.0)
        }
    }

    /// Get the number of congestion events.
    pub fn congestion_events(&self) -> u64 {
        self.inner.stats().path.congestion_events
    }

    /// Get total packets sent.
    pub fn packets_sent(&self) -> u64 {
        self.inner.stats().path.sent_packets
    }

    /// Get total packets lost.
    pub fn packets_lost(&self) -> u64 {
        self.inner.stats().path.lost_packets
    }
}

// =============================================================================
// TLS Configuration Helpers
// =============================================================================

/// Create a client TLS configuration that accepts self-signed certificates
/// and verifies the certificate hash.
pub fn client_crypto_config(expected_cert_hash: Option<&[u8]>) -> Result<rustls::ClientConfig> {
    use rustls::DigitallySignedStruct;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    /// Custom certificate verifier that optionally checks cert hash
    #[derive(Debug)]
    struct CertHashVerifier {
        expected_hash: Option<Vec<u8>>,
    }

    impl ServerCertVerifier for CertHashVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> std::result::Result<ServerCertVerified, rustls::Error> {
            if let Some(expected) = &self.expected_hash {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(end_entity.as_ref());
                let hash = hasher.finalize();

                if hash.as_slice() != expected.as_slice() {
                    return Err(rustls::Error::General(
                        "certificate hash mismatch".to_string(),
                    ));
                }
            }
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
                rustls::SignatureScheme::RSA_PKCS1_SHA384,
                rustls::SignatureScheme::RSA_PKCS1_SHA512,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::RSA_PSS_SHA384,
                rustls::SignatureScheme::RSA_PSS_SHA512,
                rustls::SignatureScheme::ED25519,
            ]
        }
    }

    let verifier = Arc::new(CertHashVerifier {
        expected_hash: expected_cert_hash.map(|h| h.to_vec()),
    });

    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    Ok(config)
}

/// Create server TLS configuration from a certificate and key.
pub fn server_crypto_config(cert: Vec<u8>, key: Vec<u8>) -> Result<rustls::ServerConfig> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let cert = CertificateDer::from(cert);
    let key = PrivateKeyDer::try_from(key).map_err(|e| Error::Transport {
        message: format!("invalid private key: {}", e),
    })?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| Error::Transport {
            message: format!("failed to create server config: {}", e),
        })?;

    Ok(config)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_type_identification() {
        // Just verify stream types work correctly
        use crate::protocol::ChannelId;
        assert!(StreamType::Control.is_bidirectional());
        assert!(StreamType::ChannelBidi(ChannelId::client(0)).is_bidirectional());
    }
}
