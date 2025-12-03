//! QUIC transport implementation using Quinn.
//!
//! Provides concrete implementations of the Connection and StreamPair traits
//! for real QUIC connections.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use quinn::{RecvStream, SendStream};
use tokio::sync::Mutex;
use tokio::select;

use crate::error::{Error, Result};
use crate::protocol::{Codec, Message};

use super::{Connection, StreamPair, StreamType};

// =============================================================================
// Quinn Stream Pair
// =============================================================================

/// A bidirectional QUIC stream pair.
pub struct QuicStream {
    send: Option<Arc<Mutex<SendStream>>>,
    recv: Option<Arc<Mutex<RecvStream>>>,
    recv_buf: BytesMut,
}

/// Map a bidirectional stream ID to StreamType.
async fn map_bidi_stream_type(stream_id: u64, next_forward_id: &Arc<Mutex<u32>>) -> StreamType {
    match stream_id {
        0 => StreamType::Control,
        4 => StreamType::Tunnel,
        _ => {
            // Use a monotonic forward id for simplicity
            let mut guard = next_forward_id.lock().await;
            let id = *guard;
            *guard = guard.saturating_add(1);
            StreamType::Forward(id)
        }
    }
}

/// Map a unidirectional stream ID to StreamType based on initiator.
fn map_uni_stream_type(stream_id: u64) -> StreamType {
    // QUIC stream ID bit0 = initiator (0 client, 1 server), bit1 = direction (0 bidirectional, 1 unidirectional)
    let initiator_server = stream_id & 0x1 == 1;
    match initiator_server {
        true => StreamType::TerminalOut, // server → client output
        false => StreamType::TerminalIn, // client → server input
    }
}

impl QuicStream {
    /// Create a new stream pair from Quinn streams.
    pub fn new(send: SendStream, recv: RecvStream) -> Self {
        Self {
            send: Some(Arc::new(Mutex::new(send))),
            recv: Some(Arc::new(Mutex::new(recv))),
            recv_buf: BytesMut::with_capacity(8192),
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
            recv_buf: BytesMut::with_capacity(8192),
        }
    }

    /// Create a recv-only stream (unidirectional).
    pub fn from_recv(recv: RecvStream) -> Self {
        Self {
            send: None,
            recv: Some(Arc::new(Mutex::new(recv))),
            recv_buf: BytesMut::with_capacity(8192),
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
        let mut recv_buf = std::mem::take(&mut self.recv_buf);

        let fut = async move {
            let Some(recv) = recv_opt else {
                return Err(Error::Transport {
                    message: "stream is send-only".to_string(),
                });
            };

            let mut recv = recv.lock().await;

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
        ;

        async move {
            let result = fut.await;
            // Note: recv_buf is consumed; if buffering across calls is needed,
            // refactor QuicStream to store the buffer via interior mutability.
            result
        }
    }

    fn close(&mut self) {
        // Closing is handled by dropping the streams
        // For explicit close, we could store a flag or send FIN
    }
}

// =============================================================================
// Quinn Connection
// =============================================================================

/// A QUIC connection wrapper.
pub struct QuicConnection {
    inner: quinn::Connection,
    /// Next forward ID for client-initiated forwards
    next_forward_id: Arc<Mutex<u32>>,
}

impl QuicConnection {
    /// Create a new connection wrapper.
    pub fn new(conn: quinn::Connection) -> Self {
        Self {
            inner: conn,
            next_forward_id: Arc::new(Mutex::new(0)),
        }
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
            StreamType::Control | StreamType::Tunnel => {
                let (send, recv) = self.inner.open_bi().await.map_err(|e| Error::Transport {
                    message: format!("failed to open bidirectional stream: {}", e),
                })?;
                Ok(QuicStream::new(send, recv))
            }
            StreamType::TerminalIn => {
                let send = self.inner.open_uni().await.map_err(|e| Error::Transport {
                    message: format!("failed to open terminal input stream: {}", e),
                })?;
                Ok(QuicStream::from_send(send))
            }
            StreamType::TerminalOut => {
                let send = self.inner.open_uni().await.map_err(|e| Error::Transport {
                    message: format!("failed to open terminal output stream: {}", e),
                })?;
                Ok(QuicStream::from_send(send))
            }
            StreamType::Forward(_) => {
                let (send, recv) = self.inner.open_bi().await.map_err(|e| Error::Transport {
                    message: format!("failed to open forward stream: {}", e),
                })?;
                Ok(QuicStream::new(send, recv))
            }
        }
    }

    async fn accept_stream(&self) -> Result<(StreamType, Self::Stream)> {
        select! {
            bi = self.inner.accept_bi() => {
                let (send, recv) = bi.map_err(|e| Error::Transport {
                    message: format!("failed to accept stream: {}", e),
                })?;
                // Use the full QUIC stream ID (includes initiator + direction bits)
                let stream_id: u64 = send.id().into();
                let stream_type = map_bidi_stream_type(stream_id, &self.next_forward_id).await;
                Ok((stream_type, QuicStream::new(send, recv)))
            }
            uni = self.inner.accept_uni() => {
                let recv = uni.map_err(|e| Error::Transport {
                    message: format!("failed to accept unidirectional stream: {}", e),
                })?;
                // Use the full QUIC stream ID (includes initiator + direction bits)
                let stream_id: u64 = recv.id().into();
                let stream_type = map_uni_stream_type(stream_id);
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
        assert!(StreamType::Control.is_bidirectional());
        assert!(StreamType::Forward(0).is_bidirectional());
    }
}
