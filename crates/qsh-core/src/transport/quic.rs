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

use crate::error::{Error, Result};
use crate::protocol::{Codec, Message};

use super::{Connection, StreamPair, StreamType};

// =============================================================================
// Quinn Stream Pair
// =============================================================================

/// A bidirectional QUIC stream pair.
pub struct QuicStream {
    send: Arc<Mutex<SendStream>>,
    recv: Arc<Mutex<RecvStream>>,
    recv_buf: BytesMut,
}

impl QuicStream {
    /// Create a new stream pair from Quinn streams.
    pub fn new(send: SendStream, recv: RecvStream) -> Self {
        Self {
            send: Arc::new(Mutex::new(send)),
            recv: Arc::new(Mutex::new(recv)),
            recv_buf: BytesMut::with_capacity(8192),
        }
    }

    /// Create from a bidirectional stream.
    pub fn from_bi(streams: (SendStream, RecvStream)) -> Self {
        Self::new(streams.0, streams.1)
    }

    /// Get a cloneable sender handle for spawning background send tasks.
    ///
    /// This allows non-blocking sends by spawning tasks that don't block
    /// the main event loop.
    pub fn sender(&self) -> QuicSender {
        QuicSender {
            send: Arc::clone(&self.send),
        }
    }
}

/// A cloneable sender handle for a QUIC stream.
///
/// Can be used to send messages from spawned tasks without blocking
/// the main event loop.
#[derive(Clone)]
pub struct QuicSender {
    send: Arc<Mutex<SendStream>>,
}

impl QuicSender {
    /// Send a message (includes flush for low latency).
    pub async fn send(&self, msg: &Message) -> Result<()> {
        use tokio::io::AsyncWriteExt;

        let data = Codec::encode(msg)?;
        let mut send = self.send.lock().await;
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
    async fn send(&mut self, msg: &Message) -> Result<()> {
        use tokio::io::AsyncWriteExt;

        let data = Codec::encode(msg)?;
        let mut send = self.send.lock().await;
        send.write_all(&data).await.map_err(|e| Error::Transport {
            message: format!("failed to send message: {}", e),
        })?;
        // Flush to ensure data is sent immediately for low latency
        send.flush().await.map_err(|e| Error::Transport {
            message: format!("failed to flush stream: {}", e),
        })?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<Message> {
        let mut recv = self.recv.lock().await;

        loop {
            // Try to decode from existing buffer
            if let Some(msg) = Codec::decode(&mut self.recv_buf)? {
                return Ok(msg);
            }

            // Need more data
            let mut chunk = [0u8; 4096];
            let n = recv
                .read(&mut chunk)
                .await
                .map_err(|e| Error::Transport {
                    message: format!("failed to read from stream: {}", e),
                })?
                .ok_or_else(|| Error::Transport {
                    message: "stream closed unexpectedly".to_string(),
                })?;

            self.recv_buf.extend_from_slice(&chunk[..n]);
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
                // Terminal input is client-initiated unidirectional
                // For unidirectional, we need to handle this specially
                // Return an error for now - terminal input should use dedicated method
                Err(Error::Transport {
                    message: "use open_uni for terminal input stream".to_string(),
                })
            }
            StreamType::TerminalOut => {
                // Terminal output is server-initiated, client accepts
                Err(Error::Transport {
                    message: "terminal output stream is accepted, not opened".to_string(),
                })
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
        // Accept bidirectional stream
        let (send, recv) = self.inner.accept_bi().await.map_err(|e| Error::Transport {
            message: format!("failed to accept stream: {}", e),
        })?;

        // Determine stream type based on stream ID
        // QUIC stream IDs encode initiator and directionality
        let stream_id = send.id().index();

        let stream_type = match stream_id {
            0 => StreamType::Control,
            4 => StreamType::Tunnel,
            _ => {
                // Forward streams - extract forward ID
                let mut next_id = self.next_forward_id.lock().await;
                let forward_id = *next_id;
                *next_id += 1;
                StreamType::Forward(forward_id)
            }
        };

        Ok((stream_type, QuicStream::new(send, recv)))
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
