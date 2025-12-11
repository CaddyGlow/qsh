//! S2N stream implementations.
//!
//! This module provides stream wrappers for s2n-quic streams, including
//! bidirectional and unidirectional variants, along with AsyncRead/AsyncWrite
//! adapters for tokio compatibility.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::{Buf, BytesMut};
use s2n_quic::stream::{BidirectionalStream, ReceiveStream, SendStream};
use tokio::sync::Mutex;

use crate::error::{Error, Result};
use crate::protocol::{Codec, Message};

use super::StreamPair;
use super::sender::S2nSender;

// =============================================================================
// Stream Direction
// =============================================================================

/// Stream direction/type.
#[derive(Debug, Clone, Copy)]
pub(super) enum StreamDirection {
    Bidirectional,
    SendOnly,
    RecvOnly,
}

// =============================================================================
// S2nStreamInner - Shared stream state
// =============================================================================

/// Inner state for S2nStream, wrapped in Arc for cloneable sender handles.
pub(super) struct S2nStreamInner {
    /// Send stream (for both bidi and unidirectional send).
    /// For bidirectional streams, this is the send half from split().
    pub(super) send: Option<Mutex<SendStream>>,
    /// Receive stream (for both bidi and unidirectional recv).
    /// For bidirectional streams, this is the recv half from split().
    pub(super) recv: Option<Mutex<ReceiveStream>>,
    /// Receive buffer for message framing.
    recv_buf: Mutex<BytesMut>,
    /// Stream direction.
    pub(super) direction: StreamDirection,
    /// Closed flag.
    closed: AtomicBool,
}

// =============================================================================
// S2nStream - Main stream wrapper
// =============================================================================

/// A QUIC stream pair using s2n-quic.
pub struct S2nStream {
    pub(super) inner: Arc<S2nStreamInner>,
}

impl S2nStream {
    /// Create a new bidirectional stream.
    ///
    /// The stream is split into separate send/recv halves to avoid lock contention
    /// between send and recv operations.
    pub fn new_bidi(stream: BidirectionalStream) -> Self {
        let (recv, send) = stream.split();
        Self {
            inner: Arc::new(S2nStreamInner {
                send: Some(Mutex::new(send)),
                recv: Some(Mutex::new(recv)),
                recv_buf: Mutex::new(BytesMut::with_capacity(8192)),
                direction: StreamDirection::Bidirectional,
                closed: AtomicBool::new(false),
            }),
        }
    }

    /// Create a send-only stream.
    pub fn send_only(stream: SendStream) -> Self {
        Self {
            inner: Arc::new(S2nStreamInner {
                send: Some(Mutex::new(stream)),
                recv: None,
                recv_buf: Mutex::new(BytesMut::new()),
                direction: StreamDirection::SendOnly,
                closed: AtomicBool::new(false),
            }),
        }
    }

    /// Create a recv-only stream.
    pub fn recv_only(stream: ReceiveStream) -> Self {
        Self {
            inner: Arc::new(S2nStreamInner {
                send: None,
                recv: Some(Mutex::new(stream)),
                recv_buf: Mutex::new(BytesMut::with_capacity(8192)),
                direction: StreamDirection::RecvOnly,
                closed: AtomicBool::new(false),
            }),
        }
    }

    /// Create a bidirectional stream with pre-populated buffer.
    pub fn with_buffer(stream: BidirectionalStream, initial_data: Option<BytesMut>) -> Self {
        let recv_buf = initial_data.unwrap_or_else(|| BytesMut::with_capacity(8192));
        let (recv, send) = stream.split();
        Self {
            inner: Arc::new(S2nStreamInner {
                send: Some(Mutex::new(send)),
                recv: Some(Mutex::new(recv)),
                recv_buf: Mutex::new(recv_buf),
                direction: StreamDirection::Bidirectional,
                closed: AtomicBool::new(false),
            }),
        }
    }

    /// Get a cloneable sender handle for spawning background send tasks.
    pub fn sender(&self) -> Option<S2nSender> {
        match self.inner.direction {
            StreamDirection::Bidirectional | StreamDirection::SendOnly => Some(S2nSender {
                inner: Arc::clone(&self.inner),
            }),
            StreamDirection::RecvOnly => None,
        }
    }

    /// Send raw bytes without message framing.
    pub async fn send_raw(&self, data: &[u8]) -> Result<()> {
        use tokio::io::AsyncWriteExt;

        if matches!(self.inner.direction, StreamDirection::RecvOnly) {
            return Err(Error::Transport {
                message: "stream is receive-only".to_string(),
            });
        }

        if let Some(ref send) = self.inner.send {
            let mut stream = send.lock().await;
            stream.write_all(data).await.map_err(|e| Error::Transport {
                message: format!("stream send failed: {}", e),
            })?;
            stream.flush().await.map_err(|e| Error::Transport {
                message: format!("stream flush failed: {}", e),
            })?;
        }
        Ok(())
    }

    /// Receive raw bytes without message framing.
    pub async fn recv_raw(&self, buf: &mut [u8]) -> Result<usize> {
        use tokio::io::AsyncReadExt;

        if matches!(self.inner.direction, StreamDirection::SendOnly) {
            return Err(Error::Transport {
                message: "stream is send-only".to_string(),
            });
        }

        if let Some(ref recv) = self.inner.recv {
            let mut stream = recv.lock().await;
            stream.read(buf).await.map_err(|e| Error::Transport {
                message: format!("stream recv failed: {}", e),
            })
        } else {
            Err(Error::Transport {
                message: "no stream available".to_string(),
            })
        }
    }

    /// Gracefully finish the send side of the stream.
    pub async fn finish(&self) -> Result<()> {
        use tokio::io::AsyncWriteExt;

        if matches!(self.inner.direction, StreamDirection::RecvOnly) {
            return Ok(());
        }

        if let Some(ref send) = self.inner.send {
            let mut stream = send.lock().await;
            stream.shutdown().await.map_err(|e| Error::Transport {
                message: format!("stream shutdown failed: {}", e),
            })?;
        }
        Ok(())
    }

    /// Split the stream into separate reader and writer halves.
    ///
    /// This consumes the stream and returns AsyncRead/AsyncWrite handles
    /// that can be used independently.
    pub fn into_split(self) -> Result<(S2nStreamWriter, S2nStreamReader)> {
        match self.inner.direction {
            StreamDirection::Bidirectional => {
                // Try to unwrap the Arc - this will fail if there are other references
                match Arc::try_unwrap(self.inner) {
                    Ok(inner) => {
                        // For bidirectional streams, we already have split halves
                        let send = inner
                            .send
                            .ok_or_else(|| Error::Transport {
                                message: "no send stream available".to_string(),
                            })?
                            .into_inner();
                        let recv = inner
                            .recv
                            .ok_or_else(|| Error::Transport {
                                message: "no recv stream available".to_string(),
                            })?
                            .into_inner();
                        let recv_buf = inner.recv_buf.into_inner();
                        Ok((
                            S2nStreamWriter::new(send),
                            S2nStreamReader::new(recv, Some(recv_buf)),
                        ))
                    }
                    Err(_) => Err(Error::Transport {
                        message: "cannot split stream while sender handles exist".to_string(),
                    }),
                }
            }
            _ => Err(Error::Transport {
                message: "can only split bidirectional streams".to_string(),
            }),
        }
    }
}

impl StreamPair for S2nStream {
    fn send(&mut self, msg: &Message) -> impl std::future::Future<Output = Result<()>> + Send {
        let data = Codec::encode(msg);
        let inner = Arc::clone(&self.inner);

        async move {
            use tokio::io::AsyncWriteExt;

            if matches!(inner.direction, StreamDirection::RecvOnly) {
                return Err(Error::Transport {
                    message: "stream is receive-only".to_string(),
                });
            }

            let data = data?;
            if let Some(ref send) = inner.send {
                let mut stream = send.lock().await;
                stream
                    .write_all(&data)
                    .await
                    .map_err(|e| Error::Transport {
                        message: format!("stream send failed: {}", e),
                    })?;
                stream.flush().await.map_err(|e| Error::Transport {
                    message: format!("stream flush failed: {}", e),
                })?;
            }
            Ok(())
        }
    }

    fn recv(&mut self) -> impl std::future::Future<Output = Result<Message>> + Send {
        let inner = Arc::clone(&self.inner);

        async move {
            use tokio::io::AsyncReadExt;

            if matches!(inner.direction, StreamDirection::SendOnly) {
                return Err(Error::Transport {
                    message: "stream is send-only".to_string(),
                });
            }

            let mut recv_buf = inner.recv_buf.lock().await;

            loop {
                if let Some(msg) = Codec::decode(&mut recv_buf)? {
                    return Ok(msg);
                }

                let mut chunk = [0u8; 4096];
                let n = if let Some(ref recv) = inner.recv {
                    let mut stream = recv.lock().await;
                    stream
                        .read(&mut chunk)
                        .await
                        .map_err(|e| Error::Transport {
                            message: format!("stream recv failed: {}", e),
                        })?
                } else {
                    return Err(Error::ConnectionClosed);
                };

                if n > 0 {
                    recv_buf.extend_from_slice(&chunk[..n]);
                } else {
                    // EOF
                    if let Some(msg) = Codec::decode(&mut recv_buf)? {
                        return Ok(msg);
                    }
                    return Err(Error::ConnectionClosed);
                }
            }
        }
    }

    fn close(&mut self) {
        self.inner.closed.store(true, Ordering::SeqCst);
    }
}

// =============================================================================
// S2nStreamReader / S2nStreamWriter - AsyncRead/AsyncWrite wrappers
// =============================================================================

/// Write half of a QUIC stream implementing AsyncWrite.
pub struct S2nStreamWriter {
    inner: SendStream,
}

impl S2nStreamWriter {
    /// Create a new stream writer.
    pub(super) fn new(stream: SendStream) -> Self {
        Self { inner: stream }
    }
}

impl tokio::io::AsyncWrite for S2nStreamWriter {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write(std::pin::Pin::new(&mut self.inner), cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_flush(std::pin::Pin::new(&mut self.inner), cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_shutdown(std::pin::Pin::new(&mut self.inner), cx)
    }
}

/// Read half of a QUIC stream implementing AsyncRead.
pub struct S2nStreamReader {
    inner: ReceiveStream,
    buffer: BytesMut,
}

impl S2nStreamReader {
    /// Create a new stream reader.
    pub(super) fn new(stream: ReceiveStream, initial_buffer: Option<BytesMut>) -> Self {
        Self {
            inner: stream,
            buffer: initial_buffer.unwrap_or_default(),
        }
    }
}

impl tokio::io::AsyncRead for S2nStreamReader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // Return from buffer first if we have data
        if !self.buffer.is_empty() {
            let to_copy = std::cmp::min(self.buffer.len(), buf.remaining());
            buf.put_slice(&self.buffer[..to_copy]);
            self.buffer.advance(to_copy);
            return std::task::Poll::Ready(Ok(()));
        }

        tokio::io::AsyncRead::poll_read(std::pin::Pin::new(&mut self.inner), cx, buf)
    }
}
