//! QUIC stream types for the quiche backend.
//!
//! This module provides stream wrappers around quiche streams, including:
//! - QuicheStream: A bidirectional stream wrapper
//! - QuicheStreamReader/QuicheStreamWriter: AsyncRead/AsyncWrite wrappers
//! - StreamPair trait implementation

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::{Buf, BytesMut};
use tokio::sync::Mutex;
use tracing::trace;

use crate::error::{Error, Result};
use crate::protocol::{Codec, Message};

use super::connection::QuicheConnectionInner;
use super::sender::QuicheSender;
use crate::transport::StreamPair;

// =============================================================================
// QuicheStream - Wrapper around quiche stream
// =============================================================================

/// A bidirectional QUIC stream pair using quiche.
pub struct QuicheStream {
    /// Connection handle for sending.
    conn: Arc<QuicheConnectionInner>,
    /// Stream ID.
    stream_id: u64,
    /// Receive buffer.
    recv_buf: Mutex<BytesMut>,
    /// Send-only flag.
    send_only: bool,
    /// Recv-only flag.
    recv_only: bool,
    /// Closed flag.
    closed: AtomicBool,
}

impl QuicheStream {
    /// Create a new bidirectional stream.
    pub fn new(conn: Arc<QuicheConnectionInner>, stream_id: u64) -> Self {
        Self {
            conn,
            stream_id,
            recv_buf: Mutex::new(BytesMut::with_capacity(8192)),
            send_only: false,
            recv_only: false,
            closed: AtomicBool::new(false),
        }
    }

    /// Create a send-only stream.
    pub fn send_only(conn: Arc<QuicheConnectionInner>, stream_id: u64) -> Self {
        Self {
            conn,
            stream_id,
            recv_buf: Mutex::new(BytesMut::new()),
            send_only: true,
            recv_only: false,
            closed: AtomicBool::new(false),
        }
    }

    /// Create a recv-only stream.
    pub fn recv_only(conn: Arc<QuicheConnectionInner>, stream_id: u64) -> Self {
        Self {
            conn,
            stream_id,
            recv_buf: Mutex::new(BytesMut::with_capacity(8192)),
            send_only: false,
            recv_only: true,
            closed: AtomicBool::new(false),
        }
    }

    /// Create a stream with pre-populated buffer and configurable direction.
    pub fn with_buffer(
        conn: Arc<QuicheConnectionInner>,
        stream_id: u64,
        initial_data: Option<BytesMut>,
        send_only: bool,
        recv_only: bool,
    ) -> Self {
        let recv_buf = match initial_data {
            Some(data) => data,
            None => BytesMut::with_capacity(8192),
        };
        Self {
            conn,
            stream_id,
            recv_buf: Mutex::new(recv_buf),
            send_only,
            recv_only,
            closed: AtomicBool::new(false),
        }
    }

    /// Get a cloneable sender handle for spawning background send tasks.
    ///
    /// Returns `Some(sender)` for bidirectional and send-only streams.
    /// Returns `None` for receive-only streams (which can't send).
    pub fn sender(&self) -> Option<QuicheSender> {
        // For now, always return Some since quiche streams are always
        // constructed from contexts that can send
        Some(QuicheSender {
            conn: Arc::clone(&self.conn),
            stream_id: self.stream_id,
        })
    }

    /// Send raw bytes without message framing.
    pub async fn send_raw(&self, data: &[u8]) -> Result<()> {
        if self.recv_only {
            return Err(Error::Transport {
                message: "stream is receive-only".to_string(),
            });
        }
        self.conn.stream_send(self.stream_id, data, false).await
    }

    /// Receive raw bytes without message framing.
    pub async fn recv_raw(&self, buf: &mut [u8]) -> Result<usize> {
        if self.send_only {
            return Err(Error::Transport {
                message: "stream is send-only".to_string(),
            });
        }
        self.conn.stream_recv(self.stream_id, buf).await
    }

    /// Gracefully finish the send side of the stream.
    pub async fn finish(&mut self) -> Result<()> {
        if self.recv_only {
            return Ok(());
        }
        self.conn.stream_send(self.stream_id, &[], true).await
    }

    /// Close the stream.
    pub fn close(&mut self) {
        self.closed.store(true, Ordering::SeqCst);
    }

    /// Split the stream into separate reader and writer halves.
    ///
    /// This consumes the stream and returns AsyncRead/AsyncWrite handles
    /// that can be used independently.
    pub fn into_split(self) -> (QuicheStreamWriter, QuicheStreamReader) {
        let recv_buf = self.recv_buf.into_inner();
        let writer = QuicheStreamWriter::new(Arc::clone(&self.conn), self.stream_id);
        let reader = QuicheStreamReader::new(self.conn, self.stream_id, Some(recv_buf));
        (writer, reader)
    }
}

impl StreamPair for QuicheStream {
    fn send(&mut self, msg: &Message) -> impl std::future::Future<Output = Result<()>> + Send {
        let data = Codec::encode(msg);
        let conn = Arc::clone(&self.conn);
        let stream_id = self.stream_id;
        let recv_only = self.recv_only;
        let msg_debug = format!("{:?}", msg);

        async move {
            if recv_only {
                return Err(Error::Transport {
                    message: "stream is receive-only".to_string(),
                });
            }
            let data = data?;
            trace!(stream_id = stream_id, msg = %msg_debug, len = data.len(), "quiche stream send");
            conn.stream_send(stream_id, &data, false).await
        }
    }

    fn recv(&mut self) -> impl std::future::Future<Output = Result<Message>> + Send {
        let conn = Arc::clone(&self.conn);
        let stream_id = self.stream_id;
        let recv_buf = unsafe {
            // SAFETY: We need to get a reference to self.recv_buf for the async block.
            // This is safe because we hold &mut self and the Mutex ensures exclusive access.
            &*((&self.recv_buf) as *const Mutex<BytesMut>)
        };
        let send_only = self.send_only;

        async move {
            if send_only {
                return Err(Error::Transport {
                    message: "stream is send-only".to_string(),
                });
            }

            let mut recv_buf = recv_buf.lock().await;

            loop {
                if let Some(msg) = Codec::decode(&mut recv_buf)? {
                    trace!(stream_id = stream_id, msg = ?msg, "quiche stream recv");
                    return Ok(msg);
                }

                let mut chunk = [0u8; 4096];
                match conn.stream_recv(stream_id, &mut chunk).await {
                    Ok(n) if n > 0 => {
                        recv_buf.extend_from_slice(&chunk[..n]);
                    }
                    Ok(_) => {
                        // EOF
                        if let Some(msg) = Codec::decode(&mut recv_buf)? {
                            trace!(stream_id = stream_id, msg = ?msg, "quiche stream recv (EOF)");
                            return Ok(msg);
                        }
                        trace!(
                            stream_id = stream_id,
                            "quiche stream recv EOF (no more messages)"
                        );
                        return Err(Error::ConnectionClosed);
                    }
                    Err(e) => {
                        trace!(stream_id = stream_id, error = %e, "quiche stream recv error");
                        return Err(e);
                    }
                }
            }
        }
    }

    fn close(&mut self) {
        self.closed.store(true, Ordering::SeqCst);
    }
}

// =============================================================================
// QuicheStreamReader / QuicheStreamWriter - AsyncRead/AsyncWrite wrappers
// =============================================================================

/// Write half of a QUIC stream implementing AsyncWrite.
pub struct QuicheStreamWriter {
    conn: Arc<QuicheConnectionInner>,
    stream_id: u64,
}

impl QuicheStreamWriter {
    /// Create a new stream writer.
    pub(crate) fn new(conn: Arc<QuicheConnectionInner>, stream_id: u64) -> Self {
        Self { conn, stream_id }
    }
}

impl tokio::io::AsyncWrite for QuicheStreamWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let conn = Arc::clone(&this.conn);
        let stream_id = this.stream_id;
        let data = buf.to_vec();

        // Create a future for the write operation
        let fut = async move {
            conn.stream_send(stream_id, &data, false)
                .await
                .map(|()| data.len())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
        };

        // Pin the future and poll it
        tokio::pin!(fut);
        fut.poll(cx)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let conn = Arc::clone(&this.conn);

        let fut = async move {
            conn.flush_send()
                .await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
        };

        tokio::pin!(fut);
        fut.poll(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let conn = Arc::clone(&this.conn);
        let stream_id = this.stream_id;

        let fut = async move {
            conn.stream_send(stream_id, &[], true)
                .await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
        };

        tokio::pin!(fut);
        fut.poll(cx)
    }
}

/// Read half of a QUIC stream implementing AsyncRead.
pub struct QuicheStreamReader {
    conn: Arc<QuicheConnectionInner>,
    stream_id: u64,
    buffer: BytesMut,
}

impl QuicheStreamReader {
    /// Create a new stream reader.
    pub(crate) fn new(
        conn: Arc<QuicheConnectionInner>,
        stream_id: u64,
        initial_buffer: Option<BytesMut>,
    ) -> Self {
        Self {
            conn,
            stream_id,
            buffer: initial_buffer.unwrap_or_default(),
        }
    }
}

impl tokio::io::AsyncRead for QuicheStreamReader {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // Return from buffer first if we have data
        if !this.buffer.is_empty() {
            let to_copy = std::cmp::min(this.buffer.len(), buf.remaining());
            buf.put_slice(&this.buffer[..to_copy]);
            this.buffer.advance(to_copy);
            return std::task::Poll::Ready(Ok(()));
        }

        let conn = Arc::clone(&this.conn);
        let stream_id = this.stream_id;
        let capacity = buf.remaining();

        let fut = async move {
            let mut temp_buf = vec![0u8; capacity];
            match conn.stream_recv(stream_id, &mut temp_buf).await {
                Ok(n) => Ok((temp_buf, n)),
                Err(e) => Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                )),
            }
        };

        tokio::pin!(fut);
        match fut.poll(cx) {
            std::task::Poll::Ready(Ok((data, n))) => {
                buf.put_slice(&data[..n]);
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}
