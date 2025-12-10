//! S2N connection implementation.
//!
//! This module provides the S2nConnection type that wraps s2n-quic connections
//! and implements the Connection trait.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use s2n_quic::stream::BidirectionalStream;
use tokio::sync::Mutex;
use tracing::debug;

use crate::error::{Error, Result};
use crate::protocol::ChannelId;

use super::common::{channel_bidi_header, channel_stream_header, CHANNEL_BIDI_MAGIC, CHANNEL_STREAM_MAGIC};
use super::stats::{ConnectionStats, HandshakeState, SessionTicketState};
use super::stream::{S2nStream, S2nStreamReader, S2nStreamWriter};
use super::{Connection, StreamType};

// =============================================================================
// S2nConnection - Public connection wrapper
// =============================================================================

/// A QUIC connection wrapper using s2n-quic.
pub struct S2nConnection {
    /// The s2n-quic connection (for accepting streams).
    conn: Mutex<s2n_quic::connection::Connection>,
    /// Remote address.
    remote_addr: SocketAddr,
    /// Local address.
    local_addr: SocketAddr,
    /// Pending incoming streams (stream_type, stream).
    pending_streams: Mutex<VecDeque<(StreamType, S2nStream)>>,
    /// Connection closed flag.
    closed: AtomicBool,
    /// Control stream (stream ID 0).
    control_stream: Mutex<Option<BidirectionalStream>>,
    /// Whether this is a server connection.
    is_server: bool,
    /// Connection statistics (populated by event subscriber).
    stats: Arc<ConnectionStats>,
    /// Handshake status tracking.
    handshake: Arc<HandshakeState>,
    /// Session ticket/resumption tracking.
    session_state: Arc<SessionTicketState>,
}

impl S2nConnection {
    /// Create a new connection wrapper from a client connection.
    pub(crate) async fn from_client_connection(
        mut conn: s2n_quic::connection::Connection,
        local_addr: SocketAddr,
        stats: Arc<ConnectionStats>,
        handshake: Arc<HandshakeState>,
        session_state: Arc<SessionTicketState>,
    ) -> Result<Self> {
        let remote_addr = conn.remote_addr().map_err(|e| Error::Transport {
            message: format!("failed to get remote address: {}", e),
        })?;

        // Open control stream (stream ID 0 equivalent)
        let control_stream = conn.open_bidirectional_stream().await.map_err(|e| Error::Transport {
            message: format!("failed to open control stream: {}", e),
        })?;

        handshake.mark_confirmed();

        Ok(Self {
            conn: Mutex::new(conn),
            remote_addr,
            local_addr,
            pending_streams: Mutex::new(VecDeque::new()),
            closed: AtomicBool::new(false),
            control_stream: Mutex::new(Some(control_stream)),
            is_server: false,
            stats,
            handshake,
            session_state,
        })
    }

    /// Create a new connection wrapper from a server connection.
    pub(crate) async fn from_server_connection(
        mut conn: s2n_quic::connection::Connection,
        local_addr: SocketAddr,
        stats: Arc<ConnectionStats>,
        handshake: Arc<HandshakeState>,
        session_state: Arc<SessionTicketState>,
    ) -> Result<Self> {
        let remote_addr = conn.remote_addr().map_err(|e| Error::Transport {
            message: format!("failed to get remote address: {}", e),
        })?;

        // For server, accept the control stream initiated by client
        let control_stream = conn.accept_bidirectional_stream().await.map_err(|e| Error::Transport {
            message: format!("failed to accept control stream: {}", e),
        })?.ok_or_else(|| Error::Transport {
            message: "connection closed before control stream".to_string(),
        })?;

        handshake.mark_confirmed();

        Ok(Self {
            conn: Mutex::new(conn),
            remote_addr,
            local_addr,
            pending_streams: Mutex::new(VecDeque::new()),
            closed: AtomicBool::new(false),
            control_stream: Mutex::new(Some(control_stream)),
            is_server: true,
            stats,
            handshake,
            session_state,
        })
    }

    /// Get session data for 0-RTT resumption on reconnect.
    pub async fn session_data(&self) -> Option<Vec<u8>> {
        self.session_state.ticket()
    }

    /// Check if the connection has early data available (0-RTT phase).
    pub async fn is_in_early_data(&self) -> bool {
        !self.handshake.is_complete()
    }

    /// Check if the connection was resumed from a previous session (0-RTT).
    pub async fn is_resumed(&self) -> bool {
        self.session_state.is_resumed()
    }

    /// Get packet loss ratio (0.0 - 1.0).
    pub async fn packet_loss(&self) -> f64 {
        self.stats.packet_loss_ratio()
    }

    /// Get the congestion window size.
    pub async fn congestion_window(&self) -> u64 {
        self.stats.congestion_window() as u64
    }

    /// Get minimum observed RTT.
    pub async fn min_rtt(&self) -> Option<Duration> {
        let min_rtt = self.stats.min_rtt();
        if min_rtt.is_zero() {
            None
        } else {
            Some(min_rtt)
        }
    }

    /// Get the connection statistics.
    pub fn stats(&self) -> &ConnectionStats {
        &self.stats
    }

    /// Close the connection gracefully.
    ///
    /// This initiates a QUIC connection close. After calling this,
    /// any pending stream operations will return errors.
    pub async fn close_connection(&self) {
        debug!("close_connection called, setting closed flag");
        self.closed.store(true, Ordering::SeqCst);

        // Close the s2n-quic connection to wake up any pending recv operations
        let conn = self.conn.lock().await;
        // Use application error code 0 (NO_ERROR)
        conn.close(0u8.into());
        debug!("s2n-quic connection closed");
    }

    /// Accept an incoming bidirectional stream.
    pub async fn accept_bi(&self) -> Result<(S2nStreamWriter, S2nStreamReader)> {
        let mut conn = self.conn.lock().await;

        // Accept bidirectional stream
        let stream = conn.accept_bidirectional_stream().await.map_err(|e| Error::Transport {
            message: format!("failed to accept bidirectional stream: {}", e),
        })?.ok_or_else(|| Error::ConnectionClosed)?;

        let (recv, send) = stream.split();
        Ok((S2nStreamWriter::new(send), S2nStreamReader::new(recv, None)))
    }
}

impl Connection for S2nConnection {
    type Stream = S2nStream;

    async fn open_stream(&self, stream_type: StreamType) -> Result<Self::Stream> {
        match stream_type {
            StreamType::Control => {
                // Return the pre-opened control stream
                let mut control = self.control_stream.lock().await;
                if let Some(stream) = control.take() {
                    Ok(S2nStream::new_bidi(stream))
                } else {
                    Err(Error::Transport {
                        message: "control stream already taken".to_string(),
                    })
                }
            }
            StreamType::ChannelBidi(channel_id) => {
                let mut conn = self.conn.lock().await;

                // Open new bidi stream
                let mut stream = conn.open_bidirectional_stream().await.map_err(|e| Error::Transport {
                    message: format!("failed to open bidirectional stream: {}", e),
                })?;
                drop(conn);

                // Write header
                let header = channel_bidi_header(channel_id);
                use tokio::io::AsyncWriteExt;
                stream.write_all(&header).await.map_err(|e| Error::Transport {
                    message: format!("failed to write stream header: {}", e),
                })?;
                stream.flush().await.map_err(|e| Error::Transport {
                    message: format!("failed to flush stream header: {}", e),
                })?;

                Ok(S2nStream::new_bidi(stream))
            }
            StreamType::ChannelIn(channel_id) | StreamType::ChannelOut(channel_id) => {
                let mut conn = self.conn.lock().await;

                // Open new unidirectional stream
                let mut stream = conn.open_send_stream().await.map_err(|e| Error::Transport {
                    message: format!("failed to open unidirectional stream: {}", e),
                })?;
                drop(conn);

                // Write header
                let header = channel_stream_header(channel_id);
                use tokio::io::AsyncWriteExt;
                stream.write_all(&header).await.map_err(|e| Error::Transport {
                    message: format!("failed to write stream header: {}", e),
                })?;
                stream.flush().await.map_err(|e| Error::Transport {
                    message: format!("failed to flush stream header: {}", e),
                })?;

                Ok(S2nStream::send_only(stream))
            }
        }
    }

    async fn accept_stream(&self) -> Result<(StreamType, Self::Stream)> {
        // First, check if the control stream is still available (for server connections)
        // The control stream is the first bidi stream and doesn't have a header
        {
            let mut control = self.control_stream.lock().await;
            if let Some(stream) = control.take() {
                debug!("Returning pre-accepted control stream");
                return Ok((StreamType::Control, S2nStream::new_bidi(stream)));
            }
        }

        // Check for pending streams
        {
            let mut pending = self.pending_streams.lock().await;
            if let Some((stream_type, stream)) = pending.pop_front() {
                return Ok((stream_type, stream));
            }
        }

        // s2n-quic's Connection doesn't support concurrent accept calls, so we need
        // to poll each accept type sequentially. We use a loop with a small timeout
        // to check for both stream types.
        loop {
            // Try to accept a bidirectional stream with a short timeout
            {
                let mut conn = self.conn.lock().await;
                match tokio::time::timeout(
                    Duration::from_millis(10),
                    conn.accept_bidirectional_stream(),
                )
                .await
                {
                    Ok(Ok(Some(mut stream))) => {
                        // Read stream header to determine type
                        let mut header = [0u8; 9];
                        use tokio::io::AsyncReadExt;
                        stream.read_exact(&mut header).await.map_err(|e| Error::Transport {
                            message: format!("failed to read stream header: {}", e),
                        })?;

                        let magic = header[0];
                        let encoded = u64::from_le_bytes(header[1..9].try_into().unwrap());
                        let channel_id = ChannelId::decode(encoded);

                        let stream_type = match magic {
                            CHANNEL_BIDI_MAGIC => StreamType::ChannelBidi(channel_id),
                            _ => {
                                return Err(Error::Transport {
                                    message: format!("unknown stream magic: {:#x}", magic),
                                });
                            }
                        };

                        return Ok((stream_type, S2nStream::new_bidi(stream)));
                    }
                    Ok(Ok(None)) => return Err(Error::ConnectionClosed),
                    Ok(Err(e)) => {
                        return Err(Error::Transport {
                            message: format!("failed to accept stream: {}", e),
                        })
                    }
                    Err(_) => {
                        // Timeout - try receive stream next
                    }
                }
            }

            // Try to accept a unidirectional receive stream with a short timeout
            {
                let mut conn = self.conn.lock().await;
                match tokio::time::timeout(
                    Duration::from_millis(10),
                    conn.accept_receive_stream(),
                )
                .await
                {
                    Ok(Ok(Some(mut stream))) => {
                        // Read stream header to determine type
                        let mut header = [0u8; 9];
                        use tokio::io::AsyncReadExt;
                        stream.read_exact(&mut header).await.map_err(|e| Error::Transport {
                            message: format!("failed to read stream header: {}", e),
                        })?;

                        let magic = header[0];
                        let encoded = u64::from_le_bytes(header[1..9].try_into().unwrap());
                        let channel_id = ChannelId::decode(encoded);

                        let stream_type = match magic {
                            CHANNEL_STREAM_MAGIC => {
                                // Determine In vs Out based on who we are
                                if self.is_server {
                                    StreamType::ChannelIn(channel_id) // Client-initiated to server
                                } else {
                                    StreamType::ChannelOut(channel_id) // Server-initiated to client
                                }
                            }
                            _ => {
                                return Err(Error::Transport {
                                    message: format!("unknown stream magic: {:#x}", magic),
                                });
                            }
                        };

                        return Ok((stream_type, S2nStream::recv_only(stream)));
                    }
                    Ok(Ok(None)) => return Err(Error::ConnectionClosed),
                    Ok(Err(e)) => {
                        return Err(Error::Transport {
                            message: format!("failed to accept stream: {}", e),
                        })
                    }
                    Err(_) => {
                        // Timeout - loop again and check for bidi streams
                    }
                }
            }
        }
    }

    fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    fn is_connected(&self) -> bool {
        !self.closed.load(Ordering::SeqCst)
    }

    async fn rtt(&self) -> Duration {
        let rtt = self.stats.smoothed_rtt();
        if rtt.is_zero() {
            // Return a default if no RTT samples yet
            Duration::from_millis(100)
        } else {
            rtt
        }
    }
}
