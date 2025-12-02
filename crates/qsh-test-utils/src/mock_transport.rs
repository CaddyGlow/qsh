//! Mock transport for testing without real network.
//!
//! Provides in-memory channels that implement the transport traits,
//! allowing testing of protocol logic without actual QUIC connections.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use tokio::sync::mpsc;
use tokio::sync::Mutex;

use qsh_core::error::{Error, Result};
use qsh_core::protocol::Message;
use qsh_core::transport::StreamType;

/// A mock bidirectional stream using channels.
#[derive(Debug)]
pub struct MockStream {
    /// Channel for receiving messages.
    rx: mpsc::Receiver<Message>,
    /// Channel for sending messages.
    tx: mpsc::Sender<Message>,
    /// Buffer for partial reads (not used in message-based API).
    _buffer: BytesMut,
    /// Whether this stream has been closed.
    closed: bool,
}

impl MockStream {
    /// Create a new mock stream from channel endpoints.
    pub fn new(tx: mpsc::Sender<Message>, rx: mpsc::Receiver<Message>) -> Self {
        Self {
            rx,
            tx,
            _buffer: BytesMut::new(),
            closed: false,
        }
    }

    /// Send a message on this stream.
    pub async fn send(&mut self, msg: &Message) -> Result<()> {
        if self.closed {
            return Err(Error::ConnectionClosed);
        }

        self.tx
            .send(msg.clone())
            .await
            .map_err(|_| Error::ConnectionClosed)
    }

    /// Receive a message from this stream.
    pub async fn recv(&mut self) -> Result<Message> {
        if self.closed {
            return Err(Error::ConnectionClosed);
        }

        self.rx.recv().await.ok_or(Error::ConnectionClosed)
    }

    /// Close the stream.
    pub fn close(&mut self) {
        self.closed = true;
    }

    /// Check if the stream is closed.
    pub fn is_closed(&self) -> bool {
        self.closed
    }
}

/// A mock connection for testing.
#[derive(Debug)]
pub struct MockConnection {
    /// Our address.
    local_addr: SocketAddr,
    /// Peer address.
    remote_addr: SocketAddr,
    /// Open streams by type.
    streams: Arc<Mutex<HashMap<StreamType, MockStream>>>,
    /// Pending incoming streams.
    incoming_rx: mpsc::Receiver<(StreamType, MockStream)>,
    /// Channel for peer to send incoming streams.
    incoming_tx: mpsc::Sender<(StreamType, MockStream)>,
    /// Counter for generating forward IDs.
    next_forward_id: AtomicU64,
    /// Simulated RTT.
    rtt: Duration,
    /// Whether connection is alive.
    connected: bool,
}

impl MockConnection {
    /// Create a new mock connection.
    pub fn new(local_addr: SocketAddr, remote_addr: SocketAddr) -> Self {
        let (incoming_tx, incoming_rx) = mpsc::channel(16);
        Self {
            local_addr,
            remote_addr,
            streams: Arc::new(Mutex::new(HashMap::new())),
            incoming_rx,
            incoming_tx,
            next_forward_id: AtomicU64::new(0),
            rtt: Duration::from_millis(10),
            connected: true,
        }
    }

    /// Get the incoming stream sender (for peer to send streams to us).
    pub fn incoming_sender(&self) -> mpsc::Sender<(StreamType, MockStream)> {
        self.incoming_tx.clone()
    }

    /// Open a new stream (returns our half, caller must provide peer half).
    pub fn open_stream_half(&self, _stream_type: StreamType) -> (MockStream, MockStream) {
        let (tx1, rx1) = mpsc::channel(64);
        let (tx2, rx2) = mpsc::channel(64);

        let our_half = MockStream::new(tx1, rx2);
        let peer_half = MockStream::new(tx2, rx1);

        (our_half, peer_half)
    }

    /// Accept an incoming stream.
    pub async fn accept_stream(&mut self) -> Result<(StreamType, MockStream)> {
        self.incoming_rx
            .recv()
            .await
            .ok_or(Error::ConnectionClosed)
    }

    /// Get the remote peer's address.
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Get the local address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Check if the connection is still alive.
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Get the current RTT estimate.
    pub fn rtt(&self) -> Duration {
        self.rtt
    }

    /// Set the simulated RTT.
    pub fn set_rtt(&mut self, rtt: Duration) {
        self.rtt = rtt;
    }

    /// Simulate disconnection.
    pub fn disconnect(&mut self) {
        self.connected = false;
    }

    /// Generate a new forward ID.
    pub fn next_forward_id(&self) -> u64 {
        self.next_forward_id.fetch_add(1, Ordering::SeqCst)
    }
}

/// Create a pair of connected mock connections (client and server).
pub fn mock_connection_pair() -> (MockConnection, MockConnection) {
    let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 4500);

    let client = MockConnection::new(client_addr, server_addr);
    let server = MockConnection::new(server_addr, client_addr);

    (client, server)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use qsh_core::protocol::{HelloPayload, Capabilities, TermSize};

    #[tokio::test]
    async fn mock_stream_send_recv() {
        let (tx1, rx1) = mpsc::channel(16);
        let (tx2, rx2) = mpsc::channel(16);

        let mut stream1 = MockStream::new(tx1, rx2);
        let mut stream2 = MockStream::new(tx2, rx1);

        let msg = Message::Ping(42);
        stream1.send(&msg).await.unwrap();

        let received = stream2.recv().await.unwrap();
        assert_eq!(received, msg);
    }

    #[tokio::test]
    async fn mock_stream_close() {
        let (tx, rx) = mpsc::channel(16);
        let mut stream = MockStream::new(tx, rx);

        assert!(!stream.is_closed());
        stream.close();
        assert!(stream.is_closed());

        let result = stream.send(&Message::Ping(1)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn mock_connection_pair_addresses() {
        let (client, server) = mock_connection_pair();

        assert_eq!(client.remote_addr(), server.local_addr());
        assert_eq!(server.remote_addr(), client.local_addr());
    }

    #[tokio::test]
    async fn mock_connection_open_stream() {
        let (client, _server) = mock_connection_pair();

        let (our_half, peer_half) = client.open_stream_half(StreamType::Control);

        // Should be able to communicate
        let (tx, rx) = (our_half.tx.clone(), peer_half.rx);
        tx.send(Message::Ping(123)).await.unwrap();
        // Note: We'd need to properly wire up the peer half in real usage
    }

    #[tokio::test]
    async fn mock_connection_disconnect() {
        let (mut client, _) = mock_connection_pair();

        assert!(client.is_connected());
        client.disconnect();
        assert!(!client.is_connected());
    }

    #[tokio::test]
    async fn mock_connection_rtt() {
        let (mut client, _) = mock_connection_pair();

        assert_eq!(client.rtt(), Duration::from_millis(10));
        client.set_rtt(Duration::from_millis(50));
        assert_eq!(client.rtt(), Duration::from_millis(50));
    }

    #[tokio::test]
    async fn mock_connection_forward_ids() {
        let (client, _) = mock_connection_pair();

        assert_eq!(client.next_forward_id(), 0);
        assert_eq!(client.next_forward_id(), 1);
        assert_eq!(client.next_forward_id(), 2);
    }
}
