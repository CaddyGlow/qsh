//! Integration tests for stream direction mapping in reverse-attach mode.
//!
//! These tests verify that the StreamDirectionMapper correctly handles both normal
//! and reverse-attach modes when integrated with the Connection/StreamPair infrastructure.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, Mutex};
use tokio::time::timeout;

use qsh_core::error::{Error, Result};
use qsh_core::protocol::{ChannelId, Message, ResizePayload};
use qsh_core::transport::{
    Connection, EndpointRole, StreamDirectionMapper, StreamType,
};
use qsh_test_utils::MockStream;

// =============================================================================
// Test Connection Infrastructure
// =============================================================================

/// A test connection that properly wires two endpoints together.
///
/// This is similar to the TestConnection in file_transfer_e2e.rs but simplified
/// for stream direction testing.
struct TestConnection {
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    incoming_rx: Arc<Mutex<mpsc::Receiver<(StreamType, MockStream)>>>,
    peer_incoming_tx: mpsc::Sender<(StreamType, MockStream)>,
    rtt: Duration,
    connected: AtomicBool,
}

impl TestConnection {
    /// Create a pair of properly wired test connections.
    fn pair() -> (Self, Self) {
        let (tx1, rx1) = mpsc::channel(16);
        let (tx2, rx2) = mpsc::channel(16);

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 4500);

        let client = TestConnection {
            local_addr: client_addr,
            remote_addr: server_addr,
            incoming_rx: Arc::new(Mutex::new(rx1)),
            peer_incoming_tx: tx2,
            rtt: Duration::from_millis(10),
            connected: AtomicBool::new(true),
        };

        let server = TestConnection {
            local_addr: server_addr,
            remote_addr: client_addr,
            incoming_rx: Arc::new(Mutex::new(rx2)),
            peer_incoming_tx: tx1,
            rtt: Duration::from_millis(10),
            connected: AtomicBool::new(true),
        };

        (client, server)
    }

    fn open_stream_half(&self) -> (MockStream, MockStream) {
        let (tx1, rx1) = mpsc::channel(64);
        let (tx2, rx2) = mpsc::channel(64);

        let our_half = MockStream::new(tx1, rx2);
        let peer_half = MockStream::new(tx2, rx1);
        (our_half, peer_half)
    }
}

impl Connection for TestConnection {
    type Stream = MockStream;

    fn open_stream(
        &self,
        stream_type: StreamType,
    ) -> impl std::future::Future<Output = Result<Self::Stream>> + Send {
        let sender = self.peer_incoming_tx.clone();
        let (our_half, peer_half) = self.open_stream_half();
        async move {
            sender
                .send((stream_type, peer_half))
                .await
                .map_err(|_| Error::ConnectionClosed)?;
            Ok(our_half)
        }
    }

    fn accept_stream(
        &self,
    ) -> impl std::future::Future<Output = Result<(StreamType, Self::Stream)>> + Send {
        let rx = Arc::clone(&self.incoming_rx);
        async move {
            let mut guard = rx.lock().await;
            guard.recv().await.ok_or(Error::ConnectionClosed)
        }
    }

    fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    fn rtt(&self) -> impl std::future::Future<Output = Duration> + Send {
        async move { self.rtt }
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Simulate opening a ChannelIn stream and verify it works correctly.
async fn test_channel_in_flow(
    opener_conn: &TestConnection,
    acceptor_conn: &TestConnection,
    _opener_mapper: &StreamDirectionMapper,
    channel_id: ChannelId,
) -> Result<()> {
    // Open ChannelIn from the opener's perspective
    let opener_task = opener_conn.open_stream(StreamType::ChannelIn(channel_id));

    // Accept ChannelIn from the acceptor's perspective
    let acceptor_task = acceptor_conn.accept_stream();

    // Run both tasks with timeout
    let timeout_duration = Duration::from_secs(1);

    let (opener_result, acceptor_result) = tokio::join!(
        timeout(timeout_duration, opener_task),
        timeout(timeout_duration, acceptor_task)
    );

    let mut opener_stream = opener_result
        .map_err(|_| Error::Timeout)?
        .map_err(|e| Error::Protocol { message: format!("Opener failed: {:?}", e) })?;

    let (stream_type, mut acceptor_stream) = acceptor_result
        .map_err(|_| Error::Timeout)?
        .map_err(|e| Error::Protocol { message: format!("Acceptor failed: {:?}", e) })?;

    // Verify the stream type was correctly detected
    assert_eq!(
        stream_type,
        StreamType::ChannelIn(channel_id),
        "Acceptor should detect ChannelIn stream"
    );

    // Send a message from opener to acceptor
    let test_msg = Message::Resize(ResizePayload {
        channel_id: Some(channel_id),
        cols: 80,
        rows: 24,
    });

    opener_stream.send(&test_msg).await?;
    let received_msg = acceptor_stream.recv().await?;
    assert_eq!(received_msg, test_msg, "Message should roundtrip correctly");

    Ok(())
}

/// Simulate opening a ChannelOut stream and verify it works correctly.
async fn test_channel_out_flow(
    opener_conn: &TestConnection,
    acceptor_conn: &TestConnection,
    _opener_mapper: &StreamDirectionMapper,
    channel_id: ChannelId,
) -> Result<()> {
    // Open ChannelOut from the opener's perspective
    let opener_task = opener_conn.open_stream(StreamType::ChannelOut(channel_id));

    // Accept ChannelOut from the acceptor's perspective
    let acceptor_task = acceptor_conn.accept_stream();

    // Run both tasks with timeout
    let timeout_duration = Duration::from_secs(1);

    let (opener_result, acceptor_result) = tokio::join!(
        timeout(timeout_duration, opener_task),
        timeout(timeout_duration, acceptor_task)
    );

    let mut opener_stream = opener_result
        .map_err(|_| Error::Timeout)?
        .map_err(|e| Error::Protocol { message: format!("Opener failed: {:?}", e) })?;

    let (stream_type, mut acceptor_stream) = acceptor_result
        .map_err(|_| Error::Timeout)?
        .map_err(|e| Error::Protocol { message: format!("Acceptor failed: {:?}", e) })?;

    // Verify the stream type was correctly detected
    assert_eq!(
        stream_type,
        StreamType::ChannelOut(channel_id),
        "Acceptor should detect ChannelOut stream"
    );

    // Send a message from opener to acceptor
    let test_msg = Message::Resize(ResizePayload {
        channel_id: Some(channel_id),
        cols: 120,
        rows: 40,
    });

    opener_stream.send(&test_msg).await?;
    let received_msg = acceptor_stream.recv().await?;
    assert_eq!(received_msg, test_msg, "Message should roundtrip correctly");

    Ok(())
}

// =============================================================================
// Normal Mode Tests
// =============================================================================

/// Test normal mode: logical client = QUIC client, logical server = QUIC server.
///
/// In this mode:
/// - Client opens ChannelIn (client-initiated uni streams)
/// - Server opens ChannelOut (server-initiated uni streams)
#[tokio::test]
async fn normal_mode_client_opens_channel_in() {
    let (client_conn, server_conn) = TestConnection::pair();

    // Normal mode: logical role = QUIC role
    let client_mapper = StreamDirectionMapper::new(EndpointRole::Client, EndpointRole::Client);
    let server_mapper = StreamDirectionMapper::new(EndpointRole::Server, EndpointRole::Server);

    assert!(!client_mapper.is_inverted(), "Client should not be inverted in normal mode");
    assert!(!server_mapper.is_inverted(), "Server should not be inverted in normal mode");

    let channel_id = ChannelId::client(0);

    // Client opens ChannelIn, server accepts it
    test_channel_in_flow(&client_conn, &server_conn, &client_mapper, channel_id)
        .await
        .expect("Normal mode: client should open ChannelIn successfully");
}

#[tokio::test]
async fn normal_mode_server_opens_channel_out() {
    let (client_conn, server_conn) = TestConnection::pair();

    // Normal mode: logical role = QUIC role
    let _client_mapper = StreamDirectionMapper::new(EndpointRole::Client, EndpointRole::Client);
    let server_mapper = StreamDirectionMapper::new(EndpointRole::Server, EndpointRole::Server);

    let channel_id = ChannelId::server(0);

    // Server opens ChannelOut, client accepts it
    test_channel_out_flow(&server_conn, &client_conn, &server_mapper, channel_id)
        .await
        .expect("Normal mode: server should open ChannelOut successfully");
}

#[tokio::test]
async fn normal_mode_bidirectional_data_exchange() {
    let (client_conn, server_conn) = TestConnection::pair();

    let client_mapper = StreamDirectionMapper::new(EndpointRole::Client, EndpointRole::Client);
    let server_mapper = StreamDirectionMapper::new(EndpointRole::Server, EndpointRole::Server);

    let channel_id = ChannelId::client(1);

    // Test both directions work
    test_channel_in_flow(&client_conn, &server_conn, &client_mapper, channel_id)
        .await
        .expect("Client should open ChannelIn");

    test_channel_out_flow(&server_conn, &client_conn, &server_mapper, channel_id)
        .await
        .expect("Server should open ChannelOut");
}

// =============================================================================
// Reverse Mode Tests (reverse-attach)
// =============================================================================

/// Test reverse mode: logical client = QUIC server, logical server = QUIC client.
///
/// This happens in reverse-attach where:
/// - The logical server (e.g., qsh-server with --connect-mode initiate) connects to bootstrap
/// - The logical client (e.g., qsh with --bootstrap) listens and accepts the connection
///
/// In this mode:
/// - Logical client (QUIC server) opens ChannelIn (server-initiated uni streams)
/// - Logical server (QUIC client) opens ChannelOut (client-initiated uni streams)
#[tokio::test]
async fn reverse_mode_logical_client_opens_channel_in() {
    let (quic_client_conn, quic_server_conn) = TestConnection::pair();

    // Reverse mode: logical roles are inverted relative to QUIC roles
    // quic_client is the logical server (server that initiated connection)
    // quic_server is the logical client (bootstrap listener)
    let logical_client_mapper = StreamDirectionMapper::new(EndpointRole::Client, EndpointRole::Server);
    let logical_server_mapper = StreamDirectionMapper::new(EndpointRole::Server, EndpointRole::Client);

    assert!(logical_client_mapper.is_inverted(), "Logical client should be inverted in reverse mode");
    assert!(logical_server_mapper.is_inverted(), "Logical server should be inverted in reverse mode");

    let channel_id = ChannelId::client(0);

    // Logical client (QUIC server) opens ChannelIn
    // Logical server (QUIC client) accepts it
    test_channel_in_flow(&quic_server_conn, &quic_client_conn, &logical_client_mapper, channel_id)
        .await
        .expect("Reverse mode: logical client should open ChannelIn successfully");
}

#[tokio::test]
async fn reverse_mode_logical_server_opens_channel_out() {
    let (quic_client_conn, quic_server_conn) = TestConnection::pair();

    // Reverse mode: logical roles are inverted
    let _logical_client_mapper = StreamDirectionMapper::new(EndpointRole::Client, EndpointRole::Server);
    let logical_server_mapper = StreamDirectionMapper::new(EndpointRole::Server, EndpointRole::Client);

    let channel_id = ChannelId::server(0);

    // Logical server (QUIC client) opens ChannelOut
    // Logical client (QUIC server) accepts it
    test_channel_out_flow(&quic_client_conn, &quic_server_conn, &logical_server_mapper, channel_id)
        .await
        .expect("Reverse mode: logical server should open ChannelOut successfully");
}

#[tokio::test]
async fn reverse_mode_bidirectional_data_exchange() {
    let (quic_client_conn, quic_server_conn) = TestConnection::pair();

    let logical_client_mapper = StreamDirectionMapper::new(EndpointRole::Client, EndpointRole::Server);
    let logical_server_mapper = StreamDirectionMapper::new(EndpointRole::Server, EndpointRole::Client);

    let channel_id = ChannelId::client(2);

    // Test both directions work in reverse mode
    test_channel_in_flow(&quic_server_conn, &quic_client_conn, &logical_client_mapper, channel_id)
        .await
        .expect("Logical client should open ChannelIn");

    test_channel_out_flow(&quic_client_conn, &quic_server_conn, &logical_server_mapper, channel_id)
        .await
        .expect("Logical server should open ChannelOut");
}

// =============================================================================
// Bidirectional initiator tests
// =============================================================================

/// Verify that server-initiated bidirectional channels work (e.g., forwarded-tcpip)
/// and are routed as ChannelBidi when the ChannelId is server-side.
#[tokio::test]
async fn server_initiates_bidi_channel() {
    let (quic_client_conn, quic_server_conn) = TestConnection::pair();

    // Logical server is QUIC client in reverse mode
    let logical_server_mapper = StreamDirectionMapper::new(EndpointRole::Server, EndpointRole::Client);

    // Use a server-side channel id to mirror server-initiated forwards
    let channel_id = ChannelId::server(7);

    // Logical server (QUIC client) opens ChannelBidi
    let opener_task = quic_client_conn.open_stream(StreamType::ChannelBidi(channel_id));

    // Logical client (QUIC server) accepts it
    let acceptor_task = quic_server_conn.accept_stream();

    let timeout_duration = Duration::from_secs(1);

    let (opener_result, acceptor_result) = tokio::join!(
        timeout(timeout_duration, opener_task),
        timeout(timeout_duration, acceptor_task)
    );

    let mut opener_stream = opener_result
        .map_err(|_| Error::Timeout)?
        .map_err(|e| Error::Protocol { message: format!("Opener failed: {:?}", e) })?;

    let (stream_type, mut acceptor_stream) = acceptor_result
        .map_err(|_| Error::Timeout)?
        .map_err(|e| Error::Protocol { message: format!("Acceptor failed: {:?}", e) })?;

    assert_eq!(stream_type, StreamType::ChannelBidi(channel_id), "Acceptor should see ChannelBidi");

    // Round-trip a message to prove directionality works
    let test_msg = Message::Resize(ResizePayload {
        channel_id: Some(channel_id),
        cols: 200,
        rows: 60,
    });

    opener_stream.send(&test_msg).await?;
    let received_msg = acceptor_stream.recv().await?;
    assert_eq!(received_msg, test_msg, "Message should roundtrip on server-initiated bidi");
}

// =============================================================================
// Control Stream Tests
// =============================================================================

/// Test that control stream is always QUIC client-initiated, regardless of logical roles.
#[tokio::test]
async fn control_stream_always_quic_client_initiated() {
    // Normal mode
    let normal_client_mapper = StreamDirectionMapper::new(EndpointRole::Client, EndpointRole::Client);
    let normal_server_mapper = StreamDirectionMapper::new(EndpointRole::Server, EndpointRole::Server);

    assert!(
        normal_client_mapper.should_initiate_stream(StreamType::Control),
        "Normal mode: QUIC client should initiate control stream"
    );
    assert!(
        !normal_server_mapper.should_initiate_stream(StreamType::Control),
        "Normal mode: QUIC server should not initiate control stream"
    );

    // Reverse mode
    let reverse_logical_client_mapper = StreamDirectionMapper::new(EndpointRole::Client, EndpointRole::Server);
    let reverse_logical_server_mapper = StreamDirectionMapper::new(EndpointRole::Server, EndpointRole::Client);

    assert!(
        !reverse_logical_client_mapper.should_initiate_stream(StreamType::Control),
        "Reverse mode: logical client (QUIC server) should not initiate control stream"
    );
    assert!(
        reverse_logical_server_mapper.should_initiate_stream(StreamType::Control),
        "Reverse mode: logical server (QUIC client) should initiate control stream"
    );
}

// =============================================================================
// Stream ID Pattern Tests
// =============================================================================

/// Test that stream ID patterns are correctly determined in normal mode.
#[tokio::test]
async fn normal_mode_stream_id_patterns() {
    let client_mapper = StreamDirectionMapper::new(EndpointRole::Client, EndpointRole::Client);
    let server_mapper = StreamDirectionMapper::new(EndpointRole::Server, EndpointRole::Server);

    let ch = ChannelId::client(0);

    // Client perspective
    let (client_init, uni) = client_mapper.stream_id_pattern(StreamType::ChannelIn(ch));
    assert!(client_init, "ChannelIn should be client-initiated in normal mode");
    assert!(uni, "ChannelIn should be unidirectional");

    let (client_init, uni) = client_mapper.stream_id_pattern(StreamType::ChannelOut(ch));
    assert!(!client_init, "ChannelOut should be server-initiated in normal mode");
    assert!(uni, "ChannelOut should be unidirectional");

    // Server perspective
    let (client_init, uni) = server_mapper.stream_id_pattern(StreamType::ChannelIn(ch));
    assert!(client_init, "ChannelIn should be client-initiated from server perspective");
    assert!(uni, "ChannelIn should be unidirectional");

    let (client_init, uni) = server_mapper.stream_id_pattern(StreamType::ChannelOut(ch));
    assert!(!client_init, "ChannelOut should be server-initiated from server perspective");
    assert!(uni, "ChannelOut should be unidirectional");
}

/// Test that stream ID patterns are correctly inverted in reverse mode.
#[tokio::test]
async fn reverse_mode_stream_id_patterns() {
    let logical_client_mapper = StreamDirectionMapper::new(EndpointRole::Client, EndpointRole::Server);
    let logical_server_mapper = StreamDirectionMapper::new(EndpointRole::Server, EndpointRole::Client);

    let ch = ChannelId::client(0);

    // Logical client (QUIC server) perspective
    let (client_init, uni) = logical_client_mapper.stream_id_pattern(StreamType::ChannelIn(ch));
    assert!(!client_init, "ChannelIn should be server-initiated in reverse mode (inverted)");
    assert!(uni, "ChannelIn should be unidirectional");

    let (client_init, uni) = logical_client_mapper.stream_id_pattern(StreamType::ChannelOut(ch));
    assert!(client_init, "ChannelOut should be client-initiated in reverse mode (inverted)");
    assert!(uni, "ChannelOut should be unidirectional");

    // Logical server (QUIC client) perspective
    let (client_init, uni) = logical_server_mapper.stream_id_pattern(StreamType::ChannelIn(ch));
    assert!(!client_init, "ChannelIn should be server-initiated from logical server perspective");
    assert!(uni, "ChannelIn should be unidirectional");

    let (client_init, uni) = logical_server_mapper.stream_id_pattern(StreamType::ChannelOut(ch));
    assert!(client_init, "ChannelOut should be client-initiated from logical server perspective");
    assert!(uni, "ChannelOut should be unidirectional");
}

// =============================================================================
// Multiple Channels Test
// =============================================================================

/// Test opening multiple channels in both normal and reverse modes.
#[tokio::test]
async fn multiple_channels_normal_mode() {
    let (client_conn, server_conn) = TestConnection::pair();

    let client_mapper = StreamDirectionMapper::new(EndpointRole::Client, EndpointRole::Client);
    let server_mapper = StreamDirectionMapper::new(EndpointRole::Server, EndpointRole::Server);

    // Open multiple ChannelIn streams from client
    for i in 0..3 {
        let channel_id = ChannelId::client(i);
        test_channel_in_flow(&client_conn, &server_conn, &client_mapper, channel_id)
            .await
            .expect(&format!("Client should open ChannelIn {}", i));
    }

    // Open multiple ChannelOut streams from server
    for i in 0..3 {
        let channel_id = ChannelId::server(i);
        test_channel_out_flow(&server_conn, &client_conn, &server_mapper, channel_id)
            .await
            .expect(&format!("Server should open ChannelOut {}", i));
    }
}

#[tokio::test]
async fn multiple_channels_reverse_mode() {
    let (quic_client_conn, quic_server_conn) = TestConnection::pair();

    let logical_client_mapper = StreamDirectionMapper::new(EndpointRole::Client, EndpointRole::Server);
    let logical_server_mapper = StreamDirectionMapper::new(EndpointRole::Server, EndpointRole::Client);

    // Open multiple ChannelIn streams from logical client (QUIC server)
    for i in 0..3 {
        let channel_id = ChannelId::client(i);
        test_channel_in_flow(&quic_server_conn, &quic_client_conn, &logical_client_mapper, channel_id)
            .await
            .expect(&format!("Logical client should open ChannelIn {}", i));
    }

    // Open multiple ChannelOut streams from logical server (QUIC client)
    for i in 0..3 {
        let channel_id = ChannelId::server(i);
        test_channel_out_flow(&quic_client_conn, &quic_server_conn, &logical_server_mapper, channel_id)
            .await
            .expect(&format!("Logical server should open ChannelOut {}", i));
    }
}

// =============================================================================
// Role Verification Tests
// =============================================================================

/// Verify that all four role combinations work correctly.
#[tokio::test]
async fn all_role_combinations_work() {
    let combinations = [
        (EndpointRole::Client, EndpointRole::Client, "normal-client"),
        (EndpointRole::Server, EndpointRole::Server, "normal-server"),
        (EndpointRole::Client, EndpointRole::Server, "reverse-logical-client"),
        (EndpointRole::Server, EndpointRole::Client, "reverse-logical-server"),
    ];

    for (logical_role, quic_role, name) in combinations {
        let mapper = StreamDirectionMapper::new(logical_role, quic_role);

        // Verify basic properties
        assert_eq!(mapper.logical_role(), logical_role, "{}: logical role mismatch", name);
        assert_eq!(mapper.quic_role(), quic_role, "{}: QUIC role mismatch", name);

        let expected_inverted = logical_role != quic_role;
        assert_eq!(
            mapper.is_inverted(),
            expected_inverted,
            "{}: inversion mismatch",
            name
        );

        // Verify control stream initiation
        let should_init_control = mapper.should_initiate_stream(StreamType::Control);
        let expected_control = quic_role == EndpointRole::Client;
        assert_eq!(
            should_init_control,
            expected_control,
            "{}: control stream initiation mismatch",
            name
        );

        println!(
            "✓ Validated {}: logical={:?}, quic={:?}, inverted={}",
            name,
            logical_role,
            quic_role,
            mapper.is_inverted()
        );
    }
}
