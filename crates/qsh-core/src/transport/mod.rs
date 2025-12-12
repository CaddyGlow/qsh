//! Transport abstractions for qsh.
//!
//! This module provides traits for abstracting over different transport layers:
//! - Real QUIC via quiche (default) or s2n-quic
//! - Mock transport for testing
//!
//! Stream types (SSH-style channel model):
//! - Control: bidirectional stream ID 0 (Hello, ChannelOpen/Accept/Reject/Close, etc.)
//! - ChannelIn(id): unidirectional client->server (terminal input, file data)
//! - ChannelOut(id): unidirectional server->client (terminal output, file data)
//! - ChannelBidi(id): bidirectional (port forwards, tunnel)
//!
//! # Backend Selection
//!
//! The QUIC backend is selected via Cargo features:
//! - `quiche-backend` (default): Cloudflare's quiche/tokio-quiche
//! - `s2n-quic-backend`: AWS s2n-quic
//!
//! Only one backend should be enabled at a time.

// Compile-time check: only one backend can be enabled
#[cfg(all(feature = "quiche-backend", feature = "s2n-quic-backend"))]
compile_error!(
    "Only one QUIC backend can be enabled at a time. Enable either `quiche-backend` or `s2n-quic-backend`, not both."
);

pub mod common;
pub mod config;
pub mod sender;
pub mod stream_mapper;

// Re-export sender types
pub use sender::{SenderConfig, TransportSender};
pub use stream_mapper::StreamDirectionMapper;

#[cfg(feature = "quiche-backend")]
mod quiche;

#[cfg(feature = "s2n-quic-backend")]
mod s2n;

// Re-export config types
pub use config::{EndpointRole, TlsCredentials, TransportConfigBuilder};

// =============================================================================
// Feature-gated Backend Exports
// =============================================================================

// quiche backend exports (default)
#[cfg(feature = "quiche-backend")]
pub use quiche::{
    QuicheConnection, QuicheSender, QuicheStream, QuicheStreamReader, QuicheStreamWriter,
    build_config, cert_hash, classify_io_error, client_config, enable_error_queue,
    generate_self_signed_cert, load_certs_from_pem, load_key_from_pem, server_config,
    server_config_with_ticket_key,
};

// Re-export with generic names for backend-agnostic code (quiche)
#[cfg(feature = "quiche-backend")]
pub use quiche::QuicheConnection as QuicConnection;
#[cfg(feature = "quiche-backend")]
pub use quiche::QuicheSender as QuicSender;
#[cfg(feature = "quiche-backend")]
pub use quiche::QuicheStream as QuicStream;

// s2n-quic backend exports (alternative)
#[cfg(feature = "s2n-quic-backend")]
pub use s2n::{
    S2nConnection, S2nSender, S2nStream, S2nStreamReader, S2nStreamWriter, build_client_config,
    build_server_config, cert_hash, classify_io_error, client_config, enable_error_queue,
    generate_self_signed_cert, load_certs_from_pem, load_key_from_pem, server_config,
    server_config_with_ticket_key,
};

// Re-export with generic names for backend-agnostic code (s2n-quic)
#[cfg(feature = "s2n-quic-backend")]
pub use s2n::S2nConnection as QuicConnection;
#[cfg(feature = "s2n-quic-backend")]
pub use s2n::S2nSender as QuicSender;
#[cfg(feature = "s2n-quic-backend")]
pub use s2n::S2nStream as QuicStream;

use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use crate::error::Result;
use crate::protocol::Message;

// =============================================================================
// Connection Configuration Types
// =============================================================================

/// Configuration for establishing a QUIC client connection.
///
/// This is backend-agnostic configuration that gets translated to
/// quiche::Config or s2n-quic providers internally.
#[derive(Debug, Clone)]
pub struct ConnectConfig {
    /// Server address to connect to.
    pub server_addr: SocketAddr,
    /// Optional local port to bind to (None = OS-assigned).
    pub local_port: Option<u16>,
    /// Maximum idle timeout for the connection.
    pub max_idle_timeout: Duration,
    /// Timeout for the initial connection handshake.
    pub connect_timeout: Duration,
    /// QUIC keep-alive interval (None disables).
    ///
    /// When enabled, the transport will send occasional ack-eliciting frames
    /// during idle periods to keep NAT mappings alive and avoid idle timeouts.
    pub keep_alive_interval: Option<Duration>,
    /// Expected certificate hash for pinning (None = no pinning, skip verification).
    pub cert_hash: Option<Vec<u8>>,
    /// Cached session data for 0-RTT resumption.
    pub session_data: Option<Vec<u8>>,
    /// Logical role for stream direction mapping.
    ///
    /// In normal mode, this should match the QUIC role (Client for connect_quic).
    /// In reverse-attach mode, this is inverted (Server for connect_quic when
    /// the logical server initiates the connection).
    pub logical_role: EndpointRole,
}

impl Default for ConnectConfig {
    fn default() -> Self {
        Self {
            server_addr: "127.0.0.1:4242".parse().unwrap(),
            local_port: None,
            max_idle_timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(10),
            keep_alive_interval: None,
            cert_hash: None,
            session_data: None,
            // Default to Client (normal mode: QUIC client = logical client)
            logical_role: EndpointRole::Client,
        }
    }
}

/// Result of a successful QUIC connection establishment.
///
/// Contains the connection and metadata about the handshake.
pub struct ConnectResult<C> {
    /// The established connection.
    pub connection: C,
    /// Whether the connection was resumed via 0-RTT.
    pub resumed: bool,
    /// Session data that can be cached for future 0-RTT resumption.
    pub session_data: Option<Vec<u8>>,
}

/// Configuration for a QUIC server listener.
#[derive(Debug, Clone)]
pub struct ListenerConfig {
    /// TLS certificate in PEM format.
    pub cert_pem: Vec<u8>,
    /// TLS private key in PEM format.
    pub key_pem: Vec<u8>,
    /// Maximum idle timeout for connections.
    pub idle_timeout: Duration,
    /// QUIC keep-alive interval for accepted connections (None disables).
    pub keep_alive_interval: Option<Duration>,
    /// Optional session ticket key for 0-RTT (None = auto-generated).
    pub ticket_key: Option<Vec<u8>>,
    /// Logical role for stream direction mapping.
    ///
    /// In normal mode, this should be Server (QUIC server = logical server).
    /// In reverse-attach mode, this is Client (QUIC server accepts connections
    /// from the logical server, but is itself the logical client).
    pub logical_role: EndpointRole,
}

// Feature-gated connect function exports
#[cfg(feature = "quiche-backend")]
pub use quiche::connect_quic;

#[cfg(feature = "s2n-quic-backend")]
pub use s2n::connect_quic;

// Feature-gated acceptor exports
#[cfg(feature = "quiche-backend")]
pub use quiche::QuicheAcceptor as QuicAcceptor;

#[cfg(feature = "s2n-quic-backend")]
pub use s2n::S2nAcceptor as QuicAcceptor;

// =============================================================================
// Stream Types
// =============================================================================

use crate::protocol::ChannelId;

/// Identifies the type/purpose of a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamType {
    /// Control stream (bidirectional, ID 0).
    /// Carries: Hello, HelloAck, GlobalRequest, GlobalReply,
    ///          ChannelOpen, ChannelAccept, ChannelReject, ChannelClose,
    ///          Resize, StateAck, Shutdown
    Control,

    /// Channel input stream (unidirectional client->server).
    /// Carries ChannelData with terminal input or file data.
    ChannelIn(ChannelId),

    /// Channel output stream (unidirectional server->client).
    /// Carries ChannelData with terminal output, state updates, or file data.
    ChannelOut(ChannelId),

    /// Bidirectional channel stream (for forwards, tunnel).
    /// Carries raw TCP bytes (forwards) or ChannelData with TunnelPacket (tunnel).
    ChannelBidi(ChannelId),
}

impl StreamType {
    /// Get the QUIC stream ID for this type (if fixed).
    /// Channel streams are dynamically allocated, so return None.
    pub fn fixed_id(&self) -> Option<u64> {
        match self {
            StreamType::Control => Some(0),
            StreamType::ChannelIn(_) | StreamType::ChannelOut(_) | StreamType::ChannelBidi(_) => {
                None
            }
        }
    }

    /// Check if this is a bidirectional stream type.
    pub fn is_bidirectional(&self) -> bool {
        matches!(self, StreamType::Control | StreamType::ChannelBidi(_))
    }

    /// Check if this is a unidirectional stream type.
    pub fn is_unidirectional(&self) -> bool {
        matches!(self, StreamType::ChannelIn(_) | StreamType::ChannelOut(_))
    }

    /// Get the channel ID for channel stream types.
    pub fn channel_id(&self) -> Option<ChannelId> {
        match self {
            StreamType::ChannelIn(id)
            | StreamType::ChannelOut(id)
            | StreamType::ChannelBidi(id) => Some(*id),
            StreamType::Control => None,
        }
    }
}

// =============================================================================
// Stream Pair Trait
// =============================================================================

/// A bidirectional stream for sending and receiving messages.
///
/// This trait abstracts over QUIC streams and mock channels for testing.
pub trait StreamPair: Send + Sync {
    /// Send a message on this stream.
    fn send(&mut self, msg: &Message) -> impl Future<Output = Result<()>> + Send;

    /// Receive a message from this stream.
    fn recv(&mut self) -> impl Future<Output = Result<Message>> + Send;

    /// Close the stream.
    fn close(&mut self);
}

// =============================================================================
// Connection Trait
// =============================================================================

/// A transport connection (QUIC connection abstraction).
///
/// Supports opening and accepting streams of various types.
pub trait Connection: Send + Sync {
    /// The stream type produced by this connection.
    type Stream: StreamPair;

    /// Open a new stream of the given type.
    fn open_stream(
        &self,
        stream_type: StreamType,
    ) -> impl Future<Output = Result<Self::Stream>> + Send;

    /// Accept an incoming stream.
    fn accept_stream(&self) -> impl Future<Output = Result<(StreamType, Self::Stream)>> + Send;

    /// Get the remote peer's address.
    fn remote_addr(&self) -> SocketAddr;

    /// Get the local address.
    fn local_addr(&self) -> SocketAddr;

    /// Check if the connection is still alive.
    fn is_connected(&self) -> bool;

    /// Get the current RTT estimate.
    fn rtt(&self) -> impl Future<Output = Duration> + Send;
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{ChannelId, ChannelSide};
    use std::collections::HashSet;

    #[test]
    fn channel_stream_type_equality_and_hashing() {
        let mut set = HashSet::new();

        set.insert(StreamType::Control);
        set.insert(StreamType::ChannelIn(ChannelId::client(0)));
        set.insert(StreamType::ChannelIn(ChannelId::client(1)));
        set.insert(StreamType::ChannelIn(ChannelId::server(0))); // Different side
        set.insert(StreamType::ChannelOut(ChannelId::client(0)));
        set.insert(StreamType::ChannelBidi(ChannelId::client(0)));
        set.insert(StreamType::ChannelIn(ChannelId::client(0))); // Duplicate

        assert_eq!(set.len(), 6);
    }

    #[test]
    fn channel_id_equality() {
        // Client(5) != Server(5)
        assert_ne!(ChannelId::client(5), ChannelId::server(5));

        // Same side, same id are equal
        assert_eq!(ChannelId::client(5), ChannelId::client(5));
        assert_eq!(ChannelId::server(5), ChannelId::server(5));

        // Different ids are not equal
        assert_ne!(ChannelId::client(0), ChannelId::client(1));
    }

    #[test]
    fn channel_id_encode_decode() {
        let test_cases = [
            ChannelId::client(0),
            ChannelId::client(1),
            ChannelId::client(u64::MAX >> 1),
            ChannelId::server(0),
            ChannelId::server(1),
            ChannelId::server(u64::MAX >> 1),
        ];

        for id in test_cases {
            let encoded = id.encode();
            let decoded = ChannelId::decode(encoded);
            assert_eq!(id, decoded, "encode/decode roundtrip failed for {:?}", id);
        }
    }

    #[test]
    fn channel_id_display() {
        assert_eq!(format!("{}", ChannelId::client(0)), "c0");
        assert_eq!(format!("{}", ChannelId::client(42)), "c42");
        assert_eq!(format!("{}", ChannelId::server(0)), "s0");
        assert_eq!(format!("{}", ChannelId::server(123)), "s123");
    }

    #[test]
    fn stream_type_channel_directionality() {
        let ch = ChannelId::client(0);

        assert!(StreamType::Control.is_bidirectional());
        assert!(StreamType::ChannelBidi(ch).is_bidirectional());

        assert!(StreamType::ChannelIn(ch).is_unidirectional());
        assert!(StreamType::ChannelOut(ch).is_unidirectional());

        assert!(!StreamType::Control.is_unidirectional());
        assert!(!StreamType::ChannelIn(ch).is_bidirectional());
    }

    #[test]
    fn stream_type_channel_id_extraction() {
        let ch = ChannelId::client(42);

        assert_eq!(StreamType::ChannelIn(ch).channel_id(), Some(ch));
        assert_eq!(StreamType::ChannelOut(ch).channel_id(), Some(ch));
        assert_eq!(StreamType::ChannelBidi(ch).channel_id(), Some(ch));
        assert_eq!(StreamType::Control.channel_id(), None);
    }

    #[test]
    fn trait_bounds_are_correct() {
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<StreamType>();
        assert_send_sync::<ChannelId>();
        assert_send_sync::<ChannelSide>();
    }
}
