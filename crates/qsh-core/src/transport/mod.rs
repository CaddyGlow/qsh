//! Transport abstractions for qsh.
//!
//! This module provides traits for abstracting over different transport layers:
//! - Real QUIC (tokio-quiche)
//! - Mock transport for testing
//!
//! Stream types (SSH-style channel model):
//! - Control: bidirectional stream ID 0 (Hello, ChannelOpen/Accept/Reject/Close, etc.)
//! - ChannelIn(id): unidirectional client->server (terminal input, file data)
//! - ChannelOut(id): unidirectional server->client (terminal output, file data)
//! - ChannelBidi(id): bidirectional (port forwards, tunnel)

mod quiche;

pub use quiche::{
    QuicheConnection, QuicheSender, QuicheStream,
    classify_io_error, enable_error_queue,
    client_config, server_config, server_config_with_ticket_key, generate_self_signed_cert,
    load_certs_from_pem, load_key_from_pem, cert_hash,
};

// Re-export as Quinn-compatible names for easier migration
pub use quiche::QuicheConnection as QuicConnection;
pub use quiche::QuicheSender as QuicSender;
pub use quiche::QuicheStream as QuicStream;

use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use crate::error::Result;
use crate::protocol::Message;

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
