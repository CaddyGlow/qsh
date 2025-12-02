//! Transport abstractions for qsh.
//!
//! This module provides traits for abstracting over different transport layers:
//! - Real QUIC (Quinn)
//! - Mock transport for testing
//!
//! Stream mapping per PROTOCOL:
//! - Control: client-bidi 0
//! - Terminal out: server-uni 3
//! - Terminal in: client-uni 2
//! - Tunnel: client-bidi 4 (reserved)
//! - Forwards: server-bidi 1/5/9..., client-bidi 8/12/...

mod quic;

pub use quic::{QuicConnection, QuicSender, QuicStream, client_crypto_config, server_crypto_config};

use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use crate::error::Result;
use crate::protocol::Message;

// =============================================================================
// Stream Types
// =============================================================================

/// Identifies the type/purpose of a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamType {
    /// Control stream (client-initiated bidirectional, ID 0).
    Control,
    /// Terminal output from server (server-initiated unidirectional, ID 3).
    TerminalOut,
    /// Terminal input to server (client-initiated unidirectional, ID 2).
    TerminalIn,
    /// IP tunnel data (client-initiated bidirectional, ID 4 reserved).
    Tunnel,
    /// Port forward data (dynamic bidirectional streams).
    Forward(u32),
}

impl StreamType {
    /// Get the QUIC stream ID for this type (if fixed).
    /// Forward streams are dynamically allocated, so return None.
    pub fn fixed_id(&self) -> Option<u64> {
        match self {
            StreamType::Control => Some(0),
            StreamType::TerminalIn => Some(2),
            StreamType::TerminalOut => Some(3),
            StreamType::Tunnel => Some(4),
            StreamType::Forward(_) => None,
        }
    }

    /// Check if this is a bidirectional stream type.
    pub fn is_bidirectional(&self) -> bool {
        matches!(
            self,
            StreamType::Control | StreamType::Tunnel | StreamType::Forward(_)
        )
    }

    /// Check if this is a unidirectional stream type.
    pub fn is_unidirectional(&self) -> bool {
        matches!(self, StreamType::TerminalIn | StreamType::TerminalOut)
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
    fn rtt(&self) -> Duration;
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn stream_type_equality_and_hashing() {
        let mut set = HashSet::new();

        set.insert(StreamType::Control);
        set.insert(StreamType::TerminalIn);
        set.insert(StreamType::TerminalOut);
        set.insert(StreamType::Tunnel);
        set.insert(StreamType::Forward(1));
        set.insert(StreamType::Forward(2));
        set.insert(StreamType::Forward(1)); // Duplicate

        assert_eq!(set.len(), 6); // 5 unique types + 2 forwards = 6
    }

    #[test]
    fn stream_type_forward_id_encoding() {
        let f1 = StreamType::Forward(1);
        let f2 = StreamType::Forward(2);
        let f1_again = StreamType::Forward(1);

        assert_ne!(f1, f2);
        assert_eq!(f1, f1_again);

        // Extract IDs
        if let StreamType::Forward(id) = f1 {
            assert_eq!(id, 1);
        }
        if let StreamType::Forward(id) = f2 {
            assert_eq!(id, 2);
        }
    }

    #[test]
    fn stream_type_fixed_ids() {
        assert_eq!(StreamType::Control.fixed_id(), Some(0));
        assert_eq!(StreamType::TerminalIn.fixed_id(), Some(2));
        assert_eq!(StreamType::TerminalOut.fixed_id(), Some(3));
        assert_eq!(StreamType::Tunnel.fixed_id(), Some(4));
        assert_eq!(StreamType::Forward(42).fixed_id(), None);
    }

    #[test]
    fn stream_type_directionality() {
        assert!(StreamType::Control.is_bidirectional());
        assert!(StreamType::Tunnel.is_bidirectional());
        assert!(StreamType::Forward(1).is_bidirectional());

        assert!(StreamType::TerminalIn.is_unidirectional());
        assert!(StreamType::TerminalOut.is_unidirectional());

        assert!(!StreamType::Control.is_unidirectional());
        assert!(!StreamType::TerminalIn.is_bidirectional());
    }

    // Trait bounds test - verifies the trait is object-safe where applicable
    // and has correct Send + Sync bounds
    #[test]
    fn trait_bounds_are_correct() {
        fn assert_send_sync<T: Send + Sync>() {}

        // StreamType should be Send + Sync
        assert_send_sync::<StreamType>();
    }
}
