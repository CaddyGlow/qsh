//! QUIC transport implementation using s2n-quic.
//!
//! This module provides concrete implementations of the Connection and StreamPair traits
//! using AWS s2n-quic as an alternative to quiche.
//!
//! # Session Resumption / 0-RTT
//!
//! s2n-quic supports TLS session tickets for 0-RTT resumption. We capture the
//! ticket bytes via s2n-tls callbacks and reuse them on reconnect, following the
//! upstream resumption example. Application-level resumption (mosh-style) still
//! works the same way.

// Submodules
mod client;
mod config;
mod connection;
mod sender;
mod server;
mod stats;
mod stream;

// Re-exports
pub use client::connect_quic;
pub use config::{
    build_client_config, build_server_config, client_config, server_config,
    server_config_with_ticket_key,
};
pub use connection::S2nConnection;
pub use sender::S2nSender;
pub use server::S2nAcceptor;
pub use stats::{ConnectionStats, StatsSubscriber};
pub use stream::{S2nStream, S2nStreamReader, S2nStreamWriter};

// Import shared utilities from common module
use super::common;

// Re-export common utilities for convenience
pub use common::{
    cert_hash, generate_self_signed_cert, load_certs_from_pem, load_key_from_pem,
    classify_io_error, enable_error_queue,
    channel_stream_header, channel_bidi_header,
    CHANNEL_STREAM_MAGIC, CHANNEL_BIDI_MAGIC,
};

// Import parent traits
use super::{Connection, ConnectConfig, ConnectResult, ListenerConfig, StreamPair, StreamType};

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ChannelId;
    use super::common::{channel_bidi_header, channel_stream_header, CHANNEL_BIDI_MAGIC, CHANNEL_STREAM_MAGIC};

    #[test]
    fn channel_stream_header_roundtrip() {
        let id = ChannelId::client(42);
        let header = channel_stream_header(id);
        assert_eq!(header[0], CHANNEL_STREAM_MAGIC);

        let encoded = u64::from_le_bytes(header[1..9].try_into().unwrap());
        let decoded = ChannelId::decode(encoded);
        assert_eq!(id, decoded);
    }

    #[test]
    fn channel_bidi_header_roundtrip() {
        let id = ChannelId::server(123);
        let header = channel_bidi_header(id);
        assert_eq!(header[0], CHANNEL_BIDI_MAGIC);

        let encoded = u64::from_le_bytes(header[1..9].try_into().unwrap());
        let decoded = ChannelId::decode(encoded);
        assert_eq!(id, decoded);
    }

    #[test]
    fn classify_io_errors() {
        use super::common::classify_io_error;
        use crate::error::Error;

        // Test that we handle basic I/O errors
        let err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "test");
        let classified = classify_io_error(err);
        assert!(matches!(classified, Error::Io(_)));
    }

    #[test]
    fn cert_hash_sha256() {
        use super::common::cert_hash;

        let data = b"test certificate data";
        let hash = cert_hash(data);
        assert_eq!(hash.len(), 32); // SHA256 produces 32 bytes
    }

    #[test]
    fn generate_self_signed_cert_works() {
        use super::common::generate_self_signed_cert;

        let result = generate_self_signed_cert();
        assert!(result.is_ok(), "should generate self-signed cert");
        let (cert, key) = result.unwrap();
        assert!(!cert.is_empty());
        assert!(!key.is_empty());
    }
}
