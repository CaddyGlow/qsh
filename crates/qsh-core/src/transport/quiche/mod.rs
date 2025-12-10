//! QUIC transport implementation using tokio-quiche.
//!
//! This module provides concrete implementations of the Connection and StreamPair traits
//! using Cloudflare's tokio-quiche for faster network error detection via connected UDP
//! sockets with IP_RECVERR.

// Import common utilities from parent module
use super::common;

// Sub-modules
mod stream;
mod connection;
mod sender;
mod config;
mod client;
mod server;

// Re-export public types
pub use stream::{QuicheStream, QuicheStreamReader, QuicheStreamWriter};
pub use connection::{QuicheConnection, QuicheConnectionInner};
pub use sender::QuicheSender;
pub use config::{client_config, server_config, server_config_with_ticket_key, build_config};
pub use client::connect_quic;
pub use server::QuicheAcceptor;

// Re-export common utilities for convenience
pub use common::{
    cert_hash, generate_self_signed_cert, load_certs_from_pem, load_key_from_pem,
    classify_io_error, enable_error_queue,
    channel_stream_header, channel_bidi_header,
    CHANNEL_STREAM_MAGIC, CHANNEL_BIDI_MAGIC,
};
