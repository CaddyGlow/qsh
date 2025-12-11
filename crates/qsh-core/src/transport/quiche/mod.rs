//! QUIC transport implementation using tokio-quiche.
//!
//! This module provides concrete implementations of the Connection and StreamPair traits
//! using Cloudflare's tokio-quiche for faster network error detection via connected UDP
//! sockets with IP_RECVERR.

// Import common utilities from parent module
use super::common;

// Sub-modules
mod client;
mod config;
mod connection;
mod sender;
mod server;
mod stream;

// Re-export public types
pub use client::connect_quic;
pub use config::{build_config, client_config, server_config, server_config_with_ticket_key};
pub use connection::{QuicheConnection, QuicheConnectionInner};
pub use sender::QuicheSender;
pub use server::QuicheAcceptor;
pub use stream::{QuicheStream, QuicheStreamReader, QuicheStreamWriter};

// Re-export common utilities for convenience
pub use common::{
    CHANNEL_BIDI_MAGIC, CHANNEL_STREAM_MAGIC, cert_hash, channel_bidi_header,
    channel_stream_header, classify_io_error, enable_error_queue, generate_self_signed_cert,
    load_certs_from_pem, load_key_from_pem,
};
