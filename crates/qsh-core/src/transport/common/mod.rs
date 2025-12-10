//! Common utilities shared between QUIC backend implementations.
//!
//! This module contains code that is identical across different QUIC backends
//! (quiche and s2n-quic), avoiding duplication.

pub mod cert;
pub mod error;
pub mod stream_header;

pub use cert::{cert_hash, generate_self_signed_cert, load_certs_from_pem, load_key_from_pem};
pub use error::{classify_io_error, enable_error_queue};
pub use stream_header::{
    channel_bidi_header, channel_stream_header, CHANNEL_BIDI_MAGIC, CHANNEL_STREAM_MAGIC,
};
