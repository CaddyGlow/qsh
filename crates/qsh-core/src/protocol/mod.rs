//! Protocol module for qsh wire format.
//!
//! This module provides:
//! - Message types and payloads
//! - Length-prefixed bincode codec
//! - Stream type mappings

mod codec;
mod types;

#[cfg(test)]
mod proptest;

pub use codec::{Codec, FRAME_HEADER_LEN};
pub use types::*;
