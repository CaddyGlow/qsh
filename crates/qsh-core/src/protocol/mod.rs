//! Protocol module for qsh wire format.
//!
//! This module provides:
//! - Message types and payloads
//! - Length-prefixed bincode codec
//! - Stream type mappings

mod channel;
mod codec;
mod control;
mod data;
mod lifecycle;
mod message;
mod params;
mod types;

#[cfg(test)]
mod proptest;

pub use channel::*;
pub use codec::{Codec, FRAME_HEADER_LEN};
pub use control::*;
pub use data::*;
pub use lifecycle::*;
pub use message::*;
pub use params::*;
