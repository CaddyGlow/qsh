//! File transfer support for qsh.
//!
//! This module provides:
//! - Rolling checksum for delta sync
//! - Delta encoding/decoding algorithm
//! - Compression utilities
//! - Transfer state types

pub mod checksum;
pub mod compress;
pub mod delta;
pub mod types;

pub use checksum::{BlockHasher, RollingChecksum, StreamingHasher, hash_xxh64};
pub use compress::{Compressor, Decompressor};
pub use delta::{DeltaDecoder, DeltaEncoder, DeltaOp, DeltaSignature, apply_delta, compute_delta};
pub use types::{TransferState, TransferStatus};

/// Default block size for delta sync (128 KB).
pub const BLOCK_SIZE: usize = 128 * 1024;

/// Minimum file size for chunked parallel transfer (1 MB).
pub const CHUNK_THRESHOLD: u64 = 1024 * 1024;

/// Default chunk size for parallel transfer (1 MB).
pub const CHUNK_SIZE: u64 = 1024 * 1024;

/// Maximum parallel chunks per file.
pub const MAX_CHUNKS_PER_FILE: usize = 4;

/// Maximum parallel file transfers.
pub const MAX_PARALLEL_FILES: usize = 4;
