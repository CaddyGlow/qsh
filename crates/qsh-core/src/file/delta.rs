//! Delta sync algorithm for efficient file transfer.
//!
//! This implements an rsync-style delta algorithm:
//! 1. Receiver computes block checksums for existing file
//! 2. Sender scans new file for matching blocks using rolling checksum
//! 3. Sender outputs instructions: either block references or literal data
//!
//! The result is a stream of DeltaOps that can reconstruct the new file
//! from the old file plus the literal data.

use std::collections::HashMap;

use super::checksum::{BlockHasher, RollingChecksum};
use crate::error::{Error, Result};
use crate::protocol::BlockChecksum;

/// A delta operation - either copy from source or insert literal data.
#[derive(Debug, Clone, PartialEq)]
pub enum DeltaOp {
    /// Copy a block from the source file at the given offset.
    Copy {
        /// Offset in the source file.
        source_offset: u64,
        /// Length to copy.
        length: u64,
    },
    /// Insert literal data.
    Literal {
        /// The literal data to insert.
        data: Vec<u8>,
    },
}

/// Delta signature: block checksums for a file.
#[derive(Debug, Clone)]
pub struct DeltaSignature {
    /// Block checksums indexed by weak checksum for fast lookup.
    blocks: HashMap<u32, Vec<(u64, u64)>>, // weak -> [(offset, strong), ...]
    /// Block size used.
    block_size: usize,
}

impl DeltaSignature {
    /// Create a new delta signature from block checksums.
    pub fn new(checksums: &[BlockChecksum], block_size: usize) -> Self {
        let mut blocks: HashMap<u32, Vec<(u64, u64)>> = HashMap::new();

        for checksum in checksums {
            blocks
                .entry(checksum.weak)
                .or_default()
                .push((checksum.offset, checksum.strong));
        }

        Self { blocks, block_size }
    }

    /// Create a signature from file data.
    pub fn from_data(data: &[u8], block_size: usize) -> Self {
        let hasher = BlockHasher::new(block_size);
        let checksums = hasher.compute_checksums(data);
        Self::new(&checksums, block_size)
    }

    /// Check if a weak checksum exists in the signature.
    pub fn has_weak(&self, weak: u32) -> bool {
        self.blocks.contains_key(&weak)
    }

    /// Find a matching block by weak and strong checksums.
    pub fn find_match(&self, weak: u32, strong: u64) -> Option<u64> {
        self.blocks.get(&weak).and_then(|candidates| {
            candidates
                .iter()
                .find(|(_, s)| *s == strong)
                .map(|(offset, _)| *offset)
        })
    }

    /// Get the block size.
    pub fn block_size(&self) -> usize {
        self.block_size
    }
}

/// Delta encoder: computes delta operations from source signature and new data.
#[derive(Debug)]
pub struct DeltaEncoder {
    signature: DeltaSignature,
    rolling: RollingChecksum,
    pending_literal: Vec<u8>,
    ops: Vec<DeltaOp>,
}

impl DeltaEncoder {
    /// Create a new delta encoder.
    pub fn new(signature: DeltaSignature) -> Self {
        let block_size = signature.block_size();
        Self {
            signature,
            rolling: RollingChecksum::new(block_size),
            pending_literal: Vec::new(),
            ops: Vec::new(),
        }
    }

    /// Process input data and generate delta operations.
    pub fn process(&mut self, data: &[u8]) -> Vec<DeltaOp> {
        if data.is_empty() {
            return self.finish();
        }

        let block_size = self.signature.block_size();
        let mut pos = 0;

        while pos < data.len() {
            // Feed byte into rolling checksum
            self.rolling.roll(data[pos]);
            self.pending_literal.push(data[pos]);
            pos += 1;

            // Only check for matches when we have a full block
            if !self.rolling.is_full() {
                continue;
            }

            let weak = self.rolling.checksum();

            // Quick check: does this weak checksum exist?
            if !self.signature.has_weak(weak) {
                continue;
            }

            // Compute strong checksum and look for match
            let window_start = self.pending_literal.len().saturating_sub(block_size);
            let window = &self.pending_literal[window_start..];
            let strong = BlockHasher::compute_strong(window);

            if let Some(source_offset) = self.signature.find_match(weak, strong) {
                // Found a match! Emit any pending literal data (before this block)
                let literal_len = self.pending_literal.len() - block_size;
                if literal_len > 0 {
                    let literal: Vec<u8> = self.pending_literal.drain(..literal_len).collect();
                    self.ops.push(DeltaOp::Literal { data: literal });
                }

                // Emit copy operation
                self.ops.push(DeltaOp::Copy {
                    source_offset,
                    length: block_size as u64,
                });

                // Clear the matched block from pending
                self.pending_literal.clear();
                self.rolling.reset();
            }
        }

        // Don't finish yet - caller may have more data
        Vec::new()
    }

    /// Finish processing and return all remaining delta operations.
    pub fn finish(&mut self) -> Vec<DeltaOp> {
        // Emit any remaining literal data
        if !self.pending_literal.is_empty() {
            let literal = std::mem::take(&mut self.pending_literal);
            self.ops.push(DeltaOp::Literal { data: literal });
        }

        std::mem::take(&mut self.ops)
    }

    /// Take any operations generated so far (without finishing).
    pub fn take_ops(&mut self) -> Vec<DeltaOp> {
        std::mem::take(&mut self.ops)
    }

    /// Process all data and return delta operations.
    pub fn encode(signature: DeltaSignature, data: &[u8]) -> Vec<DeltaOp> {
        let mut encoder = Self::new(signature);
        encoder.process(data);
        encoder.finish()
    }
}

/// Delta decoder: applies delta operations to reconstruct a file.
#[derive(Debug)]
pub struct DeltaDecoder<'a> {
    source: &'a [u8],
}

impl<'a> DeltaDecoder<'a> {
    /// Create a new delta decoder with the source file data.
    pub fn new(source: &'a [u8]) -> Self {
        Self { source }
    }

    /// Apply delta operations and return the reconstructed data.
    pub fn decode(&self, ops: &[DeltaOp]) -> Result<Vec<u8>> {
        let mut output = Vec::new();

        for op in ops {
            match op {
                DeltaOp::Copy {
                    source_offset,
                    length,
                } => {
                    let start = *source_offset as usize;
                    let end = start + *length as usize;

                    if end > self.source.len() {
                        return Err(Error::FileTransfer {
                            message: format!(
                                "delta copy out of bounds: offset {} length {} source len {}",
                                source_offset,
                                length,
                                self.source.len()
                            ),
                        });
                    }

                    output.extend_from_slice(&self.source[start..end]);
                }
                DeltaOp::Literal { data } => {
                    output.extend_from_slice(data);
                }
            }
        }

        Ok(output)
    }
}

/// Compute delta operations between two byte slices.
pub fn compute_delta(old_data: &[u8], new_data: &[u8], block_size: usize) -> Vec<DeltaOp> {
    let signature = DeltaSignature::from_data(old_data, block_size);
    DeltaEncoder::encode(signature, new_data)
}

/// Apply delta operations to source data.
pub fn apply_delta(source: &[u8], ops: &[DeltaOp]) -> Result<Vec<u8>> {
    DeltaDecoder::new(source).decode(ops)
}

/// Calculate the efficiency of a delta encoding.
///
/// Returns the ratio of bytes saved (0.0 = no savings, 1.0 = 100% savings).
pub fn delta_efficiency(_old_len: usize, new_len: usize, ops: &[DeltaOp]) -> f64 {
    let literal_bytes: usize = ops
        .iter()
        .filter_map(|op| match op {
            DeltaOp::Literal { data } => Some(data.len()),
            _ => None,
        })
        .sum();

    // Overhead: assume ~16 bytes per Copy op for serialization
    let copy_ops = ops
        .iter()
        .filter(|op| matches!(op, DeltaOp::Copy { .. }))
        .count();
    let overhead = copy_ops * 16;

    let transfer_bytes = literal_bytes + overhead;
    let baseline = new_len.max(1);

    1.0 - (transfer_bytes as f64 / baseline as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delta_identical_files() {
        // Use data that's a multiple of block size for clean matching
        let data = b"AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH"; // 32 bytes, 4 blocks of 8
        let ops = compute_delta(data, data, 8);

        // Should be mostly Copy operations
        let copy_count = ops
            .iter()
            .filter(|op| matches!(op, DeltaOp::Copy { .. }))
            .count();
        assert!(copy_count >= 3); // At least 3 of 4 blocks should match

        // Reconstruct and verify
        let reconstructed = apply_delta(data, &ops).unwrap();
        assert_eq!(reconstructed, data);
    }

    #[test]
    fn test_delta_completely_different() {
        let old = b"aaaaaaaaaaaaaaaa";
        let new = b"bbbbbbbbbbbbbbbb";
        let ops = compute_delta(old, new, 8);

        // Should be all Literal operations
        assert!(ops.iter().all(|op| matches!(op, DeltaOp::Literal { .. })));

        // Reconstruct and verify
        let reconstructed = apply_delta(old, &ops).unwrap();
        assert_eq!(reconstructed, new);
    }

    #[test]
    fn test_delta_partial_overlap() {
        let old = b"AAAABBBBCCCCDDDD";
        let new = b"XXXXBBBBCCCCYYYY";
        let ops = compute_delta(old, new, 4);

        // Should have mix of Copy and Literal
        let has_copy = ops.iter().any(|op| matches!(op, DeltaOp::Copy { .. }));
        let has_literal = ops.iter().any(|op| matches!(op, DeltaOp::Literal { .. }));
        assert!(has_copy);
        assert!(has_literal);

        // Reconstruct and verify
        let reconstructed = apply_delta(old, &ops).unwrap();
        assert_eq!(reconstructed, new);
    }

    #[test]
    fn test_delta_empty_new() {
        let old = b"some data";
        let new = b"";
        let ops = compute_delta(old, new, 4);

        // Empty result
        assert!(ops.is_empty());

        let reconstructed = apply_delta(old, &ops).unwrap();
        assert_eq!(reconstructed, new);
    }

    #[test]
    fn test_delta_empty_old() {
        let old = b"";
        let new = b"new data";
        let ops = compute_delta(old, new, 4);

        // Should be all Literal
        assert!(ops.iter().all(|op| matches!(op, DeltaOp::Literal { .. })));

        let reconstructed = apply_delta(old, &ops).unwrap();
        assert_eq!(reconstructed, new);
    }

    #[test]
    fn test_delta_signature_lookup() {
        let data = b"AAAABBBBCCCCDDDD";
        let sig = DeltaSignature::from_data(data, 4);

        // Should find blocks
        let weak_aaaa = BlockHasher::compute_weak(b"AAAA");
        let strong_aaaa = BlockHasher::compute_strong(b"AAAA");
        assert!(sig.has_weak(weak_aaaa));
        assert_eq!(sig.find_match(weak_aaaa, strong_aaaa), Some(0));

        let weak_bbbb = BlockHasher::compute_weak(b"BBBB");
        let strong_bbbb = BlockHasher::compute_strong(b"BBBB");
        assert!(sig.has_weak(weak_bbbb));
        assert_eq!(sig.find_match(weak_bbbb, strong_bbbb), Some(4));
    }

    #[test]
    fn test_delta_efficiency() {
        // All copies = high efficiency
        let ops_copy = vec![DeltaOp::Copy {
            source_offset: 0,
            length: 1000,
        }];
        let eff_copy = delta_efficiency(1000, 1000, &ops_copy);
        assert!(eff_copy > 0.9); // Should be close to 1.0

        // All literal = no efficiency
        let ops_literal = vec![DeltaOp::Literal {
            data: vec![0; 1000],
        }];
        let eff_literal = delta_efficiency(1000, 1000, &ops_literal);
        assert!(eff_literal < 0.1); // Should be close to 0.0
    }

    #[test]
    fn test_delta_large_file() {
        // Create a larger test with repeated patterns
        // Each block is 8 chars: "block000" to "block099"
        let mut old = Vec::new();
        for i in 0..100 {
            old.extend_from_slice(format!("blk{:05}", i).as_bytes()); // 8 bytes each
        }
        // Total: 100 * 8 = 800 bytes

        // Modify some blocks (first and 50th)
        let mut new = old.clone();
        new[0..8].copy_from_slice(b"MODIFIED");
        new[400..408].copy_from_slice(b"CHANGED!");

        let ops = compute_delta(&old, &new, 8);

        // Should have mostly copies (we only changed 2 of 100 blocks)
        let copy_count = ops
            .iter()
            .filter(|op| matches!(op, DeltaOp::Copy { .. }))
            .count();
        assert!(copy_count >= 50); // At least half should be copies

        // Reconstruct and verify
        let reconstructed = apply_delta(&old, &ops).unwrap();
        assert_eq!(reconstructed, new);
    }

    #[test]
    fn test_decoder_out_of_bounds() {
        let source = b"short";
        let ops = vec![DeltaOp::Copy {
            source_offset: 0,
            length: 100, // Too long!
        }];

        let result = apply_delta(source, &ops);
        assert!(result.is_err());
    }
}
