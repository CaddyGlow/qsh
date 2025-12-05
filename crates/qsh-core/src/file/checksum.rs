//! Rolling checksum and block hashing for delta sync.
//!
//! Uses Adler-32 for weak (rolling) checksum and xxHash64 for strong checksum.

use xxhash_rust::xxh64::xxh64;

use super::BLOCK_SIZE;
use crate::protocol::BlockChecksum;

/// Rolling checksum using Adler-32 algorithm.
///
/// This allows efficient computation of checksums for sliding windows.
#[derive(Debug, Clone)]
pub struct RollingChecksum {
    a: u32,
    b: u32,
    window: Vec<u8>,
    pos: usize,
    full: bool,
    block_size: usize,
}

impl RollingChecksum {
    /// Create a new rolling checksum with the given block size.
    pub fn new(block_size: usize) -> Self {
        Self {
            a: 1,
            b: 0,
            window: vec![0; block_size],
            pos: 0,
            full: false,
            block_size,
        }
    }

    /// Create a new rolling checksum with the default block size.
    pub fn with_default_block_size() -> Self {
        Self::new(BLOCK_SIZE)
    }

    /// Reset the checksum state.
    pub fn reset(&mut self) {
        self.a = 1;
        self.b = 0;
        self.window.fill(0);
        self.pos = 0;
        self.full = false;
    }

    /// Add a byte to the window and update the checksum.
    ///
    /// If the window is full, the oldest byte is removed.
    pub fn roll(&mut self, new_byte: u8) {
        let old_byte = self.window[self.pos];

        // Update window
        self.window[self.pos] = new_byte;
        self.pos = (self.pos + 1) % self.block_size;

        if self.full {
            // Roll out the old byte, roll in the new byte
            self.a = self
                .a
                .wrapping_add(new_byte as u32)
                .wrapping_sub(old_byte as u32);
            self.b = self
                .b
                .wrapping_add(self.a)
                .wrapping_sub((self.block_size as u32).wrapping_mul(old_byte as u32))
                .wrapping_sub(1);
        } else {
            // Just add the new byte
            self.a = self.a.wrapping_add(new_byte as u32);
            self.b = self.b.wrapping_add(self.a);

            if self.pos == 0 {
                self.full = true;
            }
        }
    }

    /// Compute the checksum from a full block.
    ///
    /// This is more efficient than rolling byte-by-byte when computing
    /// the initial checksum.
    pub fn update_block(&mut self, data: &[u8]) {
        self.reset();
        for &byte in data.iter().take(self.block_size) {
            self.a = self.a.wrapping_add(byte as u32);
            self.b = self.b.wrapping_add(self.a);
        }
        if data.len() >= self.block_size {
            self.window.copy_from_slice(&data[..self.block_size]);
            self.full = true;
        } else {
            self.window[..data.len()].copy_from_slice(data);
            self.pos = data.len();
        }
    }

    /// Get the current checksum value.
    pub fn checksum(&self) -> u32 {
        (self.b << 16) | (self.a & 0xFFFF)
    }

    /// Check if the window is full.
    pub fn is_full(&self) -> bool {
        self.full
    }

    /// Get the current window contents.
    pub fn window(&self) -> &[u8] {
        &self.window
    }
}

/// Block hasher for computing strong checksums.
#[derive(Debug, Clone, Default)]
pub struct BlockHasher {
    block_size: usize,
}

impl BlockHasher {
    /// Create a new block hasher with the given block size.
    pub fn new(block_size: usize) -> Self {
        Self { block_size }
    }

    /// Create a new block hasher with the default block size.
    pub fn with_default_block_size() -> Self {
        Self::new(BLOCK_SIZE)
    }

    /// Compute block checksums for a file's contents.
    pub fn compute_checksums(&self, data: &[u8]) -> Vec<BlockChecksum> {
        let mut checksums = Vec::new();
        let mut offset = 0u64;

        for chunk in data.chunks(self.block_size) {
            let weak = Self::compute_weak(chunk);
            let strong = Self::compute_strong(chunk);

            checksums.push(BlockChecksum {
                offset,
                weak,
                strong,
            });

            offset += chunk.len() as u64;
        }

        checksums
    }

    /// Compute the weak (Adler-32) checksum for a block.
    pub fn compute_weak(data: &[u8]) -> u32 {
        let mut a: u32 = 1;
        let mut b: u32 = 0;

        for &byte in data {
            a = a.wrapping_add(byte as u32);
            b = b.wrapping_add(a);
        }

        (b << 16) | (a & 0xFFFF)
    }

    /// Compute the strong (xxHash64) checksum for a block.
    pub fn compute_strong(data: &[u8]) -> u64 {
        xxh64(data, 0)
    }
}

/// Compute xxHash64 for arbitrary data.
pub fn hash_xxh64(data: &[u8]) -> u64 {
    xxh64(data, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rolling_checksum_basic() {
        let mut rc = RollingChecksum::new(4);

        // Add bytes one at a time
        for b in b"abcd" {
            rc.roll(*b);
        }

        assert!(rc.is_full());
        let checksum1 = rc.checksum();

        // Roll in a new byte
        rc.roll(b'e');
        let checksum2 = rc.checksum();

        assert_ne!(checksum1, checksum2);

        // Verify against direct computation
        let mut rc2 = RollingChecksum::new(4);
        for b in b"bcde" {
            rc2.roll(*b);
        }
        assert_eq!(rc.checksum(), rc2.checksum());
    }

    #[test]
    fn test_rolling_checksum_update_block() {
        let mut rc = RollingChecksum::new(4);
        rc.update_block(b"abcd");

        let mut rc2 = RollingChecksum::new(4);
        for b in b"abcd" {
            rc2.roll(*b);
        }

        assert_eq!(rc.checksum(), rc2.checksum());
    }

    #[test]
    fn test_rolling_checksum_reset() {
        let mut rc = RollingChecksum::new(4);
        for b in b"abcd" {
            rc.roll(*b);
        }

        rc.reset();

        assert!(!rc.is_full());
        assert_eq!(rc.checksum(), (0 << 16) | 1); // Initial a=1, b=0
    }

    #[test]
    fn test_block_hasher_compute_checksums() {
        let hasher = BlockHasher::new(4);
        let data = b"abcdefgh";

        let checksums = hasher.compute_checksums(data);

        assert_eq!(checksums.len(), 2);
        assert_eq!(checksums[0].offset, 0);
        assert_eq!(checksums[1].offset, 4);
    }

    #[test]
    fn test_block_hasher_weak_checksum() {
        let weak1 = BlockHasher::compute_weak(b"abcd");
        let weak2 = BlockHasher::compute_weak(b"abcd");
        let weak3 = BlockHasher::compute_weak(b"efgh");

        assert_eq!(weak1, weak2);
        assert_ne!(weak1, weak3);
    }

    #[test]
    fn test_block_hasher_strong_checksum() {
        let strong1 = BlockHasher::compute_strong(b"abcd");
        let strong2 = BlockHasher::compute_strong(b"abcd");
        let strong3 = BlockHasher::compute_strong(b"efgh");

        assert_eq!(strong1, strong2);
        assert_ne!(strong1, strong3);
    }

    #[test]
    fn test_hash_xxh64() {
        let hash1 = hash_xxh64(b"hello world");
        let hash2 = hash_xxh64(b"hello world");
        let hash3 = hash_xxh64(b"goodbye world");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_rolling_matches_direct() {
        // Verify rolling checksum matches direct computation for various windows
        let data = b"the quick brown fox jumps over the lazy dog";
        let block_size = 8;

        for start in 0..data.len().saturating_sub(block_size) {
            let window = &data[start..start + block_size];

            // Direct computation
            let direct = BlockHasher::compute_weak(window);

            // Rolling computation
            let mut rc = RollingChecksum::new(block_size);
            rc.update_block(window);
            let rolling = rc.checksum();

            assert_eq!(
                direct, rolling,
                "Mismatch at offset {} for window {:?}",
                start, window
            );
        }
    }
}
