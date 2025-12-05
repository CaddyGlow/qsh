//! Compression utilities for file transfer.
//!
//! Uses zstd for compression with a focus on streaming efficiency.
//! When the `compression` feature is disabled, provides passthrough stubs.

#[cfg(feature = "compression")]
use std::io::{Read, Write};

use crate::error::{Error, Result};

/// Default compression level (3 = fast with reasonable ratio).
pub const DEFAULT_COMPRESSION_LEVEL: i32 = 3;

/// File extensions that are already compressed (skip compression).
const COMPRESSED_EXTENSIONS: &[&str] = &[
    "gz", "zip", "bz2", "xz", "lz4", "zst", "7z", "rar", "jpg", "jpeg", "png", "gif", "webp",
    "mp3", "mp4", "mkv", "avi", "mov", "flac", "ogg", "opus", "pdf",
];

/// Compressor for file data.
#[derive(Debug)]
pub struct Compressor {
    #[cfg(feature = "compression")]
    level: i32,
}

impl Compressor {
    /// Create a new compressor with the given compression level.
    #[cfg(feature = "compression")]
    pub fn new(level: i32) -> Self {
        Self { level }
    }

    #[cfg(not(feature = "compression"))]
    pub fn new(_level: i32) -> Self {
        Self {}
    }

    /// Create a new compressor with the default compression level.
    pub fn with_default_level() -> Self {
        Self::new(DEFAULT_COMPRESSION_LEVEL)
    }

    /// Compress a block of data.
    #[cfg(feature = "compression")]
    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        zstd::encode_all(data, self.level).map_err(|e| Error::FileTransfer {
            message: format!("compression failed: {}", e),
        })
    }

    /// Compress a block of data (no-op when compression disabled).
    #[cfg(not(feature = "compression"))]
    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(data.to_vec())
    }

    /// Check if compression is worthwhile for the given data.
    ///
    /// Returns false if the data is too small or compression ratio is poor.
    #[cfg(feature = "compression")]
    pub fn should_compress(&self, data: &[u8]) -> bool {
        // Don't compress very small blocks
        if data.len() < 256 {
            return false;
        }

        // Sample-based entropy check (quick heuristic)
        let sample_size = data.len().min(1024);
        let sample = &data[..sample_size];

        let mut byte_counts = [0u32; 256];
        for &b in sample {
            byte_counts[b as usize] += 1;
        }

        // Count unique bytes as a simple compressibility heuristic
        let unique_bytes = byte_counts.iter().filter(|&&c| c > 0).count();

        // If more than 200 unique bytes in sample, likely not very compressible
        unique_bytes < 200
    }

    /// Check if compression is worthwhile (always false when compression disabled).
    #[cfg(not(feature = "compression"))]
    pub fn should_compress(&self, _data: &[u8]) -> bool {
        false
    }
}

impl Default for Compressor {
    fn default() -> Self {
        Self::with_default_level()
    }
}

/// Decompressor for file data.
#[derive(Debug, Default)]
pub struct Decompressor;

impl Decompressor {
    /// Create a new decompressor.
    pub fn new() -> Self {
        Self
    }

    /// Decompress a block of data.
    #[cfg(feature = "compression")]
    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>> {
        zstd::decode_all(data).map_err(|e| Error::FileTransfer {
            message: format!("decompression failed: {}", e),
        })
    }

    /// Decompress a block of data (passthrough when compression disabled).
    #[cfg(not(feature = "compression"))]
    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(data.to_vec())
    }

    /// Decompress data with a maximum output size limit.
    #[cfg(feature = "compression")]
    pub fn decompress_with_limit(&self, data: &[u8], max_size: usize) -> Result<Vec<u8>> {
        let mut decoder = zstd::Decoder::new(data).map_err(|e| Error::FileTransfer {
            message: format!("failed to create decompressor: {}", e),
        })?;

        let mut output = Vec::new();
        let mut buf = [0u8; 8192];

        loop {
            let n = decoder.read(&mut buf).map_err(|e| Error::FileTransfer {
                message: format!("decompression read failed: {}", e),
            })?;

            if n == 0 {
                break;
            }

            if output.len() + n > max_size {
                return Err(Error::FileTransfer {
                    message: format!(
                        "decompressed size exceeds limit: {} > {}",
                        output.len() + n,
                        max_size
                    ),
                });
            }

            output.extend_from_slice(&buf[..n]);
        }

        Ok(output)
    }

    /// Decompress data with limit (passthrough when compression disabled).
    #[cfg(not(feature = "compression"))]
    pub fn decompress_with_limit(&self, data: &[u8], max_size: usize) -> Result<Vec<u8>> {
        if data.len() > max_size {
            return Err(Error::FileTransfer {
                message: format!("data size exceeds limit: {} > {}", data.len(), max_size),
            });
        }
        Ok(data.to_vec())
    }
}

/// Check if a file path has a compressed extension.
pub fn is_compressed_extension(path: &str) -> bool {
    let lower = path.to_lowercase();
    COMPRESSED_EXTENSIONS
        .iter()
        .any(|ext| lower.ends_with(&format!(".{}", ext)))
}

/// Streaming compressor for large files.
#[cfg(feature = "compression")]
pub struct StreamingCompressor<W: Write> {
    encoder: zstd::Encoder<'static, W>,
}

#[cfg(feature = "compression")]
impl<W: Write> StreamingCompressor<W> {
    /// Create a new streaming compressor.
    pub fn new(writer: W, level: i32) -> Result<Self> {
        let encoder = zstd::Encoder::new(writer, level).map_err(|e| Error::FileTransfer {
            message: format!("failed to create encoder: {}", e),
        })?;

        Ok(Self { encoder })
    }

    /// Write data to the compressor.
    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        self.encoder
            .write_all(data)
            .map_err(|e| Error::FileTransfer {
                message: format!("compression write failed: {}", e),
            })
    }

    /// Finish compression and return the underlying writer.
    pub fn finish(self) -> Result<W> {
        self.encoder.finish().map_err(|e| Error::FileTransfer {
            message: format!("compression finish failed: {}", e),
        })
    }
}

/// Streaming decompressor for large files.
#[cfg(feature = "compression")]
pub struct StreamingDecompressor<R: Read> {
    decoder: zstd::Decoder<'static, std::io::BufReader<R>>,
}

#[cfg(feature = "compression")]
impl<R: Read> StreamingDecompressor<R> {
    /// Create a new streaming decompressor.
    pub fn new(reader: R) -> Result<Self> {
        let decoder = zstd::Decoder::new(reader).map_err(|e| Error::FileTransfer {
            message: format!("failed to create decoder: {}", e),
        })?;

        Ok(Self { decoder })
    }

    /// Read decompressed data.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.decoder.read(buf).map_err(|e| Error::FileTransfer {
            message: format!("decompression read failed: {}", e),
        })
    }
}

#[cfg(test)]
#[cfg(feature = "compression")]
mod tests {
    use super::*;

    #[test]
    fn test_compress_decompress_roundtrip() {
        let compressor = Compressor::with_default_level();
        let decompressor = Decompressor::new();

        let original = b"Hello, world! This is a test of compression.";

        let compressed = compressor.compress(original).unwrap();
        let decompressed = decompressor.decompress(&compressed).unwrap();

        assert_eq!(original.as_slice(), decompressed.as_slice());
    }

    #[test]
    fn test_compress_decompress_large() {
        let compressor = Compressor::with_default_level();
        let decompressor = Decompressor::new();

        // Create a large repetitive buffer (should compress well)
        let original: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();

        let compressed = compressor.compress(&original).unwrap();
        let decompressed = decompressor.decompress(&compressed).unwrap();

        assert_eq!(original, decompressed);
        assert!(compressed.len() < original.len()); // Should actually compress
    }

    #[test]
    fn test_should_compress() {
        let compressor = Compressor::with_default_level();

        // Small data: don't compress
        assert!(!compressor.should_compress(b"tiny"));

        // Text data: compress
        let text = b"The quick brown fox jumps over the lazy dog. ".repeat(100);
        assert!(compressor.should_compress(&text));

        // Random-ish data: might not compress well
        let random: Vec<u8> = (0..1000).map(|i| ((i * 17 + 31) % 256) as u8).collect();
        // This test just verifies the function doesn't panic
        let _ = compressor.should_compress(&random);
    }

    #[test]
    fn test_is_compressed_extension() {
        assert!(is_compressed_extension("file.gz"));
        assert!(is_compressed_extension("file.ZIP"));
        assert!(is_compressed_extension("image.jpg"));
        assert!(is_compressed_extension("video.mp4"));

        assert!(!is_compressed_extension("file.txt"));
        assert!(!is_compressed_extension("file.rs"));
        assert!(!is_compressed_extension("file"));
    }

    #[test]
    fn test_decompress_with_limit() {
        let compressor = Compressor::with_default_level();
        let decompressor = Decompressor::new();

        let original = b"test data".repeat(100);
        let compressed = compressor.compress(&original).unwrap();

        // Should succeed with high enough limit
        let result = decompressor.decompress_with_limit(&compressed, 10000);
        assert!(result.is_ok());

        // Should fail with too low limit
        let result = decompressor.decompress_with_limit(&compressed, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_streaming_compressor() {
        let mut output = Vec::new();
        {
            let mut compressor = StreamingCompressor::new(&mut output, 3).unwrap();
            compressor.write(b"Hello, ").unwrap();
            compressor.write(b"world!").unwrap();
            compressor.finish().unwrap();
        }

        let decompressor = Decompressor::new();
        let decompressed = decompressor.decompress(&output).unwrap();
        assert_eq!(decompressed, b"Hello, world!");
    }
}
