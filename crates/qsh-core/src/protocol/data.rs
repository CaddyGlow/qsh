//! Channel data payload types.
//!
//! This module provides:
//! - ChannelData wrapper for stream messages
//! - ChannelPayload enum for all payload variants
//! - Terminal payload types (input, output, state updates)
//! - File transfer payload types (data, ack, complete, error, blocks)
//! - Tunnel payload types (IP packets)

use serde::{Deserialize, Serialize};

use super::channel::ChannelId;
use super::params::{BlockChecksum, DataFlags, FileErrorCode, FileTransferStatus};
use crate::terminal::StateDiff;

// =============================================================================
// Channel Data Wrapper
// =============================================================================

/// Wrapper for all channel stream messages.
///
/// Sent on ChannelIn, ChannelOut, and ChannelBidi streams for uniform routing.
/// Note: Forward channels use raw bytes (no ChannelData wrapper) for zero-copy relay.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelData {
    /// Channel this data belongs to.
    pub channel_id: ChannelId,
    /// The payload.
    pub payload: ChannelPayload,
}

// =============================================================================
// Channel Payload Types
// =============================================================================

/// Channel-specific payload types.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ChannelPayload {
    // Terminal payloads
    TerminalInput(TerminalInputData),
    TerminalOutput(TerminalOutputData),
    StateUpdate(StateUpdateData),

    // File transfer payloads
    FileData(FileDataData),
    FileAck(FileAckData),
    FileComplete(FileCompleteData),
    FileError(FileErrorData),
    /// Streaming block checksums for delta sync.
    FileBlocks(FileBlocksPayload),

    // Tunnel payloads (IP packets)
    #[cfg(feature = "tunnel")]
    TunnelPacket(TunnelPacketData),
}

// =============================================================================
// Terminal Payloads
// =============================================================================

/// Terminal input (client -> server).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TerminalInputData {
    /// Monotonic sequence number.
    pub sequence: u64,
    /// Raw input bytes.
    pub data: Vec<u8>,
    /// Hint: these bytes may be predicted locally.
    pub predictable: bool,
}

/// Terminal output (server -> client).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TerminalOutputData {
    /// Raw output bytes.
    pub data: Vec<u8>,
    /// Highest input sequence processed before this output.
    pub confirmed_input_seq: u64,
}

/// Terminal state update (server -> client).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateUpdateData {
    /// State diff or full state.
    pub diff: StateDiff,
    /// Highest input sequence processed.
    pub confirmed_input_seq: u64,
    /// Server timestamp for latency calc (microseconds).
    pub timestamp: u64,
}

// =============================================================================
// File Transfer Payloads
// =============================================================================

/// File data chunk.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileDataData {
    /// Byte offset in the file.
    pub offset: u64,
    /// Data bytes (or block index if block_ref flag set).
    pub data: Vec<u8>,
    /// Data flags.
    pub flags: DataFlags,
}

/// File acknowledgment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileAckData {
    /// Bytes received so far.
    pub bytes_received: u64,
}

/// File transfer complete.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileCompleteData {
    /// Final file checksum (xxHash64).
    pub checksum: u64,
    /// Total bytes transferred.
    pub total_bytes: u64,
    /// Completion status.
    pub status: FileTransferStatus,
}

/// File transfer error.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileErrorData {
    /// Error code.
    pub code: FileErrorCode,
    /// Human-readable error message.
    pub message: String,
}

/// Streaming block checksums for delta sync.
///
/// Used in `DeltaAlgo::RollingStreaming` mode to send block checksums
/// incrementally as the existing file is scanned.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileBlocksPayload {
    /// Block checksums (partial signature).
    pub blocks: Vec<BlockChecksum>,
    /// True if this is the final chunk of blocks.
    pub final_chunk: bool,
}

// =============================================================================
// Tunnel Payloads
// =============================================================================

/// IP tunnel packet.
#[cfg(feature = "tunnel")]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TunnelPacketData {
    /// Raw IP packet (IPv4 or IPv6, including header).
    pub packet: Vec<u8>,
}
