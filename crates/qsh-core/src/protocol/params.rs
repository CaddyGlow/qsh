//! Channel parameter types for qsh protocol.
//!
//! This module contains all types related to channel opening parameters,
//! including terminal, file transfer, port forwarding, and tunnel configurations.

use serde::{Deserialize, Serialize};

// Re-export ipnet types for tunnel feature
#[cfg(feature = "tunnel")]
pub use ipnet::IpNet;

use super::ChannelType;

// ============================================================================
// Terminal Parameters
// ============================================================================

/// Terminal size in columns and rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TermSize {
    pub cols: u16,
    pub rows: u16,
}

impl Default for TermSize {
    fn default() -> Self {
        Self { cols: 80, rows: 24 }
    }
}

/// Parameters for opening a terminal channel.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TerminalParams {
    /// Requested terminal size.
    pub term_size: TermSize,
    /// TERM environment variable.
    pub term_type: String,
    /// Additional environment variables to pass to the PTY.
    #[serde(default)]
    pub env: Vec<(String, String)>,
    /// Specific shell to run (None = user's default shell).
    pub shell: Option<String>,
    /// Command to execute (None = interactive shell).
    /// When set, the server runs `$SHELL -c "command"` instead of an interactive shell.
    #[serde(default)]
    pub command: Option<String>,
    /// Whether to allocate a PTY for this session.
    /// - true: allocate PTY (interactive shell or `-t` flag)
    /// - false: use pipes instead (command execution or `-T`/`-N` flags)
    #[serde(default = "default_allocate_pty")]
    pub allocate_pty: bool,
    /// For reconnection: last confirmed state generation (0 if new session).
    #[serde(default)]
    pub last_generation: u64,
    /// For reconnection: last confirmed input sequence.
    #[serde(default)]
    pub last_input_seq: u64,
}

fn default_allocate_pty() -> bool {
    true
}

impl Default for TerminalParams {
    fn default() -> Self {
        Self {
            term_size: TermSize::default(),
            term_type: "xterm-256color".to_string(),
            env: Vec::new(),
            shell: None,
            command: None,
            allocate_pty: true,
            last_generation: 0,
            last_input_seq: 0,
        }
    }
}

// ============================================================================
// File Transfer Parameters
// ============================================================================

/// Direction of a file transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransferDirection {
    /// Client uploads to server.
    Upload,
    /// Client downloads from server.
    Download,
}

/// Delta transfer algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum DeltaAlgo {
    /// No delta; send/receive full file (optionally compressed).
    #[default]
    None,
    /// Simple fixed-block hash comparison:
    /// - Both sides read in fixed-size blocks.
    /// - Compare per-block hashes; send full blocks that differ.
    /// - Very streaming-friendly but sensitive to insertions/deletions.
    SimpleBlock,
    /// Rsync-style rolling delta with a full precomputed signature:
    /// - Receiver computes complete BlockChecksum table up front.
    /// - Sender runs rolling checksum over the new file.
    RollingClassic,
    /// Rsync-style rolling delta with streaming signatures:
    /// - Signatures arrive incrementally via FileBlocks.
    /// - Sender may start rolling delta before the full signature is known.
    RollingStreaming,
}

/// Transfer options.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransferOptions {
    /// Enable compression.
    pub compress: bool,
    /// Enable delta sync (only send changed blocks).
    /// Deprecated: use `delta_algo` instead.
    #[serde(default)]
    pub delta: bool,
    /// Delta transfer algorithm to use.
    #[serde(default)]
    pub delta_algo: DeltaAlgo,
    /// Recursive directory transfer.
    pub recursive: bool,
    /// Preserve file mode/permissions.
    pub preserve_mode: bool,
    /// Maximum parallel file operations (directories).
    #[serde(default = "default_parallel_files")]
    pub parallel: usize,
    /// If true, attempt to skip the transfer entirely when the source
    /// and destination files are already identical (size + mtime + hash match).
    #[serde(default)]
    pub skip_if_unchanged: bool,
}

const fn default_parallel_files() -> usize {
    1
}

impl Default for TransferOptions {
    fn default() -> Self {
        Self {
            compress: false,
            delta: false,
            delta_algo: DeltaAlgo::None,
            recursive: false,
            preserve_mode: false,
            parallel: default_parallel_files(),
            skip_if_unchanged: false,
        }
    }
}

/// Block checksum for delta sync.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockChecksum {
    /// Byte offset of this block.
    pub offset: u64,
    /// Weak rolling checksum (Adler-32).
    pub weak: u32,
    /// Strong checksum (xxHash64).
    pub strong: u64,
}

/// Parameters for opening a file transfer channel.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileTransferParams {
    /// Remote file path.
    pub path: String,
    /// Transfer direction.
    pub direction: TransferDirection,
    /// Transfer options.
    pub options: TransferOptions,
    /// Resume from byte offset (if resuming).
    pub resume_from: Option<u64>,
}

/// File metadata sent in ChannelAccept for file transfers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileTransferMetadata {
    /// File size in bytes.
    pub size: u64,
    /// Modification time (Unix timestamp).
    pub mtime: u64,
    /// File mode/permissions.
    pub mode: u32,
    /// Block checksums for delta sync (empty if delta disabled).
    #[serde(default)]
    pub blocks: Vec<BlockChecksum>,
    /// Whether this is a directory.
    pub is_dir: bool,
    /// Optional strong hash (xxHash64) of the entire file contents.
    /// Present when skip_if_unchanged is enabled and file exists.
    #[serde(default)]
    pub file_hash: Option<u64>,
    /// Partial file checksum for resume support.
    /// When resuming, this is the xxHash64 of the first `size` bytes.
    /// Used to verify partial file integrity before continuing transfer.
    #[serde(default)]
    pub partial_checksum: Option<u64>,
}

/// Data flags for file data blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DataFlags {
    /// Data is compressed.
    pub compressed: bool,
    /// This is the final block.
    pub final_block: bool,
    /// This is a block reference (delta transfer).
    pub block_ref: bool,
}

/// Completion status for a file transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum FileTransferStatus {
    /// Normal transfer completed; file data was sent/received.
    #[default]
    Normal,
    /// No data was transferred because the file was already up to date
    /// (size + mtime + hash match).
    AlreadyUpToDate,
}

/// File transfer error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileErrorCode {
    /// File not found.
    NotFound,
    /// Permission denied.
    PermissionDenied,
    /// I/O error.
    IoError,
    /// Checksum mismatch.
    ChecksumMismatch,
    /// Transfer was cancelled.
    Cancelled,
    /// Disk full.
    DiskFull,
    /// Path is a directory (expected file).
    IsDirectory,
    /// Path is a file (expected directory).
    IsFile,
    /// Invalid path.
    InvalidPath,
}

impl std::fmt::Display for FileErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileErrorCode::NotFound => write!(f, "file not found"),
            FileErrorCode::PermissionDenied => write!(f, "permission denied"),
            FileErrorCode::IoError => write!(f, "I/O error"),
            FileErrorCode::ChecksumMismatch => write!(f, "checksum mismatch"),
            FileErrorCode::Cancelled => write!(f, "transfer cancelled"),
            FileErrorCode::DiskFull => write!(f, "disk full"),
            FileErrorCode::IsDirectory => write!(f, "path is a directory"),
            FileErrorCode::IsFile => write!(f, "path is a file"),
            FileErrorCode::InvalidPath => write!(f, "invalid path"),
        }
    }
}

// ============================================================================
// Port Forwarding Parameters
// ============================================================================

/// Parameters for local port forward (-L).
///
/// Client opened this channel to request server connect to target.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DirectTcpIpParams {
    /// Target hostname on server side.
    pub target_host: String,
    /// Target port on server side.
    pub target_port: u16,
    /// Originator info (for logging/audit).
    pub originator_host: String,
    /// Originator port.
    pub originator_port: u16,
}

/// Parameters for remote port forward (-R).
///
/// Server opened this channel because something connected to server's listening port.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForwardedTcpIpParams {
    /// Address that was bound on server.
    pub bound_host: String,
    /// Port that was bound on server.
    pub bound_port: u16,
    /// Who connected.
    pub originator_host: String,
    /// Originator port.
    pub originator_port: u16,
}

/// Parameters for dynamic SOCKS5 forward (-D).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DynamicForwardParams {
    /// Target hostname (resolved by client SOCKS proxy).
    pub target_host: String,
    /// Target port.
    pub target_port: u16,
}

// ============================================================================
// Tunnel Parameters
// ============================================================================

/// Parameters for IP tunnel.
#[cfg(feature = "tunnel")]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TunnelParams {
    /// Requested client tunnel IP with prefix.
    pub client_ip: IpNet,
    /// Requested MTU for tunnel interface.
    pub mtu: u16,
    /// Routes to push to client.
    pub requested_routes: Vec<IpNet>,
    /// Enable IPv6 in tunnel.
    pub ipv6: bool,
}

// ============================================================================
// Channel Parameters Enum
// ============================================================================

/// Type-specific parameters for channel open.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ChannelParams {
    Terminal(TerminalParams),
    FileTransfer(FileTransferParams),
    DirectTcpIp(DirectTcpIpParams),
    ForwardedTcpIp(ForwardedTcpIpParams),
    DynamicForward(DynamicForwardParams),
    #[cfg(feature = "tunnel")]
    Tunnel(TunnelParams),
}

impl ChannelParams {
    /// Get the channel type for these parameters.
    pub fn channel_type(&self) -> ChannelType {
        match self {
            ChannelParams::Terminal(_) => ChannelType::Terminal,
            ChannelParams::FileTransfer(_) => ChannelType::FileTransfer,
            ChannelParams::DirectTcpIp(_) => ChannelType::DirectTcpIp,
            ChannelParams::ForwardedTcpIp(_) => ChannelType::ForwardedTcpIp,
            ChannelParams::DynamicForward(_) => ChannelType::DynamicForward,
            #[cfg(feature = "tunnel")]
            ChannelParams::Tunnel(_) => ChannelType::Tunnel,
        }
    }
}
