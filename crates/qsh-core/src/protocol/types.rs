//! Protocol message types for qsh wire protocol.
//!
//! Per PROTOCOL spec: Messages are serialized using bincode with length-prefixed encoding.
//!
//! ## Channel Model (v2)
//!
//! qsh uses an SSH-style channel model for multiplexing:
//! - Hello/HelloAck establishes authenticated connection (no channels yet)
//! - Either side sends `ChannelOpen` to create any resource (terminal, file transfer, forward)
//! - Receiver responds with `ChannelAccept` or `ChannelReject`
//! - Either side can send `ChannelClose` to tear down a channel
//!
//! Stream mapping:
//! - Control = bidirectional stream 0 (lifecycle messages)
//! - ChannelIn(id) = unidirectional client->server (terminal input, file data)
//! - ChannelOut(id) = unidirectional server->client (terminal output, file data)
//! - ChannelBidi(id) = bidirectional (forwards, tunnel)

use serde::{Deserialize, Serialize};
use std::hash::Hash;

// =============================================================================
// Channel Identification Types
// =============================================================================

/// Which side initiated the channel.
///
/// Both client and server can open channels. To avoid ID collisions and make
/// the initiator explicit, channel IDs include a side discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChannelSide {
    /// Client-initiated channel (terminal, file transfer, direct-tcpip, tunnel).
    Client,
    /// Server-initiated channel (forwarded-tcpip when -R connection arrives).
    Server,
}

/// Unique channel identifier within a connection.
///
/// Each side allocates from its own namespace:
/// - Client assigns `ChannelId::client(n)` starting from 0
/// - Server assigns `ChannelId::server(n)` starting from 0
/// - `(Client, 5)` and `(Server, 5)` are distinct channels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChannelId {
    pub side: ChannelSide,
    pub id: u64,
}

impl ChannelId {
    /// Create a client-initiated channel ID.
    pub fn client(id: u64) -> Self {
        Self {
            side: ChannelSide::Client,
            id,
        }
    }

    /// Create a server-initiated channel ID.
    pub fn server(id: u64) -> Self {
        Self {
            side: ChannelSide::Server,
            id,
        }
    }

    /// Check if this is a client-initiated channel.
    pub fn is_client(&self) -> bool {
        matches!(self.side, ChannelSide::Client)
    }

    /// Check if this is a server-initiated channel.
    pub fn is_server(&self) -> bool {
        matches!(self.side, ChannelSide::Server)
    }

    /// Encode the channel ID for QUIC stream ID encoding.
    ///
    /// Format: bit 0 = side (0=client, 1=server), bits 1+ = channel id
    pub fn encode(&self) -> u64 {
        let side_bit = match self.side {
            ChannelSide::Client => 0,
            ChannelSide::Server => 1,
        };
        (self.id << 1) | side_bit
    }

    /// Decode a channel ID from an encoded value.
    pub fn decode(encoded: u64) -> Self {
        let side = if encoded & 1 == 0 {
            ChannelSide::Client
        } else {
            ChannelSide::Server
        };
        Self {
            side,
            id: encoded >> 1,
        }
    }
}

impl std::fmt::Display for ChannelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let prefix = match self.side {
            ChannelSide::Client => "c",
            ChannelSide::Server => "s",
        };
        write!(f, "{}{}", prefix, self.id)
    }
}

/// Opaque identifier for a logical qsh session (across reconnects).
///
/// The server generates this on first connection; the client provides it
/// on reconnect to resume an existing session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub [u8; 16]);

impl SessionId {
    /// Generate a new random session ID.
    pub fn new() -> Self {
        let mut bytes = [0u8; 16];
        getrandom::getrandom(&mut bytes).expect("failed to generate random session ID");
        Self(bytes)
    }

    /// Create a session ID from bytes.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Get the bytes of this session ID.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Display first 8 bytes as hex for brevity
        for byte in &self.0[..8] {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

// =============================================================================
// Channel Types
// =============================================================================

/// Channel types supported by qsh.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelType {
    /// Interactive terminal (PTY).
    Terminal,
    /// File transfer (upload/download).
    FileTransfer,
    /// Local port forward (-L): client listens, server connects to target.
    DirectTcpIp,
    /// Remote port forward (-R): server listens, client connects to target.
    ForwardedTcpIp,
    /// SOCKS5 dynamic forward (-D).
    DynamicForward,
    /// IP tunnel (VPN).
    Tunnel,
}

impl std::fmt::Display for ChannelType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChannelType::Terminal => write!(f, "terminal"),
            ChannelType::FileTransfer => write!(f, "file-transfer"),
            ChannelType::DirectTcpIp => write!(f, "direct-tcpip"),
            ChannelType::ForwardedTcpIp => write!(f, "forwarded-tcpip"),
            ChannelType::DynamicForward => write!(f, "dynamic-forward"),
            ChannelType::Tunnel => write!(f, "tunnel"),
        }
    }
}

// =============================================================================
// Channel Parameters
// =============================================================================

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
    /// For reconnection: last confirmed state generation (0 if new session).
    #[serde(default)]
    pub last_generation: u64,
    /// For reconnection: last confirmed input sequence.
    #[serde(default)]
    pub last_input_seq: u64,
}

impl Default for TerminalParams {
    fn default() -> Self {
        Self {
            term_size: TermSize::default(),
            term_type: "xterm-256color".to_string(),
            env: Vec::new(),
            shell: None,
            last_generation: 0,
            last_input_seq: 0,
        }
    }
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

// =============================================================================
// Channel Lifecycle Payloads
// =============================================================================

/// Request to open a new channel.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelOpenPayload {
    /// Channel ID assigned by the initiating side.
    pub channel_id: ChannelId,
    /// Channel type and parameters.
    pub params: ChannelParams,
}

/// Accept a channel open request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelAcceptPayload {
    /// Channel ID being accepted.
    pub channel_id: ChannelId,
    /// Type-specific response data.
    pub data: ChannelAcceptData,
}

/// Type-specific data in channel accept.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ChannelAcceptData {
    Terminal {
        /// Initial terminal state (for new sessions or reconnection).
        initial_state: TerminalState,
    },
    FileTransfer {
        /// File metadata for downloads, confirmation for uploads.
        metadata: Option<FileMetadataPayload>,
    },
    DirectTcpIp,
    ForwardedTcpIp,
    DynamicForward,
    #[cfg(feature = "tunnel")]
    Tunnel {
        /// Server's tunnel IP.
        server_ip: IpNet,
        /// Negotiated MTU.
        mtu: u16,
        /// Routes client should add.
        routes: Vec<IpNet>,
        /// DNS servers to use.
        dns_servers: Vec<IpAddr>,
    },
}

/// Reject a channel open request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelRejectPayload {
    /// Channel ID being rejected.
    pub channel_id: ChannelId,
    /// Rejection code.
    pub code: ChannelRejectCode,
    /// Human-readable rejection message.
    pub message: String,
}

/// Channel rejection reasons (SSH-compatible codes where applicable).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelRejectCode {
    /// Administrative prohibition.
    AdministrativelyProhibited,
    /// Target unreachable (for forwards).
    ConnectFailed,
    /// Unknown channel type.
    UnknownChannelType,
    /// Resource limit (too many channels).
    ResourceShortage,
    /// Channel ID already in use.
    InvalidChannelId,
    /// Permission denied.
    PermissionDenied,
    /// File/path not found (for file transfer).
    NotFound,
    /// Internal server error.
    InternalError,
}

impl std::fmt::Display for ChannelRejectCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChannelRejectCode::AdministrativelyProhibited => {
                write!(f, "administratively prohibited")
            }
            ChannelRejectCode::ConnectFailed => write!(f, "connect failed"),
            ChannelRejectCode::UnknownChannelType => write!(f, "unknown channel type"),
            ChannelRejectCode::ResourceShortage => write!(f, "resource shortage"),
            ChannelRejectCode::InvalidChannelId => write!(f, "invalid channel ID"),
            ChannelRejectCode::PermissionDenied => write!(f, "permission denied"),
            ChannelRejectCode::NotFound => write!(f, "not found"),
            ChannelRejectCode::InternalError => write!(f, "internal error"),
        }
    }
}

/// Close a channel (sent by either side, requires confirmation like SSH).
///
/// SSH-style close handshake:
/// 1. Side A sends ChannelClose
/// 2. Side B receives it, cleans up, sends ChannelClose back (confirmation)
/// 3. Side A receives confirmation, channel is fully closed
///
/// If Side B had already sent ChannelClose (simultaneous close), both sides
/// treat the received ChannelClose as confirmation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelClosePayload {
    /// Channel ID being closed.
    pub channel_id: ChannelId,
    /// Reason for closing.
    pub reason: ChannelCloseReason,
}

/// Reason for channel close.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ChannelCloseReason {
    /// Normal close requested by user/application.
    Normal,
    /// Shell/process exited (for terminal channels).
    ProcessExited { exit_code: Option<i32> },
    /// Connection to target closed (for forwards).
    ConnectionClosed,
    /// Transfer completed (for file transfer).
    TransferComplete,
    /// Error occurred.
    Error { message: String },
    /// Idle timeout.
    Timeout,
}

impl std::fmt::Display for ChannelCloseReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChannelCloseReason::Normal => write!(f, "normal"),
            ChannelCloseReason::ProcessExited { exit_code: Some(code) } => {
                write!(f, "process exited ({})", code)
            }
            ChannelCloseReason::ProcessExited { exit_code: None } => {
                write!(f, "process exited")
            }
            ChannelCloseReason::ConnectionClosed => write!(f, "connection closed"),
            ChannelCloseReason::TransferComplete => write!(f, "transfer complete"),
            ChannelCloseReason::Error { message } => write!(f, "error: {}", message),
            ChannelCloseReason::Timeout => write!(f, "timeout"),
        }
    }
}

// =============================================================================
// Global Request/Reply (Connection-Level Operations)
// =============================================================================

/// Connection-level request (like SSH_MSG_GLOBAL_REQUEST).
///
/// These handle connection-wide operations that don't belong to any channel
/// (e.g., requesting a remote port forward before any ForwardedTcpIp channels exist).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GlobalRequestPayload {
    /// Request ID for correlating replies.
    pub request_id: u32,
    /// The request type and parameters.
    pub request: GlobalRequest,
}

/// Global request types.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum GlobalRequest {
    /// Request server to bind a port for remote forwarding (-R).
    /// Server will open ForwardedTcpIp channels when connections arrive.
    TcpIpForward {
        bind_host: String,
        /// Port to bind (0 = server picks).
        bind_port: u16,
    },
    /// Cancel a previously requested remote forward.
    CancelTcpIpForward { bind_host: String, bind_port: u16 },
}

/// Response to a global request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GlobalReplyPayload {
    /// Request ID this is replying to.
    pub request_id: u32,
    /// Result of the request.
    pub result: GlobalReplyResult,
}

/// Result of a global request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum GlobalReplyResult {
    /// Request succeeded.
    Success(GlobalReplyData),
    /// Request failed.
    Failure { message: String },
}

/// Type-specific data in successful global reply.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum GlobalReplyData {
    /// Response to TcpIpForward - contains actual bound port (if 0 was requested).
    TcpIpForward { bound_port: u16 },
    /// Response to CancelTcpIpForward - no data.
    CancelTcpIpForward,
}

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

    // Tunnel payloads (IP packets)
    #[cfg(feature = "tunnel")]
    TunnelPacket(TunnelPacketData),
}

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

/// IP tunnel packet.
#[cfg(feature = "tunnel")]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TunnelPacketData {
    /// Raw IP packet (IPv4 or IPv6, including header).
    pub packet: Vec<u8>,
}

// =============================================================================
// Top-level Message Enum
// =============================================================================

/// Top-level protocol message type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Message {
    // =========================================================================
    // Connection-level messages (control stream)
    // =========================================================================

    /// Client hello with session key and capabilities.
    Hello(HelloPayload),
    /// Server acknowledgment of hello.
    HelloAck(HelloAckPayload),
    /// Graceful shutdown notification.
    Shutdown(ShutdownPayload),

    // =========================================================================
    // Global requests (control stream)
    // =========================================================================

    /// Connection-level request (for port forwarding setup, etc.).
    GlobalRequest(GlobalRequestPayload),
    /// Response to a global request.
    GlobalReply(GlobalReplyPayload),

    // =========================================================================
    // Channel lifecycle messages (control stream)
    // =========================================================================

    /// Request to open a new channel.
    ChannelOpen(ChannelOpenPayload),
    /// Accept a channel open request.
    ChannelAccept(ChannelAcceptPayload),
    /// Reject a channel open request.
    ChannelReject(ChannelRejectPayload),
    /// Close a channel.
    ChannelClose(ChannelClosePayload),

    // =========================================================================
    // Per-channel control messages (control stream)
    // =========================================================================

    /// Terminal resize notification.
    Resize(ResizePayload),
    /// Client acknowledgment of state update.
    StateAck(StateAckPayload),

    // =========================================================================
    // Channel data (channel streams)
    // =========================================================================

    /// Data on a channel stream (wrapped payload).
    ChannelDataMsg(ChannelData),

    // =========================================================================
    // Standalone authentication messages (feature-gated)
    // =========================================================================

    /// Server sends after QUIC connect (includes server signature for client to verify).
    #[cfg(feature = "standalone")]
    AuthChallenge(AuthChallengePayload),
    /// Client response (proves client identity).
    #[cfg(feature = "standalone")]
    AuthResponse(AuthResponsePayload),
    /// Authentication failure (sent by server).
    #[cfg(feature = "standalone")]
    AuthFailure(AuthFailurePayload),

    // =========================================================================
    // Legacy messages (deprecated - kept for backward compatibility during migration)
    // =========================================================================

    /// User input sent to server (legacy - use ChannelDataMsg with TerminalInput).
    #[deprecated(note = "Use ChannelDataMsg with TerminalInput payload")]
    TerminalInput(TerminalInputPayload),
    /// Raw terminal output from server (legacy).
    #[deprecated(note = "Use ChannelDataMsg with TerminalOutput payload")]
    TerminalOutput(TerminalOutputPayload),
    /// Terminal state update from server (legacy).
    #[deprecated(note = "Use ChannelDataMsg with StateUpdate payload")]
    StateUpdate(StateUpdatePayload),

    /// Request to establish a forwarded connection (legacy).
    #[deprecated(note = "Use ChannelOpen with DirectTcpIp/ForwardedTcpIp params")]
    ForwardRequest(ForwardRequestPayload),
    /// Accept a forward request (legacy).
    #[deprecated(note = "Use ChannelAccept")]
    ForwardAccept(ForwardAcceptPayload),
    /// Reject a forward request (legacy).
    #[deprecated(note = "Use ChannelReject")]
    ForwardReject(ForwardRejectPayload),
    /// Data on a forwarded connection (legacy).
    #[deprecated(note = "Forward channels use raw bytes on ChannelBidi streams")]
    ForwardData(ForwardDataPayload),
    /// End of data in one direction (legacy).
    #[deprecated(note = "Use QUIC stream FIN for EOF")]
    ForwardEof(ForwardEofPayload),
    /// Close a forwarded connection (legacy).
    #[deprecated(note = "Use ChannelClose")]
    ForwardClose(ForwardClosePayload),

    /// Tunnel configuration request (legacy).
    #[cfg(feature = "tunnel")]
    #[deprecated(note = "Use ChannelOpen with Tunnel params")]
    TunnelConfig(TunnelConfigPayload),
    /// Tunnel configuration acknowledgment (legacy).
    #[cfg(feature = "tunnel")]
    #[deprecated(note = "Use ChannelAccept with Tunnel data")]
    TunnelConfigAck(TunnelConfigAckPayload),
    /// Raw IP packet through tunnel (legacy).
    #[cfg(feature = "tunnel")]
    #[deprecated(note = "Use ChannelDataMsg with TunnelPacket payload")]
    TunnelPacket(TunnelPacketPayload),

    /// Request to start a file transfer (legacy).
    #[deprecated(note = "Use ChannelOpen with FileTransfer params")]
    FileRequest(FileRequestPayload),
    /// File metadata response (legacy).
    #[deprecated(note = "Use ChannelAccept with FileTransfer data")]
    FileMetadata(FileMetadataPayload),
    /// File data block (legacy).
    #[deprecated(note = "Use ChannelDataMsg with FileData payload")]
    FileData(FileDataPayload),
    /// Acknowledge received data (legacy).
    #[deprecated(note = "Use ChannelDataMsg with FileAck payload")]
    FileAck(FileAckPayload),
    /// Transfer complete notification (legacy).
    #[deprecated(note = "Use ChannelDataMsg with FileComplete payload")]
    FileComplete(FileCompletePayload),
    /// File transfer error (legacy).
    #[deprecated(note = "Use ChannelDataMsg with FileError payload")]
    FileError(FileErrorPayload),
}

// =============================================================================
// Control Messages
// =============================================================================

/// Client hello payload.
///
/// Establishes connection-level parameters. Terminal-specific parameters
/// have been moved to `TerminalParams` in `ChannelOpen`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HelloPayload {
    /// Protocol version (must be 1).
    pub protocol_version: u32,
    /// Session key from bootstrap (32 bytes).
    pub session_key: [u8; 32],
    /// Client nonce for anti-replay (monotonic).
    pub client_nonce: u64,
    /// Client capabilities.
    pub capabilities: Capabilities,
    /// If resuming an existing logical session, the previous SessionId.
    /// None for a brand-new session.
    #[serde(default)]
    pub resume_session: Option<SessionId>,

    // Legacy fields - kept for backward compatibility during migration
    // These will be removed in protocol v2

    /// Requested terminal size (legacy - use TerminalParams in ChannelOpen).
    #[serde(default)]
    pub term_size: TermSize,
    /// TERM environment variable (legacy - use TerminalParams in ChannelOpen).
    #[serde(default)]
    pub term_type: String,
    /// Additional environment variables (legacy - use TerminalParams in ChannelOpen).
    #[serde(default)]
    pub env: Vec<(String, String)>,
    /// Last confirmed state generation (legacy - use TerminalParams in ChannelOpen).
    #[serde(default)]
    pub last_generation: u64,
    /// Last confirmed input sequence (legacy - use TerminalParams in ChannelOpen).
    #[serde(default)]
    pub last_input_seq: u64,
}

/// Server hello acknowledgment payload.
///
/// Establishes connection-level parameters. Terminal state has been moved
/// to `ChannelAcceptData::Terminal` in `ChannelAccept`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HelloAckPayload {
    /// Server protocol version.
    pub protocol_version: u32,
    /// Session accepted.
    pub accepted: bool,
    /// Rejection reason (if not accepted).
    pub reject_reason: Option<String>,
    /// Server capabilities.
    pub capabilities: Capabilities,
    /// SessionId for this logical session; reused across reconnects.
    #[serde(default)]
    pub session_id: SessionId,
    /// Server nonce for anti-replay.
    #[serde(default)]
    pub server_nonce: u64,
    /// 0-RTT is available for future reconnects.
    pub zero_rtt_available: bool,

    // Legacy field - kept for backward compatibility during migration

    /// Initial terminal state (legacy - use ChannelAccept with Terminal data).
    #[serde(default)]
    pub initial_state: Option<TerminalState>,
}

/// Client/server capabilities.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Capabilities {
    /// Supports predictive echo.
    pub predictive_echo: bool,
    /// Supports state compression.
    pub compression: bool,
    /// Maximum forward connections.
    pub max_forwards: u16,
    /// Supports IP tunnel.
    pub tunnel: bool,
}

/// Terminal size.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct TermSize {
    pub cols: u16,
    pub rows: u16,
}

impl Default for TermSize {
    fn default() -> Self {
        Self { cols: 80, rows: 24 }
    }
}

/// Resize notification payload (sent on control stream).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResizePayload {
    /// Channel ID this resize applies to.
    #[serde(default)]
    pub channel_id: Option<ChannelId>,
    pub cols: u16,
    pub rows: u16,
}

/// Shutdown payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShutdownPayload {
    pub reason: ShutdownReason,
    pub message: Option<String>,
}

/// Shutdown reason enumeration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ShutdownReason {
    /// User requested disconnect (~. escape or explicit quit).
    UserRequested,
    /// Server-side idle timeout.
    IdleTimeout,
    /// Server process exiting.
    ServerShutdown,
    /// Unrecoverable protocol violation.
    ProtocolError,
    /// Session key mismatch.
    AuthFailure,
    /// Shell process exited (exit command or ctrl-d).
    ShellExited,
}

// =============================================================================
// Terminal Messages
// =============================================================================

/// Terminal input payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TerminalInputPayload {
    /// Monotonic sequence number.
    pub sequence: u64,
    /// Raw input bytes.
    pub data: Vec<u8>,
    /// Hint: these bytes may be predicted locally.
    pub predictable: bool,
}

/// Raw terminal output payload (bypasses state tracking).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TerminalOutputPayload {
    /// Raw output bytes from PTY.
    pub data: Vec<u8>,
    /// Highest input sequence processed before this output.
    pub confirmed_input_seq: u64,
}

/// State update payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateUpdatePayload {
    /// State diff or full state.
    pub diff: StateDiff,
    /// Highest input sequence processed.
    pub confirmed_input_seq: u64,
    /// Server timestamp for latency calc (microseconds).
    pub timestamp: u64,
}

/// State acknowledgment payload (sent on control stream).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateAckPayload {
    /// Channel ID this ack applies to.
    #[serde(default)]
    pub channel_id: Option<ChannelId>,
    /// Generation number acknowledged.
    pub generation: u64,
}

// =============================================================================
// Terminal State Types (Placeholders - will be filled in Track B)
// =============================================================================

// Terminal state/diff are provided by the terminal module.
pub use crate::terminal::{Cell, Cursor, StateDiff, TerminalState};

// =============================================================================
// Forward Messages
// =============================================================================

/// Forward request payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForwardRequestPayload {
    /// Unique forward ID for this connection.
    pub forward_id: u64,
    /// Forward specification (includes bind address and target info).
    pub spec: ForwardSpec,
}

/// Forward specification enumeration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ForwardSpec {
    /// -L: Local port forward (client listens, server connects to target).
    Local {
        /// Bind address on client.
        bind_addr: std::net::SocketAddr,
        /// Target hostname on server side.
        target_host: String,
        /// Target port on server side.
        target_port: u16,
    },
    /// -R: Remote port forward (server listens, client connects to target).
    Remote {
        /// Bind address on server.
        bind_addr: std::net::SocketAddr,
        /// Target hostname on client side.
        target_host: String,
        /// Target port on client side.
        target_port: u16,
    },
    /// -D: Dynamic SOCKS5 (client runs SOCKS5 proxy).
    Dynamic {
        /// Bind address for SOCKS5 proxy.
        bind_addr: std::net::SocketAddr,
    },
}

impl ForwardSpec {
    /// Parse a local forward specification (-L).
    ///
    /// Formats:
    /// - `[bind_addr:]port:host:hostport`
    /// - `port:host:hostport` (binds to localhost)
    pub fn parse_local(s: &str) -> crate::Result<Self> {
        let (bind_addr, target_host, target_port) = parse_forward_spec(s)?;
        Ok(Self::Local {
            bind_addr,
            target_host,
            target_port,
        })
    }

    /// Parse a remote forward specification (-R).
    ///
    /// Formats:
    /// - `[bind_addr:]port:host:hostport`
    /// - `port:host:hostport` (binds to localhost on server)
    pub fn parse_remote(s: &str) -> crate::Result<Self> {
        let (bind_addr, target_host, target_port) = parse_forward_spec(s)?;
        Ok(Self::Remote {
            bind_addr,
            target_host,
            target_port,
        })
    }

    /// Parse a dynamic forward specification (-D).
    ///
    /// Formats:
    /// - `[bind_addr:]port`
    /// - `port` (binds to localhost)
    pub fn parse_dynamic(s: &str) -> crate::Result<Self> {
        let bind_addr = parse_bind_spec(s)?;
        Ok(Self::Dynamic { bind_addr })
    }

    /// Get the bind address.
    pub fn bind_addr(&self) -> std::net::SocketAddr {
        match self {
            Self::Local { bind_addr, .. } => *bind_addr,
            Self::Remote { bind_addr, .. } => *bind_addr,
            Self::Dynamic { bind_addr } => *bind_addr,
        }
    }

    /// Get the target host and port (if applicable).
    pub fn target(&self) -> Option<(&str, u16)> {
        match self {
            Self::Local {
                target_host,
                target_port,
                ..
            } => Some((target_host.as_str(), *target_port)),
            Self::Remote {
                target_host,
                target_port,
                ..
            } => Some((target_host.as_str(), *target_port)),
            Self::Dynamic { .. } => None,
        }
    }
}

/// Parse a forward specification in format `[bind_addr:]port:host:hostport`.
fn parse_forward_spec(s: &str) -> crate::Result<(std::net::SocketAddr, String, u16)> {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    if s.is_empty() {
        return Err(crate::Error::InvalidForwardSpec {
            message: "empty specification".into(),
        });
    }

    // Check for IPv6 bind address (starts with '[')
    if s.starts_with('[') {
        return parse_forward_spec_ipv6(s);
    }

    let parts: Vec<&str> = s.split(':').collect();

    match parts.len() {
        // port:host:hostport
        3 => {
            let bind_port = parse_port(parts[0])?;
            let target_host = parts[1].to_string();
            let target_port = parse_port(parts[2])?;

            let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), bind_port);
            Ok((bind_addr, target_host, target_port))
        }
        // bind_addr:port:host:hostport (IPv4)
        4 => {
            let bind_ip: IpAddr =
                parts[0]
                    .parse()
                    .map_err(|_| crate::Error::InvalidForwardSpec {
                        message: format!("invalid bind address: {}", parts[0]),
                    })?;
            let bind_port = parse_port(parts[1])?;
            let target_host = parts[2].to_string();
            let target_port = parse_port(parts[3])?;

            let bind_addr = SocketAddr::new(bind_ip, bind_port);
            Ok((bind_addr, target_host, target_port))
        }
        _ => Err(crate::Error::InvalidForwardSpec {
            message: format!(
                "invalid format: expected [bind_addr:]port:host:hostport, got: {}",
                s
            ),
        }),
    }
}

/// Parse a forward specification with IPv6 bind address.
fn parse_forward_spec_ipv6(s: &str) -> crate::Result<(std::net::SocketAddr, String, u16)> {
    use std::net::{IpAddr, SocketAddr};

    let close_bracket = s
        .find(']')
        .ok_or_else(|| crate::Error::InvalidForwardSpec {
            message: "unclosed IPv6 bracket".into(),
        })?;

    let ipv6_str = &s[1..close_bracket];
    let bind_ip: IpAddr = ipv6_str
        .parse()
        .map_err(|_| crate::Error::InvalidForwardSpec {
            message: format!("invalid IPv6 address: {}", ipv6_str),
        })?;

    let remainder = &s[close_bracket + 1..];
    if !remainder.starts_with(':') {
        return Err(crate::Error::InvalidForwardSpec {
            message: "expected ':' after IPv6 address".into(),
        });
    }

    let parts: Vec<&str> = remainder[1..].split(':').collect();
    if parts.len() != 3 {
        return Err(crate::Error::InvalidForwardSpec {
            message: format!("invalid format after IPv6 address: {}", remainder),
        });
    }

    let bind_port = parse_port(parts[0])?;
    let target_host = parts[1].to_string();
    let target_port = parse_port(parts[2])?;

    let bind_addr = SocketAddr::new(bind_ip, bind_port);
    Ok((bind_addr, target_host, target_port))
}

/// Parse a bind specification in format `[bind_addr:]port`.
fn parse_bind_spec(s: &str) -> crate::Result<std::net::SocketAddr> {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    if s.is_empty() {
        return Err(crate::Error::InvalidForwardSpec {
            message: "empty specification".into(),
        });
    }

    // Check for IPv6 bind address (starts with '[')
    if s.starts_with('[') {
        return parse_bind_spec_ipv6(s);
    }

    let parts: Vec<&str> = s.split(':').collect();

    match parts.len() {
        // port only
        1 => {
            let port = parse_port(parts[0])?;
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))
        }
        // bind_addr:port (IPv4)
        2 => {
            let bind_ip: IpAddr =
                parts[0]
                    .parse()
                    .map_err(|_| crate::Error::InvalidForwardSpec {
                        message: format!("invalid bind address: {}", parts[0]),
                    })?;
            let port = parse_port(parts[1])?;
            Ok(SocketAddr::new(bind_ip, port))
        }
        _ => Err(crate::Error::InvalidForwardSpec {
            message: format!("invalid format: expected [bind_addr:]port, got: {}", s),
        }),
    }
}

/// Parse a bind specification with IPv6 address.
fn parse_bind_spec_ipv6(s: &str) -> crate::Result<std::net::SocketAddr> {
    use std::net::{IpAddr, SocketAddr};

    let close_bracket = s
        .find(']')
        .ok_or_else(|| crate::Error::InvalidForwardSpec {
            message: "unclosed IPv6 bracket".into(),
        })?;

    let ipv6_str = &s[1..close_bracket];
    let bind_ip: IpAddr = ipv6_str
        .parse()
        .map_err(|_| crate::Error::InvalidForwardSpec {
            message: format!("invalid IPv6 address: {}", ipv6_str),
        })?;

    let remainder = &s[close_bracket + 1..];
    if !remainder.starts_with(':') {
        return Err(crate::Error::InvalidForwardSpec {
            message: "expected ':' after IPv6 address".into(),
        });
    }

    let port = parse_port(&remainder[1..])?;
    Ok(SocketAddr::new(bind_ip, port))
}

/// Parse a port number string.
fn parse_port(s: &str) -> crate::Result<u16> {
    s.parse::<u16>()
        .map_err(|_| crate::Error::InvalidForwardSpec {
            message: format!("invalid port: {}", s),
        })
}

/// Forward accept payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForwardAcceptPayload {
    pub forward_id: u64,
}

/// Forward reject payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForwardRejectPayload {
    pub forward_id: u64,
    pub reason: String,
}

/// Forward data payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForwardDataPayload {
    pub forward_id: u64,
    pub data: Vec<u8>,
}

/// Forward EOF payload (half-close).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForwardEofPayload {
    pub forward_id: u64,
}

/// Forward close payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForwardClosePayload {
    pub forward_id: u64,
    pub reason: Option<String>,
}

// =============================================================================
// Tunnel Messages (Feature-gated)
// =============================================================================

/// Tunnel configuration payload.
#[cfg(feature = "tunnel")]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TunnelConfigPayload {
    /// Requested client tunnel IP with prefix.
    pub client_ip: IpNet,
    /// Requested MTU for tunnel interface.
    pub mtu: u16,
    /// Routes to push to client (optional).
    pub requested_routes: Vec<IpNet>,
    /// Enable IPv6 in tunnel.
    pub ipv6: bool,
}

/// Tunnel configuration acknowledgment payload.
#[cfg(feature = "tunnel")]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TunnelConfigAckPayload {
    /// Whether tunnel was accepted.
    pub accepted: bool,
    /// Rejection reason (if not accepted).
    pub reject_reason: Option<String>,
    /// Server's tunnel IP.
    pub server_ip: IpNet,
    /// Negotiated MTU.
    pub mtu: u16,
    /// Routes client should add (server-pushed).
    pub routes: Vec<IpNet>,
    /// DNS servers to use (optional).
    pub dns_servers: Vec<IpAddr>,
}

/// Tunnel packet payload.
#[cfg(feature = "tunnel")]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TunnelPacketPayload {
    /// Raw IP packet (IPv4 or IPv6, including header).
    pub packet: Vec<u8>,
}

#[cfg(feature = "tunnel")]
impl TunnelPacketPayload {
    /// Get IP version from packet (4 or 6).
    pub fn ip_version(&self) -> Option<u8> {
        self.packet.first().map(|b| b >> 4)
    }

    /// Validate basic IP packet structure.
    pub fn is_valid(&self) -> bool {
        match self.ip_version() {
            Some(4) => self.packet.len() >= 20, // Min IPv4 header
            Some(6) => self.packet.len() >= 40, // Min IPv6 header
            _ => false,
        }
    }
}

// Re-export ipnet types for tunnel feature
#[cfg(feature = "tunnel")]
pub use ipnet::IpNet;

#[cfg(feature = "tunnel")]
pub use std::net::IpAddr;

// =============================================================================
// Standalone Authentication Messages (Feature-gated)
// =============================================================================

/// Server authentication challenge payload.
///
/// Server sends this after QUIC connect. Includes the server's signature
/// for the client to verify against known_hosts.
#[cfg(feature = "standalone")]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthChallengePayload {
    /// Server's host public key (OpenSSH format).
    pub server_public_key: String,
    /// Random challenge for client to sign.
    pub challenge: [u8; 32],
    /// Server's random nonce.
    pub server_nonce: [u8; 32],
    /// Server's signature over: AUTH_CTX || "server" || host || port || challenge || server_nonce
    pub server_signature: Vec<u8>,
}

/// Client authentication response payload.
///
/// Client sends this after verifying the server's identity.
#[cfg(feature = "standalone")]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthResponsePayload {
    /// Client's public key (OpenSSH format).
    pub client_public_key: String,
    /// Client's random nonce.
    pub client_nonce: [u8; 32],
    /// Client's signature over: AUTH_CTX || "client" || host || port || challenge || server_nonce || client_nonce
    pub signature: Vec<u8>,
}

/// Authentication failure payload.
///
/// Server sends this when authentication fails for any reason.
#[cfg(feature = "standalone")]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthFailurePayload {
    /// Error code indicating failure type.
    pub code: AuthErrorCode,
    /// Human-readable error message.
    pub message: String,
}

/// Authentication error codes.
///
/// Note: Only coarse-grained errors are exposed to clients.
/// Internal failure details are logged server-side only.
#[cfg(feature = "standalone")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthErrorCode {
    /// Generic authentication failure (unknown key, revoked, bad signature, etc.)
    AuthFailed,
    /// Client took too long to respond.
    Timeout,
    /// Malformed or unexpected message.
    ProtocolError,
    /// Server-side error.
    InternalError,
}

#[cfg(feature = "standalone")]
impl std::fmt::Display for AuthErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthErrorCode::AuthFailed => write!(f, "authentication failed"),
            AuthErrorCode::Timeout => write!(f, "timeout"),
            AuthErrorCode::ProtocolError => write!(f, "protocol error"),
            AuthErrorCode::InternalError => write!(f, "internal error"),
        }
    }
}

// =============================================================================
// File Transfer Messages
// =============================================================================

/// Direction of a file transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransferDirection {
    /// Client uploads to server.
    Upload,
    /// Client downloads from server.
    Download,
}

/// Transfer options.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransferOptions {
    /// Enable compression.
    pub compress: bool,
    /// Enable delta sync (only send changed blocks).
    pub delta: bool,
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
            recursive: false,
            preserve_mode: false,
            parallel: default_parallel_files(),
            skip_if_unchanged: false,
        }
    }
}

/// Chunk specification for parallel transfers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChunkSpec {
    /// Chunk identifier within the transfer.
    pub chunk_id: u32,
    /// Starting byte offset.
    pub offset: u64,
    /// Length of this chunk in bytes.
    pub length: u64,
}

/// File transfer request payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileRequestPayload {
    /// Unique identifier for this transfer.
    pub transfer_id: u64,
    /// Remote file path.
    pub path: String,
    /// Transfer direction.
    pub direction: TransferDirection,
    /// Resume from byte offset (if resuming).
    pub resume_from: Option<u64>,
    /// Transfer options.
    pub options: TransferOptions,
    /// Chunk specification for parallel transfer (None = whole file).
    pub chunk: Option<ChunkSpec>,
    /// Client-side block checksums for delta downloads (empty if unused).
    #[serde(default)]
    pub client_blocks: Vec<BlockChecksum>,
    /// Source file modification time (seconds since Unix epoch) for uploads.
    #[serde(default)]
    pub source_mtime: Option<u64>,
    /// Source file modification time nanoseconds (0-999999999) for uploads.
    #[serde(default)]
    pub source_mtime_nsec: Option<u32>,
    /// Source file access time (seconds since Unix epoch) for uploads.
    #[serde(default)]
    pub source_atime: Option<u64>,
    /// Source file access time nanoseconds (0-999999999) for uploads.
    #[serde(default)]
    pub source_atime_nsec: Option<u32>,
    /// Source file size for uploads.
    /// Used by server to optimize skip_if_unchanged (skip delta computation if sizes match).
    #[serde(default)]
    pub source_size: Option<u64>,
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

/// File metadata payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileMetadataPayload {
    /// Transfer ID this metadata belongs to.
    pub transfer_id: u64,
    /// File size in bytes.
    pub size: u64,
    /// Modification time (Unix timestamp).
    pub mtime: u64,
    /// File mode/permissions.
    pub mode: u32,
    /// Block checksums for delta sync (empty if delta disabled).
    pub blocks: Vec<BlockChecksum>,
    /// Whether this is a directory.
    pub is_dir: bool,
    /// Optional strong hash (xxHash64) of the entire file contents.
    /// Present when skip_if_unchanged is enabled and file exists.
    #[serde(default)]
    pub file_hash: Option<u64>,
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

/// File data payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileDataPayload {
    /// Transfer ID this data belongs to.
    pub transfer_id: u64,
    /// Byte offset in the file.
    pub offset: u64,
    /// Data bytes (or block index if block_ref flag set).
    pub data: Vec<u8>,
    /// Data flags.
    pub flags: DataFlags,
}

/// File acknowledgment payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileAckPayload {
    /// Transfer ID.
    pub transfer_id: u64,
    /// Bytes received so far.
    pub bytes_received: u64,
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

/// File transfer complete payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileCompletePayload {
    /// Transfer ID.
    pub transfer_id: u64,
    /// Final file checksum (xxHash64).
    pub checksum: u64,
    /// Total bytes transferred.
    pub total_bytes: u64,
    /// Completion status for this transfer.
    #[serde(default)]
    pub status: FileTransferStatus,
}

/// File transfer error payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileErrorPayload {
    /// Transfer ID.
    pub transfer_id: u64,
    /// Error code.
    pub code: FileErrorCode,
    /// Human-readable error message.
    pub message: String,
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

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(deprecated)]
    #[test]
    fn test_message_variants_exist() {
        // Test that all message variants can be constructed
        let _hello = Message::Hello(HelloPayload {
            protocol_version: 1,
            session_key: [0u8; 32],
            client_nonce: 0,
            capabilities: Capabilities::default(),
            resume_session: None,
            term_size: TermSize::default(),
            term_type: "xterm-256color".into(),
            env: Vec::new(),
            last_generation: 0,
            last_input_seq: 0,
        });

        let _hello_ack = Message::HelloAck(HelloAckPayload {
            protocol_version: 1,
            accepted: true,
            reject_reason: None,
            capabilities: Capabilities::default(),
            session_id: SessionId::from_bytes([0; 16]),
            server_nonce: 0,
            initial_state: None,
            zero_rtt_available: false,
        });

        let _resize = Message::Resize(ResizePayload {
            channel_id: None,
            cols: 80,
            rows: 24,
        });

        let _shutdown = Message::Shutdown(ShutdownPayload {
            reason: ShutdownReason::UserRequested,
            message: None,
        });

        let _input = Message::TerminalInput(TerminalInputPayload {
            sequence: 1,
            data: vec![0x61], // 'a'
            predictable: true,
        });

        let _update = Message::StateUpdate(StateUpdatePayload {
            diff: StateDiff::Full(TerminalState::default()),
            confirmed_input_seq: 0,
            timestamp: 0,
        });

        let _ack = Message::StateAck(StateAckPayload {
            channel_id: None,
            generation: 1,
        });

        let _fwd_req = Message::ForwardRequest(ForwardRequestPayload {
            forward_id: 0,
            spec: ForwardSpec::Local {
                bind_addr: std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    5432,
                ),
                target_host: "localhost".into(),
                target_port: 5432,
            },
        });

        let _fwd_accept = Message::ForwardAccept(ForwardAcceptPayload { forward_id: 0 });

        let _fwd_reject = Message::ForwardReject(ForwardRejectPayload {
            forward_id: 0,
            reason: "connection refused".into(),
        });

        let _fwd_data = Message::ForwardData(ForwardDataPayload {
            forward_id: 0,
            data: vec![1, 2, 3],
        });

        let _fwd_eof = Message::ForwardEof(ForwardEofPayload { forward_id: 0 });

        let _fwd_close = Message::ForwardClose(ForwardClosePayload {
            forward_id: 0,
            reason: None,
        });
    }

    #[test]
    fn test_channel_message_variants() {
        // Test new channel-based message variants
        let ch = ChannelId::client(0);

        let _channel_open = Message::ChannelOpen(ChannelOpenPayload {
            channel_id: ch,
            params: ChannelParams::Terminal(TerminalParams::default()),
        });

        let _channel_accept = Message::ChannelAccept(ChannelAcceptPayload {
            channel_id: ch,
            data: ChannelAcceptData::Terminal {
                initial_state: TerminalState::default(),
            },
        });

        let _channel_reject = Message::ChannelReject(ChannelRejectPayload {
            channel_id: ch,
            code: ChannelRejectCode::ResourceShortage,
            message: "too many channels".into(),
        });

        let _channel_close = Message::ChannelClose(ChannelClosePayload {
            channel_id: ch,
            reason: ChannelCloseReason::Normal,
        });

        let _global_request = Message::GlobalRequest(GlobalRequestPayload {
            request_id: 1,
            request: GlobalRequest::TcpIpForward {
                bind_host: "0.0.0.0".into(),
                bind_port: 8080,
            },
        });

        let _global_reply = Message::GlobalReply(GlobalReplyPayload {
            request_id: 1,
            result: GlobalReplyResult::Success(GlobalReplyData::TcpIpForward { bound_port: 8080 }),
        });

        let _channel_data = Message::ChannelDataMsg(ChannelData {
            channel_id: ch,
            payload: ChannelPayload::TerminalInput(TerminalInputData {
                sequence: 1,
                data: vec![0x61],
                predictable: true,
            }),
        });
    }

    #[test]
    fn test_channel_id_basics() {
        // Client(5) != Server(5)
        assert_ne!(ChannelId::client(5), ChannelId::server(5));
        assert_eq!(ChannelId::client(5), ChannelId::client(5));

        // Display
        assert_eq!(format!("{}", ChannelId::client(0)), "c0");
        assert_eq!(format!("{}", ChannelId::server(42)), "s42");

        // Predicates
        assert!(ChannelId::client(0).is_client());
        assert!(!ChannelId::client(0).is_server());
        assert!(ChannelId::server(0).is_server());
        assert!(!ChannelId::server(0).is_client());
    }

    #[test]
    fn test_channel_id_encode_decode() {
        let ids = [
            ChannelId::client(0),
            ChannelId::client(1),
            ChannelId::client(u64::MAX >> 1),
            ChannelId::server(0),
            ChannelId::server(1),
            ChannelId::server(u64::MAX >> 1),
        ];

        for id in ids {
            let encoded = id.encode();
            let decoded = ChannelId::decode(encoded);
            assert_eq!(id, decoded);
        }
    }

    #[test]
    fn test_session_id() {
        let id1 = SessionId::new();
        let id2 = SessionId::new();
        // Random IDs should be different
        assert_ne!(id1, id2);

        // From bytes
        let bytes = [1u8; 16];
        let id = SessionId::from_bytes(bytes);
        assert_eq!(id.as_bytes(), &bytes);

        // Display (first 8 bytes as hex)
        let id = SessionId::from_bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(format!("{}", id), "0102030405060708");
    }

    #[test]
    fn test_channel_params_type() {
        let terminal = ChannelParams::Terminal(TerminalParams::default());
        assert_eq!(terminal.channel_type(), ChannelType::Terminal);

        let file = ChannelParams::FileTransfer(FileTransferParams {
            path: "/tmp/test".into(),
            direction: TransferDirection::Upload,
            options: TransferOptions::default(),
            resume_from: None,
        });
        assert_eq!(file.channel_type(), ChannelType::FileTransfer);

        let direct = ChannelParams::DirectTcpIp(DirectTcpIpParams {
            target_host: "localhost".into(),
            target_port: 80,
            originator_host: "127.0.0.1".into(),
            originator_port: 12345,
        });
        assert_eq!(direct.channel_type(), ChannelType::DirectTcpIp);
    }

    #[test]
    fn test_channel_reject_code_display() {
        assert_eq!(
            format!("{}", ChannelRejectCode::ResourceShortage),
            "resource shortage"
        );
        assert_eq!(
            format!("{}", ChannelRejectCode::PermissionDenied),
            "permission denied"
        );
    }

    #[test]
    fn test_channel_close_reason_display() {
        assert_eq!(format!("{}", ChannelCloseReason::Normal), "normal");
        assert_eq!(
            format!("{}", ChannelCloseReason::ProcessExited { exit_code: Some(0) }),
            "process exited (0)"
        );
        assert_eq!(
            format!("{}", ChannelCloseReason::Error { message: "oops".into() }),
            "error: oops"
        );
    }

    #[test]
    fn test_channel_type_display() {
        assert_eq!(format!("{}", ChannelType::Terminal), "terminal");
        assert_eq!(format!("{}", ChannelType::FileTransfer), "file-transfer");
        assert_eq!(format!("{}", ChannelType::DirectTcpIp), "direct-tcpip");
    }

    #[test]
    fn test_capabilities_defaults() {
        let caps = Capabilities::default();
        assert!(!caps.predictive_echo);
        assert!(!caps.compression);
        assert_eq!(caps.max_forwards, 0);
        assert!(!caps.tunnel);
    }

    #[test]
    fn test_message_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Message>();
        assert_send_sync::<HelloPayload>();
        assert_send_sync::<HelloAckPayload>();
        assert_send_sync::<Capabilities>();
        assert_send_sync::<TerminalInputPayload>();
        assert_send_sync::<StateUpdatePayload>();
        assert_send_sync::<ForwardRequestPayload>();
    }

    #[test]
    fn test_term_size_default() {
        let size = TermSize::default();
        assert_eq!(size.cols, 80);
        assert_eq!(size.rows, 24);
    }

    #[test]
    fn test_shutdown_reasons() {
        let reasons = [
            ShutdownReason::UserRequested,
            ShutdownReason::IdleTimeout,
            ShutdownReason::ServerShutdown,
            ShutdownReason::ProtocolError,
            ShutdownReason::AuthFailure,
        ];
        for reason in reasons {
            let _ = format!("{:?}", reason);
        }
    }

    #[test]
    fn test_forward_spec_variants() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let _local = ForwardSpec::Local {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5432),
            target_host: "localhost".into(),
            target_port: 5432,
        };
        let _remote = ForwardSpec::Remote {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
            target_host: "localhost".into(),
            target_port: 80,
        };
        let _dynamic = ForwardSpec::Dynamic {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1080),
        };
    }

    #[test]
    fn test_state_diff_variants() {
        let _full = StateDiff::Full(TerminalState::default());
        let _incremental = StateDiff::Incremental {
            from_gen: 0,
            to_gen: 1,
            changes: vec![],
            cursor: None,
            title: None,
            cwd: None,
            clipboard: None,
            alternate_active: None,
        };
        let _cursor = StateDiff::CursorOnly {
            generation: 1,
            cursor: Cursor::default(),
        };
    }

    #[cfg(feature = "tunnel")]
    #[test]
    fn test_tunnel_packet_ip_version() {
        // IPv4 packet (version nibble = 4)
        let ipv4 = TunnelPacketPayload {
            packet: vec![0x45, 0x00, 0x00, 0x14],
        };
        assert_eq!(ipv4.ip_version(), Some(4));

        // IPv6 packet (version nibble = 6)
        let ipv6 = TunnelPacketPayload {
            packet: vec![0x60, 0x00, 0x00, 0x00],
        };
        assert_eq!(ipv6.ip_version(), Some(6));

        // Empty packet
        let empty = TunnelPacketPayload { packet: vec![] };
        assert_eq!(empty.ip_version(), None);
    }

    #[cfg(feature = "tunnel")]
    #[test]
    fn test_tunnel_packet_validation() {
        // Valid IPv4 (20+ bytes)
        let valid_v4 = TunnelPacketPayload {
            packet: vec![0x45; 20],
        };
        assert!(valid_v4.is_valid());

        // Too short for IPv4
        let short_v4 = TunnelPacketPayload {
            packet: vec![0x45; 10],
        };
        assert!(!short_v4.is_valid());

        // Valid IPv6 (40+ bytes)
        let valid_v6 = TunnelPacketPayload {
            packet: vec![0x60; 40],
        };
        assert!(valid_v6.is_valid());

        // Invalid version
        let bad_version = TunnelPacketPayload {
            packet: vec![0x50; 40],
        };
        assert!(!bad_version.is_valid());
    }
}
