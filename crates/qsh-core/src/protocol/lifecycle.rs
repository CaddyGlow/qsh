//! Channel and session lifecycle types.
//!
//! This module contains types related to the lifecycle of qsh sessions and channels:
//! - Session identification across reconnects
//! - Channel open/accept/reject/close payloads
//! - Lifecycle-related enums and reason codes

use serde::{Deserialize, Serialize};

use super::channel::ChannelId;
#[cfg(feature = "tunnel")]
use super::params::IpNet;
use super::params::{ChannelParams, FileTransferMetadata};
use crate::terminal::TerminalState;

// =============================================================================
// Session Identification
// =============================================================================

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
        getrandom::fill(&mut bytes).expect("failed to generate random session ID");
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
        metadata: Option<FileTransferMetadata>,
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
        dns_servers: Vec<std::net::IpAddr>,
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
            ChannelCloseReason::ProcessExited {
                exit_code: Some(code),
            } => {
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
// Session Resumption
// =============================================================================

/// Information about an existing channel during session resumption.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExistingChannel {
    /// Channel ID.
    pub channel_id: ChannelId,
    /// Channel type (terminal, file-transfer, etc.).
    pub channel_type: ExistingChannelType,
}

/// Type of existing channel for session resumption.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ExistingChannelType {
    /// Terminal channel with current state.
    Terminal {
        /// Current terminal state for immediate display.
        state: TerminalState,
    },
    /// Other channel types (forwards, file transfers) - just notify existence.
    Other,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

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
        let id = SessionId::from_bytes([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        assert_eq!(format!("{}", id), "0102030405060708");
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
            format!(
                "{}",
                ChannelCloseReason::ProcessExited { exit_code: Some(0) }
            ),
            "process exited (0)"
        );
        assert_eq!(
            format!(
                "{}",
                ChannelCloseReason::Error {
                    message: "oops".into()
                }
            ),
            "error: oops"
        );
    }
}
