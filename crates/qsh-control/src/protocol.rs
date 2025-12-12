//! Protocol codec for the unified control plane.
//!
//! This module provides encoding and decoding for the control protocol messages.
//! The wire format is:
//!
//! - Length prefix: u32 little-endian (4 bytes)
//! - Payload: protobuf-encoded `Message`
//!
//! # Example
//!
//! ```ignore
//! use qsh_control::protocol::{encode_message, decode_message, CommandBuilder};
//! use qsh_control::proto;
//!
//! // Create a command using the builder
//! let msg = CommandBuilder::new(1).status();
//!
//! // Encode to wire format
//! let bytes = encode_message(&msg)?;
//!
//! // Decode from wire format
//! let decoded = decode_message(&bytes)?;
//! ```

use bytes::{Buf, BufMut, Bytes, BytesMut};
use prost::Message as ProstMessage;

use crate::proto;
use crate::types::{
    FailureReason, FileTransferDetails, ForwardDetails, ForwardType, OutputMode, ResourceDetails,
    ResourceEvent as RustResourceEvent, ResourceInfo as RustResourceInfo, ResourceKind,
    ResourceState, ResourceStats, TerminalDetails,
};

/// Maximum message size (16 MB).
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// Errors that can occur during encoding/decoding.
#[derive(Debug)]
pub enum ProtocolError {
    /// Message too large.
    MessageTooLarge { size: usize, max: usize },
    /// Invalid message format.
    InvalidMessage(String),
    /// Incomplete message (need more bytes).
    Incomplete { needed: usize, available: usize },
    /// Protobuf decode error.
    DecodeError(prost::DecodeError),
    /// Protobuf encode error.
    EncodeError(prost::EncodeError),
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolError::MessageTooLarge { size, max } => {
                write!(f, "message too large: {} bytes (max {})", size, max)
            }
            ProtocolError::InvalidMessage(msg) => write!(f, "invalid message: {}", msg),
            ProtocolError::Incomplete { needed, available } => {
                write!(f, "incomplete message: need {} bytes, have {}", needed, available)
            }
            ProtocolError::DecodeError(e) => write!(f, "decode error: {}", e),
            ProtocolError::EncodeError(e) => write!(f, "encode error: {}", e),
        }
    }
}

impl std::error::Error for ProtocolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ProtocolError::DecodeError(e) => Some(e),
            ProtocolError::EncodeError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<prost::DecodeError> for ProtocolError {
    fn from(e: prost::DecodeError) -> Self {
        ProtocolError::DecodeError(e)
    }
}

impl From<prost::EncodeError> for ProtocolError {
    fn from(e: prost::EncodeError) -> Self {
        ProtocolError::EncodeError(e)
    }
}

/// Encode a protobuf message with length prefix.
///
/// Returns the wire-format bytes: u32 LE length + protobuf payload.
pub fn encode_message(msg: &proto::Message) -> Result<Bytes, ProtocolError> {
    let payload_len = msg.encoded_len();
    if payload_len > MAX_MESSAGE_SIZE {
        return Err(ProtocolError::MessageTooLarge {
            size: payload_len,
            max: MAX_MESSAGE_SIZE,
        });
    }

    let mut buf = BytesMut::with_capacity(4 + payload_len);
    buf.put_u32_le(payload_len as u32);
    msg.encode(&mut buf)?;

    Ok(buf.freeze())
}

/// Decode a length-prefixed protobuf message.
///
/// The input should start with a u32 LE length prefix followed by the payload.
/// Returns the decoded message.
pub fn decode_message(mut buf: &[u8]) -> Result<proto::Message, ProtocolError> {
    if buf.len() < 4 {
        return Err(ProtocolError::Incomplete {
            needed: 4,
            available: buf.len(),
        });
    }

    let len = buf.get_u32_le() as usize;
    if len > MAX_MESSAGE_SIZE {
        return Err(ProtocolError::MessageTooLarge {
            size: len,
            max: MAX_MESSAGE_SIZE,
        });
    }

    if buf.len() < len {
        return Err(ProtocolError::Incomplete {
            needed: len,
            available: buf.len(),
        });
    }

    let msg = proto::Message::decode(&buf[..len])?;
    Ok(msg)
}

/// Try to decode a message from a buffer, advancing the buffer on success.
///
/// Returns `Ok(Some(msg))` if a complete message was decoded,
/// `Ok(None)` if more data is needed, or `Err` on protocol error.
pub fn try_decode_message(buf: &mut BytesMut) -> Result<Option<proto::Message>, ProtocolError> {
    if buf.len() < 4 {
        return Ok(None);
    }

    let len = (&buf[..4]).get_u32_le() as usize;
    if len > MAX_MESSAGE_SIZE {
        return Err(ProtocolError::MessageTooLarge {
            size: len,
            max: MAX_MESSAGE_SIZE,
        });
    }

    if buf.len() < 4 + len {
        return Ok(None);
    }

    // Consume the length prefix
    buf.advance(4);

    // Decode and consume the payload
    let payload = buf.split_to(len);
    let msg = proto::Message::decode(&payload[..])?;

    Ok(Some(msg))
}

/// Encode a message directly into a BytesMut buffer.
pub fn encode_into(buf: &mut BytesMut, msg: &proto::Message) -> Result<(), ProtocolError> {
    let payload_len = msg.encoded_len();
    if payload_len > MAX_MESSAGE_SIZE {
        return Err(ProtocolError::MessageTooLarge {
            size: payload_len,
            max: MAX_MESSAGE_SIZE,
        });
    }

    buf.reserve(4 + payload_len);
    buf.put_u32_le(payload_len as u32);
    msg.encode(buf)?;

    Ok(())
}

// ============================================================================
// Conversion helpers between Rust types and proto types
// ============================================================================

impl From<ResourceKind> for proto::ResourceKind {
    fn from(kind: ResourceKind) -> Self {
        match kind {
            ResourceKind::Terminal => proto::ResourceKind::Terminal,
            ResourceKind::Forward => proto::ResourceKind::Forward,
            ResourceKind::FileTransfer => proto::ResourceKind::FileTransfer,
        }
    }
}

impl TryFrom<proto::ResourceKind> for ResourceKind {
    type Error = ProtocolError;

    fn try_from(kind: proto::ResourceKind) -> Result<Self, Self::Error> {
        match kind {
            proto::ResourceKind::Terminal => Ok(ResourceKind::Terminal),
            proto::ResourceKind::Forward => Ok(ResourceKind::Forward),
            proto::ResourceKind::FileTransfer => Ok(ResourceKind::FileTransfer),
            proto::ResourceKind::Unspecified => {
                Err(ProtocolError::InvalidMessage("unspecified resource kind".to_string()))
            }
        }
    }
}

impl From<&ResourceState> for proto::ResourceState {
    fn from(state: &ResourceState) -> Self {
        match state {
            ResourceState::Pending => proto::ResourceState::Pending,
            ResourceState::Starting => proto::ResourceState::Starting,
            ResourceState::Running => proto::ResourceState::Running,
            ResourceState::Draining => proto::ResourceState::Draining,
            ResourceState::Closed => proto::ResourceState::Closed,
            ResourceState::Failed(_) => proto::ResourceState::Failed,
        }
    }
}

impl From<&ResourceStats> for proto::ResourceStats {
    fn from(stats: &ResourceStats) -> Self {
        proto::ResourceStats {
            created_at: stats.created_at,
            bytes_in: stats.bytes_in,
            bytes_out: stats.bytes_out,
        }
    }
}

impl From<proto::ResourceStats> for ResourceStats {
    fn from(stats: proto::ResourceStats) -> Self {
        ResourceStats {
            created_at: stats.created_at,
            bytes_in: stats.bytes_in,
            bytes_out: stats.bytes_out,
        }
    }
}

impl From<ForwardType> for proto::ForwardType {
    fn from(ft: ForwardType) -> Self {
        match ft {
            ForwardType::Local => proto::ForwardType::Local,
            ForwardType::Remote => proto::ForwardType::Remote,
            ForwardType::Dynamic => proto::ForwardType::Dynamic,
        }
    }
}

impl TryFrom<proto::ForwardType> for ForwardType {
    type Error = ProtocolError;

    fn try_from(ft: proto::ForwardType) -> Result<Self, Self::Error> {
        match ft {
            proto::ForwardType::Local => Ok(ForwardType::Local),
            proto::ForwardType::Remote => Ok(ForwardType::Remote),
            proto::ForwardType::Dynamic => Ok(ForwardType::Dynamic),
            proto::ForwardType::Unspecified => {
                Err(ProtocolError::InvalidMessage("unspecified forward type".to_string()))
            }
        }
    }
}

/// Convert a Rust ResourceInfo to proto format.
pub fn resource_info_to_proto(info: &RustResourceInfo) -> proto::ResourceInfo {
    let reason = match &info.state {
        ResourceState::Failed(r) => r.to_string(),
        _ => String::new(),
    };

    let details = match &info.details {
        ResourceDetails::Terminal(t) => Some(proto::resource_info::Details::Terminal(
            proto::TerminalDetails {
                cols: t.cols,
                rows: t.rows,
                shell: t.shell.clone(),
                attached: t.attached,
                pid: t.pid.unwrap_or(0),
                socket_path: t.socket_path.clone().unwrap_or_default(),
                term_type: t.term_type.clone(),
                command: t.command.clone().unwrap_or_default(),
                output_mode: match t.output_mode {
                    OutputMode::Direct => proto::OutputMode::Direct.into(),
                    OutputMode::Mosh => proto::OutputMode::Mosh.into(),
                    OutputMode::StateDiff => proto::OutputMode::StateDiff.into(),
                },
                allocate_pty: t.allocate_pty,
            },
        )),
        ResourceDetails::Forward(f) => Some(proto::resource_info::Details::Forward(
            proto::ForwardDetails {
                forward_type: proto::ForwardType::from(f.forward_type).into(),
                bind_addr: f.bind_addr.clone(),
                bind_port: f.bind_port,
                dest_host: f.dest_host.clone().unwrap_or_default(),
                dest_port: f.dest_port.unwrap_or(0),
                active_connections: f.active_connections,
            },
        )),
        ResourceDetails::FileTransfer(ft) => Some(proto::resource_info::Details::FileTransfer(
            proto::FileTransferDetails {
                local_path: ft.local_path.clone(),
                remote_path: ft.remote_path.clone(),
                upload: ft.upload,
                total_bytes: ft.total_bytes,
                transferred_bytes: ft.transferred_bytes,
                files_total: ft.files_total,
                files_done: ft.files_done,
                files_failed: ft.files_failed,
            },
        )),
    };

    proto::ResourceInfo {
        id: info.id.clone(),
        kind: proto::ResourceKind::from(info.kind).into(),
        state: proto::ResourceState::from(&info.state).into(),
        reason,
        stats: Some(proto::ResourceStats::from(&info.stats)),
        details,
    }
}

/// Convert a proto ResourceInfo to Rust format.
pub fn resource_info_from_proto(info: proto::ResourceInfo) -> Result<RustResourceInfo, ProtocolError> {
    let kind = proto::ResourceKind::try_from(info.kind)
        .map_err(|_| ProtocolError::InvalidMessage("invalid resource kind".to_string()))?
        .try_into()?;

    let state = match proto::ResourceState::try_from(info.state) {
        Ok(proto::ResourceState::Pending) => ResourceState::Pending,
        Ok(proto::ResourceState::Starting) => ResourceState::Starting,
        Ok(proto::ResourceState::Running) => ResourceState::Running,
        Ok(proto::ResourceState::Draining) => ResourceState::Draining,
        Ok(proto::ResourceState::Closed) => ResourceState::Closed,
        Ok(proto::ResourceState::Failed) => {
            ResourceState::Failed(FailureReason::Other(info.reason.clone()))
        }
        _ => {
            return Err(ProtocolError::InvalidMessage("invalid resource state".to_string()));
        }
    };

    let stats = info.stats.map(ResourceStats::from).unwrap_or_default();

    let details = match info.details {
        Some(proto::resource_info::Details::Terminal(t)) => {
            let output_mode = proto::OutputMode::try_from(t.output_mode)
                .unwrap_or(proto::OutputMode::Direct);
            ResourceDetails::Terminal(TerminalDetails {
                cols: t.cols,
                rows: t.rows,
                shell: t.shell,
                attached: t.attached,
                pid: if t.pid > 0 { Some(t.pid) } else { None },
                socket_path: if t.socket_path.is_empty() {
                    None
                } else {
                    Some(t.socket_path)
                },
                term_type: t.term_type,
                command: if t.command.is_empty() {
                    None
                } else {
                    Some(t.command)
                },
                output_mode: match output_mode {
                    proto::OutputMode::Direct | proto::OutputMode::Unspecified => {
                        OutputMode::Direct
                    }
                    proto::OutputMode::Mosh => OutputMode::Mosh,
                    proto::OutputMode::StateDiff => OutputMode::StateDiff,
                },
                allocate_pty: t.allocate_pty,
            })
        }
        Some(proto::resource_info::Details::Forward(f)) => {
            let forward_type = proto::ForwardType::try_from(f.forward_type)
                .map_err(|_| ProtocolError::InvalidMessage("invalid forward type".to_string()))?
                .try_into()?;
            ResourceDetails::Forward(ForwardDetails {
                forward_type,
                bind_addr: f.bind_addr,
                bind_port: f.bind_port,
                dest_host: if f.dest_host.is_empty() { None } else { Some(f.dest_host) },
                dest_port: if f.dest_port > 0 { Some(f.dest_port) } else { None },
                active_connections: f.active_connections,
            })
        }
        Some(proto::resource_info::Details::FileTransfer(ft)) => {
            ResourceDetails::FileTransfer(FileTransferDetails {
                local_path: ft.local_path,
                remote_path: ft.remote_path,
                upload: ft.upload,
                total_bytes: ft.total_bytes,
                transferred_bytes: ft.transferred_bytes,
                files_total: ft.files_total,
                files_done: ft.files_done,
                files_failed: ft.files_failed,
            })
        }
        None => {
            // Default to terminal with empty details
            ResourceDetails::Terminal(TerminalDetails::default())
        }
    };

    Ok(RustResourceInfo {
        id: info.id,
        kind,
        state,
        stats,
        details,
    })
}

/// Convert a Rust ResourceEvent to proto format.
pub fn resource_event_to_proto(event: &RustResourceEvent, event_seq: u64) -> proto::Event {
    let reason = match &event.state {
        ResourceState::Failed(r) => r.to_string(),
        _ => String::new(),
    };

    proto::Event {
        event_seq,
        evt: Some(proto::event::Evt::ResourceEvent(proto::ResourceEvent {
            id: event.id.clone(),
            kind: proto::ResourceKind::from(event.kind).into(),
            state: proto::ResourceState::from(&event.state).into(),
            reason,
            stats: Some(proto::ResourceStats::from(&event.stats)),
        })),
    }
}

// ============================================================================
// Command/Response builders
// ============================================================================

/// Builder for creating command messages.
pub struct CommandBuilder {
    request_id: u32,
}

impl CommandBuilder {
    /// Create a new command builder with the given request ID.
    pub fn new(request_id: u32) -> Self {
        Self { request_id }
    }

    /// Build a status command.
    pub fn status(self) -> proto::Message {
        proto::Message {
            kind: Some(proto::message::Kind::Command(proto::Command {
                request_id: self.request_id,
                cmd: Some(proto::command::Cmd::Status(proto::StatusCmd {})),
            })),
        }
    }

    /// Build a ping command.
    pub fn ping(self, timestamp: u64) -> proto::Message {
        proto::Message {
            kind: Some(proto::message::Kind::Command(proto::Command {
                request_id: self.request_id,
                cmd: Some(proto::command::Cmd::Ping(proto::PingCmd { timestamp })),
            })),
        }
    }

    /// Build a sessions command.
    pub fn sessions(self) -> proto::Message {
        proto::Message {
            kind: Some(proto::message::Kind::Command(proto::Command {
                request_id: self.request_id,
                cmd: Some(proto::command::Cmd::Sessions(proto::SessionsCmd {})),
            })),
        }
    }

    /// Build an exit command.
    pub fn exit(self, force: bool) -> proto::Message {
        proto::Message {
            kind: Some(proto::message::Kind::Command(proto::Command {
                request_id: self.request_id,
                cmd: Some(proto::command::Cmd::Exit(proto::ExitCmd { force })),
            })),
        }
    }

    /// Build a resource list command.
    pub fn resource_list(self, kind: Option<ResourceKind>) -> proto::Message {
        proto::Message {
            kind: Some(proto::message::Kind::Command(proto::Command {
                request_id: self.request_id,
                cmd: Some(proto::command::Cmd::ResourceList(proto::ResourceList {
                    kind: kind.map(|k| proto::ResourceKind::from(k).into()).unwrap_or(0),
                })),
            })),
        }
    }

    /// Build a resource describe command.
    pub fn resource_describe(self, resource_id: String) -> proto::Message {
        proto::Message {
            kind: Some(proto::message::Kind::Command(proto::Command {
                request_id: self.request_id,
                cmd: Some(proto::command::Cmd::ResourceDescribe(proto::ResourceDescribe {
                    resource_id,
                })),
            })),
        }
    }

    /// Build a resource drain command.
    pub fn resource_drain(self, resource_id: String, deadline_ms: u64) -> proto::Message {
        proto::Message {
            kind: Some(proto::message::Kind::Command(proto::Command {
                request_id: self.request_id,
                cmd: Some(proto::command::Cmd::ResourceDrain(proto::ResourceDrain {
                    resource_id,
                    deadline_ms,
                })),
            })),
        }
    }

    /// Build a resource close command.
    pub fn resource_close(self, resource_id: String) -> proto::Message {
        proto::Message {
            kind: Some(proto::message::Kind::Command(proto::Command {
                request_id: self.request_id,
                cmd: Some(proto::command::Cmd::ResourceClose(proto::ResourceClose {
                    resource_id,
                })),
            })),
        }
    }

    /// Build a terminal attach command.
    pub fn terminal_attach(self, resource_id: String) -> proto::Message {
        proto::Message {
            kind: Some(proto::message::Kind::Command(proto::Command {
                request_id: self.request_id,
                cmd: Some(proto::command::Cmd::TerminalAttach(proto::TerminalAttachCmd {
                    resource_id,
                })),
            })),
        }
    }

    /// Build a terminal detach command.
    pub fn terminal_detach(self, resource_id: String) -> proto::Message {
        proto::Message {
            kind: Some(proto::message::Kind::Command(proto::Command {
                request_id: self.request_id,
                cmd: Some(proto::command::Cmd::TerminalDetach(proto::TerminalDetachCmd {
                    resource_id,
                })),
            })),
        }
    }

    /// Build a terminal resize command.
    pub fn terminal_resize(self, resource_id: String, cols: u32, rows: u32) -> proto::Message {
        proto::Message {
            kind: Some(proto::message::Kind::Command(proto::Command {
                request_id: self.request_id,
                cmd: Some(proto::command::Cmd::TerminalResize(proto::TerminalResizeCmd {
                    resource_id,
                    cols,
                    rows,
                })),
            })),
        }
    }

    /// Build a file upload command.
    pub fn file_upload(
        self,
        local_path: String,
        remote_path: String,
        options: proto::FileTransferOptions,
    ) -> proto::Message {
        proto::Message {
            kind: Some(proto::message::Kind::Command(proto::Command {
                request_id: self.request_id,
                cmd: Some(proto::command::Cmd::FileUpload(proto::FileUploadCmd {
                    local_path,
                    remote_path,
                    options: Some(options),
                })),
            })),
        }
    }

    /// Build a file download command.
    pub fn file_download(
        self,
        remote_path: String,
        local_path: String,
        options: proto::FileTransferOptions,
    ) -> proto::Message {
        proto::Message {
            kind: Some(proto::message::Kind::Command(proto::Command {
                request_id: self.request_id,
                cmd: Some(proto::command::Cmd::FileDownload(proto::FileDownloadCmd {
                    remote_path,
                    local_path,
                    options: Some(options),
                })),
            })),
        }
    }

    /// Build a file cancel command.
    pub fn file_cancel(self, resource_id: String) -> proto::Message {
        proto::Message {
            kind: Some(proto::message::Kind::Command(proto::Command {
                request_id: self.request_id,
                cmd: Some(proto::command::Cmd::FileCancel(proto::FileCancelCmd {
                    resource_id,
                })),
            })),
        }
    }

    /// Build an enroll command (for bootstrap reuse).
    pub fn enroll(self) -> proto::Message {
        proto::Message {
            kind: Some(proto::message::Kind::Command(proto::Command {
                request_id: self.request_id,
                cmd: Some(proto::command::Cmd::Enroll(proto::EnrollCmd {})),
            })),
        }
    }
}

/// Builder for creating event/response messages.
pub struct EventBuilder {
    event_seq: u64,
}

impl EventBuilder {
    /// Create a new event builder with the given sequence number.
    pub fn new(event_seq: u64) -> Self {
        Self { event_seq }
    }

    /// Build a command result event (success).
    pub fn command_ok(self, request_id: u32, data: proto::command_ok::Data) -> proto::Message {
        proto::Message {
            kind: Some(proto::message::Kind::Event(proto::Event {
                event_seq: self.event_seq,
                evt: Some(proto::event::Evt::CommandResult(proto::CommandResult {
                    request_id,
                    result: Some(proto::command_result::Result::Ok(proto::CommandOk {
                        data: Some(data),
                    })),
                })),
            })),
        }
    }

    /// Build a command result event (success with no data).
    pub fn command_ok_empty(self, request_id: u32) -> proto::Message {
        proto::Message {
            kind: Some(proto::message::Kind::Event(proto::Event {
                event_seq: self.event_seq,
                evt: Some(proto::event::Evt::CommandResult(proto::CommandResult {
                    request_id,
                    result: Some(proto::command_result::Result::Ok(proto::CommandOk {
                        data: None,
                    })),
                })),
            })),
        }
    }

    /// Build a command result event (error).
    pub fn command_error(
        self,
        request_id: u32,
        code: proto::ErrorCode,
        message: String,
        details: String,
    ) -> proto::Message {
        proto::Message {
            kind: Some(proto::message::Kind::Event(proto::Event {
                event_seq: self.event_seq,
                evt: Some(proto::event::Evt::CommandResult(proto::CommandResult {
                    request_id,
                    result: Some(proto::command_result::Result::Error(proto::CommandError {
                        code: code.into(),
                        message,
                        details,
                    })),
                })),
            })),
        }
    }

    /// Build a resource event.
    pub fn resource_event(self, event: proto::ResourceEvent) -> proto::Message {
        proto::Message {
            kind: Some(proto::message::Kind::Event(proto::Event {
                event_seq: self.event_seq,
                evt: Some(proto::event::Evt::ResourceEvent(event)),
            })),
        }
    }
}

/// Build a stream message.
pub fn stream_message(
    resource_id: String,
    stream_kind: proto::StreamKind,
    direction: proto::StreamDirection,
    data: Vec<u8>,
) -> proto::Message {
    proto::Message {
        kind: Some(proto::message::Kind::Stream(proto::Stream {
            resource_id,
            stream_kind: stream_kind.into(),
            direction: direction.into(),
            data,
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let msg = CommandBuilder::new(42).status();
        let encoded = encode_message(&msg).unwrap();
        let decoded = decode_message(&encoded).unwrap();

        match decoded.kind {
            Some(proto::message::Kind::Command(cmd)) => {
                assert_eq!(cmd.request_id, 42);
                assert!(matches!(cmd.cmd, Some(proto::command::Cmd::Status(_))));
            }
            _ => panic!("unexpected message kind"),
        }
    }

    #[test]
    fn test_try_decode_incomplete() {
        let msg = CommandBuilder::new(1).ping(12345);
        let encoded = encode_message(&msg).unwrap();

        // Test with partial length prefix
        let mut buf = BytesMut::from(&encoded[..2]);
        assert!(matches!(try_decode_message(&mut buf), Ok(None)));
        assert_eq!(buf.len(), 2); // Buffer not advanced

        // Test with complete length but partial payload
        let mut buf = BytesMut::from(&encoded[..6]);
        assert!(matches!(try_decode_message(&mut buf), Ok(None)));
        assert_eq!(buf.len(), 6); // Buffer not advanced

        // Test with complete message
        let mut buf = BytesMut::from(&encoded[..]);
        let result = try_decode_message(&mut buf).unwrap();
        assert!(result.is_some());
        assert!(buf.is_empty()); // Buffer consumed
    }

    #[test]
    fn test_message_too_large() {
        // Create a message that claims to be too large
        let mut buf = BytesMut::new();
        buf.put_u32_le((MAX_MESSAGE_SIZE + 1) as u32);
        buf.put_slice(&[0u8; 10]);

        let result = try_decode_message(&mut buf);
        assert!(matches!(result, Err(ProtocolError::MessageTooLarge { .. })));
    }

    #[test]
    fn test_resource_kind_conversion() {
        assert_eq!(
            proto::ResourceKind::from(ResourceKind::Terminal),
            proto::ResourceKind::Terminal
        );
        assert_eq!(
            ResourceKind::try_from(proto::ResourceKind::Forward).unwrap(),
            ResourceKind::Forward
        );
    }

    #[test]
    fn test_command_builders() {
        // Status
        let msg = CommandBuilder::new(1).status();
        assert!(matches!(
            msg.kind,
            Some(proto::message::Kind::Command(proto::Command {
                request_id: 1,
                cmd: Some(proto::command::Cmd::Status(_))
            }))
        ));

        // Ping
        let msg = CommandBuilder::new(2).ping(999);
        if let Some(proto::message::Kind::Command(cmd)) = msg.kind {
            if let Some(proto::command::Cmd::Ping(ping)) = cmd.cmd {
                assert_eq!(ping.timestamp, 999);
            } else {
                panic!("expected ping command");
            }
        } else {
            panic!("expected command message");
        }

        // Resource list
        let msg = CommandBuilder::new(3).resource_list(Some(ResourceKind::Terminal));
        assert!(matches!(
            msg.kind,
            Some(proto::message::Kind::Command(proto::Command {
                request_id: 3,
                cmd: Some(proto::command::Cmd::ResourceList(_))
            }))
        ));

        // Enroll
        let msg = CommandBuilder::new(4).enroll();
        assert!(matches!(
            msg.kind,
            Some(proto::message::Kind::Command(proto::Command {
                request_id: 4,
                cmd: Some(proto::command::Cmd::Enroll(_))
            }))
        ));
    }

    #[test]
    fn test_stream_message() {
        let msg = stream_message(
            "term-0".to_string(),
            proto::StreamKind::TerminalIo,
            proto::StreamDirection::In,
            vec![0x1b, 0x5b, 0x41], // ESC [ A
        );

        if let Some(proto::message::Kind::Stream(stream)) = msg.kind {
            assert_eq!(stream.resource_id, "term-0");
            assert_eq!(stream.stream_kind, proto::StreamKind::TerminalIo as i32);
            assert_eq!(stream.direction, proto::StreamDirection::In as i32);
            assert_eq!(stream.data, vec![0x1b, 0x5b, 0x41]);
        } else {
            panic!("expected stream message");
        }
    }
}
