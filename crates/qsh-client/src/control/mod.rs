//! Control socket interface for managing qsh connections.
//!
//! This module provides a Unix socket-based control interface that allows
//! separate terminal sessions to manage an existing qsh connection. Commands
//! include querying connection status, adding/removing port forwards, and
//! managing sessions.
//!
//! The protocol uses length-prefixed protobuf messages over Unix domain sockets.
//!
//! # Architecture
//!
//! The control system is built around a unified resource model:
//!
//! - **Resource**: Common interface for all manageable entities (terminals,
//!   forwards, file transfers). See [`resource::Resource`].
//! - **ResourceManager**: Central registry that tracks all resources and
//!   broadcasts lifecycle events. See [`manager::ResourceManager`].
//! - **Protocol**: Length-prefixed protobuf messages carrying commands,
//!   events, and streams. See [`protocol`].
//!
//! # Wire Format
//!
//! Messages are framed as:
//! - 4 bytes: u32 little-endian length prefix
//! - N bytes: protobuf-encoded `Message`
//!
//! The `Message` envelope contains one of:
//! - `Command`: Client-to-server requests
//! - `Event`: Server-to-client notifications (including command results)
//! - `Stream`: Bidirectional data (e.g., terminal I/O)

pub mod client;
pub mod commands;
pub mod manager;
pub mod protocol;
pub mod repl;
pub mod resource;
pub mod resources;
pub mod socket;

// Re-export main types from legacy interface
pub use client::ControlClient;
pub use commands::{
    handle_command, ConnectionState, ForwardAddCommand, SessionState, TerminalCommand,
    TerminalState,
};
pub use repl::{run_repl, list_sessions, discover_latest_session, SessionInfo};
pub use socket::{ControlSocket, ControlSocketGuard, ControlEvent, socket_path};

// Re-export new resource control types
pub use manager::ResourceManager;
pub use resource::{
    FailureReason, FileTransferDetails, ForwardDetails, ForwardType, Resource, ResourceDetails,
    ResourceError, ResourceEvent, ResourceInfo, ResourceKind, ResourceState, ResourceStats,
    StubResource, TerminalDetails,
};

// Re-export concrete resource implementations
pub use resources::{FileTransfer, Forward, ForwardParams, Terminal};
pub use protocol::{
    CommandBuilder, EventBuilder, ProtocolError, decode_message, encode_into, encode_message,
    resource_event_to_proto, resource_info_from_proto, resource_info_to_proto, stream_message,
    try_decode_message,
};

// Include generated protobuf types
pub(crate) mod proto {
    include!(concat!(env!("OUT_DIR"), "/qsh.control.rs"));
}

// Re-export commonly used protobuf types (legacy)
pub use proto::{
    ControlRequest, ControlResponse, ErrorResponse, ForwardAddRequest, ForwardAddResponse,
    ForwardInfo, ForwardListRequest, ForwardListResponse, ForwardRemoveRequest,
    ForwardRemoveResponse, GetStatusRequest, PingRequest, PongResponse, SessionInfoRequest,
    SessionInfoResponse, StatusResponse, TerminalCloseRequest, TerminalCloseResponse,
    TerminalInfo, TerminalListRequest, TerminalListResponse, TerminalOpenRequest,
    TerminalOpenResponse, TerminalResizeRequest, TerminalResizeResponse,
};

// Re-export new unified protocol types
pub use proto::{
    Command, CommandError, CommandOk, CommandResult, EnvPair, Event, ExitCmd,
    FileCancelCmd, FileDownloadCmd, FileTransferCreateParams, FileTransferOptions, FileUploadCmd,
    ForwardCreateParams, Message, PingCmd, ResourceClose, ResourceCreate, ResourceDescribe,
    ResourceDrain, ResourceForceClose, ResourceList, ResourceCreateResult, ResourceDescribeResult,
    ResourceListResult, SessionSummary, SessionsCmd, SessionsResult, StatusCmd, StatusResult,
    Stream, StreamDirection, StreamKind, TerminalAttachCmd, TerminalCreateParams,
    TerminalDetachCmd, TerminalResizeCmd,
};

// Re-export proto enums
pub use proto::{ErrorCode, ResourceKind as ProtoResourceKind, ResourceState as ProtoResourceState};
