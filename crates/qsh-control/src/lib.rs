//! Shared control protocol for qsh - Unix socket IPC and resource management.
//!
//! This crate provides the protocol layer for qsh control sockets, used by
//! both qsh-client and qsh-server for local session management and monitoring.
//!
//! # Architecture
//!
//! The control system uses a unified resource model:
//!
//! - **Protocol**: Length-prefixed protobuf messages carrying commands, events,
//!   and streams. See [`protocol`].
//! - **Types**: Protocol-only types for resources, states, and events. See [`types`].
//! - **Socket**: Unix socket server for multi-client handling. See [`socket`].
//! - **Client**: Async client for connecting to control sockets. See [`client`].
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
//!
//! # Socket Paths
//!
//! - Client session socket: `$XDG_RUNTIME_DIR/qsh/<session>.sock`
//! - Server control socket: `$XDG_RUNTIME_DIR/qsh/server.sock`
//! - Fallback: `/tmp/qsh-<uid>-<name>.sock`

pub mod client;
pub mod protocol;
pub mod socket;
pub mod types;

// Include generated protobuf types
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/qsh.control.rs"));
}

// Re-export main types from client
pub use client::ControlClient;

// Re-export socket types
pub use socket::{
    bind_server_socket, create_socket, server_socket_path, session_dir, socket_path,
    ControlEvent, ControlSocket, ControlSocketGuard, SocketError, SocketResult,
    try_connect_server_socket,
};

// Re-export protocol types and helpers
pub use protocol::{
    decode_message, encode_into, encode_message, resource_event_to_proto,
    resource_info_from_proto, resource_info_to_proto, stream_message, try_decode_message,
    CommandBuilder, EventBuilder, ProtocolError, MAX_MESSAGE_SIZE,
};

// Re-export resource/protocol types
pub use types::{
    FailureReason, FileTransferDetails, ForwardDetails, ForwardType, OutputMode, ResourceDetails,
    ResourceError, ResourceEvent, ResourceInfo, ResourceKind, ResourceState, ResourceStats,
    TerminalDetails,
};

// Re-export commonly used proto types
pub use proto::{
    command, command_ok, command_result, event, message, Command, CommandError, CommandOk,
    CommandResult, EnrollCmd, EnrollResult, EnvPair, ErrorCode, Event, ExitCmd, FileCancelCmd,
    FileDownloadCmd, FileTransferCreateParams, FileTransferOptions, FileUploadCmd,
    ForwardCreateParams, Message, PingCmd, PongResult, ResourceClose, ResourceCreate,
    ResourceCreateResult, ResourceDescribe, ResourceDescribeResult, ResourceDrain,
    ResourceForceClose, ResourceList, ResourceListResult, SessionSummary, SessionsCmd,
    SessionsResult, StatusCmd, StatusResult, Stream, StreamDirection, StreamKind,
    TerminalAttachCmd, TerminalAttachResult, TerminalCreateParams, TerminalDetachCmd,
    TerminalResizeCmd,
};

// Re-export proto enums
pub use proto::{
    ForwardType as ProtoForwardType, OutputMode as ProtoOutputMode,
    ResourceKind as ProtoResourceKind, ResourceState as ProtoResourceState,
};
