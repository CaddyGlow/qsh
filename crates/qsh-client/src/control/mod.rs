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
//!   events, and streams. See [`qsh_control::protocol`].
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

// Client-specific modules
pub mod attachment;
pub mod commands;
pub mod manager;
pub mod repl;
pub mod resource;
pub mod resources;

// Re-export attachment types
pub use attachment::{AttachError, AttachmentRegistry};

// Re-export command types (client-specific)
pub use commands::{
    ConnectionState, ForwardAddCommand, SessionState, TerminalAttachChannels, TerminalCommand,
    TerminalState,
};

// Re-export REPL
pub use repl::{discover_latest_session, list_sessions, run_repl, SessionInfo};

// Re-export manager
pub use manager::ResourceManager;

// Re-export Resource trait and StubResource from local module (client-specific)
pub use resource::{Resource, StubResource};

// Re-export concrete resource implementations
pub use resources::{FileTransfer, Forward, ForwardParams, Terminal};

// =============================================================================
// Re-exports from qsh-control (shared protocol layer)
// =============================================================================

// Re-export control client and socket types
pub use qsh_control::{
    ControlClient, ControlEvent, ControlSocket, ControlSocketGuard, session_dir, socket_path,
    SocketError, SocketResult,
};

// Re-export protocol codec functions
pub use qsh_control::{
    decode_message, encode_into, encode_message, resource_event_to_proto,
    resource_info_from_proto, resource_info_to_proto, stream_message, try_decode_message,
    CommandBuilder, EventBuilder, ProtocolError,
};

// Re-export protocol types (from qsh-control::types)
pub use qsh_control::{
    FailureReason, FileTransferDetails, ForwardDetails, ForwardType, OutputMode, ResourceDetails,
    ResourceError, ResourceEvent, ResourceInfo, ResourceKind, ResourceState, ResourceStats,
    TerminalDetails,
};

// Re-export proto module and commonly used proto types
pub use qsh_control::proto;
pub use qsh_control::{
    Command, CommandError, CommandOk, CommandResult, EnvPair, EnrollCmd, EnrollResult, ErrorCode,
    Event, ExitCmd, FileCancelCmd, FileDownloadCmd, FileTransferCreateParams, FileTransferOptions,
    FileUploadCmd, ForwardCreateParams, Message, PingCmd, PongResult, ResourceClose,
    ResourceCreate, ResourceCreateResult, ResourceDescribe, ResourceDescribeResult, ResourceDrain,
    ResourceForceClose, ResourceList, ResourceListResult, SessionSummary, SessionsCmd,
    SessionsResult, StatusCmd, StatusResult, Stream, StreamDirection, StreamKind,
    TerminalAttachCmd, TerminalAttachResult, TerminalCreateParams, TerminalDetachCmd,
    TerminalResizeCmd,
};

// Re-export proto enums with aliases for backwards compatibility
pub use qsh_control::{
    ProtoForwardType, ProtoOutputMode, ProtoResourceKind, ProtoResourceState,
};
