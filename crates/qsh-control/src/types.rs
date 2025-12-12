//! Protocol-only types for the unified resource control system.
//!
//! This module defines the data types used in the control protocol:
//!
//! - `ResourceKind`: Type discriminant for resources
//! - `ResourceState`: Lifecycle state machine (Pending -> Running -> Closed/Failed)
//! - `ResourceEvent`: Events emitted during resource lifecycle
//! - `ResourceInfo`: Descriptive information about a resource
//!
//! Note: The `Resource` trait is NOT included here - it belongs in qsh-client
//! because it depends on client-specific connection types.

use std::time::SystemTime;

// Re-export OutputMode from qsh-core for use in TerminalDetails
pub use qsh_core::protocol::OutputMode;

/// Resource kinds supported by the control plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceKind {
    Terminal,
    Forward,
    FileTransfer,
}

impl ResourceKind {
    /// Get the prefix used for resource IDs of this kind.
    pub fn id_prefix(&self) -> &'static str {
        match self {
            ResourceKind::Terminal => "term",
            ResourceKind::Forward => "fwd",
            ResourceKind::FileTransfer => "xfer",
        }
    }

    /// Parse a resource kind from an ID prefix.
    pub fn from_id_prefix(prefix: &str) -> Option<Self> {
        match prefix {
            "term" => Some(ResourceKind::Terminal),
            "fwd" => Some(ResourceKind::Forward),
            "xfer" => Some(ResourceKind::FileTransfer),
            _ => None,
        }
    }
}

impl std::fmt::Display for ResourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResourceKind::Terminal => write!(f, "terminal"),
            ResourceKind::Forward => write!(f, "forward"),
            ResourceKind::FileTransfer => write!(f, "file_transfer"),
        }
    }
}

/// Resource lifecycle states.
///
/// State transitions:
/// ```text
/// Pending -> Starting -> Running -> Draining -> Closed
///                    \                      \-> Failed(reason)
///                     \-> Failed(reason)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceState {
    /// Resource created but not yet started.
    Pending,
    /// Resource is starting up (e.g., binding ports, spawning process).
    Starting,
    /// Resource is running and operational.
    Running,
    /// Resource is draining (no new work, finishing existing).
    Draining,
    /// Resource has been cleanly closed.
    Closed,
    /// Resource failed with a reason.
    Failed(FailureReason),
}

impl ResourceState {
    /// Check if this is a terminal state (Closed or Failed).
    pub fn is_terminal(&self) -> bool {
        matches!(self, ResourceState::Closed | ResourceState::Failed(_))
    }

    /// Check if the resource is active (not terminal).
    pub fn is_active(&self) -> bool {
        !self.is_terminal()
    }

    /// Check if the resource is operational (Running).
    pub fn is_running(&self) -> bool {
        matches!(self, ResourceState::Running)
    }
}

impl std::fmt::Display for ResourceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResourceState::Pending => write!(f, "pending"),
            ResourceState::Starting => write!(f, "starting"),
            ResourceState::Running => write!(f, "running"),
            ResourceState::Draining => write!(f, "draining"),
            ResourceState::Closed => write!(f, "closed"),
            ResourceState::Failed(reason) => write!(f, "failed: {}", reason),
        }
    }
}

/// Reasons for resource failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailureReason {
    /// Failed to bind to requested address/port.
    BindFailed(String),
    /// Failed to resume after reconnection.
    ResumeFailed(String),
    /// Connection was lost.
    Disconnected(String),
    /// User or system cancelled the operation.
    Cancelled,
    /// Operation timed out.
    Timeout,
    /// Internal error.
    Internal(String),
    /// Resource already up to date (file transfer specific).
    AlreadyUpToDate,
    /// Connection to remote failed.
    ConnectFailed(String),
    /// Process exited unexpectedly.
    ProcessExited(Option<i32>),
    /// Custom failure reason.
    Other(String),
}

impl std::fmt::Display for FailureReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FailureReason::BindFailed(msg) => write!(f, "bind failed: {}", msg),
            FailureReason::ResumeFailed(msg) => write!(f, "resume failed: {}", msg),
            FailureReason::Disconnected(msg) => write!(f, "disconnected: {}", msg),
            FailureReason::Cancelled => write!(f, "cancelled"),
            FailureReason::Timeout => write!(f, "timeout"),
            FailureReason::Internal(msg) => write!(f, "internal error: {}", msg),
            FailureReason::AlreadyUpToDate => write!(f, "already up to date"),
            FailureReason::ConnectFailed(msg) => write!(f, "connect failed: {}", msg),
            FailureReason::ProcessExited(code) => match code {
                Some(c) => write!(f, "process exited with code {}", c),
                None => write!(f, "process exited"),
            },
            FailureReason::Other(msg) => write!(f, "{}", msg),
        }
    }
}

/// Statistics tracked for a resource.
#[derive(Debug, Clone, Default)]
pub struct ResourceStats {
    /// When the resource was created (Unix timestamp milliseconds).
    pub created_at: u64,
    /// Bytes received by this resource.
    pub bytes_in: u64,
    /// Bytes sent by this resource.
    pub bytes_out: u64,
}

impl ResourceStats {
    /// Create stats with the current timestamp.
    pub fn new() -> Self {
        Self {
            created_at: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            bytes_in: 0,
            bytes_out: 0,
        }
    }

    /// Record bytes received.
    pub fn record_bytes_in(&mut self, n: u64) {
        self.bytes_in = self.bytes_in.saturating_add(n);
    }

    /// Record bytes sent.
    pub fn record_bytes_out(&mut self, n: u64) {
        self.bytes_out = self.bytes_out.saturating_add(n);
    }
}

/// Information about a resource for listing/describing.
#[derive(Debug, Clone)]
pub struct ResourceInfo {
    /// Resource ID (e.g., "term-0", "fwd-1").
    pub id: String,
    /// Resource kind.
    pub kind: ResourceKind,
    /// Current state.
    pub state: ResourceState,
    /// Statistics.
    pub stats: ResourceStats,
    /// Kind-specific details.
    pub details: ResourceDetails,
}

/// Kind-specific resource details.
#[derive(Debug, Clone)]
pub enum ResourceDetails {
    Terminal(TerminalDetails),
    Forward(ForwardDetails),
    FileTransfer(FileTransferDetails),
}

/// Terminal-specific details.
#[derive(Debug, Clone, Default)]
pub struct TerminalDetails {
    pub cols: u32,
    pub rows: u32,
    pub shell: String,
    pub attached: bool,
    pub pid: Option<u64>,
    /// Path to the I/O socket for raw terminal access.
    pub socket_path: Option<String>,
    // Creation config
    pub term_type: String,
    pub command: Option<String>,
    pub output_mode: OutputMode,
    pub allocate_pty: bool,
}

/// Forward-specific details.
#[derive(Debug, Clone)]
pub struct ForwardDetails {
    pub forward_type: ForwardType,
    pub bind_addr: String,
    pub bind_port: u32,
    pub dest_host: Option<String>,
    pub dest_port: Option<u32>,
    pub active_connections: u64,
}

/// Forward types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardType {
    Local,
    Remote,
    Dynamic,
}

impl std::fmt::Display for ForwardType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ForwardType::Local => write!(f, "local"),
            ForwardType::Remote => write!(f, "remote"),
            ForwardType::Dynamic => write!(f, "dynamic"),
        }
    }
}

/// File transfer-specific details.
#[derive(Debug, Clone, Default)]
pub struct FileTransferDetails {
    pub local_path: String,
    pub remote_path: String,
    pub upload: bool,
    pub total_bytes: u64,
    pub transferred_bytes: u64,
    pub files_total: u32,
    pub files_done: u32,
    pub files_failed: u32,
}

/// Events emitted by resources during their lifecycle.
///
/// These events are broadcast to all control clients for state tracking.
#[derive(Debug, Clone)]
pub struct ResourceEvent {
    /// Resource ID.
    pub id: String,
    /// Resource kind.
    pub kind: ResourceKind,
    /// New state.
    pub state: ResourceState,
    /// Current statistics.
    pub stats: ResourceStats,
    /// Event sequence number (monotonic per session).
    pub event_seq: u64,
}

impl ResourceEvent {
    /// Create a new resource event.
    pub fn new(
        id: String,
        kind: ResourceKind,
        state: ResourceState,
        stats: ResourceStats,
        event_seq: u64,
    ) -> Self {
        Self {
            id,
            kind,
            state,
            stats,
            event_seq,
        }
    }
}

/// Errors that can occur during resource operations.
#[derive(Debug, Clone)]
pub enum ResourceError {
    /// Resource not found.
    NotFound(String),
    /// Resource is in wrong state for the operation.
    InvalidState { current: ResourceState, expected: &'static str },
    /// Bind operation failed.
    BindFailed(String),
    /// Connection operation failed.
    ConnectFailed(String),
    /// I/O error (stores error message since std::io::Error is not Clone).
    Io(String),
    /// Operation timed out.
    Timeout,
    /// Resource was cancelled.
    Cancelled,
    /// Internal error.
    Internal(String),
}

impl std::fmt::Display for ResourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResourceError::NotFound(id) => write!(f, "resource not found: {}", id),
            ResourceError::InvalidState { current, expected } => {
                write!(f, "invalid state: {} (expected {})", current, expected)
            }
            ResourceError::BindFailed(msg) => write!(f, "bind failed: {}", msg),
            ResourceError::ConnectFailed(msg) => write!(f, "connect failed: {}", msg),
            ResourceError::Io(msg) => write!(f, "I/O error: {}", msg),
            ResourceError::Timeout => write!(f, "operation timed out"),
            ResourceError::Cancelled => write!(f, "operation cancelled"),
            ResourceError::Internal(msg) => write!(f, "internal error: {}", msg),
        }
    }
}

impl std::error::Error for ResourceError {}

impl From<std::io::Error> for ResourceError {
    fn from(e: std::io::Error) -> Self {
        ResourceError::Io(e.to_string())
    }
}

impl From<ResourceError> for FailureReason {
    fn from(e: ResourceError) -> Self {
        match e {
            ResourceError::NotFound(id) => FailureReason::Internal(format!("not found: {}", id)),
            ResourceError::InvalidState { current, .. } => {
                FailureReason::Internal(format!("invalid state: {}", current))
            }
            ResourceError::BindFailed(msg) => FailureReason::BindFailed(msg),
            ResourceError::ConnectFailed(msg) => FailureReason::ConnectFailed(msg),
            ResourceError::Io(msg) => FailureReason::Internal(msg),
            ResourceError::Timeout => FailureReason::Timeout,
            ResourceError::Cancelled => FailureReason::Cancelled,
            ResourceError::Internal(msg) => FailureReason::Internal(msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_kind_id_prefix_roundtrip() {
        for kind in [ResourceKind::Terminal, ResourceKind::Forward, ResourceKind::FileTransfer] {
            let prefix = kind.id_prefix();
            let parsed = ResourceKind::from_id_prefix(prefix);
            assert_eq!(parsed, Some(kind));
        }
    }

    #[test]
    fn resource_state_is_terminal() {
        assert!(!ResourceState::Pending.is_terminal());
        assert!(!ResourceState::Starting.is_terminal());
        assert!(!ResourceState::Running.is_terminal());
        assert!(!ResourceState::Draining.is_terminal());
        assert!(ResourceState::Closed.is_terminal());
        assert!(ResourceState::Failed(FailureReason::Cancelled).is_terminal());
    }

    #[test]
    fn resource_state_display() {
        assert_eq!(ResourceState::Pending.to_string(), "pending");
        assert_eq!(ResourceState::Running.to_string(), "running");
        assert_eq!(
            ResourceState::Failed(FailureReason::Timeout).to_string(),
            "failed: timeout"
        );
    }

    #[test]
    fn resource_stats_tracking() {
        let mut stats = ResourceStats::new();
        assert!(stats.created_at > 0);

        stats.record_bytes_in(100);
        stats.record_bytes_out(50);

        assert_eq!(stats.bytes_in, 100);
        assert_eq!(stats.bytes_out, 50);

        // Test saturation
        stats.bytes_in = u64::MAX;
        stats.record_bytes_in(1);
        assert_eq!(stats.bytes_in, u64::MAX);
    }

    #[test]
    fn failure_reason_display() {
        assert_eq!(FailureReason::Cancelled.to_string(), "cancelled");
        assert_eq!(FailureReason::Timeout.to_string(), "timeout");
        assert_eq!(
            FailureReason::BindFailed("address in use".to_string()).to_string(),
            "bind failed: address in use"
        );
    }
}
