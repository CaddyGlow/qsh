//! Resource trait and types for the unified resource control system.
//!
//! This module defines the core abstractions for managing resources (terminals,
//! forwards, file transfers) through a unified control plane:
//!
//! - `Resource` trait: Common interface for all manageable resources
//! - `ResourceState`: Lifecycle state machine (Pending -> Running -> Closed/Failed)
//! - `ResourceEvent`: Events emitted during resource lifecycle
//! - `ResourceInfo`: Descriptive information about a resource
//! - `ResourceKind`: Type discriminant for resources

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::ChannelConnection;

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
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
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

/// Core trait for manageable resources.
///
/// All resources (terminals, forwards, file transfers) implement this trait
/// to participate in the unified control plane. Resources are managed by the
/// `ResourceManager` and driven by the `SessionSupervisor`.
///
/// # Lifecycle
///
/// 1. Resource is created in `Pending` state
/// 2. `start()` is called, transitioning to `Starting` then `Running`
/// 3. `drain()` can be called to gracefully wind down
/// 4. `close()` terminates the resource
///
/// # Thread Safety
///
/// Resources must be `Send + Sync` to allow management from multiple tasks.
#[async_trait]
pub trait Resource: Send + Sync + 'static {
    /// Start the resource.
    ///
    /// Called after the resource is added to the manager. The resource should
    /// transition from Pending -> Starting -> Running, emitting events.
    ///
    /// The connection is provided for resources that need to open channels.
    async fn start(&mut self, conn: Arc<ChannelConnection>) -> Result<(), ResourceError>;

    /// Gracefully drain the resource.
    ///
    /// Stop accepting new work but allow existing operations to complete.
    /// The deadline specifies how long to wait before forcing closure.
    async fn drain(&mut self, deadline: Duration) -> Result<(), ResourceError>;

    /// Close the resource immediately.
    ///
    /// Terminate all operations and release resources.
    async fn close(&mut self) -> Result<(), ResourceError>;

    /// Get descriptive information about this resource.
    fn describe(&self) -> ResourceInfo;

    /// Get the resource kind.
    fn kind(&self) -> ResourceKind;

    /// Get the resource ID.
    fn id(&self) -> &str;

    /// Get the current state.
    fn state(&self) -> &ResourceState;

    /// Called when the connection is lost.
    ///
    /// Resources can update their state accordingly (e.g., mark as failed
    /// or prepare for reconnection).
    fn on_disconnect(&mut self);

    /// Called when the connection is restored.
    ///
    /// Resources can attempt to rebind/resume. Returns Ok if successful,
    /// Err if the resource should be marked as failed.
    async fn on_reconnect(&mut self, conn: Arc<ChannelConnection>) -> Result<(), ResourceError>;
}

/// Errors that can occur during resource operations.
#[derive(Debug, Clone)]
pub enum ResourceError {
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

// ============================================================================
// Stub Resource Implementation (for testing and as a template)
// ============================================================================

/// A stub resource implementation for testing trait bounds and as a template.
///
/// This implementation:
/// - Tracks state transitions
/// - Supports configurable start/drain/close behavior
/// - Can simulate failures
///
/// Useful for:
/// - Unit testing ResourceManager
/// - Integration testing without real resources
/// - Template for implementing actual resources
#[derive(Debug)]
pub struct StubResource {
    id: String,
    kind: ResourceKind,
    state: ResourceState,
    stats: ResourceStats,
    /// If set, start() will return this error.
    pub start_error: Option<ResourceError>,
    /// If set, drain() will return this error.
    pub drain_error: Option<ResourceError>,
    /// If set, close() will return this error.
    pub close_error: Option<ResourceError>,
    /// If set, on_reconnect() will return this error.
    pub reconnect_error: Option<ResourceError>,
}

impl StubResource {
    /// Create a new stub resource with the given ID and kind.
    pub fn new(id: impl Into<String>, kind: ResourceKind) -> Self {
        Self {
            id: id.into(),
            kind,
            state: ResourceState::Pending,
            stats: ResourceStats::new(),
            start_error: None,
            drain_error: None,
            close_error: None,
            reconnect_error: None,
        }
    }

    /// Create a stub terminal resource.
    pub fn terminal(id: impl Into<String>) -> Self {
        Self::new(id, ResourceKind::Terminal)
    }

    /// Create a stub forward resource.
    pub fn forward(id: impl Into<String>) -> Self {
        Self::new(id, ResourceKind::Forward)
    }

    /// Create a stub file transfer resource.
    pub fn file_transfer(id: impl Into<String>) -> Self {
        Self::new(id, ResourceKind::FileTransfer)
    }

    /// Configure the resource to fail on start.
    pub fn with_start_error(mut self, err: ResourceError) -> Self {
        self.start_error = Some(err);
        self
    }

    /// Configure the resource to fail on drain.
    pub fn with_drain_error(mut self, err: ResourceError) -> Self {
        self.drain_error = Some(err);
        self
    }

    /// Configure the resource to fail on close.
    pub fn with_close_error(mut self, err: ResourceError) -> Self {
        self.close_error = Some(err);
        self
    }

    /// Configure the resource to fail on reconnect.
    pub fn with_reconnect_error(mut self, err: ResourceError) -> Self {
        self.reconnect_error = Some(err);
        self
    }

    /// Set the resource ID (useful when manager assigns IDs).
    pub fn set_id(&mut self, id: String) {
        self.id = id;
    }
}

#[async_trait]
impl Resource for StubResource {
    async fn start(&mut self, _conn: Arc<ChannelConnection>) -> Result<(), ResourceError> {
        if let Some(err) = self.start_error.take() {
            self.state = ResourceState::Failed(err.clone().into());
            return Err(err);
        }
        self.state = ResourceState::Running;
        Ok(())
    }

    async fn drain(&mut self, _deadline: Duration) -> Result<(), ResourceError> {
        if let Some(err) = self.drain_error.take() {
            self.state = ResourceState::Failed(err.clone().into());
            return Err(err);
        }
        self.state = ResourceState::Draining;
        // In a real implementation, we'd wait for work to complete
        self.state = ResourceState::Closed;
        Ok(())
    }

    async fn close(&mut self) -> Result<(), ResourceError> {
        if let Some(err) = self.close_error.take() {
            self.state = ResourceState::Failed(err.clone().into());
            return Err(err);
        }
        self.state = ResourceState::Closed;
        Ok(())
    }

    fn describe(&self) -> ResourceInfo {
        ResourceInfo {
            id: self.id.clone(),
            kind: self.kind,
            state: self.state.clone(),
            stats: self.stats.clone(),
            details: match self.kind {
                ResourceKind::Terminal => ResourceDetails::Terminal(TerminalDetails {
                    cols: 80,
                    rows: 24,
                    shell: "/bin/bash".to_string(),
                    attached: false,
                    pid: None,
                }),
                ResourceKind::Forward => ResourceDetails::Forward(ForwardDetails {
                    forward_type: ForwardType::Local,
                    bind_addr: "127.0.0.1".to_string(),
                    bind_port: 8080,
                    dest_host: Some("localhost".to_string()),
                    dest_port: Some(80),
                    active_connections: 0,
                }),
                ResourceKind::FileTransfer => ResourceDetails::FileTransfer(FileTransferDetails {
                    local_path: "/tmp/test".to_string(),
                    remote_path: "/home/user/test".to_string(),
                    upload: true,
                    total_bytes: 1024,
                    transferred_bytes: 0,
                    files_total: 1,
                    files_done: 0,
                    files_failed: 0,
                }),
            },
        }
    }

    fn kind(&self) -> ResourceKind {
        self.kind
    }

    fn id(&self) -> &str {
        &self.id
    }

    fn state(&self) -> &ResourceState {
        &self.state
    }

    fn on_disconnect(&mut self) {
        // Stub does nothing on disconnect
    }

    async fn on_reconnect(&mut self, _conn: Arc<ChannelConnection>) -> Result<(), ResourceError> {
        if let Some(err) = self.reconnect_error.take() {
            return Err(err);
        }
        Ok(())
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
