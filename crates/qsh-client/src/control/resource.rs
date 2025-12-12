//! Resource trait for the unified resource control system.
//!
//! This module defines the core abstraction for managing resources (terminals,
//! forwards, file transfers) through a unified control plane:
//!
//! - `Resource` trait: Common interface for all manageable resources
//! - `StubResource`: Test implementation for unit testing
//!
//! Protocol types (ResourceKind, ResourceState, etc.) are provided by qsh-control.

use std::any::Any;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::ChannelConnection;

// Re-export protocol types from qsh-control for use in this module and by consumers
pub use qsh_control::{
    FailureReason, FileTransferDetails, ForwardDetails, ForwardType, OutputMode, ResourceDetails,
    ResourceError, ResourceEvent, ResourceInfo, ResourceKind, ResourceState, ResourceStats,
    TerminalDetails,
};

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

    /// Return self as Any for downcasting to concrete types.
    ///
    /// This allows accessing resource-specific methods like Terminal::attach().
    fn as_any(&self) -> &dyn Any;

    /// Return self as mutable Any for downcasting to concrete types.
    fn as_any_mut(&mut self) -> &mut dyn Any;
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
                    socket_path: None,
                    term_type: "xterm-256color".to_string(),
                    command: None,
                    output_mode: OutputMode::Direct,
                    allocate_pty: true,
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

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
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
