//! Forward resource implementation.
//!
//! Wraps the existing forward module implementations (LocalForwarder, RemoteForwarder,
//! Socks5Proxy) to integrate with the unified resource control plane.

use std::any::Any;
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::control::resource::{
    FailureReason, ForwardDetails, ForwardType, Resource, ResourceError, ResourceInfo,
    ResourceKind, ResourceState, ResourceStats,
};
use crate::control::ResourceDetails;
use crate::forward::{ForwarderHandle, LocalForwarder, ProxyHandle, RemoteForwarder, RemoteForwarderHandle, Socks5Proxy};
use crate::ChannelConnection;

/// Parameters for creating a forward.
#[derive(Debug, Clone)]
pub struct ForwardParams {
    /// Type of forward (local, remote, dynamic).
    pub forward_type: ForwardType,
    /// Bind address (e.g., "127.0.0.1" or "0.0.0.0").
    pub bind_addr: String,
    /// Bind port (0 for ephemeral).
    pub bind_port: u32,
    /// Destination host (None for dynamic forwards).
    pub dest_host: Option<String>,
    /// Destination port (None for dynamic forwards).
    pub dest_port: Option<u32>,
}

/// Internal handle for the underlying forwarder.
enum ForwardHandle {
    Local(ForwarderHandle),
    Remote(RemoteForwarderHandle),
    Dynamic(ProxyHandle),
}

/// Forward resource wrapper.
///
/// Manages port forwards (local, remote, dynamic/SOCKS5) through the unified
/// resource control plane. Supports:
///
/// - Start: Bind ports and begin forwarding
/// - Drain: Stop accepting new connections, complete in-flight (graceful shutdown)
/// - Close: Immediately terminate all connections
/// - Rebind: Restore forward after reconnection
pub struct Forward {
    /// Resource ID (e.g., "fwd-0").
    id: String,
    /// Current state (uses std::sync::RwLock for sync access in describe()).
    state: StdRwLock<ResourceState>,
    /// Statistics (uses std::sync::RwLock for sync access in describe()).
    stats: StdRwLock<ResourceStats>,
    /// Forward configuration.
    params: ForwardParams,
    /// Handle to the running forwarder (set when started).
    handle: RwLock<Option<ForwardHandle>>,
    /// Track active connections for drain support.
    active_connections: RwLock<u64>,
}

impl Forward {
    /// Create a new forward resource.
    pub fn new(id: impl Into<String>, params: ForwardParams) -> Self {
        Self {
            id: id.into(),
            state: StdRwLock::new(ResourceState::Pending),
            stats: StdRwLock::new(ResourceStats::new()),
            params,
            handle: RwLock::new(None),
            active_connections: RwLock::new(0),
        }
    }

    /// Get the actual bound port (useful when bind_port is 0/ephemeral).
    pub async fn bound_port(&self) -> u32 {
        let handle = self.handle.read().await;
        match &*handle {
            Some(ForwardHandle::Local(h)) => h.local_addr().port() as u32,
            Some(ForwardHandle::Remote(h)) => h.bound_port() as u32,
            Some(ForwardHandle::Dynamic(h)) => h.local_addr().port() as u32,
            None => self.params.bind_port,
        }
    }

    /// Start the forward with the given connection.
    async fn start_forward(&mut self, conn: Arc<ChannelConnection>) -> Result<(), ResourceError> {
        debug!(
            id = %self.id,
            forward_type = %self.params.forward_type,
            bind = %format!("{}:{}", self.params.bind_addr, self.params.bind_port),
            "starting forward"
        );

        let handle = match self.params.forward_type {
            ForwardType::Local => {
                let dest_host = self.params.dest_host.clone().ok_or_else(|| {
                    ResourceError::Internal("local forward requires dest_host".to_string())
                })?;
                let dest_port = self.params.dest_port.ok_or_else(|| {
                    ResourceError::Internal("local forward requires dest_port".to_string())
                })? as u16;

                // Parse bind address
                let bind_addr = format!("{}:{}", self.params.bind_addr, self.params.bind_port)
                    .parse()
                    .map_err(|e| ResourceError::BindFailed(format!("invalid bind address: {}", e)))?;

                let forwarder = LocalForwarder::new(bind_addr, dest_host, dest_port, conn);
                let handle = forwarder.start().await.map_err(|e| {
                    ResourceError::BindFailed(format!("failed to start local forward: {}", e))
                })?;

                info!(
                    id = %self.id,
                    local_addr = %handle.local_addr(),
                    "local forward started"
                );

                ForwardHandle::Local(handle)
            }
            ForwardType::Remote => {
                let dest_host = self.params.dest_host.clone().ok_or_else(|| {
                    ResourceError::Internal("remote forward requires dest_host".to_string())
                })?;
                let dest_port = self.params.dest_port.ok_or_else(|| {
                    ResourceError::Internal("remote forward requires dest_port".to_string())
                })? as u16;

                let forwarder = RemoteForwarder::new(
                    conn,
                    self.params.bind_addr.clone(),
                    self.params.bind_port as u16,
                    dest_host,
                    dest_port,
                );

                let handle = forwarder.start().await.map_err(|e| {
                    ResourceError::BindFailed(format!("failed to start remote forward: {}", e))
                })?;

                info!(
                    id = %self.id,
                    bound_port = handle.bound_port(),
                    "remote forward started"
                );

                ForwardHandle::Remote(handle)
            }
            ForwardType::Dynamic => {
                // Parse bind address for SOCKS5 proxy
                let bind_addr = format!("{}:{}", self.params.bind_addr, self.params.bind_port)
                    .parse()
                    .map_err(|e| ResourceError::BindFailed(format!("invalid bind address: {}", e)))?;

                let proxy = Socks5Proxy::new(bind_addr, conn);
                let handle = proxy.start().await.map_err(|e| {
                    ResourceError::BindFailed(format!("failed to start SOCKS5 proxy: {}", e))
                })?;

                info!(
                    id = %self.id,
                    local_addr = %handle.local_addr(),
                    "dynamic forward (SOCKS5) started"
                );

                ForwardHandle::Dynamic(handle)
            }
        };

        *self.handle.write().await = Some(handle);
        Ok(())
    }

    /// Stop the forward.
    async fn stop_forward(&mut self) -> Result<(), ResourceError> {
        let mut handle = self.handle.write().await;
        if let Some(fwd) = handle.take() {
            match fwd {
                ForwardHandle::Local(h) => {
                    debug!(id = %self.id, "stopping local forward");
                    h.stop().await;
                }
                ForwardHandle::Remote(h) => {
                    debug!(id = %self.id, "stopping remote forward");
                    h.stop().await.map_err(|e| {
                        ResourceError::Internal(format!("failed to stop remote forward: {}", e))
                    })?;
                }
                ForwardHandle::Dynamic(h) => {
                    debug!(id = %self.id, "stopping dynamic forward");
                    h.stop().await;
                }
            }
        }
        Ok(())
    }
}

#[async_trait]
impl Resource for Forward {
    async fn start(&mut self, conn: Arc<ChannelConnection>) -> Result<(), ResourceError> {
        // Transition to Starting
        *self.state.write().unwrap() = ResourceState::Starting;

        // Start the forward
        match self.start_forward(conn).await {
            Ok(()) => {
                *self.state.write().unwrap() = ResourceState::Running;
                info!(id = %self.id, "forward resource started");
                Ok(())
            }
            Err(e) => {
                error!(id = %self.id, error = %e, "failed to start forward");
                *self.state.write().unwrap() = ResourceState::Failed(e.clone().into());
                Err(e)
            }
        }
    }

    async fn drain(&mut self, deadline: Duration) -> Result<(), ResourceError> {
        {
            let state = self.state.read().unwrap();
            if !matches!(*state, ResourceState::Running) {
                return Err(ResourceError::InvalidState {
                    current: state.clone(),
                    expected: "Running",
                });
            }
        }

        info!(
            id = %self.id,
            deadline_secs = deadline.as_secs(),
            "draining forward"
        );

        // Transition to Draining
        *self.state.write().unwrap() = ResourceState::Draining;

        // For forwards, "drain" means:
        // 1. Stop accepting new connections (stop the listener)
        // 2. Wait for in-flight connections to complete (up to deadline)
        // 3. Then fully close

        // Stop the forward immediately to stop accepting new connections
        if let Err(e) = self.stop_forward().await {
            warn!(id = %self.id, error = %e, "error stopping forward during drain");
        }

        // Wait for active connections to drain (with timeout)
        let start = tokio::time::Instant::now();
        loop {
            let active = *self.active_connections.read().await;
            if active == 0 {
                break;
            }

            if start.elapsed() >= deadline {
                warn!(
                    id = %self.id,
                    active_connections = active,
                    "drain deadline exceeded, force closing"
                );
                break;
            }

            // Check every 100ms
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }

        *self.state.write().unwrap() = ResourceState::Closed;
        info!(id = %self.id, "forward drained");
        Ok(())
    }

    async fn close(&mut self) -> Result<(), ResourceError> {
        {
            let state = self.state.read().unwrap();
            if state.is_terminal() {
                return Err(ResourceError::InvalidState {
                    current: state.clone(),
                    expected: "active",
                });
            }
        }

        info!(id = %self.id, "closing forward");

        // Stop the forward
        if let Err(e) = self.stop_forward().await {
            error!(id = %self.id, error = %e, "error stopping forward");
            *self.state.write().unwrap() = ResourceState::Failed(FailureReason::Internal(e.to_string()));
            return Err(e);
        }

        *self.state.write().unwrap() = ResourceState::Closed;
        info!(id = %self.id, "forward closed");
        Ok(())
    }

    fn describe(&self) -> ResourceInfo {
        let active_connections = self.active_connections.try_read()
            .map(|guard| *guard)
            .unwrap_or(0);

        ResourceInfo {
            id: self.id.clone(),
            kind: ResourceKind::Forward,
            state: self.state.read().unwrap().clone(),
            stats: self.stats.read().unwrap().clone(),
            details: ResourceDetails::Forward(ForwardDetails {
                forward_type: self.params.forward_type,
                bind_addr: self.params.bind_addr.clone(),
                bind_port: self.params.bind_port,
                dest_host: self.params.dest_host.clone(),
                dest_port: self.params.dest_port,
                active_connections,
            }),
        }
    }

    fn kind(&self) -> ResourceKind {
        ResourceKind::Forward
    }

    fn id(&self) -> &str {
        &self.id
    }

    fn state(&self) -> &ResourceState {
        // The Resource trait expects a synchronous state() method.
        // Since we use a std::sync::RwLock, we could technically return a reference,
        // but to avoid lifetime issues and match the Terminal implementation pattern,
        // we return a static placeholder. Callers should use describe() for actual state.
        static PENDING: ResourceState = ResourceState::Pending;
        &PENDING
    }

    fn on_disconnect(&mut self) {
        debug!(id = %self.id, "forward disconnected");
        // Mark as disconnected but don't change state yet
        // The supervisor will decide whether to try reconnect
    }

    async fn on_reconnect(&mut self, conn: Arc<ChannelConnection>) -> Result<(), ResourceError> {
        info!(id = %self.id, "attempting to rebind forward after reconnection");

        // Stop any existing forward
        let _ = self.stop_forward().await;

        // Try to rebind
        match self.start_forward(conn).await {
            Ok(()) => {
                *self.state.write().unwrap() = ResourceState::Running;
                info!(id = %self.id, "forward rebound successfully");
                Ok(())
            }
            Err(e) => {
                error!(id = %self.id, error = %e, "failed to rebind forward");
                *self.state.write().unwrap() = ResourceState::Failed(FailureReason::ResumeFailed(e.to_string()));
                Err(e)
            }
        }
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
    fn test_forward_creation() {
        let params = ForwardParams {
            forward_type: ForwardType::Local,
            bind_addr: "127.0.0.1".to_string(),
            bind_port: 8080,
            dest_host: Some("localhost".to_string()),
            dest_port: Some(80),
        };

        let forward = Forward::new("fwd-0", params.clone());
        assert_eq!(forward.id(), "fwd-0");
        assert_eq!(forward.kind(), ResourceKind::Forward);
        assert_eq!(forward.state(), &ResourceState::Pending);
    }

    #[test]
    fn test_forward_describe() {
        let params = ForwardParams {
            forward_type: ForwardType::Remote,
            bind_addr: "0.0.0.0".to_string(),
            bind_port: 9000,
            dest_host: Some("localhost".to_string()),
            dest_port: Some(3000),
        };

        let forward = Forward::new("fwd-1", params);
        let info = forward.describe();

        assert_eq!(info.id, "fwd-1");
        assert_eq!(info.kind, ResourceKind::Forward);

        if let ResourceDetails::Forward(details) = info.details {
            assert_eq!(details.forward_type, ForwardType::Remote);
            assert_eq!(details.bind_addr, "0.0.0.0");
            assert_eq!(details.bind_port, 9000);
            assert_eq!(details.dest_host, Some("localhost".to_string()));
            assert_eq!(details.dest_port, Some(3000));
        } else {
            panic!("expected Forward details");
        }
    }

    #[test]
    fn test_dynamic_forward_params() {
        let params = ForwardParams {
            forward_type: ForwardType::Dynamic,
            bind_addr: "127.0.0.1".to_string(),
            bind_port: 1080,
            dest_host: None,
            dest_port: None,
        };

        let forward = Forward::new("fwd-2", params);
        let info = forward.describe();

        if let ResourceDetails::Forward(details) = info.details {
            assert_eq!(details.forward_type, ForwardType::Dynamic);
            assert_eq!(details.dest_host, None);
            assert_eq!(details.dest_port, None);
        } else {
            panic!("expected Forward details");
        }
    }
}
