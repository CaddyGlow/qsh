//! Resource manager for the unified control plane.
//!
//! The `ResourceManager` is the central registry for all resources in a session.
//! It provides:
//!
//! - Resource registration with auto-generated IDs
//! - Resource lookup by ID
//! - Resource lifecycle management (start, drain, close)
//! - Event broadcasting to control clients
//!
//! # Example
//!
//! ```ignore
//! let (manager, mut event_rx) = ResourceManager::new();
//!
//! // Add a resource
//! let id = manager.add(my_terminal).await?;
//!
//! // Start it
//! manager.start(&id, connection).await?;
//!
//! // Listen for events
//! while let Ok(event) = event_rx.recv().await {
//!     println!("Resource {} is now {:?}", event.id, event.state);
//! }
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{broadcast, RwLock};
use tracing::{debug, error, info, warn};

use super::resource::{
    FailureReason, Resource, ResourceError, ResourceEvent, ResourceInfo, ResourceKind,
    ResourceState, ResourceStats,
};
use super::resources::Terminal;
use crate::ChannelConnection;

/// Channel capacity for the event broadcast.
const EVENT_CHANNEL_CAPACITY: usize = 256;

/// Default drain timeout in seconds.
const DEFAULT_DRAIN_TIMEOUT_SECS: u64 = 30;

/// Manages all resources in a session.
///
/// Thread-safe registry of resources with event broadcasting. Resources are
/// stored behind an `Arc<RwLock<>>` to allow concurrent access from the
/// supervisor's select loop and control command handlers.
pub struct ResourceManager {
    /// Resources indexed by ID.
    resources: Arc<RwLock<HashMap<String, Box<dyn Resource>>>>,
    /// Per-kind ID counters for generating unique IDs.
    id_counters: Arc<RwLock<HashMap<ResourceKind, u64>>>,
    /// Event broadcast sender.
    event_tx: broadcast::Sender<ResourceEvent>,
    /// Monotonic event sequence counter.
    event_seq: Arc<RwLock<u64>>,
}

impl ResourceManager {
    /// Create a new resource manager.
    ///
    /// Returns the manager and a receiver for resource events.
    pub fn new() -> (Self, broadcast::Receiver<ResourceEvent>) {
        let (event_tx, event_rx) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        let manager = Self {
            resources: Arc::new(RwLock::new(HashMap::new())),
            id_counters: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
            event_seq: Arc::new(RwLock::new(0)),
        };
        (manager, event_rx)
    }

    /// Subscribe to resource events.
    ///
    /// Returns a new receiver for the event broadcast.
    pub fn subscribe(&self) -> broadcast::Receiver<ResourceEvent> {
        self.event_tx.subscribe()
    }

    /// Generate a unique ID for a resource of the given kind.
    ///
    /// IDs follow the format `{kind_prefix}-{n}` (e.g., "term-0", "fwd-1").
    async fn generate_id(&self, kind: ResourceKind) -> String {
        let mut counters = self.id_counters.write().await;
        let counter = counters.entry(kind).or_insert(0);
        let id = format!("{}-{}", kind.id_prefix(), counter);
        *counter += 1;
        id
    }

    /// Get the next event sequence number.
    pub async fn next_event_seq(&self) -> u64 {
        let mut seq = self.event_seq.write().await;
        let current = *seq;
        *seq += 1;
        current
    }

    /// Emit a resource event.
    async fn emit_event(&self, id: &str, kind: ResourceKind, state: ResourceState, stats: ResourceStats) {
        let event_seq = self.next_event_seq().await;
        let event = ResourceEvent::new(id.to_string(), kind, state, stats, event_seq);

        debug!(
            resource_id = %id,
            state = %event.state,
            event_seq = event_seq,
            "emitting resource event"
        );

        // Ignore send errors (no receivers is fine)
        let _ = self.event_tx.send(event);
    }

    /// Add a resource to the manager.
    ///
    /// The resource is assigned a unique ID and stored in the Pending state.
    /// Call `start()` to begin resource operation.
    ///
    /// Returns the assigned resource ID.
    pub async fn add(&self, resource: Box<dyn Resource>) -> String {
        let kind = resource.kind();
        let id = self.generate_id(kind).await;

        info!(resource_id = %id, kind = %kind, "adding resource");

        // Store the resource
        {
            let mut resources = self.resources.write().await;
            resources.insert(id.clone(), resource);
        }

        // Emit event
        self.emit_event(&id, kind, ResourceState::Pending, ResourceStats::new()).await;

        id
    }

    /// Add a resource using a factory function.
    ///
    /// The factory receives the generated resource ID and should return the resource.
    /// This allows resources that need their ID at construction time.
    pub async fn add_with_factory<F>(&self, kind: ResourceKind, factory: F) -> Result<String, ResourceError>
    where
        F: FnOnce(String) -> Box<dyn Resource>,
    {
        let id = self.generate_id(kind).await;
        let resource = factory(id.clone());

        // Store the resource
        {
            let mut resources = self.resources.write().await;
            resources.insert(id.clone(), resource);
        }

        info!(resource_id = %id, kind = %kind, "adding resource via factory");
        self.emit_event(&id, kind, ResourceState::Pending, ResourceStats::new()).await;

        Ok(id)
    }

    /// Add a resource with a specific ID.
    ///
    /// Useful for restoring resources after reconnection. Returns an error if
    /// the ID is already in use.
    pub async fn add_with_id(
        &self,
        id: String,
        resource: Box<dyn Resource>,
    ) -> Result<(), ResourceError> {
        let kind = resource.kind();

        {
            let mut resources = self.resources.write().await;
            if resources.contains_key(&id) {
                return Err(ResourceError::Internal(format!(
                    "resource ID {} already exists",
                    id
                )));
            }
            resources.insert(id.clone(), resource);
        }

        info!(resource_id = %id, kind = %kind, "adding resource with explicit ID");
        self.emit_event(&id, kind, ResourceState::Pending, ResourceStats::new()).await;

        Ok(())
    }

    /// Start a resource.
    ///
    /// Calls the resource's `start()` method with the provided connection.
    /// The resource should transition through Starting -> Running.
    pub async fn start(
        &self,
        id: &str,
        conn: Arc<ChannelConnection>,
    ) -> Result<(), ResourceError> {
        // Get mutable access to the resource
        let (kind, stats) = {
            let mut resources = self.resources.write().await;
            let resource = resources.get_mut(id).ok_or_else(|| {
                ResourceError::Internal(format!("resource {} not found", id))
            })?;

            let kind = resource.kind();

            // Emit starting event
            self.emit_event(id, kind, ResourceState::Starting, ResourceStats::new()).await;

            // Start the resource
            match resource.start(conn).await {
                Ok(()) => {
                    let info = resource.describe();
                    (kind, info.stats)
                }
                Err(e) => {
                    // Emit failed event
                    self.emit_event(
                        id,
                        kind,
                        ResourceState::Failed(e.clone().into()),
                        ResourceStats::new(),
                    ).await;
                    return Err(e);
                }
            }
        };

        // Emit running event
        self.emit_event(id, kind, ResourceState::Running, stats).await;
        info!(resource_id = %id, "resource started");

        Ok(())
    }

    /// Get information about a resource.
    pub async fn describe(&self, id: &str) -> Option<ResourceInfo> {
        let resources = self.resources.read().await;
        resources.get(id).map(|r| r.describe())
    }

    /// List all resources, optionally filtered by kind.
    pub async fn list(&self, kind_filter: Option<ResourceKind>) -> Vec<ResourceInfo> {
        let resources = self.resources.read().await;
        resources
            .values()
            .filter(|r| kind_filter.map_or(true, |k| r.kind() == k))
            .map(|r| r.describe())
            .collect()
    }

    /// Get the count of resources, optionally filtered by kind.
    pub async fn count(&self, kind_filter: Option<ResourceKind>) -> usize {
        let resources = self.resources.read().await;
        resources
            .values()
            .filter(|r| kind_filter.map_or(true, |k| r.kind() == k))
            .count()
    }

    /// Get the count of active (non-terminal) resources.
    pub async fn active_count(&self) -> usize {
        let resources = self.resources.read().await;
        resources.values().filter(|r| r.state().is_active()).count()
    }

    /// Drain a specific resource.
    ///
    /// Initiates graceful shutdown: stop accepting new work, complete existing.
    pub async fn drain(
        &self,
        id: &str,
        deadline: Option<Duration>,
    ) -> Result<(), ResourceError> {
        let deadline = deadline.unwrap_or(Duration::from_secs(DEFAULT_DRAIN_TIMEOUT_SECS));

        let (kind, stats) = {
            let mut resources = self.resources.write().await;
            let resource = resources.get_mut(id).ok_or_else(|| {
                ResourceError::Internal(format!("resource {} not found", id))
            })?;

            let kind = resource.kind();

            // Check state
            if resource.state().is_terminal() {
                return Err(ResourceError::InvalidState {
                    current: resource.state().clone(),
                    expected: "active",
                });
            }

            // Emit draining event
            let info = resource.describe();
            self.emit_event(id, kind, ResourceState::Draining, info.stats.clone()).await;

            // Drain the resource
            match resource.drain(deadline).await {
                Ok(()) => (kind, resource.describe().stats),
                Err(e) => {
                    self.emit_event(
                        id,
                        kind,
                        ResourceState::Failed(e.clone().into()),
                        info.stats,
                    ).await;
                    return Err(e);
                }
            }
        };

        // Emit closed event
        self.emit_event(id, kind, ResourceState::Closed, stats).await;
        info!(resource_id = %id, "resource drained");

        Ok(())
    }

    /// Close a specific resource.
    ///
    /// Immediately terminates the resource. If the resource is already in a terminal
    /// state (Closed or Failed), it will be removed from the registry.
    pub async fn close(&self, id: &str) -> Result<(), ResourceError> {
        let mut resources = self.resources.write().await;
        let resource = resources.get_mut(id).ok_or_else(|| {
            ResourceError::NotFound(id.to_string())
        })?;

        let kind = resource.kind();
        let info = resource.describe();
        let current_state = info.state.clone();

        // If already terminal, just remove from registry
        if current_state.is_terminal() {
            resources.remove(id);
            info!(resource_id = %id, "removed terminal resource from registry");
            return Ok(());
        }

        // Close the resource
        match resource.close().await {
            Ok(()) => {
                let final_stats = resource.describe().stats;
                // Remove from registry after successful close
                resources.remove(id);
                drop(resources); // Release lock before emitting event
                self.emit_event(id, kind, ResourceState::Closed, final_stats).await;
                info!(resource_id = %id, "resource closed");
                Ok(())
            }
            Err(e) => {
                self.emit_event(
                    id,
                    kind,
                    ResourceState::Failed(e.clone().into()),
                    info.stats,
                ).await;
                Err(e)
            }
        }
    }

    /// Force close a resource, ignoring errors.
    pub async fn force_close(&self, id: &str) {
        let result = {
            let mut resources = self.resources.write().await;
            if let Some(resource) = resources.get_mut(id) {
                let kind = resource.kind();
                let _ = resource.close().await;
                Some((kind, resource.describe().stats))
            } else {
                None
            }
        };

        if let Some((kind, stats)) = result {
            self.emit_event(id, kind, ResourceState::Closed, stats).await;
            info!(resource_id = %id, "resource force closed");
        }
    }

    /// Remove a resource from the manager.
    ///
    /// Only removes resources in terminal states (Closed or Failed).
    pub async fn remove(&self, id: &str) -> Option<Box<dyn Resource>> {
        let mut resources = self.resources.write().await;
        if let Some(resource) = resources.get(id) {
            if resource.state().is_terminal() {
                return resources.remove(id);
            }
            warn!(resource_id = %id, state = %resource.state(), "cannot remove active resource");
        }
        None
    }

    /// Drain all resources.
    pub async fn drain_all(&self, deadline: Option<Duration>) {
        let deadline = deadline.unwrap_or(Duration::from_secs(DEFAULT_DRAIN_TIMEOUT_SECS));
        let ids: Vec<String> = {
            let resources = self.resources.read().await;
            resources
                .iter()
                .filter(|(_, r)| r.state().is_active())
                .map(|(id, _)| id.clone())
                .collect()
        };

        for id in ids {
            if let Err(e) = self.drain(&id, Some(deadline)).await {
                error!(resource_id = %id, error = %e, "failed to drain resource");
            }
        }
    }

    /// Close all resources.
    pub async fn close_all(&self) {
        let ids: Vec<String> = {
            let resources = self.resources.read().await;
            resources
                .iter()
                .filter(|(_, r)| r.state().is_active())
                .map(|(id, _)| id.clone())
                .collect()
        };

        for id in ids {
            if let Err(e) = self.close(&id).await {
                error!(resource_id = %id, error = %e, "failed to close resource");
            }
        }
    }

    /// Notify all resources of a disconnection.
    pub async fn on_disconnect(&self) {
        let mut resources = self.resources.write().await;
        for (id, resource) in resources.iter_mut() {
            if resource.state().is_active() {
                debug!(resource_id = %id, "notifying resource of disconnect");
                resource.on_disconnect();
            }
        }
    }

    /// Notify all resources of a reconnection.
    ///
    /// Attempts to restore each resource. Resources that fail to restore
    /// are marked as Failed.
    pub async fn on_reconnect(&self, conn: Arc<ChannelConnection>) {
        let ids: Vec<String> = {
            let resources = self.resources.read().await;
            resources
                .iter()
                .filter(|(_, r)| r.state().is_active())
                .map(|(id, _)| id.clone())
                .collect()
        };

        for id in ids {
            let result = {
                let mut resources = self.resources.write().await;
                if let Some(resource) = resources.get_mut(&id) {
                    Some((
                        resource.kind(),
                        resource.on_reconnect(conn.clone()).await,
                        resource.describe().stats,
                    ))
                } else {
                    None
                }
            };

            if let Some((kind, result, stats)) = result {
                match result {
                    Ok(()) => {
                        debug!(resource_id = %id, "resource reconnected");
                        self.emit_event(&id, kind, ResourceState::Running, stats).await;
                    }
                    Err(e) => {
                        error!(resource_id = %id, error = %e, "resource failed to reconnect");
                        self.emit_event(
                            &id,
                            kind,
                            ResourceState::Failed(FailureReason::ResumeFailed(e.to_string())),
                            stats,
                        ).await;
                    }
                }
            }
        }
    }

    /// Check if any resources are active.
    pub async fn has_active_resources(&self) -> bool {
        let resources = self.resources.read().await;
        resources.values().any(|r| r.state().is_active())
    }

    /// Get all resource IDs.
    pub async fn ids(&self) -> Vec<String> {
        let resources = self.resources.read().await;
        resources.keys().cloned().collect()
    }

    /// Execute a function with mutable access to a resource, with downcasting.
    ///
    /// This allows calling resource-specific methods like Terminal::attach().
    /// Returns None if the resource doesn't exist or can't be downcast to T.
    pub async fn with_resource_mut<T: 'static, F, R>(&self, id: &str, f: F) -> Option<R>
    where
        F: FnOnce(&mut T) -> R,
    {
        let mut resources = self.resources.write().await;
        if let Some(resource) = resources.get_mut(id) {
            if let Some(typed) = resource.as_any_mut().downcast_mut::<T>() {
                return Some(f(typed));
            }
        }
        None
    }

    /// Execute an async function with mutable access to a resource, with downcasting.
    ///
    /// This allows calling async resource-specific methods like Terminal::attach().
    /// Returns None if the resource doesn't exist or can't be downcast to T.
    ///
    /// Note: The closure must return a boxed future since we can't use async closures yet.
    pub async fn with_resource<T: 'static, F, R>(&self, id: &str, f: F) -> Option<R>
    where
        F: FnOnce(&T) -> R,
    {
        let resources = self.resources.read().await;
        if let Some(resource) = resources.get(id) {
            if let Some(typed) = resource.as_any().downcast_ref::<T>() {
                return Some(f(typed));
            }
        }
        None
    }

    // =========================================================================
    // Terminal-specific operations
    // =========================================================================

    /// Get the I/O socket path for a terminal resource.
    ///
    /// Returns the Unix socket path that clients can connect to for raw terminal I/O.
    /// Any TTY-aware client (socat, nc, custom tools) can connect to this socket.
    pub async fn terminal_io_socket(&self, id: &str) -> Result<std::path::PathBuf, ResourceError> {
        let resources = self.resources.read().await;
        let resource = resources.get(id).ok_or_else(|| {
            ResourceError::NotFound(id.to_string())
        })?;

        // Verify it's a terminal
        if resource.kind() != ResourceKind::Terminal {
            return Err(ResourceError::Internal(format!(
                "resource {} is not a terminal",
                id
            )));
        }

        // Downcast and get socket path
        let terminal = resource.as_any().downcast_ref::<Terminal>().ok_or_else(|| {
            ResourceError::Internal("failed to downcast to Terminal".to_string())
        })?;

        terminal.io_socket_path().ok_or_else(|| {
            ResourceError::Internal("terminal I/O socket not ready".to_string())
        })
    }

    /// Check if a terminal resource is attached (has a connected client).
    pub async fn terminal_is_attached(&self, id: &str) -> Result<bool, ResourceError> {
        let resources = self.resources.read().await;
        let resource = resources.get(id).ok_or_else(|| {
            ResourceError::NotFound(id.to_string())
        })?;

        // Verify it's a terminal
        if resource.kind() != ResourceKind::Terminal {
            return Err(ResourceError::Internal(format!(
                "resource {} is not a terminal",
                id
            )));
        }

        // Downcast and check attached
        let terminal = resource.as_any().downcast_ref::<Terminal>().ok_or_else(|| {
            ResourceError::Internal("failed to downcast to Terminal".to_string())
        })?;

        Ok(terminal.is_attached())
    }

    /// Resize a terminal resource.
    pub async fn terminal_resize(&self, id: &str, cols: u32, rows: u32) -> Result<(), ResourceError> {
        let resources = self.resources.read().await;
        let resource = resources.get(id).ok_or_else(|| {
            ResourceError::NotFound(id.to_string())
        })?;

        // Verify it's a terminal
        if resource.kind() != ResourceKind::Terminal {
            return Err(ResourceError::Internal(format!(
                "resource {} is not a terminal",
                id
            )));
        }

        // Downcast and call resize
        let terminal = resource.as_any().downcast_ref::<Terminal>().ok_or_else(|| {
            ResourceError::Internal("failed to downcast to Terminal".to_string())
        })?;

        terminal.resize(cols, rows).await
    }

    /// Set the session directory for a terminal resource's I/O socket.
    ///
    /// Must be called before start() for the socket to be created in the right location.
    pub async fn terminal_set_session_dir(&self, id: &str, dir: std::path::PathBuf) -> Result<(), ResourceError> {
        let resources = self.resources.read().await;
        let resource = resources.get(id).ok_or_else(|| {
            ResourceError::NotFound(id.to_string())
        })?;

        // Verify it's a terminal
        if resource.kind() != ResourceKind::Terminal {
            return Err(ResourceError::Internal(format!(
                "resource {} is not a terminal",
                id
            )));
        }

        // Downcast and set session dir
        let terminal = resource.as_any().downcast_ref::<Terminal>().ok_or_else(|| {
            ResourceError::Internal("failed to downcast to Terminal".to_string())
        })?;

        terminal.set_session_dir(dir).await;
        Ok(())
    }
}

impl Default for ResourceManager {
    fn default() -> Self {
        Self::new().0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::resource::StubResource;

    #[tokio::test]
    async fn test_generate_id() {
        let (manager, _rx) = ResourceManager::new();

        let id1 = manager.generate_id(ResourceKind::Terminal).await;
        let id2 = manager.generate_id(ResourceKind::Terminal).await;
        let id3 = manager.generate_id(ResourceKind::Forward).await;

        assert_eq!(id1, "term-0");
        assert_eq!(id2, "term-1");
        assert_eq!(id3, "fwd-0");
    }

    #[tokio::test]
    async fn test_add_and_list() {
        let (manager, _rx) = ResourceManager::new();

        let r1 = Box::new(StubResource::terminal(""));
        let r2 = Box::new(StubResource::forward(""));

        let id1 = manager.add(r1).await;
        let id2 = manager.add(r2).await;

        assert_eq!(id1, "term-0");
        assert_eq!(id2, "fwd-0");

        let all = manager.list(None).await;
        assert_eq!(all.len(), 2);

        let terminals = manager.list(Some(ResourceKind::Terminal)).await;
        assert_eq!(terminals.len(), 1);

        let forwards = manager.list(Some(ResourceKind::Forward)).await;
        assert_eq!(forwards.len(), 1);
    }

    #[tokio::test]
    async fn test_describe() {
        let (manager, _rx) = ResourceManager::new();

        let r = Box::new(StubResource::terminal(""));
        let id = manager.add(r).await;

        let info = manager.describe(&id).await.unwrap();
        assert_eq!(info.kind, ResourceKind::Terminal);
        assert_eq!(info.state, ResourceState::Pending);
    }

    #[tokio::test]
    async fn test_count() {
        let (manager, _rx) = ResourceManager::new();

        manager.add(Box::new(StubResource::terminal(""))).await;
        manager.add(Box::new(StubResource::terminal(""))).await;
        manager.add(Box::new(StubResource::forward(""))).await;

        assert_eq!(manager.count(None).await, 3);
        assert_eq!(manager.count(Some(ResourceKind::Terminal)).await, 2);
        assert_eq!(manager.count(Some(ResourceKind::Forward)).await, 1);
        assert_eq!(manager.count(Some(ResourceKind::FileTransfer)).await, 0);
    }

    #[tokio::test]
    async fn test_event_sequence() {
        let (manager, mut rx) = ResourceManager::new();

        // Add resources to generate events
        manager.add(Box::new(StubResource::terminal(""))).await;
        manager.add(Box::new(StubResource::forward(""))).await;

        // Receive events and check sequence numbers
        let e1 = rx.recv().await.unwrap();
        let e2 = rx.recv().await.unwrap();

        assert_eq!(e1.event_seq, 0);
        assert_eq!(e2.event_seq, 1);
    }
}
