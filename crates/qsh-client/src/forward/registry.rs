//! Registry for tracking runtime-added forwards.
//!
//! This module provides a registry for managing forwards that are added
//! dynamically via the control socket, as opposed to those specified at
//! startup via CLI arguments.
//!
//! The registry tracks active forwards and provides lifecycle management
//! (add, remove, list) operations.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

/// Information about a forward for listing purposes.
#[derive(Debug, Clone)]
pub struct ForwardInfo {
    /// Unique forward ID.
    pub id: String,
    /// Forward type: "local", "remote", or "dynamic".
    pub forward_type: String,
    /// Bind address (IP or hostname).
    pub bind_addr: String,
    /// Bind port.
    pub bind_port: u32,
    /// Destination host (for local/remote forwards).
    pub dest_host: Option<String>,
    /// Destination port (for local/remote forwards).
    pub dest_port: Option<u32>,
    /// Forward status: "active", "failed", etc.
    pub status: String,
    /// Number of active connections.
    pub connections: u64,
    /// Bytes sent through this forward.
    pub bytes_sent: u64,
    /// Bytes received through this forward.
    pub bytes_received: u64,
}

/// Registry for tracking runtime-added forwards.
///
/// This maintains the state of all forwards added via the control socket,
/// allowing them to be queried, listed, and removed.
pub struct ForwardRegistry {
    /// Local forwards (-L): bind locally, forward to remote target.
    local: HashMap<String, LocalForwardEntry>,

    /// Remote forwards (-R): bind on server, forward to local target.
    remote: HashMap<String, RemoteForwardEntry>,

    /// Dynamic SOCKS5 forwards (-D): bind locally, dynamic destination.
    dynamic: HashMap<String, DynamicForwardEntry>,

    /// Counter for generating unique forward IDs.
    next_id: AtomicU64,
}

/// Entry for a local forward (-L).
pub struct LocalForwardEntry {
    /// The original spec string (for display/debugging).
    pub spec: String,

    /// The address we're bound to locally.
    pub bind_addr: SocketAddr,

    /// The target host:port to forward to (on the server side).
    pub target: String,

    /// Handle to stop the forwarder (kept alive to prevent abort on drop).
    #[allow(dead_code)]
    pub handle: Option<crate::forward::ForwarderHandle>,
}

/// Entry for a remote forward (-R).
pub struct RemoteForwardEntry {
    /// The original spec string (for display/debugging).
    pub spec: String,

    /// The address the server is bound to.
    pub bind_addr: String,

    /// The local target host:port to forward to.
    pub target: String,

    // TODO: Add handle for shutdown
}

/// Entry for a dynamic SOCKS5 forward (-D).
pub struct DynamicForwardEntry {
    /// The original spec string (for display/debugging).
    pub spec: String,

    /// The address we're bound to locally.
    pub bind_addr: SocketAddr,

    /// Handle to stop the proxy (kept alive to prevent abort on drop).
    #[allow(dead_code)]
    pub handle: Option<crate::forward::ProxyHandle>,
}

/// Enum to represent the type of forward entry when removing.
pub enum ForwardEntryType {
    Local(LocalForwardEntry),
    Remote(RemoteForwardEntry),
    Dynamic(DynamicForwardEntry),
}

impl ForwardRegistry {
    /// Create a new empty forward registry.
    pub fn new() -> Self {
        Self {
            local: HashMap::new(),
            remote: HashMap::new(),
            dynamic: HashMap::new(),
            next_id: AtomicU64::new(1),
        }
    }

    /// Add a local forward to the registry.
    ///
    /// Returns the generated forward ID.
    pub fn add_local(
        &mut self,
        spec: &str,
        bind_addr: SocketAddr,
        target: String,
        handle: Option<crate::forward::ForwarderHandle>,
    ) -> String {
        let id = self.generate_id();
        let entry = LocalForwardEntry {
            spec: spec.to_string(),
            bind_addr,
            target,
            handle,
        };
        self.local.insert(id.clone(), entry);
        id
    }

    /// Add a remote forward to the registry.
    ///
    /// Returns the generated forward ID.
    pub fn add_remote(&mut self, spec: &str, bind_addr: String, target: String) -> String {
        let id = self.generate_id();
        let entry = RemoteForwardEntry {
            spec: spec.to_string(),
            bind_addr,
            target,
        };
        self.remote.insert(id.clone(), entry);
        id
    }

    /// Add a dynamic SOCKS5 forward to the registry.
    ///
    /// Returns the generated forward ID.
    pub fn add_dynamic(
        &mut self,
        spec: &str,
        bind_addr: SocketAddr,
        handle: Option<crate::forward::ProxyHandle>,
    ) -> String {
        let id = self.generate_id();
        let entry = DynamicForwardEntry {
            spec: spec.to_string(),
            bind_addr,
            handle,
        };
        self.dynamic.insert(id.clone(), entry);
        id
    }

    /// Remove a forward by ID.
    ///
    /// Returns the removed entry if found, or None if the ID doesn't exist.
    pub fn remove(&mut self, id: &str) -> Option<ForwardEntryType> {
        if let Some(entry) = self.local.remove(id) {
            return Some(ForwardEntryType::Local(entry));
        }
        if let Some(entry) = self.remote.remove(id) {
            return Some(ForwardEntryType::Remote(entry));
        }
        if let Some(entry) = self.dynamic.remove(id) {
            return Some(ForwardEntryType::Dynamic(entry));
        }
        None
    }

    /// List all forwards in the registry.
    ///
    /// Returns a vector of ForwardInfo structs suitable for the control protocol.
    pub fn list(&self) -> Vec<ForwardInfo> {
        let mut forwards = Vec::new();

        // Add local forwards
        for (id, entry) in &self.local {
            forwards.push(ForwardInfo {
                id: id.clone(),
                forward_type: "local".to_string(),
                bind_addr: entry.bind_addr.ip().to_string(),
                bind_port: entry.bind_addr.port() as u32,
                dest_host: Some(entry.target.clone()),
                dest_port: None, // Target is already in "host:port" format
                status: "active".to_string(),
                connections: 0, // TODO: Track actual connection count
                bytes_sent: 0,  // TODO: Track actual bytes
                bytes_received: 0, // TODO: Track actual bytes
            });
        }

        // Add remote forwards
        for (id, entry) in &self.remote {
            forwards.push(ForwardInfo {
                id: id.clone(),
                forward_type: "remote".to_string(),
                bind_addr: entry.bind_addr.clone(),
                bind_port: 0, // TODO: Parse from bind_addr
                dest_host: Some(entry.target.clone()),
                dest_port: None,
                status: "active".to_string(),
                connections: 0,
                bytes_sent: 0,
                bytes_received: 0,
            });
        }

        // Add dynamic forwards
        for (id, entry) in &self.dynamic {
            forwards.push(ForwardInfo {
                id: id.clone(),
                forward_type: "dynamic".to_string(),
                bind_addr: entry.bind_addr.ip().to_string(),
                bind_port: entry.bind_addr.port() as u32,
                dest_host: None,
                dest_port: None,
                status: "active".to_string(),
                connections: 0,
                bytes_sent: 0,
                bytes_received: 0,
            });
        }

        forwards
    }

    /// Generate a unique forward ID.
    fn generate_id(&self) -> String {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        format!("fwd-{}", id)
    }
}

impl Default for ForwardRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_local_forward() {
        let mut registry = ForwardRegistry::new();
        let bind_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let target = "localhost:80".to_string();

        let id = registry.add_local("8080:localhost:80", bind_addr, target.clone(), None);

        assert!(id.starts_with("fwd-"));
        assert_eq!(registry.local.len(), 1);

        let entry = registry.local.get(&id).unwrap();
        assert_eq!(entry.spec, "8080:localhost:80");
        assert_eq!(entry.bind_addr, bind_addr);
        assert_eq!(entry.target, target);
    }

    #[test]
    fn test_add_remote_forward() {
        let mut registry = ForwardRegistry::new();
        let bind_addr = "0.0.0.0:8080".to_string();
        let target = "localhost:3000".to_string();

        let id = registry.add_remote("8080:localhost:3000", bind_addr.clone(), target.clone());

        assert!(id.starts_with("fwd-"));
        assert_eq!(registry.remote.len(), 1);

        let entry = registry.remote.get(&id).unwrap();
        assert_eq!(entry.spec, "8080:localhost:3000");
        assert_eq!(entry.bind_addr, bind_addr);
        assert_eq!(entry.target, target);
    }

    #[test]
    fn test_add_dynamic_forward() {
        let mut registry = ForwardRegistry::new();
        let bind_addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();

        let id = registry.add_dynamic("1080", bind_addr, None);

        assert!(id.starts_with("fwd-"));
        assert_eq!(registry.dynamic.len(), 1);

        let entry = registry.dynamic.get(&id).unwrap();
        assert_eq!(entry.spec, "1080");
        assert_eq!(entry.bind_addr, bind_addr);
    }

    #[test]
    fn test_remove_forward() {
        let mut registry = ForwardRegistry::new();
        let bind_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let id = registry.add_local("8080:localhost:80", bind_addr, "localhost:80".to_string(), None);

        let removed = registry.remove(&id);
        assert!(removed.is_some());
        assert_eq!(registry.local.len(), 0);

        // Try removing again
        let removed_again = registry.remove(&id);
        assert!(removed_again.is_none());
    }

    #[test]
    fn test_list_forwards() {
        let mut registry = ForwardRegistry::new();

        let local_bind: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        registry.add_local("8080:localhost:80", local_bind, "localhost:80".to_string(), None);

        let dynamic_bind: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        registry.add_dynamic("1080", dynamic_bind, None);

        let forwards = registry.list();
        assert_eq!(forwards.len(), 2);

        let local_fwd = forwards.iter().find(|f| f.forward_type == "local").unwrap();
        assert_eq!(local_fwd.bind_port, 8080);

        let dynamic_fwd = forwards.iter().find(|f| f.forward_type == "dynamic").unwrap();
        assert_eq!(dynamic_fwd.bind_port, 1080);
    }

    #[test]
    fn test_unique_ids() {
        let mut registry = ForwardRegistry::new();
        let bind_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        let id1 = registry.add_local("8080:localhost:80", bind_addr, "localhost:80".to_string(), None);
        let id2 = registry.add_local("8081:localhost:81", bind_addr, "localhost:81".to_string(), None);

        assert_ne!(id1, id2);
    }
}
