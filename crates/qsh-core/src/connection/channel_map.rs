//! Generic channel container for both client and server.
//!
//! Provides a type-safe container for managing channels with automatic
//! ID allocation that distinguishes between client and server initiated channels.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::RwLock;

use crate::protocol::ChannelId;

/// Generic channel container used by both client and server.
///
/// Type parameter `H` is the channel handle type (client or server specific).
/// The container manages channel lifecycle and provides proper ID allocation
/// based on whether it's used by a client or server.
pub struct ChannelMap<H> {
    channels: RwLock<HashMap<ChannelId, H>>,
    next_id: AtomicU64,
    is_server: bool,
}

impl<H: Clone> ChannelMap<H> {
    /// Create a new channel map for client use.
    ///
    /// Client-initiated channel IDs have the client origin bit set.
    pub fn new_client() -> Self {
        Self {
            channels: RwLock::new(HashMap::new()),
            next_id: AtomicU64::new(0),
            is_server: false,
        }
    }

    /// Create a new channel map for server use.
    ///
    /// Server-initiated channel IDs have the server origin bit set.
    pub fn new_server() -> Self {
        Self {
            channels: RwLock::new(HashMap::new()),
            next_id: AtomicU64::new(0),
            is_server: true,
        }
    }

    /// Allocate a new channel ID.
    ///
    /// The ID will be marked as client or server initiated based on
    /// how this map was constructed.
    pub fn allocate_id(&self) -> ChannelId {
        let seq = self.next_id.fetch_add(1, Ordering::SeqCst);
        if self.is_server {
            ChannelId::server(seq)
        } else {
            ChannelId::client(seq)
        }
    }

    /// Insert a channel handle.
    pub async fn insert(&self, id: ChannelId, handle: H) {
        self.channels.write().await.insert(id, handle);
    }

    /// Remove a channel by ID.
    pub async fn remove(&self, id: &ChannelId) -> Option<H> {
        self.channels.write().await.remove(id)
    }

    /// Get a clone of a channel handle by ID.
    pub async fn get(&self, id: &ChannelId) -> Option<H> {
        self.channels.read().await.get(id).cloned()
    }

    /// Check if a channel exists.
    pub async fn contains(&self, id: &ChannelId) -> bool {
        self.channels.read().await.contains_key(id)
    }

    /// Get the number of channels.
    pub async fn len(&self) -> usize {
        self.channels.read().await.len()
    }

    /// Check if empty.
    pub async fn is_empty(&self) -> bool {
        self.channels.read().await.is_empty()
    }

    /// Drain all channels, returning them as a vector.
    pub async fn drain(&self) -> Vec<(ChannelId, H)> {
        self.channels.write().await.drain().collect()
    }

    /// Get all channel IDs.
    pub async fn keys(&self) -> Vec<ChannelId> {
        self.channels.read().await.keys().copied().collect()
    }

    /// Get all channel handles.
    pub async fn values(&self) -> Vec<H> {
        self.channels.read().await.values().cloned().collect()
    }

    /// Iterate over channels with a closure.
    ///
    /// Note: The lock is held for the duration of the iteration.
    pub async fn for_each<F>(&self, mut f: F)
    where
        F: FnMut(&ChannelId, &H),
    {
        let channels = self.channels.read().await;
        for (id, handle) in channels.iter() {
            f(id, handle);
        }
    }

    /// Find a channel matching a predicate.
    pub async fn find<F>(&self, predicate: F) -> Option<(ChannelId, H)>
    where
        F: Fn(&ChannelId, &H) -> bool,
    {
        let channels = self.channels.read().await;
        for (id, handle) in channels.iter() {
            if predicate(id, handle) {
                return Some((*id, handle.clone()));
            }
        }
        None
    }
}

// Need a separate impl block for non-Clone types if we want basic operations
impl<H> ChannelMap<H> {
    /// Insert a channel handle (non-clone version).
    pub async fn insert_owned(&self, id: ChannelId, handle: H) {
        self.channels.write().await.insert(id, handle);
    }

    /// Remove a channel by ID (non-clone version).
    pub async fn remove_owned(&self, id: &ChannelId) -> Option<H> {
        self.channels.write().await.remove(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_client_channel_id_allocation() {
        let map: ChannelMap<String> = ChannelMap::new_client();
        let id1 = map.allocate_id();
        let id2 = map.allocate_id();

        assert!(id1.is_client());
        assert!(id2.is_client());
        assert_ne!(id1, id2);
    }

    #[tokio::test]
    async fn test_server_channel_id_allocation() {
        let map: ChannelMap<String> = ChannelMap::new_server();
        let id1 = map.allocate_id();
        let id2 = map.allocate_id();

        assert!(id1.is_server());
        assert!(id2.is_server());
        assert_ne!(id1, id2);
    }

    #[tokio::test]
    async fn test_insert_remove() {
        let map: ChannelMap<String> = ChannelMap::new_client();
        let id = map.allocate_id();

        map.insert(id, "test".to_string()).await;
        assert_eq!(map.len().await, 1);
        assert!(map.contains(&id).await);

        let removed = map.remove(&id).await;
        assert_eq!(removed, Some("test".to_string()));
        assert!(map.is_empty().await);
    }

    #[tokio::test]
    async fn test_get() {
        let map: ChannelMap<String> = ChannelMap::new_client();
        let id = map.allocate_id();

        map.insert(id, "test".to_string()).await;

        let got = map.get(&id).await;
        assert_eq!(got, Some("test".to_string()));

        // Original still exists
        assert!(!map.is_empty().await);
    }

    #[tokio::test]
    async fn test_drain() {
        let map: ChannelMap<String> = ChannelMap::new_client();
        let id1 = map.allocate_id();
        let id2 = map.allocate_id();

        map.insert(id1, "one".to_string()).await;
        map.insert(id2, "two".to_string()).await;

        let drained = map.drain().await;
        assert_eq!(drained.len(), 2);
        assert!(map.is_empty().await);
    }

    #[tokio::test]
    async fn test_keys_values() {
        let map: ChannelMap<String> = ChannelMap::new_client();
        let id1 = map.allocate_id();
        let id2 = map.allocate_id();

        map.insert(id1, "one".to_string()).await;
        map.insert(id2, "two".to_string()).await;

        let keys = map.keys().await;
        assert_eq!(keys.len(), 2);

        let values = map.values().await;
        assert_eq!(values.len(), 2);
    }

    #[tokio::test]
    async fn test_find() {
        let map: ChannelMap<String> = ChannelMap::new_client();
        let id1 = map.allocate_id();
        let id2 = map.allocate_id();

        map.insert(id1, "one".to_string()).await;
        map.insert(id2, "two".to_string()).await;

        let found = map.find(|_, v| v == "two").await;
        assert!(found.is_some());
        assert_eq!(found.unwrap().1, "two");

        let not_found = map.find(|_, v| v == "three").await;
        assert!(not_found.is_none());
    }
}
