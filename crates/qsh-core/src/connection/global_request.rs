//! Global request tracking for pending requests and responses.
//!
//! Used by both client (for tcpip-forward requests) and server
//! (for initiated channel opens).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};

use tokio::sync::{Mutex, oneshot};

use crate::protocol::GlobalReplyResult;

/// Tracks pending global requests and their response channels.
///
/// Used by both client (for tcpip-forward requests) and server
/// (for initiated channel opens).
pub struct GlobalRequestTracker {
    next_id: AtomicU32,
    pending: Mutex<HashMap<u32, oneshot::Sender<GlobalReplyResult>>>,
}

impl GlobalRequestTracker {
    /// Create a new global request tracker.
    pub fn new() -> Self {
        Self {
            next_id: AtomicU32::new(0),
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Allocate a new request ID and register a response channel.
    ///
    /// Returns the request ID and a receiver for the response.
    pub async fn register(&self) -> (u32, oneshot::Receiver<GlobalReplyResult>) {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(id, tx);
        (id, rx)
    }

    /// Allocate a request ID without registering a response channel.
    ///
    /// Use this when you don't need to wait for the response.
    pub fn allocate_id(&self) -> u32 {
        self.next_id.fetch_add(1, Ordering::SeqCst)
    }

    /// Register a pre-allocated request ID with a response channel.
    pub async fn register_with_id(&self, id: u32) -> oneshot::Receiver<GlobalReplyResult> {
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(id, tx);
        rx
    }

    /// Complete a pending request with a result.
    ///
    /// Returns true if the request was found and completed.
    pub async fn complete(&self, id: u32, result: GlobalReplyResult) -> bool {
        if let Some(tx) = self.pending.lock().await.remove(&id) {
            let _ = tx.send(result);
            true
        } else {
            false
        }
    }

    /// Check if a request is pending.
    pub async fn is_pending(&self, id: u32) -> bool {
        self.pending.lock().await.contains_key(&id)
    }

    /// Get the number of pending requests.
    pub async fn pending_count(&self) -> usize {
        self.pending.lock().await.len()
    }

    /// Cancel a pending request without sending a result.
    ///
    /// The receiver will get a `RecvError` if it tries to await.
    pub async fn cancel(&self, id: u32) -> bool {
        self.pending.lock().await.remove(&id).is_some()
    }

    /// Cancel all pending requests.
    pub async fn cancel_all(&self) {
        self.pending.lock().await.clear();
    }
}

impl Default for GlobalRequestTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::GlobalReplyData;

    #[tokio::test]
    async fn test_register_and_complete() {
        let tracker = GlobalRequestTracker::new();

        let (id, rx) = tracker.register().await;
        assert_eq!(id, 0);
        assert!(tracker.is_pending(id).await);

        let result = GlobalReplyResult::Success(GlobalReplyData::TcpIpForward { bound_port: 8080 });
        assert!(tracker.complete(id, result).await);
        assert!(!tracker.is_pending(id).await);

        let received = rx.await.unwrap();
        match received {
            GlobalReplyResult::Success(GlobalReplyData::TcpIpForward { bound_port }) => {
                assert_eq!(bound_port, 8080);
            }
            _ => panic!("unexpected result"),
        }
    }

    #[tokio::test]
    async fn test_sequential_ids() {
        let tracker = GlobalRequestTracker::new();

        let (id1, _) = tracker.register().await;
        let (id2, _) = tracker.register().await;
        let (id3, _) = tracker.register().await;

        assert_eq!(id1, 0);
        assert_eq!(id2, 1);
        assert_eq!(id3, 2);
    }

    #[tokio::test]
    async fn test_complete_unknown() {
        let tracker = GlobalRequestTracker::new();

        let result = GlobalReplyResult::Failure {
            message: "test".to_string(),
        };
        assert!(!tracker.complete(999, result).await);
    }

    #[tokio::test]
    async fn test_cancel() {
        let tracker = GlobalRequestTracker::new();

        let (id, rx) = tracker.register().await;
        assert!(tracker.is_pending(id).await);

        assert!(tracker.cancel(id).await);
        assert!(!tracker.is_pending(id).await);

        // Receiver should error
        assert!(rx.await.is_err());
    }

    #[tokio::test]
    async fn test_cancel_all() {
        let tracker = GlobalRequestTracker::new();

        let (_, _rx1) = tracker.register().await;
        let (_, _rx2) = tracker.register().await;
        let (_, _rx3) = tracker.register().await;

        assert_eq!(tracker.pending_count().await, 3);

        tracker.cancel_all().await;

        assert_eq!(tracker.pending_count().await, 0);
    }

    #[tokio::test]
    async fn test_allocate_without_register() {
        let tracker = GlobalRequestTracker::new();

        let id = tracker.allocate_id();
        assert_eq!(id, 0);
        assert!(!tracker.is_pending(id).await);

        let rx = tracker.register_with_id(id).await;
        assert!(tracker.is_pending(id).await);

        let result = GlobalReplyResult::Success(GlobalReplyData::CancelTcpIpForward);
        tracker.complete(id, result).await;

        assert!(rx.await.is_ok());
    }
}
