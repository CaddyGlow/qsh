//! Connection registry for qsh-server.
//!
//! Manages SSH-style connections with multiple channels (terminals, file transfers,
//! port forwards) multiplexed over a single QUIC connection.
//!
//! Sessions are indexed by both session key (for initial auth) and session ID
//! (for reconnection). When a client reconnects with a session ID, the existing
//! session state (terminals, forwards) is preserved.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex as AsyncMutex, mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use qsh_core::constants::SESSION_KEY_LEN;
use qsh_core::error::Result;
use qsh_core::protocol::SessionId;

use crate::connection::{ConnectionConfig, ConnectionSession};

/// Control operations on a PTY (resize/kill/status).
pub trait PtyControl: Send + Sync {
    /// Get current terminal size.
    fn size(&self) -> (u16, u16);

    /// Resize the PTY.
    fn resize(&self, cols: u16, rows: u16) -> Result<()>;

    /// Non-blocking child status.
    fn try_wait(&self) -> Result<Option<i32>>;

    /// Kill the child process.
    fn kill(&self) -> Result<()>;

    /// Best-effort reap with timeout.
    fn wait_reap(&self, timeout: Duration) -> Result<Option<i32>>;
}

/// Commands for the connection registry supervisor.
#[derive(Debug)]
enum ConnectionRegistryCommand {
    /// Remove a session by key.
    RemoveSession([u8; SESSION_KEY_LEN]),
}

/// Registry for managing SSH-style connections with multiple channels.
///
/// Unlike `SessionRegistry` which manages per-PTY sessions, `ConnectionRegistry`
/// manages connections that can have multiple channels (terminals, file transfers,
/// port forwards) multiplexed over a single QUIC connection.
///
/// Sessions are indexed by both session key (for initial auth) and session ID
/// (for reconnection lookup).
pub struct ConnectionRegistry {
    /// Active sessions keyed by session key.
    sessions: Arc<AsyncMutex<HashMap<[u8; SESSION_KEY_LEN], Arc<ConnectionSession>>>>,
    /// Index from session ID to session key (for reconnection lookup).
    sessions_by_id: Arc<AsyncMutex<HashMap<SessionId, [u8; SESSION_KEY_LEN]>>>,
    /// Default configuration for new connections.
    config: ConnectionConfig,
    /// Channel for cleanup commands.
    cleanup_tx: mpsc::UnboundedSender<ConnectionRegistryCommand>,
    /// GC task handle (wrapped in Mutex to allow take without consuming self).
    gc_task: std::sync::Mutex<Option<JoinHandle<()>>>,
    /// Shutdown signal.
    shutdown_tx: watch::Sender<bool>,
}

impl ConnectionRegistry {
    /// Create a new connection registry.
    pub fn new(config: ConnectionConfig) -> Self {
        let sessions: Arc<AsyncMutex<HashMap<[u8; SESSION_KEY_LEN], Arc<ConnectionSession>>>> =
            Arc::new(AsyncMutex::new(HashMap::new()));
        let sessions_by_id: Arc<AsyncMutex<HashMap<SessionId, [u8; SESSION_KEY_LEN]>>> =
            Arc::new(AsyncMutex::new(HashMap::new()));
        let (cleanup_tx, mut cleanup_rx) = mpsc::unbounded_channel::<ConnectionRegistryCommand>();
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

        let sessions_gc = Arc::clone(&sessions);
        let sessions_by_id_gc = Arc::clone(&sessions_by_id);
        let linger = config.linger_timeout;

        let gc_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        break;
                    }
                    Some(cmd) = cleanup_rx.recv() => {
                        match cmd {
                            ConnectionRegistryCommand::RemoveSession(key) => {
                                let mut guard = sessions_gc.lock().await;
                                if let Some(session) = guard.remove(&key) {
                                    debug!("Removed session {:?}", session.session_id);
                                    // Also remove from session_id index
                                    sessions_by_id_gc.lock().await.remove(&session.session_id);
                                }
                            }
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_secs(30)) => {
                        run_connection_gc(&sessions_gc, &sessions_by_id_gc, linger).await;
                    }
                }
            }

            // Final cleanup
            run_connection_gc(&sessions_gc, &sessions_by_id_gc, Duration::from_secs(0)).await;
        });

        Self {
            sessions,
            sessions_by_id,
            config,
            cleanup_tx,
            gc_task: std::sync::Mutex::new(Some(gc_task)),
            shutdown_tx,
        }
    }

    /// Get the default connection configuration.
    pub fn config(&self) -> &ConnectionConfig {
        &self.config
    }

    /// Look up or create a session for the given key.
    ///
    /// If the session exists and is attached (has an active connection), this
    /// returns `None` - the caller should reject the connection or wait for
    /// the existing connection to detach.
    ///
    /// If the session exists but is detached, this returns the existing session
    /// for reconnection.
    ///
    /// If no session exists, this creates a new one.
    pub async fn get_or_create_session(
        &self,
        session_key: [u8; SESSION_KEY_LEN],
        client_addr: std::net::SocketAddr,
    ) -> Result<ConnectionSessionGuard> {
        let mut guard = self.sessions.lock().await;

        if let Some(session) = guard.get(&session_key).cloned() {
            // Existing session - check if it's attached
            if session.is_attached().await {
                // Another client is connected - reject or replace
                // For now, we allow replacement (like SSH multiplexing)
                info!(
                    session_id = ?session.session_id,
                    "Session already attached, allowing replacement"
                );
            }

            session.touch().await;
            drop(guard);

            return Ok(ConnectionSessionGuard {
                session,
                cleanup_tx: self.cleanup_tx.clone(),
            });
        }

        // Create new session
        let session = Arc::new(ConnectionSession::new(session_key, client_addr));
        guard.insert(session_key, Arc::clone(&session));

        // Also add to session_id index
        self.sessions_by_id
            .lock()
            .await
            .insert(session.session_id, session_key);

        info!(session_id = ?session.session_id, "Created new connection session");

        Ok(ConnectionSessionGuard {
            session,
            cleanup_tx: self.cleanup_tx.clone(),
        })
    }

    /// Look up a session by session ID (for reconnection).
    ///
    /// Returns the session if it exists and the session key matches.
    /// The session key check prevents session hijacking.
    pub async fn get_session_for_resume(
        &self,
        session_id: SessionId,
        session_key: &[u8; SESSION_KEY_LEN],
    ) -> Option<ConnectionSessionGuard> {
        // Look up session key from session ID
        let stored_key = self.sessions_by_id.lock().await.get(&session_id).copied()?;

        // Verify session key matches (prevents hijacking)
        if &stored_key != session_key {
            warn!(
                ?session_id,
                "Session resume rejected: session key mismatch"
            );
            return None;
        }

        // Get the session
        let session = self.sessions.lock().await.get(&stored_key).cloned()?;

        // Check if it's already attached
        if session.is_attached().await {
            info!(
                ?session_id,
                "Session resume: detaching existing connection"
            );
            // Detach the existing connection (client reconnected)
            session.detach().await;
        }

        session.touch().await;

        info!(
            ?session_id,
            "Session resumed"
        );

        Some(ConnectionSessionGuard {
            session,
            cleanup_tx: self.cleanup_tx.clone(),
        })
    }

    /// Get an existing session by key.
    pub async fn get_session(
        &self,
        session_key: &[u8; SESSION_KEY_LEN],
    ) -> Option<Arc<ConnectionSession>> {
        self.sessions.lock().await.get(session_key).cloned()
    }

    /// Remove a session.
    pub async fn remove_session(&self, session_key: &[u8; SESSION_KEY_LEN]) {
        let _ = self
            .cleanup_tx
            .send(ConnectionRegistryCommand::RemoveSession(*session_key));
    }

    /// Get the number of active sessions.
    pub async fn session_count(&self) -> usize {
        self.sessions.lock().await.len()
    }

    /// Shutdown the registry.
    pub async fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);

        // Take and await the GC task
        let gc_task = self
            .gc_task
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(task) = gc_task {
            if !task.is_finished() {
                let _ = task.await;
            }
        }

        // Close all sessions
        let sessions = self.sessions.lock().await;
        for session in sessions.values() {
            if let Some(handler) = session.handler.lock().await.take() {
                handler.shutdown().await;
            }
        }
    }
}

/// Guard that provides access to a connection session.
pub struct ConnectionSessionGuard {
    /// The session.
    pub session: Arc<ConnectionSession>,
    /// Cleanup channel.
    cleanup_tx: mpsc::UnboundedSender<ConnectionRegistryCommand>,
}

impl ConnectionSessionGuard {
    /// Request removal of this session.
    pub fn request_removal(&self) {
        let _ = self.cleanup_tx.send(ConnectionRegistryCommand::RemoveSession(
            self.session.session_key,
        ));
    }
}

/// Run garbage collection on the connection registry.
async fn run_connection_gc(
    sessions: &Arc<AsyncMutex<HashMap<[u8; SESSION_KEY_LEN], Arc<ConnectionSession>>>>,
    sessions_by_id: &Arc<AsyncMutex<HashMap<SessionId, [u8; SESSION_KEY_LEN]>>>,
    linger: Duration,
) {
    let snapshot: Vec<Arc<ConnectionSession>> = {
        let guard = sessions.lock().await;
        guard.values().cloned().collect()
    };

    for session in snapshot {
        let idle = session.idle_duration().await;
        let attached = session.is_attached().await;

        if !attached && idle >= linger {
            info!(
                session_id = ?session.session_id,
                idle_secs = idle.as_secs(),
                "Removing idle connection session after linger"
            );

            // Close any lingering handlers
            if let Some(handler) = session.handler.lock().await.take() {
                handler.shutdown().await;
            }

            // Remove from both indices
            let mut guard = sessions.lock().await;
            guard.remove(&session.session_key);
            sessions_by_id.lock().await.remove(&session.session_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qsh_core::constants::DEFAULT_MAX_FORWARDS;

    #[test]
    fn connection_registry_config_default() {
        let config = ConnectionConfig::default();
        assert_eq!(config.max_forwards, DEFAULT_MAX_FORWARDS);
    }
}
