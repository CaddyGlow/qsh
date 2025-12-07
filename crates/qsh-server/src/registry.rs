//! Session registry for qsh-server.
//!
//! Keeps PTYs alive across client disconnects and coordinates single
//! attachment per session key. Entries are garbage-collected after a
//! configurable linger window when detached.
//!
//! The registry provides two models:
//! - `SessionRegistry`: Legacy per-PTY session management (single terminal per session)
//! - `ConnectionRegistry`: SSH-style channel model (multiple channels per connection)

use std::collections::HashMap;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

use tokio::sync::{Mutex as AsyncMutex, broadcast, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use qsh_core::constants::SESSION_KEY_LEN;
use qsh_core::error::{Error, Result};
use qsh_core::protocol::HelloPayload;
use qsh_core::terminal::{TerminalParser, TerminalState};

use crate::connection::{ConnectionConfig, ConnectionHandler, ConnectionSession};
use crate::pty::{Pty, PtyRelay};

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

/// Real PTY controller backed by [`Pty`].
struct RealPtyControl {
    pty: Arc<Pty>,
}

impl PtyControl for RealPtyControl {
    fn size(&self) -> (u16, u16) {
        self.pty.size()
    }

    fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        self.pty.resize(cols, rows)
    }

    fn try_wait(&self) -> Result<Option<i32>> {
        self.pty.try_wait()
    }

    fn kill(&self) -> Result<()> {
        self.pty.kill()
    }

    fn wait_reap(&self, timeout: Duration) -> Result<Option<i32>> {
        self.pty.wait_reap(timeout)
    }
}

/// Spawned PTY handles and I/O channels.
pub struct SpawnedSession {
    pub control: Box<dyn PtyControl>,
    pub input_tx: mpsc::Sender<Vec<u8>>,
    pub output_rx: mpsc::Receiver<Vec<u8>>,
}

/// Abstraction for creating sessions (real PTY or fake for tests).
pub trait SessionSpawner: Send + Sync {
    /// Spawn a session for the given key and requested size.
    fn spawn(
        &self,
        key: [u8; SESSION_KEY_LEN],
        cols: u16,
        rows: u16,
        term_type: &str,
        client_env: &[(String, String)],
    ) -> Result<SpawnedSession>;
}

/// Default spawner that launches real PTYs.
pub struct RealSessionSpawner {
    pub shell: Option<String>,
    pub env: Vec<(String, String)>,
}

impl SessionSpawner for RealSessionSpawner {
    fn spawn(
        &self,
        _key: [u8; SESSION_KEY_LEN],
        cols: u16,
        rows: u16,
        term_type: &str,
        client_env: &[(String, String)],
    ) -> Result<SpawnedSession> {
        // Merge: server base env < client env < TERM override
        let mut env = self.env.clone();
        // Add client environment variables (e.g., COLORTERM)
        env.extend(client_env.iter().cloned());
        // TERM from term_type takes precedence
        env.push(("TERM".to_string(), term_type.to_string()));
        let pty = Arc::new(Pty::spawn(cols, rows, self.shell.as_deref(), &env)?);
        let relay = PtyRelay::start(pty.clone());
        let (input_tx, output_rx) = relay.split();

        Ok(SpawnedSession {
            control: Box::new(RealPtyControl { pty }),
            input_tx,
            output_rx,
        })
    }
}

/// Reason an attachment is being stopped.
#[derive(Debug, Clone, Copy)]
pub enum AttachmentStopReason {
    /// Another client has taken over this session key.
    Replaced,
    /// Registry is shutting down.
    RegistryShutdown,
    /// PTY exited.
    PtyExited,
    /// Session was explicitly closed.
    ExplicitClose,
}

/// Active attachment bookkeeping.
struct ActiveAttachment {
    id: u64,
    stop_tx: Option<oneshot::Sender<AttachmentStopReason>>,
}

impl ActiveAttachment {
    fn notify(self, reason: AttachmentStopReason) {
        if let Some(tx) = self.stop_tx {
            let _ = tx.send(reason);
        }
    }
}

/// Guard returned to connection handlers to manage exclusive attachment.
pub struct AttachmentGuard {
    id: u64,
    entry: Arc<SessionEntry>,
    stop_rx: Option<oneshot::Receiver<AttachmentStopReason>>,
}

impl AttachmentGuard {
    /// Wait for a stop signal (replacement, shutdown, PTY exit).
    pub async fn stopped(&mut self) -> Option<AttachmentStopReason> {
        if let Some(rx) = self.stop_rx.take() {
            rx.await.ok()
        } else {
            None
        }
    }
}

impl Drop for AttachmentGuard {
    fn drop(&mut self) {
        self.entry.clear_attachment(self.id);
    }
}

/// Session entry tracked by the registry.
pub struct SessionEntry {
    key: [u8; SESSION_KEY_LEN],
    parser: Arc<AsyncMutex<TerminalParser>>,
    input_tx: mpsc::Sender<Vec<u8>>,
    output_tx: broadcast::Sender<Vec<u8>>,
    control: Box<dyn PtyControl>,
    attached: AsyncMutex<Option<ActiveAttachment>>,
    last_activity: AsyncMutex<Instant>,
    last_input_seq: AtomicU64,
    closed: AtomicBool,
    next_attachment_id: AtomicU64,
    cleanup_tx: mpsc::UnboundedSender<RegistryCommand>,
}

impl SessionEntry {
    fn new(
        key: [u8; SESSION_KEY_LEN],
        spawn: SpawnedSession,
        cleanup_tx: mpsc::UnboundedSender<RegistryCommand>,
    ) -> Arc<Self> {
        let parser = Arc::new(AsyncMutex::new(TerminalParser::new(
            spawn.control.size().0,
            spawn.control.size().1,
        )));

        let (output_tx, _) = broadcast::channel(256);
        let entry = Arc::new(Self {
            key,
            parser,
            input_tx: spawn.input_tx,
            output_tx,
            control: spawn.control,
            attached: AsyncMutex::new(None),
            last_activity: AsyncMutex::new(Instant::now()),
            last_input_seq: AtomicU64::new(0),
            closed: AtomicBool::new(false),
            next_attachment_id: AtomicU64::new(1),
            cleanup_tx,
        });

        // Spawn output processing task
        let entry_clone = entry.clone();
        let mut output_rx = spawn.output_rx;
        tokio::spawn(async move {
            while let Some(data) = output_rx.recv().await {
                entry_clone.touch().await;
                entry_clone.process_output(&data).await;
            }

            // PTY output channel closed - treat as exit
            entry_clone.handle_pty_exit().await;
        });

        entry
    }

    /// Clone the current terminal state for handshake.
    pub async fn current_state(&self) -> TerminalState {
        let parser = self.parser.lock().await;
        let mut state = parser.state().clone();
        state.generation = state.generation.max(1);
        state
    }

    pub fn key(&self) -> [u8; SESSION_KEY_LEN] {
        self.key
    }

    /// Get a handle to the shared parser.
    pub fn parser(&self) -> Arc<AsyncMutex<TerminalParser>> {
        Arc::clone(&self.parser)
    }

    /// Subscribe to live output.
    pub fn subscribe_output(&self) -> broadcast::Receiver<Vec<u8>> {
        self.output_tx.subscribe()
    }

    /// Register an active attachment, replacing any existing one.
    pub async fn attach(self: &Arc<Self>) -> AttachmentGuard {
        let mut attached = self.attached.lock().await;
        if let Some(active) = attached.take() {
            active.notify(AttachmentStopReason::Replaced);
        }

        let id = self.next_attachment_id.fetch_add(1, Ordering::SeqCst);
        let (stop_tx, stop_rx) = oneshot::channel();
        *attached = Some(ActiveAttachment {
            id,
            stop_tx: Some(stop_tx),
        });

        AttachmentGuard {
            id,
            entry: Arc::clone(self),
            stop_rx: Some(stop_rx),
        }
    }

    fn clear_attachment(&self, id: u64) {
        if let Ok(mut attached) = self.attached.try_lock() {
            if let Some(current) = attached.as_ref() {
                if current.id == id {
                    attached.take();
                }
            }
        }
    }

    /// Record activity timestamp.
    pub async fn touch(&self) {
        let mut ts = self.last_activity.lock().await;
        *ts = Instant::now();
    }

    /// Duration since last activity.
    pub async fn idle_duration(&self) -> Duration {
        let ts = self.last_activity.lock().await;
        ts.elapsed()
    }

    /// Whether an attachment exists.
    pub async fn has_attachment(&self) -> bool {
        self.attached.lock().await.is_some()
    }

    /// Update last processed input sequence and mark activity.
    pub async fn record_input_seq(&self, seq: u64) {
        self.last_input_seq.store(seq, Ordering::SeqCst);
        self.touch().await;
    }

    /// Last input sequence recorded for this session.
    pub fn last_input_seq(&self) -> u64 {
        self.last_input_seq.load(Ordering::SeqCst)
    }

    /// Send input to PTY.
    pub async fn send_input(&self, data: Vec<u8>) -> Result<()> {
        self.input_tx.send(data).await.map_err(|_| Error::Pty {
            message: "input channel closed".to_string(),
        })
    }

    /// Resize the PTY.
    pub fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        self.control.resize(cols, rows)
    }

    pub fn term_size(&self) -> (u16, u16) {
        self.control.size()
    }

    /// Whether the PTY has exited.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Explicitly close the session (user requested).
    pub async fn explicit_close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }

        self.notify_attachment(AttachmentStopReason::ExplicitClose)
            .await;
        let _ = self.control.kill();
        let _ = self.control.wait_reap(Duration::from_secs(1));
        let _ = self
            .cleanup_tx
            .send(RegistryCommand::Remove(self.key))
            .map_err(|e| {
                warn!(error = %e, "Failed to queue entry removal");
            });
    }

    async fn process_output(&self, data: &[u8]) {
        {
            let mut parser = self.parser.lock().await;
            parser.process(data);
        }
        let _ = self.output_tx.send(data.to_vec());
    }

    async fn handle_pty_exit(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }

        // Reap child to avoid zombies.
        let _ = self.control.wait_reap(Duration::from_secs(1));

        // Notify any attached client.
        self.notify_attachment(AttachmentStopReason::PtyExited)
            .await;

        // Request registry removal immediately.
        let _ = self.cleanup_tx.send(RegistryCommand::Remove(self.key));
    }

    async fn notify_attachment(&self, reason: AttachmentStopReason) {
        let mut attached = self.attached.lock().await;
        if let Some(active) = attached.take() {
            active.notify(reason);
        }
    }
}

/// Commands sent back to the registry supervisor.
#[derive(Debug)]
enum RegistryCommand {
    Remove([u8; SESSION_KEY_LEN]),
}

/// Result of preparing an attachment.
pub struct SessionAttach {
    pub entry: Arc<SessionEntry>,
    pub guard: AttachmentGuard,
    pub output_rx: broadcast::Receiver<Vec<u8>>,
    pub initial_state: TerminalState,
    pub last_input_seq: u64,
    pub parser: Arc<AsyncMutex<TerminalParser>>,
}

/// Registry that holds all session entries.
pub struct SessionRegistry {
    entries: Arc<AsyncMutex<HashMap<[u8; SESSION_KEY_LEN], Arc<SessionEntry>>>>,
    spawner: Arc<dyn SessionSpawner>,
    cleanup_tx: mpsc::UnboundedSender<RegistryCommand>,
    gc_task: JoinHandle<()>,
    shutdown_tx: watch::Sender<bool>,
}

impl SessionRegistry {
    /// Create a new registry with the provided linger window.
    pub fn new(linger: Duration, spawner: Arc<dyn SessionSpawner>) -> Self {
        let entries = Arc::new(AsyncMutex::new(HashMap::new()));
        let (cleanup_tx, mut cleanup_rx) = mpsc::unbounded_channel::<RegistryCommand>();
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let entries_gc = Arc::clone(&entries);

        let gc_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        break;
                    }
                    Some(RegistryCommand::Remove(key)) = cleanup_rx.recv() => {
                        remove_entry(&entries_gc, &key).await;
                    }
                    _ = tokio::time::sleep(Duration::from_secs(30)) => {
                        run_gc(&entries_gc, linger).await;
                    }
                }
            }

            // Final cleanup
            run_gc(&entries_gc, Duration::from_secs(0)).await;
        });

        Self {
            entries,
            spawner,
            cleanup_tx,
            gc_task,
            shutdown_tx,
        }
    }

    /// Prepare an attachment for the given hello payload.
    pub async fn prepare(&self, hello: &HelloPayload) -> Result<SessionAttach> {
        let entry = {
            let mut guard = self.entries.lock().await;
            if let Some(entry) = guard.get(&hello.session_key).cloned() {
                entry
            } else {
                let spawned = self.spawner.spawn(
                    hello.session_key,
                    hello.term_size.cols,
                    hello.term_size.rows,
                    &hello.term_type,
                    &hello.env,
                )?;
                let entry = SessionEntry::new(hello.session_key, spawned, self.cleanup_tx.clone());
                guard.insert(hello.session_key, entry.clone());
                entry
            }
        };

        if entry.is_closed() {
            remove_entry(&self.entries, &hello.session_key).await;
            return Err(Error::SessionExpired);
        }

        let guard = entry.attach().await;
        let output_rx = entry.subscribe_output();
        let initial_state = entry.current_state().await;
        let last_input_seq = entry.last_input_seq();
        let parser = entry.parser();

        Ok(SessionAttach {
            entry,
            guard,
            output_rx,
            initial_state,
            last_input_seq,
            parser,
        })
    }

    /// Remove and close an entry explicitly.
    pub async fn close_entry(&self, key: &[u8; SESSION_KEY_LEN]) {
        if let Some(entry) = remove_entry(&self.entries, key).await {
            entry.explicit_close().await;
        }
    }

    /// Stop the registry and clean up resources.
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        if !self.gc_task.is_finished() {
            let _ = self.gc_task.await;
        }

        // Close all remaining entries
        let entries = self.entries.lock().await;
        for entry in entries.values() {
            entry.explicit_close().await;
        }
    }

    /// Inspect number of entries (testing).
    #[cfg(test)]
    pub async fn entry_count(&self) -> usize {
        self.entries.lock().await.len()
    }
}

async fn run_gc(
    entries: &Arc<AsyncMutex<HashMap<[u8; SESSION_KEY_LEN], Arc<SessionEntry>>>>,
    linger: Duration,
) {
    let snapshot: Vec<Arc<SessionEntry>> = {
        let guard = entries.lock().await;
        guard.values().cloned().collect()
    };

    for entry in snapshot {
        if entry.is_closed() {
            remove_entry(entries, &entry.key()).await;
            continue;
        }

        let idle = entry.idle_duration().await;
        let attached = entry.has_attachment().await;

        if !attached && idle >= linger {
            info!(
                idle_secs = idle.as_secs(),
                "Removing idle session after linger"
            );
            entry.explicit_close().await;
            remove_entry(entries, &entry.key()).await;
        }
    }
}

async fn remove_entry(
    entries: &Arc<AsyncMutex<HashMap<[u8; SESSION_KEY_LEN], Arc<SessionEntry>>>>,
    key: &[u8; SESSION_KEY_LEN],
) -> Option<Arc<SessionEntry>> {
    let mut guard = entries.lock().await;
    guard.remove(key)
}

// =============================================================================
// Connection Registry (SSH-style Channel Model)
// =============================================================================

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
pub struct ConnectionRegistry {
    /// Active sessions keyed by session key.
    sessions: Arc<AsyncMutex<HashMap<[u8; SESSION_KEY_LEN], Arc<ConnectionSession>>>>,
    /// Default configuration for new connections.
    config: ConnectionConfig,
    /// Channel for cleanup commands.
    cleanup_tx: mpsc::UnboundedSender<ConnectionRegistryCommand>,
    /// GC task handle.
    gc_task: JoinHandle<()>,
    /// Shutdown signal.
    shutdown_tx: watch::Sender<bool>,
}

impl ConnectionRegistry {
    /// Create a new connection registry.
    pub fn new(config: ConnectionConfig) -> Self {
        let sessions: Arc<AsyncMutex<HashMap<[u8; SESSION_KEY_LEN], Arc<ConnectionSession>>>> =
            Arc::new(AsyncMutex::new(HashMap::new()));
        let (cleanup_tx, mut cleanup_rx) = mpsc::unbounded_channel::<ConnectionRegistryCommand>();
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

        let sessions_gc = Arc::clone(&sessions);
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
                                }
                            }
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_secs(30)) => {
                        run_connection_gc(&sessions_gc, linger).await;
                    }
                }
            }

            // Final cleanup
            run_connection_gc(&sessions_gc, Duration::from_secs(0)).await;
        });

        Self {
            sessions,
            config,
            cleanup_tx,
            gc_task,
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

        info!(session_id = ?session.session_id, "Created new connection session");

        Ok(ConnectionSessionGuard {
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
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        if !self.gc_task.is_finished() {
            let _ = self.gc_task.await;
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

            let mut guard = sessions.lock().await;
            guard.remove(&session.session_key);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use futures::FutureExt;
    use qsh_test_utils::FakePty;

    use super::*;

    struct FakePtyControl {
        pty: Arc<std::sync::Mutex<FakePty>>,
    }

    impl PtyControl for FakePtyControl {
        fn size(&self) -> (u16, u16) {
            self.pty.lock().unwrap().size()
        }

        fn resize(&self, cols: u16, rows: u16) -> Result<()> {
            self.pty.lock().unwrap().resize(cols, rows);
            Ok(())
        }

        fn try_wait(&self) -> Result<Option<i32>> {
            if self.pty.lock().unwrap().is_closed() {
                Ok(Some(0))
            } else {
                Ok(None)
            }
        }

        fn kill(&self) -> Result<()> {
            self.pty.lock().unwrap().close();
            Ok(())
        }

        fn wait_reap(&self, _timeout: Duration) -> Result<Option<i32>> {
            if self.pty.lock().unwrap().is_closed() {
                Ok(Some(0))
            } else {
                Ok(None)
            }
        }
    }

    struct FakeSpawner;

    impl SessionSpawner for FakeSpawner {
        fn spawn(
            &self,
            _key: [u8; SESSION_KEY_LEN],
            cols: u16,
            rows: u16,
            _term_type: &str,
            _client_env: &[(String, String)],
        ) -> Result<SpawnedSession> {
            let mut fake = FakePty::with_size(cols, rows);
            let mut output_rx = fake
                .take_output_receiver()
                .expect("output receiver should be present");

            let pty = Arc::new(std::sync::Mutex::new(fake));
            let input_pty = pty.clone();

            let (input_tx, mut input_rx) = mpsc::channel::<Vec<u8>>(32);
            tokio::spawn(async move {
                while let Some(data) = input_rx.recv().await {
                    input_pty.lock().unwrap().write_input(&data);
                }
            });

            let (proxy_tx, proxy_rx) = mpsc::channel::<Vec<u8>>(32);
            tokio::spawn(async move {
                while let Some(data) = output_rx.recv().await {
                    if proxy_tx.send(data).await.is_err() {
                        break;
                    }
                }
            });

            Ok(SpawnedSession {
                control: Box::new(FakePtyControl { pty }),
                input_tx,
                output_rx: proxy_rx,
            })
        }
    }

    fn hello_with_key(key: [u8; SESSION_KEY_LEN]) -> HelloPayload {
        HelloPayload {
            protocol_version: 1,
            session_key: key,
            client_nonce: 0,
            capabilities: Default::default(),
            resume_session: None,
            term_size: qsh_core::protocol::TermSize { cols: 80, rows: 24 },
            term_type: "xterm".to_string(),
            env: Vec::new(),
            last_generation: 0,
            last_input_seq: 0,
        }
    }

    #[tokio::test]
    async fn create_detach_and_reattach_reuses_entry() {
        let registry = SessionRegistry::new(Duration::from_secs(3600), Arc::new(FakeSpawner));
        let key = [1u8; SESSION_KEY_LEN];
        let hello = hello_with_key(key);

        let attach1 = registry.prepare(&hello).await.unwrap();
        let entry_addr = Arc::as_ptr(&attach1.entry) as usize;
        drop(attach1.guard);

        let attach2 = registry.prepare(&hello).await.unwrap();
        let entry2_addr = Arc::as_ptr(&attach2.entry) as usize;

        assert_eq!(entry_addr, entry2_addr);
        drop(registry);
    }

    #[tokio::test]
    async fn pty_exit_removes_entry() {
        let registry = SessionRegistry::new(Duration::from_secs(3600), Arc::new(FakeSpawner));
        let key = [2u8; SESSION_KEY_LEN];
        let hello = hello_with_key(key);

        let attach = registry.prepare(&hello).await.unwrap();
        let entry = attach.entry.clone();
        drop(attach.guard);

        entry.handle_pty_exit().await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert_eq!(registry.entry_count().await, 0);
        drop(registry);
    }

    #[tokio::test]
    async fn idle_linger_expires_entry() {
        let registry = SessionRegistry::new(Duration::from_millis(50), Arc::new(FakeSpawner));
        let key = [3u8; SESSION_KEY_LEN];
        let hello = hello_with_key(key);

        let attach = registry.prepare(&hello).await.unwrap();
        drop(attach.guard);

        tokio::time::sleep(Duration::from_millis(120)).await;
        run_gc(&registry.entries, Duration::from_millis(50)).await;

        assert_eq!(registry.entry_count().await, 0);
        drop(registry);
    }

    #[tokio::test]
    async fn attaching_replaces_previous_client() {
        let registry = SessionRegistry::new(Duration::from_secs(3600), Arc::new(FakeSpawner));
        let key = [4u8; SESSION_KEY_LEN];
        let hello = hello_with_key(key);

        let mut first = registry.prepare(&hello).await.unwrap();
        let mut second = registry.prepare(&hello).await.unwrap();

        // First should be notified
        let reason = first.guard.stopped().await.unwrap();
        assert!(matches!(reason, AttachmentStopReason::Replaced));

        // Second remains active
        assert!(second.guard.stopped().now_or_never().is_none());
        drop(registry);
    }
}
