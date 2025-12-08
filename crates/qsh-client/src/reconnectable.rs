//! Reconnectable connection wrapper for transparent reconnection.
//!
//! `ReconnectableConnection` wraps `ChannelConnection` and provides transparent
//! reconnection on network failures. Channels are unaware of reconnection - they
//! just see a brief stall during reconnect.
//!
//! # Design
//!
//! - No buffering: send/recv calls block (stall) during reconnection
//! - In-flight data loss handled by channel-level recovery:
//!   - Terminal: last_input_seq / last_generation
//!   - File: offset tracking
//!   - Forward: TCP retransmit
//! - Exponential backoff with jitter
//! - Retry until server rejects (expired/auth) or user cancels

use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::sync::Notify;
use tracing::{debug, error, info, warn};

use qsh_core::error::{Error, Result};
use qsh_core::protocol::SessionId;
use qsh_core::session::ReconnectionHandler;

use crate::connection::ChannelConnection;
use crate::session::{ConnectionState, SessionContext};

/// Reconnectable connection wrapper.
///
/// Provides transparent reconnection for `ChannelConnection`. When a transient
/// error occurs, reconnection is attempted in the background while callers
/// block waiting for the connection to be restored.
pub struct ReconnectableConnection {
    /// Current connection (None during reconnection).
    inner: RwLock<Option<Arc<ChannelConnection>>>,
    /// Session context for reconnection.
    context: RwLock<SessionContext>,
    /// Current connection state.
    state: RwLock<ConnectionState>,
    /// Notify when connection state changes.
    state_changed: Notify,
    /// Reconnection handler with backoff logic.
    reconnect_handler: RwLock<ReconnectionHandler>,
    /// Cached session data for 0-RTT resumption.
    session_data: RwLock<Option<Vec<u8>>>,
}

// Helper to read from std RwLock without panicking on poison
fn read_lock<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|e| e.into_inner())
}

fn write_lock<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(|e| e.into_inner())
}

impl ReconnectableConnection {
    /// Create a new reconnectable connection from an established connection.
    pub fn new(conn: ChannelConnection, context: SessionContext) -> Self {
        Self {
            inner: RwLock::new(Some(Arc::new(conn))),
            context: RwLock::new(context),
            state: RwLock::new(ConnectionState::Connected),
            state_changed: Notify::new(),
            reconnect_handler: RwLock::new(ReconnectionHandler::new()),
            session_data: RwLock::new(None),
        }
    }

    /// Store session data for 0-RTT resumption.
    ///
    /// Call this after a successful connection to cache the session data
    /// for faster reconnection.
    pub async fn store_session_data(&self) {
        if let Some(conn) = read_lock(&self.inner).as_ref() {
            if let Some(data) = conn.quic().session_data().await {
                debug!(session_data_len = data.len(), "Storing session data for 0-RTT");
                *write_lock(&self.session_data) = Some(data);
            }
        }
    }

    /// Get the cached session data for 0-RTT resumption.
    pub fn session_data(&self) -> Option<Vec<u8>> {
        read_lock(&self.session_data).clone()
    }

    /// Get the current connection state.
    pub fn state(&self) -> ConnectionState {
        *read_lock(&self.state)
    }

    /// Get the session ID.
    pub fn session_id(&self) -> Option<SessionId> {
        read_lock(&self.context).session_id()
    }

    /// Get a reference to the underlying connection.
    ///
    /// Returns None if currently reconnecting. Callers should use
    /// `wait_connected` instead for proper handling.
    pub fn connection(&self) -> Option<Arc<ChannelConnection>> {
        read_lock(&self.inner).clone()
    }

    /// Wait for the connection to be in Connected state.
    ///
    /// Returns the connection or an error if reconnection failed permanently.
    pub async fn wait_connected(&self) -> Result<Arc<ChannelConnection>> {
        loop {
            {
                let state = read_lock(&self.state);
                match *state {
                    ConnectionState::Connected => {
                        if let Some(conn) = read_lock(&self.inner).clone() {
                            return Ok(conn);
                        }
                    }
                    ConnectionState::Disconnected => {
                        return Err(Error::ConnectionClosed);
                    }
                    ConnectionState::Reconnecting => {
                        // Fall through to wait
                    }
                }
            }

            // Wait for state change
            self.state_changed.notified().await;
        }
    }

    /// Handle a transient error by triggering reconnection.
    ///
    /// Call this when an operation fails with a transient error.
    /// After calling this, use `wait_connected` to get the new connection.
    pub async fn handle_error(&self, error: &Error) {
        if error.is_transient() {
            self.trigger_reconnect(error).await;
        }
    }

    /// Trigger reconnection after a transient error.
    async fn trigger_reconnect(&self, error: &Error) {
        // Check if already reconnecting
        {
            let state = read_lock(&self.state);
            if *state == ConnectionState::Reconnecting {
                return;
            }
        }

        // Set state to reconnecting
        {
            let mut state = write_lock(&self.state);
            *state = ConnectionState::Reconnecting;
        }

        // Clear current connection
        {
            let mut inner = write_lock(&self.inner);
            *inner = None;
        }

        self.state_changed.notify_waiters();

        info!(error = %error, "Connection lost, starting reconnection");

        // Start reconnection handler
        {
            let context = read_lock(&self.context);
            let mut handler = write_lock(&self.reconnect_handler);
            let (generation, seq) = (0, 0); // TODO: Get from terminal state if available
            handler.start(generation, seq, context.config.zero_rtt_available);
        }

        // Perform reconnection
        self.do_reconnect().await;
    }

    /// Perform the reconnection loop.
    async fn do_reconnect(&self) {
        loop {
            // Check if we should retry
            let should_retry = {
                let handler = read_lock(&self.reconnect_handler);
                handler.should_retry()
            };

            if !should_retry {
                error!("Reconnection attempts exhausted");
                let mut state = write_lock(&self.state);
                *state = ConnectionState::Disconnected;
                self.state_changed.notify_waiters();
                return;
            }

            // Get delay and increment attempt counter
            let delay = {
                let mut handler = write_lock(&self.reconnect_handler);
                handler.next_delay()
            };

            let attempt = {
                let handler = read_lock(&self.reconnect_handler);
                handler.attempt()
            };

            debug!(attempt, delay_ms = delay.as_millis(), "Reconnection attempt");

            // Wait for backoff delay
            tokio::time::sleep(delay).await;

            // Attempt reconnection with cached session data for 0-RTT
            let (mut config, session_id) = {
                let context = read_lock(&self.context);
                (context.reconnect_config(), context.session_id())
            };

            // Inject cached session data for 0-RTT resumption
            config.session_data = read_lock(&self.session_data).clone();
            let had_session_data = config.session_data.is_some();

            let result = if let Some(sid) = session_id {
                ChannelConnection::reconnect(config, sid).await
            } else {
                // No session ID - this shouldn't happen in normal flow
                warn!("No session ID for reconnection, trying fresh connection");
                ChannelConnection::connect(config).await
            };

            match result {
                Ok(conn) => {
                    // Check if 0-RTT was used
                    let is_resumed = conn.quic().is_resumed().await;
                    info!(
                        attempt,
                        session_id = ?conn.session_id(),
                        resumed_0rtt = is_resumed,
                        had_session_data,
                        "Reconnection successful"
                    );

                    // Update context with new session ID
                    {
                        let mut context = write_lock(&self.context);
                        context.set_session_id(conn.session_id());
                    }

                    // Store new connection
                    let conn = Arc::new(conn);
                    {
                        let mut inner = write_lock(&self.inner);
                        *inner = Some(Arc::clone(&conn));
                    }

                    // Update session data for next reconnection (do this after storing connection)
                    if let Some(data) = conn.quic().session_data().await {
                        debug!(session_data_len = data.len(), "Updating session data for 0-RTT");
                        *write_lock(&self.session_data) = Some(data);
                    }

                    // Reset handler for next disconnect
                    {
                        let mut handler = write_lock(&self.reconnect_handler);
                        handler.reset();
                    }

                    // Update state to connected
                    {
                        let mut state = write_lock(&self.state);
                        *state = ConnectionState::Connected;
                    }

                    self.state_changed.notify_waiters();
                    return;
                }
                Err(e) if e.is_fatal() => {
                    error!(error = %e, "Reconnection failed with fatal error");
                    let mut state = write_lock(&self.state);
                    *state = ConnectionState::Disconnected;
                    self.state_changed.notify_waiters();
                    return;
                }
                Err(e) => {
                    warn!(attempt, error = %e, "Reconnection attempt failed");
                    // Continue loop to retry
                }
            }
        }
    }

    /// Get the current RTT (if connected).
    pub fn rtt(&self) -> Option<Duration> {
        read_lock(&self.inner).as_ref().map(|c| c.rtt())
    }

    /// Manually trigger disconnection (for testing or user-initiated disconnect).
    pub fn disconnect(&self) {
        {
            let mut state = write_lock(&self.state);
            *state = ConnectionState::Disconnected;
        }
        {
            let mut inner = write_lock(&self.inner);
            *inner = None;
        }
        self.state_changed.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_state_transitions() {
        // Just verify the enum variants exist
        let _connected = ConnectionState::Connected;
        let _reconnecting = ConnectionState::Reconnecting;
        let _disconnected = ConnectionState::Disconnected;
    }
}
