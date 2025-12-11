//! Connection handler core logic.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tracing::info;

use qsh_core::error::Result;
use qsh_core::protocol::Message;
use qsh_core::transport::{Connection, StreamPair};

use super::{ConnectionHandler, ShutdownReason};

impl ConnectionHandler {
    /// Send a message on the control stream.
    pub async fn send_control(&self, msg: &Message) -> Result<()> {
        self.touch().await;
        self.control_sender.read().await.send(msg).await
    }

    /// Receive a message from the control stream.
    pub async fn recv_control(&self) -> Result<Message> {
        self.touch().await;
        self.control.lock().await.recv().await
    }

    /// Reconnect to a new QUIC connection (mosh-style session resume).
    ///
    /// This updates the underlying QUIC connection and control stream while
    /// keeping all channels (and their PTYs) alive. Terminal channels will
    /// have their output streams reconnected to the new connection.
    pub async fn reconnect(
        &self,
        new_quic: qsh_core::transport::QuicConnection,
        new_control: qsh_core::transport::QuicStream,
        new_shutdown_tx: mpsc::Sender<ShutdownReason>,
    ) {
        use tracing::warn;

        let new_quic = Arc::new(new_quic);
        let new_control_sender = new_control
            .sender()
            .expect("control stream must support sending");

        info!(
            session_id = ?self.session_id,
            new_addr = %new_quic.remote_addr(),
            "Reconnecting handler to new QUIC connection"
        );

        // Update the QUIC connection
        *self.quic.write().await = Arc::clone(&new_quic);

        // Update control stream
        *self.control.lock().await = new_control;
        *self.control_sender.write().await = new_control_sender;

        // Update shutdown channel
        *self.shutdown_tx.lock().await = new_shutdown_tx;

        // Update activity timestamp
        self.touch().await;

        // Reconnect all terminal channels' output streams
        let channels = self.channels.read().await;
        for (channel_id, handle) in channels.iter() {
            if let crate::channel::ChannelHandle::Terminal(terminal) = handle {
                if let Err(e) = terminal.reconnect_output(&new_quic).await {
                    warn!(
                        channel_id = %channel_id,
                        error = %e,
                        "Failed to reconnect terminal output stream"
                    );
                }
            }
        }

        info!(
            session_id = ?self.session_id,
            channel_count = channels.len(),
            "Handler reconnection complete"
        );
    }

    /// Update last activity timestamp.
    pub async fn touch(&self) {
        *self.last_activity.lock().await = Instant::now();
    }

    /// Get the idle duration.
    pub async fn idle_duration(&self) -> Duration {
        self.last_activity.lock().await.elapsed()
    }
}
