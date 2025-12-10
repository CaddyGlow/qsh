//! Terminal channel implementation.
//!
//! Manages an interactive PTY session within a channel.

use std::sync::{Arc, Weak};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, broadcast, mpsc};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, trace, warn};

use qsh_core::error::{Error, Result};
use qsh_core::protocol::{
    ChannelCloseReason, ChannelData, ChannelId, ChannelPayload, Message, StateDiff,
    StateUpdateData, TerminalInputData, TerminalOutputData, TerminalParams,
};
use qsh_core::terminal::{TerminalParser, TerminalState};
use qsh_core::transport::{Connection, QuicConnection, QuicStream, StreamPair, StreamType, TransportSender};

use crate::pty::{Pty, PtyRelay};
use crate::registry::PtyControl;

/// Terminal channel managing a PTY session.
#[derive(Clone)]
pub struct TerminalChannel {
    inner: Arc<TerminalChannelInner>,
}

/// Minimum interval between state updates (allows throttling when connection is fast).
const STATE_UPDATE_MIN_INTERVAL: Duration = Duration::from_millis(20);

struct TerminalChannelInner {
    /// Channel ID.
    channel_id: ChannelId,
    /// QUIC connection for opening streams.
    quic: Arc<QuicConnection>,
    /// PTY control handle.
    pty_control: Arc<dyn PtyControl>,
    /// Terminal state parser.
    parser: Arc<Mutex<TerminalParser>>,
    /// Channel for sending input to PTY.
    input_tx: mpsc::Sender<Vec<u8>>,
    /// Broadcast channel for PTY output.
    output_tx: broadcast::Sender<Vec<u8>>,
    /// Output stream (server -> client).
    output_stream: Mutex<Option<QuicStream>>,
    /// Last confirmed input sequence.
    confirmed_input_seq: AtomicU64,
    /// Last state generation acknowledged by client.
    acked_generation: AtomicU64,
    /// Last sent terminal state (for diff computation).
    last_sent_state: Mutex<Option<TerminalState>>,
    /// Whether the channel is closed.
    closed: AtomicBool,
    /// Whether output stream is disconnected (skip sending until reconnect).
    disconnected: AtomicBool,
    /// Handle to the output relay task.
    relay_task: Mutex<Option<JoinHandle<()>>>,
    /// Shutdown signal.
    shutdown_tx: Mutex<Option<mpsc::Sender<()>>>,
    /// Last time a state update was sent (for throttling).
    last_state_update: Mutex<Option<Instant>>,
    /// Weak reference to the connection handler for notifying PTY exit.
    handler: Weak<crate::connection::ConnectionHandler>,
}

/// Real PTY control implementation.
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

impl TerminalChannel {
    /// Create a new terminal channel.
    ///
    /// Returns the channel and the initial terminal state.
    pub async fn new(
        channel_id: ChannelId,
        params: TerminalParams,
        quic: Arc<QuicConnection>,
        handler: Arc<crate::connection::ConnectionHandler>,
    ) -> Result<(Self, TerminalState)> {
        let cols = params.term_size.cols;
        let rows = params.term_size.rows;

        // Build environment for the shell/command
        let env: Vec<(String, String)> = params
            .env
            .into_iter()
            .chain(std::iter::once(("TERM".to_string(), params.term_type.clone())))
            .collect();

        // Spawn PTY with optional command
        // Note: allocate_pty=false (non-PTY mode) not yet implemented
        let pty = Arc::new(Pty::spawn(
            cols,
            rows,
            params.shell.as_deref(),
            params.command.as_deref(),
            &env,
        )?);
        let pty_control: Arc<dyn PtyControl> = Arc::new(RealPtyControl { pty: pty.clone() });

        // Set up PTY relay
        let relay = PtyRelay::start(pty.clone());
        let (input_tx, output_rx) = relay.split();

        // Create parser for terminal state tracking
        let parser = Arc::new(Mutex::new(TerminalParser::new(cols, rows)));

        // Create broadcast channel for output
        let (output_tx, _) = broadcast::channel(256);

        // Create shutdown channel
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

        // Open output stream
        let output_stream = quic
            .as_ref()
            .open_stream(StreamType::ChannelOut(channel_id))
            .await
            .map_err(|e| Error::Transport {
                message: format!("failed to open output stream: {}", e),
            })?;

        let inner = Arc::new(TerminalChannelInner {
            channel_id,
            quic,
            pty_control,
            parser: parser.clone(),
            input_tx,
            output_tx: output_tx.clone(),
            output_stream: Mutex::new(Some(output_stream)),
            confirmed_input_seq: AtomicU64::new(0),
            acked_generation: AtomicU64::new(0),
            last_sent_state: Mutex::new(None),
            closed: AtomicBool::new(false),
            disconnected: AtomicBool::new(false),
            relay_task: Mutex::new(None),
            shutdown_tx: Mutex::new(Some(shutdown_tx)),
            last_state_update: Mutex::new(None),
            handler: Arc::downgrade(&handler),
        });

        // Spawn output relay task with Mosh-style output batching (8ms mindelay for server)
        let inner_clone = Arc::clone(&inner);
        let mut output_rx = output_rx;
        let relay_task = tokio::spawn(async move {
            // Initialize TransportSender for Mosh-style output coalescing
            // Server uses 8ms mindelay (vs 1ms for client) for efficient output batching
            let mut output_sender = TransportSender::for_server();

            loop {
                tokio::select! {
                    biased;

                    _ = shutdown_rx.recv() => {
                        debug!(channel_id = %inner_clone.channel_id, "Terminal relay shutdown");
                        // Flush any pending output before shutdown
                        if output_sender.has_pending() {
                            let data = output_sender.flush();
                            let _ = inner_clone.send_output_to_client(data).await;
                        }
                        break;
                    }

                    output = output_rx.recv() => {
                        match output {
                            Some(data) => {
                                // Update terminal state immediately (for accurate tracking)
                                // This also broadcasts to local subscribers
                                inner_clone.update_state_and_broadcast(&data).await;

                                // Push to TransportSender for batched network send
                                output_sender.push(&data);
                                trace!(
                                    channel_id = %inner_clone.channel_id,
                                    output_len = data.len(),
                                    pending_len = output_sender.pending_len(),
                                    "Pushed output to TransportSender"
                                );

                                // Check if ready to send (timer may have expired)
                                if let Some(batched) = output_sender.tick() {
                                    trace!(
                                        channel_id = %inner_clone.channel_id,
                                        len = batched.len(),
                                        send_interval_ms = output_sender.send_interval().as_millis(),
                                        "TransportSender tick flush (inline)"
                                    );
                                    let _ = inner_clone.send_output_to_client(batched).await;
                                }
                            }
                            None => {
                                // PTY has exited - flush remaining output then break
                                if output_sender.has_pending() {
                                    let data = output_sender.flush();
                                    debug!(
                                        channel_id = %inner_clone.channel_id,
                                        len = data.len(),
                                        "Flushing remaining output on PTY exit"
                                    );
                                    let _ = inner_clone.send_output_to_client(data).await;
                                }
                                info!(channel_id = %inner_clone.channel_id, "PTY output_rx returned None - PTY exited, breaking relay loop");
                                break;
                            }
                        }
                    }

                    // TransportSender timer: flush pending output when timing allows
                    // (Mosh-style: max(mindelay_clock + 8ms, last_send + send_interval))
                    _ = tokio::time::sleep_until(output_sender.next_send_time().into()),
                        if output_sender.has_pending() => {
                        if let Some(batched) = output_sender.tick() {
                            trace!(
                                channel_id = %inner_clone.channel_id,
                                len = batched.len(),
                                send_interval_ms = output_sender.send_interval().as_millis(),
                                "TransportSender timer flush"
                            );
                            let _ = inner_clone.send_output_to_client(batched).await;
                        }
                    }
                }
            }

            // Mark channel as closed only when PTY actually exits
            inner_clone.closed.store(true, Ordering::SeqCst);

            // Try to get exit code
            let exit_code = inner_clone.pty_control.try_wait().ok().flatten();
            info!(
                channel_id = %inner_clone.channel_id,
                exit_code = ?exit_code,
                "Terminal channel closed (PTY exited)"
            );

            // IMPORTANT: Send ChannelClose BEFORE closing the output stream.
            // This ensures the client receives the ChannelClose message before
            // it detects the stream closure, allowing it to exit gracefully
            // instead of treating it as a transient network error.
            if let Some(handler) = inner_clone.handler.upgrade() {
                let reason = ChannelCloseReason::ProcessExited { exit_code };
                debug!(
                    channel_id = %inner_clone.channel_id,
                    reason = ?reason,
                    "Sending ChannelClose before closing output stream"
                );
                handler.close_channel(inner_clone.channel_id, reason).await;
                debug!(
                    channel_id = %inner_clone.channel_id,
                    "ChannelClose sent, now closing output stream"
                );
            } else {
                debug!(
                    channel_id = %inner_clone.channel_id,
                    "Handler not available, skipping ChannelClose"
                );
            }

            // Now close the output stream
            let mut stream_guard = inner_clone.output_stream.lock().await;
            if let Some(ref mut stream) = *stream_guard {
                debug!(
                    channel_id = %inner_clone.channel_id,
                    "Finishing output stream"
                );
                if let Err(e) = stream.finish().await {
                    debug!(
                        channel_id = %inner_clone.channel_id,
                        error = %e,
                        "Failed to finish output stream (client may have disconnected)"
                    );
                }
                debug!(
                    channel_id = %inner_clone.channel_id,
                    "Output stream finished"
                );
            }
            *stream_guard = None;
        });

        *inner.relay_task.lock().await = Some(relay_task);

        // Get initial state
        let initial_state = {
            let p = parser.lock().await;
            p.state().clone()
        };

        let channel = Self { inner };

        Ok((channel, initial_state))
    }

    /// Get the channel ID.
    pub fn channel_id(&self) -> ChannelId {
        self.inner.channel_id
    }

    /// Resize the terminal.
    pub async fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(Error::ConnectionClosed);
        }

        self.inner.pty_control.resize(cols, rows)?;

        // Update parser size
        {
            let mut parser = self.inner.parser.lock().await;
            parser.resize(cols, rows);
        }

        debug!(
            channel_id = %self.inner.channel_id,
            cols, rows, "Terminal resized"
        );

        Ok(())
    }

    /// Handle incoming terminal input from a stream.
    pub async fn handle_incoming_stream(&self, mut stream: QuicStream) -> Result<()> {
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(Error::ConnectionClosed);
        }

        // Process input messages from the stream
        loop {
            match stream.recv().await {
                Ok(Message::ChannelDataMsg(data)) => {
                    if let ChannelPayload::TerminalInput(input) = data.payload {
                        self.handle_input(input).await?;
                    }
                }
                Ok(other) => {
                    warn!(
                        channel_id = %self.inner.channel_id,
                        msg = ?other, "Unexpected message on terminal input stream"
                    );
                }
                Err(Error::ConnectionClosed) => break,
                Err(e) => {
                    warn!(
                        channel_id = %self.inner.channel_id,
                        error = %e, "Terminal input stream error"
                    );
                    break;
                }
            }
        }

        Ok(())
    }

    /// Handle a terminal input message.
    async fn handle_input(&self, input: TerminalInputData) -> Result<()> {
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(Error::ConnectionClosed);
        }

        debug!(
            channel_id = %self.inner.channel_id,
            seq = input.sequence,
            len = input.data.len(),
            "Received terminal input"
        );

        self.inner
            .confirmed_input_seq
            .store(input.sequence, Ordering::SeqCst);

        self.inner
            .input_tx
            .send(input.data)
            .await
            .map_err(|_| Error::Pty {
                message: "input channel closed".to_string(),
            })
    }

    /// Handle state acknowledgment from client.
    pub async fn handle_state_ack(&self, generation: u64) {
        self.inner.acked_generation.store(generation, Ordering::SeqCst);
    }

    /// Subscribe to PTY output.
    pub fn subscribe_output(&self) -> broadcast::Receiver<Vec<u8>> {
        self.inner.output_tx.subscribe()
    }

    /// Get the terminal state parser.
    pub fn parser(&self) -> Arc<Mutex<TerminalParser>> {
        Arc::clone(&self.inner.parser)
    }

    /// Get current terminal size.
    pub fn term_size(&self) -> (u16, u16) {
        self.inner.pty_control.size()
    }

    /// Get the last confirmed input sequence.
    pub fn confirmed_input_seq(&self) -> u64 {
        self.inner.confirmed_input_seq.load(Ordering::SeqCst)
    }

    /// Check if the PTY has exited.
    pub fn is_pty_exited(&self) -> bool {
        matches!(self.inner.pty_control.try_wait(), Ok(Some(_)))
    }

    /// Close the channel.
    pub async fn close(&self) {
        if self.inner.closed.swap(true, Ordering::SeqCst) {
            return;
        }

        // Signal shutdown
        if let Some(tx) = self.inner.shutdown_tx.lock().await.take() {
            let _ = tx.send(()).await;
        }

        // Cancel relay task
        if let Some(task) = self.inner.relay_task.lock().await.take() {
            task.abort();
        }

        // Kill PTY
        let _ = self.inner.pty_control.kill();
        let _ = self.inner.pty_control.wait_reap(Duration::from_secs(1));

        info!(channel_id = %self.inner.channel_id, "Terminal channel closed");
    }

    /// Check if the channel is closed.
    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::SeqCst)
    }

    /// Reconnect the channel's output stream to a new QUIC connection.
    ///
    /// This is used during mosh-style reconnection to redirect terminal output
    /// to a new client connection while keeping the PTY alive.
    pub async fn reconnect_output(&self, quic: &QuicConnection) -> Result<()> {
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(Error::ConnectionClosed);
        }

        // Open new output stream on the new connection
        let new_stream = quic
            .open_stream(StreamType::ChannelOut(self.inner.channel_id))
            .await
            .map_err(|e| Error::Transport {
                message: format!("failed to open output stream on reconnect: {}", e),
            })?;

        // Swap the output stream
        let mut stream_guard = self.inner.output_stream.lock().await;

        // Close old stream if present (best effort)
        if let Some(ref mut old_stream) = *stream_guard {
            let _ = old_stream.finish().await;
        }

        *stream_guard = Some(new_stream);

        // Clear disconnected flag so output resumes
        self.inner.disconnected.store(false, Ordering::SeqCst);

        info!(
            channel_id = %self.inner.channel_id,
            "Terminal channel output reconnected"
        );

        // Note: We don't send StateUpdate here because:
        // 1. It would block before HelloAck is sent, causing a deadlock
        // 2. The terminal state is already included in HelloAck.existing_channels
        // 3. The client can render the state from the HelloAck directly
        //
        // After reconnection, normal PTY output will resume flowing through
        // this new stream automatically.

        Ok(())
    }
}

impl TerminalChannelInner {
    /// Process PTY output and send to client (non-batched version).
    ///
    /// Note: The relay task uses the batched version via TransportSender.
    /// This method is retained for potential direct use cases.
    #[allow(dead_code)]
    async fn process_output(&self, data: Vec<u8>) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Ok(());
        }

        // Update terminal state (always, even when disconnected)
        {
            let mut parser = self.parser.lock().await;
            parser.process(&data);
        }

        // Broadcast to any local subscribers
        let _ = self.output_tx.send(data.clone());

        // Skip sending if disconnected - state is tracked, client will get it on reconnect
        if self.disconnected.load(Ordering::SeqCst) {
            return Ok(());
        }

        // Send to client
        let mut stream_guard = self.output_stream.lock().await;
        if let Some(ref mut stream) = *stream_guard {
            let confirmed_seq = self.confirmed_input_seq.load(Ordering::SeqCst);
            let channel_id = self.channel_id;

            // Send raw output first
            let output = Message::ChannelDataMsg(ChannelData {
                channel_id,
                payload: ChannelPayload::TerminalOutput(TerminalOutputData {
                    data: data.clone(),
                    confirmed_input_seq: confirmed_seq,
                }),
            });
            if let Err(e) = stream.send(&output).await {
                // Connection lost - mark disconnected and stop trying to send
                if !self.disconnected.swap(true, Ordering::SeqCst) {
                    info!(
                        channel_id = %channel_id,
                        error = %e,
                        "Output stream disconnected, waiting for reconnection"
                    );
                }
                return Ok(());
            }

            // Throttle state updates - raw output is always sent immediately,
            // but state updates (for prediction validation) can be rate-limited.
            // When connection is fast, predictions aren't needed, so we can throttle.
            let should_send_state = {
                let mut last_update = self.last_state_update.lock().await;
                let now = Instant::now();
                let send = match *last_update {
                    None => true, // First update, always send
                    Some(last) => now.duration_since(last) >= STATE_UPDATE_MIN_INTERVAL,
                };
                if send {
                    *last_update = Some(now);
                }
                send
            };

            if should_send_state {
                // Send state update for reconnection/prediction support
                let new_state = {
                    let parser = self.parser.lock().await;
                    parser.state().clone()
                };

                let diff = {
                    let mut last = self.last_sent_state.lock().await;
                    let diff = if let Some(ref last_state) = *last {
                        last_state.diff_to(&new_state)
                    } else {
                        StateDiff::Full(new_state.clone())
                    };
                    *last = Some(new_state);
                    diff
                };

                let update = Message::ChannelDataMsg(ChannelData {
                    channel_id,
                    payload: ChannelPayload::StateUpdate(StateUpdateData {
                        diff,
                        confirmed_input_seq: confirmed_seq,
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_micros() as u64,
                    }),
                });
                let _ = stream.send(&update).await; // Best effort for state update
            }
        }

        Ok(())
    }

    /// Update terminal state and broadcast locally (immediate, no network send).
    ///
    /// Used by TransportSender-based relay to track state immediately while
    /// batching network sends.
    async fn update_state_and_broadcast(&self, data: &[u8]) {
        if self.closed.load(Ordering::SeqCst) {
            return;
        }

        // Update terminal state (always, even when disconnected)
        {
            let mut parser = self.parser.lock().await;
            parser.process(data);
        }

        // Broadcast to any local subscribers
        let _ = self.output_tx.send(data.to_vec());
    }

    /// Send batched output to client (called from TransportSender timer).
    ///
    /// This handles the network send portion, including optional state updates.
    async fn send_output_to_client(&self, data: Vec<u8>) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) || data.is_empty() {
            return Ok(());
        }

        // Skip sending if disconnected - state is tracked, client will get it on reconnect
        if self.disconnected.load(Ordering::SeqCst) {
            return Ok(());
        }

        // Send to client
        let mut stream_guard = self.output_stream.lock().await;
        if let Some(ref mut stream) = *stream_guard {
            let confirmed_seq = self.confirmed_input_seq.load(Ordering::SeqCst);
            let channel_id = self.channel_id;

            // Send raw output (batched)
            let output = Message::ChannelDataMsg(ChannelData {
                channel_id,
                payload: ChannelPayload::TerminalOutput(TerminalOutputData {
                    data: data.clone(),
                    confirmed_input_seq: confirmed_seq,
                }),
            });
            if let Err(e) = stream.send(&output).await {
                // Connection lost - mark disconnected and stop trying to send
                if !self.disconnected.swap(true, Ordering::SeqCst) {
                    info!(
                        channel_id = %channel_id,
                        error = %e,
                        "Output stream disconnected, waiting for reconnection"
                    );
                }
                return Ok(());
            }

            // Throttle state updates
            let should_send_state = {
                let mut last_update = self.last_state_update.lock().await;
                let now = Instant::now();
                let send = match *last_update {
                    None => true, // First update, always send
                    Some(last) => now.duration_since(last) >= STATE_UPDATE_MIN_INTERVAL,
                };
                if send {
                    *last_update = Some(now);
                }
                send
            };

            if should_send_state {
                // Send state update for reconnection/prediction support
                let new_state = {
                    let parser = self.parser.lock().await;
                    parser.state().clone()
                };

                let diff = {
                    let mut last = self.last_sent_state.lock().await;
                    let diff = if let Some(ref last_state) = *last {
                        last_state.diff_to(&new_state)
                    } else {
                        StateDiff::Full(new_state.clone())
                    };
                    *last = Some(new_state);
                    diff
                };

                let update = Message::ChannelDataMsg(ChannelData {
                    channel_id,
                    payload: ChannelPayload::StateUpdate(StateUpdateData {
                        diff,
                        confirmed_input_seq: confirmed_seq,
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_micros() as u64,
                    }),
                });
                let _ = stream.send(&update).await; // Best effort for state update
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_terminal_channel_structure() {
        // Just verify the struct compiles
        fn _assert_clone<T: Clone>() {}
        _assert_clone::<TerminalChannel>();
    }
}
