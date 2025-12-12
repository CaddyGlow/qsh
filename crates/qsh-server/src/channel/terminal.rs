//! Terminal channel implementation.
//!
//! Manages an interactive PTY session within a channel.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{Mutex, broadcast, mpsc};
use tokio::task::JoinHandle;
use tracing::{debug, info, trace, warn};

use qsh_core::error::{Error, Result};
use qsh_core::protocol::{
    ChannelCloseReason, ChannelData, ChannelId, ChannelPayload, Message, OutputMode,
    StateUpdateData, TerminalInputData, TerminalOutputData, TerminalParams,
};
use qsh_core::terminal::{Display, StateDiff, TerminalParser, TerminalState};
use qsh_core::transport::{
    Connection, QuicConnection, QuicStream, StreamPair, StreamType, TransportSender,
};

use crate::pty::{Pty, PtyRelay};
use crate::registry::PtyControl;

/// Terminal channel managing a PTY session.
#[derive(Clone)]
pub struct TerminalChannel {
    inner: Arc<TerminalChannelInner>,
}

struct TerminalChannelInner {
    /// Channel ID.
    channel_id: ChannelId,
    /// QUIC connection for opening streams.
    #[allow(dead_code)]
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
    /// Whether the channel is closed.
    closed: AtomicBool,
    /// Whether output stream is disconnected (skip sending until reconnect).
    disconnected: AtomicBool,
    /// Handle to the output relay task.
    relay_task: Mutex<Option<JoinHandle<()>>>,
    /// Shutdown signal.
    shutdown_tx: Mutex<Option<mpsc::Sender<()>>>,
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
        output_mode: OutputMode,
    ) -> Result<(Self, TerminalState)> {
        let cols = params.term_size.cols;
        let rows = params.term_size.rows;

        // Build environment for the shell/command
        let env: Vec<(String, String)> = params
            .env
            .into_iter()
            .chain(std::iter::once((
                "TERM".to_string(),
                params.term_type.clone(),
            )))
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
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);

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
            closed: AtomicBool::new(false),
            disconnected: AtomicBool::new(false),
            relay_task: Mutex::new(None),
            shutdown_tx: Mutex::new(Some(shutdown_tx)),
            handler: Arc::downgrade(&handler),
        });

        // Spawn output relay task based on output mode
        let inner_clone = Arc::clone(&inner);
        let relay_task = tokio::spawn(async move {
            // Call the appropriate relay loop based on output mode
            match output_mode {
                OutputMode::Direct => {
                    direct_relay_loop(inner_clone.clone(), output_rx, shutdown_rx).await;
                }
                OutputMode::Mosh => {
                    mosh_relay_loop(inner_clone.clone(), output_rx, shutdown_rx).await;
                }
                OutputMode::StateDiff => {
                    statediff_relay_loop(inner_clone.clone(), output_rx, shutdown_rx).await;
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
        self.inner
            .acked_generation
            .store(generation, Ordering::SeqCst);
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

/// Direct relay loop: send raw PTY output with 1ms window batching.
///
/// Batches PTY output within 1ms windows to reduce packet count while
/// maintaining low latency. Data is sent when either:
/// - 1ms has elapsed since first buffered byte, or
/// - Buffer reaches 16KB
async fn direct_relay_loop(
    inner: Arc<TerminalChannelInner>,
    mut output_rx: mpsc::Receiver<Vec<u8>>,
    mut shutdown_rx: mpsc::Receiver<()>,
) {
    use std::time::Duration;
    use tokio::time::{interval, Instant, MissedTickBehavior};

    debug!(channel_id = %inner.channel_id, "Terminal relay: DIRECT mode (1ms batched)");

    let mut buffer = Vec::with_capacity(8192);
    let mut batch_start: Option<Instant> = None;
    let batch_window = Duration::from_millis(1);

    // 1ms tick interval for flush checks
    let mut tick = interval(batch_window);
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;

            _ = shutdown_rx.recv() => {
                // Flush any remaining data before shutdown
                if !buffer.is_empty() {
                    let _ = inner.send_output_to_client(std::mem::take(&mut buffer)).await;
                }
                debug!(channel_id = %inner.channel_id, "Terminal relay shutdown");
                break;
            }

            output = output_rx.recv() => {
                match output {
                    Some(data) => {
                        if batch_start.is_none() {
                            batch_start = Some(Instant::now());
                        }
                        buffer.extend_from_slice(&data);

                        // Flush immediately if buffer is large enough
                        if buffer.len() >= 16384 {
                            let _ = inner.send_output_to_client(std::mem::take(&mut buffer)).await;
                            batch_start = None;
                        }
                    }
                    None => {
                        // Flush remaining before exit
                        if !buffer.is_empty() {
                            let _ = inner.send_output_to_client(std::mem::take(&mut buffer)).await;
                        }
                        info!(channel_id = %inner.channel_id, "PTY output_rx returned None - PTY exited");
                        break;
                    }
                }
            }

            _ = tick.tick() => {
                // Flush if we have data and batch window elapsed
                if !buffer.is_empty() {
                    if let Some(start) = batch_start {
                        if start.elapsed() >= batch_window {
                            let _ = inner.send_output_to_client(std::mem::take(&mut buffer)).await;
                            batch_start = None;
                        }
                    }
                }
            }
        }
    }
}

/// Mosh relay loop: generate ANSI escape sequences from terminal state diffs, batched.
async fn mosh_relay_loop(
    inner: Arc<TerminalChannelInner>,
    mut output_rx: mpsc::Receiver<Vec<u8>>,
    mut shutdown_rx: mpsc::Receiver<()>,
) {
    debug!(channel_id = %inner.channel_id, "Terminal relay: MOSH mode (ANSI from state diffs, batched)");

    let mut output_sender = TransportSender::for_server();
    let mut display = Display::new();

    loop {
        tokio::select! {
            biased;

            _ = shutdown_rx.recv() => {
                debug!(channel_id = %inner.channel_id, "Terminal relay shutdown");
                // Generate final frame and send
                let state = inner.parser.lock().await.state().clone();
                let ansi = display.new_frame(&state);
                if !ansi.is_empty() {
                    let _ = inner.send_output_to_client(ansi).await;
                }
                break;
            }

            output = output_rx.recv() => {
                match output {
                    Some(data) => {
                        // Update terminal state from raw PTY output
                        inner.update_state_and_broadcast(&data).await;

                        // Accumulate raw bytes for timing (use dummy byte)
                        output_sender.push(&[0]);

                        // Check if it's time to send a frame
                        if output_sender.tick().is_some() {
                            output_sender.flush();

                            // Generate complete ANSI frame from current state
                            let state = inner.parser.lock().await.state().clone();
                            let ansi = display.new_frame(&state);

                            trace!(
                                channel_id = %inner.channel_id,
                                output_len = data.len(),
                                ansi_len = ansi.len(),
                                "Generated ANSI frame (mosh mode)"
                            );

                            // Send complete frame immediately (don't batch frames together!)
                            if !ansi.is_empty() {
                                let _ = inner.send_output_to_client(ansi).await;
                            }
                        }
                    }
                    None => {
                        // Generate final frame and send
                        let state = inner.parser.lock().await.state().clone();
                        let ansi = display.new_frame(&state);
                        if !ansi.is_empty() {
                            debug!(
                                channel_id = %inner.channel_id,
                                len = ansi.len(),
                                "Sending final ANSI frame on PTY exit"
                            );
                            let _ = inner.send_output_to_client(ansi).await;
                        }
                        info!(channel_id = %inner.channel_id, "PTY output_rx returned None - PTY exited, breaking relay loop");
                        break;
                    }
                }
            }

            _ = tokio::time::sleep_until(output_sender.next_send_time().into()),
                if output_sender.has_pending() => {
                output_sender.flush();

                // Time to send a frame
                let state = inner.parser.lock().await.state().clone();
                let ansi = display.new_frame(&state);

                trace!(
                    channel_id = %inner.channel_id,
                    len = ansi.len(),
                    "Generated ANSI frame (timer)"
                );

                // Send complete frame immediately
                if !ansi.is_empty() {
                    let _ = inner.send_output_to_client(ansi).await;
                }
            }
        }
    }
}

/// StateDiff relay loop: send binary StateDiff structs, batched.
async fn statediff_relay_loop(
    inner: Arc<TerminalChannelInner>,
    mut output_rx: mpsc::Receiver<Vec<u8>>,
    mut shutdown_rx: mpsc::Receiver<()>,
) {
    debug!(channel_id = %inner.channel_id, "Terminal relay: STATEDIFF mode (binary diffs, batched)");

    let mut output_sender = TransportSender::for_server();
    let mut last_sent_state: Option<TerminalState> = None;

    loop {
        tokio::select! {
            biased;

            _ = shutdown_rx.recv() => {
                debug!(channel_id = %inner.channel_id, "Terminal relay shutdown");
                send_state_diff(&inner, &mut last_sent_state).await;
                break;
            }

            output = output_rx.recv() => {
                match output {
                    Some(data) => {
                        inner.update_state_and_broadcast(&data).await;
                        output_sender.push(&[0]); // Dummy byte for timing

                        if output_sender.tick().is_some() {
                            output_sender.flush();
                            send_state_diff(&inner, &mut last_sent_state).await;
                        }
                    }
                    None => {
                        send_state_diff(&inner, &mut last_sent_state).await;
                        info!(channel_id = %inner.channel_id, "PTY output_rx returned None - PTY exited, breaking relay loop");
                        break;
                    }
                }
            }

            _ = tokio::time::sleep_until(output_sender.next_send_time().into()),
                if output_sender.has_pending() => {
                output_sender.flush();
                send_state_diff(&inner, &mut last_sent_state).await;
            }
        }
    }
}

/// Helper function to send state diff in statediff mode.
async fn send_state_diff(
    inner: &TerminalChannelInner,
    last_sent_state: &mut Option<TerminalState>,
) {
    let current_state = inner.parser.lock().await.state().clone();

    let diff = if let Some(last) = last_sent_state {
        last.diff_to(&current_state)
    } else {
        StateDiff::Full(current_state.clone())
    };

    trace!(
        channel_id = %inner.channel_id,
        diff_type = match &diff {
            StateDiff::Full(_) => "Full",
            StateDiff::Incremental { .. } => "Incremental",
            StateDiff::CursorOnly { .. } => "CursorOnly",
        },
        "Sending state diff"
    );

    let _ = inner.send_state_update(diff).await;
    *last_sent_state = Some(current_state);
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

            // Note: StateUpdate removed to fix sync bug with batched output.
            // The client reconstructs terminal state from raw output.
            // StateUpdate is only sent on reconnection (see reconnect_output method).
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

    /// Send state update to client (used in statediff mode).
    async fn send_state_update(&self, diff: StateDiff) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Ok(());
        }

        // Skip sending if disconnected
        if self.disconnected.load(Ordering::SeqCst) {
            return Ok(());
        }

        let mut stream_guard = self.output_stream.lock().await;
        if let Some(ref mut stream) = *stream_guard {
            let state_update = Message::ChannelDataMsg(ChannelData {
                channel_id: self.channel_id,
                payload: ChannelPayload::StateUpdate(StateUpdateData {
                    diff,
                    confirmed_input_seq: self.confirmed_input_seq.load(Ordering::SeqCst),
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_micros() as u64,
                }),
            });

            if let Err(e) = stream.send(&state_update).await {
                // Connection lost - mark disconnected
                if !self.disconnected.swap(true, Ordering::SeqCst) {
                    info!(
                        channel_id = %self.channel_id,
                        error = %e,
                        "Output stream disconnected during state update"
                    );
                }
                return Ok(());
            }
        }

        Ok(())
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

            // Send raw output
            let output = Message::ChannelDataMsg(ChannelData {
                channel_id,
                payload: ChannelPayload::TerminalOutput(TerminalOutputData {
                    data, // Move data, no clone needed
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

            // Note: StateUpdate removed to fix sync bug with batched output.
            // The client reconstructs terminal state from raw output.
            // StateUpdate is only sent on reconnection (see reconnect_output method).
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
