//! Client-side channel abstractions for the SSH-style channel model.
//!
//! This module provides type-safe wrappers for different channel types:
//! - `TerminalChannel`: Interactive PTY sessions
//! - `FileChannel`: File upload/download operations
//! - `ForwardChannel`: Port forwarding (local and dynamic)

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use tokio::sync::{Mutex, mpsc};
use tracing::warn;

use qsh_core::error::{Error, Result};
use qsh_core::protocol::{
    ChannelData, ChannelId, ChannelPayload, DataFlags, FileCompleteData, FileDataData,
    FileTransferMetadata, FileTransferStatus, Message, TerminalInputData, TerminalOutputData,
};
use qsh_core::terminal::TerminalState;
use qsh_core::transport::{QuicSender, QuicStream, StreamPair};

use crate::prediction::PredictionEngine;

// =============================================================================
// Terminal Channel
// =============================================================================

/// Client-side terminal channel.
///
/// Provides methods for sending input and receiving output from a remote PTY.
#[derive(Clone)]
pub struct TerminalChannel {
    inner: Arc<TerminalChannelInner>,
}

struct TerminalChannelInner {
    /// Channel ID.
    channel_id: ChannelId,
    /// Input stream sender.
    input_sender: QuicSender,
    /// Output stream.
    output_stream: Mutex<QuicStream>,
    /// Initial terminal state from server.
    initial_state: Mutex<Option<TerminalState>>,
    /// Next input sequence number.
    next_seq: AtomicU64,
    /// Last confirmed input sequence.
    confirmed_seq: AtomicU64,
    /// Whether the channel is closed.
    closed: AtomicBool,
    /// Terminal size (cols, rows).
    term_size: Mutex<(u16, u16)>,
    /// Prediction engine for local echo.
    prediction: Mutex<PredictionEngine>,
    /// Channel for queued input messages.
    input_tx: mpsc::UnboundedSender<Message>,
    /// Background task handle.
    _input_task: tokio::task::JoinHandle<()>,
}

impl TerminalChannel {
    /// Create a new terminal channel.
    pub(crate) fn new(
        channel_id: ChannelId,
        input_stream: QuicStream,
        output_stream: QuicStream,
        initial_state: TerminalState,
    ) -> Self {
        let term_size = initial_state.size();
        let input_sender = input_stream.sender();

        // Create input sender task
        let (input_tx, mut input_rx) = mpsc::unbounded_channel::<Message>();
        let sender_clone = input_sender.clone();
        let input_task = tokio::spawn(async move {
            while let Some(msg) = input_rx.recv().await {
                if let Err(e) = sender_clone.send(&msg).await {
                    warn!(error = %e, "Terminal input sender failed");
                    break;
                }
            }
        });

        let inner = Arc::new(TerminalChannelInner {
            channel_id,
            input_sender,
            output_stream: Mutex::new(output_stream),
            initial_state: Mutex::new(Some(initial_state)),
            next_seq: AtomicU64::new(1),
            confirmed_seq: AtomicU64::new(0),
            closed: AtomicBool::new(false),
            term_size: Mutex::new(term_size),
            prediction: Mutex::new(PredictionEngine::new()),
            input_tx,
            _input_task: input_task,
        });

        Self { inner }
    }

    /// Get the channel ID.
    pub fn channel_id(&self) -> ChannelId {
        self.inner.channel_id
    }

    /// Take the initial terminal state (can only be called once).
    pub async fn take_initial_state(&self) -> Option<TerminalState> {
        self.inner.initial_state.lock().await.take()
    }

    /// Get the terminal size (cols, rows).
    pub async fn term_size(&self) -> (u16, u16) {
        *self.inner.term_size.lock().await
    }

    /// Send input to the terminal (non-blocking).
    ///
    /// Returns the sequence number assigned to this input.
    pub fn queue_input(&self, data: &[u8], predictable: bool) -> Result<u64> {
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(Error::ConnectionClosed);
        }

        let seq = self.inner.next_seq.fetch_add(1, Ordering::SeqCst);

        let msg = Message::ChannelDataMsg(ChannelData {
            channel_id: self.inner.channel_id,
            payload: ChannelPayload::TerminalInput(TerminalInputData {
                sequence: seq,
                data: data.to_vec(),
                predictable,
            }),
        });

        self.inner.input_tx.send(msg).map_err(|_| Error::Transport {
            message: "input channel closed".to_string(),
        })?;

        Ok(seq)
    }

    /// Send input to the terminal (blocking).
    pub async fn send_input(&self, data: &[u8], predictable: bool) -> Result<u64> {
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(Error::ConnectionClosed);
        }

        let seq = self.inner.next_seq.fetch_add(1, Ordering::SeqCst);

        let msg = Message::ChannelDataMsg(ChannelData {
            channel_id: self.inner.channel_id,
            payload: ChannelPayload::TerminalInput(TerminalInputData {
                sequence: seq,
                data: data.to_vec(),
                predictable,
            }),
        });

        self.inner.input_sender.send(&msg).await?;
        Ok(seq)
    }

    /// Receive output from the terminal.
    pub async fn recv_output(&self) -> Result<TerminalOutputData> {
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(Error::ConnectionClosed);
        }

        let mut stream = self.inner.output_stream.lock().await;
        loop {
            match stream.recv().await? {
                Message::ChannelDataMsg(data) => match data.payload {
                    ChannelPayload::TerminalOutput(output) => {
                        // Update confirmed sequence
                        self.inner
                            .confirmed_seq
                            .fetch_max(output.confirmed_input_seq, Ordering::SeqCst);
                        return Ok(output);
                    }
                    ChannelPayload::StateUpdate(update) => {
                        // State updates also confirm input
                        self.inner
                            .confirmed_seq
                            .fetch_max(update.confirmed_input_seq, Ordering::SeqCst);
                        // TODO: Process state diff for prediction
                    }
                    other => {
                        warn!(?other, "Unexpected channel payload on terminal output stream");
                    }
                },
                other => {
                    warn!(?other, "Unexpected message on terminal output stream");
                }
            }
        }
    }

    /// Record that a sequence was confirmed.
    pub fn confirm_seq(&self, seq: u64) {
        self.inner.confirmed_seq.fetch_max(seq, Ordering::SeqCst);
    }

    /// Get the last confirmed sequence.
    pub fn confirmed_seq(&self) -> u64 {
        self.inner.confirmed_seq.load(Ordering::SeqCst)
    }

    /// Get mutable access to the prediction engine.
    pub async fn prediction_mut(&self) -> tokio::sync::MutexGuard<'_, PredictionEngine> {
        self.inner.prediction.lock().await
    }

    /// Check if the channel is closed.
    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::SeqCst)
    }

    /// Mark the channel as closed.
    pub fn mark_closed(&self) {
        self.inner.closed.store(true, Ordering::SeqCst);
    }
}

// =============================================================================
// File Channel
// =============================================================================

/// Client-side file transfer channel.
#[derive(Clone)]
pub struct FileChannel {
    inner: Arc<FileChannelInner>,
}

struct FileChannelInner {
    /// Channel ID.
    channel_id: ChannelId,
    /// Bidirectional stream for file data.
    stream: Mutex<QuicStream>,
    /// File metadata (size, etc).
    metadata: Option<FileTransferMetadata>,
    /// Whether the channel is closed.
    closed: AtomicBool,
    /// Bytes transferred.
    bytes_transferred: AtomicU64,
    /// Resume offset (for resuming partial transfers).
    resume_offset: u64,
}

impl FileChannel {
    /// Create a new file channel.
    pub(crate) fn new(
        channel_id: ChannelId,
        stream: QuicStream,
        metadata: Option<FileTransferMetadata>,
        resume_offset: Option<u64>,
    ) -> Self {
        let inner = Arc::new(FileChannelInner {
            channel_id,
            stream: Mutex::new(stream),
            metadata,
            closed: AtomicBool::new(false),
            bytes_transferred: AtomicU64::new(0),
            resume_offset: resume_offset.unwrap_or(0),
        });

        Self { inner }
    }

    /// Get the channel ID.
    pub fn channel_id(&self) -> ChannelId {
        self.inner.channel_id
    }

    /// Get file metadata (for downloads).
    pub fn metadata(&self) -> Option<&FileTransferMetadata> {
        self.inner.metadata.as_ref()
    }

    /// Get the resume offset (for resuming partial transfers).
    pub fn resume_offset(&self) -> u64 {
        self.inner.resume_offset
    }

    /// Send file data chunk.
    pub async fn send_data(&self, offset: u64, data: Vec<u8>) -> Result<()> {
        self.send_data_with_flags(offset, data, DataFlags::default()).await
    }

    /// Send file data chunk with custom flags.
    pub async fn send_data_with_flags(
        &self,
        offset: u64,
        data: Vec<u8>,
        flags: DataFlags,
    ) -> Result<()> {
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(Error::ConnectionClosed);
        }

        let len = data.len() as u64;
        let msg = Message::ChannelDataMsg(ChannelData {
            channel_id: self.inner.channel_id,
            payload: ChannelPayload::FileData(FileDataData {
                offset,
                data,
                flags,
            }),
        });

        self.inner.stream.lock().await.send(&msg).await?;
        self.inner.bytes_transferred.fetch_add(len, Ordering::SeqCst);
        Ok(())
    }

    /// Send file transfer completion message.
    pub async fn send_complete(
        &self,
        checksum: u64,
        total_bytes: u64,
        status: FileTransferStatus,
    ) -> Result<()> {
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(Error::ConnectionClosed);
        }

        let msg = Message::ChannelDataMsg(ChannelData {
            channel_id: self.inner.channel_id,
            payload: ChannelPayload::FileComplete(FileCompleteData {
                checksum,
                total_bytes,
                status,
            }),
        });

        self.inner.stream.lock().await.send(&msg).await
    }

    /// Receive a message from the file channel.
    pub async fn recv(&self) -> Result<Message> {
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(Error::ConnectionClosed);
        }

        self.inner.stream.lock().await.recv().await
    }

    /// Get bytes transferred so far.
    pub fn bytes_transferred(&self) -> u64 {
        self.inner.bytes_transferred.load(Ordering::SeqCst)
    }

    /// Check if the channel is closed.
    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::SeqCst)
    }

    /// Mark the channel as closed.
    pub fn mark_closed(&self) {
        self.inner.closed.store(true, Ordering::SeqCst);
    }
}

// =============================================================================
// Forward Channel
// =============================================================================

/// Client-side port forward channel.
#[derive(Clone)]
pub struct ForwardChannel {
    inner: Arc<ForwardChannelInner>,
}

struct ForwardChannelInner {
    /// Channel ID.
    channel_id: ChannelId,
    /// Bidirectional stream for forwarded data.
    /// No outer Mutex needed - QuicStream has internal locks for send/recv.
    stream: QuicStream,
    /// Target host:port for this forward.
    target: (String, u16),
    /// Whether the channel is closed.
    closed: AtomicBool,
    /// Bytes sent.
    bytes_sent: AtomicU64,
    /// Bytes received.
    bytes_received: AtomicU64,
}

impl ForwardChannel {
    /// Create a new forward channel.
    pub(crate) fn new(
        channel_id: ChannelId,
        stream: QuicStream,
        target_host: String,
        target_port: u16,
    ) -> Self {
        let inner = Arc::new(ForwardChannelInner {
            channel_id,
            stream,
            target: (target_host, target_port),
            closed: AtomicBool::new(false),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
        });

        Self { inner }
    }

    /// Get the channel ID.
    pub fn channel_id(&self) -> ChannelId {
        self.inner.channel_id
    }

    /// Get the target (host, port).
    pub fn target(&self) -> (&str, u16) {
        (&self.inner.target.0, self.inner.target.1)
    }

    /// Send raw data through the forward.
    pub async fn send(&self, data: &[u8]) -> Result<()> {
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(Error::ConnectionClosed);
        }

        let len = data.len() as u64;
        self.inner.stream.send_raw(data).await?;
        self.inner.bytes_sent.fetch_add(len, Ordering::SeqCst);
        Ok(())
    }

    /// Receive raw data from the forward.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(Error::ConnectionClosed);
        }

        let n = self.inner.stream.recv_raw(buf).await?;
        self.inner.bytes_received.fetch_add(n as u64, Ordering::SeqCst);
        Ok(n)
    }

    /// Get bytes sent.
    pub fn bytes_sent(&self) -> u64 {
        self.inner.bytes_sent.load(Ordering::SeqCst)
    }

    /// Get bytes received.
    pub fn bytes_received(&self) -> u64 {
        self.inner.bytes_received.load(Ordering::SeqCst)
    }

    /// Check if the channel is closed.
    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::SeqCst)
    }

    /// Mark the channel as closed.
    pub fn mark_closed(&self) {
        self.inner.closed.store(true, Ordering::SeqCst);
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_types_compile() {
        // Just verify the types compile with Clone
        fn _assert_clone<T: Clone>() {}
        _assert_clone::<TerminalChannel>();
        _assert_clone::<FileChannel>();
        _assert_clone::<ForwardChannel>();
    }
}
