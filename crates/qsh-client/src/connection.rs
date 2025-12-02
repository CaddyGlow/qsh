//! Client connection management.
//!
//! Handles the full connection lifecycle:
//! 1. SSH bootstrap to discover QUIC endpoint
//! 2. QUIC connection establishment with cert pinning
//! 3. Session handshake (Hello/HelloAck)
//! 4. Terminal I/O with prediction
//! 5. Reconnection on network change

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::{ClientConfig, Endpoint};
use tracing::{debug, info};

use qsh_core::error::{Error, Result};
use qsh_core::protocol::{
    Capabilities, HelloPayload, Message, ResizePayload, ShutdownPayload, ShutdownReason, TermSize,
    TerminalInputPayload,
};
use qsh_core::session::{InputTracker, SessionState};
use qsh_core::transport::{
    Connection, QuicConnection, QuicStream, StreamPair, client_crypto_config,
};

use crate::prediction::PredictionEngine;

// ============================================================================
// Latency Tracker
// ============================================================================

/// Tracks input-to-output latency for measuring responsiveness.
#[derive(Debug)]
pub struct LatencyTracker {
    /// Timestamps when input sequences were sent.
    pending: HashMap<u64, Instant>,
    /// Recent latency samples (circular buffer).
    samples: Vec<Duration>,
    /// Index for circular buffer.
    sample_idx: usize,
    /// Maximum samples to keep.
    max_samples: usize,
    /// Minimum observed latency.
    min_latency: Option<Duration>,
    /// Maximum observed latency.
    max_latency: Option<Duration>,
}

impl LatencyTracker {
    /// Create a new latency tracker.
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            samples: Vec::with_capacity(100),
            sample_idx: 0,
            max_samples: 100,
            min_latency: None,
            max_latency: None,
        }
    }

    /// Record when an input sequence was sent.
    pub fn record_send(&mut self, seq: u64) {
        self.pending.insert(seq, Instant::now());
        // Clean up old entries (keep last 1000)
        if self.pending.len() > 1000 {
            let min_seq = seq.saturating_sub(1000);
            self.pending.retain(|&k, _| k >= min_seq);
        }
    }

    /// Record when a sequence was confirmed, returning the latency.
    pub fn record_confirm(&mut self, seq: u64) -> Option<Duration> {
        if let Some(sent_at) = self.pending.remove(&seq) {
            let latency = sent_at.elapsed();

            // Update min/max
            self.min_latency = Some(self.min_latency.map_or(latency, |min| min.min(latency)));
            self.max_latency = Some(self.max_latency.map_or(latency, |max| max.max(latency)));

            // Add to samples
            if self.samples.len() < self.max_samples {
                self.samples.push(latency);
            } else {
                self.samples[self.sample_idx] = latency;
            }
            self.sample_idx = (self.sample_idx + 1) % self.max_samples;

            Some(latency)
        } else {
            None
        }
    }

    /// Get the average latency from recent samples.
    pub fn average(&self) -> Option<Duration> {
        if self.samples.is_empty() {
            return None;
        }
        let sum: Duration = self.samples.iter().sum();
        Some(sum / self.samples.len() as u32)
    }

    /// Get latency statistics.
    pub fn stats(&self) -> LatencyStats {
        LatencyStats {
            sample_count: self.samples.len(),
            average: self.average(),
            min: self.min_latency,
            max: self.max_latency,
        }
    }
}

impl Default for LatencyTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Latency statistics snapshot.
#[derive(Debug, Clone)]
pub struct LatencyStats {
    /// Number of samples collected.
    pub sample_count: usize,
    /// Average latency.
    pub average: Option<Duration>,
    /// Minimum observed latency.
    pub min: Option<Duration>,
    /// Maximum observed latency.
    pub max: Option<Duration>,
}

impl std::fmt::Display for LatencyStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(avg) = self.average {
            write!(
                f,
                "avg={:.1}ms min={:.1}ms max={:.1}ms (n={})",
                avg.as_secs_f64() * 1000.0,
                self.min.unwrap_or_default().as_secs_f64() * 1000.0,
                self.max.unwrap_or_default().as_secs_f64() * 1000.0,
                self.sample_count
            )
        } else {
            write!(f, "no samples")
        }
    }
}

/// Client connection configuration.
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    /// Server address for QUIC connection.
    pub server_addr: SocketAddr,
    /// Session key from bootstrap.
    pub session_key: [u8; 32],
    /// Expected server certificate hash (optional, for pinning).
    pub cert_hash: Option<Vec<u8>>,
    /// Terminal size.
    pub term_size: TermSize,
    /// TERM environment variable.
    pub term_type: String,
    /// Enable predictive echo.
    pub predictive_echo: bool,
    /// Connection timeout.
    pub connect_timeout: Duration,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            server_addr: "127.0.0.1:4500".parse().unwrap(),
            session_key: [0; 32],
            cert_hash: None,
            term_size: TermSize { cols: 80, rows: 24 },
            term_type: "xterm-256color".to_string(),
            predictive_echo: true,
            connect_timeout: Duration::from_secs(10),
        }
    }
}

/// Active client connection.
pub struct ClientConnection {
    /// QUIC connection wrapper (shared for forwarders).
    quic: Arc<QuicConnection>,
    /// Control stream for protocol messages.
    control: QuicStream,
    /// Channel for queueing outgoing messages.
    outgoing_tx: tokio::sync::mpsc::UnboundedSender<Message>,
    /// Session state.
    session: SessionState,
    /// Input sequence tracker.
    input_tracker: InputTracker,
    /// Prediction engine for local echo.
    #[allow(dead_code)] // Will be used when terminal I/O is implemented
    prediction: PredictionEngine,
    /// Server capabilities.
    server_caps: Capabilities,
    /// Latency tracker for input-to-output measurement.
    latency_tracker: LatencyTracker,
    /// Handle to sender task (kept alive).
    _sender_task: tokio::task::JoinHandle<()>,
}

impl ClientConnection {
    /// Establish a new connection to the server.
    pub async fn connect(config: ConnectionConfig) -> Result<Self> {
        info!(addr = %config.server_addr, "Connecting to server");

        // Create QUIC endpoint
        let mut endpoint =
            Endpoint::client("0.0.0.0:0".parse().unwrap()).map_err(|e| Error::Transport {
                message: format!("failed to create QUIC endpoint: {}", e),
            })?;

        // Configure TLS with optional cert pinning
        let crypto = client_crypto_config(config.cert_hash.as_deref())?;
        let client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto).map_err(|e| {
                Error::Transport {
                    message: format!("failed to create QUIC config: {}", e),
                }
            })?,
        ));
        endpoint.set_default_client_config(client_config);

        // Connect to server
        let connecting = endpoint
            .connect(config.server_addr, "qsh-server")
            .map_err(|e| Error::Transport {
                message: format!("failed to initiate connection: {}", e),
            })?;

        let conn = tokio::time::timeout(config.connect_timeout, connecting)
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|e| Error::Transport {
                message: format!("connection failed: {}", e),
            })?;

        info!("QUIC connection established");
        let quic = Arc::new(QuicConnection::new(conn));

        // Open control stream (client-initiated bidi 0)
        let mut control = quic
            .open_stream(qsh_core::transport::StreamType::Control)
            .await?;

        // Send Hello
        let hello = HelloPayload {
            protocol_version: 1,
            session_key: config.session_key,
            client_nonce: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
            capabilities: Capabilities {
                predictive_echo: config.predictive_echo,
                compression: false,
                max_forwards: 10,
                tunnel: false,
            },
            term_size: config.term_size,
            term_type: config.term_type.clone(),
            last_generation: 0,
            last_input_seq: 0,
        };

        control.send(&Message::Hello(hello)).await?;
        debug!("Sent Hello");

        // Wait for HelloAck
        let hello_ack = match control.recv().await? {
            Message::HelloAck(ack) => ack,
            other => {
                return Err(Error::Protocol {
                    message: format!("expected HelloAck, got {:?}", other),
                });
            }
        };

        if !hello_ack.accepted {
            return Err(Error::AuthenticationFailed);
        }

        info!(
            zero_rtt = hello_ack.zero_rtt_available,
            "Session established"
        );

        let session = SessionState::new(config.session_key);
        let input_tracker = InputTracker::new();
        let prediction = PredictionEngine::new();
        let latency_tracker = LatencyTracker::new();

        // Create a channel for outgoing messages and spawn a sender task
        let (outgoing_tx, mut outgoing_rx) = tokio::sync::mpsc::unbounded_channel::<Message>();
        let sender = control.sender();
        let sender_task = tokio::spawn(async move {
            while let Some(msg) = outgoing_rx.recv().await {
                if let Err(e) = sender.send(&msg).await {
                    tracing::error!(error = %e, "Sender task failed");
                    break;
                }
            }
            tracing::debug!("Sender task ended");
        });

        Ok(Self {
            quic,
            control,
            outgoing_tx,
            session,
            input_tracker,
            prediction,
            server_caps: hello_ack.capabilities,
            latency_tracker,
            _sender_task: sender_task,
        })
    }

    /// Get the server capabilities.
    pub fn server_capabilities(&self) -> &Capabilities {
        &self.server_caps
    }

    /// Get the session state.
    pub fn session(&self) -> &SessionState {
        &self.session
    }

    /// Get the current RTT estimate.
    pub fn rtt(&self) -> Duration {
        self.quic.rtt()
    }

    /// Get a shared reference to the underlying QUIC connection.
    ///
    /// Used by forwarders to open additional streams.
    pub fn quic_connection(&self) -> Arc<QuicConnection> {
        Arc::clone(&self.quic)
    }

    /// Send terminal input to the server (blocking).
    ///
    /// Returns the sequence number assigned to this input.
    /// Note: This awaits the send completion. For non-blocking sends,
    /// use `queue_input` instead.
    pub async fn send_input(&mut self, data: &[u8]) -> Result<u64> {
        // Track for reliable delivery
        let predictable = self.server_caps.predictive_echo;
        let seq = self.input_tracker.push(data.to_vec(), predictable);

        // Record send time for latency tracking
        self.latency_tracker.record_send(seq);

        let msg = Message::TerminalInput(TerminalInputPayload {
            sequence: seq,
            data: data.to_vec(),
            predictable,
        });

        self.control.send(&msg).await?;
        Ok(seq)
    }

    /// Queue terminal input for sending without blocking.
    ///
    /// Returns the sequence number assigned to this input.
    /// The message is queued to a channel and sent by a background task.
    /// This prevents the main loop from being blocked by QUIC send latency.
    pub fn queue_input(&mut self, data: &[u8]) -> Result<u64> {
        // Track for reliable delivery
        let predictable = self.server_caps.predictive_echo;
        let seq = self.input_tracker.push(data.to_vec(), predictable);

        // Record send time for latency tracking
        self.latency_tracker.record_send(seq);

        let msg = Message::TerminalInput(TerminalInputPayload {
            sequence: seq,
            data: data.to_vec(),
            predictable,
        });

        // Queue to the sender task - this is non-blocking (unbounded channel)
        if self.outgoing_tx.send(msg).is_err() {
            return Err(Error::Transport {
                message: "sender task closed".to_string(),
            });
        }

        Ok(seq)
    }

    /// Record that a sequence was confirmed by the server.
    ///
    /// Returns the measured latency if the sequence was being tracked.
    pub fn record_confirmation(&mut self, seq: u64) -> Option<Duration> {
        self.latency_tracker.record_confirm(seq)
    }

    /// Get the current latency statistics.
    pub fn latency_stats(&self) -> LatencyStats {
        self.latency_tracker.stats()
    }

    /// Send a ping for latency measurement.
    pub async fn ping(&mut self) -> Result<Duration> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;

        self.control.send(&Message::Ping(timestamp)).await?;

        // Wait for Pong
        let pong_time = match self.control.recv().await? {
            Message::Pong(ts) => ts,
            other => {
                return Err(Error::Protocol {
                    message: format!("expected Pong, got {:?}", other),
                });
            }
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;

        Ok(Duration::from_micros(now - pong_time))
    }

    /// Receive a message from the server.
    pub async fn recv(&mut self) -> Result<Message> {
        self.control.recv().await
    }

    /// Send a resize notification to the server.
    pub async fn send_resize(&mut self, cols: u16, rows: u16) -> Result<()> {
        self.control
            .send(&Message::Resize(ResizePayload { cols, rows }))
            .await
    }

    /// Close the connection gracefully.
    pub async fn close(mut self) -> Result<()> {
        self.control
            .send(&Message::Shutdown(ShutdownPayload {
                reason: ShutdownReason::UserRequested,
                message: Some("client disconnect".to_string()),
            }))
            .await?;

        self.control.close();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_config_default() {
        let config = ConnectionConfig::default();
        assert_eq!(config.term_size.cols, 80);
        assert_eq!(config.term_size.rows, 24);
        assert!(config.predictive_echo);
    }

    #[test]
    fn latency_tracker_new() {
        let tracker = LatencyTracker::new();
        assert!(tracker.average().is_none());
        let stats = tracker.stats();
        assert_eq!(stats.sample_count, 0);
    }

    #[test]
    fn latency_tracker_record_and_confirm() {
        let mut tracker = LatencyTracker::new();

        // Record send
        tracker.record_send(1);

        // Small delay to ensure measurable latency
        std::thread::sleep(std::time::Duration::from_millis(1));

        // Confirm and get latency
        let latency = tracker.record_confirm(1);
        assert!(latency.is_some());
        assert!(latency.unwrap() >= std::time::Duration::from_millis(1));

        // Stats should reflect the sample
        let stats = tracker.stats();
        assert_eq!(stats.sample_count, 1);
        assert!(stats.average.is_some());
        assert!(stats.min.is_some());
        assert!(stats.max.is_some());
    }

    #[test]
    fn latency_tracker_unknown_seq() {
        let mut tracker = LatencyTracker::new();

        // Confirming unknown sequence returns None
        let latency = tracker.record_confirm(999);
        assert!(latency.is_none());
    }

    #[test]
    fn latency_tracker_min_max() {
        let mut tracker = LatencyTracker::new();

        // First sample
        tracker.record_send(1);
        std::thread::sleep(std::time::Duration::from_millis(5));
        tracker.record_confirm(1);

        // Second sample (should be similar or longer due to sleep)
        tracker.record_send(2);
        std::thread::sleep(std::time::Duration::from_millis(10));
        tracker.record_confirm(2);

        let stats = tracker.stats();
        assert_eq!(stats.sample_count, 2);
        // Max should be >= min
        assert!(stats.max.unwrap() >= stats.min.unwrap());
    }

    #[test]
    fn latency_stats_display() {
        let mut tracker = LatencyTracker::new();
        tracker.record_send(1);
        std::thread::sleep(std::time::Duration::from_millis(1));
        tracker.record_confirm(1);

        let stats = tracker.stats();
        let display = format!("{}", stats);
        assert!(display.contains("avg="));
        assert!(display.contains("min="));
        assert!(display.contains("max="));
        assert!(display.contains("n=1"));
    }

    #[test]
    fn latency_stats_display_no_samples() {
        let tracker = LatencyTracker::new();
        let stats = tracker.stats();
        let display = format!("{}", stats);
        assert_eq!(display, "no samples");
    }
}
