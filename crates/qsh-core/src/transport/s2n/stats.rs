//! Connection statistics and event handling for s2n-quic.
//!
//! This module provides shared connection statistics updated by the event subscriber,
//! handshake state tracking, and session ticket management for 0-RTT resumption.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use s2n_quic::provider::tls::s2n_tls::callbacks::ConnectionFuture;
use tokio::sync::Notify;

// =============================================================================
// Connection Statistics (shared between event subscriber and connection)
// =============================================================================

/// Shared connection statistics updated by the event subscriber.
///
/// These statistics are updated atomically by the s2n-quic event system
/// and can be read from the S2nConnection at any time.
#[derive(Debug, Default)]
pub struct ConnectionStats {
    /// Smoothed RTT in microseconds.
    smoothed_rtt_us: AtomicU64,
    /// Minimum RTT in microseconds.
    min_rtt_us: AtomicU64,
    /// Latest RTT sample in microseconds.
    latest_rtt_us: AtomicU64,
    /// Current congestion window in bytes.
    congestion_window: AtomicU32,
    /// Bytes currently in flight.
    bytes_in_flight: AtomicU32,
    /// Total packets lost.
    packets_lost: AtomicU64,
    /// Total bytes lost.
    bytes_lost: AtomicU64,
    /// Total packets sent (for loss ratio calculation).
    packets_sent: AtomicU64,
}

impl ConnectionStats {
    /// Get smoothed RTT as Duration.
    pub fn smoothed_rtt(&self) -> Duration {
        Duration::from_micros(self.smoothed_rtt_us.load(Ordering::Relaxed))
    }

    /// Get minimum RTT as Duration.
    pub fn min_rtt(&self) -> Duration {
        Duration::from_micros(self.min_rtt_us.load(Ordering::Relaxed))
    }

    /// Get latest RTT sample as Duration.
    pub fn latest_rtt(&self) -> Duration {
        Duration::from_micros(self.latest_rtt_us.load(Ordering::Relaxed))
    }

    /// Get congestion window in bytes.
    pub fn congestion_window(&self) -> u32 {
        self.congestion_window.load(Ordering::Relaxed)
    }

    /// Get bytes in flight.
    pub fn bytes_in_flight(&self) -> u32 {
        self.bytes_in_flight.load(Ordering::Relaxed)
    }

    /// Get packet loss ratio (0.0 - 1.0).
    pub fn packet_loss_ratio(&self) -> f64 {
        let sent = self.packets_sent.load(Ordering::Relaxed);
        let lost = self.packets_lost.load(Ordering::Relaxed);
        if sent == 0 {
            0.0
        } else {
            lost as f64 / sent as f64
        }
    }

    /// Get total packets lost.
    pub fn packets_lost(&self) -> u64 {
        self.packets_lost.load(Ordering::Relaxed)
    }

    /// Get total bytes lost.
    pub fn bytes_lost(&self) -> u64 {
        self.bytes_lost.load(Ordering::Relaxed)
    }
}

// =============================================================================
// Handshake State
// =============================================================================

/// Handshake status shared between the event subscriber and connection wrapper.
#[derive(Debug, Default)]
pub struct HandshakeState {
    complete: AtomicBool,
    confirmed: AtomicBool,
}

impl HandshakeState {
    pub(crate) fn mark_complete(&self) {
        self.complete.store(true, Ordering::Relaxed);
    }

    pub(crate) fn mark_confirmed(&self) {
        self.complete.store(true, Ordering::Relaxed);
        self.confirmed.store(true, Ordering::Relaxed);
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.complete.load(Ordering::Relaxed)
    }
}

// =============================================================================
// Session Ticket State for 0-RTT Resumption
// =============================================================================

/// Shared session ticket state used for 0-RTT resumption.
#[derive(Default)]
pub(crate) struct SessionTicketState {
    ticket: std::sync::Mutex<Option<Vec<u8>>>,
    resumed: AtomicBool,
    pub(crate) notify: Notify,
}

impl SessionTicketState {
    pub(crate) fn new(initial: Option<Vec<u8>>) -> Arc<Self> {
        Arc::new(Self {
            ticket: std::sync::Mutex::new(initial),
            resumed: AtomicBool::new(false),
            notify: Notify::new(),
        })
    }

    pub(crate) fn set_ticket(&self, data: Vec<u8>) {
        *self.ticket.lock().unwrap() = Some(data);
        self.notify.notify_waiters();
    }

    pub(crate) fn ticket(&self) -> Option<Vec<u8>> {
        self.ticket.lock().unwrap().clone()
    }

    pub(crate) fn set_resumed(&self, resumed: bool) {
        self.resumed.store(resumed, Ordering::Relaxed);
        self.notify.notify_waiters();
    }

    pub(crate) fn is_resumed(&self) -> bool {
        self.resumed.load(Ordering::Relaxed)
    }
}

// =============================================================================
// Session Ticket Handler
// =============================================================================

/// Handler that injects and captures session tickets for resumption.
#[derive(Clone)]
pub(crate) struct SessionTicketHandler {
    state: Arc<SessionTicketState>,
}

impl SessionTicketHandler {
    pub(crate) fn new(state: Arc<SessionTicketState>) -> Self {
        Self { state }
    }
}

impl s2n_quic::provider::tls::s2n_tls::config::ConnectionInitializer for SessionTicketHandler {
    fn initialize_connection(
        &self,
        connection: &mut s2n_quic::provider::tls::s2n_tls::connection::Connection,
    ) -> std::result::Result<
        Option<Pin<Box<dyn ConnectionFuture>>>,
        s2n_quic::provider::tls::s2n_tls::error::Error,
    > {
        if let Some(ticket) = self.state.ticket() {
            // Best effort; if resumption fails the handshake falls back to full 1-RTT.
            let _ = connection.set_session_ticket(&ticket);
        }
        Ok(None)
    }
}

impl s2n_quic::provider::tls::s2n_tls::callbacks::SessionTicketCallback for SessionTicketHandler {
    fn on_session_ticket(
        &self,
        connection: &mut s2n_quic::provider::tls::s2n_tls::connection::Connection,
        session_ticket: &s2n_quic::provider::tls::s2n_tls::callbacks::SessionTicket,
    ) {
        if let Ok(size) = session_ticket.len() {
            let mut data = vec![0; size];
            if session_ticket.data(&mut data).is_ok() {
                self.state.set_ticket(data);
            }
        }
        self.state.set_resumed(connection.resumed());
    }
}

// =============================================================================
// Event Subscriber for Statistics
// =============================================================================

/// Event subscriber that collects connection statistics.
///
/// This subscriber receives events from s2n-quic and updates the shared
/// ConnectionStats structure.
pub struct StatsSubscriber {
    stats: Arc<ConnectionStats>,
    handshake: Arc<HandshakeState>,
}

impl StatsSubscriber {
    /// Create a new statistics subscriber with shared stats.
    pub fn new(stats: Arc<ConnectionStats>, handshake: Arc<HandshakeState>) -> Self {
        Self { stats, handshake }
    }
}

/// Per-connection context for the stats subscriber.
pub struct StatsContext {
    stats: Arc<ConnectionStats>,
    handshake: Arc<HandshakeState>,
}

impl s2n_quic::provider::event::Subscriber for StatsSubscriber {
    type ConnectionContext = StatsContext;

    fn create_connection_context(
        &mut self,
        _meta: &s2n_quic::provider::event::events::ConnectionMeta,
        _info: &s2n_quic::provider::event::events::ConnectionInfo,
    ) -> Self::ConnectionContext {
        StatsContext {
            stats: Arc::clone(&self.stats),
            handshake: Arc::clone(&self.handshake),
        }
    }

    fn on_recovery_metrics(
        &mut self,
        context: &mut Self::ConnectionContext,
        _meta: &s2n_quic::provider::event::events::ConnectionMeta,
        event: &s2n_quic::provider::event::events::RecoveryMetrics,
    ) {
        context
            .stats
            .smoothed_rtt_us
            .store(event.smoothed_rtt.as_micros() as u64, Ordering::Relaxed);
        context
            .stats
            .min_rtt_us
            .store(event.min_rtt.as_micros() as u64, Ordering::Relaxed);
        context
            .stats
            .latest_rtt_us
            .store(event.latest_rtt.as_micros() as u64, Ordering::Relaxed);
        context
            .stats
            .congestion_window
            .store(event.congestion_window, Ordering::Relaxed);
        context
            .stats
            .bytes_in_flight
            .store(event.bytes_in_flight, Ordering::Relaxed);
    }

    fn on_packet_lost(
        &mut self,
        context: &mut Self::ConnectionContext,
        _meta: &s2n_quic::provider::event::events::ConnectionMeta,
        event: &s2n_quic::provider::event::events::PacketLost,
    ) {
        context.stats.packets_lost.fetch_add(1, Ordering::Relaxed);
        context
            .stats
            .bytes_lost
            .fetch_add(event.bytes_lost as u64, Ordering::Relaxed);
    }

    fn on_packet_sent(
        &mut self,
        context: &mut Self::ConnectionContext,
        _meta: &s2n_quic::provider::event::events::ConnectionMeta,
        _event: &s2n_quic::provider::event::events::PacketSent,
    ) {
        context.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
    }

    fn on_handshake_status_updated(
        &mut self,
        context: &mut Self::ConnectionContext,
        _meta: &s2n_quic::provider::event::events::ConnectionMeta,
        event: &s2n_quic::provider::event::events::HandshakeStatusUpdated,
    ) {
        use s2n_quic::provider::event::events::HandshakeStatus::*;
        match event.status {
            Complete { .. } | HandshakeDoneLost { .. } => context.handshake.mark_complete(),
            HandshakeDoneAcked { .. } | Confirmed { .. } => context.handshake.mark_confirmed(),
            _ => {}
        }
    }
}
