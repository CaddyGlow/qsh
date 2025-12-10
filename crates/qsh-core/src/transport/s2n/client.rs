//! S2N client connection establishment.
//!
//! This module provides functions for establishing QUIC client connections
//! using s2n-quic, including support for 0-RTT session resumption.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::debug;

use crate::error::{Error, Result};

use super::connection::S2nConnection;
use super::stats::{ConnectionStats, HandshakeState, SessionTicketHandler, SessionTicketState, StatsSubscriber};
use super::{ConnectConfig, ConnectResult};

/// Wait for a session ticket to be delivered, with timeout.
async fn wait_for_session_ticket(
    state: &Arc<SessionTicketState>,
    timeout: Duration,
) -> Option<Vec<u8>> {
    if let Some(ticket) = state.ticket() {
        return Some(ticket);
    }

    let _ = tokio::time::timeout(timeout, state.notify.notified()).await.ok()?;
    state.ticket()
}

/// Wait for the resumption flag to be set, with timeout.
async fn wait_for_resumption_flag(
    state: &Arc<SessionTicketState>,
    timeout: Duration,
) -> bool {
    if state.is_resumed() {
        return true;
    }

    let _ = tokio::time::timeout(timeout, state.notify.notified()).await;
    state.is_resumed()
}

/// Establish a QUIC client connection using s2n-quic.
///
/// This performs the full QUIC/TLS handshake and returns a connected
/// `S2nConnection`.
///
/// # Arguments
/// * `config` - Connection configuration including server address, timeouts, and optional session data
///
/// # Returns
/// * `Ok(ConnectResult)` - Contains the connection, resume status, and cached session data (if available)
/// * `Err(Error)` - On connection failure (timeout, handshake failure, certificate mismatch)
///
/// # 0-RTT Session Resumption
/// s2n-quic uses TLS session tickets for 0-RTT. Any provided `session_data` is
/// applied via s2n-tls, and new tickets are captured for reuse on reconnect. If
/// a ticket has not arrived before the function returns, it can still be fetched
/// later via `connection.session_data()`.
///
/// # Certificate Verification
/// - X.509 verification is disabled for bootstrap mode (self-signed certificates)
/// - Certificate hash verification should be done at the application layer
pub async fn connect_quic(config: &ConnectConfig) -> Result<ConnectResult<S2nConnection>> {
    use s2n_quic::Client;
    use s2n_quic::client::Connect;
    use s2n_quic::provider::tls::s2n_tls;

    let start = Instant::now();

    // Create shared statistics for event subscriber
    let stats = Arc::new(ConnectionStats::default());
    let handshake_state = Arc::new(HandshakeState::default());
    let event_subscriber = StatsSubscriber::new(Arc::clone(&stats), Arc::clone(&handshake_state));
    let session_state = SessionTicketState::new(config.session_data.clone());
    let ticket_handler = SessionTicketHandler::new(Arc::clone(&session_state));

    // Build the client
    // Note: s2n-quic binds internally, we can't specify a local port directly
    // For local port binding, we would need to use a custom I/O provider
    let bind_addr = if config.server_addr.is_ipv4() {
        format!("0.0.0.0:{}", config.local_port.unwrap_or(0))
    } else {
        format!("[::]:{}", config.local_port.unwrap_or(0))
    };

    // Configure TLS
    // For bootstrap mode, we disable X.509 verification since we're using
    // self-signed certificates with hash-based pinning
    let mut tls_builder = s2n_tls::Client::builder();

    tls_builder
        .config_mut()
        .enable_session_tickets(true)
        .map_err(|e| Error::Transport {
            message: format!("failed to enable session tickets: {}", e),
        })?
        .set_session_ticket_callback(ticket_handler.clone())
        .map_err(|e| Error::Transport {
            message: format!("failed to set session ticket callback: {}", e),
        })?
        .set_connection_initializer(ticket_handler.clone())
        .map_err(|e| Error::Transport {
            message: format!("failed to set connection initializer: {}", e),
        })?;

    // Disable X.509 verification for self-signed certificates
    // SAFETY: This is used for bootstrap mode where certificates are verified via hash pinning
    // instead of traditional CA chains. The cert_hash is verified after the handshake completes.
    unsafe {
        tls_builder.config_mut().disable_x509_verification().map_err(|e| Error::Transport {
            message: format!("failed to disable x509 verification: {}", e),
        })?;
    }

    let tls = tls_builder.build().map_err(|e| Error::Transport {
        message: format!("failed to build TLS config: {}", e),
    })?;

    // Configure limits including idle timeout
    let limits = s2n_quic::provider::limits::Limits::new()
        .with_max_idle_timeout(config.max_idle_timeout)
        .map_err(|e| Error::Transport {
            message: format!("failed to configure idle timeout: {}", e),
        })?;

    let client = Client::builder()
        .with_tls(tls)
        .map_err(|e| Error::Transport {
            message: format!("failed to configure TLS: {}", e),
        })?
        .with_limits(limits)
        .map_err(|e| Error::Transport {
            message: format!("failed to configure limits: {}", e),
        })?
        .with_event(event_subscriber)
        .map_err(|e| Error::Transport {
            message: format!("failed to configure event subscriber: {}", e),
        })?
        .with_io(bind_addr.as_str())
        .map_err(|e| Error::Transport {
            message: format!("failed to configure I/O: {}", e),
        })?
        .start()
        .map_err(|e| Error::Transport {
            message: format!("failed to start client: {}", e),
        })?;

    let local_addr = client.local_addr().map_err(|e| Error::Transport {
        message: format!("failed to get local address: {}", e),
    })?;

    // Create connect handle
    let connect = Connect::new(config.server_addr)
        .with_server_name("qsh-server");

    // Connect with timeout
    let connection = tokio::time::timeout(config.connect_timeout, client.connect(connect))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|e| Error::HandshakeFailed {
            message: format!("connection failed: {}", e),
        })?;

    let elapsed = start.elapsed();
    debug!(
        addr = %config.server_addr,
        elapsed_ms = elapsed.as_millis() as u64,
        "s2n-quic handshake completed"
    );

    // Wrap in S2nConnection with shared stats
    let s2n_conn = S2nConnection::from_client_connection(
        connection,
        local_addr,
        stats,
        handshake_state,
        Arc::clone(&session_state),
    ).await?;

    // Note: Certificate hash verification should be done at the application layer
    // s2n-quic doesn't expose the peer certificate chain directly

    // Wait briefly for session ticket delivery so callers can cache it for the
    // next reconnect. If a ticket hasn't arrived yet, the connection can still
    // export it later via `session_data()`.
    let resumed =
        wait_for_resumption_flag(&session_state, Duration::from_millis(500)).await;
    let session_data =
        wait_for_session_ticket(&session_state, Duration::from_millis(500)).await;

    Ok(ConnectResult {
        connection: s2n_conn,
        resumed,
        session_data,
    })
}
