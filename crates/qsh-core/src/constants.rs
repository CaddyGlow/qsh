//! Protocol and configuration constants for qsh.

use std::time::Duration;

// =============================================================================
// Protocol Constants
// =============================================================================

/// Current protocol version.
pub const PROTOCOL_VERSION: u8 = 1;

/// ALPN identifier for QUIC connections.
pub const ALPN: &[u8] = b"qsh/1";

/// Maximum message payload size (16 MiB).
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// Maximum terminal columns.
pub const MAX_TERMINAL_COLS: u16 = 500;

/// Maximum terminal rows.
pub const MAX_TERMINAL_ROWS: u16 = 200;

/// Maximum terminal size as (cols, rows) tuple.
pub const MAX_TERMINAL_SIZE: (u16, u16) = (MAX_TERMINAL_COLS, MAX_TERMINAL_ROWS);

/// Session key length in bytes.
pub const SESSION_KEY_LEN: usize = 32;

// =============================================================================
// Timing Constants
// =============================================================================

/// QUIC idle timeout.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Session timeout (24 hours).
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(86400);

/// Reconnection timeout before session is considered lost.
pub const RECONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum reconnection timeout.
pub const MAX_RECONNECT_TIMEOUT: Duration = Duration::from_secs(60);

/// Bootstrap phase timeout.
pub const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(30);

/// State update debounce interval.
pub const STATE_UPDATE_DEBOUNCE: Duration = Duration::from_millis(10);

/// Anti-replay window duration.
pub const ANTI_REPLAY_WINDOW: Duration = Duration::from_secs(3600);

// =============================================================================
// Prediction Constants
// =============================================================================

/// Number of successful confirmations needed to restore confidence.
pub const PREDICTION_CONFIDENCE_THRESHOLD: u8 = 3;

/// Maximum pending predictions before dropping oldest.
pub const MAX_PENDING_PREDICTIONS: usize = 1000;

// =============================================================================
// Forwarding Constants
// =============================================================================

/// Maximum concurrent port forwards per session.
pub const MAX_FORWARDS_PER_SESSION: usize = 100;

/// Buffer size for forwarded data.
pub const FORWARD_BUFFER_SIZE: usize = 64 * 1024;

/// Maximum forward data chunk size.
pub const MAX_FORWARD_CHUNK: usize = 64 * 1024;

// =============================================================================
// Bootstrap Constants
// =============================================================================

/// Default QUIC port range for server.
pub const DEFAULT_QUIC_PORT_RANGE: (u16, u16) = (4500, 4600);

// =============================================================================
// Tunnel Constants (Feature: tunnel)
// =============================================================================

/// Default tunnel MTU.
pub const DEFAULT_TUNNEL_MTU: u16 = 1280;

/// Minimum tunnel MTU (IPv4 minimum).
pub const MIN_TUNNEL_MTU: u16 = 576;

/// Maximum tunnel MTU (jumbo frames).
pub const MAX_TUNNEL_MTU: u16 = 9000;

/// Maximum tunnel packet size.
pub const MAX_TUNNEL_PACKET: usize = 65535;

/// Tunnel read buffer size.
pub const TUNNEL_BUFFER_SIZE: usize = 64 * 1024;

/// Default tunnel subnet.
pub const DEFAULT_TUNNEL_SUBNET: &str = "10.99.0.0/24";

// =============================================================================
// Default Values
// =============================================================================

/// Default terminal columns.
pub const DEFAULT_COLS: u16 = 80;

/// Default terminal rows.
pub const DEFAULT_ROWS: u16 = 24;

/// Default TERM environment variable.
pub const DEFAULT_TERM: &str = "xterm-256color";

/// State history depth for incremental diffs.
pub const STATE_HISTORY_DEPTH: usize = 100;

/// Anti-replay cache size.
pub const ANTI_REPLAY_CACHE_SIZE: usize = 10000;

// =============================================================================
// Standalone Auth Constants (Feature: standalone)
// =============================================================================

/// Auth context prefix for domain separation.
#[cfg(feature = "standalone")]
pub const AUTH_CTX: &[u8] = b"qsh-standalone-auth-v1";

/// Nonce length in bytes.
#[cfg(feature = "standalone")]
pub const AUTH_NONCE_LEN: usize = 32;

/// Challenge length in bytes.
#[cfg(feature = "standalone")]
pub const AUTH_CHALLENGE_LEN: usize = 32;

/// Auth handshake timeout.
#[cfg(feature = "standalone")]
pub const AUTH_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum passphrase attempts for encrypted keys.
#[cfg(feature = "standalone")]
pub const MAX_PASSPHRASE_ATTEMPTS: u8 = 3;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timing_constants_are_ordered() {
        // Runtime checks that make sense for the test context
        assert!(RECONNECT_TIMEOUT <= MAX_RECONNECT_TIMEOUT);
        assert!(IDLE_TIMEOUT < SESSION_TIMEOUT);
    }

    #[test]
    fn port_range_is_valid() {
        let (start, end) = DEFAULT_QUIC_PORT_RANGE;
        assert!(start < end);
        assert!(start > 1024); // Above privileged ports
    }

    #[test]
    fn alpn_starts_with_qsh() {
        assert!(ALPN.starts_with(b"qsh/"));
    }

    #[test]
    fn session_key_length() {
        // Verify session key is 256 bits
        assert_eq!(SESSION_KEY_LEN, 32);
    }
}
