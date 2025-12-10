//! Protocol control message types.
//!
//! This module contains connection-level control messages:
//! - Global requests/replies (port forwarding setup)
//! - Hello/HelloAck (connection establishment)
//! - Shutdown, heartbeat, resize
//! - Forward specifications and parsing
//! - Standalone authentication messages (feature-gated)

use serde::{Deserialize, Serialize};

use super::channel::ChannelId;
use super::lifecycle::{ExistingChannel, SessionId};

// =============================================================================
// Global Request/Reply (Connection-Level Operations)
// =============================================================================

/// Connection-level request (like SSH_MSG_GLOBAL_REQUEST).
///
/// These handle connection-wide operations that don't belong to any channel
/// (e.g., requesting a remote port forward before any ForwardedTcpIp channels exist).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GlobalRequestPayload {
    /// Request ID for correlating replies.
    pub request_id: u32,
    /// The request type and parameters.
    pub request: GlobalRequest,
}

/// Global request types.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum GlobalRequest {
    /// Request server to bind a port for remote forwarding (-R).
    /// Server will open ForwardedTcpIp channels when connections arrive.
    TcpIpForward {
        bind_host: String,
        /// Port to bind (0 = server picks).
        bind_port: u16,
    },
    /// Cancel a previously requested remote forward.
    CancelTcpIpForward { bind_host: String, bind_port: u16 },
}

/// Response to a global request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GlobalReplyPayload {
    /// Request ID this is replying to.
    pub request_id: u32,
    /// Result of the request.
    pub result: GlobalReplyResult,
}

/// Result of a global request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum GlobalReplyResult {
    /// Request succeeded.
    Success(GlobalReplyData),
    /// Request failed.
    Failure { message: String },
}

/// Type-specific data in successful global reply.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum GlobalReplyData {
    /// Response to TcpIpForward - contains actual bound port (if 0 was requested).
    TcpIpForward { bound_port: u16 },
    /// Response to CancelTcpIpForward - no data.
    CancelTcpIpForward,
}

// =============================================================================
// Control Messages
// =============================================================================

/// Client hello payload.
///
/// Establishes connection-level parameters. Terminal-specific parameters
/// are sent via `TerminalParams` in `ChannelOpen`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HelloPayload {
    /// Protocol version (must be 1).
    pub protocol_version: u32,
    /// Session key from bootstrap (32 bytes).
    pub session_key: [u8; 32],
    /// Client nonce for anti-replay (monotonic).
    pub client_nonce: u64,
    /// Client capabilities.
    pub capabilities: Capabilities,
    /// If resuming an existing logical session, the previous SessionId.
    /// None for a brand-new session.
    #[serde(default)]
    pub resume_session: Option<SessionId>,
}

/// Server hello acknowledgment payload.
///
/// Establishes connection-level parameters. Terminal state is sent via
/// `ChannelAcceptData::Terminal` in `ChannelAccept`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HelloAckPayload {
    /// Server protocol version.
    pub protocol_version: u32,
    /// Session accepted.
    pub accepted: bool,
    /// Rejection reason (if not accepted).
    pub reject_reason: Option<String>,
    /// Server capabilities.
    pub capabilities: Capabilities,
    /// SessionId for this logical session; reused across reconnects.
    #[serde(default)]
    pub session_id: SessionId,
    /// Server nonce for anti-replay.
    #[serde(default)]
    pub server_nonce: u64,
    /// 0-RTT is available for future reconnects.
    pub zero_rtt_available: bool,
    /// Existing channels from session resumption (mosh-style reconnect).
    ///
    /// When a client reconnects to an existing session, this contains
    /// information about channels that are still active on the server.
    /// The client should restore these channels and start receiving data.
    #[serde(default)]
    pub existing_channels: Vec<ExistingChannel>,
}

/// Client/server capabilities.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Capabilities {
    /// Supports predictive echo.
    pub predictive_echo: bool,
    /// Supports state compression.
    pub compression: bool,
    /// Maximum forward connections.
    pub max_forwards: u16,
    /// Supports IP tunnel.
    pub tunnel: bool,
}

/// Resize notification payload (sent on control stream).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResizePayload {
    /// Channel ID this resize applies to.
    #[serde(default)]
    pub channel_id: Option<ChannelId>,
    pub cols: u16,
    pub rows: u16,
}

/// Shutdown payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShutdownPayload {
    pub reason: ShutdownReason,
    pub message: Option<String>,
}

/// Shutdown reason enumeration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ShutdownReason {
    /// User requested disconnect (~. escape or explicit quit).
    UserRequested,
    /// Server-side idle timeout.
    IdleTimeout,
    /// Server process exiting.
    ServerShutdown,
    /// Unrecoverable protocol violation.
    ProtocolError,
    /// Session key mismatch.
    AuthFailure,
    /// Shell process exited (exit command or ctrl-d).
    ShellExited,
}

/// Heartbeat payload for RTT measurement (mosh-style).
///
/// Uses 16-bit timestamps (milliseconds mod 65536) like mosh for minimal overhead.
/// Each side echoes the received timestamp back, adjusted for hold time.
/// A sequence number is used for reliable matching of replies.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct HeartbeatPayload {
    /// Sender's current timestamp (ms mod 65536).
    pub timestamp: u16,
    /// Echo of last received timestamp + hold time, or u16::MAX if none.
    pub timestamp_reply: u16,
    /// Sequence number for matching replies (wraps at u16::MAX).
    #[serde(default)]
    pub seq: u16,
    /// Echo of sequence number from the heartbeat being replied to.
    #[serde(default)]
    pub seq_reply: u16,
}

impl HeartbeatPayload {
    /// Create a new heartbeat with current timestamp and no reply.
    pub fn new(timestamp: u16, seq: u16) -> Self {
        Self {
            timestamp,
            timestamp_reply: u16::MAX,
            seq,
            seq_reply: 0,
        }
    }

    /// Create a heartbeat reply echoing the given timestamp and sequence.
    pub fn reply(timestamp: u16, echo_ts: u16, echo_seq: u16) -> Self {
        Self {
            timestamp,
            timestamp_reply: echo_ts,
            seq: 0, // Reply doesn't need its own seq
            seq_reply: echo_seq,
        }
    }

    /// Check if this heartbeat has a valid reply.
    pub fn has_reply(&self) -> bool {
        self.timestamp_reply != u16::MAX
    }
}

/// State acknowledgment payload (sent on control stream).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateAckPayload {
    /// Channel ID this ack applies to.
    #[serde(default)]
    pub channel_id: Option<ChannelId>,
    /// Generation number acknowledged.
    pub generation: u64,
}

// =============================================================================
// Forward Types
// =============================================================================

/// Forward specification enumeration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ForwardSpec {
    /// -L: Local port forward (client listens, server connects to target).
    Local {
        /// Bind address on client.
        bind_addr: std::net::SocketAddr,
        /// Target hostname on server side.
        target_host: String,
        /// Target port on server side.
        target_port: u16,
    },
    /// -R: Remote port forward (server listens, client connects to target).
    Remote {
        /// Bind address on server.
        bind_addr: std::net::SocketAddr,
        /// Target hostname on client side.
        target_host: String,
        /// Target port on client side.
        target_port: u16,
    },
    /// -D: Dynamic SOCKS5 (client runs SOCKS5 proxy).
    Dynamic {
        /// Bind address for SOCKS5 proxy.
        bind_addr: std::net::SocketAddr,
    },
}

impl ForwardSpec {
    /// Parse a local forward specification (-L).
    ///
    /// Formats:
    /// - `[bind_addr:]port:host:hostport`
    /// - `port:host:hostport` (binds to localhost)
    pub fn parse_local(s: &str) -> crate::Result<Self> {
        let (bind_addr, target_host, target_port) = parse_forward_spec(s)?;
        Ok(Self::Local {
            bind_addr,
            target_host,
            target_port,
        })
    }

    /// Parse a remote forward specification (-R).
    ///
    /// Formats:
    /// - `[bind_addr:]port:host:hostport`
    /// - `port:host:hostport` (binds to localhost on server)
    pub fn parse_remote(s: &str) -> crate::Result<Self> {
        let (bind_addr, target_host, target_port) = parse_forward_spec(s)?;
        Ok(Self::Remote {
            bind_addr,
            target_host,
            target_port,
        })
    }

    /// Parse a dynamic forward specification (-D).
    ///
    /// Formats:
    /// - `[bind_addr:]port`
    /// - `port` (binds to localhost)
    pub fn parse_dynamic(s: &str) -> crate::Result<Self> {
        let bind_addr = parse_bind_spec(s)?;
        Ok(Self::Dynamic { bind_addr })
    }

    /// Get the bind address.
    pub fn bind_addr(&self) -> std::net::SocketAddr {
        match self {
            Self::Local { bind_addr, .. } => *bind_addr,
            Self::Remote { bind_addr, .. } => *bind_addr,
            Self::Dynamic { bind_addr } => *bind_addr,
        }
    }

    /// Get the target host and port (if applicable).
    pub fn target(&self) -> Option<(&str, u16)> {
        match self {
            Self::Local {
                target_host,
                target_port,
                ..
            } => Some((target_host.as_str(), *target_port)),
            Self::Remote {
                target_host,
                target_port,
                ..
            } => Some((target_host.as_str(), *target_port)),
            Self::Dynamic { .. } => None,
        }
    }
}

/// Parse a forward specification in format `[bind_addr:]port:host:hostport`.
fn parse_forward_spec(s: &str) -> crate::Result<(std::net::SocketAddr, String, u16)> {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    if s.is_empty() {
        return Err(crate::Error::InvalidForwardSpec {
            message: "empty specification".into(),
        });
    }

    // Check for IPv6 bind address (starts with '[')
    if s.starts_with('[') {
        return parse_forward_spec_ipv6(s);
    }

    let parts: Vec<&str> = s.split(':').collect();

    match parts.len() {
        // port:host:hostport
        3 => {
            let bind_port = parse_port(parts[0])?;
            let target_host = parts[1].to_string();
            let target_port = parse_port(parts[2])?;

            let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), bind_port);
            Ok((bind_addr, target_host, target_port))
        }
        // bind_addr:port:host:hostport (IPv4)
        4 => {
            let bind_ip: IpAddr =
                parts[0]
                    .parse()
                    .map_err(|_| crate::Error::InvalidForwardSpec {
                        message: format!("invalid bind address: {}", parts[0]),
                    })?;
            let bind_port = parse_port(parts[1])?;
            let target_host = parts[2].to_string();
            let target_port = parse_port(parts[3])?;

            let bind_addr = SocketAddr::new(bind_ip, bind_port);
            Ok((bind_addr, target_host, target_port))
        }
        _ => Err(crate::Error::InvalidForwardSpec {
            message: format!(
                "invalid format: expected [bind_addr:]port:host:hostport, got: {}",
                s
            ),
        }),
    }
}

/// Parse a forward specification with IPv6 bind address.
fn parse_forward_spec_ipv6(s: &str) -> crate::Result<(std::net::SocketAddr, String, u16)> {
    use std::net::{IpAddr, SocketAddr};

    let close_bracket = s
        .find(']')
        .ok_or_else(|| crate::Error::InvalidForwardSpec {
            message: "unclosed IPv6 bracket".into(),
        })?;

    let ipv6_str = &s[1..close_bracket];
    let bind_ip: IpAddr = ipv6_str
        .parse()
        .map_err(|_| crate::Error::InvalidForwardSpec {
            message: format!("invalid IPv6 address: {}", ipv6_str),
        })?;

    let remainder = &s[close_bracket + 1..];
    if !remainder.starts_with(':') {
        return Err(crate::Error::InvalidForwardSpec {
            message: "expected ':' after IPv6 address".into(),
        });
    }

    let parts: Vec<&str> = remainder[1..].split(':').collect();
    if parts.len() != 3 {
        return Err(crate::Error::InvalidForwardSpec {
            message: format!("invalid format after IPv6 address: {}", remainder),
        });
    }

    let bind_port = parse_port(parts[0])?;
    let target_host = parts[1].to_string();
    let target_port = parse_port(parts[2])?;

    let bind_addr = SocketAddr::new(bind_ip, bind_port);
    Ok((bind_addr, target_host, target_port))
}

/// Parse a bind specification in format `[bind_addr:]port`.
fn parse_bind_spec(s: &str) -> crate::Result<std::net::SocketAddr> {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    if s.is_empty() {
        return Err(crate::Error::InvalidForwardSpec {
            message: "empty specification".into(),
        });
    }

    // Check for IPv6 bind address (starts with '[')
    if s.starts_with('[') {
        return parse_bind_spec_ipv6(s);
    }

    let parts: Vec<&str> = s.split(':').collect();

    match parts.len() {
        // port only
        1 => {
            let port = parse_port(parts[0])?;
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))
        }
        // bind_addr:port (IPv4)
        2 => {
            let bind_ip: IpAddr =
                parts[0]
                    .parse()
                    .map_err(|_| crate::Error::InvalidForwardSpec {
                        message: format!("invalid bind address: {}", parts[0]),
                    })?;
            let port = parse_port(parts[1])?;
            Ok(SocketAddr::new(bind_ip, port))
        }
        _ => Err(crate::Error::InvalidForwardSpec {
            message: format!("invalid format: expected [bind_addr:]port, got: {}", s),
        }),
    }
}

/// Parse a bind specification with IPv6 address.
fn parse_bind_spec_ipv6(s: &str) -> crate::Result<std::net::SocketAddr> {
    use std::net::{IpAddr, SocketAddr};

    let close_bracket = s
        .find(']')
        .ok_or_else(|| crate::Error::InvalidForwardSpec {
            message: "unclosed IPv6 bracket".into(),
        })?;

    let ipv6_str = &s[1..close_bracket];
    let bind_ip: IpAddr = ipv6_str
        .parse()
        .map_err(|_| crate::Error::InvalidForwardSpec {
            message: format!("invalid IPv6 address: {}", ipv6_str),
        })?;

    let remainder = &s[close_bracket + 1..];
    if !remainder.starts_with(':') {
        return Err(crate::Error::InvalidForwardSpec {
            message: "expected ':' after IPv6 address".into(),
        });
    }

    let port = parse_port(&remainder[1..])?;
    Ok(SocketAddr::new(bind_ip, port))
}

/// Parse a port number string.
fn parse_port(s: &str) -> crate::Result<u16> {
    s.parse::<u16>()
        .map_err(|_| crate::Error::InvalidForwardSpec {
            message: format!("invalid port: {}", s),
        })
}

// =============================================================================
// Standalone Authentication Messages (Feature-gated)
// =============================================================================

/// Server authentication challenge payload.
///
/// Server sends this after QUIC connect. Includes the server's signature
/// for the client to verify against known_hosts.
#[cfg(feature = "standalone")]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthChallengePayload {
    /// Server's host public key (OpenSSH format).
    pub server_public_key: String,
    /// Random challenge for client to sign.
    pub challenge: [u8; 32],
    /// Server's random nonce.
    pub server_nonce: [u8; 32],
    /// Server's signature over: AUTH_CTX || "server" || host || port || challenge || server_nonce
    pub server_signature: Vec<u8>,
}

/// Client authentication response payload.
///
/// Client sends this after verifying the server's identity.
#[cfg(feature = "standalone")]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthResponsePayload {
    /// Client's public key (OpenSSH format).
    pub client_public_key: String,
    /// Client's random nonce.
    pub client_nonce: [u8; 32],
    /// Client's signature over: AUTH_CTX || "client" || host || port || challenge || server_nonce || client_nonce
    pub signature: Vec<u8>,
}

/// Authentication failure payload.
///
/// Server sends this when authentication fails for any reason.
#[cfg(feature = "standalone")]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthFailurePayload {
    /// Error code indicating failure type.
    pub code: AuthErrorCode,
    /// Human-readable error message.
    pub message: String,
}

/// Authentication error codes.
///
/// Note: Only coarse-grained errors are exposed to clients.
/// Internal failure details are logged server-side only.
#[cfg(feature = "standalone")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthErrorCode {
    /// Generic authentication failure (unknown key, revoked, bad signature, etc.)
    AuthFailed,
    /// Client took too long to respond.
    Timeout,
    /// Malformed or unexpected message.
    ProtocolError,
    /// Server-side error.
    InternalError,
}

#[cfg(feature = "standalone")]
impl std::fmt::Display for AuthErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthErrorCode::AuthFailed => write!(f, "authentication failed"),
            AuthErrorCode::Timeout => write!(f, "timeout"),
            AuthErrorCode::ProtocolError => write!(f, "protocol error"),
            AuthErrorCode::InternalError => write!(f, "internal error"),
        }
    }
}
