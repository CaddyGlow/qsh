//! Protocol message types for qsh wire protocol.
//!
//! Per PROTOCOL spec: Messages are serialized using bincode with length-prefixed encoding.
//! Stream mapping:
//! - Control = client-bidi 0
//! - Terminal out = server-uni 3
//! - Terminal in = client-uni 2
//! - Forwards on proper bidi IDs (server bidi 1/5..., client bidi 8/12...)
//! - Tunnel uses client-bidi 4 reserved

use serde::{Deserialize, Serialize};

// =============================================================================
// Top-level Message Enum
// =============================================================================

/// Top-level protocol message type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Message {
    // Control stream (ID 0)
    /// Client hello with session key and capabilities.
    Hello(HelloPayload),
    /// Server acknowledgment of hello.
    HelloAck(HelloAckPayload),
    /// Terminal resize notification.
    Resize(ResizePayload),
    /// Ping for keepalive and latency measurement.
    Ping(u64),
    /// Pong response to ping.
    Pong(u64),
    /// Graceful shutdown notification.
    Shutdown(ShutdownPayload),

    // Terminal streams
    /// User input sent to server (client-uni stream 2).
    TerminalInput(TerminalInputPayload),
    /// Raw terminal output from server (bypass state tracking).
    TerminalOutput(TerminalOutputPayload),
    /// Terminal state update from server (server-uni stream 3).
    StateUpdate(StateUpdatePayload),
    /// Client acknowledgment of state update (on control stream).
    StateAck(StateAckPayload),

    // Forward streams
    /// Request to establish a forwarded connection.
    ForwardRequest(ForwardRequestPayload),
    /// Accept a forward request.
    ForwardAccept(ForwardAcceptPayload),
    /// Reject a forward request.
    ForwardReject(ForwardRejectPayload),
    /// Data on a forwarded connection.
    ForwardData(ForwardDataPayload),
    /// End of data in one direction (half-close).
    ForwardEof(ForwardEofPayload),
    /// Close a forwarded connection.
    ForwardClose(ForwardClosePayload),

    // Tunnel stream (ID 4)
    /// Tunnel configuration request from client.
    #[cfg(feature = "tunnel")]
    TunnelConfig(TunnelConfigPayload),
    /// Tunnel configuration acknowledgment from server.
    #[cfg(feature = "tunnel")]
    TunnelConfigAck(TunnelConfigAckPayload),
    /// Raw IP packet through tunnel.
    #[cfg(feature = "tunnel")]
    TunnelPacket(TunnelPacketPayload),
}

// =============================================================================
// Control Messages
// =============================================================================

/// Client hello payload.
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
    /// Requested terminal size.
    pub term_size: TermSize,
    /// TERM environment variable.
    pub term_type: String,
    /// Last confirmed state generation (0 if new session).
    pub last_generation: u64,
    /// Last confirmed input sequence.
    pub last_input_seq: u64,
}

/// Server hello acknowledgment payload.
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
    /// Initial terminal state (if accepted).
    pub initial_state: Option<TerminalState>,
    /// 0-RTT is available for future reconnects.
    pub zero_rtt_available: bool,
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

/// Terminal size.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct TermSize {
    pub cols: u16,
    pub rows: u16,
}

impl Default for TermSize {
    fn default() -> Self {
        Self { cols: 80, rows: 24 }
    }
}

/// Resize notification payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResizePayload {
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

// =============================================================================
// Terminal Messages
// =============================================================================

/// Terminal input payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TerminalInputPayload {
    /// Monotonic sequence number.
    pub sequence: u64,
    /// Raw input bytes.
    pub data: Vec<u8>,
    /// Hint: these bytes may be predicted locally.
    pub predictable: bool,
}

/// Raw terminal output payload (bypasses state tracking).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TerminalOutputPayload {
    /// Raw output bytes from PTY.
    pub data: Vec<u8>,
    /// Highest input sequence processed before this output.
    pub confirmed_input_seq: u64,
}

/// State update payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateUpdatePayload {
    /// State diff or full state.
    pub diff: StateDiff,
    /// Highest input sequence processed.
    pub confirmed_input_seq: u64,
    /// Server timestamp for latency calc (microseconds).
    pub timestamp: u64,
}

/// State acknowledgment payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateAckPayload {
    /// Generation number acknowledged.
    pub generation: u64,
}

// =============================================================================
// Terminal State Types (Placeholders - will be filled in Track B)
// =============================================================================

// Terminal state/diff are provided by the terminal module.
pub use crate::terminal::{Cell, Cursor, StateDiff, TerminalState};

// =============================================================================
// Forward Messages
// =============================================================================

/// Forward request payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForwardRequestPayload {
    /// Unique forward ID for this connection.
    pub forward_id: u64,
    /// Forward specification (includes bind address and target info).
    pub spec: ForwardSpec,
}

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

/// Forward accept payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForwardAcceptPayload {
    pub forward_id: u64,
}

/// Forward reject payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForwardRejectPayload {
    pub forward_id: u64,
    pub reason: String,
}

/// Forward data payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForwardDataPayload {
    pub forward_id: u64,
    pub data: Vec<u8>,
}

/// Forward EOF payload (half-close).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForwardEofPayload {
    pub forward_id: u64,
}

/// Forward close payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForwardClosePayload {
    pub forward_id: u64,
    pub reason: Option<String>,
}

// =============================================================================
// Tunnel Messages (Feature-gated)
// =============================================================================

/// Tunnel configuration payload.
#[cfg(feature = "tunnel")]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TunnelConfigPayload {
    /// Requested client tunnel IP with prefix.
    pub client_ip: IpNet,
    /// Requested MTU for tunnel interface.
    pub mtu: u16,
    /// Routes to push to client (optional).
    pub requested_routes: Vec<IpNet>,
    /// Enable IPv6 in tunnel.
    pub ipv6: bool,
}

/// Tunnel configuration acknowledgment payload.
#[cfg(feature = "tunnel")]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TunnelConfigAckPayload {
    /// Whether tunnel was accepted.
    pub accepted: bool,
    /// Rejection reason (if not accepted).
    pub reject_reason: Option<String>,
    /// Server's tunnel IP.
    pub server_ip: IpNet,
    /// Negotiated MTU.
    pub mtu: u16,
    /// Routes client should add (server-pushed).
    pub routes: Vec<IpNet>,
    /// DNS servers to use (optional).
    pub dns_servers: Vec<IpAddr>,
}

/// Tunnel packet payload.
#[cfg(feature = "tunnel")]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TunnelPacketPayload {
    /// Raw IP packet (IPv4 or IPv6, including header).
    pub packet: Vec<u8>,
}

#[cfg(feature = "tunnel")]
impl TunnelPacketPayload {
    /// Get IP version from packet (4 or 6).
    pub fn ip_version(&self) -> Option<u8> {
        self.packet.first().map(|b| b >> 4)
    }

    /// Validate basic IP packet structure.
    pub fn is_valid(&self) -> bool {
        match self.ip_version() {
            Some(4) => self.packet.len() >= 20, // Min IPv4 header
            Some(6) => self.packet.len() >= 40, // Min IPv6 header
            _ => false,
        }
    }
}

// Re-export ipnet types for tunnel feature
#[cfg(feature = "tunnel")]
pub use ipnet::IpNet;

#[cfg(feature = "tunnel")]
pub use std::net::IpAddr;

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_variants_exist() {
        // Test that all message variants can be constructed
        let _hello = Message::Hello(HelloPayload {
            protocol_version: 1,
            session_key: [0u8; 32],
            client_nonce: 0,
            capabilities: Capabilities::default(),
            term_size: TermSize::default(),
            term_type: "xterm-256color".into(),
            last_generation: 0,
            last_input_seq: 0,
        });

        let _hello_ack = Message::HelloAck(HelloAckPayload {
            protocol_version: 1,
            accepted: true,
            reject_reason: None,
            capabilities: Capabilities::default(),
            initial_state: None,
            zero_rtt_available: false,
        });

        let _resize = Message::Resize(ResizePayload { cols: 80, rows: 24 });
        let _ping = Message::Ping(12345);
        let _pong = Message::Pong(12345);

        let _shutdown = Message::Shutdown(ShutdownPayload {
            reason: ShutdownReason::UserRequested,
            message: None,
        });

        let _input = Message::TerminalInput(TerminalInputPayload {
            sequence: 1,
            data: vec![0x61], // 'a'
            predictable: true,
        });

        let _update = Message::StateUpdate(StateUpdatePayload {
            diff: StateDiff::Full(TerminalState::default()),
            confirmed_input_seq: 0,
            timestamp: 0,
        });

        let _ack = Message::StateAck(StateAckPayload { generation: 1 });

        let _fwd_req = Message::ForwardRequest(ForwardRequestPayload {
            forward_id: 0,
            spec: ForwardSpec::Local {
                bind_addr: std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    5432,
                ),
                target_host: "localhost".into(),
                target_port: 5432,
            },
        });

        let _fwd_accept = Message::ForwardAccept(ForwardAcceptPayload { forward_id: 0 });

        let _fwd_reject = Message::ForwardReject(ForwardRejectPayload {
            forward_id: 0,
            reason: "connection refused".into(),
        });

        let _fwd_data = Message::ForwardData(ForwardDataPayload {
            forward_id: 0,
            data: vec![1, 2, 3],
        });

        let _fwd_eof = Message::ForwardEof(ForwardEofPayload { forward_id: 0 });

        let _fwd_close = Message::ForwardClose(ForwardClosePayload {
            forward_id: 0,
            reason: None,
        });
    }

    #[test]
    fn test_capabilities_defaults() {
        let caps = Capabilities::default();
        assert!(!caps.predictive_echo);
        assert!(!caps.compression);
        assert_eq!(caps.max_forwards, 0);
        assert!(!caps.tunnel);
    }

    #[test]
    fn test_message_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Message>();
        assert_send_sync::<HelloPayload>();
        assert_send_sync::<HelloAckPayload>();
        assert_send_sync::<Capabilities>();
        assert_send_sync::<TerminalInputPayload>();
        assert_send_sync::<StateUpdatePayload>();
        assert_send_sync::<ForwardRequestPayload>();
    }

    #[test]
    fn test_term_size_default() {
        let size = TermSize::default();
        assert_eq!(size.cols, 80);
        assert_eq!(size.rows, 24);
    }

    #[test]
    fn test_shutdown_reasons() {
        let reasons = [
            ShutdownReason::UserRequested,
            ShutdownReason::IdleTimeout,
            ShutdownReason::ServerShutdown,
            ShutdownReason::ProtocolError,
            ShutdownReason::AuthFailure,
        ];
        for reason in reasons {
            let _ = format!("{:?}", reason);
        }
    }

    #[test]
    fn test_forward_spec_variants() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let _local = ForwardSpec::Local {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5432),
            target_host: "localhost".into(),
            target_port: 5432,
        };
        let _remote = ForwardSpec::Remote {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
            target_host: "localhost".into(),
            target_port: 80,
        };
        let _dynamic = ForwardSpec::Dynamic {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1080),
        };
    }

    #[test]
    fn test_state_diff_variants() {
        let _full = StateDiff::Full(TerminalState::default());
        let _incremental = StateDiff::Incremental {
            from_gen: 0,
            to_gen: 1,
            changes: vec![],
            cursor: None,
            title: None,
            cwd: None,
            clipboard: None,
            pending_osc: vec![],
            alternate_active: None,
        };
        let _cursor = StateDiff::CursorOnly {
            generation: 1,
            cursor: Cursor::default(),
        };
    }

    #[cfg(feature = "tunnel")]
    #[test]
    fn test_tunnel_packet_ip_version() {
        // IPv4 packet (version nibble = 4)
        let ipv4 = TunnelPacketPayload {
            packet: vec![0x45, 0x00, 0x00, 0x14],
        };
        assert_eq!(ipv4.ip_version(), Some(4));

        // IPv6 packet (version nibble = 6)
        let ipv6 = TunnelPacketPayload {
            packet: vec![0x60, 0x00, 0x00, 0x00],
        };
        assert_eq!(ipv6.ip_version(), Some(6));

        // Empty packet
        let empty = TunnelPacketPayload { packet: vec![] };
        assert_eq!(empty.ip_version(), None);
    }

    #[cfg(feature = "tunnel")]
    #[test]
    fn test_tunnel_packet_validation() {
        // Valid IPv4 (20+ bytes)
        let valid_v4 = TunnelPacketPayload {
            packet: vec![0x45; 20],
        };
        assert!(valid_v4.is_valid());

        // Too short for IPv4
        let short_v4 = TunnelPacketPayload {
            packet: vec![0x45; 10],
        };
        assert!(!short_v4.is_valid());

        // Valid IPv6 (40+ bytes)
        let valid_v6 = TunnelPacketPayload {
            packet: vec![0x60; 40],
        };
        assert!(valid_v6.is_valid());

        // Invalid version
        let bad_version = TunnelPacketPayload {
            packet: vec![0x50; 40],
        };
        assert!(!bad_version.is_valid());
    }
}
