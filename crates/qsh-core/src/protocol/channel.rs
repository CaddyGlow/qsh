//! Channel identification and type definitions.
//!
//! This module provides:
//! - Channel side discrimination (client vs server initiated)
//! - Channel ID encoding/decoding for QUIC stream mapping
//! - Channel type definitions (terminal, file transfer, forwards, tunnel)

use serde::{Deserialize, Serialize};

// =============================================================================
// Channel Identification Types
// =============================================================================

/// Which side initiated the channel.
///
/// Both client and server can open channels. To avoid ID collisions and make
/// the initiator explicit, channel IDs include a side discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChannelSide {
    /// Client-initiated channel (terminal, file transfer, direct-tcpip, tunnel).
    Client,
    /// Server-initiated channel (forwarded-tcpip when -R connection arrives).
    Server,
}

/// Unique channel identifier within a connection.
///
/// Each side allocates from its own namespace:
/// - Client assigns `ChannelId::client(n)` starting from 0
/// - Server assigns `ChannelId::server(n)` starting from 0
/// - `(Client, 5)` and `(Server, 5)` are distinct channels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChannelId {
    pub side: ChannelSide,
    pub id: u64,
}

impl ChannelId {
    /// Create a client-initiated channel ID.
    pub fn client(id: u64) -> Self {
        Self {
            side: ChannelSide::Client,
            id,
        }
    }

    /// Create a server-initiated channel ID.
    pub fn server(id: u64) -> Self {
        Self {
            side: ChannelSide::Server,
            id,
        }
    }

    /// Check if this is a client-initiated channel.
    pub fn is_client(&self) -> bool {
        matches!(self.side, ChannelSide::Client)
    }

    /// Check if this is a server-initiated channel.
    pub fn is_server(&self) -> bool {
        matches!(self.side, ChannelSide::Server)
    }

    /// Encode the channel ID for QUIC stream ID encoding.
    ///
    /// Format: bit 0 = side (0=client, 1=server), bits 1+ = channel id
    pub fn encode(&self) -> u64 {
        let side_bit = match self.side {
            ChannelSide::Client => 0,
            ChannelSide::Server => 1,
        };
        (self.id << 1) | side_bit
    }

    /// Decode a channel ID from an encoded value.
    pub fn decode(encoded: u64) -> Self {
        let side = if encoded & 1 == 0 {
            ChannelSide::Client
        } else {
            ChannelSide::Server
        };
        Self {
            side,
            id: encoded >> 1,
        }
    }
}

impl std::fmt::Display for ChannelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let prefix = match self.side {
            ChannelSide::Client => "c",
            ChannelSide::Server => "s",
        };
        write!(f, "{}{}", prefix, self.id)
    }
}

// =============================================================================
// Channel Types
// =============================================================================

/// Channel types supported by qsh.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelType {
    /// Interactive terminal (PTY).
    Terminal,
    /// File transfer (upload/download).
    FileTransfer,
    /// Local port forward (-L): client listens, server connects to target.
    DirectTcpIp,
    /// Remote port forward (-R): server listens, client connects to target.
    ForwardedTcpIp,
    /// SOCKS5 dynamic forward (-D).
    DynamicForward,
    /// IP tunnel (VPN).
    Tunnel,
}

impl std::fmt::Display for ChannelType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChannelType::Terminal => write!(f, "terminal"),
            ChannelType::FileTransfer => write!(f, "file-transfer"),
            ChannelType::DirectTcpIp => write!(f, "direct-tcpip"),
            ChannelType::ForwardedTcpIp => write!(f, "forwarded-tcpip"),
            ChannelType::DynamicForward => write!(f, "dynamic-forward"),
            ChannelType::Tunnel => write!(f, "tunnel"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_id_encode_decode() {
        // Test client channel
        let client_id = ChannelId::client(42);
        let encoded = client_id.encode();
        let decoded = ChannelId::decode(encoded);
        assert_eq!(client_id, decoded);

        // Test server channel
        let server_id = ChannelId::server(99);
        let encoded = server_id.encode();
        let decoded = ChannelId::decode(encoded);
        assert_eq!(server_id, decoded);
    }

    #[test]
    fn test_channel_id_display() {
        assert_eq!(ChannelId::client(5).to_string(), "c5");
        assert_eq!(ChannelId::server(10).to_string(), "s10");
    }

    #[test]
    fn test_channel_type_display() {
        assert_eq!(ChannelType::Terminal.to_string(), "terminal");
        assert_eq!(ChannelType::FileTransfer.to_string(), "file-transfer");
        assert_eq!(ChannelType::DirectTcpIp.to_string(), "direct-tcpip");
        assert_eq!(ChannelType::ForwardedTcpIp.to_string(), "forwarded-tcpip");
        assert_eq!(ChannelType::DynamicForward.to_string(), "dynamic-forward");
        assert_eq!(ChannelType::Tunnel.to_string(), "tunnel");
    }
}
