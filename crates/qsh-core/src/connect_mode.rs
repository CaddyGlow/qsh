//! Connection mode for bidirectional qsh sessions.
//!
//! qsh supports two connection modes that determine which side initiates the QUIC connection:
//!
//! - **Initiate**: Actively connects to a listening peer (traditional client behavior)
//! - **Respond**: Listens for and accepts connections from an initiating peer (traditional server behavior)
//!
//! # Use Cases
//!
//! ## Normal Mode (Client Initiates)
//! ```text
//! qsh user@server           # Client runs in Initiate mode
//! qsh-server --bootstrap    # Server runs in Respond mode
//! ```
//! The client SSHes to the server, launches `qsh-server --bootstrap`, which outputs connection info
//! and listens. The client then connects via QUIC.
//!
//! ## Reverse Mode (Server Initiates)
//! ```text
//! qsh --bootstrap                                      # Client runs in Respond mode
//! qsh-server --connect-mode initiate --target user@client  # Server runs in Initiate mode
//! ```
//! The server SSHes to the client, launches `qsh --bootstrap`, parses connection info,
//! and connects via QUIC. Useful for NAT traversal or reverse shells.
//!
//! # Security
//!
//! Both modes rely on SSH for initial authentication:
//! - Normal: Server trusts client's SSH credentials
//! - Reverse: Client trusts server's SSH credentials
//!
//! After SSH authentication, the QUIC session is secured with the exchanged session key.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Connection mode determining which side initiates the QUIC connection.
///
/// This enum controls the connection direction during bootstrap, independent of
/// which binary is running. Either `qsh` or `qsh-server` can operate in either mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectMode {
    /// Initiate the QUIC connection to a listening peer.
    ///
    /// Used by:
    /// - `qsh` in normal mode (default)
    /// - `qsh-server --connect-mode initiate` in reverse mode
    ///
    /// The initiator sends the Hello message first during handshake.
    Initiate,

    /// Listen for and accept QUIC connections from an initiating peer.
    ///
    /// Used by:
    /// - `qsh-server --bootstrap` in normal mode (default)
    /// - `qsh --bootstrap` in reverse mode
    ///
    /// The responder receives the Hello message and replies with HelloAck.
    Respond,
}

impl ConnectMode {
    /// Check if this is the initiating side.
    pub fn is_initiate(&self) -> bool {
        matches!(self, ConnectMode::Initiate)
    }

    /// Check if this is the responding side.
    pub fn is_respond(&self) -> bool {
        matches!(self, ConnectMode::Respond)
    }
}

impl Default for ConnectMode {
    /// Default to Initiate (traditional client behavior).
    fn default() -> Self {
        ConnectMode::Initiate
    }
}

impl fmt::Display for ConnectMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectMode::Initiate => write!(f, "initiate"),
            ConnectMode::Respond => write!(f, "respond"),
        }
    }
}

impl FromStr for ConnectMode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "initiate" => Ok(ConnectMode::Initiate),
            "respond" => Ok(ConnectMode::Respond),
            _ => Err(Error::Protocol {
                message: format!(
                    "invalid connect mode: '{}' (expected 'initiate' or 'respond')",
                    s
                ),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_initiate() {
        assert_eq!(ConnectMode::default(), ConnectMode::Initiate);
    }

    #[test]
    fn display_lowercase() {
        assert_eq!(ConnectMode::Initiate.to_string(), "initiate");
        assert_eq!(ConnectMode::Respond.to_string(), "respond");
    }

    #[test]
    fn parse_from_str() {
        assert_eq!(
            "initiate".parse::<ConnectMode>().unwrap(),
            ConnectMode::Initiate
        );
        assert_eq!(
            "respond".parse::<ConnectMode>().unwrap(),
            ConnectMode::Respond
        );
        assert_eq!(
            "INITIATE".parse::<ConnectMode>().unwrap(),
            ConnectMode::Initiate
        );
        assert_eq!(
            "RESPOND".parse::<ConnectMode>().unwrap(),
            ConnectMode::Respond
        );
    }

    #[test]
    fn parse_invalid() {
        assert!("invalid".parse::<ConnectMode>().is_err());
        assert!("client".parse::<ConnectMode>().is_err());
        assert!("server".parse::<ConnectMode>().is_err());
    }

    #[test]
    fn is_initiate() {
        assert!(ConnectMode::Initiate.is_initiate());
        assert!(!ConnectMode::Respond.is_initiate());
    }

    #[test]
    fn is_respond() {
        assert!(ConnectMode::Respond.is_respond());
        assert!(!ConnectMode::Initiate.is_respond());
    }

    #[test]
    fn serde_roundtrip() {
        let initiate = ConnectMode::Initiate;
        let json = serde_json::to_string(&initiate).unwrap();
        assert_eq!(json, r#""initiate""#);
        let parsed: ConnectMode = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, initiate);

        let respond = ConnectMode::Respond;
        let json = serde_json::to_string(&respond).unwrap();
        assert_eq!(json, r#""respond""#);
        let parsed: ConnectMode = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, respond);
    }
}
