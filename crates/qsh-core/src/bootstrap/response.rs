//! Bootstrap response types.
//!
//! The bootstrap process outputs a JSON response when run in bootstrap mode:
//! ```json
//! {
//!   "version": 1,
//!   "status": "ok",
//!   "endpoint_info": {
//!     "address": "192.168.1.100",
//!     "port": 4500,
//!     "session_key": "base64-encoded-32-bytes",
//!     "server_cert_hash": "base64-encoded-cert-hash",
//!     "connect_mode": "respond"
//!   }
//! }
//! ```

use serde::{Deserialize, Serialize};

use crate::connect_mode::ConnectMode;
use crate::constants::SESSION_KEY_LEN;
use crate::error::{Error, Result};

/// Bootstrap response from the responder.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BootstrapResponse {
    /// Protocol version (should be 1).
    pub version: u32,
    /// Status: "ok" on success, "error" on failure.
    pub status: String,
    /// Error message if status is "error".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Endpoint connection info if status is "ok".
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "server_info")]
    pub endpoint_info: Option<EndpointInfo>,
}

/// Endpoint connection information.
///
/// Used for both client-to-server and server-to-client bootstrap.
/// The `connect_mode` field indicates which role this endpoint plays.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EndpointInfo {
    /// Endpoint address for QUIC connection (IP or hostname).
    pub address: String,
    /// Endpoint port for QUIC connection.
    pub port: u16,
    /// Base64-encoded session key (32 bytes).
    pub session_key: String,
    /// Base64-encoded certificate hash for pinning.
    pub server_cert_hash: String,
    /// Connect mode indicating this endpoint's role.
    #[serde(default)]
    pub connect_mode: ConnectMode,
    /// Path to the named pipe for attaching to this session.
    /// Used in bootstrap/responder mode to allow a separate process to attach.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attach_pipe: Option<String>,
}

impl BootstrapResponse {
    /// Create a successful bootstrap response.
    pub fn ok(endpoint_info: EndpointInfo) -> Self {
        Self {
            version: 1,
            status: "ok".to_string(),
            error: None,
            endpoint_info: Some(endpoint_info),
        }
    }

    /// Create an error bootstrap response.
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            version: 1,
            status: "error".to_string(),
            error: Some(message.into()),
            endpoint_info: None,
        }
    }

    /// Parse a bootstrap response from JSON.
    pub fn parse(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| Error::Protocol {
            message: format!("invalid bootstrap response: {}", e),
        })
    }

    /// Serialize to JSON string.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| Error::Protocol {
            message: format!("failed to serialize bootstrap response: {}", e),
        })
    }

    /// Serialize to pretty JSON string.
    pub fn to_json_pretty(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| Error::Protocol {
            message: format!("failed to serialize bootstrap response: {}", e),
        })
    }

    /// Check if this is a successful response.
    pub fn is_ok(&self) -> bool {
        self.status == "ok" && self.endpoint_info.is_some()
    }

    /// Check if this is an error response.
    pub fn is_error(&self) -> bool {
        self.status == "error"
    }

    /// Get the endpoint info, returning an error if not present.
    pub fn get_endpoint_info(&self) -> Result<&EndpointInfo> {
        self.endpoint_info.as_ref().ok_or_else(|| Error::Protocol {
            message: self
                .error
                .clone()
                .unwrap_or_else(|| "no endpoint info in bootstrap response".to_string()),
        })
    }
}

impl EndpointInfo {
    /// Create new endpoint info.
    pub fn new(
        address: impl Into<String>,
        port: u16,
        session_key: [u8; SESSION_KEY_LEN],
        server_cert_hash: &[u8],
    ) -> Self {
        use base64::Engine;
        Self {
            address: address.into(),
            port,
            session_key: base64::engine::general_purpose::STANDARD.encode(session_key),
            server_cert_hash: base64::engine::general_purpose::STANDARD.encode(server_cert_hash),
            connect_mode: ConnectMode::Respond,
            attach_pipe: None,
        }
    }

    /// Create new endpoint info with a specific connect mode.
    pub fn with_connect_mode(
        address: impl Into<String>,
        port: u16,
        session_key: [u8; SESSION_KEY_LEN],
        server_cert_hash: &[u8],
        connect_mode: ConnectMode,
    ) -> Self {
        use base64::Engine;
        Self {
            address: address.into(),
            port,
            session_key: base64::engine::general_purpose::STANDARD.encode(session_key),
            server_cert_hash: base64::engine::general_purpose::STANDARD.encode(server_cert_hash),
            connect_mode,
            attach_pipe: None,
        }
    }

    /// Create new endpoint info with connect mode and attach pipe.
    pub fn with_attach_pipe(
        address: impl Into<String>,
        port: u16,
        session_key: [u8; SESSION_KEY_LEN],
        server_cert_hash: &[u8],
        connect_mode: ConnectMode,
        attach_pipe: impl Into<String>,
    ) -> Self {
        use base64::Engine;
        Self {
            address: address.into(),
            port,
            session_key: base64::engine::general_purpose::STANDARD.encode(session_key),
            server_cert_hash: base64::engine::general_purpose::STANDARD.encode(server_cert_hash),
            connect_mode,
            attach_pipe: Some(attach_pipe.into()),
        }
    }

    /// Decode the session key from base64.
    pub fn decode_session_key(&self) -> Result<[u8; SESSION_KEY_LEN]> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.session_key)
            .map_err(|e| Error::Protocol {
                message: format!("invalid session key base64: {}", e),
            })?;

        if bytes.len() != SESSION_KEY_LEN {
            return Err(Error::Protocol {
                message: format!(
                    "invalid session key length: expected {}, got {}",
                    SESSION_KEY_LEN,
                    bytes.len()
                ),
            });
        }

        let mut key = [0u8; SESSION_KEY_LEN];
        key.copy_from_slice(&bytes);
        Ok(key)
    }

    /// Decode the server certificate hash from base64.
    pub fn decode_cert_hash(&self) -> Result<Vec<u8>> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(&self.server_cert_hash)
            .map_err(|e| Error::Protocol {
                message: format!("invalid cert hash base64: {}", e),
            })
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_response_ok() {
        let session_key = [0xAB; 32];
        let cert_hash = vec![0xCD; 32];
        let info = EndpointInfo::new("192.168.1.100", 4500, session_key, &cert_hash);

        let resp = BootstrapResponse::ok(info.clone());
        assert!(resp.is_ok());
        assert!(!resp.is_error());
        assert_eq!(resp.version, 1);
        assert_eq!(resp.status, "ok");
        assert!(resp.endpoint_info.is_some());
    }

    #[test]
    fn bootstrap_response_error() {
        let resp = BootstrapResponse::error("something went wrong");
        assert!(!resp.is_ok());
        assert!(resp.is_error());
        assert_eq!(resp.error, Some("something went wrong".to_string()));
        assert!(resp.endpoint_info.is_none());
    }

    #[test]
    fn bootstrap_response_json_roundtrip() {
        let session_key = [0xAB; 32];
        let cert_hash = vec![0xCD; 32];
        let info = EndpointInfo::new("192.168.1.100", 4500, session_key, &cert_hash);
        let resp = BootstrapResponse::ok(info);

        let json = resp.to_json().unwrap();
        let parsed = BootstrapResponse::parse(&json).unwrap();

        assert_eq!(resp, parsed);
    }

    #[test]
    fn bootstrap_response_parse_error() {
        let result = BootstrapResponse::parse("not json");
        assert!(result.is_err());
    }

    #[test]
    fn endpoint_info_session_key_decode() {
        let session_key = [0x42; 32];
        let cert_hash = vec![0xAB; 32];
        let info = EndpointInfo::new("localhost", 4500, session_key, &cert_hash);

        let decoded = info.decode_session_key().unwrap();
        assert_eq!(decoded, session_key);
    }

    #[test]
    fn endpoint_info_invalid_session_key_base64() {
        let info = EndpointInfo {
            address: "localhost".to_string(),
            port: 4500,
            session_key: "not-valid-base64!!!".to_string(),
            server_cert_hash: "AAAA".to_string(),
            connect_mode: ConnectMode::Respond,
            attach_pipe: None,
        };

        let result = info.decode_session_key();
        assert!(result.is_err());
    }

    #[test]
    fn endpoint_info_wrong_session_key_length() {
        use base64::Engine;
        let info = EndpointInfo {
            address: "localhost".to_string(),
            port: 4500,
            session_key: base64::engine::general_purpose::STANDARD.encode(&[0u8; 16]), // Wrong length
            server_cert_hash: "AAAA".to_string(),
            connect_mode: ConnectMode::Respond,
            attach_pipe: None,
        };

        let result = info.decode_session_key();
        assert!(result.is_err());
    }

    #[test]
    fn endpoint_info_cert_hash_decode() {
        let session_key = [0x42; 32];
        let cert_hash = vec![0xAB, 0xCD, 0xEF];
        let info = EndpointInfo::new("localhost", 4500, session_key, &cert_hash);

        let decoded = info.decode_cert_hash().unwrap();
        assert_eq!(decoded, cert_hash);
    }

    #[test]
    fn get_endpoint_info_when_error() {
        let resp = BootstrapResponse::error("test error");
        let result = resp.get_endpoint_info();
        assert!(result.is_err());
    }

    #[test]
    fn bootstrap_response_pretty_json() {
        let session_key = [0xAB; 32];
        let cert_hash = vec![0xCD; 32];
        let info = EndpointInfo::new("192.168.1.100", 4500, session_key, &cert_hash);
        let resp = BootstrapResponse::ok(info);

        let json = resp.to_json_pretty().unwrap();
        assert!(json.contains('\n')); // Pretty printed has newlines
        assert!(json.contains("192.168.1.100"));

        // Should still parse correctly
        let parsed = BootstrapResponse::parse(&json).unwrap();
        assert_eq!(resp, parsed);
    }

    #[test]
    fn endpoint_info_with_connect_mode() {
        let session_key = [0xAB; 32];
        let cert_hash = vec![0xCD; 32];

        let info =
            EndpointInfo::with_connect_mode("localhost", 4500, session_key, &cert_hash, ConnectMode::Initiate);
        assert_eq!(info.connect_mode, ConnectMode::Initiate);

        let info = EndpointInfo::new("localhost", 4500, session_key, &cert_hash);
        assert_eq!(info.connect_mode, ConnectMode::Respond);
    }

    #[test]
    fn backward_compatibility_server_info_alias() {
        // Test that old JSON with "server_info" field still deserializes correctly
        let json = r#"{
            "version": 1,
            "status": "ok",
            "server_info": {
                "address": "192.168.1.100",
                "port": 4500,
                "session_key": "q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s=",
                "server_cert_hash": "zc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3NzQ=="
            }
        }"#;

        let parsed = BootstrapResponse::parse(json).unwrap();
        assert!(parsed.is_ok());
        assert!(parsed.endpoint_info.is_some());
        let info = parsed.endpoint_info.unwrap();
        assert_eq!(info.address, "192.168.1.100");
        assert_eq!(info.port, 4500);
        // connect_mode should default to Initiate when missing
        assert_eq!(info.connect_mode, ConnectMode::Initiate);
    }

    #[test]
    fn connect_mode_defaults_when_missing() {
        // Test that connect_mode defaults correctly when not present in JSON
        let json = r#"{
            "address": "localhost",
            "port": 4500,
            "session_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "server_cert_hash": "AAAA"
        }"#;

        let info: EndpointInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.connect_mode, ConnectMode::Initiate);
    }

    #[test]
    fn connect_mode_serializes_correctly() {
        let session_key = [0xAB; 32];
        let cert_hash = vec![0xCD; 32];
        let info = EndpointInfo::with_connect_mode(
            "localhost",
            4500,
            session_key,
            &cert_hash,
            ConnectMode::Respond,
        );

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains(r#""connect_mode":"respond""#));
    }
}
