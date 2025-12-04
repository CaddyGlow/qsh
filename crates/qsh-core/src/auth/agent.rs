//! SSH agent client for key listing and signing.
//!
//! This is a placeholder for SSH agent support. Full agent support
//! requires the ssh-agent protocol implementation which can be added
//! as a future enhancement.
//!
//! For now, we provide stubs that indicate agent is unavailable,
//! forcing fallback to file-based keys.

use ssh_key::public::PublicKey;
use tracing::debug;

use crate::error::{Error, Result};

/// SSH agent connection (placeholder).
///
/// Currently always returns None from connect() since full agent
/// support is not yet implemented.
pub struct Agent {
    // Placeholder - would hold Unix socket connection
    _private: (),
}

impl Agent {
    /// Connect to the SSH agent via SSH_AUTH_SOCK.
    ///
    /// Currently always returns `Ok(None)` as agent support is not implemented.
    pub async fn connect() -> Result<Option<Self>> {
        // Check if SSH_AUTH_SOCK is set
        if std::env::var_os("SSH_AUTH_SOCK").is_none() {
            debug!("SSH_AUTH_SOCK not set, agent unavailable");
            return Ok(None);
        }

        // For now, always return None even if socket exists
        // Full agent support can be added later
        debug!("SSH agent support not yet implemented");
        Ok(None)
    }

    /// List all keys held by the agent.
    pub fn list_keys(&self) -> &[PublicKey] {
        &[]
    }

    /// Sign data with a specific key.
    pub async fn sign(&mut self, _key: &PublicKey, _data: &[u8]) -> Result<Vec<u8>> {
        Err(Error::Protocol {
            message: "SSH agent signing not implemented".into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_agent_connect_returns_none() {
        // Should always return None since not implemented
        // SAFETY: This test is single-threaded and doesn't access SSH_AUTH_SOCK
        // from other threads concurrently
        unsafe {
            std::env::remove_var("SSH_AUTH_SOCK");
        }
        let result = Agent::connect().await.unwrap();
        assert!(result.is_none());
    }
}
