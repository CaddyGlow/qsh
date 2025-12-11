//! Session configuration types shared between client and server.
//!
//! Provides base configuration that can be extended by client and server
//! with their specific settings.

use std::time::Duration;

use crate::constants::{DEFAULT_IDLE_TIMEOUT_SECS, DEFAULT_MAX_CHANNELS, DEFAULT_MAX_FORWARDS};
use crate::protocol::Capabilities;

/// Base configuration shared between client and server.
///
/// Contains settings that are common to both sides of a qsh connection.
#[derive(Debug, Clone)]
pub struct BaseSessionConfig {
    /// Protocol capabilities.
    pub capabilities: Capabilities,
    /// Maximum idle timeout before connection close.
    pub idle_timeout: Duration,
    /// Maximum number of channels.
    pub max_channels: usize,
    /// Maximum port forwards.
    pub max_forwards: u16,
}

impl Default for BaseSessionConfig {
    fn default() -> Self {
        Self {
            capabilities: Capabilities {
                predictive_echo: true,
                compression: false,
                max_forwards: DEFAULT_MAX_FORWARDS,
                tunnel: false,
            },
            idle_timeout: Duration::from_secs(DEFAULT_IDLE_TIMEOUT_SECS),
            max_channels: DEFAULT_MAX_CHANNELS,
            max_forwards: DEFAULT_MAX_FORWARDS,
        }
    }
}

impl BaseSessionConfig {
    /// Create a new base config with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the capabilities.
    pub fn with_capabilities(mut self, capabilities: Capabilities) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Set the idle timeout.
    pub fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Set the maximum channels.
    pub fn with_max_channels(mut self, max: usize) -> Self {
        self.max_channels = max;
        self
    }

    /// Set the maximum forwards.
    pub fn with_max_forwards(mut self, max: u16) -> Self {
        self.max_forwards = max;
        self
    }

    /// Check if predictive echo is enabled.
    pub fn predictive_echo(&self) -> bool {
        self.capabilities.predictive_echo
    }

    /// Check if compression is enabled.
    pub fn compression(&self) -> bool {
        self.capabilities.compression
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_config_defaults() {
        let config = BaseSessionConfig::default();
        assert!(config.capabilities.predictive_echo);
        assert!(!config.capabilities.compression);
        assert_eq!(config.max_forwards, DEFAULT_MAX_FORWARDS);
        assert_eq!(config.max_channels, DEFAULT_MAX_CHANNELS);
    }

    #[test]
    fn test_base_config_builder() {
        let config = BaseSessionConfig::new()
            .with_idle_timeout(Duration::from_secs(120))
            .with_max_channels(50)
            .with_max_forwards(20);

        assert_eq!(config.idle_timeout, Duration::from_secs(120));
        assert_eq!(config.max_channels, 50);
        assert_eq!(config.max_forwards, 20);
    }

    #[test]
    fn test_base_config_helpers() {
        let config = BaseSessionConfig::default();
        assert!(config.predictive_echo());
        assert!(!config.compression());
    }
}
