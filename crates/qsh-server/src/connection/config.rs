//! Connection configuration.

use std::time::Duration;

use qsh_core::constants::{
    DEFAULT_IDLE_TIMEOUT_SECS, DEFAULT_LINGER_TIMEOUT_SECS, DEFAULT_MAX_CHANNELS,
    DEFAULT_MAX_FILE_TRANSFERS, DEFAULT_MAX_FORWARDS, DEFAULT_MAX_TERMINALS,
};

/// Configuration for connection-level limits.
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    /// Maximum total channels per connection.
    pub max_channels: usize,
    /// Maximum terminal channels per connection.
    pub max_terminals: usize,
    /// Maximum port forward channels per connection.
    pub max_forwards: u16,
    /// Maximum file transfer channels per connection.
    pub max_file_transfers: usize,
    /// Allow remote port forwards (-R).
    pub allow_remote_forwards: bool,
    /// Session linger timeout (keep PTY alive after disconnect).
    pub linger_timeout: Duration,
    /// Idle timeout for channels.
    pub idle_timeout: Duration,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            max_channels: DEFAULT_MAX_CHANNELS,
            max_terminals: DEFAULT_MAX_TERMINALS,
            max_forwards: DEFAULT_MAX_FORWARDS,
            max_file_transfers: DEFAULT_MAX_FILE_TRANSFERS,
            allow_remote_forwards: false,
            linger_timeout: Duration::from_secs(DEFAULT_LINGER_TIMEOUT_SECS),
            idle_timeout: Duration::from_secs(DEFAULT_IDLE_TIMEOUT_SECS),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_config_default() {
        let config = ConnectionConfig::default();
        assert_eq!(config.max_channels, DEFAULT_MAX_CHANNELS);
        assert_eq!(config.max_terminals, DEFAULT_MAX_TERMINALS);
        assert_eq!(config.max_forwards, DEFAULT_MAX_FORWARDS);
        assert_eq!(config.max_file_transfers, DEFAULT_MAX_FILE_TRANSFERS);
        assert!(!config.allow_remote_forwards);
        assert_eq!(config.linger_timeout, Duration::from_secs(DEFAULT_LINGER_TIMEOUT_SECS));
        assert_eq!(config.idle_timeout, Duration::from_secs(DEFAULT_IDLE_TIMEOUT_SECS));
    }
}
