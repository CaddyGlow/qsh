//! Tunnel configuration and state types.

use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// Tunnel configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TunnelConfig {
    /// Client's tunnel IP with prefix.
    pub client_ip: IpNet,
    /// Server's tunnel IP with prefix.
    pub server_ip: IpNet,
    /// Maximum transmission unit.
    pub mtu: u16,
    /// Routes to add on the client.
    pub routes: Vec<IpNet>,
    /// DNS servers to use through tunnel.
    pub dns_servers: Vec<IpAddr>,
}

impl TunnelConfig {
    /// Default MTU for tunnel interface.
    pub const DEFAULT_MTU: u16 = 1400;

    /// Minimum MTU allowed.
    pub const MIN_MTU: u16 = 576;

    /// Maximum MTU allowed.
    pub const MAX_MTU: u16 = 9000;

    /// Create a new tunnel config with default MTU.
    pub fn new(client_ip: IpNet, server_ip: IpNet) -> Self {
        Self {
            client_ip,
            server_ip,
            mtu: Self::DEFAULT_MTU,
            routes: Vec::new(),
            dns_servers: Vec::new(),
        }
    }

    /// Set the MTU, clamping to valid range.
    pub fn with_mtu(mut self, mtu: u16) -> Self {
        self.mtu = mtu.clamp(Self::MIN_MTU, Self::MAX_MTU);
        self
    }

    /// Add routes to the configuration.
    pub fn with_routes(mut self, routes: Vec<IpNet>) -> Self {
        self.routes = routes;
        self
    }

    /// Add DNS servers to the configuration.
    pub fn with_dns(mut self, servers: Vec<IpAddr>) -> Self {
        self.dns_servers = servers;
        self
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), TunnelConfigError> {
        // Check MTU range
        if self.mtu < Self::MIN_MTU || self.mtu > Self::MAX_MTU {
            return Err(TunnelConfigError::InvalidMtu(self.mtu));
        }

        // Check IP address families match
        let client_is_v4 = self.client_ip.addr().is_ipv4();
        let server_is_v4 = self.server_ip.addr().is_ipv4();
        if client_is_v4 != server_is_v4 {
            return Err(TunnelConfigError::AddressFamilyMismatch);
        }

        // Check client and server IPs are different
        if self.client_ip.addr() == self.server_ip.addr() {
            return Err(TunnelConfigError::DuplicateAddress);
        }

        Ok(())
    }
}

/// Tunnel configuration error.
#[derive(Debug, Clone, PartialEq)]
pub enum TunnelConfigError {
    /// MTU is out of valid range.
    InvalidMtu(u16),
    /// Client and server use different IP address families.
    AddressFamilyMismatch,
    /// Client and server have the same IP address.
    DuplicateAddress,
}

impl std::fmt::Display for TunnelConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMtu(mtu) => write!(
                f,
                "Invalid MTU {}: must be between {} and {}",
                mtu,
                TunnelConfig::MIN_MTU,
                TunnelConfig::MAX_MTU
            ),
            Self::AddressFamilyMismatch => {
                write!(f, "Client and server IPs must use the same address family")
            }
            Self::DuplicateAddress => {
                write!(f, "Client and server cannot have the same IP address")
            }
        }
    }
}

impl std::error::Error for TunnelConfigError {}

/// Tunnel state machine.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum TunnelState {
    /// Tunnel is not active.
    #[default]
    Inactive,
    /// Tunnel is being configured (waiting for server ack).
    Configuring {
        /// The requested configuration.
        requested: TunnelConfig,
    },
    /// Tunnel is active and passing traffic.
    Active {
        /// The active configuration.
        config: TunnelConfig,
    },
    /// Tunnel is suspended (e.g., during reconnection).
    Suspended {
        /// The configuration to restore.
        config: TunnelConfig,
    },
}


impl TunnelState {
    /// Check if tunnel is active.
    pub fn is_active(&self) -> bool {
        matches!(self, TunnelState::Active { .. })
    }

    /// Check if tunnel is inactive.
    pub fn is_inactive(&self) -> bool {
        matches!(self, TunnelState::Inactive)
    }

    /// Check if tunnel is suspended.
    pub fn is_suspended(&self) -> bool {
        matches!(self, TunnelState::Suspended { .. })
    }

    /// Get the current config if active or suspended.
    pub fn config(&self) -> Option<&TunnelConfig> {
        match self {
            TunnelState::Active { config } | TunnelState::Suspended { config } => Some(config),
            _ => None,
        }
    }

    /// Transition to configuring state.
    pub fn start_configuring(&mut self, requested: TunnelConfig) -> Result<(), TunnelStateError> {
        match self {
            TunnelState::Inactive => {
                *self = TunnelState::Configuring { requested };
                Ok(())
            }
            _ => Err(TunnelStateError::InvalidTransition {
                from: self.state_name(),
                to: "Configuring",
            }),
        }
    }

    /// Transition to active state.
    pub fn activate(&mut self, config: TunnelConfig) -> Result<(), TunnelStateError> {
        match self {
            TunnelState::Configuring { .. } => {
                *self = TunnelState::Active { config };
                Ok(())
            }
            TunnelState::Suspended { .. } => {
                *self = TunnelState::Active { config };
                Ok(())
            }
            _ => Err(TunnelStateError::InvalidTransition {
                from: self.state_name(),
                to: "Active",
            }),
        }
    }

    /// Transition to suspended state.
    pub fn suspend(&mut self) -> Result<(), TunnelStateError> {
        match self {
            TunnelState::Active { config } => {
                let config = config.clone();
                *self = TunnelState::Suspended { config };
                Ok(())
            }
            _ => Err(TunnelStateError::InvalidTransition {
                from: self.state_name(),
                to: "Suspended",
            }),
        }
    }

    /// Transition to inactive state.
    pub fn deactivate(&mut self) {
        *self = TunnelState::Inactive;
    }

    /// Get the name of the current state.
    fn state_name(&self) -> &'static str {
        match self {
            TunnelState::Inactive => "Inactive",
            TunnelState::Configuring { .. } => "Configuring",
            TunnelState::Active { .. } => "Active",
            TunnelState::Suspended { .. } => "Suspended",
        }
    }
}

/// Tunnel state transition error.
#[derive(Debug, Clone, PartialEq)]
pub enum TunnelStateError {
    /// Invalid state transition.
    InvalidTransition {
        /// State we tried to transition from.
        from: &'static str,
        /// State we tried to transition to.
        to: &'static str,
    },
}

impl std::fmt::Display for TunnelStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTransition { from, to } => {
                write!(f, "Invalid tunnel state transition: {} -> {}", from, to)
            }
        }
    }
}

impl std::error::Error for TunnelStateError {}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_v4_config() -> TunnelConfig {
        TunnelConfig::new(
            "10.0.0.2/24".parse().unwrap(),
            "10.0.0.1/24".parse().unwrap(),
        )
    }

    fn sample_v6_config() -> TunnelConfig {
        TunnelConfig::new(
            "fd00::2/64".parse().unwrap(),
            "fd00::1/64".parse().unwrap(),
        )
    }

    // -------------------------------------------------------------------------
    // TunnelConfig tests
    // -------------------------------------------------------------------------

    #[test]
    fn config_new() {
        let config = sample_v4_config();
        assert_eq!(config.mtu, TunnelConfig::DEFAULT_MTU);
        assert!(config.routes.is_empty());
        assert!(config.dns_servers.is_empty());
    }

    #[test]
    fn config_with_mtu() {
        let config = sample_v4_config().with_mtu(1500);
        assert_eq!(config.mtu, 1500);
    }

    #[test]
    fn config_mtu_clamp_low() {
        let config = sample_v4_config().with_mtu(100);
        assert_eq!(config.mtu, TunnelConfig::MIN_MTU);
    }

    #[test]
    fn config_mtu_clamp_high() {
        let config = sample_v4_config().with_mtu(10000);
        assert_eq!(config.mtu, TunnelConfig::MAX_MTU);
    }

    #[test]
    fn config_with_routes() {
        let routes = vec!["192.168.1.0/24".parse().unwrap()];
        let config = sample_v4_config().with_routes(routes.clone());
        assert_eq!(config.routes, routes);
    }

    #[test]
    fn config_with_dns() {
        let dns = vec!["8.8.8.8".parse().unwrap(), "8.8.4.4".parse().unwrap()];
        let config = sample_v4_config().with_dns(dns.clone());
        assert_eq!(config.dns_servers, dns);
    }

    #[test]
    fn config_validate_ok() {
        let config = sample_v4_config();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn config_validate_v6_ok() {
        let config = sample_v6_config();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn config_validate_address_family_mismatch() {
        let config = TunnelConfig::new(
            "10.0.0.2/24".parse().unwrap(),
            "fd00::1/64".parse().unwrap(),
        );
        assert_eq!(
            config.validate(),
            Err(TunnelConfigError::AddressFamilyMismatch)
        );
    }

    #[test]
    fn config_validate_duplicate_address() {
        let config = TunnelConfig::new(
            "10.0.0.1/24".parse().unwrap(),
            "10.0.0.1/24".parse().unwrap(),
        );
        assert_eq!(config.validate(), Err(TunnelConfigError::DuplicateAddress));
    }

    #[test]
    fn config_serialization_roundtrip() {
        let config = sample_v4_config()
            .with_mtu(1500)
            .with_routes(vec!["192.168.0.0/16".parse().unwrap()])
            .with_dns(vec!["1.1.1.1".parse().unwrap()]);

        let json = serde_json::to_string(&config).unwrap();
        let restored: TunnelConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, restored);
    }

    // -------------------------------------------------------------------------
    // TunnelState tests
    // -------------------------------------------------------------------------

    #[test]
    fn state_default() {
        let state = TunnelState::default();
        assert!(state.is_inactive());
        assert!(!state.is_active());
        assert!(!state.is_suspended());
        assert!(state.config().is_none());
    }

    #[test]
    fn state_start_configuring() {
        let mut state = TunnelState::Inactive;
        let config = sample_v4_config();

        assert!(state.start_configuring(config.clone()).is_ok());
        assert!(matches!(state, TunnelState::Configuring { .. }));
    }

    #[test]
    fn state_activate_from_configuring() {
        let mut state = TunnelState::Inactive;
        let config = sample_v4_config();

        state.start_configuring(config.clone()).unwrap();
        assert!(state.activate(config.clone()).is_ok());
        assert!(state.is_active());
        assert_eq!(state.config(), Some(&config));
    }

    #[test]
    fn state_suspend_from_active() {
        let mut state = TunnelState::Inactive;
        let config = sample_v4_config();

        state.start_configuring(config.clone()).unwrap();
        state.activate(config.clone()).unwrap();
        assert!(state.suspend().is_ok());
        assert!(state.is_suspended());
        assert_eq!(state.config(), Some(&config));
    }

    #[test]
    fn state_activate_from_suspended() {
        let mut state = TunnelState::Inactive;
        let config = sample_v4_config();

        state.start_configuring(config.clone()).unwrap();
        state.activate(config.clone()).unwrap();
        state.suspend().unwrap();
        assert!(state.activate(config.clone()).is_ok());
        assert!(state.is_active());
    }

    #[test]
    fn state_deactivate() {
        let mut state = TunnelState::Inactive;
        let config = sample_v4_config();

        state.start_configuring(config.clone()).unwrap();
        state.activate(config).unwrap();
        state.deactivate();
        assert!(state.is_inactive());
    }

    #[test]
    fn state_invalid_transition_active_from_inactive() {
        let mut state = TunnelState::Inactive;
        let config = sample_v4_config();

        let result = state.activate(config);
        assert!(result.is_err());
    }

    #[test]
    fn state_invalid_transition_configuring_from_active() {
        let mut state = TunnelState::Inactive;
        let config = sample_v4_config();

        state.start_configuring(config.clone()).unwrap();
        state.activate(config.clone()).unwrap();

        let result = state.start_configuring(config);
        assert!(result.is_err());
    }

    #[test]
    fn state_invalid_transition_suspend_from_inactive() {
        let mut state = TunnelState::Inactive;
        let result = state.suspend();
        assert!(result.is_err());
    }
}
