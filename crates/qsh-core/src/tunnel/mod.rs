//! Tunnel module for IP-over-QUIC functionality.
//!
//! This module is feature-gated behind the `tunnel` feature.
//! It provides:
//! - Tunnel configuration and state management
//! - Tun device abstraction
//! - Tunnel handler for packet relay

mod handler;
mod types;

#[cfg(target_os = "linux")]
mod tun_linux;

pub use handler::{TunnelHandler, TunnelStats};
pub use types::{TunnelConfig, TunnelConfigError, TunnelState, TunnelStateError};

#[cfg(target_os = "linux")]
pub use tun_linux::LinuxTun;

/// Trait for tun device implementations.
#[allow(async_fn_in_trait)]
pub trait TunDevice: Send + Sync {
    /// Read a packet from the tun device.
    async fn read_packet(&mut self) -> std::io::Result<Vec<u8>>;

    /// Write a packet to the tun device.
    async fn write_packet(&mut self, packet: &[u8]) -> std::io::Result<()>;

    /// Get the local IP address of the tun interface.
    fn local_ip(&self) -> ipnet::IpNet;

    /// Get the tun interface name.
    fn name(&self) -> &str;

    /// Get the MTU of the tun interface.
    fn mtu(&self) -> u16;
}
