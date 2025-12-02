//! Linux tun device wrapper.
//!
//! This module provides tun device functionality for Linux.
//! Requires elevated privileges (CAP_NET_ADMIN) to create tun devices.

use std::io;

use ipnet::IpNet;

use super::TunDevice;

/// Linux tun device wrapper.
///
/// TODO: This is a stub. Full implementation requires tokio-tun dependency
/// and elevated privileges to test.
pub struct LinuxTun {
    /// Tun interface name.
    name: String,
    /// Local IP address with prefix.
    local_ip: IpNet,
    /// Maximum transmission unit.
    mtu: u16,
}

impl LinuxTun {
    /// Create a new tun device.
    ///
    /// # Arguments
    ///
    /// * `name` - Interface name (e.g., "tun0"). If empty, system assigns name.
    /// * `ip` - IP address to assign to the interface.
    /// * `mtu` - Maximum transmission unit.
    ///
    /// # Errors
    ///
    /// Returns error if tun device cannot be created (usually due to permissions).
    pub async fn create(_name: &str, _ip: IpNet, _mtu: u16) -> io::Result<Self> {
        // TODO: Implement actual tun device creation using tokio-tun
        //
        // The implementation would:
        // 1. Create tun device with tokio_tun::Tun::builder()
        // 2. Set IP address and MTU
        // 3. Bring interface up
        //
        // For now, return an error indicating this is not implemented
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "LinuxTun not yet implemented - requires tokio-tun dependency",
        ))
    }
}

impl TunDevice for LinuxTun {
    async fn read_packet(&mut self) -> io::Result<Vec<u8>> {
        // TODO: Read from tun device
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "LinuxTun not yet implemented",
        ))
    }

    async fn write_packet(&mut self, _packet: &[u8]) -> io::Result<()> {
        // TODO: Write to tun device
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "LinuxTun not yet implemented",
        ))
    }

    fn local_ip(&self) -> IpNet {
        self.local_ip
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn mtu(&self) -> u16 {
        self.mtu
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    // Tun device tests would require elevated privileges and real kernel interfaces.
    // They should be integration tests marked #[ignore].

    #[test]
    fn linux_tun_stub() {
        // Just verify the module compiles
    }
}
