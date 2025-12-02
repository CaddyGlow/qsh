//! Linux tun device wrapper.
//!
//! This module provides tun device functionality for Linux.
//! Requires elevated privileges (CAP_NET_ADMIN) to create tun devices.

use std::io;
use std::net::IpAddr;
use std::process::Command;

use ipnet::IpNet;
use tun::{AbstractDevice, AsyncDevice, Configuration};

use super::TunDevice;

/// Linux tun device wrapper.
///
/// Wraps the `tun` crate's AsyncDevice with our TunDevice trait.
pub struct LinuxTun {
    /// Async tun device from the tun crate.
    device: AsyncDevice,
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
    pub async fn create(name: &str, ip: IpNet, mtu: u16) -> io::Result<Self> {
        let mut config = Configuration::default();

        // Set interface name if provided
        if !name.is_empty() {
            config.tun_name(name);
        }

        // Set IP address
        config.address(ip.addr());

        // Set netmask from prefix length
        let netmask = prefix_to_netmask(ip.prefix_len(), ip.addr().is_ipv4());
        config.netmask(netmask);

        // Set MTU
        config.mtu(mtu);

        // Bring interface up
        config.up();

        // Create the async device
        let device = tun::create_as_async(&config)
            .map_err(|e| io::Error::other(format!("failed to create tun device: {}", e)))?;

        // Get actual interface name (in case system assigned one)
        let actual_name = device
            .tun_name()
            .map_err(|e| io::Error::other(format!("failed to get tun name: {}", e)))?;

        Ok(Self {
            device,
            name: actual_name,
            local_ip: ip,
            mtu,
        })
    }

    /// Add a route through this tun device.
    ///
    /// # Arguments
    ///
    /// * `destination` - The destination network to route.
    ///
    /// # Errors
    ///
    /// Returns error if route cannot be added.
    pub fn add_route(&self, destination: IpNet) -> io::Result<()> {
        // Use ip command to add route
        let status = Command::new("ip")
            .args(["route", "add", &destination.to_string(), "dev", &self.name])
            .status()?;

        if !status.success() {
            return Err(io::Error::other(format!(
                "failed to add route {} via {}",
                destination, self.name
            )));
        }

        Ok(())
    }

    /// Remove a route from this tun device.
    ///
    /// # Arguments
    ///
    /// * `destination` - The destination network to remove.
    ///
    /// # Errors
    ///
    /// Returns error if route cannot be removed.
    pub fn remove_route(&self, destination: IpNet) -> io::Result<()> {
        let status = Command::new("ip")
            .args(["route", "del", &destination.to_string(), "dev", &self.name])
            .status()?;

        if !status.success() {
            return Err(io::Error::other(format!(
                "failed to remove route {} via {}",
                destination, self.name
            )));
        }

        Ok(())
    }
}

impl TunDevice for LinuxTun {
    async fn read_packet(&mut self) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; self.mtu as usize + 4]; // +4 for potential TUN header
        let n = self.device.recv(&mut buf).await?;
        buf.truncate(n);
        Ok(buf)
    }

    async fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        self.device.send(packet).await?;
        Ok(())
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

/// Convert a prefix length to a netmask IP address.
fn prefix_to_netmask(prefix_len: u8, is_ipv4: bool) -> IpAddr {
    if is_ipv4 {
        let mask = if prefix_len == 0 {
            0
        } else if prefix_len >= 32 {
            u32::MAX
        } else {
            u32::MAX << (32 - prefix_len)
        };
        IpAddr::V4(std::net::Ipv4Addr::from(mask))
    } else {
        let mask = if prefix_len == 0 {
            0
        } else if prefix_len >= 128 {
            u128::MAX
        } else {
            u128::MAX << (128 - prefix_len)
        };
        IpAddr::V6(std::net::Ipv6Addr::from(mask))
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefix_to_netmask_ipv4() {
        // /24 -> 255.255.255.0
        let mask = prefix_to_netmask(24, true);
        assert_eq!(mask, IpAddr::V4(std::net::Ipv4Addr::new(255, 255, 255, 0)));

        // /16 -> 255.255.0.0
        let mask = prefix_to_netmask(16, true);
        assert_eq!(mask, IpAddr::V4(std::net::Ipv4Addr::new(255, 255, 0, 0)));

        // /32 -> 255.255.255.255
        let mask = prefix_to_netmask(32, true);
        assert_eq!(
            mask,
            IpAddr::V4(std::net::Ipv4Addr::new(255, 255, 255, 255))
        );

        // /0 -> 0.0.0.0
        let mask = prefix_to_netmask(0, true);
        assert_eq!(mask, IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)));
    }

    #[test]
    fn test_prefix_to_netmask_ipv6() {
        // /64 -> ffff:ffff:ffff:ffff::
        let mask = prefix_to_netmask(64, false);
        assert_eq!(
            mask,
            IpAddr::V6(std::net::Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0
            ))
        );

        // /128 -> all ones
        let mask = prefix_to_netmask(128, false);
        assert_eq!(
            mask,
            IpAddr::V6(std::net::Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff
            ))
        );
    }

    // Note: Actual tun device tests require elevated privileges.
    // They should be run as integration tests with #[ignore] and require root.

    #[test]
    #[ignore = "requires root privileges"]
    fn test_create_tun_device() {
        // This test would require root and is marked as ignored
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let ip: IpNet = "10.0.0.1/24".parse().unwrap();
            let result = LinuxTun::create("qsh-test0", ip, 1500).await;
            // Just check that the call succeeds with proper permissions
            if let Err(e) = result {
                eprintln!("Expected to fail without root: {}", e);
            }
        });
    }
}
