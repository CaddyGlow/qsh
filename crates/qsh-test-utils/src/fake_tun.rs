//! Fake tun device for testing.
//!
//! Provides an in-memory tun device implementation that doesn't require
//! elevated privileges or real kernel interfaces.

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};

use ipnet::IpNet;

/// Fake tun device for testing.
///
/// All packets are queued in memory for inspection and can be
/// injected for reading.
#[derive(Debug)]
pub struct FakeTun {
    /// Interface name.
    name: String,
    /// Local IP address.
    local_ip: IpNet,
    /// MTU.
    mtu: u16,
    /// Packets written to the device (to be "sent" to network).
    outgoing: Arc<Mutex<VecDeque<Vec<u8>>>>,
    /// Packets to be read from the device (as if "received" from network).
    incoming: Arc<Mutex<VecDeque<Vec<u8>>>>,
    /// Whether the device is "up".
    up: Arc<Mutex<bool>>,
}

impl FakeTun {
    /// Create a new fake tun device.
    pub fn new(name: &str, local_ip: IpNet, mtu: u16) -> Self {
        Self {
            name: name.to_string(),
            local_ip,
            mtu,
            outgoing: Arc::new(Mutex::new(VecDeque::new())),
            incoming: Arc::new(Mutex::new(VecDeque::new())),
            up: Arc::new(Mutex::new(true)),
        }
    }

    /// Create with default settings.
    pub fn default_v4() -> Self {
        Self::new("tun0", "10.0.0.2/24".parse().unwrap(), 1400)
    }

    /// Create with default IPv6 settings.
    pub fn default_v6() -> Self {
        Self::new("tun0", "fd00::2/64".parse().unwrap(), 1400)
    }

    /// Inject a packet as if received from the network.
    pub fn inject_packet(&self, packet: Vec<u8>) {
        let mut incoming = self.incoming.lock().unwrap();
        incoming.push_back(packet);
    }

    /// Get the next packet that was "sent" to the network.
    pub fn take_outgoing(&self) -> Option<Vec<u8>> {
        let mut outgoing = self.outgoing.lock().unwrap();
        outgoing.pop_front()
    }

    /// Get all outgoing packets.
    pub fn take_all_outgoing(&self) -> Vec<Vec<u8>> {
        let mut outgoing = self.outgoing.lock().unwrap();
        outgoing.drain(..).collect()
    }

    /// Check if there are packets waiting to be read.
    pub fn has_incoming(&self) -> bool {
        let incoming = self.incoming.lock().unwrap();
        !incoming.is_empty()
    }

    /// Count outgoing packets.
    pub fn outgoing_count(&self) -> usize {
        let outgoing = self.outgoing.lock().unwrap();
        outgoing.len()
    }

    /// Set whether the device is "up".
    pub fn set_up(&self, up: bool) {
        let mut state = self.up.lock().unwrap();
        *state = up;
    }

    /// Check if device is "up".
    pub fn is_up(&self) -> bool {
        let state = self.up.lock().unwrap();
        *state
    }

    /// Read a packet from the device.
    pub async fn read_packet(&mut self) -> io::Result<Vec<u8>> {
        if !self.is_up() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "Device is down",
            ));
        }

        let mut incoming = self.incoming.lock().unwrap();
        incoming.pop_front().ok_or_else(|| {
            io::Error::new(io::ErrorKind::WouldBlock, "No packets available")
        })
    }

    /// Write a packet to the device.
    pub async fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        if !self.is_up() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "Device is down",
            ));
        }

        if packet.len() > self.mtu as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Packet too large: {} > {}", packet.len(), self.mtu),
            ));
        }

        let mut outgoing = self.outgoing.lock().unwrap();
        outgoing.push_back(packet.to_vec());
        Ok(())
    }

    /// Get the local IP address.
    pub fn local_ip(&self) -> IpNet {
        self.local_ip
    }

    /// Get the interface name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the MTU.
    pub fn mtu(&self) -> u16 {
        self.mtu
    }
}

impl Clone for FakeTun {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            local_ip: self.local_ip,
            mtu: self.mtu,
            outgoing: Arc::clone(&self.outgoing),
            incoming: Arc::clone(&self.incoming),
            up: Arc::clone(&self.up),
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fake_tun_new() {
        let tun = FakeTun::default_v4();
        assert_eq!(tun.name(), "tun0");
        assert_eq!(tun.mtu(), 1400);
        assert!(tun.is_up());
    }

    #[tokio::test]
    async fn fake_tun_inject_and_read() {
        let mut tun = FakeTun::default_v4();

        let packet = vec![0x45, 0x00, 0x00, 0x28]; // IPv4 header start
        tun.inject_packet(packet.clone());

        assert!(tun.has_incoming());
        let read = tun.read_packet().await.unwrap();
        assert_eq!(read, packet);
        assert!(!tun.has_incoming());
    }

    #[tokio::test]
    async fn fake_tun_write_and_take() {
        let mut tun = FakeTun::default_v4();

        let packet = vec![0x45, 0x00, 0x00, 0x28]; // IPv4 header start
        tun.write_packet(&packet).await.unwrap();

        assert_eq!(tun.outgoing_count(), 1);
        let written = tun.take_outgoing().unwrap();
        assert_eq!(written, packet);
    }

    #[tokio::test]
    async fn fake_tun_multiple_packets() {
        let mut tun = FakeTun::default_v4();

        for i in 0..5 {
            let packet = vec![0x45, i];
            tun.write_packet(&packet).await.unwrap();
        }

        assert_eq!(tun.outgoing_count(), 5);
        let all = tun.take_all_outgoing();
        assert_eq!(all.len(), 5);
        assert_eq!(tun.outgoing_count(), 0);
    }

    #[tokio::test]
    async fn fake_tun_mtu_enforcement() {
        let mut tun = FakeTun::new("tun0", "10.0.0.2/24".parse().unwrap(), 100);

        // Packet within MTU
        let small = vec![0; 50];
        assert!(tun.write_packet(&small).await.is_ok());

        // Packet exceeds MTU
        let large = vec![0; 150];
        let result = tun.write_packet(&large).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn fake_tun_down() {
        let mut tun = FakeTun::default_v4();
        tun.set_up(false);

        let packet = vec![0x45, 0x00];
        let write_result = tun.write_packet(&packet).await;
        assert!(write_result.is_err());

        let read_result = tun.read_packet().await;
        assert!(read_result.is_err());
    }

    #[tokio::test]
    async fn fake_tun_no_packets() {
        let mut tun = FakeTun::default_v4();
        let result = tun.read_packet().await;
        assert!(result.is_err());
    }

    #[test]
    fn fake_tun_clone_shares_state() {
        let tun1 = FakeTun::default_v4();
        let tun2 = tun1.clone();

        tun1.inject_packet(vec![1, 2, 3]);
        assert!(tun2.has_incoming());
    }
}
