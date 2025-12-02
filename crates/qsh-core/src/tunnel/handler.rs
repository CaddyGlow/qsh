//! Tunnel handler for managing IP packet relay.
//!
//! The TunnelHandler bridges between a tun device and the QUIC tunnel stream,
//! handling bidirectional packet relay with state management.

use std::io;
use std::sync::Arc;

use tokio::sync::Mutex;

use super::TunDevice;
use super::types::{TunnelConfig, TunnelState, TunnelStateError};

/// Statistics tracked by the tunnel handler.
#[derive(Debug, Clone, Default)]
pub struct TunnelStats {
    /// Packets sent through tunnel.
    pub packets_sent: u64,
    /// Packets received from tunnel.
    pub packets_recv: u64,
    /// Bytes sent through tunnel.
    pub bytes_sent: u64,
    /// Bytes received from tunnel.
    pub bytes_recv: u64,
    /// Packets dropped due to errors.
    pub packets_dropped: u64,
}

impl TunnelStats {
    /// Record a sent packet.
    pub fn record_sent(&mut self, size: usize) {
        self.packets_sent += 1;
        self.bytes_sent += size as u64;
    }

    /// Record a received packet.
    pub fn record_recv(&mut self, size: usize) {
        self.packets_recv += 1;
        self.bytes_recv += size as u64;
    }

    /// Record a dropped packet.
    pub fn record_dropped(&mut self) {
        self.packets_dropped += 1;
    }
}

/// Tunnel handler manages the lifecycle and packet relay for an IP tunnel.
pub struct TunnelHandler<T: TunDevice> {
    /// The tun device for this tunnel.
    tun: T,
    /// Current tunnel state.
    state: Arc<Mutex<TunnelState>>,
    /// Tunnel statistics.
    stats: Arc<Mutex<TunnelStats>>,
}

impl<T: TunDevice> TunnelHandler<T> {
    /// Create a new tunnel handler with the given tun device.
    pub fn new(tun: T) -> Self {
        Self {
            tun,
            state: Arc::new(Mutex::new(TunnelState::default())),
            stats: Arc::new(Mutex::new(TunnelStats::default())),
        }
    }

    /// Get the current tunnel state.
    pub async fn state(&self) -> TunnelState {
        self.state.lock().await.clone()
    }

    /// Get the current tunnel statistics.
    pub async fn stats(&self) -> TunnelStats {
        self.stats.lock().await.clone()
    }

    /// Start configuring the tunnel with the given config.
    pub async fn start_configuring(&self, config: TunnelConfig) -> Result<(), TunnelStateError> {
        let mut state = self.state.lock().await;
        state.start_configuring(config)
    }

    /// Activate the tunnel with the negotiated config.
    pub async fn activate(&self, config: TunnelConfig) -> Result<(), TunnelStateError> {
        let mut state = self.state.lock().await;
        state.activate(config)
    }

    /// Suspend the tunnel (e.g., during reconnection).
    pub async fn suspend(&self) -> Result<(), TunnelStateError> {
        let mut state = self.state.lock().await;
        state.suspend()
    }

    /// Deactivate the tunnel.
    pub async fn deactivate(&self) {
        let mut state = self.state.lock().await;
        state.deactivate();
    }

    /// Check if the tunnel is active.
    pub async fn is_active(&self) -> bool {
        let state = self.state.lock().await;
        state.is_active()
    }

    /// Read a packet from the tun device.
    ///
    /// Returns `None` if the tunnel is not active.
    pub async fn read_packet(&mut self) -> io::Result<Option<Vec<u8>>> {
        if !self.is_active().await {
            return Ok(None);
        }

        match self.tun.read_packet().await {
            Ok(packet) => {
                let mut stats = self.stats.lock().await;
                stats.record_recv(packet.len());
                Ok(Some(packet))
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => {
                let mut stats = self.stats.lock().await;
                stats.record_dropped();
                Err(e)
            }
        }
    }

    /// Write a packet to the tun device.
    ///
    /// Returns `false` if the tunnel is not active.
    pub async fn write_packet(&mut self, packet: &[u8]) -> io::Result<bool> {
        if !self.is_active().await {
            return Ok(false);
        }

        match self.tun.write_packet(packet).await {
            Ok(()) => {
                let mut stats = self.stats.lock().await;
                stats.record_sent(packet.len());
                Ok(true)
            }
            Err(e) => {
                let mut stats = self.stats.lock().await;
                stats.record_dropped();
                Err(e)
            }
        }
    }

    /// Get the tun device name.
    pub fn tun_name(&self) -> &str {
        self.tun.name()
    }

    /// Get the local IP address.
    pub fn local_ip(&self) -> ipnet::IpNet {
        self.tun.local_ip()
    }

    /// Get the MTU.
    pub fn mtu(&self) -> u16 {
        self.tun.mtu()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::VecDeque;

    /// Test tun device for handler tests.
    #[derive(Debug)]
    struct TestTun {
        name: String,
        local_ip: ipnet::IpNet,
        mtu: u16,
        outgoing: Arc<Mutex<VecDeque<Vec<u8>>>>,
        incoming: Arc<Mutex<VecDeque<Vec<u8>>>>,
    }

    impl TestTun {
        fn new() -> Self {
            Self {
                name: "tun0".to_string(),
                local_ip: "10.0.0.2/24".parse().unwrap(),
                mtu: 1400,
                outgoing: Arc::new(Mutex::new(VecDeque::new())),
                incoming: Arc::new(Mutex::new(VecDeque::new())),
            }
        }

        async fn inject_packet(&self, packet: Vec<u8>) {
            let mut incoming = self.incoming.lock().await;
            incoming.push_back(packet);
        }

        async fn take_outgoing(&self) -> Option<Vec<u8>> {
            let mut outgoing = self.outgoing.lock().await;
            outgoing.pop_front()
        }
    }

    impl Clone for TestTun {
        fn clone(&self) -> Self {
            Self {
                name: self.name.clone(),
                local_ip: self.local_ip,
                mtu: self.mtu,
                outgoing: Arc::clone(&self.outgoing),
                incoming: Arc::clone(&self.incoming),
            }
        }
    }

    impl TunDevice for TestTun {
        async fn read_packet(&mut self) -> io::Result<Vec<u8>> {
            let mut incoming = self.incoming.lock().await;
            incoming
                .pop_front()
                .ok_or_else(|| io::Error::new(io::ErrorKind::WouldBlock, "No packets available"))
        }

        async fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
            let mut outgoing = self.outgoing.lock().await;
            outgoing.push_back(packet.to_vec());
            Ok(())
        }

        fn local_ip(&self) -> ipnet::IpNet {
            self.local_ip
        }

        fn name(&self) -> &str {
            &self.name
        }

        fn mtu(&self) -> u16 {
            self.mtu
        }
    }

    fn make_handler() -> TunnelHandler<TestTun> {
        let tun = TestTun::new();
        TunnelHandler::new(tun)
    }

    fn sample_config() -> TunnelConfig {
        TunnelConfig::new(
            "10.0.0.2/24".parse().unwrap(),
            "10.0.0.1/24".parse().unwrap(),
        )
    }

    #[tokio::test]
    async fn handler_initial_state() {
        let handler = make_handler();
        let state = handler.state().await;
        assert!(state.is_inactive());
    }

    #[tokio::test]
    async fn handler_lifecycle() {
        let handler = make_handler();
        let config = sample_config();

        // Inactive -> Configuring
        handler.start_configuring(config.clone()).await.unwrap();
        let state = handler.state().await;
        assert!(matches!(state, TunnelState::Configuring { .. }));

        // Configuring -> Active
        handler.activate(config.clone()).await.unwrap();
        assert!(handler.is_active().await);

        // Active -> Suspended
        handler.suspend().await.unwrap();
        let state = handler.state().await;
        assert!(state.is_suspended());

        // Suspended -> Active
        handler.activate(config).await.unwrap();
        assert!(handler.is_active().await);

        // Active -> Inactive
        handler.deactivate().await;
        let state = handler.state().await;
        assert!(state.is_inactive());
    }

    #[tokio::test]
    async fn handler_read_when_inactive() {
        let mut handler = make_handler();

        // Reading when inactive should return None
        let result = handler.read_packet().await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn handler_write_when_inactive() {
        let mut handler = make_handler();
        let packet = vec![0x45, 0x00, 0x00, 0x28];

        // Writing when inactive should return false
        let result = handler.write_packet(&packet).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn handler_read_write_when_active() {
        let tun = TestTun::new();
        let tun_clone = tun.clone();
        let mut handler = TunnelHandler::new(tun);
        let config = sample_config();

        // Activate
        handler.start_configuring(config.clone()).await.unwrap();
        handler.activate(config).await.unwrap();

        // Write a packet
        let packet = vec![0x45, 0x00, 0x00, 0x28];
        let result = handler.write_packet(&packet).await.unwrap();
        assert!(result);

        // Verify it went to the tun device
        let outgoing = tun_clone.take_outgoing().await.unwrap();
        assert_eq!(outgoing, packet);

        // Inject a packet for reading
        tun_clone.inject_packet(vec![0x60, 0x00, 0x00, 0x00]).await;

        // Read it back
        let read = handler.read_packet().await.unwrap().unwrap();
        assert_eq!(read, vec![0x60, 0x00, 0x00, 0x00]);

        // Check stats
        let stats = handler.stats().await;
        assert_eq!(stats.packets_sent, 1);
        assert_eq!(stats.packets_recv, 1);
        assert_eq!(stats.bytes_sent, 4);
        assert_eq!(stats.bytes_recv, 4);
    }

    #[tokio::test]
    async fn handler_tun_properties() {
        let handler = make_handler();
        assert_eq!(handler.tun_name(), "tun0");
        assert_eq!(handler.mtu(), 1400);
        assert_eq!(
            handler.local_ip(),
            "10.0.0.2/24".parse::<ipnet::IpNet>().unwrap()
        );
    }

    #[tokio::test]
    async fn handler_stats_tracking() {
        let tun = TestTun::new();
        let tun_clone = tun.clone();
        let mut handler = TunnelHandler::new(tun);
        let config = sample_config();

        handler.start_configuring(config.clone()).await.unwrap();
        handler.activate(config).await.unwrap();

        // Send multiple packets
        for _ in 0..5 {
            handler.write_packet(&[0x45, 0x00]).await.unwrap();
        }

        // Receive multiple packets
        for _ in 0..3 {
            tun_clone.inject_packet(vec![0x60, 0x00, 0x00]).await;
        }
        for _ in 0..3 {
            handler.read_packet().await.unwrap();
        }

        let stats = handler.stats().await;
        assert_eq!(stats.packets_sent, 5);
        assert_eq!(stats.packets_recv, 3);
        assert_eq!(stats.bytes_sent, 10);
        assert_eq!(stats.bytes_recv, 9);
    }
}
