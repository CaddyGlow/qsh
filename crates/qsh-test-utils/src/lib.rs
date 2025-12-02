//! qsh-test-utils: Test infrastructure for qsh.
//!
//! Provides:
//! - MockTransport: In-memory transport for testing without network
//! - FakePty: Simulated PTY for testing without real terminal
//! - FakeTun: Simulated tun device for tunnel testing
//! - TestKeys: Pre-generated keys for deterministic testing

mod fake_pty;
mod fake_tun;
mod mock_transport;
mod test_keys;

pub use fake_pty::FakePty;
pub use fake_tun::FakeTun;
pub use mock_transport::{MockConnection, MockStream, mock_connection_pair};
pub use test_keys::TestKeys;
