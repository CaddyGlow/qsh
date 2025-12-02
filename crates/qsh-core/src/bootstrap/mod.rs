//! Bootstrap protocol for qsh server discovery.
//!
//! The bootstrap protocol uses SSH to:
//! 1. Verify the server supports qsh
//! 2. Get QUIC connection parameters (address, port)
//! 3. Exchange a session key for secure reconnection
//!
//! Protocol flow:
//! 1. Client SSH's to server and runs `qsh-server --bootstrap`
//! 2. Server outputs JSON bootstrap response
//! 3. Client parses response and connects via QUIC

mod response;

pub use response::{BootstrapResponse, ServerInfo};
