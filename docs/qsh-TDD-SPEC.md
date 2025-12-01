# qsh — TDD Protocol Specification

**Test-Driven Development Guide for a Solo Maintainer**

| Field | Value |
|-------|-------|
| Version | 1.0 |
| Rust Edition | 2024 |
| Status | Draft |
| Last Updated | December 2025 |

---

> **Note on Tunnel Feature**
> 
> The IP tunnel (VPN) functionality is implemented under the `tunnel` feature flag and initially supports **Linux only**. This allows:
> - Core terminal functionality to ship without tunnel dependencies
> - Gradual platform expansion (macOS, Windows) without blocking releases
> - Smaller binary size for users who don't need VPN features
> 
> ```toml
> # Cargo.toml
> [features]
> default = []
> tunnel = ["dep:tokio-tun", "dep:netconfig"]
> ```
> 
> All tunnel-related code, tests, and CI jobs are gated behind `#[cfg(feature = "tunnel")]`.

---

## Table of Contents

1. [Philosophy](#1-philosophy)
2. [Project Structure](#2-project-structure)
3. [Core Abstractions](#3-core-abstractions)
4. [Testing Pyramid](#4-testing-pyramid)
5. [Module Specifications](#5-module-specifications)
6. [Mock & Fake Strategies](#6-mock--fake-strategies)
7. [Integration Test Scenarios](#7-integration-test-scenarios)
8. [Property-Based Testing](#8-property-based-testing)
9. [CI Pipeline](#9-ci-pipeline)
10. [Development Workflow](#10-development-workflow)

---

## 1. Philosophy

### 1.1 Guiding Principles

**Write tests first, but don't over-test.** Focus on:

- Public API contracts (what the module promises)
- Edge cases that have bitten you before
- Invariants that must never break
- Integration points between components

**Avoid testing:**

- Private implementation details
- Trivial getters/setters
- External library behavior (trust `quinn`, `russh`, etc.)

### 1.2 Rust 2024 Idioms

```rust
// Prefer `impl Trait` in return position for flexibility
fn create_transport() -> impl Transport { ... }

// Use `async fn` in traits (stabilized in 2024)
trait Transport {
    async fn send(&mut self, data: &[u8]) -> Result<()>;
    async fn recv(&mut self) -> Result<Vec<u8>>;
}

// Leverage `let-else` for early returns
let Some(session) = sessions.get(&id) else {
    return Err(Error::SessionNotFound(id));
};

// Use `#[expect]` over `#[allow]` for intentional lint suppression
#[expect(clippy::large_enum_variant, reason = "FullState is rare")]
enum StateUpdate { ... }
```

### 1.3 Error Handling Strategy

Single crate-level error type using `thiserror`:

```rust
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("SSH bootstrap failed: {0}")]
    SshBootstrap(#[from] russh::Error),
    
    #[error("QUIC connection error: {0}")]
    Quic(#[from] quinn::ConnectionError),
    
    #[error("PTY error: {0}")]
    Pty(#[from] std::io::Error),
    
    #[error("Protocol violation: {message}")]
    Protocol { message: String },
    
    #[error("Session not found: {0}")]
    SessionNotFound(SessionId),
}

pub type Result<T> = std::result::Result<T, Error>;
```

---

## 2. Project Structure

```
qsh/
├── Cargo.toml                 # Workspace root
├── crates/
│   ├── qsh-core/              # Shared protocol, types, state
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── protocol/      # Wire protocol definitions
│   │   │   ├── terminal/      # Terminal state, parsing
│   │   │   ├── forward/       # Port forwarding types
│   │   │   ├── tunnel/        # IP tunnel types
│   │   │   └── crypto.rs      # Session keys, certs
│   │   └── tests/
│   │       └── protocol_tests.rs
│   │
│   ├── qsh-client/            # Client binary
│   │   ├── src/
│   │   │   ├── main.rs
│   │   │   ├── bootstrap.rs   # SSH bootstrap
│   │   │   ├── session.rs     # QUIC session management
│   │   │   ├── prediction.rs  # Local echo prediction
│   │   │   ├── overlay.rs     # Status overlay
│   │   │   ├── tunnel.rs      # Client tunnel handler
│   │   │   └── tui.rs         # Terminal I/O
│   │   └── tests/
│   │       ├── prediction_tests.rs
│   │       └── overlay_tests.rs
│   │
│   ├── qsh-server/            # Server binary
│   │   ├── src/
│   │   │   ├── main.rs
│   │   │   ├── pty.rs         # PTY management
│   │   │   ├── state.rs       # Terminal state tracking
│   │   │   ├── session.rs     # Session handler
│   │   │   ├── forward.rs     # Forwarding implementation
│   │   │   └── tunnel.rs      # Server tunnel handler
│   │   └── tests/
│   │       ├── pty_tests.rs
│   │       └── state_tests.rs
│   │
│   └── qsh-test-utils/        # Shared test infrastructure
│       └── src/
│           ├── lib.rs
│           ├── mock_transport.rs
│           ├── fake_pty.rs
│           ├── fake_tun.rs
│           └── test_keys.rs
│
└── tests/                     # Integration tests
    ├── bootstrap_test.rs
    ├── reconnection_test.rs
    ├── forwarding_test.rs
    ├── tunnel_test.rs
    └── e2e_test.rs
```

### 2.1 Crate Dependencies

```toml
# Cargo.toml (workspace)
[workspace]
resolver = "2"
members = ["crates/*"]

[workspace.dependencies]
tokio = { version = "1.40", features = ["full"] }
quinn = "0.11"
rustls = "0.23"
russh = "0.45"
portable-pty = "0.8"
vte = "0.13"
tracing = "0.1"
tracing-subscriber = "0.3"
clap = { version = "4.5", features = ["derive"] }
bincode = "1.3"
serde = { version = "1.0", features = ["derive"] }
thiserror = "2.0"
bytes = "1.7"
ipnet = "2.9"                    # IP network types

# Tunnel dependencies (Linux only, feature-gated)
tokio-tun = { version = "0.11", optional = true }  # Tun interface
netconfig = { version = "0.5", optional = true }   # Route configuration

# Test dependencies
tokio-test = "0.4"
proptest = "1.5"
test-case = "3.3"
assert_matches = "1.5"
```

```toml
# crates/qsh-core/Cargo.toml
[features]
default = []
tunnel = []  # Just types, no platform deps

# crates/qsh-client/Cargo.toml  
[features]
default = []
tunnel = ["qsh-core/tunnel", "dep:tokio-tun", "dep:netconfig"]

[target.'cfg(target_os = "linux")'.dependencies]
tokio-tun = { workspace = true, optional = true }
netconfig = { workspace = true, optional = true }

# crates/qsh-server/Cargo.toml
[features]
default = []
tunnel = ["qsh-core/tunnel", "dep:tokio-tun", "dep:netconfig"]

[target.'cfg(target_os = "linux")'.dependencies]
tokio-tun = { workspace = true, optional = true }
netconfig = { workspace = true, optional = true }
```

---

## 3. Core Abstractions

Define testable interfaces at module boundaries. These traits enable mocking.

### 3.1 Transport Abstraction

```rust
// qsh-core/src/transport.rs

/// Abstraction over QUIC streams for testing
pub trait StreamPair: Send + Sync {
    async fn send(&mut self, msg: &Message) -> Result<()>;
    async fn recv(&mut self) -> Result<Message>;
    fn close(&mut self);
}

/// Connection-level abstraction
pub trait Connection: Send + Sync {
    type Stream: StreamPair;
    
    async fn open_stream(&self, stream_type: StreamType) -> Result<Self::Stream>;
    async fn accept_stream(&self) -> Result<(StreamType, Self::Stream)>;
    fn remote_addr(&self) -> SocketAddr;
    fn is_connected(&self) -> bool;
    fn rtt(&self) -> Duration;
}
```

### 3.2 PTY Abstraction

```rust
// qsh-core/src/pty.rs

/// PTY operations for server-side testing
pub trait PtyHandle: Send {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    fn write(&mut self, buf: &[u8]) -> io::Result<usize>;
    fn resize(&mut self, cols: u16, rows: u16) -> io::Result<()>;
    fn get_size(&self) -> io::Result<(u16, u16)>;
}

/// Async wrapper used in production
pub trait AsyncPty: Send {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    async fn write(&mut self, buf: &[u8]) -> io::Result<usize>;
    async fn resize(&mut self, cols: u16, rows: u16) -> io::Result<()>;
}
```

### 3.3 Terminal State

```rust
// qsh-core/src/terminal/state.rs

/// Immutable snapshot of terminal state
#[derive(Clone, Debug, PartialEq)]
pub struct TerminalState {
    pub generation: u64,
    pub screen: Screen,
    pub cursor: Cursor,
    pub modes: TerminalModes,
    pub title: Option<String>,
    pub alternate_active: bool,
}

/// Diff between two states
#[derive(Clone, Debug, PartialEq)]
pub enum StateDiff {
    Full(TerminalState),
    Incremental {
        from_gen: u64,
        to_gen: u64,
        changes: Vec<CellChange>,
        cursor: Option<Cursor>,
    },
    CursorOnly {
        generation: u64,
        cursor: Cursor,
    },
}

impl TerminalState {
    /// Compute minimal diff to reach `other`
    pub fn diff_to(&self, other: &Self) -> StateDiff { ... }
    
    /// Apply diff, returning new state
    pub fn apply_diff(&self, diff: &StateDiff) -> Result<Self> { ... }
}
```

### 3.4 Tunnel Abstraction (Feature: `tunnel`, Linux only)

```rust
// qsh-core/src/tunnel.rs

#[cfg(feature = "tunnel")]
use ipnet::IpNet;

/// Tunnel device operations for testing
#[cfg(feature = "tunnel")]
pub trait TunDevice: Send {
    /// Read an IP packet from the tunnel
    async fn read_packet(&mut self) -> io::Result<Vec<u8>>;
    
    /// Write an IP packet to the tunnel
    async fn write_packet(&mut self, packet: &[u8]) -> io::Result<()>;
    
    /// Get the tunnel's assigned IP
    fn local_ip(&self) -> IpNet;
    
    /// Get the tunnel interface name
    fn name(&self) -> &str;
    
    /// Get the MTU
    fn mtu(&self) -> u16;
}

/// Tunnel configuration
#[cfg(feature = "tunnel")]
#[derive(Clone, Debug, PartialEq)]
pub struct TunnelConfig {
    pub client_ip: IpNet,
    pub server_ip: IpNet,
    pub mtu: u16,
    pub routes: Vec<IpNet>,
    pub dns_servers: Vec<std::net::IpAddr>,
}

/// Tunnel state machine
#[cfg(feature = "tunnel")]
#[derive(Clone, Debug, PartialEq)]
pub enum TunnelState {
    Inactive,
    Configuring,
    Active { config: TunnelConfig },
    Suspended,
    TornDown { reason: String },
}
```

---

## 4. Testing Pyramid

```
                    ╱╲
                   ╱  ╲
                  ╱ E2E╲           ~5 tests (slow, real network)
                 ╱──────╲
                ╱        ╲
               ╱Integration╲       ~20 tests (in-process, mocked I/O)
              ╱────────────╲
             ╱              ╲
            ╱   Unit Tests   ╲     ~200 tests (fast, pure logic)
           ╱──────────────────╲
```

### 4.1 Unit Test Guidelines

**Location:** `src/` alongside implementation (Rust convention)

**What to test:**
- Pure functions (parsing, encoding, diffing)
- State machines (prediction engine, connection state)
- Error conditions and edge cases

**Example:**

```rust
// qsh-core/src/terminal/state.rs

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn diff_empty_states_produces_cursor_only() {
        let state = TerminalState::new(80, 24);
        let same = state.clone();
        
        let diff = state.diff_to(&same);
        
        assert_matches!(diff, StateDiff::CursorOnly { .. });
    }
    
    #[test]
    fn diff_detects_single_cell_change() {
        let mut state = TerminalState::new(80, 24);
        let mut modified = state.clone();
        modified.screen.set_cell(0, 0, Cell::new('X'));
        modified.generation += 1;
        
        let diff = state.diff_to(&modified);
        
        assert_matches!(diff, StateDiff::Incremental { changes, .. } => {
            assert_eq!(changes.len(), 1);
            assert_eq!(changes[0].col, 0);
            assert_eq!(changes[0].row, 0);
        });
    }
    
    #[test]
    fn apply_diff_roundtrip() {
        let state1 = TerminalState::new(80, 24);
        let state2 = make_modified_state(&state1);
        
        let diff = state1.diff_to(&state2);
        let restored = state1.apply_diff(&diff).unwrap();
        
        assert_eq!(restored, state2);
    }
}
```

### 4.2 Integration Test Guidelines

**Location:** `crates/*/tests/` or workspace `tests/`

**What to test:**
- Component interactions (bootstrap → QUIC handshake)
- Protocol round-trips
- Reconnection scenarios
- Port forwarding flows

**Example:**

```rust
// tests/reconnection_test.rs

use qsh_test_utils::{MockTransport, FakePty, TestKeys};

#[tokio::test]
async fn client_recovers_from_connection_drop() {
    let (client_transport, server_transport) = MockTransport::pair();
    let keys = TestKeys::generate();
    
    // Setup server
    let server = TestServer::new(server_transport, keys.clone());
    let server_handle = tokio::spawn(server.run());
    
    // Setup client
    let mut client = TestClient::new(client_transport, keys);
    client.connect().await.unwrap();
    
    // Verify initial state
    assert!(client.is_connected());
    
    // Simulate network drop
    client.simulate_disconnect();
    
    // Client should detect and reconnect
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(client.is_connected());
    
    // Verify state was preserved
    let state = client.get_terminal_state();
    assert_eq!(state.generation, 1); // State synced
    
    server_handle.abort();
}
```

### 4.3 E2E Test Guidelines

**Location:** `tests/e2e_test.rs`

**What to test:**
- Full binary execution
- Real PTY behavior
- Actual QUIC over localhost
- SSH bootstrap (with test SSH server or mock)

**Run separately:** `cargo test --test e2e -- --ignored`

```rust
// tests/e2e_test.rs

#[tokio::test]
#[ignore = "requires network, run with --ignored"]
async fn full_session_with_real_pty() {
    // Start real qsh-server in background
    let server = Command::new(env!("CARGO_BIN_EXE_qsh-server"))
        .args(["--bootstrap", "--port-range", "14500-14500"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    
    // Parse connection info from server stdout
    let conn_info = parse_bootstrap_output(&server);
    
    // Connect client
    let client = Command::new(env!("CARGO_BIN_EXE_qsh"))
        .args(["--test-mode", &conn_info])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    
    // Send input, verify output
    client.stdin.write_all(b"echo hello\n").unwrap();
    let output = read_until(&client.stdout, b"hello\n").await;
    assert!(output.contains(b"hello"));
    
    // Cleanup
    client.kill().unwrap();
    server.kill().unwrap();
}
```

---

## 5. Module Specifications

### 5.1 Protocol Module (`qsh-core/src/protocol/`)

**Responsibility:** Wire format encoding/decoding, message types

#### Messages

```rust
// protocol/messages.rs

use serde::{Serialize, Deserialize};

/// Top-level protocol message
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Message {
    // Control stream
    Hello(HelloPayload),
    HelloAck(HelloAckPayload),
    Resize(ResizePayload),
    Ping(u64),
    Pong(u64),
    Shutdown(ShutdownReason),
    
    // Terminal streams
    TerminalInput(TerminalInputPayload),
    StateUpdate(StateUpdatePayload),
    StateAck(u64), // generation acknowledged
    
    // Forwarding
    ForwardRequest(ForwardRequestPayload),
    ForwardAccept(ForwardAcceptPayload),
    ForwardReject(ForwardRejectPayload),
    ForwardData(ForwardDataPayload),
    ForwardClose(u64), // forward_id
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HelloPayload {
    pub protocol_version: u32,
    pub session_key: [u8; 32],
    pub client_nonce: u64,
    pub capabilities: Capabilities,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TerminalInputPayload {
    pub sequence: u64,
    pub data: Vec<u8>,
    pub echo_prediction: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StateUpdatePayload {
    pub diff: StateDiff,
    pub confirmed_input_seq: u64,
}
```

#### Codec

```rust
// protocol/codec.rs

use bytes::{Buf, BufMut, Bytes, BytesMut};

/// Length-prefixed bincode encoding
pub struct Codec;

impl Codec {
    pub fn encode(msg: &Message) -> Result<Bytes> {
        let payload = bincode::serialize(msg)?;
        let len = payload.len() as u32;
        
        let mut buf = BytesMut::with_capacity(4 + payload.len());
        buf.put_u32_le(len);
        buf.put_slice(&payload);
        
        Ok(buf.freeze())
    }
    
    pub fn decode(buf: &mut impl Buf) -> Result<Option<Message>> {
        if buf.remaining() < 4 {
            return Ok(None); // Need more data
        }
        
        let len = buf.get_u32_le() as usize;
        if buf.remaining() < len {
            return Ok(None); // Need more data
        }
        
        let payload = buf.copy_to_bytes(len);
        let msg = bincode::deserialize(&payload)?;
        Ok(Some(msg))
    }
}
```

#### Tests

```rust
// protocol/tests.rs

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    
    #[test]
    fn encode_decode_roundtrip_hello() {
        let msg = Message::Hello(HelloPayload {
            protocol_version: 1,
            session_key: [0xAB; 32],
            client_nonce: 12345,
            capabilities: Capabilities::default(),
        });
        
        let encoded = Codec::encode(&msg).unwrap();
        let mut buf = encoded.as_ref();
        let decoded = Codec::decode(&mut buf).unwrap().unwrap();
        
        assert_eq!(msg, decoded);
    }
    
    #[test]
    fn decode_partial_returns_none() {
        let msg = Message::Ping(42);
        let encoded = Codec::encode(&msg).unwrap();
        
        // Only provide half the bytes
        let partial = &encoded[..encoded.len() / 2];
        let mut buf = partial;
        
        assert!(Codec::decode(&mut buf).unwrap().is_none());
    }
    
    proptest! {
        #[test]
        fn roundtrip_arbitrary_terminal_input(
            seq in 0u64..u64::MAX,
            data in prop::collection::vec(any::<u8>(), 0..1024),
            echo in any::<bool>(),
        ) {
            let msg = Message::TerminalInput(TerminalInputPayload {
                sequence: seq,
                data,
                echo_prediction: echo,
            });
            
            let encoded = Codec::encode(&msg).unwrap();
            let mut buf = encoded.as_ref();
            let decoded = Codec::decode(&mut buf).unwrap().unwrap();
            
            prop_assert_eq!(msg, decoded);
        }
    }
}
```

---

### 5.2 Terminal State Module (`qsh-core/src/terminal/`)

**Responsibility:** Screen buffer, escape sequence parsing, state diffing

#### Screen Buffer

```rust
// terminal/screen.rs

#[derive(Clone, Debug, PartialEq)]
pub struct Screen {
    cols: u16,
    rows: u16,
    cells: Vec<Cell>, // row-major: cells[row * cols + col]
    dirty: BitVec,    // Tracks modified cells for diffing
}

#[derive(Clone, Debug, PartialEq, Default)]
pub struct Cell {
    pub grapheme: String, // Full Unicode grapheme cluster
    pub width: u8,        // Display width (1 or 2)
    pub attrs: CellAttrs,
}

#[derive(Clone, Debug, PartialEq, Default)]
pub struct CellAttrs {
    pub fg: Color,
    pub bg: Color,
    pub flags: AttrFlags, // bold, italic, underline, etc.
}

impl Screen {
    pub fn new(cols: u16, rows: u16) -> Self { ... }
    
    pub fn get_cell(&self, col: u16, row: u16) -> Option<&Cell> { ... }
    
    pub fn set_cell(&mut self, col: u16, row: u16, cell: Cell) {
        let idx = self.index(col, row);
        self.cells[idx] = cell;
        self.dirty.set(idx, true);
    }
    
    pub fn dirty_cells(&self) -> impl Iterator<Item = (u16, u16, &Cell)> {
        self.dirty.iter_ones().map(|idx| {
            let row = (idx / self.cols as usize) as u16;
            let col = (idx % self.cols as usize) as u16;
            (col, row, &self.cells[idx])
        })
    }
    
    pub fn clear_dirty(&mut self) {
        self.dirty.fill(false);
    }
    
    pub fn resize(&mut self, new_cols: u16, new_rows: u16) { ... }
}
```

#### VTE Parser Integration

```rust
// terminal/parser.rs

use vte::{Parser, Perform};

/// Parses escape sequences and updates terminal state
pub struct TerminalParser {
    state: TerminalState,
    parser: Parser,
}

impl TerminalParser {
    pub fn new(cols: u16, rows: u16) -> Self {
        Self {
            state: TerminalState::new(cols, rows),
            parser: Parser::new(),
        }
    }
    
    /// Process raw PTY output, updating internal state
    pub fn process(&mut self, data: &[u8]) {
        for byte in data {
            self.parser.advance(self, *byte);
        }
        self.state.generation += 1;
    }
    
    /// Take current state snapshot
    pub fn snapshot(&self) -> TerminalState {
        self.state.clone()
    }
    
    /// Take state and reset dirty tracking
    pub fn take_snapshot(&mut self) -> TerminalState {
        let state = self.state.clone();
        self.state.screen.clear_dirty();
        state
    }
}

impl Perform for TerminalParser {
    fn print(&mut self, c: char) {
        self.state.put_char(c);
    }
    
    fn execute(&mut self, byte: u8) {
        match byte {
            0x08 => self.state.backspace(),
            0x09 => self.state.tab(),
            0x0A => self.state.newline(),
            0x0D => self.state.carriage_return(),
            _ => {}
        }
    }
    
    fn csi_dispatch(&mut self, params: &[i64], intermediates: &[u8], _ignore: bool, action: char) {
        // Handle CSI sequences (cursor movement, colors, etc.)
        match (action, intermediates) {
            ('m', []) => self.handle_sgr(params),
            ('H', []) | ('f', []) => self.handle_cup(params),
            ('A', []) => self.handle_cuu(params),
            // ... etc
            _ => {}
        }
    }
    
    // ... other Perform methods
}
```

#### Tests

```rust
// terminal/tests.rs

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn print_ascii_updates_cursor() {
        let mut parser = TerminalParser::new(80, 24);
        parser.process(b"ABC");
        
        let state = parser.snapshot();
        assert_eq!(state.cursor.col, 3);
        assert_eq!(state.cursor.row, 0);
        assert_eq!(state.screen.get_cell(0, 0).unwrap().grapheme, "A");
        assert_eq!(state.screen.get_cell(1, 0).unwrap().grapheme, "B");
        assert_eq!(state.screen.get_cell(2, 0).unwrap().grapheme, "C");
    }
    
    #[test]
    fn cursor_movement_csi() {
        let mut parser = TerminalParser::new(80, 24);
        
        // Move to row 5, col 10 (1-indexed in ANSI)
        parser.process(b"\x1b[5;10H");
        
        let state = parser.snapshot();
        assert_eq!(state.cursor.row, 4); // 0-indexed
        assert_eq!(state.cursor.col, 9);
    }
    
    #[test]
    fn sgr_sets_colors() {
        let mut parser = TerminalParser::new(80, 24);
        
        // Red foreground, blue background
        parser.process(b"\x1b[31;44mX");
        
        let state = parser.snapshot();
        let cell = state.screen.get_cell(0, 0).unwrap();
        assert_eq!(cell.attrs.fg, Color::Indexed(1)); // Red
        assert_eq!(cell.attrs.bg, Color::Indexed(4)); // Blue
    }
    
    #[test]
    fn true_color_sgr() {
        let mut parser = TerminalParser::new(80, 24);
        
        // RGB foreground: 255, 128, 64
        parser.process(b"\x1b[38;2;255;128;64mX");
        
        let state = parser.snapshot();
        let cell = state.screen.get_cell(0, 0).unwrap();
        assert_eq!(cell.attrs.fg, Color::Rgb(255, 128, 64));
    }
    
    #[test]
    fn alternate_screen_switch() {
        let mut parser = TerminalParser::new(80, 24);
        
        // Write to main screen
        parser.process(b"MAIN");
        
        // Switch to alternate screen
        parser.process(b"\x1b[?1049h");
        parser.process(b"ALT");
        
        let state = parser.snapshot();
        assert!(state.alternate_active);
        assert_eq!(state.screen.get_cell(0, 0).unwrap().grapheme, "A");
        
        // Switch back
        parser.process(b"\x1b[?1049l");
        
        let state = parser.snapshot();
        assert!(!state.alternate_active);
        assert_eq!(state.screen.get_cell(0, 0).unwrap().grapheme, "M");
    }
    
    #[test]
    fn wide_character_handling() {
        let mut parser = TerminalParser::new(80, 24);
        
        // Chinese character (2 cells wide)
        parser.process("中".as_bytes());
        
        let state = parser.snapshot();
        assert_eq!(state.cursor.col, 2); // Advanced by 2
        assert_eq!(state.screen.get_cell(0, 0).unwrap().width, 2);
    }
    
    #[test]
    fn emoji_with_zwj() {
        let mut parser = TerminalParser::new(80, 24);
        
        // Family emoji (ZWJ sequence)
        parser.process("👨‍👩‍👧".as_bytes());
        
        let state = parser.snapshot();
        let cell = state.screen.get_cell(0, 0).unwrap();
        assert_eq!(cell.grapheme, "👨‍👩‍👧");
    }
}
```

---

### 5.3 Prediction Engine (`qsh-client/src/prediction.rs`)

**Responsibility:** Local echo prediction, confirmation, rollback

```rust
// prediction.rs

use std::collections::VecDeque;

#[derive(Debug)]
pub struct PredictionEngine {
    predictions: VecDeque<Prediction>,
    next_sequence: u64,
    confirmed_sequence: u64,
    state: PredictionState,
}

#[derive(Debug, Clone)]
struct Prediction {
    sequence: u64,
    chars: Vec<char>,
    timestamp: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PredictionState {
    Confident,      // Predictions likely correct
    Tentative,      // Recent misprediction, be conservative  
    Disabled,       // Too many errors, wait for sync
}

impl PredictionEngine {
    pub fn new() -> Self {
        Self {
            predictions: VecDeque::new(),
            next_sequence: 0,
            confirmed_sequence: 0,
            state: PredictionState::Confident,
        }
    }
    
    /// Predict local echo for a character. Returns display info.
    pub fn predict(&mut self, c: char) -> Option<PredictedEcho> {
        if !self.should_predict(c) {
            return None;
        }
        
        let seq = self.next_sequence;
        self.next_sequence += 1;
        
        self.predictions.push_back(Prediction {
            sequence: seq,
            chars: vec![c],
            timestamp: Instant::now(),
        });
        
        Some(PredictedEcho {
            sequence: seq,
            char: c,
            style: PredictedStyle::Underline,
        })
    }
    
    /// Server confirmed input up to this sequence
    pub fn confirm(&mut self, sequence: u64) {
        self.confirmed_sequence = sequence;
        
        // Remove confirmed predictions
        while let Some(p) = self.predictions.front() {
            if p.sequence <= sequence {
                self.predictions.pop_front();
            } else {
                break;
            }
        }
        
        // Successful confirmations increase confidence
        if self.state == PredictionState::Tentative {
            self.state = PredictionState::Confident;
        }
    }
    
    /// Server sent state that contradicts predictions
    pub fn misprediction(&mut self) {
        self.predictions.clear();
        self.state = match self.state {
            PredictionState::Confident => PredictionState::Tentative,
            PredictionState::Tentative => PredictionState::Disabled,
            PredictionState::Disabled => PredictionState::Disabled,
        };
    }
    
    /// Reset after full state sync
    pub fn reset(&mut self) {
        self.predictions.clear();
        self.state = PredictionState::Confident;
    }
    
    fn should_predict(&self, c: char) -> bool {
        match self.state {
            PredictionState::Disabled => false,
            PredictionState::Tentative => c.is_ascii_alphanumeric(),
            PredictionState::Confident => c.is_ascii() && !c.is_control(),
        }
    }
    
    /// Get pending predictions for display
    pub fn pending(&self) -> impl Iterator<Item = &Prediction> {
        self.predictions.iter()
    }
}

#[derive(Debug, Clone)]
pub struct PredictedEcho {
    pub sequence: u64,
    pub char: char,
    pub style: PredictedStyle,
}

#[derive(Debug, Clone, Copy)]
pub enum PredictedStyle {
    Underline,
    Dim,
}
```

#### Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn predict_printable_chars() {
        let mut engine = PredictionEngine::new();
        
        let echo = engine.predict('a').unwrap();
        assert_eq!(echo.char, 'a');
        assert_eq!(echo.sequence, 0);
        
        let echo = engine.predict('b').unwrap();
        assert_eq!(echo.sequence, 1);
    }
    
    #[test]
    fn no_predict_control_chars() {
        let mut engine = PredictionEngine::new();
        
        assert!(engine.predict('\x03').is_none()); // Ctrl-C
        assert!(engine.predict('\x1b').is_none()); // Escape
    }
    
    #[test]
    fn confirm_removes_predictions() {
        let mut engine = PredictionEngine::new();
        
        engine.predict('a');
        engine.predict('b');
        engine.predict('c');
        
        assert_eq!(engine.pending().count(), 3);
        
        engine.confirm(1);
        assert_eq!(engine.pending().count(), 1); // Only 'c' remains
    }
    
    #[test]
    fn misprediction_degrades_confidence() {
        let mut engine = PredictionEngine::new();
        assert_eq!(engine.state, PredictionState::Confident);
        
        engine.misprediction();
        assert_eq!(engine.state, PredictionState::Tentative);
        
        engine.misprediction();
        assert_eq!(engine.state, PredictionState::Disabled);
    }
    
    #[test]
    fn confirmation_restores_confidence() {
        let mut engine = PredictionEngine::new();
        engine.misprediction();
        assert_eq!(engine.state, PredictionState::Tentative);
        
        engine.predict('a');
        engine.confirm(0);
        assert_eq!(engine.state, PredictionState::Confident);
    }
    
    #[test]
    fn tentative_only_predicts_alphanumeric() {
        let mut engine = PredictionEngine::new();
        engine.misprediction(); // -> Tentative
        
        assert!(engine.predict('a').is_some());
        assert!(engine.predict('5').is_some());
        assert!(engine.predict('-').is_none()); // Not alphanumeric
    }
}
```

---

### 5.4 Port Forwarding (`qsh-core/src/forward/`)

**Responsibility:** Forwarding request types, connection tracking

```rust
// forward/types.rs

#[derive(Debug, Clone, PartialEq)]
pub enum ForwardSpec {
    Local {
        bind_addr: SocketAddr,
        target_host: String,
        target_port: u16,
    },
    Remote {
        bind_addr: SocketAddr,
        target_host: String,
        target_port: u16,
    },
    Dynamic {
        bind_addr: SocketAddr,
    },
}

impl ForwardSpec {
    /// Parse SSH-style forward specification
    pub fn parse_local(spec: &str) -> Result<Self> { ... }
    pub fn parse_remote(spec: &str) -> Result<Self> { ... }
    pub fn parse_dynamic(spec: &str) -> Result<Self> { ... }
}

#[derive(Debug)]
pub struct ForwardManager {
    forwards: HashMap<u64, ActiveForward>,
    next_id: u64,
}

#[derive(Debug)]
struct ActiveForward {
    spec: ForwardSpec,
    connections: HashMap<u64, ForwardConnection>,
    listener: Option<TcpListener>,
}
```

#### Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn parse_local_full() {
        let spec = ForwardSpec::parse_local("127.0.0.1:5432:db.internal:5432").unwrap();
        
        assert_matches!(spec, ForwardSpec::Local { bind_addr, target_host, target_port } => {
            assert_eq!(bind_addr, "127.0.0.1:5432".parse().unwrap());
            assert_eq!(target_host, "db.internal");
            assert_eq!(target_port, 5432);
        });
    }
    
    #[test]
    fn parse_local_short() {
        // Omitted bind address defaults to localhost
        let spec = ForwardSpec::parse_local("5432:db.internal:5432").unwrap();
        
        assert_matches!(spec, ForwardSpec::Local { bind_addr, .. } => {
            assert_eq!(bind_addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        });
    }
    
    #[test]
    fn parse_dynamic() {
        let spec = ForwardSpec::parse_dynamic("1080").unwrap();
        
        assert_matches!(spec, ForwardSpec::Dynamic { bind_addr } => {
            assert_eq!(bind_addr.port(), 1080);
        });
    }
    
    #[test]
    fn parse_invalid_rejects() {
        assert!(ForwardSpec::parse_local("invalid").is_err());
        assert!(ForwardSpec::parse_local("").is_err());
        assert!(ForwardSpec::parse_local("abc:def:ghi").is_err());
    }
}
```

---

### 5.5 Tunnel Module (`qsh-core/src/tunnel/`) — Feature: `tunnel`, Linux only

**Responsibility:** IP tunnel configuration, packet handling, routing

> **Platform Note:** This module is gated behind `#[cfg(all(feature = "tunnel", target_os = "linux"))]`. 
> Tests requiring real tun devices need `CAP_NET_ADMIN` or root.

#### Types

```rust
// tunnel/types.rs

#[cfg(feature = "tunnel")]
use ipnet::IpNet;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TunnelConfigPayload {
    pub client_ip: IpNet,
    pub mtu: u16,
    pub requested_routes: Vec<IpNet>,
    pub ipv6: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TunnelConfigAckPayload {
    pub accepted: bool,
    pub reject_reason: Option<String>,
    pub server_ip: IpNet,
    pub mtu: u16,
    pub routes: Vec<IpNet>,
    pub dns_servers: Vec<std::net::IpAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TunnelPacketPayload {
    pub packet: Vec<u8>,
}

impl TunnelPacketPayload {
    /// Get IP version from packet (4 or 6)
    pub fn ip_version(&self) -> Option<u8> {
        self.packet.first().map(|b| b >> 4)
    }
    
    /// Validate basic IP packet structure
    pub fn is_valid(&self) -> bool {
        match self.ip_version() {
            Some(4) => self.packet.len() >= 20, // Min IPv4 header
            Some(6) => self.packet.len() >= 40, // Min IPv6 header
            _ => false,
        }
    }
}
```

#### Handler

```rust
// tunnel/handler.rs

#[cfg(all(feature = "tunnel", target_os = "linux"))]
use tokio_tun::Tun;

#[cfg(feature = "tunnel")]
pub struct TunnelHandler<T: TunDevice> {
    tun: T,
    config: TunnelConfig,
    state: TunnelState,
    stats: TunnelStats,
}

#[cfg(feature = "tunnel")]
#[derive(Default)]
pub struct TunnelStats {
    pub packets_sent: u64,
    pub packets_recv: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
}

#[cfg(feature = "tunnel")]
impl<T: TunDevice> TunnelHandler<T> {
    pub fn new(tun: T, config: TunnelConfig) -> Self {
        Self {
            tun,
            config,
            state: TunnelState::Active { config: config.clone() },
            stats: TunnelStats::default(),
        }
    }
    
    pub async fn read_packet(&mut self) -> Result<TunnelPacketPayload> {
        let packet = self.tun.read_packet().await?;
        self.stats.packets_recv += 1;
        self.stats.bytes_recv += packet.len() as u64;
        Ok(TunnelPacketPayload { packet })
    }
    
    pub async fn write_packet(&mut self, payload: &TunnelPacketPayload) -> Result<()> {
        if !payload.is_valid() {
            return Err(Error::Protocol { 
                message: "invalid IP packet".into() 
            });
        }
        self.tun.write_packet(&payload.packet).await?;
        self.stats.packets_sent += 1;
        self.stats.bytes_sent += payload.packet.len() as u64;
        Ok(())
    }
    
    pub fn stats(&self) -> &TunnelStats { &self.stats }
    pub fn state(&self) -> &TunnelState { &self.state }
    pub fn config(&self) -> &TunnelConfig { &self.config }
}
```

#### Tests

```rust
// tunnel/tests.rs

#[cfg(all(test, feature = "tunnel"))]
mod tests {
    use super::*;
    use crate::test_utils::FakeTun;
    
    #[test]
    fn packet_ip_version_detection() {
        // IPv4 packet (version nibble = 4)
        let ipv4 = TunnelPacketPayload { 
            packet: vec![0x45, 0x00, 0x00, 0x14, /* ... */] 
        };
        assert_eq!(ipv4.ip_version(), Some(4));
        
        // IPv6 packet (version nibble = 6)
        let ipv6 = TunnelPacketPayload { 
            packet: vec![0x60, 0x00, 0x00, 0x00, /* ... */] 
        };
        assert_eq!(ipv6.ip_version(), Some(6));
        
        // Empty packet
        let empty = TunnelPacketPayload { packet: vec![] };
        assert_eq!(empty.ip_version(), None);
    }
    
    #[test]
    fn packet_validation() {
        // Valid IPv4 (20+ bytes)
        let valid_v4 = TunnelPacketPayload { 
            packet: vec![0x45; 20] 
        };
        assert!(valid_v4.is_valid());
        
        // Too short for IPv4
        let short_v4 = TunnelPacketPayload { 
            packet: vec![0x45; 10] 
        };
        assert!(!short_v4.is_valid());
        
        // Valid IPv6 (40+ bytes)
        let valid_v6 = TunnelPacketPayload { 
            packet: vec![0x60; 40] 
        };
        assert!(valid_v6.is_valid());
        
        // Invalid version
        let bad_version = TunnelPacketPayload { 
            packet: vec![0x50; 40] // Version 5 doesn't exist
        };
        assert!(!bad_version.is_valid());
    }
    
    #[tokio::test]
    async fn handler_tracks_stats() {
        let fake_tun = FakeTun::new("10.99.0.2/24".parse().unwrap(), 1280);
        let config = TunnelConfig {
            client_ip: "10.99.0.2/24".parse().unwrap(),
            server_ip: "10.99.0.1/24".parse().unwrap(),
            mtu: 1280,
            routes: vec![],
            dns_servers: vec![],
        };
        
        let mut handler = TunnelHandler::new(fake_tun, config);
        
        // Simulate receiving a packet
        handler.tun.inject_packet(vec![0x45; 64]);
        let _ = handler.read_packet().await.unwrap();
        
        assert_eq!(handler.stats().packets_recv, 1);
        assert_eq!(handler.stats().bytes_recv, 64);
        
        // Simulate sending a packet
        let outbound = TunnelPacketPayload { packet: vec![0x45; 100] };
        handler.write_packet(&outbound).await.unwrap();
        
        assert_eq!(handler.stats().packets_sent, 1);
        assert_eq!(handler.stats().bytes_sent, 100);
    }
    
    #[test]
    fn config_serialization_roundtrip() {
        let config = TunnelConfigPayload {
            client_ip: "10.99.0.2/24".parse().unwrap(),
            mtu: 1280,
            requested_routes: vec!["192.168.0.0/16".parse().unwrap()],
            ipv6: false,
        };
        
        let encoded = bincode::serialize(&config).unwrap();
        let decoded: TunnelConfigPayload = bincode::deserialize(&encoded).unwrap();
        
        assert_eq!(config, decoded);
    }
    
    #[test]
    fn config_ack_with_routes() {
        let ack = TunnelConfigAckPayload {
            accepted: true,
            reject_reason: None,
            server_ip: "10.99.0.1/24".parse().unwrap(),
            mtu: 1280,
            routes: vec![
                "0.0.0.0/0".parse().unwrap(),  // Default route
            ],
            dns_servers: vec!["10.99.0.1".parse().unwrap()],
        };
        
        assert!(ack.accepted);
        assert_eq!(ack.routes.len(), 1);
        assert_eq!(ack.dns_servers.len(), 1);
    }
}

// Tests requiring real tun device (need root/CAP_NET_ADMIN)
#[cfg(all(test, feature = "tunnel", target_os = "linux"))]
mod integration_tests {
    use super::*;
    
    #[tokio::test]
    #[ignore = "requires CAP_NET_ADMIN, run with: sudo -E cargo test tunnel_integration"]
    async fn real_tun_device_creation() {
        use tokio_tun::Tun;
        
        let tun = Tun::builder()
            .name("qshtest%d")
            .tap(false)
            .mtu(1280)
            .address("10.99.99.1".parse().unwrap())
            .netmask("255.255.255.0".parse().unwrap())
            .up()
            .try_build()
            .expect("failed to create tun device");
        
        assert!(tun.name().starts_with("qshtest"));
    }
}
```

---

## 6. Mock & Fake Strategies

### 6.1 Mock Transport

```rust
// qsh-test-utils/src/mock_transport.rs

use tokio::sync::mpsc;
use std::sync::Arc;
use parking_lot::Mutex;

/// In-memory transport for testing without network
pub struct MockTransport {
    tx: mpsc::Sender<Bytes>,
    rx: mpsc::Receiver<Bytes>,
    metrics: Arc<Mutex<MockMetrics>>,
}

#[derive(Default)]
pub struct MockMetrics {
    pub bytes_sent: usize,
    pub bytes_recv: usize,
    pub messages_sent: usize,
    pub messages_recv: usize,
}

impl MockTransport {
    /// Create a connected pair of transports
    pub fn pair() -> (Self, Self) {
        let (tx1, rx1) = mpsc::channel(100);
        let (tx2, rx2) = mpsc::channel(100);
        
        let metrics1 = Arc::new(Mutex::new(MockMetrics::default()));
        let metrics2 = Arc::new(Mutex::new(MockMetrics::default()));
        
        (
            Self { tx: tx1, rx: rx2, metrics: metrics1 },
            Self { tx: tx2, rx: rx1, metrics: metrics2 },
        )
    }
    
    pub fn metrics(&self) -> MockMetrics {
        self.metrics.lock().clone()
    }
}

impl StreamPair for MockTransport {
    async fn send(&mut self, msg: &Message) -> Result<()> {
        let bytes = Codec::encode(msg)?;
        let mut metrics = self.metrics.lock();
        metrics.bytes_sent += bytes.len();
        metrics.messages_sent += 1;
        drop(metrics);
        
        self.tx.send(bytes).await.map_err(|_| Error::Disconnected)?;
        Ok(())
    }
    
    async fn recv(&mut self) -> Result<Message> {
        let bytes = self.rx.recv().await.ok_or(Error::Disconnected)?;
        let mut metrics = self.metrics.lock();
        metrics.bytes_recv += bytes.len();
        metrics.messages_recv += 1;
        drop(metrics);
        
        let mut buf = bytes.as_ref();
        Codec::decode(&mut buf)?.ok_or(Error::Protocol { 
            message: "incomplete message".into() 
        })
    }
    
    fn close(&mut self) {
        // Drop sender to signal EOF
    }
}
```

### 6.2 Fake PTY

```rust
// qsh-test-utils/src/fake_pty.rs

use std::collections::VecDeque;

/// Simulated PTY for testing without real terminal
pub struct FakePty {
    input_buffer: VecDeque<u8>,
    output_buffer: VecDeque<u8>,
    size: (u16, u16),
    closed: bool,
}

impl FakePty {
    pub fn new(cols: u16, rows: u16) -> Self {
        Self {
            input_buffer: VecDeque::new(),
            output_buffer: VecDeque::new(),
            size: (cols, rows),
            closed: false,
        }
    }
    
    /// Inject data as if it came from the PTY (shell output)
    pub fn inject_output(&mut self, data: &[u8]) {
        self.output_buffer.extend(data);
    }
    
    /// Read data written to the PTY (user input)
    pub fn take_input(&mut self) -> Vec<u8> {
        self.input_buffer.drain(..).collect()
    }
}

impl PtyHandle for FakePty {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.closed {
            return Ok(0);
        }
        
        let n = buf.len().min(self.output_buffer.len());
        for (i, byte) in self.output_buffer.drain(..n).enumerate() {
            buf[i] = byte;
        }
        Ok(n)
    }
    
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.closed {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"));
        }
        self.input_buffer.extend(buf);
        Ok(buf.len())
    }
    
    fn resize(&mut self, cols: u16, rows: u16) -> io::Result<()> {
        self.size = (cols, rows);
        Ok(())
    }
    
    fn get_size(&self) -> io::Result<(u16, u16)> {
        Ok(self.size)
    }
}
```

### 6.3 Fake Tun (Feature: `tunnel`)

```rust
// qsh-test-utils/src/fake_tun.rs

#[cfg(feature = "tunnel")]
use std::collections::VecDeque;
use ipnet::IpNet;

/// Simulated tun device for testing without real network interface
#[cfg(feature = "tunnel")]
pub struct FakeTun {
    /// Packets "received" from the network (to be read)
    inbound: VecDeque<Vec<u8>>,
    /// Packets "sent" to the network (written by handler)
    outbound: VecDeque<Vec<u8>>,
    /// Assigned IP
    local_ip: IpNet,
    /// Interface MTU
    mtu: u16,
    /// Interface name
    name: String,
}

#[cfg(feature = "tunnel")]
impl FakeTun {
    pub fn new(local_ip: IpNet, mtu: u16) -> Self {
        Self {
            inbound: VecDeque::new(),
            outbound: VecDeque::new(),
            local_ip,
            mtu,
            name: "faketun0".to_string(),
        }
    }
    
    /// Inject a packet as if it arrived from the network
    pub fn inject_packet(&mut self, packet: Vec<u8>) {
        self.inbound.push_back(packet);
    }
    
    /// Take packets that were "sent" to the network
    pub fn take_outbound(&mut self) -> Vec<Vec<u8>> {
        self.outbound.drain(..).collect()
    }
    
    /// Check if any packets are waiting to be read
    pub fn has_inbound(&self) -> bool {
        !self.inbound.is_empty()
    }
}

#[cfg(feature = "tunnel")]
impl TunDevice for FakeTun {
    async fn read_packet(&mut self) -> io::Result<Vec<u8>> {
        self.inbound.pop_front().ok_or_else(|| {
            io::Error::new(io::ErrorKind::WouldBlock, "no packets")
        })
    }
    
    async fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        if packet.len() > self.mtu as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet exceeds MTU"
            ));
        }
        self.outbound.push_back(packet.to_vec());
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
```

### 6.4 Test Keys

```rust
// qsh-test-utils/src/test_keys.rs

use rcgen::{CertifiedKey, generate_simple_self_signed};
use rand::RngCore;

/// Pre-generated keys for deterministic testing
pub struct TestKeys {
    pub session_key: [u8; 32],
    pub cert: CertifiedKey,
}

impl TestKeys {
    pub fn generate() -> Self {
        let mut session_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut session_key);
        
        let subject_alt_names = vec!["localhost".to_string()];
        let cert = generate_simple_self_signed(subject_alt_names).unwrap();
        
        Self { session_key, cert }
    }
    
    /// Fixed keys for snapshot tests
    pub fn deterministic() -> Self {
        let session_key = [0x42u8; 32];
        // Load pre-generated cert from test fixtures
        let cert_pem = include_str!("../fixtures/test_cert.pem");
        let key_pem = include_str!("../fixtures/test_key.pem");
        // ... parse and construct
        todo!()
    }
}
```

---

## 7. Integration Test Scenarios

### 7.1 Bootstrap Flow

```rust
// tests/bootstrap_test.rs

#[tokio::test]
async fn bootstrap_exchanges_credentials() {
    let (client_ssh, server_ssh) = mock_ssh_channel();
    
    // Server side: generate and send credentials
    let server_keys = TestKeys::generate();
    let bootstrap_msg = BootstrapMessage {
        quic_port: 4500,
        session_key: server_keys.session_key,
        cert_der: server_keys.cert.cert.der().to_vec(),
    };
    server_ssh.send(bootstrap_msg.encode()).await.unwrap();
    
    // Client side: receive and parse
    let received = client_ssh.recv().await.unwrap();
    let parsed = BootstrapMessage::decode(&received).unwrap();
    
    assert_eq!(parsed.quic_port, 4500);
    assert_eq!(parsed.session_key, server_keys.session_key);
}
```

### 7.2 State Sync Flow

```rust
// tests/state_sync_test.rs

#[tokio::test]
async fn incremental_sync_after_reconnect() {
    let (mut client, mut server) = setup_connected_pair().await;
    
    // Server produces some output
    server.pty.inject_output(b"Hello, World!\r\n");
    server.process_pty().await;
    
    // Client receives state
    let update = client.recv_state_update().await.unwrap();
    client.apply_update(update);
    
    assert_eq!(client.state().generation, 1);
    
    // Simulate disconnect/reconnect
    client.disconnect();
    client.reconnect().await.unwrap();
    
    // Server sends only diff (nothing changed)
    let update = client.recv_state_update().await.unwrap();
    assert_matches!(update.diff, StateDiff::CursorOnly { .. });
}
```

### 7.3 Port Forwarding Flow

```rust
// tests/forwarding_test.rs

#[tokio::test]
async fn local_forward_connects_to_target() {
    let (mut client, mut server) = setup_connected_pair().await;
    
    // Setup mock target server
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_port = target.local_addr().unwrap().port();
    
    // Client requests local forward
    client.request_forward(ForwardSpec::Local {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        target_host: "127.0.0.1".into(),
        target_port,
    }).await.unwrap();
    
    let local_port = client.forward_local_port(0).unwrap();
    
    // Connect through the forward
    let mut conn = TcpStream::connect(format!("127.0.0.1:{}", local_port))
        .await
        .unwrap();
    
    // Accept on target side
    let (mut target_conn, _) = target.accept().await.unwrap();
    
    // Data flows through
    conn.write_all(b"ping").await.unwrap();
    
    let mut buf = [0u8; 4];
    target_conn.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
}
```

### 7.4 Reconnection with State Preservation

```rust
// tests/reconnection_test.rs

#[tokio::test]
async fn state_preserved_across_reconnect() {
    let (mut client, mut server) = setup_connected_pair().await;
    
    // Draw something to terminal
    server.pty.inject_output(b"\x1b[31mRED TEXT\x1b[0m");
    server.process_pty().await;
    
    client.recv_and_apply_updates().await;
    let state_before = client.state().clone();
    
    // Force disconnect
    server.disconnect_client();
    
    // Wait for client to notice
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!client.is_connected());
    
    // Server accepts reconnection
    server.accept_reconnect().await;
    
    // Client reconnects
    client.reconnect().await.unwrap();
    assert!(client.is_connected());
    
    // State should match
    let state_after = client.state();
    assert_eq!(state_before.screen, state_after.screen);
}
```

### 7.5 Tunnel Setup and Traffic (Feature: `tunnel`, Linux only)

```rust
// tests/tunnel_test.rs

#![cfg(all(feature = "tunnel", target_os = "linux"))]

use qsh_test_utils::{MockTransport, FakeTun, TestKeys};

#[tokio::test]
async fn tunnel_config_exchange() {
    let (mut client, mut server) = setup_connected_pair().await;
    
    // Client requests tunnel
    let config = TunnelConfigPayload {
        client_ip: "10.99.0.2/24".parse().unwrap(),
        mtu: 1280,
        requested_routes: vec![],
        ipv6: false,
    };
    
    client.send_tunnel_config(config).await.unwrap();
    
    // Server receives and responds
    let received = server.recv_tunnel_config().await.unwrap();
    assert_eq!(received.client_ip, "10.99.0.2/24".parse().unwrap());
    
    let ack = TunnelConfigAckPayload {
        accepted: true,
        reject_reason: None,
        server_ip: "10.99.0.1/24".parse().unwrap(),
        mtu: 1280,
        routes: vec!["0.0.0.0/0".parse().unwrap()],
        dns_servers: vec!["10.99.0.1".parse().unwrap()],
    };
    
    server.send_tunnel_config_ack(ack).await.unwrap();
    
    // Client receives ack
    let received_ack = client.recv_tunnel_config_ack().await.unwrap();
    assert!(received_ack.accepted);
    assert_eq!(received_ack.routes.len(), 1);
}

#[tokio::test]
async fn tunnel_packet_flow() {
    let (mut client, mut server) = setup_tunnel_pair().await;
    
    // Simulate ICMP ping: client → server
    let ping_packet = craft_icmp_echo_request("10.99.0.2", "10.99.0.1");
    
    client.tun.inject_packet(ping_packet.clone());
    client.process_tun().await;
    
    // Server receives packet
    let received = server.recv_tunnel_packet().await.unwrap();
    assert_eq!(received.packet, ping_packet);
    
    // Server sends reply
    let pong_packet = craft_icmp_echo_reply("10.99.0.1", "10.99.0.2");
    server.send_tunnel_packet(pong_packet.clone()).await.unwrap();
    
    // Client receives reply
    let received = client.recv_tunnel_packet().await.unwrap();
    assert_eq!(received.packet, pong_packet);
}

#[tokio::test]
async fn tunnel_survives_reconnect() {
    let (mut client, mut server) = setup_tunnel_pair().await;
    
    // Verify tunnel is active
    assert!(matches!(client.tunnel_state(), TunnelState::Active { .. }));
    
    // Force disconnect
    server.disconnect_client();
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Tunnel should be suspended, not torn down
    assert!(matches!(client.tunnel_state(), TunnelState::Suspended));
    
    // Reconnect
    server.accept_reconnect().await;
    client.reconnect().await.unwrap();
    
    // Tunnel should resume without re-config
    assert!(matches!(client.tunnel_state(), TunnelState::Active { .. }));
    
    // Packets should flow again
    let test_packet = vec![0x45; 64];
    client.tun.inject_packet(test_packet.clone());
    client.process_tun().await;
    
    let received = server.recv_tunnel_packet().await.unwrap();
    assert_eq!(received.packet, test_packet);
}

#[tokio::test]
async fn tunnel_rejects_invalid_packets() {
    let (mut client, mut server) = setup_tunnel_pair().await;
    
    // Send packet with invalid IP version
    let bad_packet = TunnelPacketPayload { 
        packet: vec![0x50; 64] // Version 5 doesn't exist
    };
    
    let result = client.tunnel_handler.write_packet(&bad_packet).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn tunnel_respects_mtu() {
    let (mut client, _server) = setup_tunnel_pair().await;
    
    // Send packet exceeding MTU
    let oversized = TunnelPacketPayload { 
        packet: vec![0x45; 2000] // Exceeds 1280 MTU
    };
    
    let result = client.tunnel_handler.write_packet(&oversized).await;
    assert!(result.is_err());
}

// Helper to create minimal ICMP echo request
fn craft_icmp_echo_request(src: &str, dst: &str) -> Vec<u8> {
    // Minimal IPv4 + ICMP header (simplified for testing)
    let mut packet = vec![0u8; 28];
    packet[0] = 0x45; // IPv4, IHL=5
    // ... fill in IP header ...
    packet
}

fn craft_icmp_echo_reply(src: &str, dst: &str) -> Vec<u8> {
    let mut packet = craft_icmp_echo_request(src, dst);
    packet[20] = 0; // ICMP type 0 = echo reply
    packet
}
```

---

## 8. Property-Based Testing

Use `proptest` for fuzzing-style tests on parsers and state machines.

### 8.1 Protocol Fuzzing

```rust
// qsh-core/src/protocol/proptest.rs

use proptest::prelude::*;

prop_compose! {
    fn arb_terminal_input()(
        seq in 0u64..u64::MAX,
        data in prop::collection::vec(any::<u8>(), 0..4096),
        echo in any::<bool>(),
    ) -> Message {
        Message::TerminalInput(TerminalInputPayload {
            sequence: seq,
            data,
            echo_prediction: echo,
        })
    }
}

prop_compose! {
    fn arb_message()(variant in 0u8..10) -> Message {
        match variant {
            0 => Message::Ping(0),
            1 => Message::Pong(0),
            // ... generate other variants
            _ => Message::Ping(0),
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]
    
    #[test]
    fn codec_never_panics(data in prop::collection::vec(any::<u8>(), 0..10000)) {
        let mut buf = data.as_slice();
        // Should not panic, may return Ok(None) or Err
        let _ = Codec::decode(&mut buf);
    }
    
    #[test]
    fn codec_roundtrip(msg in arb_message()) {
        let encoded = Codec::encode(&msg).unwrap();
        let mut buf = encoded.as_ref();
        let decoded = Codec::decode(&mut buf).unwrap().unwrap();
        prop_assert_eq!(msg, decoded);
    }
}
```

### 8.2 Terminal Parser Fuzzing

```rust
// qsh-core/src/terminal/proptest.rs

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10000))]
    
    #[test]
    fn parser_never_panics(data in prop::collection::vec(any::<u8>(), 0..10000)) {
        let mut parser = TerminalParser::new(80, 24);
        // Should never panic regardless of input
        parser.process(&data);
        let _ = parser.snapshot();
    }
    
    #[test]
    fn parser_cursor_stays_in_bounds(
        data in prop::collection::vec(any::<u8>(), 0..1000),
        cols in 1u16..500,
        rows in 1u16..200,
    ) {
        let mut parser = TerminalParser::new(cols, rows);
        parser.process(&data);
        
        let state = parser.snapshot();
        prop_assert!(state.cursor.col < cols);
        prop_assert!(state.cursor.row < rows);
    }
}
```

### 8.3 State Diff Properties

```rust
proptest! {
    #[test]
    fn diff_apply_is_idempotent(
        initial in arb_terminal_state(),
        changes in prop::collection::vec(arb_cell_change(), 0..100),
    ) {
        let mut modified = initial.clone();
        for change in &changes {
            modified.apply_change(change);
        }
        
        let diff = initial.diff_to(&modified);
        let restored = initial.apply_diff(&diff).unwrap();
        
        prop_assert_eq!(restored, modified);
    }
    
    #[test]
    fn diff_composition(
        s1 in arb_terminal_state(),
        s2 in arb_terminal_state(),
        s3 in arb_terminal_state(),
    ) {
        // diff(s1, s3) should produce same result as 
        // applying diff(s1, s2) then diff(s2, s3)
        
        let direct = s1.diff_to(&s3);
        
        let step1 = s1.diff_to(&s2);
        let intermediate = s1.apply_diff(&step1).unwrap();
        let step2 = intermediate.diff_to(&s3);
        let composed = intermediate.apply_diff(&step2).unwrap();
        
        let direct_result = s1.apply_diff(&direct).unwrap();
        
        prop_assert_eq!(direct_result, composed);
    }
}
```

---

## 9. CI Pipeline

### 9.1 GitHub Actions Workflow

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [main]
  pull_request:

env:
  CARGO_TERM_COLOR: always
  RUST_BACKTRACE: 1

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy, rustfmt
      
      - name: Format check
        run: cargo fmt --all -- --check
      
      - name: Clippy (no features)
        run: cargo clippy --all-targets -- -D warnings
      
      - name: Clippy (all features)
        run: cargo clippy --all-targets --all-features -- -D warnings
      
      - name: Check (no features)
        run: cargo check
      
      - name: Check (all features)
        run: cargo check --all-features

  test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        features: ["", "tunnel"]
        exclude:
          # Tunnel only supported on Linux for now
          - os: macos-latest
            features: tunnel
          - os: windows-latest
            features: tunnel
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      
      - name: Unit tests (features: ${{ matrix.features || 'default' }})
        run: cargo test --lib ${{ matrix.features && format('--features {0}', matrix.features) || '' }}
      
      - name: Integration tests
        run: cargo test --test '*' ${{ matrix.features && format('--features {0}', matrix.features) || '' }}
      
      - name: Doc tests
        run: cargo test --doc

  # Tunnel tests requiring root (Linux only)
  tunnel-integration:
    runs-on: ubuntu-latest
    needs: test
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      
      - name: Build with tunnel feature
        run: cargo build --features tunnel
      
      - name: Tunnel integration tests (requires sudo)
        run: |
          # Grant CAP_NET_ADMIN to test binary
          sudo setcap cap_net_admin=eip target/debug/deps/tunnel_test-*
          cargo test --features tunnel --test tunnel_test -- --ignored
        continue-on-error: true  # Don't fail CI if tun tests fail

  e2e:
    runs-on: ubuntu-latest
    needs: test
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      
      - name: Build binaries
        run: cargo build --release
      
      - name: E2E tests
        run: cargo test --test e2e -- --ignored
        timeout-minutes: 10

  coverage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: taiki-e/install-action@cargo-llvm-cov
      
      - name: Generate coverage (without tunnel)
        run: cargo llvm-cov --lcov --output-path lcov.info
      
      - name: Generate coverage (with tunnel)
        run: cargo llvm-cov --features tunnel --lcov --output-path lcov-tunnel.info
      
      - name: Upload to Codecov
        uses: codecov/codecov-action@v4
        with:
          files: lcov.info,lcov-tunnel.info

  proptest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      
      - name: Property tests (extended)
        run: cargo test --all-features -- --ignored proptest
        env:
          PROPTEST_CASES: 100000
```

### 9.2 Pre-commit Hooks

```bash
#!/bin/bash
# .git/hooks/pre-commit

set -e

echo "Running pre-commit checks..."

# Format
cargo fmt --all -- --check

# Quick clippy
cargo clippy --all-targets -- -D warnings

# Fast tests only
cargo test --lib -- --skip slow --skip proptest

echo "Pre-commit checks passed!"
```

---

## 10. Development Workflow

### 10.1 TDD Cycle

```
┌─────────────────────────────────────────────────────────────┐
│                     TDD Development Cycle                    │
│                                                             │
│   ┌─────────┐     ┌─────────┐     ┌──────────┐             │
│   │  RED    │────►│  GREEN  │────►│ REFACTOR │─────┐       │
│   │  Write  │     │  Make   │     │  Clean   │     │       │
│   │  Test   │     │  Pass   │     │  Up      │     │       │
│   └─────────┘     └─────────┘     └──────────┘     │       │
│        ▲                                           │       │
│        └───────────────────────────────────────────┘       │
│                                                             │
│   Tips:                                                     │
│   • Keep tests focused (one behavior per test)             │
│   • Run tests frequently (cargo watch -x test)             │
│   • Refactor only when tests pass                          │
│   • Don't test private implementation                      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 10.2 Feature Development Template

When adding a new feature:

```rust
// 1. Start with the test (RED)
#[test]
fn new_feature_does_thing() {
    let mut system = SystemUnderTest::new();
    
    system.do_action();
    
    assert!(system.expected_outcome());
}

// 2. Implement minimum code to pass (GREEN)
impl SystemUnderTest {
    fn do_action(&mut self) {
        // Quick and dirty implementation
        self.state = true;
    }
    
    fn expected_outcome(&self) -> bool {
        self.state
    }
}

// 3. Add edge case tests
#[test]
fn new_feature_handles_edge_case() {
    let mut system = SystemUnderTest::new();
    system.setup_edge_condition();
    
    system.do_action();
    
    assert!(system.handles_edge_gracefully());
}

// 4. Refactor with confidence
impl SystemUnderTest {
    fn do_action(&mut self) {
        // Cleaner implementation
        // Tests will catch regressions
    }
}
```

### 10.3 Useful Commands

```bash
# Watch mode for rapid iteration
cargo watch -x "test --lib"

# Run specific test
cargo test terminal::tests::cursor_movement

# Run tests with output
cargo test -- --nocapture

# Run only fast tests (exclude proptest, e2e)
cargo test --lib -- --skip proptest --skip slow

# Run proptest with more cases
PROPTEST_CASES=10000 cargo test proptest

# Generate coverage report
cargo llvm-cov --html --open

# Run specific integration test
cargo test --test reconnection_test

# Run E2E tests
cargo test --test e2e -- --ignored

# Benchmark (if benchmarks exist)
cargo bench

# === Tunnel-specific commands (Linux only) ===

# Build with tunnel feature
cargo build --features tunnel

# Run tunnel unit tests
cargo test --features tunnel tunnel::

# Run tunnel integration tests (requires CAP_NET_ADMIN)
sudo -E cargo test --features tunnel --test tunnel_test -- --ignored

# Check compilation without tunnel (default)
cargo check

# Check compilation with tunnel
cargo check --features tunnel

# Clippy with tunnel feature
cargo clippy --features tunnel -- -D warnings
```

### 10.4 Test Naming Conventions

```rust
// Unit tests: describe behavior
#[test]
fn parser_handles_csi_cursor_up() { }

#[test]  
fn prediction_degrades_after_misprediction() { }

#[test]
fn codec_rejects_oversized_message() { }

// Integration tests: describe scenario
#[tokio::test]
async fn client_reconnects_after_network_drop() { }

#[tokio::test]
async fn local_forward_survives_reconnection() { }

// Property tests: describe invariant
#[test]
fn roundtrip_preserves_message() { }

#[test]
fn cursor_stays_in_bounds() { }
```

---

## Appendix A: Checklist per Module

Use this checklist when implementing each module:

```markdown
## Module: [name]

### Tests Written
- [ ] Happy path unit tests
- [ ] Error condition tests
- [ ] Edge case tests
- [ ] Property tests (if applicable)
- [ ] Integration test scenario

### Implementation
- [ ] Public API designed
- [ ] Types defined
- [ ] Core logic implemented
- [ ] Error handling complete

### Quality
- [ ] All tests pass
- [ ] No clippy warnings
- [ ] Documentation complete
- [ ] Code reviewed (self or peer)
```

---

## Appendix B: Quick Reference

### Assert Macros

```rust
use assert_matches::assert_matches;

assert_eq!(actual, expected);
assert_ne!(actual, unexpected);
assert!(condition);
assert_matches!(value, Pattern { .. });
assert!(result.is_ok());
assert!(result.is_err());
```

### Test Attributes

```rust
#[test]                           // Sync test
#[tokio::test]                    // Async test
#[test_case(1, 2, 3)]            // Parameterized
#[ignore = "reason"]             // Skip by default
#[should_panic(expected = "msg")] // Expect panic
```

### Common Patterns

```rust
// Setup/teardown with Drop
struct TestFixture { /* ... */ }
impl Drop for TestFixture {
    fn drop(&mut self) { /* cleanup */ }
}

// Timeout in async tests
#[tokio::test]
async fn test_with_timeout() {
    tokio::time::timeout(Duration::from_secs(5), async {
        // test code
    }).await.expect("test timed out");
}

// Test both Ok and Err paths
#[test]
fn handles_both_outcomes() {
    assert!(parse("valid").is_ok());
    assert!(parse("invalid").is_err());
}
```

---

*Document generated December 2025*
