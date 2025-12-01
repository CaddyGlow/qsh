# qsh — Implementation Specification

**Step-by-Step Guide for LLM-Assisted Development**

| Field | Value |
|-------|-------|
| Version | 1.0 |
| Status | Draft |
| Last Updated | December 2025 |

---

## How to Use This Document

This spec breaks qsh into **atomic tasks** that an LLM can execute sequentially or in parallel.

### Task Markers

| Marker | Meaning |
|--------|---------|
| `[A]`, `[B]`, `[C]` | **Parallel tracks** — tasks with same letter can run simultaneously |
| `[SEQ]` | **Sequential** — must complete before next task starts |
| `[SYNC]` | **Synchronization point** — all parallel tracks must complete before continuing |
| `[DEP: X.Y]` | **Dependency** — requires task X.Y to be complete |
| `[TEST]` | **Test task** — write tests, no implementation |
| `[IMPL]` | **Implementation task** — write production code |

### Task Format

Each task includes:
- **Input**: What the LLM receives (context, prior code)
- **Output**: What the LLM produces (files, functions)
- **Validation**: How to verify success (tests, compilation)
- **Prompt**: Ready-to-use prompt for the LLM

---

## Table of Contents

1. [Phase 0: Bootstrap](#phase-0-bootstrap)
2. [Phase 1: Core Terminal](#phase-1-core-terminal)
3. [Phase 2: Resilience](#phase-2-resilience)
4. [Phase 3: Port Forwarding](#phase-3-port-forwarding)
5. [Phase 4: Observability](#phase-4-observability)
6. [Phase 5: Polish](#phase-5-polish)
7. [Phase 6: Tunnel](#phase-6-tunnel)
8. [Appendix: Prompt Templates](#appendix-prompt-templates)

---

## Phase 0: Bootstrap

**Goal**: Set up the workspace structure and dependencies.

### Task 0.1 [SEQ] Create Workspace Structure

**Output**: Cargo workspace with 4 crates

```
qsh/
├── Cargo.toml
├── crates/
│   ├── qsh-core/
│   │   ├── Cargo.toml
│   │   └── src/lib.rs
│   ├── qsh-client/
│   │   ├── Cargo.toml
│   │   └── src/main.rs
│   ├── qsh-server/
│   │   ├── Cargo.toml
│   │   └── src/main.rs
│   └── qsh-test-utils/
│       ├── Cargo.toml
│       └── src/lib.rs
└── tests/
```

**Validation**: `cargo check` passes

**Prompt**:
```
Create a Rust workspace for a project called "qsh" with 4 crates:
- qsh-core: shared library (protocol, types, terminal state)
- qsh-client: binary
- qsh-server: binary  
- qsh-test-utils: test utilities library

Use Rust 2024 edition. Set up workspace dependencies for:
- tokio = { version = "1.40", features = ["full"] }
- quinn = "0.11"
- rustls = "0.23"
- russh = "0.45"
- portable-pty = "0.8"
- vte = "0.13"
- tracing = "0.1"
- tracing-subscriber = "0.3"
- clap = { version = "4.5", features = ["derive"] }
- bincode = "1.3"
- serde = { version = "1.0", features = ["derive"] }
- thiserror = "2.0"
- bytes = "1.7"

Test deps: tokio-test, proptest, test-case, assert_matches

Output only the Cargo.toml files and minimal lib.rs/main.rs stubs.
```

---

### Task 0.2 [SEQ] Create Error Types

**Input**: Workspace from 0.1
**Output**: `qsh-core/src/error.rs`

**Validation**: `cargo check -p qsh-core`

**Prompt**:
```
Create error types for qsh-core using thiserror.

Define an Error enum with variants:
- Io(#[from] std::io::Error)
- Protocol { message: String }
- Codec { message: String }
- SessionNotFound(u64)
- SessionExpired
- AuthenticationFailed
- ConnectionClosed
- InvalidState { expected: String, actual: String }
- Timeout
- Pty(#[from] std::io::Error) — use #[error(transparent)]

Also define: pub type Result<T> = std::result::Result<T, Error>;

Use Rust 2024 idioms. Export from lib.rs.
```

---

### Task 0.3 [SEQ] Create Constants Module

**Input**: Workspace from 0.1
**Output**: `qsh-core/src/constants.rs`

**Prompt**:
```
Create constants module for qsh-core with:

// Protocol
pub const PROTOCOL_VERSION: u8 = 1;
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024; // 16 MiB
pub const MAX_TERMINAL_SIZE: (u16, u16) = (500, 200);

// Timing
pub const PING_INTERVAL: Duration = Duration::from_secs(5);
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(86400);
pub const RECONNECT_TIMEOUT: Duration = Duration::from_secs(30);

// Prediction
pub const PREDICTION_CONFIDENCE_THRESHOLD: u8 = 3;
pub const MAX_PENDING_PREDICTIONS: usize = 1000;

// Forwarding
pub const MAX_FORWARDS_PER_SESSION: usize = 100;
pub const FORWARD_BUFFER_SIZE: usize = 64 * 1024;

// Bootstrap
pub const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEFAULT_QUIC_PORT_RANGE: (u16, u16) = (4500, 4600);

Export from lib.rs.
```

---

## Phase 1: Core Terminal

**Goal**: Basic terminal session over QUIC.

### Parallel Track Overview

```
Track A: Protocol Layer (codec, messages)
Track B: Terminal Layer (state, parser)
Track C: Transport Layer (QUIC abstraction)

     0.1-0.3 (Bootstrap)
          │
    ┌─────┼─────┐
    ▼     ▼     ▼
   [A]   [B]   [C]
    │     │     │
    └─────┴─────┘
          │
       [SYNC] 1.10
          │
    ┌─────┼─────┐
    ▼     ▼     ▼
   [D]   [E]   [F]
  SSH   PTY  Session
    │     │     │
    └─────┴─────┘
          │
       [SYNC] 1.20
          │
       Integration
```

---

### Track A: Protocol Layer

#### Task 1.1 [A] [TEST] Protocol Message Types — Tests First

**Output**: `qsh-core/src/protocol/tests.rs`

**Prompt**:
```
Write tests for qsh protocol message types. Do NOT write implementation yet.

Test cases needed:

1. Message enum should have variants:
   - Hello(HelloPayload)
   - HelloAck(HelloAckPayload)
   - Resize(ResizePayload)
   - Ping(u64)
   - Pong(u64)
   - Shutdown(ShutdownPayload)
   - TerminalInput(TerminalInputPayload)
   - StateUpdate(StateUpdatePayload)
   - StateAck(StateAckPayload)
   - ForwardRequest(ForwardRequestPayload)
   - ForwardAccept(ForwardAcceptPayload)
   - ForwardReject(ForwardRejectPayload)
   - ForwardData(ForwardDataPayload)
   - ForwardEof(ForwardEofPayload)
   - ForwardClose(ForwardClosePayload)
   - TunnelConfig(TunnelConfigPayload)
   - TunnelConfigAck(TunnelConfigAckPayload)
   - TunnelPacket(TunnelPacketPayload)

2. Capabilities struct with fields:
   - predictive_echo: bool
   - compression: bool
   - max_forwards: u16
   - tunnel: bool

3. All types derive: Debug, Clone, PartialEq, Serialize, Deserialize

Write tests that will compile once types exist:
- test_message_variants_exist()
- test_capabilities_defaults()
- test_message_is_send_sync()

Use #[cfg(test)] module.
```

---

#### Task 1.2 [A] [IMPL] Protocol Message Types

**Input**: Tests from 1.1
**Output**: `qsh-core/src/protocol/types.rs`
**Validation**: Tests from 1.1 pass

**Prompt**:
```
Implement protocol message types for qsh to make these tests pass:
[paste tests from 1.1]

Requirements:
- Use serde with derive macros
- All types must be Send + Sync
- Use Rust 2024 idioms
- StateDiff and TerminalState can be placeholder types for now:
  
  #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
  pub struct TerminalState {
      pub generation: u64,
      // Will be filled in Track B
  }
  
  #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
  pub enum StateDiff {
      Full(TerminalState),
      // Will be filled in Track B
  }

Export via mod.rs.
```

---

#### Task 1.3 [A] [TEST] Codec — Tests First

**DEP**: 1.2
**Output**: `qsh-core/src/protocol/codec_tests.rs`

**Prompt**:
```
Write tests for the qsh wire protocol codec. Do NOT implement yet.

Wire format: 4-byte little-endian length prefix + bincode-encoded Message

Test cases:
1. encode_decode_roundtrip — any Message encodes then decodes to equal value
2. decode_partial_returns_none — incomplete data returns Ok(None)
3. decode_empty_returns_none
4. decode_length_too_large_returns_error — length > MAX_MESSAGE_SIZE
5. decode_invalid_bincode_returns_error
6. encode_creates_length_prefix — first 4 bytes are LE length
7. multiple_messages_in_buffer — decode consumes exactly one message

Codec interface:
```rust
pub struct Codec;

impl Codec {
    pub fn encode(msg: &Message) -> Result<Bytes>;
    pub fn decode(buf: &mut BytesMut) -> Result<Option<Message>>;
}
```

Use bytes crate (Bytes, BytesMut).
```

---

#### Task 1.4 [A] [IMPL] Codec

**DEP**: 1.3
**Output**: `qsh-core/src/protocol/codec.rs`
**Validation**: Tests from 1.3 pass

**Prompt**:
```
Implement the qsh protocol codec to pass these tests:
[paste tests from 1.3]

Implementation notes:
- Use bincode for serialization
- Length prefix is 4 bytes, little-endian
- Check length against MAX_MESSAGE_SIZE before allocating
- decode() should advance the buffer only on success
- Return Ok(None) if buffer has incomplete message
- Return Err on invalid data

Use bytes::{Bytes, BytesMut, Buf, BufMut}.
```

---

#### Task 1.5 [A] [TEST] Codec Property Tests

**DEP**: 1.4
**Output**: `qsh-core/src/protocol/proptest.rs`

**Prompt**:
```
Write proptest property-based tests for the qsh codec.

Properties to test:
1. Any valid Message roundtrips through encode/decode
2. Codec never panics on arbitrary byte input
3. Encoded length prefix matches actual payload length
4. Partial buffers always return Ok(None), never panic

Generate arbitrary Messages using prop_compose!:
- arb_message() — generates random Message variants
- arb_capabilities() — random Capabilities
- arb_terminal_input() — random TerminalInput

Use proptest config with 1000 cases for unit tests.
Mark extended tests (10000+ cases) with #[ignore].
```

---

### Track B: Terminal Layer

#### Task 1.6 [B] [TEST] Terminal State — Tests First

**Output**: `qsh-core/src/terminal/tests.rs`

**Prompt**:
```
Write tests for terminal state types. Do NOT implement yet.

Types needed:

```rust
pub struct Cell {
    pub char: char,
    pub fg: Color,
    pub bg: Color,
    pub attrs: CellAttrs,
}

pub struct CellAttrs {
    pub bold: bool,
    pub italic: bool,
    pub underline: bool,
    pub strikethrough: bool,
    pub dim: bool,
    pub blink: bool,
    pub reverse: bool,
    pub hidden: bool,
}

pub enum Color {
    Default,
    Indexed(u8),
    Rgb(u8, u8, u8),
}

pub struct Cursor {
    pub col: u16,
    pub row: u16,
    pub visible: bool,
    pub shape: CursorShape,
}

pub struct Screen {
    cells: Vec<Cell>,
    cols: u16,
    rows: u16,
}

pub struct TerminalState {
    pub generation: u64,
    pub primary: Screen,
    pub alternate: Screen,
    pub cursor: Cursor,
    pub alternate_active: bool,
    pub title: Option<String>,
}
```

Test cases:
1. Screen::new creates correct size with default cells
2. Screen::get/set cell by position
3. Screen::resize preserves content where possible
4. Cell::default is space with default colors
5. TerminalState::new creates primary/alternate screens
6. TerminalState clone is deep copy
```

---

#### Task 1.7 [B] [IMPL] Terminal State Types

**DEP**: 1.6
**Output**: `qsh-core/src/terminal/state.rs`
**Validation**: Tests from 1.6 pass

**Prompt**:
```
Implement terminal state types to pass these tests:
[paste tests from 1.6]

Requirements:
- All types derive: Debug, Clone, PartialEq, Serialize, Deserialize
- Screen should use flat Vec<Cell> with row-major indexing
- Implement Display for Color (output ANSI codes)
- Cell::default() returns space with Color::Default
- Screen::resize should:
  - Preserve existing content in overlap region
  - Fill new cells with defaults
  - Handle both grow and shrink
```

---

#### Task 1.8 [B] [TEST] Terminal Parser — Tests First

**DEP**: 1.7
**Output**: `qsh-core/src/terminal/parser_tests.rs`

**Prompt**:
```
Write tests for VTE-based terminal parser. Do NOT implement yet.

Parser wraps vte crate and updates TerminalState.

Test cases:
1. print_ascii — "ABC" moves cursor, sets cells
2. print_unicode — emoji "🎉" uses 2 cells (wide char)
3. newline — \n moves cursor down, scrolls if at bottom
4. carriage_return — \r moves cursor to column 0
5. backspace — \x08 moves cursor left (doesn't delete)
6. tab — \t moves to next tab stop (every 8 cols)
7. csi_cursor_up — \x1b[A moves up
8. csi_cursor_down — \x1b[B moves down
9. csi_cursor_forward — \x1b[C moves right
10. csi_cursor_back — \x1b[D moves left
11. csi_cursor_position — \x1b[H, \x1b[5;10H
12. csi_erase_display — \x1b[J, \x1b[2J
13. csi_erase_line — \x1b[K
14. sgr_reset — \x1b[0m
15. sgr_bold — \x1b[1m
16. sgr_fg_color — \x1b[31m (red)
17. sgr_bg_color — \x1b[44m (blue bg)
18. sgr_256_color — \x1b[38;5;196m
19. sgr_rgb_color — \x1b[38;2;255;128;0m
20. alternate_screen_on — \x1b[?1049h
21. alternate_screen_off — \x1b[?1049l
22. set_title — \x1b]0;Title\x07

Interface:
```rust
pub struct TerminalParser {
    state: TerminalState,
    parser: vte::Parser,
}

impl TerminalParser {
    pub fn new(cols: u16, rows: u16) -> Self;
    pub fn process(&mut self, data: &[u8]);
    pub fn state(&self) -> &TerminalState;
    pub fn take_state(&mut self) -> TerminalState;
    pub fn resize(&mut self, cols: u16, rows: u16);
}
```
```

---

#### Task 1.9 [B] [IMPL] Terminal Parser

**DEP**: 1.8
**Output**: `qsh-core/src/terminal/parser.rs`
**Validation**: Tests from 1.8 pass

**Prompt**:
```
Implement VTE-based terminal parser to pass these tests:
[paste tests from 1.8]

Implementation notes:
- Use vte crate's Parser and implement Perform trait
- Handle wide characters (emoji, CJK) with unicode_width crate
- Increment generation on each process() call
- SGR (Select Graphic Rendition) params:
  - 0: reset
  - 1: bold, 3: italic, 4: underline, 7: reverse, 9: strikethrough
  - 30-37: fg color, 40-47: bg color
  - 38;5;N: 256-color fg, 48;5;N: 256-color bg
  - 38;2;R;G;B: RGB fg, 48;2;R;G;B: RGB bg
- CSI sequences: A/B/C/D cursor, H cup, J/K erase, m sgr
- Private modes: ?1049h/l alternate screen
- OSC: title setting

Add unicode-width = "0.1" to dependencies.
```

---

### Track C: Transport Layer

#### Task 1.10 [C] [TEST] Transport Traits — Tests First

**Output**: `qsh-core/src/transport/tests.rs`

**Prompt**:
```
Write tests for transport abstraction traits. Do NOT implement yet.

Traits needed:
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamType {
    Control,      // Stream 0
    TerminalOut,  // Stream 2  
    TerminalIn,   // Client-initiated
    Tunnel,       // Stream 4
    Forward(u32), // Dynamic
}

pub trait StreamPair: Send + Sync {
    async fn send(&mut self, msg: &Message) -> Result<()>;
    async fn recv(&mut self) -> Result<Message>;
    fn close(&mut self);
}

pub trait Connection: Send + Sync {
    type Stream: StreamPair;
    
    async fn open_stream(&self, stream_type: StreamType) -> Result<Self::Stream>;
    async fn accept_stream(&self) -> Result<(StreamType, Self::Stream)>;
    fn remote_addr(&self) -> SocketAddr;
    fn local_addr(&self) -> SocketAddr;
    fn is_connected(&self) -> bool;
    fn rtt(&self) -> Duration;
}
```

Test cases (will use mock implementations):
1. StreamType equality and hashing
2. StreamType::Forward id encoding
3. Trait bounds are correct (Send + Sync + async fn)
```

---

#### Task 1.11 [C] [IMPL] Transport Traits

**DEP**: 1.10
**Output**: `qsh-core/src/transport/mod.rs`
**Validation**: Tests from 1.10 pass, compiles

**Prompt**:
```
Implement transport trait definitions to pass tests:
[paste tests from 1.10]

Just the trait definitions and StreamType enum.
Real implementations (Quinn, Mock) come later.

Export from lib.rs.
```

---

### [SYNC] Integration Point 1.12

**All of Track A, B, C must complete before continuing.**

At this point you should have:
- Protocol types and codec (A)
- Terminal state and parser (B)
- Transport traits (C)

**Validation**: `cargo test -p qsh-core` — all tests pass

---

### Track D: SSH Bootstrap (Client)

#### Task 1.13 [D] [TEST] Bootstrap Protocol — Tests First

**DEP**: 1.12
**Output**: `qsh-client/src/bootstrap/tests.rs`

**Prompt**:
```
Write tests for SSH bootstrap protocol. Do NOT implement yet.

Bootstrap flow:
1. Client connects via SSH to server
2. Client executes: qsh-server --bootstrap
3. Server responds with JSON on stdout:
   {
     "quic_port": 4500,
     "session_key": "base64...", // 32 bytes
     "cert_der": "base64...",    // Self-signed cert
     "server_id": "uuid"
   }
4. Client parses response, connects to QUIC

Types:
```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct BootstrapResponse {
    pub quic_port: u16,
    pub session_key: String, // base64
    pub cert_der: String,    // base64
    pub server_id: String,
}

impl BootstrapResponse {
    pub fn session_key_bytes(&self) -> Result<[u8; 32]>;
    pub fn cert_der_bytes(&self) -> Result<Vec<u8>>;
}
```

Test cases:
1. parse_valid_response — valid JSON parses correctly
2. parse_invalid_json — returns error
3. session_key_wrong_length — base64 decodes but not 32 bytes
4. session_key_invalid_base64 — returns error
5. cert_der_valid — decodes correctly
```

---

#### Task 1.14 [D] [IMPL] Bootstrap Response Parsing

**DEP**: 1.13
**Output**: `qsh-client/src/bootstrap/response.rs`
**Validation**: Tests from 1.13 pass

**Prompt**:
```
Implement bootstrap response parsing to pass tests:
[paste tests from 1.13]

Use base64 crate for decoding.
Add base64 = "0.22" to qsh-client dependencies.
```

---

#### Task 1.15 [D] [IMPL] SSH Bootstrap Client

**DEP**: 1.14
**Output**: `qsh-client/src/bootstrap/mod.rs`

**Prompt**:
```
Implement SSH bootstrap client using russh.

```rust
pub struct BootstrapClient {
    config: Arc<russh::client::Config>,
}

impl BootstrapClient {
    pub fn new() -> Self;
    
    pub async fn connect(
        &self,
        host: &str,
        port: u16,
        username: &str,
        auth: AuthMethod,
    ) -> Result<BootstrapSession>;
}

pub enum AuthMethod {
    PublicKey { key_path: PathBuf },
    Password { password: String },
    Agent,
}

pub struct BootstrapSession {
    session: russh::client::Handle<Client>,
}

impl BootstrapSession {
    pub async fn bootstrap(&mut self) -> Result<BootstrapResponse>;
}
```

The bootstrap() method should:
1. Open a channel
2. Execute "qsh-server --bootstrap"
3. Read stdout until EOF
4. Parse JSON response
5. Return BootstrapResponse

Handle russh Client trait with minimal implementation.
```

---

### Track E: PTY Management (Server)

#### Task 1.16 [E] [TEST] PTY Trait — Tests First

**DEP**: 1.12
**Output**: `qsh-server/src/pty/tests.rs`

**Prompt**:
```
Write tests for PTY abstraction. Do NOT implement yet.

```rust
pub trait PtyHandle: Send {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    fn write(&mut self, buf: &[u8]) -> io::Result<usize>;
    fn resize(&mut self, cols: u16, rows: u16) -> io::Result<()>;
    fn get_size(&self) -> io::Result<(u16, u16)>;
}

pub struct PtyProcess {
    // Wraps portable-pty
}

impl PtyProcess {
    pub fn spawn(shell: &str, cols: u16, rows: u16) -> io::Result<Self>;
    pub fn handle(&self) -> impl PtyHandle;
    pub fn wait(&mut self) -> io::Result<ExitStatus>;
    pub fn kill(&mut self) -> io::Result<()>;
}
```

Test cases (with real PTY, mark #[ignore] for CI):
1. spawn_shell — spawns /bin/sh
2. write_read — write command, read output
3. resize — changes terminal size
4. get_size — returns correct dimensions
```

---

#### Task 1.17 [E] [IMPL] PTY Wrapper

**DEP**: 1.16
**Output**: `qsh-server/src/pty/mod.rs`
**Validation**: Tests from 1.16 pass

**Prompt**:
```
Implement PTY wrapper using portable-pty to pass tests:
[paste tests from 1.16]

Use portable_pty crate.
Handle both Unix and Windows (PtySize, CommandBuilder).
```

---

### Track F: Session Management

#### Task 1.18 [F] [TEST] Session State — Tests First

**DEP**: 1.12
**Output**: `qsh-core/src/session/tests.rs`

**Prompt**:
```
Write tests for session state management. Do NOT implement yet.

```rust
pub struct SessionId(pub u64);

pub struct SessionState {
    pub id: SessionId,
    pub created_at: Instant,
    pub last_activity: Instant,
    pub terminal_state: TerminalState,
    pub input_sequence: u64,
    pub confirmed_sequence: u64,
    pub forwards: Vec<ForwardSpec>,
}

impl SessionState {
    pub fn new(id: SessionId, cols: u16, rows: u16) -> Self;
    pub fn update_activity(&mut self);
    pub fn is_expired(&self, timeout: Duration) -> bool;
    pub fn next_input_sequence(&mut self) -> u64;
    pub fn confirm_sequence(&mut self, seq: u64);
}
```

Test cases:
1. new_session_has_zero_sequences
2. next_input_sequence_increments
3. confirm_sequence_updates
4. is_expired_after_timeout
5. is_not_expired_before_timeout
6. update_activity_resets_expiry
```

---

#### Task 1.19 [F] [IMPL] Session State

**DEP**: 1.18
**Output**: `qsh-core/src/session/mod.rs`
**Validation**: Tests from 1.18 pass

**Prompt**:
```
Implement session state to pass tests:
[paste tests from 1.18]
```

---

### [SYNC] Integration Point 1.20

**Tracks D, E, F must complete.**

Now we have:
- SSH bootstrap client (D)
- PTY management (E)  
- Session state (F)

---

### Task 1.21 [SEQ] Mock Transport

**DEP**: 1.20
**Output**: `qsh-test-utils/src/mock_transport.rs`

**Prompt**:
```
Implement MockTransport for testing without real QUIC.

```rust
use tokio::sync::mpsc;

pub struct MockTransport {
    tx: mpsc::Sender<Message>,
    rx: mpsc::Receiver<Message>,
    metrics: Arc<Mutex<MockMetrics>>,
}

#[derive(Default)]
pub struct MockMetrics {
    pub messages_sent: usize,
    pub messages_recv: usize,
    pub bytes_sent: usize,
    pub bytes_recv: usize,
}

impl MockTransport {
    /// Create connected pair
    pub fn pair() -> (Self, Self);
    
    /// Create pair with artificial latency
    pub fn pair_with_latency(latency: Duration) -> (Self, Self);
    
    pub fn metrics(&self) -> MockMetrics;
}

impl StreamPair for MockTransport {
    async fn send(&mut self, msg: &Message) -> Result<()>;
    async fn recv(&mut self) -> Result<Message>;
    fn close(&mut self);
}
```

Use tokio channels. Track metrics on send/recv.
For latency simulation, use tokio::time::sleep.
```

---

### Task 1.22 [SEQ] Fake PTY

**DEP**: 1.20
**Output**: `qsh-test-utils/src/fake_pty.rs`

**Prompt**:
```
Implement FakePty for testing without real terminal.

```rust
pub struct FakePty {
    output_buffer: VecDeque<u8>,
    input_buffer: Vec<u8>,
    size: (u16, u16),
    closed: bool,
}

impl FakePty {
    pub fn new(cols: u16, rows: u16) -> Self;
    
    /// Inject data as if PTY produced it
    pub fn inject_output(&mut self, data: &[u8]);
    
    /// Get data written to PTY
    pub fn take_input(&mut self) -> Vec<u8>;
    
    /// Check if closed
    pub fn is_closed(&self) -> bool;
}

impl PtyHandle for FakePty {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    fn write(&mut self, buf: &[u8]) -> io::Result<usize>;
    fn resize(&mut self, cols: u16, rows: u16) -> io::Result<()>;
    fn get_size(&self) -> io::Result<(u16, u16)>;
}
```

read() returns from output_buffer, write() appends to input_buffer.
Return WouldBlock if output_buffer empty.
```

---

### Task 1.23 [SEQ] QUIC Connection (Quinn)

**DEP**: 1.21
**Output**: `qsh-core/src/transport/quinn.rs`

**Prompt**:
```
Implement real QUIC transport using Quinn.

```rust
pub struct QuicConnection {
    connection: quinn::Connection,
}

impl QuicConnection {
    pub fn new(connection: quinn::Connection) -> Self;
}

impl Connection for QuicConnection {
    type Stream = QuicStream;
    
    async fn open_stream(&self, stream_type: StreamType) -> Result<Self::Stream>;
    async fn accept_stream(&self) -> Result<(StreamType, Self::Stream)>;
    fn remote_addr(&self) -> SocketAddr;
    fn local_addr(&self) -> SocketAddr;
    fn is_connected(&self) -> bool;
    fn rtt(&self) -> Duration;
}

pub struct QuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    codec: Codec,
    read_buf: BytesMut,
}

impl StreamPair for QuicStream {
    async fn send(&mut self, msg: &Message) -> Result<()>;
    async fn recv(&mut self) -> Result<Message>;
    fn close(&mut self);
}
```

For stream type mapping (QUIC semantics: bit0 initiator, bit1 uni/bidi):
- Control: client-initiated bidirectional stream 0
- TerminalOut: server-initiated unidirectional stream (first is 3)
- TerminalIn: client-initiated unidirectional stream (first is 2)
- Forward(id): bidirectional streams per connection (server bidi IDs 1/5/9..., client bidi IDs 8/12/...; tunnel reserves client bidi stream 4)
- Tunnel: client-initiated bidirectional stream 4 (reserved)

Use codec from protocol module.
```

---

### Task 1.24 [SEQ] Server Bootstrap Mode

**DEP**: 1.23
**Output**: `qsh-server/src/bootstrap.rs`

**Prompt**:
```
Implement server bootstrap mode.

When run with --bootstrap flag:
1. Generate random session key (32 bytes)
2. Generate self-signed certificate
3. Pick available port in range
4. Start QUIC listener
5. Print JSON response to stdout
6. Wait for single client connection
7. Transition to session mode

```rust
pub struct BootstrapServer {
    session_key: [u8; 32],
    cert: rcgen::CertifiedKey,
    quic_port: u16,
}

impl BootstrapServer {
    pub fn new(port_range: (u16, u16)) -> Result<Self>;
    pub fn response_json(&self) -> String;
    pub async fn accept(&self) -> Result<quinn::Connection>;
}
```

Use rcgen for certificate generation.
Use rand for session key.
Add rcgen = "0.13" and rand = "0.8" to dependencies.
```

---

### Task 1.25 [SEQ] Integration: Basic Session

**DEP**: 1.24
**Output**: `tests/basic_session_test.rs`

**Prompt**:
```
Write integration test for basic terminal session.

Test flow:
1. Create FakePty
2. Create MockTransport pair
3. Spawn server task with FakePty + server transport
4. Client sends Hello
5. Server responds with HelloAck containing initial state
6. Client sends TerminalInput "echo hello\n"
7. FakePty receives input
8. FakePty injects output "hello\n"
9. Server processes PTY output
10. Server sends StateUpdate to client
11. Client verifies terminal state contains "hello"

Use tokio::spawn for concurrent tasks.
Use tokio::time::timeout to prevent hanging.

This test validates the core data flow works end-to-end
with mocked transport and PTY.
```

---

## Phase 2: Resilience

**Goal**: Connection migration, 0-RTT reconnection, predictive echo.

### Task 2.1 [A] [TEST] Prediction Engine — Tests First

**Output**: `qsh-client/src/prediction/tests.rs`

**Prompt**:
```
Write tests for predictive local echo engine.

```rust
pub enum PredictionState {
    Confident,
    Tentative,
    Disabled,
}

pub struct PredictionEngine {
    state: PredictionState,
    pending: VecDeque<Prediction>,
    misprediction_count: u8,
}

pub struct Prediction {
    pub sequence: u64,
    pub char: char,
    pub col: u16,
    pub row: u16,
}

impl PredictionEngine {
    pub fn new() -> Self;
    
    /// Should we predict this character?
    pub fn should_predict(&self, c: char) -> bool;
    
    /// Add a prediction
    pub fn predict(&mut self, seq: u64, c: char, col: u16, row: u16);
    
    /// Confirm predictions up to sequence
    pub fn confirm(&mut self, seq: u64);
    
    /// Handle misprediction
    pub fn misprediction(&mut self);
    
    /// Get pending predictions for display
    pub fn pending(&self) -> &VecDeque<Prediction>;
    
    /// Current state
    pub fn state(&self) -> PredictionState;
}
```

Test cases:
1. initial_state_is_confident
2. should_predict_printable_in_confident
3. should_predict_alphanumeric_only_in_tentative
4. should_not_predict_in_disabled
5. predict_adds_to_pending
6. confirm_removes_from_pending
7. misprediction_degrades_state
8. three_mispredictions_disables
9. disabled_stays_disabled
```

---

#### Task 2.2 [A] [IMPL] Prediction Engine

**DEP**: 2.1
**Output**: `qsh-client/src/prediction/mod.rs`
**Validation**: Tests from 2.1 pass

---

### Task 2.3 [B] [TEST] State Diff — Tests First

**Output**: `qsh-core/src/terminal/diff_tests.rs`

**Prompt**:
```
Write tests for terminal state diffing.

```rust
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

pub struct CellChange {
    pub col: u16,
    pub row: u16,
    pub cell: Cell,
}

impl TerminalState {
    pub fn diff_to(&self, other: &Self) -> StateDiff;
    pub fn apply_diff(&self, diff: &StateDiff) -> Result<Self>;
}
```

Test cases:
1. diff_identical_states_returns_cursor_only
2. diff_cursor_only_change
3. diff_single_cell_change
4. diff_multiple_cell_changes
5. diff_large_change_returns_full
6. apply_incremental_diff
7. apply_full_diff
8. apply_cursor_only_diff
9. diff_apply_roundtrip
```

---

#### Task 2.4 [B] [IMPL] State Diff

**DEP**: 2.3
**Output**: `qsh-core/src/terminal/diff.rs`
**Validation**: Tests from 2.3 pass

---

### Task 2.5 [C] [TEST] Reconnection — Tests First

**Output**: `qsh-core/src/session/reconnect_tests.rs`

**Prompt**:
```
Write tests for reconnection handling.

Test scenarios:
1. reconnect_with_0rtt — client has session ticket, reconnects quickly
2. reconnect_with_1rtt — no ticket, full handshake
3. reconnect_state_sync — server sends full state on reconnect
4. reconnect_sequence_gap — handle input sequence discontinuity
5. reconnect_timeout — session expired, reject reconnect
```

---

#### Task 2.6 [C] [IMPL] Reconnection Handler

**DEP**: 2.5
**Output**: `qsh-core/src/session/reconnect.rs`
**Validation**: Tests from 2.5 pass

---

### Task 2.7 [SEQ] Client Overlay Display

**DEP**: 2.2
**Output**: `qsh-client/src/overlay.rs`

**Prompt**:
```
Implement prediction overlay display.

Predictions shown with underline style in terminal.
On confirmation, remove underline.
On misprediction, clear and show authoritative state.

```rust
pub struct OverlayRenderer {
    predictions: Vec<PredictionDisplay>,
}

pub struct PredictionDisplay {
    pub col: u16,
    pub row: u16,
    pub char: char,
}

impl OverlayRenderer {
    pub fn new() -> Self;
    pub fn add_prediction(&mut self, p: &Prediction);
    pub fn clear_confirmed(&mut self, up_to_seq: u64);
    pub fn clear_all(&mut self);
    pub fn render(&self) -> String; // ANSI escape sequences
}
```
```

---

### [SYNC] Phase 2 Complete

**Validation**:
- `cargo test -p qsh-client`
- `cargo test -p qsh-core`
- Integration test: reconnect_preserves_state

---

## Phase 3: Port Forwarding

### Task 3.1 [A] [TEST] Forward Spec Parsing

**Output**: `qsh-core/src/forward/tests.rs`

**Prompt**:
```
Write tests for port forward specification parsing.

```rust
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
    pub fn parse_local(s: &str) -> Result<Self>;   // -L
    pub fn parse_remote(s: &str) -> Result<Self>;  // -R
    pub fn parse_dynamic(s: &str) -> Result<Self>; // -D
}
```

Formats:
- Local/Remote: [bind_addr:]port:host:hostport
- Dynamic: [bind_addr:]port

Test cases:
1. parse_local_full — "127.0.0.1:5432:db.internal:5432"
2. parse_local_short — "5432:db.internal:5432" (defaults localhost)
3. parse_remote_full
4. parse_dynamic — "1080"
5. parse_dynamic_with_bind — "0.0.0.0:1080"
6. parse_invalid_format
7. parse_invalid_port
```

---

#### Task 3.2 [A] [IMPL] Forward Spec

**DEP**: 3.1
**Output**: `qsh-core/src/forward/spec.rs`

---

### Task 3.3 [B] [IMPL] Local Forward Handler

**DEP**: 3.2
**Output**: `qsh-client/src/forward/local.rs`

**Prompt**:
```
Implement local port forwarding (-L).

Flow:
1. Client binds local port
2. Accept local connection
3. Send ForwardRequest to server
4. Server connects to target
5. Server sends ForwardAccept or ForwardReject
6. Bidirectional data relay

```rust
pub struct LocalForwarder {
    spec: ForwardSpec,
    listener: TcpListener,
    connection: Arc<dyn Connection>,
}

impl LocalForwarder {
    pub async fn new(spec: ForwardSpec, conn: Arc<dyn Connection>) -> Result<Self>;
    pub async fn run(&mut self) -> Result<()>;
}
```
```

---

### Task 3.4 [B] [IMPL] Remote Forward Handler

**DEP**: 3.2
**Output**: `qsh-server/src/forward/remote.rs`

---

### Task 3.5 [C] [IMPL] SOCKS5 Proxy

**DEP**: 3.2
**Output**: `qsh-client/src/forward/socks.rs`

**Prompt**:
```
Implement SOCKS5 dynamic forwarding (-D).

SOCKS5 handshake:
1. Client sends greeting (version, auth methods)
2. Server selects method (0x00 = no auth)
3. Client sends request (cmd, address)
4. Server responds with status

Support:
- CONNECT command only
- IPv4, IPv6, domain name addresses
- No authentication

```rust
pub struct Socks5Proxy {
    listener: TcpListener,
    connection: Arc<dyn Connection>,
}

impl Socks5Proxy {
    pub async fn new(bind_addr: SocketAddr, conn: Arc<dyn Connection>) -> Result<Self>;
    pub async fn run(&mut self) -> Result<()>;
}
```
```

---

### [SYNC] Phase 3 Complete

**Validation**: `cargo test --test forwarding_test`

---

## Phase 4: Observability

### Task 4.1 [A] [IMPL] Status Overlay Widget

**Output**: `qsh-client/src/overlay/widget.rs`

**Prompt**:
```
Implement status overlay widget.

Display (when visible):
┌─────────────────────────────────────┐
│ qsh │ user@host │ RTT: 45ms │ ✓    │
└─────────────────────────────────────┘

States: ✓ connected, ↻ reconnecting, ⚠ degraded

```rust
pub struct StatusOverlay {
    visible: bool,
    position: OverlayPosition,
    metrics: ConnectionMetrics,
}

pub enum OverlayPosition {
    Top,
    Bottom,
    TopRight,
}

impl StatusOverlay {
    pub fn render(&self, cols: u16) -> Vec<String>;
    pub fn toggle(&mut self);
    pub fn update_metrics(&mut self, metrics: ConnectionMetrics);
}
```
```

---

### Task 4.2 [B] [IMPL] Tracing Integration

**Output**: `qsh-core/src/logging.rs`

**Prompt**:
```
Set up tracing with structured logging.

```rust
pub fn init_logging(verbosity: u8, log_file: Option<&Path>, json: bool) -> Result<()>;
```

Verbosity levels:
- 0: error
- 1: warn
- 2: info
- 3: debug
- 4+: trace

Use tracing-subscriber with:
- EnvFilter
- fmt layer (text or json)
- Optional file appender
```

---

### Task 4.3 [A] [IMPL] Metrics Collection

**Output**: `qsh-core/src/metrics.rs`

**Prompt**:
```
Implement metrics collection.

```rust
pub struct ConnectionMetrics {
    pub rtt: Duration,
    pub rtt_smoothed: Duration,
    pub jitter: Duration,
    pub packet_loss: f64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub messages_sent: u64,
    pub messages_recv: u64,
    pub reconnect_count: u32,
    pub session_start: Instant,
}

impl ConnectionMetrics {
    pub fn new() -> Self;
    pub fn update_rtt(&mut self, sample: Duration);
    pub fn record_send(&mut self, bytes: usize);
    pub fn record_recv(&mut self, bytes: usize);
}
```

RTT smoothing: SRTT = 0.875 * SRTT + 0.125 * sample
```

---

### [SYNC] Phase 4 Complete

---

## Phase 5: Polish

### Task 5.1 [SEQ] CLI Implementation (Client)

**Output**: `qsh-client/src/cli.rs`

**Prompt**:
```
Implement full client CLI using clap.

```rust
#[derive(Parser)]
#[command(name = "qsh", about = "Modern roaming-capable remote terminal")]
pub struct Cli {
    /// Remote host (user@host or host)
    pub destination: String,
    
    /// Command to execute
    pub command: Option<String>,
    
    #[arg(short = 'p', long, default_value = "22")]
    pub port: u16,
    
    #[arg(short = 'l', long)]
    pub login: Option<String>,
    
    #[arg(short = 'L', action = ArgAction::Append)]
    pub local_forward: Vec<String>,
    
    #[arg(short = 'R', action = ArgAction::Append)]
    pub remote_forward: Vec<String>,
    
    #[arg(short = 'D', action = ArgAction::Append)]
    pub dynamic_forward: Vec<String>,
    
    #[arg(short = 'N')]
    pub no_pty: bool,
    
    #[arg(short = 'f')]
    pub background: bool,
    
    #[arg(short = 'v', action = ArgAction::Count)]
    pub verbose: u8,
    
    #[arg(long)]
    pub log_file: Option<PathBuf>,
    
    #[arg(long, default_value = "text")]
    pub log_format: LogFormat,
    
    // ... tunnel options (feature-gated)
}
```
```

---

### Task 5.2 [SEQ] CLI Implementation (Server)

**Output**: `qsh-server/src/cli.rs`

---

### Task 5.3 [SEQ] Main Entry Points

**Output**: `qsh-client/src/main.rs`, `qsh-server/src/main.rs`

---

### Task 5.4 [A] [TEST] E2E Tests

**Output**: `tests/e2e_test.rs`

**Prompt**:
```
Write E2E tests that spawn real binaries.

Mark with #[ignore] for CI (requires built binaries).

Test scenarios:
1. basic_connection — connect, type, exit
2. reconnection — connect, kill network, reconnect
3. local_forward — set up forward, verify connectivity
4. dynamic_forward — SOCKS5 proxy test
```

---

### Task 5.5 [B] Cross-Platform Testing

**Output**: CI workflow updates

---

### [SYNC] Phase 5 Complete

Core qsh is feature-complete.

---

## Phase 6: Tunnel (Feature-Flagged, Linux Only)

### Task 6.1 [A] [TEST] Tunnel Types

**Output**: `qsh-core/src/tunnel/tests.rs`

**Prompt**:
```
Write tests for tunnel types. Feature-gated.

#[cfg(feature = "tunnel")]

```rust
pub struct TunnelConfig {
    pub client_ip: IpNet,
    pub server_ip: IpNet,
    pub mtu: u16,
    pub routes: Vec<IpNet>,
    pub dns_servers: Vec<IpAddr>,
}

pub enum TunnelState {
    Inactive,
    Configuring,
    Active { config: TunnelConfig },
    Suspended,
}
```

Test cases:
1. config_serialization_roundtrip
2. tunnel_state_transitions
3. ip_validation
```

---

#### Task 6.2 [A] [IMPL] Tunnel Types

**DEP**: 6.1
**Output**: `qsh-core/src/tunnel/types.rs`

---

### Task 6.3 [B] [IMPL] Tun Device Wrapper (Linux)

**Output**: `qsh-core/src/tunnel/tun_linux.rs`

**Prompt**:
```
Implement tun device wrapper for Linux using tokio-tun.

#[cfg(all(feature = "tunnel", target_os = "linux"))]

```rust
pub struct LinuxTun {
    tun: tokio_tun::Tun,
    name: String,
    local_ip: IpNet,
    mtu: u16,
}

impl LinuxTun {
    pub async fn create(name: &str, ip: IpNet, mtu: u16) -> io::Result<Self>;
}

impl TunDevice for LinuxTun {
    async fn read_packet(&mut self) -> io::Result<Vec<u8>>;
    async fn write_packet(&mut self, packet: &[u8]) -> io::Result<()>;
    fn local_ip(&self) -> IpNet;
    fn name(&self) -> &str;
    fn mtu(&self) -> u16;
}
```
```

---

### Task 6.4 [B] [IMPL] Fake Tun (Testing)

**Output**: `qsh-test-utils/src/fake_tun.rs`

---

### Task 6.5 [C] [IMPL] Tunnel Handler

**DEP**: 6.2, 6.3
**Output**: `qsh-core/src/tunnel/handler.rs`

---

### Task 6.6 [SEQ] Tunnel Integration

**DEP**: 6.5
**Output**: `qsh-client/src/tunnel.rs`, `qsh-server/src/tunnel.rs`

---

### Task 6.7 [SEQ] Tunnel Tests

**Output**: `tests/tunnel_test.rs`

---

### [SYNC] Phase 6 Complete

---

## Appendix: Prompt Templates

### Template A: Test-First Implementation

```
You are implementing a Rust module for the qsh project.

## Context
qsh is a modern remote terminal using QUIC transport.
It uses Rust 2024 edition with async/await.

## Task
Implement [MODULE_NAME] to pass these tests:

```rust
[PASTE_TESTS_HERE]
```

## Requirements
- Use the types and traits already defined in qsh-core
- All types must be Send + Sync
- Use thiserror for errors
- Follow Rust 2024 idioms (async fn in traits, let-else, etc.)

## Output
Provide only the implementation code. Do not explain.
```

### Template B: Integration Task

```
You are writing integration code for qsh.

## Context
[DESCRIBE_CONTEXT]

## Existing Code
The following modules are available:
- qsh_core::protocol::{Message, Codec}
- qsh_core::terminal::{TerminalState, TerminalParser}
- qsh_core::transport::{Connection, StreamPair}

## Task
[DESCRIBE_TASK]

## Requirements
[LIST_REQUIREMENTS]

## Output
Provide the complete implementation.
```

### Template C: Bug Fix

```
The following test is failing:

```rust
[PASTE_FAILING_TEST]
```

Error message:
```
[PASTE_ERROR]
```

Current implementation:
```rust
[PASTE_IMPLEMENTATION]
```

Fix the implementation to make the test pass.
Explain the bug briefly, then provide the corrected code.
```

---

## Task Dependency Graph

```
Phase 0: Bootstrap
  0.1 ─► 0.2 ─► 0.3

Phase 1: Core Terminal
  Track A (Protocol):    1.1 ─► 1.2 ─► 1.3 ─► 1.4 ─► 1.5
  Track B (Terminal):    1.6 ─► 1.7 ─► 1.8 ─► 1.9
  Track C (Transport):   1.10 ─► 1.11
                                    │
                              [SYNC 1.12]
                                    │
  Track D (Bootstrap):   1.13 ─► 1.14 ─► 1.15
  Track E (PTY):         1.16 ─► 1.17
  Track F (Session):     1.18 ─► 1.19
                                    │
                              [SYNC 1.20]
                                    │
                         1.21 ─► 1.22 ─► 1.23 ─► 1.24 ─► 1.25

Phase 2: Resilience
  Track A (Prediction):  2.1 ─► 2.2 ─► 2.7
  Track B (Diff):        2.3 ─► 2.4
  Track C (Reconnect):   2.5 ─► 2.6

Phase 3: Port Forwarding
  Track A (Spec):        3.1 ─► 3.2
  Track B (Local/Rem):   3.3 ─► 3.4  (parallel)
  Track C (SOCKS):       3.5

Phase 4: Observability
  Track A (Overlay):     4.1 ─► 4.3
  Track B (Logging):     4.2

Phase 5: Polish
  5.1 ─► 5.2 ─► 5.3 ─► 5.4/5.5 (parallel)

Phase 6: Tunnel (optional)
  Track A (Types):       6.1 ─► 6.2
  Track B (Tun):         6.3 ─► 6.4
  Track C (Handler):     6.5 ─► 6.6 ─► 6.7
```

---

## Parallelization Summary

| Phase | Max Parallel Tracks | Estimated Speedup |
|-------|--------------------:|------------------:|
| 0 | 1 | 1x |
| 1 (first half) | 3 | 2.5x |
| 1 (second half) | 3 | 2x |
| 2 | 3 | 2x |
| 3 | 3 | 2x |
| 4 | 2 | 1.5x |
| 5 | 2 | 1.5x |
| 6 | 3 | 2x |

**Total tasks**: ~55
**Critical path**: ~30 tasks
**With parallelization**: ~20-25 sequential steps

---

## Checkpoint Validation

After each [SYNC] point, run:

```bash
# Compilation
cargo check --all-targets

# Tests
cargo test

# Clippy
cargo clippy -- -D warnings

# Format
cargo fmt -- --check
```

All must pass before proceeding to next phase.
