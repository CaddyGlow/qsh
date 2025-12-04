# qsh — Protocol Specification

**Wire Protocol for a Roaming-Capable Remote Terminal**

| Field | Value |
|-------|-------|
| Version | 1.0 |
| Protocol Version | 1 |
| Status | Draft |
| Last Updated | December 2025 |

---

> **Note on Tunnel Feature**
> 
> The IP tunnel (VPN) functionality described in [Section 10](#10-tunnel-protocol) is implemented under the `tunnel` feature flag and initially supports **Linux only**. The tunnel protocol messages (`TunnelConfig`, `TunnelConfigAck`, `TunnelPacket`) are only available when this feature is enabled. Core terminal and port forwarding functionality works without the tunnel feature.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Connection Lifecycle](#2-connection-lifecycle)
3. [Transport Layer](#3-transport-layer)
4. [Stream Architecture](#4-stream-architecture)
5. [Message Format](#5-message-format)
6. [Message Types](#6-message-types)
7. [Terminal State Protocol](#7-terminal-state-protocol)
8. [Predictive Echo Protocol](#8-predictive-echo-protocol)
9. [Port Forwarding Protocol](#9-port-forwarding-protocol)
10. [Tunnel Protocol](#10-tunnel-protocol)
11. [Reconnection Protocol](#11-reconnection-protocol)
12. [Security Considerations](#12-security-considerations)
13. [Error Handling](#13-error-handling)
14. [Constants and Limits](#14-constants-and-limits)

---

## 1. Overview

### 1.1 Design Goals

The qsh protocol is designed for:

- **Roaming**: Seamless session continuity across network changes
- **Low latency**: Predictive local echo for responsive typing
- **Multiplexing**: Independent streams for terminal and port forwarding
- **Simplicity**: Minimal state machine, easy to implement and debug

### 1.2 Protocol Stack

```
┌─────────────────────────────────────────┐
│           Application Layer             │
│  (Terminal I/O, Port Forwarding)        │
├─────────────────────────────────────────┤
│           qsh Protocol Layer            │
│  (Messages, State Sync, Prediction)     │
├─────────────────────────────────────────┤
│           QUIC Transport                │
│  (Streams, Reliability, Encryption)     │
├─────────────────────────────────────────┤
│              UDP                        │
└─────────────────────────────────────────┘
```

### 1.3 Terminology

| Term | Definition |
|------|------------|
| **Client** | The qsh binary running on the user's machine |
| **Server** | The qsh-server daemon running on the remote host |
| **Session** | A logical connection identified by session key |
| **Generation** | Monotonic version number for terminal state |
| **Stream** | A QUIC stream within the connection |

---

## 2. Connection Lifecycle

### 2.1 Two-Phase Connection Model

qsh uses SSH for authentication and QUIC for the session:

```
┌────────────────────────────────────────────────────────────────────┐
│ Phase 1: SSH Bootstrap                                              │
│                                                                    │
│  Client                              Server                        │
│    │                                   │                           │
│    │──── SSH Connect ─────────────────►│                           │
│    │                                   │                           │
│    │◄─── SSH Auth Challenge ───────────│                           │
│    │                                   │                           │
│    │──── SSH Auth Response ───────────►│                           │
│    │                                   │                           │
│    │──── exec: qsh-server --bootstrap─►│                           │
│    │                                   │ (server starts)           │
│    │                                   │                           │
│    │◄─── Bootstrap Response ───────────│                           │
│    │     (port, session_key, cert)     │                           │
│    │                                   │                           │
│    │──── SSH Disconnect ──────────────►│                           │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────┐
│ Phase 2: QUIC Session                                              │
│                                                                    │
│  Client                              Server                        │
│    │                                   │                           │
│    │════ QUIC Connect (0-RTT?) ═══════►│                           │
│    │     (cert pinned from bootstrap)  │                           │
│    │                                   │                           │
│    │◄════ QUIC Established ════════════│                           │
│    │                                   │                           │
│    │──── Hello (session_key) ─────────►│                           │
│    │                                   │                           │
│    │◄─── HelloAck (initial state) ─────│                           │
│    │                                   │                           │
│    │◄═══ Bidirectional Session ═══════►│                           │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

### 2.2 Bootstrap Protocol

The bootstrap phase uses SSH to securely exchange QUIC credentials.

#### Bootstrap Request

Client executes on server via SSH:

```bash
qsh-server --bootstrap [--port-range 4500-4600]
```

If a bootstrap instance is already running for the same UID, new `--bootstrap`
invocations write to the FIFO `/tmp/qsh-server-$UID` and receive a fresh
response (new session key, same listener) without spawning another daemon.

#### Bootstrap Response

Server writes to stdout (JSON, single line):

```json
{
  "version": 1,
  "quic_port": 4500,
  "session_key": "<base64-encoded 32 bytes>",
  "cert_der": "<base64-encoded DER certificate>",
  "server_id": "<uuid>"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `version` | u32 | Bootstrap protocol version (always 1) |
| `quic_port` | u16 | UDP port server is listening on |
| `session_key` | string | Base64-encoded 256-bit session key |
| `cert_der` | string | Base64-encoded DER X.509 certificate |
| `server_id` | string | Unique server instance identifier |

### 2.3 Session Establishment

After bootstrap, client connects via QUIC:

1. Client initiates QUIC connection to `server:quic_port`
2. Client validates server certificate matches `cert_der` exactly
3. Client opens control stream (stream ID 0)
4. Client sends `Hello` message with `session_key`
5. Server validates session key
6. Server sends `HelloAck` with initial terminal state
7. Session is established

### 2.3.1 Reattach / Session Persistence

- The server keeps PTYs alive in a session registry keyed by `session_key`.
- Only one attachment is active per session; a new attach with the same key
  replaces the prior client.
- `Hello` with a known `session_key` reuses the existing PTY and sends the
  current terminal state; no respawn occurs.
- Detached sessions linger for 48h by default (configurable via
  `--session-linger` or `QSH_SESSION_LINGER_SECS`); if idle longer with no
  attachment, the entry is destroyed.
- PTY exit immediately tears down the registry entry and notifies any attached
  client with `Shutdown(ShellExited)`.

### 2.4 Session Termination

Sessions can end via:

| Method | Initiator | Behavior |
|--------|-----------|----------|
| `Shutdown` message | Either | Graceful close with reason |
| QUIC connection close | Either | Immediate termination |
| Idle timeout | Server | After `session_timeout` with no activity |
| `~.` escape | Client | Sends Shutdown, closes connection |

---

## 3. Transport Layer

### 3.1 QUIC Configuration

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| ALPN | `qsh/1` | Protocol identification |
| Idle timeout | 30s | Detect dead connections |
| Keep-alive | 10s | Prevent NAT timeout |
| Max streams (bidi) | 256 | Terminal + forwards |
| Max streams (uni) | 16 | Future use |
| Initial RTT | 100ms | Conservative estimate |
| Max datagram size | 1350 | Safe for most paths |

### 3.2 TLS Configuration

| Parameter | Value |
|-----------|-------|
| TLS version | 1.3 only |
| Certificate | Self-signed, ephemeral |
| Key exchange | X25519 |
| Cipher suites | TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256 |
| Client auth | None (session key provides auth) |

### 3.3 Connection Migration

QUIC connection migration is fully supported:

- Client may change IP address at any time
- Server accepts packets from new address after path validation
- No protocol-level action required; QUIC handles transparently

---

## 4. Stream Architecture

### 4.1 Stream Types

qsh uses QUIC's native stream multiplexing. Stream IDs follow QUIC semantics (bit 0 = initiator, bit 1 = uni/bidi):

| Stream ID | Type | Direction | Purpose |
|-----------|------|-----------|---------|
| 0 (client bidi) | Control | Bidirectional | Session management |
| 3 (server uni) | Terminal Out | Server → Client | State updates |
| 2, 6, ... (client uni) | Terminal In | Client → Server | User input |
| 1, 5, ... (server bidi) | Forward | Bidirectional | Port forwarding |
| 8, 12, ... (client bidi) | Forward | Bidirectional | Port forwarding (client-initiated) |
| 4 (client bidi; reserved) | Tunnel | Bidirectional | IP tunnel (VPN) |

### 4.2 Stream Lifecycle

```
Control Stream (ID 0, client-initiated bidi):
  - Opened by client immediately after QUIC handshake
  - Remains open for session lifetime
  - Carries Hello, HelloAck, Resize, Shutdown

Terminal Output Stream (server-initiated uni, first ID 3):
  - Opened by server after HelloAck
  - Server sends StateUpdate messages
  - Client sends StateAck messages on control stream
  - Remains open for session lifetime

Terminal Input Stream (client-initiated uni, first ID 2):
  - Opened by client after receiving HelloAck
  - Client sends TerminalInput messages to the server
  - Closed when session ends

Tunnel Stream (client-initiated bidi, reserved ID 4):
  - Opened by client if tunnel requested (--tun flag) using a dedicated bidi stream
  - Client sends TunnelConfig, server responds TunnelConfigAck
  - Both sides send TunnelPacket messages
  - Remains open for session lifetime
  - Survives reconnection (tunnel interface persists)

Forward Streams:
  - Opened on-demand for each forwarded connection
  - Either side may initiate based on forward direction
  - Carries ForwardData messages
  - Closed when forwarded connection closes
```

### 4.3 Stream Priorities

| Stream | Priority | Rationale |
|--------|----------|-----------|
| Control | Highest | Session management critical |
| Terminal In | High | User input should be responsive |
| Terminal Out | High | Screen updates important |
| Tunnel | High | Low-latency VPN traffic |
| Forward | Normal | Bulk data transfer |

---

## 5. Message Format

### 5.1 Wire Format

All messages use length-prefixed encoding:

```
┌──────────────────────────────────────────────────────┐
│  Length (4 bytes, little-endian)                     │
├──────────────────────────────────────────────────────┤
│  Payload (bincode-encoded Message)                   │
│  ... variable length ...                             │
└──────────────────────────────────────────────────────┘
```

### 5.2 Encoding

Messages are serialized using [bincode](https://github.com/bincode-org/bincode) with these settings:

```rust
bincode::config::standard()
    .with_little_endian()
    .with_variable_int_encoding()
```

### 5.3 Message Envelope

```rust
/// Top-level message type
#[derive(Serialize, Deserialize)]
pub enum Message {
    // Control stream (ID 0)
    Hello(HelloPayload),           // 0x00
    HelloAck(HelloAckPayload),     // 0x01
    Resize(ResizePayload),         // 0x02
    Shutdown(ShutdownPayload),     // 0x03
    
    // Terminal streams
    TerminalInput(TerminalInputPayload),   // 0x04
    TerminalOutput(TerminalOutputPayload), // 0x05
    StateUpdate(StateUpdatePayload),       // 0x06
    StateAck(StateAckPayload),             // 0x07
    
    // Forward streams
    ForwardRequest(ForwardRequestPayload), // 0x08
    ForwardAccept(ForwardAcceptPayload),   // 0x09
    ForwardReject(ForwardRejectPayload),   // 0x0A
    ForwardData(ForwardDataPayload),       // 0x0B
    ForwardEof(ForwardEofPayload),         // 0x0C
    ForwardClose(ForwardClosePayload),     // 0x0D
    
    // Tunnel stream (ID 4)
    TunnelConfig(TunnelConfigPayload),     // 0x0E
    TunnelConfigAck(TunnelConfigAckPayload), // 0x0F
    TunnelPacket(TunnelPacketPayload),     // 0x10
}
```

---

## 6. Message Types

### 6.1 Control Messages

#### Hello

Sent by client on control stream to authenticate session.

```rust
pub struct HelloPayload {
    /// Protocol version (must be 1)
    pub protocol_version: u32,
    
    /// Session key from bootstrap (32 bytes)
    pub session_key: [u8; 32],
    
    /// Client nonce for anti-replay (monotonic)
    pub client_nonce: u64,
    
    /// Client capabilities
    pub capabilities: Capabilities,
    
    /// Requested terminal size
    pub term_size: TermSize,
    
    /// TERM environment variable
    pub term_type: String,
}

pub struct Capabilities {
    /// Supports predictive echo
    pub predictive_echo: bool,
    
    /// Supports state compression
    pub compression: bool,
    
    /// Maximum forward connections
    pub max_forwards: u16,
    
    /// Supports IP tunnel
    pub tunnel: bool,
}

pub struct TermSize {
    pub cols: u16,
    pub rows: u16,
}
```

#### HelloAck

Sent by server in response to Hello.

```rust
pub struct HelloAckPayload {
    /// Server protocol version
    pub protocol_version: u32,
    
    /// Session accepted
    pub accepted: bool,
    
    /// Rejection reason (if not accepted)
    pub reject_reason: Option<String>,
    
    /// Server capabilities
    pub capabilities: Capabilities,
    
    /// Initial terminal state (if accepted)
    pub initial_state: Option<TerminalState>,
    
    /// 0-RTT is available for future reconnects
    pub zero_rtt_available: bool,
}
```

#### Resize

Sent by client when terminal size changes.

```rust
pub struct ResizePayload {
    pub cols: u16,
    pub rows: u16,
}
```

Connection liveness and keepalive are handled by QUIC transport parameters; no application-level ping/pong messages are exchanged.

#### Shutdown

Graceful session termination.

```rust
pub struct ShutdownPayload {
    pub reason: ShutdownReason,
    pub message: Option<String>,
}

pub enum ShutdownReason {
    UserRequested,      // ~. escape or explicit quit
    IdleTimeout,        // Server-side timeout
    ServerShutdown,     // Server process exiting
    ProtocolError,      // Unrecoverable protocol violation
    AuthFailure,        // Session key mismatch
}
```

### 6.2 Terminal Messages

#### TerminalInput

User input sent to server.

```rust
pub struct TerminalInputPayload {
    /// Monotonic sequence number
    pub sequence: u64,
    
    /// Raw input bytes
    pub data: Vec<u8>,
    
    /// Hint: these bytes may be predicted locally
    pub predictable: bool,
}
```

#### StateUpdate

Terminal state sent from server to client.

```rust
pub struct StateUpdatePayload {
    /// State diff or full state
    pub diff: StateDiff,
    
    /// Highest input sequence processed
    pub confirmed_input_seq: u64,
    
    /// Server timestamp for latency calc
    pub timestamp: u64,
}

pub enum StateDiff {
    /// Complete terminal state (reconnect, major desync)
    Full(TerminalState),
    
    /// Incremental changes
    Incremental(IncrementalDiff),
    
    /// Only cursor moved
    CursorOnly(CursorUpdate),
}
```

#### StateAck

Client acknowledges received state.

```rust
pub struct StateAckPayload {
    /// Generation number acknowledged
    pub generation: u64,
}
```

### 6.3 Forward Messages

#### ForwardRequest

Request to establish a forwarded connection.

```rust
pub struct ForwardRequestPayload {
    /// Unique forward ID for this connection
    pub forward_id: u64,
    
    /// Forward specification
    pub spec: ForwardSpec,
    
    /// For local forwards: target host:port
    /// For remote forwards: originating address
    pub target: String,
    pub target_port: u16,
}

pub enum ForwardSpec {
    /// -L: Local port forward
    Local { bind_port: u16 },
    
    /// -R: Remote port forward  
    Remote { bind_port: u16 },
    
    /// -D: Dynamic SOCKS5
    Dynamic,
}
```

#### ForwardAccept

Accept a forward request.

```rust
pub struct ForwardAcceptPayload {
    pub forward_id: u64,
}
```

#### ForwardReject

Reject a forward request.

```rust
pub struct ForwardRejectPayload {
    pub forward_id: u64,
    pub reason: String,
}
```

#### ForwardData

Data on a forwarded connection.

```rust
pub struct ForwardDataPayload {
    pub forward_id: u64,
    pub data: Vec<u8>,
}
```

#### ForwardEof

End of data in one direction (half-close).

```rust
pub struct ForwardEofPayload {
    pub forward_id: u64,
}
```

#### ForwardClose

Close a forwarded connection.

```rust
pub struct ForwardClosePayload {
    pub forward_id: u64,
    pub reason: Option<String>,
}
```

### 6.4 Tunnel Messages

#### TunnelConfig

Sent by client to configure IP tunnel.

```rust
pub struct TunnelConfigPayload {
    /// Requested client tunnel IP with prefix (e.g., "10.99.0.2/24")
    pub client_ip: IpNet,
    
    /// Requested MTU for tunnel interface
    pub mtu: u16,
    
    /// Routes to push to client (optional)
    pub requested_routes: Vec<IpNet>,
    
    /// Enable IPv6 in tunnel
    pub ipv6: bool,
}

/// IP network (address + prefix length)
pub struct IpNet {
    pub addr: IpAddr,
    pub prefix_len: u8,
}

pub enum IpAddr {
    V4([u8; 4]),
    V6([u8; 16]),
}
```

#### TunnelConfigAck

Server response to tunnel configuration.

```rust
pub struct TunnelConfigAckPayload {
    /// Whether tunnel was accepted
    pub accepted: bool,
    
    /// Rejection reason (if not accepted)
    pub reject_reason: Option<String>,
    
    /// Server's tunnel IP (e.g., "10.99.0.1/24")
    pub server_ip: IpNet,
    
    /// Negotiated MTU
    pub mtu: u16,
    
    /// Routes client should add (server-pushed)
    pub routes: Vec<IpNet>,
    
    /// DNS servers to use (optional)
    pub dns_servers: Vec<IpAddr>,
}
```

#### TunnelPacket

Raw IP packet sent through tunnel.

```rust
pub struct TunnelPacketPayload {
    /// Raw IP packet (IPv4 or IPv6, including header)
    pub packet: Vec<u8>,
}
```

The packet field contains a complete IP packet starting with the IP header. The IP version is determined by inspecting the first nibble (4 = IPv4, 6 = IPv6).

---

## 7. Terminal State Protocol

### 7.1 State Model

The server maintains authoritative terminal state:

```rust
pub struct TerminalState {
    /// Monotonic version number
    pub generation: u64,
    
    /// Screen dimensions
    pub cols: u16,
    pub rows: u16,
    
    /// Primary screen buffer
    pub primary_screen: Screen,
    
    /// Alternate screen buffer
    pub alternate_screen: Screen,
    
    /// Which screen is active
    pub alternate_active: bool,
    
    /// Cursor state
    pub cursor: CursorState,
    
    /// Terminal modes
    pub modes: TerminalModes,
    
    /// Scroll region
    pub scroll_region: Option<ScrollRegion>,
    
    /// Window title
    pub title: Option<String>,
    
    /// Tab stops
    pub tab_stops: Vec<u16>,
}

pub struct Screen {
    /// Row-major cell array
    pub cells: Vec<Cell>,
}

pub struct Cell {
    /// Unicode grapheme cluster
    pub grapheme: String,
    
    /// Display width (1 or 2)
    pub width: u8,
    
    /// Cell attributes
    pub attrs: CellAttrs,
}

pub struct CellAttrs {
    pub fg: Color,
    pub bg: Color,
    pub flags: AttrFlags,
}

pub struct Color {
    pub kind: ColorKind,
}

pub enum ColorKind {
    Default,
    Indexed(u8),        // 0-255
    Rgb(u8, u8, u8),    // True color
}

bitflags! {
    pub struct AttrFlags: u16 {
        const BOLD       = 0x0001;
        const DIM        = 0x0002;
        const ITALIC     = 0x0004;
        const UNDERLINE  = 0x0008;
        const BLINK      = 0x0010;
        const REVERSE    = 0x0020;
        const HIDDEN     = 0x0040;
        const STRIKE     = 0x0080;
        const OVERLINE   = 0x0100;
    }
}

pub struct CursorState {
    pub col: u16,
    pub row: u16,
    pub style: CursorStyle,
    pub visible: bool,
}

pub enum CursorStyle {
    Block,
    Underline,
    Bar,
    BlinkBlock,
    BlinkUnderline,
    BlinkBar,
}
```

### 7.2 Incremental Diff Format

For efficiency, most updates are incremental:

```rust
pub struct IncrementalDiff {
    /// Previous generation this diff applies to
    pub from_generation: u64,
    
    /// New generation after applying
    pub to_generation: u64,
    
    /// Changed cells
    pub cell_changes: Vec<CellChange>,
    
    /// Cursor update (if changed)
    pub cursor: Option<CursorState>,
    
    /// Mode changes (if any)
    pub mode_changes: Option<TerminalModes>,
    
    /// Title change (if any)
    pub title_change: Option<Option<String>>,
    
    /// Screen switch (if changed)
    pub screen_switch: Option<bool>,
}

pub struct CellChange {
    pub col: u16,
    pub row: u16,
    pub cell: Cell,
}

pub struct CursorUpdate {
    pub generation: u64,
    pub cursor: CursorState,
}
```

### 7.3 State Synchronization Flow

```
Normal Operation:
  Server                              Client
    │                                   │
    │ (PTY output received)             │
    │ (parse, update state)             │
    │                                   │
    │──── StateUpdate(Incremental) ────►│
    │                                   │ (apply diff)
    │                                   │ (render)
    │◄─── StateAck(generation) ─────────│
    │                                   │
    
Reconnection:
  Server                              Client
    │                                   │
    │◄─── Hello (with last gen) ────────│
    │                                   │
    │ (compute diff from last gen)      │
    │                                   │
    │──── StateUpdate(diff or full) ───►│
    │                                   │ (apply)
    │◄─── StateAck(generation) ─────────│
```

### 7.4 Generation Numbers

- Generation starts at 0 for new sessions
- Increments with every state-changing PTY output
- Client tracks last acknowledged generation
- On reconnect, client sends last known generation in Hello
- Server sends diff from that generation, or full state if unavailable

---

## 8. Predictive Echo Protocol

### 8.1 Overview

Predictive echo displays typed characters immediately before server confirmation, improving perceived latency on slow links.

### 8.2 Prediction Flow

```
User types 'a':
  Client                              Server
    │                                   │
    │ (user presses 'a')                │
    │ (display 'a' with underline)      │
    │                                   │
    │──── TerminalInput(seq=1, 'a') ───►│
    │                                   │ (write to PTY)
    │                                   │ (PTY echoes 'a')
    │◄─── StateUpdate(confirmed=1) ─────│
    │                                   │
    │ (remove underline from 'a')       │
```

### 8.3 Prediction Rules

Client predicts echo for:

| Character Type | Predict? | Rationale |
|----------------|----------|-----------|
| Printable ASCII | Yes | Usually echoed |
| Unicode printable | Yes | Usually echoed |
| Control chars | No | May trigger actions |
| Escape sequences | No | Complex behavior |
| After newline | Tentative | Shell prompt unknown |

### 8.4 Misprediction Handling

When server state differs from prediction:

1. Client detects mismatch in StateUpdate
2. Client clears all pending predictions
3. Client enters tentative mode (predict less)
4. After N successful confirmations, return to confident mode

```rust
pub enum PredictionMode {
    /// Normal prediction
    Confident,
    
    /// Recent misprediction, be conservative
    Tentative,
    
    /// Too many errors, disable prediction
    Disabled,
}
```

### 8.5 Sequence Number Tracking

- Each TerminalInput has monotonic sequence number
- Server echoes highest processed sequence in StateUpdate
- Client removes predictions with seq ≤ confirmed_input_seq

---

## 9. Port Forwarding Protocol

### 9.1 Local Forward (-L)

```
Local Forward: client:5432 → server → db:5432

  Local App     Client                Server              Database
      │           │                     │                    │
      │──connect─►│                     │                    │
      │           │──ForwardRequest────►│                    │
      │           │  (Local, 5432,      │                    │
      │           │   db:5432)          │                    │
      │           │                     │────connect────────►│
      │           │◄──ForwardAccept─────│                    │
      │           │                     │◄───────────────────│
      │──data────►│──ForwardData───────►│────data───────────►│
      │◄──data────│◄──ForwardData───────│◄───data────────────│
      │           │                     │                    │
```

### 9.2 Remote Forward (-R)

```
Remote Forward: server:8080 → client → localhost:3000

  Remote App    Server                Client              Local App
      │           │                     │                    │
      │──connect─►│                     │                    │
      │           │──ForwardRequest────►│                    │
      │           │  (Remote, 8080,     │                    │
      │           │   remote_addr)      │────connect────────►│
      │           │◄──ForwardAccept─────│                    │
      │           │                     │◄───────────────────│
      │──data────►│──ForwardData───────►│────data───────────►│
      │◄──data────│◄──ForwardData───────│◄───data────────────│
```

### 9.3 Dynamic Forward (-D)

SOCKS5 proxy with target determined per-connection:

```
Dynamic Forward (SOCKS5): client:1080 → server → anywhere

  Browser       Client                Server              Target
      │           │                     │                    │
      │─SOCKS5───►│                     │                    │
      │ CONNECT   │                     │                    │
      │ example:80│──ForwardRequest────►│                    │
      │           │  (Dynamic,          │                    │
      │           │   example.com:80)   │────connect────────►│
      │◄──────────│◄──ForwardAccept─────│                    │
      │           │                     │◄───────────────────│
      │──HTTP────►│──ForwardData───────►│────HTTP───────────►│
      │◄──HTTP────│◄──ForwardData───────│◄───HTTP────────────│
```

### 9.4 Forward ID Assignment

- Client-initiated forwards: even IDs (0, 2, 4, ...)
- Server-initiated forwards: odd IDs (1, 3, 5, ...)
- Each side maintains own counter
- IDs unique within session

### 9.5 Forward Persistence

Forwards survive reconnection:

1. ForwardRequest/Accept state cached on both sides
2. On reconnect, active listeners remain bound
3. In-flight data may be lost (TCP-like behavior)
4. New connections resume normally

---

## 10. Tunnel Protocol

> **Implementation Note**
> 
> This feature is gated behind `#[cfg(feature = "tunnel")]` and initially supports **Linux only**.
> Build with: `cargo build --features tunnel`

### 10.1 Overview

The tunnel protocol provides a Layer 3 (IP) VPN over the qsh session. It creates a virtual network interface (tun) on both client and server, allowing IP traffic to be routed through the encrypted QUIC connection.

```
┌────────────────────────────────────────────────────────────────────┐
│ Tunnel Architecture                                                 │
│                                                                    │
│  Client Machine                          Server Machine            │
│  ┌─────────────┐                        ┌─────────────┐           │
│  │ Application │                        │ Destination │           │
│  └──────┬──────┘                        └──────▲──────┘           │
│         │ IP packets                           │ IP packets       │
│         ▼                                      │                  │
│  ┌─────────────┐                        ┌──────┴──────┐           │
│  │  tun0       │                        │  tun0       │           │
│  │ 10.99.0.2   │                        │ 10.99.0.1   │           │
│  └──────┬──────┘                        └──────▲──────┘           │
│         │                                      │                  │
│         ▼                                      │                  │
│  ┌─────────────┐      TunnelPacket      ┌──────┴──────┐           │
│  │    qsh      │ ══════════════════════►│ qsh-server  │           │
│  │   client    │◄══════════════════════ │             │           │
│  └─────────────┘   (over QUIC stream)   └─────────────┘           │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

### 10.2 Tunnel Configuration Flow

```
Tunnel Setup:
  Client                              Server
    │                                   │
    │──── TunnelConfig ────────────────►│
    │     (client_ip: 10.99.0.2/24,     │
    │      mtu: 1280)                   │
    │                                   │ (create tun interface)
    │                                   │ (configure IP, routes)
    │                                   │
    │◄─── TunnelConfigAck ──────────────│
    │     (server_ip: 10.99.0.1/24,     │
    │      mtu: 1280,                   │
    │      routes: [0.0.0.0/0])         │
    │                                   │
    │ (create tun interface)            │
    │ (configure IP, routes)            │
    │                                   │
    │◄═══ TunnelPacket ═══════════════►│
    │     (bidirectional IP traffic)    │
```

### 10.3 IP Address Assignment

Two modes are supported:

#### Static Assignment

Client specifies desired IP in TunnelConfig:

```rust
TunnelConfig {
    client_ip: IpNet { addr: "10.99.0.2", prefix_len: 24 },
    mtu: 1280,
    requested_routes: [],
    ipv6: false,
}
```

#### Server Assignment (Future)

Client requests assignment:

```rust
TunnelConfig {
    client_ip: IpNet { addr: "0.0.0.0", prefix_len: 0 }, // Request assignment
    mtu: 1280,
    requested_routes: [],
    ipv6: false,
}
```

Server assigns from pool and returns in TunnelConfigAck.

### 10.4 MTU Handling

The tunnel MTU must account for encapsulation overhead:

```
Path MTU (typical)     1500 bytes
- UDP header             8 bytes
- QUIC header (max)     38 bytes
- TLS record overhead   22 bytes
- qsh message header     8 bytes
─────────────────────────────────
Available for IP       1424 bytes

Recommended tunnel MTU: 1280 bytes (IPv6 minimum, safe default)
```

The client and server negotiate MTU:

1. Client proposes MTU in TunnelConfig
2. Server may reduce (never increase) in TunnelConfigAck
3. Both sides configure tun interface with negotiated MTU

### 10.5 Packet Flow

#### Client → Server (Outbound)

1. Application sends IP packet
2. Kernel routes to tun interface (based on routing table)
3. qsh reads packet from tun device
4. qsh wraps in TunnelPacket message
5. qsh sends on tunnel stream (ID 4)
6. qsh-server receives TunnelPacket
7. qsh-server writes raw IP packet to server's tun
8. Server kernel routes packet (NAT, forward, or local delivery)

#### Server → Client (Inbound)

1. Response packet arrives at server
2. Server kernel routes to tun (based on tunnel subnet)
3. qsh-server reads from tun
4. qsh-server sends TunnelPacket to client
5. qsh writes to client's tun
6. Client kernel delivers to application

### 10.6 Routing Configuration

#### Client-Side Routes

The client configures routes based on:

1. **Default gateway** (optional): Route all traffic through tunnel

```bash
# Pushed by server: routes: ["0.0.0.0/0"]
ip route add default via 10.99.0.1 dev tun0 metric 100
```

2. **Specific subnets**: Route only certain networks

```bash
# Pushed by server: routes: ["192.168.0.0/16", "10.0.0.0/8"]
ip route add 192.168.0.0/16 via 10.99.0.1 dev tun0
ip route add 10.0.0.0/8 via 10.99.0.1 dev tun0
```

3. **Exclude qsh traffic**: Prevent routing loop

```bash
# Automatic: route to qsh server via original gateway
ip route add <server_ip>/32 via <original_gateway> dev eth0
```

#### Server-Side Routes

Server typically enables:

1. **IP forwarding**: `sysctl net.ipv4.ip_forward=1`
2. **NAT masquerade**: `iptables -t nat -A POSTROUTING -s 10.99.0.0/24 -o eth0 -j MASQUERADE`
3. **Firewall rules**: Allow tunnel subnet

### 10.7 Tunnel Persistence

The tunnel survives connection migration and brief disconnections:

| Event | Tunnel Behavior |
|-------|-----------------|
| QUIC migration | Packets continue flowing |
| Brief disconnect (<30s) | Tun stays up, packets queue |
| Reconnect (0-RTT) | No TunnelConfig needed, resume immediately |
| Reconnect (1-RTT) | Re-send TunnelConfig, server validates |
| Session timeout | Tun torn down on both sides |

### 10.8 Tunnel State Machine

```
                    ┌──────────────┐
                    │   Inactive   │
                    └──────┬───────┘
                           │ --tun flag
                           ▼
                    ┌──────────────┐
                    │ Configuring  │
                    └──────┬───────┘
                           │ TunnelConfigAck(accepted)
                           ▼
                    ┌──────────────┐
              ┌─────│    Active    │◄────────┐
              │     └──────┬───────┘         │
              │            │ disconnect      │ reconnect
              │            ▼                 │
              │     ┌──────────────┐         │
              │     │   Suspended  │─────────┘
              │     └──────┬───────┘
              │            │ session timeout
              │            ▼
              │     ┌──────────────┐
              └────►│  TornDown    │
                    └──────────────┘
```

### 10.9 Platform-Specific Implementation

#### Linux

```rust
// Using /dev/net/tun
let tun = Tun::builder()
    .name("qsh%d")           // Auto-numbered: qsh0, qsh1, ...
    .mtu(1280)
    .address(client_ip)
    .netmask(netmask)
    .up()
    .try_build()?;
```

Requires: `CAP_NET_ADMIN` capability or root.

#### macOS

```rust
// Using utun
let tun = Tun::builder()
    .name("")                // System assigns: utun0, utun1, ...
    .mtu(1280)
    .address(client_ip)
    .destination(server_ip)  // Point-to-point
    .up()
    .try_build()?;
```

Requires: root or entitled binary.

#### Windows

Uses Wintun driver:

```rust
// Using wintun crate
let adapter = Adapter::create("qsh", "qsh Tunnel", None)?;
let session = adapter.start_session(0x400000)?; // 4MB ring buffer
```

Requires: Administrator or Wintun installed.

### 10.10 IPv6 Support

When `ipv6: true` in TunnelConfig:

1. Client and server allocate IPv6 addresses (e.g., `fd00:qsh::2/64`)
2. Both IPv4 and IPv6 packets accepted on tunnel stream
3. IP version determined by first nibble of packet:
   - `0x4_` = IPv4
   - `0x6_` = IPv6

### 10.11 CLI Usage

```bash
# Basic tunnel (auto IP: 10.99.0.2/24)
qsh --tun user@server

# Specify tunnel IP
qsh --tun 10.0.0.2/24 user@server

# Tunnel with specific routes (don't route everything)
qsh --tun --route 192.168.0.0/16 --route 10.0.0.0/8 user@server

# Full VPN (route all traffic)
qsh --tun --route 0.0.0.0/0 user@server

# Tunnel only, no terminal
qsh --tun -N user@server

# Tunnel + port forwards + terminal
qsh --tun -L 5432:db:5432 user@server
```

### 10.12 Security Considerations

| Concern | Mitigation |
|---------|------------|
| Tunnel traffic inspection | Encrypted via QUIC/TLS 1.3 |
| IP spoofing from client | Server validates source IP matches assigned |
| Unauthorized tunnel access | Requires valid session key |
| DNS leaks | Optional DNS push in TunnelConfigAck |
| Routing loops | Automatic exclusion of qsh server IP |

---

## 11. Reconnection Protocol

### 10.1 0-RTT Reconnection

For fast reconnection, qsh uses QUIC 0-RTT when available:

```
0-RTT Reconnection:
  Client                              Server
    │                                   │
    │════ QUIC 0-RTT Connect ══════════►│
    │     (includes Hello in 0-RTT)     │
    │                                   │
    │◄════ QUIC Established ════════════│
    │                                   │
    │◄─── HelloAck (state diff) ────────│
    │                                   │
    │ (session restored in ~100ms)      │
```

### 10.2 Anti-Replay Protection

0-RTT data is vulnerable to replay attacks. qsh mitigates:

| Mechanism | Implementation |
|-----------|----------------|
| Client nonce | Monotonic counter in Hello, persisted to disk |
| Server cache | Sliding window of seen nonces (1 hour) |
| Safe operations | Only idempotent ops (Hello, StateAck) in 0-RTT |
| Input deferral | TerminalInput waits for 1-RTT confirmation |

### 10.3 Reconnection States

```rust
pub enum ConnectionState {
    /// Initial connection
    Connecting,
    
    /// Fully established
    Connected,
    
    /// Connection lost, attempting reconnect
    Reconnecting {
        attempt: u32,
        last_error: String,
        next_retry: Instant,
    },
    
    /// QUIC connection migrating to new path
    Migrating {
        from_addr: SocketAddr,
        to_addr: SocketAddr,
    },
    
    /// Session ended
    Disconnected {
        reason: ShutdownReason,
    },
}
```

### 10.4 Reconnection Backoff

| Attempt | Delay | Jitter |
|---------|-------|--------|
| 1 | 100ms | ±50ms |
| 2 | 200ms | ±100ms |
| 3 | 500ms | ±250ms |
| 4 | 1s | ±500ms |
| 5+ | 2s | ±1s |
| Max | 30s | ±5s |

### 10.5 State Recovery

On reconnect, client sends last known generation:

```rust
pub struct HelloPayload {
    // ... other fields ...
    
    /// Last confirmed state generation (0 if new session)
    pub last_generation: u64,
    
    /// Last confirmed input sequence
    pub last_input_seq: u64,
}
```

Server responds with appropriate diff:

| Condition | Server Action |
|-----------|---------------|
| `last_generation` matches current | Send CursorOnly or empty diff |
| `last_generation` is recent | Send Incremental diff |
| `last_generation` is stale | Send Full state |
| Session not found | Reject with AuthFailure |

---

## 12. Security Considerations

### 11.1 Threat Model

| Threat | Mitigation |
|--------|------------|
| Eavesdropping | TLS 1.3 encryption |
| MITM | Certificate pinning via SSH |
| Replay (1-RTT) | Standard TLS protections |
| Replay (0-RTT) | Nonce + server cache |
| Session hijacking | 256-bit session key |
| Unauthorized server | Cert pinned to bootstrap response |

### 11.2 Session Key Usage

The session key serves as secondary authentication:

1. Generated by server during bootstrap
2. Transmitted over authenticated SSH channel
3. Client includes in Hello message
4. Server validates before accepting session
5. Prevents connection from unauthorized clients

### 11.3 Certificate Handling

```
Bootstrap:
  1. Server generates ephemeral self-signed cert
  2. Cert DER transmitted via SSH
  3. Client pins to exact cert bytes
  
Connection:
  1. QUIC TLS handshake with server cert
  2. Client compares cert to pinned bytes
  3. Reject if mismatch (possible MITM)
```

### 11.4 Forward Security

Port forwards inherit session security:

- All forward traffic encrypted via QUIC
- Forward IDs are session-scoped
- Cannot inject traffic without session key
- Remote forwards require explicit server-side binding

---

## 13. Error Handling

### 12.1 Error Categories

```rust
pub enum ProtocolError {
    /// Version mismatch
    UnsupportedVersion { 
        client: u32, 
        server: u32 
    },
    
    /// Invalid session key
    AuthenticationFailed,
    
    /// Message decode failed
    MalformedMessage { 
        context: String 
    },
    
    /// Unexpected message type
    UnexpectedMessage { 
        expected: String, 
        got: String 
    },
    
    /// State sync failed
    StateSyncFailed { 
        reason: String 
    },
    
    /// Forward error
    ForwardError { 
        forward_id: u64, 
        reason: String 
    },
    
    /// Resource limit exceeded
    ResourceExhausted { 
        resource: String 
    },
}
```

### 12.2 Error Recovery

| Error | Recovery Action |
|-------|-----------------|
| Malformed message | Log, ignore message |
| Unexpected message | Log, ignore message |
| State desync | Request full state |
| Forward failed | Close forward, notify |
| Auth failed | Close connection |
| Version mismatch | Close connection |

### 12.3 Connection Errors

QUIC connection errors bubble up:

| QUIC Error | qsh Behavior |
|------------|--------------|
| Timeout | Enter Reconnecting state |
| Connection refused | Retry with backoff |
| Certificate error | Abort (possible MITM) |
| Stream reset | Close affected stream |

---

## 14. Constants and Limits

### 14.1 Protocol Constants

```rust
/// Current protocol version
pub const PROTOCOL_VERSION: u32 = 1;

/// ALPN identifier
pub const ALPN: &[u8] = b"qsh/1";

/// Session key length in bytes
pub const SESSION_KEY_LEN: usize = 32;

/// Maximum message payload size
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024; // 16 MiB

/// Maximum terminal dimensions
pub const MAX_COLS: u16 = 1000;
pub const MAX_ROWS: u16 = 500;

/// Maximum grapheme cluster length
pub const MAX_GRAPHEME_LEN: usize = 32;
```

### 14.2 Timing Constants

```rust
/// QUIC idle timeout
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Keepalive interval
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// State update debounce
pub const STATE_UPDATE_DEBOUNCE: Duration = Duration::from_millis(10);

/// Reconnection attempt timeout
pub const RECONNECT_TIMEOUT: Duration = Duration::from_secs(60);

/// 0-RTT anti-replay window
pub const ANTI_REPLAY_WINDOW: Duration = Duration::from_secs(3600);
```

### 14.3 Resource Limits

```rust
/// Maximum concurrent forwards
pub const MAX_FORWARDS: usize = 100;

/// Maximum forward data chunk
pub const MAX_FORWARD_CHUNK: usize = 64 * 1024; // 64 KiB

/// Maximum pending predictions
pub const MAX_PENDING_PREDICTIONS: usize = 1000;

/// State history for diffs (generations)
pub const STATE_HISTORY_DEPTH: usize = 100;

/// Anti-replay cache size (nonces)
pub const ANTI_REPLAY_CACHE_SIZE: usize = 10000;

/// Maximum tunnel packet size
pub const MAX_TUNNEL_PACKET: usize = 65535; // Max IP packet

/// Default tunnel MTU
pub const DEFAULT_TUNNEL_MTU: u16 = 1280;

/// Minimum tunnel MTU
pub const MIN_TUNNEL_MTU: u16 = 576; // IPv4 minimum

/// Maximum tunnel MTU
pub const MAX_TUNNEL_MTU: u16 = 9000; // Jumbo frames

/// Default tunnel subnet
pub const DEFAULT_TUNNEL_SUBNET: &str = "10.99.0.0/24";

/// Tunnel read buffer size
pub const TUNNEL_BUFFER_SIZE: usize = 64 * 1024; // 64 KiB
```

### 14.4 Default Values

```rust
/// Default QUIC port range
pub const DEFAULT_PORT_RANGE: Range<u16> = 4500..4600;

/// Default session timeout
pub const DEFAULT_SESSION_TIMEOUT: Duration = Duration::from_secs(86400); // 24h

/// Default TERM value
pub const DEFAULT_TERM: &str = "xterm-256color";

/// Default terminal size
pub const DEFAULT_COLS: u16 = 80;
pub const DEFAULT_ROWS: u16 = 24;
```

---

## Appendix A: Message Size Estimates

| Message Type | Typical Size | Max Size |
|--------------|--------------|----------|
| Hello | ~200 bytes | ~1 KiB |
| HelloAck (no state) | ~100 bytes | ~500 bytes |
| HelloAck (full state) | ~50 KiB | ~5 MiB |
| TerminalInput | ~50 bytes | ~64 KiB |
| StateUpdate (cursor) | ~50 bytes | ~100 bytes |
| StateUpdate (incremental) | ~500 bytes | ~100 KiB |
| StateUpdate (full) | ~50 KiB | ~5 MiB |
| ForwardData | ~1 KiB | ~64 KiB |
| TunnelConfig | ~100 bytes | ~1 KiB |
| TunnelConfigAck | ~150 bytes | ~2 KiB |
| TunnelPacket | ~500 bytes | ~64 KiB |

---

## Appendix B: State Machine Diagrams

### B.1 Client Connection State

```
                    ┌──────────────┐
                    │   Initial    │
                    └──────┬───────┘
                           │ connect()
                           ▼
                    ┌──────────────┐
              ┌─────│  Connecting  │─────┐
              │     └──────┬───────┘     │
              │            │ connected   │ timeout/error
              │            ▼             │
              │     ┌──────────────┐     │
              │     │  Connected   │◄────┼────────────┐
              │     └──────┬───────┘     │            │
              │            │ lost        │            │ reconnected
              │            ▼             │            │
              │     ┌──────────────┐     │     ┌──────┴──────┐
              │     │ Reconnecting │─────┴────►│Disconnected │
              │     └──────────────┘ max       └─────────────┘
              │                       retries
              └───────────────────────────────────────┘
```

### B.2 Server Session State

```
                    ┌──────────────┐
                    │  Listening   │
                    └──────┬───────┘
                           │ accept
                           ▼
                    ┌──────────────┐
                    │   AwaitHello │
                    └──────┬───────┘
                           │ valid Hello
                           ▼
                    ┌──────────────┐
                    │    Active    │◄─────────┐
                    └──────┬───────┘          │
                           │ disconnect       │ reconnect
                           ▼                  │
                    ┌──────────────┐          │
                    │   Detached   │──────────┘
                    └──────┬───────┘
                           │ timeout
                           ▼
                    ┌──────────────┐
                    │  Terminated  │
                    └──────────────┘
```

---

## Appendix C: Example Message Traces

### C.1 Normal Session Startup

```
# SSH Bootstrap (via SSH channel)
→ exec: qsh-server --bootstrap
← {"version":1,"quic_port":4500,"session_key":"...","cert_der":"..."}

# QUIC Connection (UDP)
→ QUIC Initial
← QUIC Handshake
→ QUIC Handshake
← QUIC Handshake Done

# Control Stream (Stream 0)
→ Hello { version: 1, session_key: [...], term_size: {80, 24}, ... }
← HelloAck { accepted: true, initial_state: Some(...), ... }

# Terminal Streams
→ TerminalInput { seq: 1, data: [0x6C, 0x73, 0x0A], predictable: true } // "ls\n"
← StateUpdate { diff: Incremental(...), confirmed_input_seq: 1 }
→ StateAck { generation: 5 }
```

### C.2 Reconnection After Network Change

```
# Connection lost (QUIC timeout)

# New QUIC connection (0-RTT)
→ QUIC 0-RTT Initial + Hello { last_generation: 42, ... }
← QUIC Handshake
← HelloAck { accepted: true, initial_state: Some(Incremental from 42) }
→ StateAck { generation: 43 }

# Session continues
→ TerminalInput { seq: 100, data: [...] }
```

### C.3 Local Port Forward

```
# On control stream
→ ForwardRequest { forward_id: 0, spec: Local { bind_port: 5432 }, target: "db:5432" }
← ForwardAccept { forward_id: 0 }

# On new forward stream
→ ForwardData { forward_id: 0, data: [...] }  // SQL query
← ForwardData { forward_id: 0, data: [...] }  // SQL response
→ ForwardEof { forward_id: 0 }                // Client done sending
← ForwardEof { forward_id: 0 }                // Server done sending
← ForwardClose { forward_id: 0, reason: None }
```

### C.4 IP Tunnel Setup and Traffic

```
# Tunnel stream (Stream 4)
→ TunnelConfig { 
    client_ip: 10.99.0.2/24, 
    mtu: 1280, 
    requested_routes: [], 
    ipv6: false 
  }
← TunnelConfigAck { 
    accepted: true, 
    server_ip: 10.99.0.1/24, 
    mtu: 1280, 
    routes: [0.0.0.0/0],
    dns_servers: [10.99.0.1] 
  }

# IP packets (ICMP ping example)
→ TunnelPacket { packet: [0x45, 0x00, 0x00, 0x54, ...] }  // ICMP Echo Request
← TunnelPacket { packet: [0x45, 0x00, 0x00, 0x54, ...] }  // ICMP Echo Reply

# IPv6 packet (if enabled)
→ TunnelPacket { packet: [0x60, 0x00, 0x00, 0x00, ...] }  // IPv6 packet
```

### C.5 Tunnel Reconnection

```
# Connection lost, tunnel suspended
# Tun interface stays up, packets queue

# Reconnect (0-RTT)
→ QUIC 0-RTT Initial + Hello { last_generation: 100, ... }
← HelloAck { accepted: true, ... }

# Tunnel resumes immediately (no TunnelConfig needed)
→ TunnelPacket { packet: [...] }  // Queued packets flush
← TunnelPacket { packet: [...] }
```

---

*Document generated December 2025*
