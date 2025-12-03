# qsh — Product Requirements Document

**A Modern, Roaming-Capable Remote Terminal**

| Field | Value |
|-------|-------|
| Version | 1.1 |
| Status | Draft |
| Last Updated | December 2025 |

---

> **Note on Tunnel Feature**
> 
> The IP tunnel (VPN) functionality described in [Section 6.4](#64-ip-tunnel-vpn) is implemented under the `tunnel` feature flag and initially supports **Linux only**. This allows the core terminal to ship without tunnel dependencies while enabling gradual platform expansion.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement](#2-problem-statement)
3. [Goals and Non-Goals](#3-goals-and-non-goals)
4. [Technical Architecture](#4-technical-architecture)
5. [Security Model](#5-security-model)
6. [Feature Specifications](#6-feature-specifications)
7. [Terminal Emulation](#7-terminal-emulation)
8. [Status Overlay](#8-status-overlay)
9. [Logging and Debugging](#9-logging-and-debugging)
10. [Command-Line Interface](#10-command-line-interface)
11. [Implementation Roadmap](#11-implementation-roadmap)
12. [Technology Stack](#12-technology-stack)
13. [Success Metrics](#13-success-metrics)
14. [Risks and Mitigations](#14-risks-and-mitigations)
15. [Appendix](#15-appendix)

---

## 1. Executive Summary

**qsh** is a next-generation remote terminal application designed to replace and improve upon mosh (mobile shell). Built in Rust with QUIC as the transport protocol, qsh provides a seamless, roaming-capable terminal experience that maintains session continuity across network changes, IP migrations, and connection interruptions.

The product leverages SSH for secure authentication and session bootstrapping, then transitions to QUIC for the active session. This architecture combines the trust model and ubiquity of SSH with the modern transport capabilities of QUIC, including connection migration, multiplexed streams, and 0-RTT session resumption.

### Key Differentiators

- **Sub-100ms reconnection** via QUIC 0-RTT session resumption
- **Full port forwarding** support (-L, -R, -D) with roaming capability
- **IP tunnel (VPN)** for full network access through the session (Linux, feature-flagged)
- **Real-time status overlay** showing connection health, latency, and session info
- **Predictive local echo** for responsive typing on high-latency links
- **No new credentials** — uses existing SSH authentication

---

## 2. Problem Statement

### 2.1 Current Challenges

Remote terminal users face several persistent challenges with existing solutions:

- **SSH sessions terminate** when IP addresses change (WiFi → cellular, VPN reconnection)
- **High latency connections** create sluggish typing experiences with delayed echo
- **TCP head-of-line blocking** degrades multiplexed session performance
- **Mosh limitations**: custom UDP protocol lacks modern transport features; no port forwarding
- **Lack of visibility**: users have no insight into connection health or session state

### 2.2 Target Users

| User Type | Primary Need |
|-----------|--------------|
| DevOps Engineers | Reliable remote infrastructure management from varying networks |
| Mobile Developers | Uninterrupted sessions while commuting or traveling |
| System Administrators | Long-running sessions that survive network disruptions |
| Security Professionals | Roaming-capable tunnels for penetration testing |

---

## 3. Goals and Non-Goals

### 3.1 Goals

1. Seamless session continuity across network changes and IP migrations
2. Sub-100ms reconnection using QUIC 0-RTT session resumption
3. Local echo prediction for responsive typing on high-latency connections
4. Full SSH-compatible authentication (no new credentials to manage)
5. Complete port forwarding: local (-L), remote (-R), and dynamic SOCKS5 (-D)
6. IP tunnel (VPN) for roaming-capable full network access (Linux initially, feature-flagged)
7. Real-time status overlay with connection metrics and session information
8. Comprehensive logging for debugging (client and server)
9. Modern cryptography with perfect forward secrecy via TLS 1.3
10. Cross-platform support: Linux, macOS, Windows (tunnel feature Linux-only initially)

### 3.2 Non-Goals

1. Replacing SSH for non-interactive use cases (scp, sftp, git)
2. Implementing a custom authentication system
3. X11 forwarding (may be added in future versions)
4. SSH agent forwarding (future version)
5. Backward compatibility with mosh protocol

---

## 4. Technical Architecture

### 4.1 System Overview

qsh uses a two-phase connection model:

```
┌──────────────────────────────────────────────────────────────────────┐
│  Phase 1: SSH Bootstrap                                              │
│  ┌────────┐         SSH          ┌────────────┐                     │
│  │ Client │ ─────────────────────► │ SSH Server │                    │
│  └────────┘   (auth, start qsh-server)  └────────────┘               │
│       │                                      │                       │
│       │◄──── port, session_key, cert ────────│                       │
│       │                                                              │
│  [SSH disconnects]                                                   │
│                                                                      │
│  Phase 2: QUIC Session                                               │
│  ┌────────┐        QUIC          ┌────────────┐                     │
│  │ Client │ ◄═══════════════════► │ qsh-server │                     │
│  └────────┘   (terminal, tunnels) └────────────┘                     │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

**Phase 1 — SSH Bootstrap**: Client authenticates via SSH, starts the qsh-server daemon. Server generates ephemeral TLS credentials and a session key, transmits them back through the secure SSH channel.

**Phase 2 — QUIC Session**: Using credentials from SSH, client establishes QUIC connection for all terminal I/O and port forwarding with full connection migration and 0-RTT support.

### 4.2 Component Architecture

| Component | Description |
|-----------|-------------|
| `qsh` (client) | Terminal client: user input, local echo prediction, state sync, port forwarding listeners, status overlay |
| `qsh-server` | Server daemon: PTY management, terminal state, port forwarding, QUIC endpoint |
| `libqsh` | Shared library: protocol definitions, state sync algorithms, crypto utilities |

### 4.3 Protocol Design

#### 4.3.1 Stream Multiplexing

QUIC provides native stream multiplexing, eliminating head-of-line blocking:

| Stream Type | Direction | Purpose |
|-------------|-----------|---------|
| Control | Bidirectional | Session management, resize, keepalives, metrics |
| Terminal State | Server → Client | Screen state diffs, cursor position |
| Terminal Input | Client → Server | Keystrokes, paste operations |
| Port Forward | Bidirectional | One stream per forwarded connection |

#### 4.3.2 Terminal State Synchronization

The server maintains authoritative terminal state, parsed from PTY output using VT100/xterm escape sequences. Updates transmitted as diffs:

- **Full state**: Complete screen (initial connect, major desync)
- **Incremental diff**: Changed cells only, with generation numbers
- **Cursor-only**: Fast updates for cursor movement

#### 4.3.3 Predictive Local Echo

For responsive typing on high-latency connections:

1. Printable characters displayed immediately with visual distinction (underline)
2. Predictions tagged with sequence numbers
3. Server confirmations remove prediction markers
4. Mispredictions trigger state resync

---

## 5. Security Model

### 5.1 Authentication

qsh inherits SSH's authentication model:

- Public key authentication (recommended)
- Password authentication
- SSH agent forwarding (future release; not supported in initial scope)
- Host key verification via `known_hosts`

### 5.2 Transport Security

QUIC connection uses TLS 1.3 with ephemeral credentials:

1. Server generates self-signed certificate (valid only for session)
2. Certificate transmitted to client over authenticated SSH channel
3. Client pins to exact certificate bytes (no CA trust required)
4. X25519 key exchange provides perfect forward secrecy
5. 256-bit session key provides additional client authentication

### 5.3 0-RTT Security

0-RTT resumption requires anti-replay protection:

| Mechanism | Implementation |
|-----------|----------------|
| Client nonce | Monotonically increasing per session |
| Server cache | Sliding window anti-replay filter |
| Safe operations | Only idempotent ops (state sync) in 0-RTT |
| Input deferral | User input waits for 1-RTT completion |

### 5.4 Security Properties

| Property | Implementation |
|----------|----------------|
| Server Authentication | Certificate pinned to bytes received via SSH |
| Client Authentication | SSH auth (bootstrap) + session key (QUIC) |
| Forward Secrecy | Ephemeral X25519 keys per connection |
| MITM Prevention | Credentials delivered over authenticated SSH |
| Replay Protection | Per-session nonce + server anti-replay cache |

---

## 6. Feature Specifications

### 6.1 Terminal Session

| Feature | Specification |
|---------|---------------|
| PTY Allocation | Full PTY with configurable TERM (default: xterm-256color) |
| Window Resize | Real-time propagation via SIGWINCH |
| Unicode Support | Full UTF-8, including wide characters and emoji |
| Color Support | True color (24-bit) and 256-color modes |
| Local Echo | Predictive echo with visual feedback |

### 6.2 Port Forwarding

#### Local Forwarding (-L)

Binds local port, forwards through server to remote target:

```bash
qsh -L [bind_address:]port:host:hostport user@server

# Example: Access remote PostgreSQL locally
qsh -L 5432:db.internal:5432 user@bastion
```

#### Remote Forwarding (-R)

Binds port on server, forwards to local target:

```bash
qsh -R [bind_address:]port:host:hostport user@server

# Example: Expose local dev server remotely
qsh -R 8080:localhost:3000 user@server
```

#### Dynamic Forwarding (-D)

Creates SOCKS5 proxy:

```bash
qsh -D [bind_address:]port user@server

# Example: Route browser through server
qsh -D 1080 user@bastion
```

### 6.3 Connection Resilience

| Scenario | Behavior | Recovery Time |
|----------|----------|---------------|
| IP Address Change | QUIC connection migration | < 500ms |
| Brief Network Loss | 0-RTT reconnection | ~100ms |
| Extended Outage | Session persists, reconnect with state sync | < 2s |
| Laptop Suspend/Resume | 0-RTT resumption, full state recovery | ~100ms |

### 6.4 IP Tunnel (VPN)

> **Implementation Note**: This feature is gated behind `--features tunnel` and initially supports **Linux only**. macOS and Windows support planned for future releases.

The IP tunnel provides Layer 3 VPN functionality over the qsh session, enabling full network access through the encrypted QUIC connection.

#### Use Cases

| Use Case | Description |
|----------|-------------|
| Full VPN | Route all traffic through the remote server |
| Split Tunnel | Access specific subnets (e.g., internal networks) via the tunnel |
| Roaming VPN | VPN that survives network changes, unlike traditional solutions |
| Pentest Pivot | Maintain network access during security assessments |

#### CLI Usage

```bash
# Basic tunnel (auto IP: 10.99.0.2/24)
qsh --tun user@server

# Specify tunnel IP
qsh --tun 10.0.0.2/24 user@server

# Full VPN (route all traffic)
qsh --tun --route 0.0.0.0/0 user@server

# Split tunnel (specific subnets only)
qsh --tun --route 192.168.0.0/16 --route 10.0.0.0/8 user@server

# Tunnel only, no terminal
qsh --tun -N user@server

# Tunnel + port forwards + terminal
qsh --tun -L 5432:db:5432 user@server
```

#### Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│ Tunnel Data Flow                                                    │
│                                                                    │
│  Client Machine                          Server Machine            │
│  ┌─────────────┐                        ┌─────────────┐           │
│  │ Application │                        │ Destination │           │
│  └──────┬──────┘                        └──────▲──────┘           │
│         │ IP packets                           │                  │
│         ▼                                      │                  │
│  ┌─────────────┐                        ┌──────┴──────┐           │
│  │  tun0       │                        │  tun0       │           │
│  │ 10.99.0.2   │                        │ 10.99.0.1   │           │
│  └──────┬──────┘                        └──────▲──────┘           │
│         │                                      │                  │
│  ┌──────┴──────┐      TunnelPacket      ┌──────┴──────┐           │
│  │    qsh      │ ══════════════════════►│ qsh-server  │           │
│  │   client    │◄══════════════════════ │             │           │
│  └─────────────┘   (over QUIC stream)   └─────────────┘           │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

#### Features

| Feature | Description |
|---------|-------------|
| Auto IP Assignment | Client proposes IP, server confirms or assigns |
| Route Pushing | Server can push routes to client |
| DNS Configuration | Server can push DNS servers |
| IPv6 Support | Optional IPv6 in addition to IPv4 |
| MTU Negotiation | Automatic MTU adjustment for path |
| Reconnection | Tunnel survives reconnects without reconfiguration |

#### Comparison with Traditional VPNs

| Aspect | WireGuard/OpenVPN | qsh Tunnel |
|--------|-------------------|------------|
| Setup | Separate keys/config | Uses SSH auth |
| Roaming | Limited/none | Full QUIC migration |
| Reconnect | Seconds | ~100ms (0-RTT) |
| Port Forwards | Separate feature | Integrated |
| Terminal | Separate SSH | Integrated |

#### Requirements

- **Linux**: Requires `CAP_NET_ADMIN` capability or root
- **Build**: `cargo build --features tunnel`
- **Server**: IP forwarding enabled, optional NAT

---

## 7. Terminal Emulation

### 7.1 Overview

Proper ANSI escape code handling is critical for a seamless terminal experience. qsh must faithfully transmit all escape sequences between the server PTY and client terminal, ensuring applications like vim, tmux, htop, and modern CLI tools render correctly.

### 7.2 Design Philosophy

qsh uses a **hybrid approach**:

1. **Pass-through mode**: Raw escape sequences forwarded directly for real-time display
2. **State tracking**: Server parses sequences to maintain authoritative screen state for reconnection/sync
3. **Transparent proxy**: Client terminal capabilities negotiated end-to-end

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  PTY Output Flow                                                            │
│                                                                             │
│  ┌─────────┐      ┌─────────────┐      ┌─────────┐      ┌──────────────┐   │
│  │ Shell/  │ ───► │ PTY Master  │ ───► │ qsh-    │ ───► │ qsh client   │   │
│  │ App     │      │             │      │ server  │      │              │   │
│  └─────────┘      └─────────────┘      └─────────┘      └──────────────┘   │
│       │                                     │                   │           │
│       │ Raw bytes with                      │ Parse + forward   │ Forward   │
│       │ ANSI escapes                        │ (dual path)       │ to TTY    │
│       ▼                                     ▼                   ▼           │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ Examples:                                                            │   │
│  │ • \x1b[31m         → Set foreground red                             │   │
│  │ • \x1b[38;2;255;128;0m → True color (RGB)                           │   │
│  │ • \x1b[?1049h      → Switch to alternate screen                     │   │
│  │ • \x1b]0;title\x07 → Set window title                               │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 7.3 Supported Escape Sequences

#### 7.3.1 CSI Sequences (Control Sequence Introducer)

| Category | Sequences | Description |
|----------|-----------|-------------|
| **Cursor Movement** | `CUU`, `CUD`, `CUF`, `CUB`, `CUP`, `HVP` | Up, down, forward, back, position |
| **Cursor Style** | `DECSCUSR` | Block, underline, bar (blinking/steady) |
| **Cursor Save/Restore** | `DECSC`, `DECRC`, `s`, `u` | Save and restore cursor state |
| **Erase** | `ED`, `EL`, `DECSEL`, `DECSED` | Erase display/line variants |
| **Scroll** | `SU`, `SD`, `DECSTBM` | Scroll up/down, set scroll region |
| **Text Formatting** | `SGR` | All attributes (see 7.3.2) |
| **Mode Setting** | `SM`, `RM`, `DECSET`, `DECRST` | Terminal modes |
| **Device Status** | `DSR`, `DA` | Status reports, device attributes |
| **Window Ops** | `XTWINOPS` | Resize, move, report size |

#### 7.3.2 SGR (Select Graphic Rendition) — Full Support

| Code | Attribute | Notes |
|------|-----------|-------|
| 0 | Reset all | |
| 1, 2, 3, 4, 5, 7, 8, 9 | Bold, dim, italic, underline, blink, reverse, hidden, strikethrough | |
| 21, 22, 23, 24, 25, 27, 28, 29 | Reset individual attributes | |
| 30-37 | Foreground colors (standard) | 8 colors |
| 38;5;N | Foreground 256-color | Indexed palette |
| 38;2;R;G;B | Foreground true color | 24-bit RGB |
| 40-47 | Background colors (standard) | 8 colors |
| 48;5;N | Background 256-color | Indexed palette |
| 48;2;R;G;B | Background true color | 24-bit RGB |
| 53, 55 | Overline on/off | |
| 58;2;R;G;B | Underline color | |
| 90-97, 100-107 | Bright foreground/background | 8 bright colors |

#### 7.3.3 OSC Sequences (Operating System Command)

| OSC | Purpose | Support |
|-----|---------|---------|
| 0, 1, 2 | Set icon name / window title | ✅ Full |
| 4 | Set/query color palette | ✅ Full |
| 7 | Current working directory | ✅ Full |
| 8 | Hyperlinks | ✅ Full |
| 9 | Desktop notification (iTerm2) | ✅ Pass-through |
| 10, 11, 12 | Foreground/background/cursor color | ✅ Full |
| 52 | Clipboard access | ⚠️ Configurable (security) |
| 104 | Reset color | ✅ Full |
| 110, 111, 112 | Reset fg/bg/cursor color | ✅ Full |
| 133 | Shell integration (prompt markers) | ✅ Pass-through |
| 1337 | iTerm2 proprietary | ✅ Pass-through |

#### 7.3.4 DCS Sequences (Device Control String)

| Sequence | Purpose | Support |
|----------|---------|---------|
| DECRQSS | Request setting | ✅ Full |
| XTGETTCAP | Query terminfo | ✅ Full |
| Sixel | Inline graphics | ⚠️ Pass-through (no state tracking) |
| tmux control mode | tmux integration | ⚠️ Pass-through |

#### 7.3.5 Private Modes (DECSET/DECRST)

| Mode | Name | Description |
|------|------|-------------|
| 1 | DECCKM | Application cursor keys |
| 7 | DECAWM | Auto-wrap mode |
| 12 | Cursor blink | |
| 25 | DECTCEM | Cursor visibility |
| 47 | Alternate screen (old) | |
| 1000-1006 | Mouse tracking | Various modes |
| 1047 | Alternate screen buffer | |
| 1048 | Save/restore cursor | |
| 1049 | Alternate screen + cursor | Combined (vim, less) |
| 2004 | Bracketed paste | |
| 2026 | Synchronized output | Reduce flicker |

### 7.4 Terminal Capability Negotiation

#### 7.4.1 TERM Environment Variable

qsh preserves the client's TERM value when possible, falling back gracefully:

```
Client TERM        Server TERM         Notes
─────────────────────────────────────────────────────
xterm-256color  →  xterm-256color      Preferred
xterm-direct    →  xterm-direct        True color
alacritty       →  alacritty           If terminfo exists, else xterm-256color
tmux-256color   →  tmux-256color       Nested tmux
screen-256color →  screen-256color     Nested screen
dumb            →  dumb                Minimal
```

#### 7.4.2 Terminfo Synchronization

If client's TERM is not available on server, qsh can:

1. **Fallback**: Use `xterm-256color` (widely compatible)
2. **Upload**: Transfer terminfo entry via side channel (future)
3. **Query**: Use XTGETTCAP to probe capabilities

#### 7.4.3 Capability Detection

qsh probes terminal capabilities on startup:

```rust
pub struct TerminalCapabilities {
    pub colors: ColorSupport,       // 16, 256, or TrueColor
    pub unicode: UnicodeSupport,    // Narrow, Wide, Emoji
    pub mouse: MouseSupport,        // None, Basic, SGR, URxvt
    pub bracketed_paste: bool,
    pub synchronized_output: bool,
    pub sixel: bool,
    pub hyperlinks: bool,
    pub kitty_keyboard: bool,       // Kitty keyboard protocol
}

pub enum ColorSupport {
    Basic16,
    Palette256,
    TrueColor,
}
```

### 7.5 State Synchronization

#### 7.5.1 What Gets Tracked

The server maintains full terminal state for reconnection:

| State | Tracked | Notes |
|-------|---------|-------|
| Cell contents (chars) | ✅ | Per-cell Unicode grapheme |
| Cell attributes | ✅ | FG, BG, bold, italic, etc. |
| Cursor position | ✅ | Row, column |
| Cursor style | ✅ | Shape, blink, visibility |
| Scroll region | ✅ | Top/bottom margins |
| Character sets | ✅ | G0-G3 designations |
| Modes | ✅ | Origin, wrap, insert, etc. |
| Tab stops | ✅ | Custom tab positions |
| Window title | ✅ | For overlay display |
| Alternate screen | ✅ | Both buffers preserved |

#### 7.5.2 What Gets Passed Through (Not Tracked)

Some sequences are forwarded without state tracking:

| Sequence | Reason |
|----------|--------|
| Sixel graphics | Stateless image data |
| iTerm2 inline images | Stateless |
| Desktop notifications | Side effect only |
| Clipboard operations | Security-sensitive |
| Audio bell | Side effect only |

### 7.6 Reconnection Behavior

On reconnect, qsh restores terminal state:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Reconnection Sequence                                                       │
│                                                                             │
│ 1. Client connects (0-RTT if available)                                    │
│ 2. Server sends state diff since last confirmed generation                 │
│ 3. Client applies diff:                                                    │
│    a. Switch to correct screen buffer (main/alt)                           │
│    b. Restore scroll region                                                │
│    c. Apply cell contents and attributes                                   │
│    d. Restore cursor position and style                                    │
│    e. Restore terminal modes                                               │
│ 4. Client confirms sync complete                                           │
│ 5. Normal streaming resumes                                                │
│                                                                             │
│ Total time: ~100ms (0-RTT) to ~300ms (full handshake)                      │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 7.7 Edge Cases and Compatibility

#### 7.7.1 Wide Characters (CJK, Emoji)

- Each cell stores full grapheme cluster
- Width calculated using Unicode UAX #11
- Emoji with ZWJ sequences handled correctly
- State diff includes width metadata

#### 7.7.2 Combining Characters

- Combining marks attached to base character
- Cell stores complete grapheme
- Example: `é` = `e` + `\u0301` stored as single unit

#### 7.7.3 Bidirectional Text

- Pass-through to client terminal
- No server-side reordering
- RTL handling delegated to client

#### 7.7.4 Long Lines and Wrap

- Soft wrap tracked separately from hard newlines
- Resize triggers reflow on server
- State includes wrap points for accurate sync

### 7.8 Known Limitations

| Limitation | Impact | Workaround |
|------------|--------|------------|
| Sixel not tracked | Graphics lost on reconnect | Apps redraw on SIGWINCH |
| No kitty graphics protocol | Static images only | Use sixel or iTerm2 |
| OSC 52 clipboard | Security restriction | Enable with `--allow-clipboard` |
| 1ms+ sync delay | Slight flicker on reconnect | Synchronized output mode |

### 7.9 Testing Matrix

qsh must pass rendering tests with:

| Application | Test Cases |
|-------------|------------|
| vim/neovim | Syntax highlighting, splits, true color themes |
| tmux | Nested sessions, status bar, colors |
| htop | Real-time updates, colors, graphs |
| less | Alternate screen, search highlighting |
| git log --graph | Unicode box drawing, colors |
| fzf | Popup windows, mouse support |
| bat | Syntax highlighting, line numbers |
| delta | Side-by-side diffs, true color |
| lazygit | TUI, mouse, colors |
| btop | Graphs, Unicode, true color |

---

## 8. Status Overlay

### 8.1 Overview

The status overlay provides real-time visibility into connection health and session state. It can be toggled with a keybinding and displays critical metrics without interrupting terminal use.

### 8.2 Activation

| Keybinding | Action |
|------------|--------|
| `Ctrl+Shift+S` | Toggle status overlay on/off |
| `Ctrl+Shift+D` | Show overlay for 3 seconds (peek) |
| `~.` | Disconnect (SSH-style escape) |
| `~s` | Toggle overlay (alternative) |

> **Note**: The escape character (`~`) only works after a newline, following SSH conventions.

### 8.3 Overlay Display

The overlay renders as a semi-transparent bar at the top or bottom of the terminal (configurable):

```
┌─────────────────────────────────────────────────────────────────────────┐
│ qsh │ 192.168.1.50:4500 │ RTT: 45ms │ ↑ 1.2KB/s ↓ 3.4KB/s │ Session: 2h │
└─────────────────────────────────────────────────────────────────────────┘
```

### 8.4 Metrics Displayed

| Metric | Description | Update Frequency |
|--------|-------------|------------------|
| **Connection Status** | `Connected`, `Reconnecting`, `Migrating` | Real-time |
| **Server Address** | Remote IP:port | On change |
| **Local Address** | Client IP (shows migration) | On change |
| **RTT (Latency)** | Round-trip time in ms | 1s (smoothed) |
| **Jitter** | RTT variance | 5s |
| **Packet Loss** | Percentage over sliding window | 5s |
| **Bandwidth** | Upload/download rates | 1s |
| **Session Duration** | Time since connection established | 1s |
| **State Generation** | Terminal state sync version | On change |
| **Pending Predictions** | Unconfirmed local echo count | Real-time |
| **Forwarded Connections** | Active tunnel count | On change |
| **0-RTT Status** | Whether 0-RTT is available | On connect |
| **Encryption** | Cipher suite in use | On connect |

### 8.5 Visual Indicators

Status indicators use color coding:

| Indicator | Color | Meaning |
|-----------|-------|---------|
| ● | Green | Connected, healthy (RTT < 100ms) |
| ● | Yellow | Connected, degraded (RTT 100-300ms or loss > 1%) |
| ● | Red | Reconnecting or connection issues |
| ● | Blue | Connection migrating |

### 8.6 Overlay Positions

Configurable via `--overlay-position`:

- `top` — Full-width bar at top (default)
- `bottom` — Full-width bar at bottom
- `top-right` — Compact badge, top-right corner
- `none` — Disabled (metrics still logged)

### 8.7 Implementation

```rust
pub struct OverlayState {
    visible: bool,
    position: OverlayPosition,
    metrics: ConnectionMetrics,
    last_update: Instant,
}

pub struct ConnectionMetrics {
    pub status: ConnectionStatus,
    pub remote_addr: SocketAddr,
    pub local_addr: SocketAddr,
    pub rtt_ms: f64,
    pub rtt_smoothed_ms: f64,
    pub jitter_ms: f64,
    pub packet_loss_pct: f64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub bandwidth_up: f64,      // bytes/sec
    pub bandwidth_down: f64,    // bytes/sec
    pub session_start: Instant,
    pub state_generation: u64,
    pub pending_predictions: usize,
    pub active_forwards: usize,
    pub zero_rtt_available: bool,
    pub cipher_suite: String,
    
    // Tunnel metrics (feature = "tunnel")
    #[cfg(feature = "tunnel")]
    pub tunnel: Option<TunnelMetrics>,
}

#[cfg(feature = "tunnel")]
pub struct TunnelMetrics {
    pub status: TunnelStatus,
    pub local_ip: IpNet,
    pub remote_ip: IpNet,
    pub packets_sent: u64,
    pub packets_recv: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
}

#[cfg(feature = "tunnel")]
pub enum TunnelStatus {
    Active,
    Suspended,
    Configuring,
}

pub enum ConnectionStatus {
    Connected,
    Reconnecting { attempt: u32, last_error: String },
    Migrating { from: SocketAddr, to: SocketAddr },
    Disconnected { reason: String },
}
```

---

## 9. Logging and Debugging

### 9.1 Client Verbose Mode

The client supports multiple verbosity levels via `-v` flags:

| Flag | Level | Output |
|------|-------|--------|
| (none) | Error | Critical errors only |
| `-v` | Warn | Warnings and errors |
| `-vv` | Info | Connection events, state syncs |
| `-vvv` | Debug | Detailed protocol messages |
| `-vvvv` | Trace | Full packet-level tracing |

Example output at `-vv`:

```
[2025-12-01T10:23:45Z INFO  qsh] Bootstrapping via SSH to user@server:22
[2025-12-01T10:23:46Z INFO  qsh] SSH authentication successful
[2025-12-01T10:23:46Z INFO  qsh] Server allocated QUIC port 4500
[2025-12-01T10:23:46Z INFO  qsh] QUIC connection established (0-RTT: available)
[2025-12-01T10:23:46Z INFO  qsh] Session authenticated, receiving initial state
[2025-12-01T10:23:46Z INFO  qsh] Terminal ready (80x24)
[2025-12-01T10:25:12Z INFO  qsh] Network change detected, migrating connection
[2025-12-01T10:25:12Z INFO  qsh] Migration complete: 192.168.1.50 → 10.0.0.15
```

### 9.2 Server Verbose Mode

The server supports identical verbosity levels via `--verbose` / `-v`:

```bash
qsh-server --bootstrap -vvv
```

| Flag | Level | Output |
|------|-------|--------|
| (none) | Error | Critical errors only |
| `-v` | Warn | Client events, auth failures |
| `-vv` | Info | Session lifecycle, forwarding setup |
| `-vvv` | Debug | PTY I/O, state diff details |
| `-vvvv` | Trace | Full packet/stream tracing |

Example output at `-vv`:

```
[2025-12-01T10:23:46Z INFO  qsh-server] Starting in bootstrap mode
[2025-12-01T10:23:46Z INFO  qsh-server] Generated ephemeral certificate (SHA256: 3f8a...)
[2025-12-01T10:23:46Z INFO  qsh-server] Listening on 0.0.0.0:4500
[2025-12-01T10:23:46Z INFO  qsh-server] Client connected from 192.168.1.50:54321
[2025-12-01T10:23:46Z INFO  qsh-server] Session key verified, spawning PTY
[2025-12-01T10:23:46Z INFO  qsh-server] PTY allocated: /dev/pts/5 (bash)
[2025-12-01T10:25:12Z INFO  qsh-server] Client migrated: 192.168.1.50 → 10.0.0.15
[2025-12-01T10:30:00Z INFO  qsh-server] Local forward established: 5432 → db.internal:5432
```

### 9.3 Log Destinations

| Destination | Flag | Description |
|-------------|------|-------------|
| stderr | (default) | Standard error output |
| File | `--log-file PATH` | Append to specified file |
| Syslog | `--syslog` | System logging (server only) |
| Journald | `--journald` | Systemd journal (Linux server) |

### 9.4 Structured Logging

JSON output available for log aggregation:

```bash
qsh -vvv --log-format json user@server 2>qsh.log
```

```json
{"timestamp":"2025-12-01T10:23:46Z","level":"INFO","target":"qsh::quic","message":"Connection established","remote_addr":"192.168.1.100:4500","rtt_ms":45.2}
```

### 9.5 Debug Commands

In-session debug commands (escape sequence `~`):

| Command | Action |
|---------|--------|
| `~?` | Show available escape commands |
| `~s` | Toggle status overlay |
| `~v` | Print current connection metrics to terminal |
| `~r` | Force reconnection (for testing) |
| `~#` | List active forwarded connections |
| `~.` | Disconnect and exit |

---

## 10. Command-Line Interface

### 10.1 Client Usage

```
qsh [OPTIONS] [user@]hostname [command]

ARGUMENTS:
    <destination>    Remote host (user@host or host)
    [command]        Command to execute (optional, default: shell)

OPTIONS:
    -p, --port <PORT>           SSH port for bootstrap [default: 22]
    -l, --login <USER>          Login username
    
    -L <SPEC>                   Local port forwarding [bind_addr:]port:host:hostport
    -R <SPEC>                   Remote port forwarding [bind_addr:]port:host:hostport
    -D <PORT>                   Dynamic SOCKS5 forwarding [bind_addr:]port
    
    --tun [IP/MASK]             Enable IP tunnel (Linux only, requires CAP_NET_ADMIN)
                                Optional: specify client IP [default: 10.99.0.2/24]
    --route <CIDR>              Route subnet through tunnel (repeatable)
                                Use 0.0.0.0/0 for full VPN
    --tun-mtu <MTU>             Tunnel MTU [default: 1280]
    
    -N                          No PTY (forwarding/tunnel only)
    -f                          Background after connection
    -t                          Force PTY allocation
    -T                          Disable PTY allocation
    
    -v, --verbose               Increase verbosity (use multiple times)
    --log-file <PATH>           Write logs to file
    --log-format <FMT>          Log format: text, json [default: text]
    
    --overlay-position <POS>    Status overlay: top, bottom, top-right, none
    --no-overlay                Disable status overlay
    --overlay-key <KEY>         Custom overlay toggle key [default: ctrl+shift+s]
    
    -o <OPTION>                 SSH-style options (limited support)
    -F <FILE>                   SSH config file for host aliases
    
    -h, --help                  Print help
    -V, --version               Print version
```

### 10.2 Server Usage

```
qsh-server [OPTIONS]

OPTIONS:
    --bootstrap                 Run in bootstrap mode (started via SSH)
    --session-timeout <SECS>    Idle timeout [default: 86400 (24h)]
    --session-linger <SECS>     Keep detached sessions alive [default: 172800 (48h), env: QSH_SESSION_LINGER_SECS]
    --max-forwards <N>          Maximum concurrent forwards [default: 100]
    
    --allow-tunnel              Enable IP tunnel support (Linux only)
    --tun-subnet <CIDR>         Tunnel IP pool [default: 10.99.0.0/24]
    --tun-nat                   Enable NAT for tunnel traffic
    --tun-routes <CIDR>         Routes to push to clients (repeatable)
    --tun-dns <IP>              DNS server to push to clients
    
    -v, --verbose               Increase verbosity (use multiple times)
    --log-file <PATH>           Write logs to file
    --log-format <FMT>          Log format: text, json [default: text]
    --syslog                    Log to syslog
    --journald                  Log to systemd journal
    
    --bind <ADDR>               Bind address [default: 0.0.0.0]
    --port-range <RANGE>        Port range for QUIC [default: 4500-4600]
    
    -h, --help                  Print help
    -V, --version               Print version
```

Bootstrap reuse: a running `qsh-server --bootstrap` publishes a FIFO at `/tmp/qsh-server-$UID`. New bootstrap invocations write to the pipe and receive a fresh session key/json from the live instance instead of spawning another daemon; if the pipe is missing or unresponsive, a new server is started.

### 10.3 Usage Examples

```bash
# Basic connection
qsh user@server

# With verbose logging
qsh -vv user@server

# Multiple port forwards with background mode
qsh -f -N \
    -L 5432:db.internal:5432 \
    -L 6379:redis.internal:6379 \
    -D 1080 \
    user@bastion

# Explicit overlay configuration
qsh --overlay-position bottom user@server

# JSON logging to file for debugging
qsh -vvv --log-format json --log-file ~/qsh-debug.log user@server

# Using SSH config aliases
qsh -F ~/.ssh/config prod-bastion

# === Tunnel Examples (Linux only, --features tunnel) ===

# Simple tunnel with auto IP
qsh --tun user@server

# Full VPN (all traffic through tunnel)
qsh --tun --route 0.0.0.0/0 user@server

# Split tunnel (internal networks only)
qsh --tun --route 192.168.0.0/16 --route 10.0.0.0/8 user@bastion

# Tunnel-only mode (no terminal)
qsh --tun -N user@server

# Tunnel with custom IP and MTU
qsh --tun 10.0.0.50/24 --tun-mtu 1400 user@server

# Background tunnel + port forward
qsh -f --tun --route 0.0.0.0/0 -L 5432:db:5432 user@server
```

---

## 11. Implementation Roadmap

### Phase 1: Core Terminal (Weeks 1-4)

- [ ] SSH bootstrap implementation with `russh`
- [ ] QUIC transport layer with `quinn`
- [ ] Basic PTY allocation and I/O
- [ ] Simple terminal state synchronization
- [ ] Basic CLI structure

### Phase 2: Resilience (Weeks 5-8)

- [ ] Connection migration support
- [ ] 0-RTT session resumption
- [ ] Anti-replay protection
- [ ] Predictive local echo
- [ ] Reconnection handling

### Phase 3: Port Forwarding (Weeks 9-12)

- [ ] Local port forwarding (-L)
- [ ] Remote port forwarding (-R)
- [ ] SOCKS5 dynamic forwarding (-D)
- [ ] Forwarding persistence across reconnects

### Phase 4: Observability (Weeks 13-14)

- [ ] Status overlay implementation
- [ ] Keybinding system
- [ ] Client verbose logging
- [ ] Server verbose logging
- [ ] Structured JSON logging
- [ ] Metrics collection

### Phase 5: Polish (Weeks 15-18)

- [ ] Cross-platform testing (Linux, macOS, Windows)
- [ ] Performance optimization
- [ ] Documentation and man pages
- [ ] Package distribution (cargo, deb, rpm, brew)
- [ ] Integration tests

### Phase 6: IP Tunnel (Weeks 19-21) — Feature-Flagged, Linux Only

- [ ] Tun device abstraction (`tokio-tun`)
- [ ] Tunnel protocol messages (TunnelConfig, TunnelPacket)
- [ ] IP address assignment and negotiation
- [ ] Route configuration and pushing
- [ ] Tunnel persistence across reconnects
- [ ] MTU handling and negotiation
- [ ] Integration with status overlay (tunnel stats)
- [ ] Documentation and testing

### Future: Tunnel Platform Expansion

- [ ] macOS tunnel support (`utun`)
- [ ] Windows tunnel support (Wintun)
- [ ] IPv6 tunnel support
- [ ] DNS configuration pushing

---

## 12. Technology Stack

| Component | Technology | Rationale |
|-----------|------------|-----------|
| Language | Rust | Memory safety, performance, async ecosystem |
| Async Runtime | Tokio | Industry standard, excellent I/O |
| QUIC | Quinn | Mature Rust QUIC implementation |
| TLS | Rustls | Pure Rust, memory-safe TLS |
| SSH | Russh | Async SSH client library |
| PTY | Custom PTY (nix/termios + AsyncFd on Unix; platform adapters elsewhere) | Cross-platform PTY abstraction without external portable-pty |
| Terminal Parser | vte | VT100/xterm escape parsing |
| Serialization | bincode | Fast, compact binary format |
| Logging | tracing | Structured, async-aware logging |
| CLI | clap | Ergonomic argument parsing |
| IP Networks | ipnet | IP address/network types |
| Tun Device | tokio-tun | Linux tun interface (feature-gated) |

---

## 13. Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| 0-RTT Reconnection | < 100ms | Network recovery to usable terminal |
| Local Echo Latency | < 10ms | Keypress to screen update |
| State Sync Overhead | < 5% | Compared to raw terminal output |
| Connection Migration | < 500ms | Time to restore after IP change |
| Memory (client) | < 50MB | Resident during active session |
| Memory (server) | < 20MB/session | Per active session |
| Overlay Render | < 1ms | Time to draw overlay frame |
| Tunnel Throughput | > 100 Mbps | Sustained tunnel bandwidth |
| Tunnel Latency Overhead | < 5ms | Added latency vs raw QUIC |

---

## 14. Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| QUIC blocked by firewalls | High | Fallback to TCP/TLS mode |
| Terminal emulation bugs | Medium | Extensive testing with ncurses, vim, tmux |
| Prediction misprediction | Low | Conservative prediction, fast resync |
| Cross-platform PTY issues | Medium | CI testing on all platforms |
| Key binding conflicts | Low | Configurable bindings, escape sequences |
| Tunnel requires root/CAP_NET_ADMIN | Medium | Document requirements, provide setcap instructions |
| Tunnel Linux-only initially | Low | Feature-flagged, clear messaging, planned expansion |
| Tunnel routing conflicts | Medium | Automatic server IP exclusion, clear route management |
| Tunnel NAT/firewall complexity | Medium | Server-side NAT option, documentation |

---

## 15. Appendix

### 15.1 Comparison with Existing Solutions

| Feature | SSH | Mosh | Eternal Terminal | WireGuard | qsh |
|---------|-----|------|------------------|-----------|-----|
| Roaming | ❌ | ✅ | ✅ | Limited | ✅ |
| Local Echo | ❌ | ✅ | ❌ | N/A | ✅ |
| Port Forwarding | ✅ | ❌ | Limited | N/A | ✅ |
| IP Tunnel (VPN) | ❌ | ❌ | ❌ | ✅ | ✅* |
| 0-RTT Resume | ❌ | ❌ | ❌ | ✅ | ✅ |
| Status Overlay | ❌ | ❌ | ❌ | ❌ | ✅ |
| SSH Auth | ✅ | ✅ | ✅ | ❌ | ✅ |
| Transport | TCP | Custom UDP | TCP | UDP | QUIC |
| Encryption | SSH | AES-OCB | SSH | ChaCha20 | TLS 1.3 |

*IP Tunnel: Linux only, feature-flagged

### 15.2 Escape Sequences

Following SSH conventions, escape sequences begin with `~` after a newline:

| Sequence | Action |
|----------|--------|
| `~.` | Disconnect |
| `~^Z` | Suspend client |
| `~#` | List forwarded connections |
| `~t` | Show tunnel status |
| `~s` | Toggle status overlay |
| `~v` | Print verbose metrics |
| `~r` | Force reconnect |
| `~?` | Show escape help |
| `~~` | Send literal `~` |

### 15.3 Environment Variables

| Variable | Description |
|----------|-------------|
| `QSH_LOG` | Set log level (error, warn, info, debug, trace) |
| `QSH_LOG_FILE` | Log file path |
| `QSH_OVERLAY` | Overlay position (top, bottom, top-right, none) |
| `QSH_OVERLAY_KEY` | Overlay toggle keybinding |
| `QSH_NO_COLOR` | Disable colored output |
| `QSH_TUN_IP` | Default tunnel IP (e.g., 10.99.0.2/24) |
| `QSH_TUN_MTU` | Default tunnel MTU |

### 15.4 Feature Flags

The following Cargo features control optional functionality:

| Feature | Description | Platforms |
|---------|-------------|-----------|
| `default` | Core terminal, port forwarding, overlay | All |
| `tunnel` | IP tunnel (VPN) support | Linux only |

```bash
# Build without tunnel
cargo build

# Build with tunnel
cargo build --features tunnel

# Install with tunnel
cargo install qsh --features tunnel
```

### 15.5 References

- RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport
- RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
- Mosh: An Interactive Remote Shell for Mobile Clients (USENIX ATC 2012)
- Quinn QUIC Implementation: https://github.com/quinn-rs/quinn
- Russh SSH Implementation: https://github.com/warp-tech/russh
- tokio-tun: https://github.com/yaa110/tokio-tun

---

*Document generated December 2025*
