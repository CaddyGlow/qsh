# Control Socket Module

This module provides a Unix socket-based control interface for managing qsh connections from separate terminal sessions.

## Overview

The control socket allows you to:
- Query connection status
- Add/remove port forwards dynamically
- Get session information
- Monitor channel statistics

## Architecture

### Components

1. **control.proto** - Protobuf schema defining the request/response protocol
2. **socket.rs** - Unix socket server implementation with multi-client support
3. **commands.rs** - Command handlers (currently stub implementations)
4. **mod.rs** - Module exports and protobuf integration

### Protocol

Messages use length-prefixed protobuf encoding:
- 4-byte little-endian length prefix
- Protobuf-encoded payload
- Maximum message size: 1MB

### Socket Path

The socket path is determined by:
1. First preference: `$XDG_RUNTIME_DIR/qsh/<name>.sock`
2. Fallback: `/tmp/qsh-<uid>-<name>.sock`

Permissions are set to 0600 (owner read/write only).

## Usage Example

### Server Side

```rust
use qsh_client::control::{ControlSocket, ControlEvent, handle_command};

// Create control socket
let socket_path = qsh_client::control::socket_path("my-session");
let mut socket = ControlSocket::new(&socket_path)?;

// Event loop
loop {
    tokio::select! {
        Some(event) = socket.next_event() => {
            match event? {
                ControlEvent::ClientConnected { client_id } => {
                    println!("Client {} connected", client_id);
                }
                ControlEvent::Request { client_id, request } => {
                    let response = handle_command(request);
                    socket.send_response(client_id, response).await?;
                }
                ControlEvent::ClientDisconnected { client_id, error } => {
                    if let Some(e) = error {
                        eprintln!("Client {} disconnected: {}", client_id, e);
                    }
                }
            }
        }
        // ... other events ...
    }
}
```

### Client Side

```rust
use tokio::net::UnixStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use bytes::{BufMut, BytesMut};
use prost::Message;

// Connect to control socket
let socket_path = qsh_client::control::socket_path("my-session");
let mut stream = UnixStream::connect(&socket_path).await?;

// Build request
let request = ControlRequest {
    id: 1,
    command: Some(control_request::Command::GetStatus(GetStatusRequest {})),
};

// Encode and send
let payload = request.encode_to_vec();
let len = payload.len() as u32;
let mut buf = BytesMut::with_capacity(4 + payload.len());
buf.put_u32_le(len);
buf.put_slice(&payload);
stream.write_all(&buf).await?;

// Read response (length-prefixed)
let mut len_buf = [0u8; 4];
stream.read_exact(&mut len_buf).await?;
let len = u32::from_le_bytes(len_buf) as usize;

let mut payload = vec![0u8; len];
stream.read_exact(&mut payload).await?;

let response = ControlResponse::decode(&payload[..])?;
```

## Available Commands

### GetStatus
Query connection status including uptime, bytes transferred, RTT.

### ForwardAdd
Add a new port forward (local, remote, or dynamic SOCKS).

### ForwardList
List all active port forwards with statistics.

### ForwardRemove
Remove a port forward by ID.

### SessionInfo
Get session information including channels and metadata.

### Ping
Simple ping/pong for latency testing.

## Current Status

This is **Track A** implementation - the protocol and socket layer.

### Completed
- Full protobuf schema
- Unix socket server with multi-client support
- Length-prefixed message framing
- Stub command handlers
- RAII cleanup with ControlSocketGuard
- XDG_RUNTIME_DIR support with fallback

### TODO (Track B - Integration)
- Wire up actual connection state to command handlers
- Integrate with ChannelConnection for live data
- Implement dynamic forward management
- Add authentication/authorization
- Error handling improvements
- Performance monitoring

## Testing

Run tests with:
```bash
cargo test -p qsh-client --lib control
```

Tests verify:
- Socket creation and cleanup
- Permission handling (0600)
- Path generation (XDG and fallback)
- Message encoding/decoding
- Command handling logic
