//! Control socket client for sending commands to qsh sessions.
//!
//! This module provides a client for connecting to and communicating with
//! the control socket of a running qsh session. It handles length-prefixed
//! protobuf message encoding/decoding and provides convenience methods for
//! common operations.

use bytes::{Buf, BufMut, BytesMut};
use prost::Message;
use qsh_core::error::{Error, Result};
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use super::proto::{
    control_request, control_response, forward_add_request, ControlRequest, ControlResponse,
    DynamicForwardSpec, ForwardAddRequest, ForwardAddResponse, ForwardListRequest,
    ForwardListResponse, ForwardRemoveRequest, ForwardRemoveResponse, GetStatusRequest,
    LocalForwardSpec, PingRequest, PongResponse, RemoteForwardSpec, SessionInfoRequest,
    SessionInfoResponse, StatusResponse, TerminalCloseRequest, TerminalCloseResponse,
    TerminalListRequest, TerminalListResponse, TerminalOpenRequest, TerminalOpenResponse,
    TerminalResizeRequest, TerminalResizeResponse,
};
use super::socket::socket_path;

/// Length of the frame header (4 bytes, little-endian u32).
const FRAME_HEADER_LEN: usize = 4;

/// Maximum message size (1MB).
const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Client for communicating with a qsh control socket.
pub struct ControlClient {
    stream: UnixStream,
    read_buffer: BytesMut,
    next_id: u32,
}

impl ControlClient {
    /// Connect to a control socket by session name.
    ///
    /// Uses the standard socket path resolution (XDG_RUNTIME_DIR or /tmp).
    pub async fn connect(session_name: &str) -> Result<Self> {
        let path = socket_path(session_name);
        Self::connect_path(&path).await
    }

    /// Connect to a control socket at a specific path.
    pub async fn connect_path(path: &Path) -> Result<Self> {
        let stream = UnixStream::connect(path).await.map_err(Error::Io)?;

        Ok(Self {
            stream,
            read_buffer: BytesMut::with_capacity(8192),
            next_id: 1,
        })
    }

    /// Send a request and wait for the response.
    pub async fn send_request(&mut self, mut request: ControlRequest) -> Result<ControlResponse> {
        // Assign a request ID
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        request.id = id;

        // Encode and send the request
        let payload = request.encode_to_vec();

        if payload.len() > MAX_MESSAGE_SIZE {
            return Err(Error::Codec {
                message: format!(
                    "request too large: {} bytes (max {})",
                    payload.len(),
                    MAX_MESSAGE_SIZE
                ),
            });
        }

        let len = payload.len() as u32;
        let mut buf = BytesMut::with_capacity(FRAME_HEADER_LEN + payload.len());
        buf.put_u32_le(len);
        buf.put_slice(&payload);

        self.stream.write_all(&buf).await.map_err(Error::Io)?;
        self.stream.flush().await.map_err(Error::Io)?;

        // Read the response
        let response = self.read_response().await?;

        // Verify response ID matches
        if response.id != id {
            return Err(Error::Codec {
                message: format!("response ID mismatch: expected {}, got {}", id, response.id),
            });
        }

        Ok(response)
    }

    /// Read a response from the control socket.
    async fn read_response(&mut self) -> Result<ControlResponse> {
        loop {
            // Try to decode a message from the buffer
            if let Some(response) = Self::try_decode_response(&mut self.read_buffer)? {
                return Ok(response);
            }

            // Need more data
            let n = self
                .stream
                .read_buf(&mut self.read_buffer)
                .await
                .map_err(Error::Io)?;

            if n == 0 {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "control socket closed",
                )));
            }
        }
    }

    /// Try to decode a response from the buffer.
    fn try_decode_response(buf: &mut BytesMut) -> Result<Option<ControlResponse>> {
        // Need at least 4 bytes for length
        if buf.len() < FRAME_HEADER_LEN {
            return Ok(None);
        }

        // Peek the length without consuming
        let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;

        // Check for oversized message
        if len > MAX_MESSAGE_SIZE {
            return Err(Error::Codec {
                message: format!(
                    "message length {} exceeds maximum {}",
                    len, MAX_MESSAGE_SIZE
                ),
            });
        }

        // Check if we have the full message
        if buf.len() < FRAME_HEADER_LEN + len {
            return Ok(None);
        }

        // Consume the header
        buf.advance(FRAME_HEADER_LEN);

        // Consume and decode the payload
        let payload = buf.split_to(len);
        let response = ControlResponse::decode(&payload[..]).map_err(|e| Error::Codec {
            message: format!("protobuf decode failed: {}", e),
        })?;

        Ok(Some(response))
    }

    // Convenience methods for common operations

    /// Get connection status.
    pub async fn get_status(&mut self) -> Result<StatusResponse> {
        let request = ControlRequest {
            id: 0, // Will be assigned by send_request
            command: Some(control_request::Command::GetStatus(GetStatusRequest {})),
        };

        let response = self.send_request(request).await?;

        match response.result {
            Some(control_response::Result::Status(status)) => Ok(status),
            Some(control_response::Result::Error(err)) => Err(Error::Transport {
                message: format!("status error: {}", err.message),
            }),
            _ => Err(Error::Codec {
                message: "unexpected response type".to_string(),
            }),
        }
    }

    /// Add a local port forward.
    pub async fn add_forward_local(&mut self, spec: &str) -> Result<ForwardAddResponse> {
        let (bind_addr, bind_port, dest_host, dest_port) = parse_local_forward_spec(spec)?;

        let request = ControlRequest {
            id: 0,
            command: Some(control_request::Command::ForwardAdd(ForwardAddRequest {
                spec: Some(forward_add_request::Spec::Local(LocalForwardSpec {
                    bind_addr,
                    bind_port,
                    dest_host,
                    dest_port,
                })),
            })),
        };

        let response = self.send_request(request).await?;

        match response.result {
            Some(control_response::Result::ForwardAdded(resp)) => Ok(resp),
            Some(control_response::Result::Error(err)) => Err(Error::Transport {
                message: format!("forward add error: {}", err.message),
            }),
            _ => Err(Error::Codec {
                message: "unexpected response type".to_string(),
            }),
        }
    }

    /// Add a remote port forward.
    pub async fn add_forward_remote(&mut self, spec: &str) -> Result<ForwardAddResponse> {
        let (bind_addr, bind_port, dest_host, dest_port) = parse_remote_forward_spec(spec)?;

        let request = ControlRequest {
            id: 0,
            command: Some(control_request::Command::ForwardAdd(ForwardAddRequest {
                spec: Some(forward_add_request::Spec::Remote(RemoteForwardSpec {
                    bind_addr,
                    bind_port,
                    dest_host,
                    dest_port,
                })),
            })),
        };

        let response = self.send_request(request).await?;

        match response.result {
            Some(control_response::Result::ForwardAdded(resp)) => Ok(resp),
            Some(control_response::Result::Error(err)) => Err(Error::Transport {
                message: format!("forward add error: {}", err.message),
            }),
            _ => Err(Error::Codec {
                message: "unexpected response type".to_string(),
            }),
        }
    }

    /// Add a dynamic SOCKS5 forward.
    pub async fn add_forward_dynamic(&mut self, spec: &str) -> Result<ForwardAddResponse> {
        let (bind_addr, bind_port) = parse_dynamic_forward_spec(spec)?;

        let request = ControlRequest {
            id: 0,
            command: Some(control_request::Command::ForwardAdd(ForwardAddRequest {
                spec: Some(forward_add_request::Spec::Dynamic(DynamicForwardSpec {
                    bind_addr,
                    bind_port,
                })),
            })),
        };

        let response = self.send_request(request).await?;

        match response.result {
            Some(control_response::Result::ForwardAdded(resp)) => Ok(resp),
            Some(control_response::Result::Error(err)) => Err(Error::Transport {
                message: format!("forward add error: {}", err.message),
            }),
            _ => Err(Error::Codec {
                message: "unexpected response type".to_string(),
            }),
        }
    }

    /// List all port forwards.
    pub async fn list_forwards(&mut self) -> Result<ForwardListResponse> {
        let request = ControlRequest {
            id: 0,
            command: Some(control_request::Command::ForwardList(ForwardListRequest {})),
        };

        let response = self.send_request(request).await?;

        match response.result {
            Some(control_response::Result::ForwardList(list)) => Ok(list),
            Some(control_response::Result::Error(err)) => Err(Error::Transport {
                message: format!("forward list error: {}", err.message),
            }),
            _ => Err(Error::Codec {
                message: "unexpected response type".to_string(),
            }),
        }
    }

    /// Remove a port forward by ID.
    pub async fn remove_forward(&mut self, forward_id: &str) -> Result<ForwardRemoveResponse> {
        let request = ControlRequest {
            id: 0,
            command: Some(control_request::Command::ForwardRemove(
                ForwardRemoveRequest {
                    forward_id: forward_id.to_string(),
                },
            )),
        };

        let response = self.send_request(request).await?;

        match response.result {
            Some(control_response::Result::ForwardRemoved(resp)) => Ok(resp),
            Some(control_response::Result::Error(err)) => Err(Error::Transport {
                message: format!("forward remove error: {}", err.message),
            }),
            _ => Err(Error::Codec {
                message: "unexpected response type".to_string(),
            }),
        }
    }

    /// Get session information.
    pub async fn get_session_info(&mut self) -> Result<SessionInfoResponse> {
        let request = ControlRequest {
            id: 0,
            command: Some(control_request::Command::SessionInfo(SessionInfoRequest {})),
        };

        let response = self.send_request(request).await?;

        match response.result {
            Some(control_response::Result::SessionInfo(info)) => Ok(info),
            Some(control_response::Result::Error(err)) => Err(Error::Transport {
                message: format!("session info error: {}", err.message),
            }),
            _ => Err(Error::Codec {
                message: "unexpected response type".to_string(),
            }),
        }
    }

    /// Send a ping and get a pong response.
    pub async fn ping(&mut self, timestamp: u64) -> Result<PongResponse> {
        let request = ControlRequest {
            id: 0,
            command: Some(control_request::Command::Ping(PingRequest { timestamp })),
        };

        let response = self.send_request(request).await?;

        match response.result {
            Some(control_response::Result::Pong(pong)) => Ok(pong),
            Some(control_response::Result::Error(err)) => Err(Error::Transport {
                message: format!("ping error: {}", err.message),
            }),
            _ => Err(Error::Codec {
                message: "unexpected response type".to_string(),
            }),
        }
    }

    // Terminal operations

    /// Open a new terminal.
    pub async fn open_terminal(
        &mut self,
        cols: Option<u32>,
        rows: Option<u32>,
        term_type: Option<String>,
        shell: Option<String>,
        command: Option<String>,
    ) -> Result<TerminalOpenResponse> {
        let request = ControlRequest {
            id: 0,
            command: Some(control_request::Command::TerminalOpen(TerminalOpenRequest {
                cols,
                rows,
                term_type,
                shell,
                command,
            })),
        };

        let response = self.send_request(request).await?;

        match response.result {
            Some(control_response::Result::TerminalOpened(resp)) => Ok(resp),
            Some(control_response::Result::Error(err)) => Err(Error::Transport {
                message: format!("terminal open error: {}", err.message),
            }),
            _ => Err(Error::Codec {
                message: "unexpected response type".to_string(),
            }),
        }
    }

    /// Close a terminal.
    pub async fn close_terminal(&mut self, terminal_id: u64) -> Result<TerminalCloseResponse> {
        let request = ControlRequest {
            id: 0,
            command: Some(control_request::Command::TerminalClose(
                TerminalCloseRequest { terminal_id },
            )),
        };

        let response = self.send_request(request).await?;

        match response.result {
            Some(control_response::Result::TerminalClosed(resp)) => Ok(resp),
            Some(control_response::Result::Error(err)) => Err(Error::Transport {
                message: format!("terminal close error: {}", err.message),
            }),
            _ => Err(Error::Codec {
                message: "unexpected response type".to_string(),
            }),
        }
    }

    /// Resize a terminal.
    pub async fn resize_terminal(
        &mut self,
        terminal_id: u64,
        cols: u32,
        rows: u32,
    ) -> Result<TerminalResizeResponse> {
        let request = ControlRequest {
            id: 0,
            command: Some(control_request::Command::TerminalResize(
                TerminalResizeRequest {
                    terminal_id,
                    cols,
                    rows,
                },
            )),
        };

        let response = self.send_request(request).await?;

        match response.result {
            Some(control_response::Result::TerminalResized(resp)) => Ok(resp),
            Some(control_response::Result::Error(err)) => Err(Error::Transport {
                message: format!("terminal resize error: {}", err.message),
            }),
            _ => Err(Error::Codec {
                message: "unexpected response type".to_string(),
            }),
        }
    }

    /// List all terminals.
    pub async fn list_terminals(&mut self) -> Result<TerminalListResponse> {
        let request = ControlRequest {
            id: 0,
            command: Some(control_request::Command::TerminalList(
                TerminalListRequest {},
            )),
        };

        let response = self.send_request(request).await?;

        match response.result {
            Some(control_response::Result::TerminalList(list)) => Ok(list),
            Some(control_response::Result::Error(err)) => Err(Error::Transport {
                message: format!("terminal list error: {}", err.message),
            }),
            _ => Err(Error::Codec {
                message: "unexpected response type".to_string(),
            }),
        }
    }
}

// Forward spec parsing helpers
// These are simplified versions - in production they should use the existing parsing from qsh-client

fn parse_local_forward_spec(spec: &str) -> Result<(Option<String>, u32, String, u32)> {
    // Format: [bind_addr:]port:host:hostport
    let parts: Vec<&str> = spec.split(':').collect();

    match parts.len() {
        3 => {
            // port:host:hostport
            let bind_port: u32 = parts[0].parse().map_err(|_| Error::Transport {
                message: format!("invalid bind port: {}", parts[0]),
            })?;
            let dest_host = parts[1].to_string();
            let dest_port: u32 = parts[2].parse().map_err(|_| Error::Transport {
                message: format!("invalid dest port: {}", parts[2]),
            })?;
            Ok((None, bind_port, dest_host, dest_port))
        }
        4 => {
            // bind_addr:port:host:hostport
            let bind_addr = Some(parts[0].to_string());
            let bind_port: u32 = parts[1].parse().map_err(|_| Error::Transport {
                message: format!("invalid bind port: {}", parts[1]),
            })?;
            let dest_host = parts[2].to_string();
            let dest_port: u32 = parts[3].parse().map_err(|_| Error::Transport {
                message: format!("invalid dest port: {}", parts[3]),
            })?;
            Ok((bind_addr, bind_port, dest_host, dest_port))
        }
        _ => Err(Error::Transport {
            message: format!(
                "invalid local forward spec (expected [bind_addr:]port:host:hostport): {}",
                spec
            ),
        }),
    }
}

fn parse_remote_forward_spec(spec: &str) -> Result<(Option<String>, u32, String, u32)> {
    // Same format as local forward
    parse_local_forward_spec(spec)
}

fn parse_dynamic_forward_spec(spec: &str) -> Result<(Option<String>, u32)> {
    // Format: [bind_addr:]port
    let parts: Vec<&str> = spec.split(':').collect();

    match parts.len() {
        1 => {
            // port
            let bind_port: u32 = parts[0].parse().map_err(|_| Error::Transport {
                message: format!("invalid bind port: {}", parts[0]),
            })?;
            Ok((None, bind_port))
        }
        2 => {
            // bind_addr:port
            let bind_addr = Some(parts[0].to_string());
            let bind_port: u32 = parts[1].parse().map_err(|_| Error::Transport {
                message: format!("invalid bind port: {}", parts[1]),
            })?;
            Ok((bind_addr, bind_port))
        }
        _ => Err(Error::Transport {
            message: format!(
                "invalid dynamic forward spec (expected [bind_addr:]port): {}",
                spec
            ),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_local_forward_spec() {
        // port:host:hostport
        let (bind_addr, bind_port, dest_host, dest_port) =
            parse_local_forward_spec("8080:localhost:80").unwrap();
        assert_eq!(bind_addr, None);
        assert_eq!(bind_port, 8080);
        assert_eq!(dest_host, "localhost");
        assert_eq!(dest_port, 80);

        // bind_addr:port:host:hostport
        let (bind_addr, bind_port, dest_host, dest_port) =
            parse_local_forward_spec("127.0.0.1:8080:localhost:80").unwrap();
        assert_eq!(bind_addr, Some("127.0.0.1".to_string()));
        assert_eq!(bind_port, 8080);
        assert_eq!(dest_host, "localhost");
        assert_eq!(dest_port, 80);
    }

    #[test]
    fn test_parse_dynamic_forward_spec() {
        // port
        let (bind_addr, bind_port) = parse_dynamic_forward_spec("1080").unwrap();
        assert_eq!(bind_addr, None);
        assert_eq!(bind_port, 1080);

        // bind_addr:port
        let (bind_addr, bind_port) = parse_dynamic_forward_spec("127.0.0.1:1080").unwrap();
        assert_eq!(bind_addr, Some("127.0.0.1".to_string()));
        assert_eq!(bind_port, 1080);
    }
}
