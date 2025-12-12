//! Control socket client for sending commands to qsh sessions.
//!
//! This module provides a client for connecting to and communicating with
//! the control socket of a running qsh session. It handles length-prefixed
//! protobuf message encoding/decoding and provides convenience methods for
//! common operations.
//!
//! The protocol uses the unified Message { Command | Event | Stream } envelope.

use bytes::{Buf, BufMut, BytesMut};
use prost::Message as ProstMessage;
use qsh_core::error::{Error, Result};
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use super::proto::{
    self, command, command_ok, command_result, event, message, resource_create, Command,
    CommandResult, Event, Message, StatusResult, Stream, StreamDirection, StreamKind,
};
use super::socket::socket_path;
use super::{resource_info_from_proto, ResourceInfo as RustResourceInfo};

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

    /// Send a command and wait for the response.
    async fn send_command(&mut self, cmd: command::Cmd) -> Result<CommandResult> {
        // Assign a request ID
        let request_id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        let message = Message {
            kind: Some(message::Kind::Command(Command {
                request_id,
                cmd: Some(cmd),
            })),
        };

        // Encode and send
        self.send_message(&message).await?;

        // Wait for matching CommandResult
        loop {
            let event = self.read_event().await?;
            if let Some(event::Evt::CommandResult(result)) = event.evt {
                if result.request_id == request_id {
                    return Ok(result);
                }
                // Ignore results for other request IDs (shouldn't happen with single client)
            }
            // Ignore other events (resource events, etc.)
        }
    }

    /// Send a message (low-level).
    async fn send_message(&mut self, message: &Message) -> Result<()> {
        let payload = message.encode_to_vec();

        if payload.len() > MAX_MESSAGE_SIZE {
            return Err(Error::Codec {
                message: format!(
                    "message too large: {} bytes (max {})",
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

        Ok(())
    }

    /// Read an event from the control socket.
    async fn read_event(&mut self) -> Result<Event> {
        loop {
            // Try to decode a message from the buffer
            if let Some(msg) = Self::try_decode_message(&mut self.read_buffer)? {
                match msg.kind {
                    Some(message::Kind::Event(event)) => return Ok(event),
                    Some(message::Kind::Stream(_)) => {
                        // Skip stream messages when waiting for events
                        continue;
                    }
                    Some(message::Kind::Command(_)) => {
                        // Server shouldn't send commands to client
                        continue;
                    }
                    None => continue,
                }
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

    /// Try to decode a message from the buffer.
    fn try_decode_message(buf: &mut BytesMut) -> Result<Option<Message>> {
        if buf.len() < FRAME_HEADER_LEN {
            return Ok(None);
        }

        let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;

        if len > MAX_MESSAGE_SIZE {
            return Err(Error::Codec {
                message: format!(
                    "message length {} exceeds maximum {}",
                    len, MAX_MESSAGE_SIZE
                ),
            });
        }

        if buf.len() < FRAME_HEADER_LEN + len {
            return Ok(None);
        }

        buf.advance(FRAME_HEADER_LEN);
        let payload = buf.split_to(len);
        let msg = Message::decode(&payload[..]).map_err(|e| Error::Codec {
            message: format!("protobuf decode failed: {}", e),
        })?;

        Ok(Some(msg))
    }

    /// Extract successful result data or return error.
    fn extract_result<T>(
        result: CommandResult,
        extract: impl FnOnce(command_ok::Data) -> Option<T>,
    ) -> Result<T> {
        match result.result {
            Some(command_result::Result::Ok(ok)) => {
                if let Some(data) = ok.data {
                    extract(data).ok_or_else(|| Error::Codec {
                        message: "unexpected response data type".to_string(),
                    })
                } else {
                    Err(Error::Codec {
                        message: "empty response data".to_string(),
                    })
                }
            }
            Some(command_result::Result::Error(err)) => Err(Error::Transport {
                message: format!("command error: {} (code: {:?})", err.message, err.code),
            }),
            None => Err(Error::Codec {
                message: "empty command result".to_string(),
            }),
        }
    }

    /// Extract void result (commands that return no data).
    fn extract_void_result(result: CommandResult) -> Result<()> {
        match result.result {
            Some(command_result::Result::Ok(_)) => Ok(()),
            Some(command_result::Result::Error(err)) => Err(Error::Transport {
                message: format!("command error: {} (code: {:?})", err.message, err.code),
            }),
            None => Err(Error::Codec {
                message: "empty command result".to_string(),
            }),
        }
    }

    // =========================================================================
    // High-level API
    // =========================================================================

    /// Get connection status.
    pub async fn get_status(&mut self) -> Result<StatusResult> {
        let result = self.send_command(command::Cmd::Status(proto::StatusCmd {})).await?;
        Self::extract_result(result, |data| {
            if let command_ok::Data::Status(s) = data {
                Some(s)
            } else {
                None
            }
        })
    }

    /// Send a ping and get a pong response.
    pub async fn ping(&mut self, timestamp: u64) -> Result<proto::PongResult> {
        let result = self
            .send_command(command::Cmd::Ping(proto::PingCmd { timestamp }))
            .await?;
        Self::extract_result(result, |data| {
            if let command_ok::Data::Pong(p) = data {
                Some(p)
            } else {
                None
            }
        })
    }

    /// List resources (optionally filtered by kind).
    pub async fn list_resources(
        &mut self,
        kind: Option<proto::ResourceKind>,
    ) -> Result<Vec<RustResourceInfo>> {
        let result = self
            .send_command(command::Cmd::ResourceList(proto::ResourceList {
                kind: kind.map(|k| k as i32).unwrap_or(0),
            }))
            .await?;

        let list = Self::extract_result(result, |data| {
            if let command_ok::Data::ResourceList(l) = data {
                Some(l)
            } else {
                None
            }
        })?;

        // Convert proto ResourceInfo to Rust ResourceInfo
        list.resources
            .into_iter()
            .map(|info| {
                resource_info_from_proto(info).map_err(|e| Error::Codec {
                    message: format!("invalid resource info: {}", e),
                })
            })
            .collect()
    }

    /// Describe a specific resource.
    pub async fn describe_resource(&mut self, resource_id: &str) -> Result<RustResourceInfo> {
        let result = self
            .send_command(command::Cmd::ResourceDescribe(proto::ResourceDescribe {
                resource_id: resource_id.to_string(),
            }))
            .await?;

        let describe = Self::extract_result(result, |data| {
            if let command_ok::Data::ResourceDescribe(d) = data {
                Some(d)
            } else {
                None
            }
        })?;

        describe
            .info
            .ok_or_else(|| Error::Codec {
                message: "missing resource info".to_string(),
            })
            .and_then(|info| {
                resource_info_from_proto(info).map_err(|e| Error::Codec {
                    message: format!("invalid resource info: {}", e),
                })
            })
    }

    /// Close a resource.
    pub async fn close_resource(&mut self, resource_id: &str) -> Result<()> {
        let result = self
            .send_command(command::Cmd::ResourceClose(proto::ResourceClose {
                resource_id: resource_id.to_string(),
            }))
            .await?;
        Self::extract_void_result(result)
    }

    /// Drain a resource (graceful shutdown).
    pub async fn drain_resource(&mut self, resource_id: &str, deadline_ms: u64) -> Result<()> {
        let result = self
            .send_command(command::Cmd::ResourceDrain(proto::ResourceDrain {
                resource_id: resource_id.to_string(),
                deadline_ms,
            }))
            .await?;
        Self::extract_void_result(result)
    }

    // =========================================================================
    // Resource creation
    // =========================================================================

    /// Create a forward resource.
    ///
    /// Returns the created resource info including the assigned ID.
    pub async fn create_forward(
        &mut self,
        forward_type: proto::ForwardType,
        bind_addr: &str,
        bind_port: u32,
        dest_host: Option<&str>,
        dest_port: Option<u32>,
    ) -> Result<RustResourceInfo> {
        let result = self
            .send_command(command::Cmd::ResourceCreate(proto::ResourceCreate {
                kind: proto::ResourceKind::Forward as i32,
                params: Some(proto::resource_create::Params::Forward(
                    proto::ForwardCreateParams {
                        forward_type: forward_type as i32,
                        bind_addr: bind_addr.to_string(),
                        bind_port,
                        dest_host: dest_host.unwrap_or_default().to_string(),
                        dest_port: dest_port.unwrap_or(0),
                    },
                )),
            }))
            .await?;

        let created = Self::extract_result(result, |data| {
            if let command_ok::Data::ResourceCreated(c) = data {
                Some(c)
            } else {
                None
            }
        })?;

        created
            .info
            .ok_or_else(|| Error::Codec {
                message: "missing resource info".to_string(),
            })
            .and_then(|info| {
                resource_info_from_proto(info).map_err(|e| Error::Codec {
                    message: format!("invalid resource info: {}", e),
                })
            })
    }

    /// Create a terminal resource.
    ///
    /// Returns the created resource info including the assigned ID.
    pub async fn create_terminal(
        &mut self,
        cols: u32,
        rows: u32,
        term_type: Option<&str>,
        shell: Option<&str>,
        command: Option<&str>,
    ) -> Result<RustResourceInfo> {
        let result = self
            .send_command(command::Cmd::ResourceCreate(proto::ResourceCreate {
                kind: proto::ResourceKind::Terminal as i32,
                params: Some(proto::resource_create::Params::Terminal(
                    proto::TerminalCreateParams {
                        cols,
                        rows,
                        term_type: term_type.unwrap_or("xterm-256color").to_string(),
                        shell: shell.unwrap_or_default().to_string(),
                        command: command.unwrap_or_default().to_string(),
                        env: vec![],
                    },
                )),
            }))
            .await?;

        let created = Self::extract_result(result, |data| {
            if let command_ok::Data::ResourceCreated(c) = data {
                Some(c)
            } else {
                None
            }
        })?;

        created
            .info
            .ok_or_else(|| Error::Codec {
                message: "missing resource info".to_string(),
            })
            .and_then(|info| {
                resource_info_from_proto(info).map_err(|e| Error::Codec {
                    message: format!("invalid resource info: {}", e),
                })
            })
    }

    // =========================================================================
    // Terminal operations
    // =========================================================================

    /// Attach to a terminal and get its I/O socket path.
    ///
    /// Returns the Unix socket path for direct terminal I/O.
    /// Connect to this socket for low-latency raw terminal access.
    pub async fn attach_terminal(&mut self, resource_id: &str) -> Result<std::path::PathBuf> {
        let result = self
            .send_command(command::Cmd::TerminalAttach(proto::TerminalAttachCmd {
                resource_id: resource_id.to_string(),
            }))
            .await?;

        let attach_result = Self::extract_result(result, |data| {
            if let command_ok::Data::TerminalAttach(a) = data {
                Some(a)
            } else {
                None
            }
        })?;

        if attach_result.io_socket_path.is_empty() {
            return Err(Error::Codec {
                message: "missing I/O socket path in attach response".to_string(),
            });
        }

        Ok(std::path::PathBuf::from(attach_result.io_socket_path))
    }

    /// Detach from a terminal.
    pub async fn detach_terminal(&mut self, resource_id: &str) -> Result<()> {
        let result = self
            .send_command(command::Cmd::TerminalDetach(proto::TerminalDetachCmd {
                resource_id: resource_id.to_string(),
            }))
            .await?;
        Self::extract_void_result(result)
    }

    /// Resize a terminal.
    pub async fn resize_terminal(&mut self, resource_id: &str, cols: u32, rows: u32) -> Result<()> {
        let result = self
            .send_command(command::Cmd::TerminalResize(proto::TerminalResizeCmd {
                resource_id: resource_id.to_string(),
                cols,
                rows,
            }))
            .await?;
        Self::extract_void_result(result)
    }

    /// Send terminal input as a stream message.
    ///
    /// This is fire-and-forget - no response expected.
    pub async fn send_terminal_stream(&mut self, resource_id: &str, data: Vec<u8>) -> Result<()> {
        let message = Message {
            kind: Some(message::Kind::Stream(Stream {
                resource_id: resource_id.to_string(),
                stream_kind: StreamKind::TerminalIo as i32,
                direction: StreamDirection::In as i32,
                data,
            })),
        };

        // Send without waiting for response
        let payload = message.encode_to_vec();
        let len = payload.len() as u32;
        let mut buf = BytesMut::with_capacity(FRAME_HEADER_LEN + payload.len());
        buf.put_u32_le(len);
        buf.put_slice(&payload);

        self.stream.write_all(&buf).await.map_err(Error::Io)?;
        Ok(())
    }

    /// Flush any buffered writes.
    pub async fn flush(&mut self) -> Result<()> {
        self.stream.flush().await.map_err(Error::Io)
    }

    /// Try to receive a stream message (non-blocking).
    ///
    /// Returns `Ok(Some(stream))` if a stream message is available,
    /// `Ok(None)` if no data is ready, or `Err` on error.
    pub async fn try_recv_stream(&mut self) -> Result<Option<Stream>> {
        // Non-blocking read
        match self.stream.try_read_buf(&mut self.read_buffer) {
            Ok(0) => {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "control socket closed",
                )));
            }
            Ok(_) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                return Ok(None);
            }
            Err(e) => return Err(Error::Io(e)),
        }

        // Try to decode a stream message
        if let Some(msg) = Self::try_decode_message(&mut self.read_buffer)? {
            if let Some(message::Kind::Stream(stream)) = msg.kind {
                return Ok(Some(stream));
            }
        }

        Ok(None)
    }

    /// Receive the next stream message (blocking).
    pub async fn recv_stream(&mut self) -> Result<Stream> {
        loop {
            // Try to decode from buffer first
            if let Some(msg) = Self::try_decode_message(&mut self.read_buffer)? {
                if let Some(message::Kind::Stream(stream)) = msg.kind {
                    return Ok(stream);
                }
                // Skip non-stream messages
                continue;
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

    /// Get direct access to the underlying stream for select!
    pub fn stream_mut(&mut self) -> &mut UnixStream {
        &mut self.stream
    }

    /// Get access to the read buffer for processing partial reads
    pub fn read_buffer_mut(&mut self) -> &mut BytesMut {
        &mut self.read_buffer
    }
}

#[cfg(test)]
mod tests {
    // Tests would require a mock server - skipping for now
}
