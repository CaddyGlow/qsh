//! Control socket client for sending commands to qsh sessions.
//!
//! This module provides a client for connecting to and communicating with
//! the control socket of a running qsh session or server. It handles length-prefixed
//! protobuf message encoding/decoding and provides convenience methods for
//! common operations.
//!
//! The protocol uses the unified Message { Command | Event | Stream } envelope.

use bytes::{Buf, BufMut, BytesMut};
use prost::Message as ProstMessage;
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::proto::{
    self, command, command_ok, command_result, event, message, Command, CommandResult, Event,
    Message, StatusResult, Stream, StreamDirection, StreamKind,
};
use crate::protocol::resource_info_from_proto;
use crate::socket::{socket_path, server_socket_path, SocketError, SocketResult};
use crate::types::{OutputMode, ResourceInfo as RustResourceInfo};

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
    pub async fn connect(session_name: &str) -> SocketResult<Self> {
        let path = socket_path(session_name);
        Self::connect_path(&path).await
    }

    /// Connect to the server control socket.
    ///
    /// Uses the standard server socket path.
    pub async fn connect_server() -> SocketResult<Self> {
        let path = server_socket_path();
        Self::connect_path(&path).await
    }

    /// Connect to a control socket at a specific path.
    pub async fn connect_path(path: &Path) -> SocketResult<Self> {
        let stream = UnixStream::connect(path).await?;

        Ok(Self {
            stream,
            read_buffer: BytesMut::with_capacity(8192),
            next_id: 1,
        })
    }

    /// Send a command and wait for the response.
    async fn send_command(&mut self, cmd: command::Cmd) -> SocketResult<CommandResult> {
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
    async fn send_message(&mut self, message: &Message) -> SocketResult<()> {
        let payload = message.encode_to_vec();

        if payload.len() > MAX_MESSAGE_SIZE {
            return Err(SocketError::Codec(format!(
                "message too large: {} bytes (max {})",
                payload.len(),
                MAX_MESSAGE_SIZE
            )));
        }

        let len = payload.len() as u32;
        let mut buf = BytesMut::with_capacity(FRAME_HEADER_LEN + payload.len());
        buf.put_u32_le(len);
        buf.put_slice(&payload);

        self.stream.write_all(&buf).await?;
        self.stream.flush().await?;

        Ok(())
    }

    /// Read an event from the control socket.
    async fn read_event(&mut self) -> SocketResult<Event> {
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
            let n = self.stream.read_buf(&mut self.read_buffer).await?;

            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "control socket closed",
                )
                .into());
            }
        }
    }

    /// Try to decode a message from the buffer.
    fn try_decode_message(buf: &mut BytesMut) -> SocketResult<Option<Message>> {
        if buf.len() < FRAME_HEADER_LEN {
            return Ok(None);
        }

        let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;

        if len > MAX_MESSAGE_SIZE {
            return Err(SocketError::Codec(format!(
                "message length {} exceeds maximum {}",
                len, MAX_MESSAGE_SIZE
            )));
        }

        if buf.len() < FRAME_HEADER_LEN + len {
            return Ok(None);
        }

        buf.advance(FRAME_HEADER_LEN);
        let payload = buf.split_to(len);
        let msg = Message::decode(&payload[..]).map_err(|e| {
            SocketError::Codec(format!("protobuf decode failed: {}", e))
        })?;

        Ok(Some(msg))
    }

    /// Extract successful result data or return error.
    fn extract_result<T>(
        result: CommandResult,
        extract: impl FnOnce(command_ok::Data) -> Option<T>,
    ) -> SocketResult<T> {
        match result.result {
            Some(command_result::Result::Ok(ok)) => {
                if let Some(data) = ok.data {
                    extract(data).ok_or_else(|| {
                        SocketError::Codec("unexpected response data type".to_string())
                    })
                } else {
                    Err(SocketError::Codec("empty response data".to_string()))
                }
            }
            Some(command_result::Result::Error(err)) => Err(SocketError::Codec(format!(
                "command error: {} (code: {:?})",
                err.message, err.code
            ))),
            None => Err(SocketError::Codec("empty command result".to_string())),
        }
    }

    /// Extract void result (commands that return no data).
    fn extract_void_result(result: CommandResult) -> SocketResult<()> {
        match result.result {
            Some(command_result::Result::Ok(_)) => Ok(()),
            Some(command_result::Result::Error(err)) => Err(SocketError::Codec(format!(
                "command error: {} (code: {:?})",
                err.message, err.code
            ))),
            None => Err(SocketError::Codec("empty command result".to_string())),
        }
    }

    // =========================================================================
    // High-level API
    // =========================================================================

    /// Get connection status.
    pub async fn get_status(&mut self) -> SocketResult<StatusResult> {
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
    pub async fn ping(&mut self, timestamp: u64) -> SocketResult<proto::PongResult> {
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
    ) -> SocketResult<Vec<RustResourceInfo>> {
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
                resource_info_from_proto(info).map_err(|e| {
                    SocketError::Codec(format!("invalid resource info: {}", e))
                })
            })
            .collect()
    }

    /// Describe a specific resource.
    pub async fn describe_resource(&mut self, resource_id: &str) -> SocketResult<RustResourceInfo> {
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
            .ok_or_else(|| SocketError::Codec("missing resource info".to_string()))
            .and_then(|info| {
                resource_info_from_proto(info)
                    .map_err(|e| SocketError::Codec(format!("invalid resource info: {}", e)))
            })
    }

    /// Close a resource.
    pub async fn close_resource(&mut self, resource_id: &str) -> SocketResult<()> {
        let result = self
            .send_command(command::Cmd::ResourceClose(proto::ResourceClose {
                resource_id: resource_id.to_string(),
            }))
            .await?;
        Self::extract_void_result(result)
    }

    /// Drain a resource (graceful shutdown).
    pub async fn drain_resource(&mut self, resource_id: &str, deadline_ms: u64) -> SocketResult<()> {
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
    ) -> SocketResult<RustResourceInfo> {
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
            .ok_or_else(|| SocketError::Codec("missing resource info".to_string()))
            .and_then(|info| {
                resource_info_from_proto(info)
                    .map_err(|e| SocketError::Codec(format!("invalid resource info: {}", e)))
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
        env: Vec<(String, String)>,
        output_mode: OutputMode,
        allocate_pty: bool,
    ) -> SocketResult<RustResourceInfo> {
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
                        env: env
                            .into_iter()
                            .map(|(k, v)| proto::EnvPair { key: k, value: v })
                            .collect(),
                        output_mode: match output_mode {
                            OutputMode::Direct => proto::OutputMode::Direct as i32,
                            OutputMode::Mosh => proto::OutputMode::Mosh as i32,
                            OutputMode::StateDiff => proto::OutputMode::StateDiff as i32,
                        },
                        allocate_pty,
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
            .ok_or_else(|| SocketError::Codec("missing resource info".to_string()))
            .and_then(|info| {
                resource_info_from_proto(info)
                    .map_err(|e| SocketError::Codec(format!("invalid resource info: {}", e)))
            })
    }

    // =========================================================================
    // Terminal operations
    // =========================================================================

    /// Attach to a terminal and get its I/O socket path.
    ///
    /// Returns the Unix socket path for direct terminal I/O.
    /// Connect to this socket for low-latency raw terminal access.
    pub async fn attach_terminal(&mut self, resource_id: &str) -> SocketResult<std::path::PathBuf> {
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
            return Err(SocketError::Codec(
                "missing I/O socket path in attach response".to_string(),
            ));
        }

        Ok(std::path::PathBuf::from(attach_result.io_socket_path))
    }

    /// Detach from a terminal.
    pub async fn detach_terminal(&mut self, resource_id: &str) -> SocketResult<()> {
        let result = self
            .send_command(command::Cmd::TerminalDetach(proto::TerminalDetachCmd {
                resource_id: resource_id.to_string(),
            }))
            .await?;
        Self::extract_void_result(result)
    }

    /// Resize a terminal.
    pub async fn resize_terminal(&mut self, resource_id: &str, cols: u32, rows: u32) -> SocketResult<()> {
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
    pub async fn send_terminal_stream(&mut self, resource_id: &str, data: Vec<u8>) -> SocketResult<()> {
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

        self.stream.write_all(&buf).await?;
        Ok(())
    }

    /// Flush any buffered writes.
    pub async fn flush(&mut self) -> SocketResult<()> {
        self.stream.flush().await.map_err(Into::into)
    }

    // =========================================================================
    // Server enrollment (for bootstrap reuse)
    // =========================================================================

    /// Request a new session enrollment from the server.
    ///
    /// Used by `qsh-server --bootstrap` to reuse an existing server instance.
    /// Returns enrollment info needed to build a bootstrap response.
    pub async fn enroll(&mut self) -> SocketResult<proto::EnrollResult> {
        let result = self.send_command(command::Cmd::Enroll(proto::EnrollCmd {})).await?;
        Self::extract_result(result, |data| {
            if let command_ok::Data::Enroll(e) = data {
                Some(e)
            } else {
                None
            }
        })
    }

    // =========================================================================
    // File transfer operations
    // =========================================================================

    /// Start a file upload.
    ///
    /// Returns the created resource info including the assigned ID.
    /// The transfer runs in the background; use `describe_resource` to check progress.
    pub async fn upload_file(
        &mut self,
        local_path: &str,
        remote_path: &str,
        options: proto::FileTransferOptions,
    ) -> SocketResult<RustResourceInfo> {
        let result = self
            .send_command(command::Cmd::FileUpload(proto::FileUploadCmd {
                local_path: local_path.to_string(),
                remote_path: remote_path.to_string(),
                options: Some(options),
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
            .ok_or_else(|| SocketError::Codec("missing resource info".to_string()))
            .and_then(|info| {
                resource_info_from_proto(info)
                    .map_err(|e| SocketError::Codec(format!("invalid resource info: {}", e)))
            })
    }

    /// Start a file download.
    ///
    /// Returns the created resource info including the assigned ID.
    /// The transfer runs in the background; use `describe_resource` to check progress.
    pub async fn download_file(
        &mut self,
        remote_path: &str,
        local_path: &str,
        options: proto::FileTransferOptions,
    ) -> SocketResult<RustResourceInfo> {
        let result = self
            .send_command(command::Cmd::FileDownload(proto::FileDownloadCmd {
                remote_path: remote_path.to_string(),
                local_path: local_path.to_string(),
                options: Some(options),
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
            .ok_or_else(|| SocketError::Codec("missing resource info".to_string()))
            .and_then(|info| {
                resource_info_from_proto(info)
                    .map_err(|e| SocketError::Codec(format!("invalid resource info: {}", e)))
            })
    }

    /// Cancel a file transfer.
    pub async fn cancel_file_transfer(&mut self, resource_id: &str) -> SocketResult<()> {
        let result = self
            .send_command(command::Cmd::FileCancel(proto::FileCancelCmd {
                resource_id: resource_id.to_string(),
            }))
            .await?;
        Self::extract_void_result(result)
    }

    /// List file transfers.
    ///
    /// Convenience method that filters resources by FileTransfer kind.
    pub async fn list_file_transfers(&mut self) -> SocketResult<Vec<RustResourceInfo>> {
        self.list_resources(Some(proto::ResourceKind::FileTransfer))
            .await
    }

    /// Try to receive a stream message (non-blocking).
    ///
    /// Returns `Ok(Some(stream))` if a stream message is available,
    /// `Ok(None)` if no data is ready, or `Err` on error.
    pub async fn try_recv_stream(&mut self) -> SocketResult<Option<Stream>> {
        // Non-blocking read
        match self.stream.try_read_buf(&mut self.read_buffer) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "control socket closed",
                )
                .into());
            }
            Ok(_) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
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
    pub async fn recv_stream(&mut self) -> SocketResult<Stream> {
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
            let n = self.stream.read_buf(&mut self.read_buffer).await?;

            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "control socket closed",
                )
                .into());
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
