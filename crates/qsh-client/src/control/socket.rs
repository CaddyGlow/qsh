//! Unix socket server for control interface.
//!
//! The control socket allows separate terminal sessions to manage an existing
//! qsh connection (query status, add/remove port forwards, etc.).
//!
//! Socket path strategy:
//! - Prefer: $XDG_RUNTIME_DIR/qsh/<name>.sock
//! - Fallback: /tmp/qsh-<uid>-<name>.sock
//!
//! Messages use length-prefixed protobuf encoding (4-byte LE length + payload).

use bytes::{Buf, BufMut, BytesMut};
use prost::Message as ProstMessage;
use qsh_core::error::{Error, Result};
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use super::proto::{self, Message};

/// Length of the frame header (4 bytes, little-endian u32).
const FRAME_HEADER_LEN: usize = 4;

/// Maximum message size (1MB).
const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Generate a control socket path for the given session name.
///
/// Prefers $XDG_RUNTIME_DIR/qsh/<name>.sock for better per-user isolation.
/// Falls back to /tmp/qsh-<uid>-<name>.sock for compatibility.
pub fn socket_path(name: &str) -> PathBuf {
    if let Ok(xdg_runtime) = std::env::var("XDG_RUNTIME_DIR") {
        let dir = PathBuf::from(xdg_runtime).join("qsh");
        if std::fs::create_dir_all(&dir).is_ok() {
            return dir.join(format!("{}.sock", name));
        }
    }

    // Fallback to /tmp
    let uid = unsafe { libc::geteuid() };
    PathBuf::from(format!("/tmp/qsh-{}-{}.sock", uid, name))
}

/// Get the session directory path where per-session sockets are stored.
///
/// For a session named "foo", returns the directory containing sockets like:
/// - foo.sock (control socket)
/// - foo/term-0.io.sock (terminal I/O socket)
///
/// Creates the directory if it doesn't exist.
pub fn session_dir(name: &str) -> PathBuf {
    if let Ok(xdg_runtime) = std::env::var("XDG_RUNTIME_DIR") {
        let dir = PathBuf::from(xdg_runtime).join("qsh").join(name);
        if std::fs::create_dir_all(&dir).is_ok() {
            return dir;
        }
    }

    // Fallback to /tmp/<session>
    let uid = unsafe { libc::geteuid() };
    let dir = PathBuf::from(format!("/tmp/qsh-{}-{}", uid, name));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// Create a control socket and return a guard plus listener.
///
/// The socket file is removed automatically when the guard is dropped.
/// Permissions are set to 0600 to restrict access to the current user.
pub fn create_socket(path: &Path) -> Result<(ControlSocketGuard, UnixListener)> {
    if path.exists() {
        std::fs::remove_file(path).map_err(Error::Io)?;
    }

    let listener = UnixListener::bind(path).map_err(Error::Io)?;

    // Restrict permissions to current user (0600)
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms).map_err(Error::Io)?;

    Ok((
        ControlSocketGuard {
            path: path.to_path_buf(),
        },
        listener,
    ))
}

/// RAII guard that removes the socket path on drop.
pub struct ControlSocketGuard {
    path: PathBuf,
}

impl Drop for ControlSocketGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Control socket server that manages multiple client connections.
pub struct ControlSocket {
    listener: UnixListener,
    _guard: ControlSocketGuard,
    clients: HashMap<usize, ClientConnection>,
    next_client_id: usize,
}

impl ControlSocket {
    /// Create a new control socket at the given path.
    pub fn new(path: &Path) -> Result<Self> {
        let (guard, listener) = create_socket(path)?;
        Ok(Self {
            listener,
            _guard: guard,
            clients: HashMap::new(),
            next_client_id: 0,
        })
    }

    /// Wait for the next event (new connection or client message).
    ///
    /// This method is designed to be used in a `select!` loop alongside
    /// other async operations.
    ///
    /// Returns:
    /// - `Ok(Some(ControlEvent))` when an event occurs
    /// - `Ok(None)` when all clients have disconnected and listener is closed
    /// - `Err` on I/O errors
    pub async fn next_event(&mut self) -> Result<Option<ControlEvent>> {
        loop {
            tokio::select! {
                // Accept new connections
                result = self.listener.accept() => {
                    match result {
                        Ok((stream, _addr)) => {
                            let client_id = self.next_client_id;
                            self.next_client_id += 1;
                            self.clients.insert(client_id, ClientConnection::new(stream));
                            return Ok(Some(ControlEvent::ClientConnected { client_id }));
                        }
                        Err(e) => {
                            return Err(Error::Io(e));
                        }
                    }
                }

                // Read from existing clients
                Some((client_id, result)) = Self::poll_clients(&mut self.clients) => {
                    match result {
                        Ok(msg) => {
                            // Dispatch based on message kind
                            match msg.kind {
                                Some(proto::message::Kind::Command(cmd)) => {
                                    if let Some(c) = cmd.cmd {
                                        return Ok(Some(ControlEvent::Command {
                                            client_id,
                                            request_id: cmd.request_id,
                                            cmd: c,
                                        }));
                                    }
                                }
                                Some(proto::message::Kind::Stream(stream)) => {
                                    return Ok(Some(ControlEvent::Stream { client_id, stream }));
                                }
                                Some(proto::message::Kind::Event(_)) => {
                                    // Events are server-to-client only, ignore from clients
                                    tracing::debug!(client_id, "Ignoring Event message from client");
                                }
                                None => {
                                    tracing::debug!(client_id, "Empty message from client");
                                }
                            }
                        }
                        Err(e) => {
                            // Client disconnected or error
                            self.clients.remove(&client_id);
                            return Ok(Some(ControlEvent::ClientDisconnected { client_id, error: Some(e) }));
                        }
                    }
                }

                // No more events
                else => {
                    return Ok(None);
                }
            }
        }
    }

    /// Send a message to a specific client.
    pub async fn send_message(&mut self, client_id: usize, message: Message) -> Result<()> {
        if let Some(client) = self.clients.get_mut(&client_id) {
            client.send_message(message).await?;
        }
        Ok(())
    }

    /// Send a command result (success) to a client.
    pub async fn send_command_ok(
        &mut self,
        client_id: usize,
        request_id: u32,
        event_seq: u64,
        data: Option<proto::command_ok::Data>,
    ) -> Result<()> {
        let message = Message {
            kind: Some(proto::message::Kind::Event(proto::Event {
                event_seq,
                evt: Some(proto::event::Evt::CommandResult(proto::CommandResult {
                    request_id,
                    result: Some(proto::command_result::Result::Ok(proto::CommandOk { data })),
                })),
            })),
        };
        self.send_message(client_id, message).await
    }

    /// Send a command error to a client.
    pub async fn send_command_error(
        &mut self,
        client_id: usize,
        request_id: u32,
        event_seq: u64,
        code: proto::ErrorCode,
        message: String,
    ) -> Result<()> {
        let msg = Message {
            kind: Some(proto::message::Kind::Event(proto::Event {
                event_seq,
                evt: Some(proto::event::Evt::CommandResult(proto::CommandResult {
                    request_id,
                    result: Some(proto::command_result::Result::Error(proto::CommandError {
                        code: code.into(),
                        message,
                        details: String::new(),
                    })),
                })),
            })),
        };
        self.send_message(client_id, msg).await
    }

    /// Send a stream message to a specific client.
    pub async fn send_stream(&mut self, client_id: usize, stream: proto::Stream) -> Result<()> {
        let message = Message {
            kind: Some(proto::message::Kind::Stream(stream)),
        };
        self.send_message(client_id, message).await
    }

    /// Poll all clients for incoming messages.
    ///
    /// This is a simplified implementation that polls clients sequentially.
    /// A production version would use futures::select_all for better concurrency.
    async fn poll_clients(
        clients: &mut HashMap<usize, ClientConnection>,
    ) -> Option<(usize, Result<Message>)> {
        if clients.is_empty() {
            return None;
        }

        // Simple sequential polling - in production, use select_all
        for (client_id, client) in clients.iter_mut() {
            // Non-blocking check if client has data ready
            match tokio::time::timeout(
                std::time::Duration::from_millis(1),
                client.read_message(),
            )
            .await
            {
                Ok(result) => return Some((*client_id, result)),
                Err(_) => continue, // Timeout, try next client
            }
        }

        None
    }

    /// Broadcast raw bytes to all connected clients.
    ///
    /// This is used for pushing events (like resource state changes) to all
    /// control clients. Failed sends are logged but don't fail the broadcast.
    pub async fn broadcast(&mut self, data: &[u8]) -> Result<()> {
        let mut failed_clients = Vec::new();

        for (client_id, client) in self.clients.iter_mut() {
            if let Err(e) = client.send_bytes(data).await {
                tracing::debug!(client_id, error = %e, "Failed to send to client during broadcast");
                failed_clients.push(*client_id);
            }
        }

        // Remove failed clients
        for client_id in failed_clients {
            self.clients.remove(&client_id);
        }

        Ok(())
    }

    /// Get the number of connected clients.
    pub fn client_count(&self) -> usize {
        self.clients.len()
    }
}

/// Events emitted by the control socket.
#[derive(Debug)]
pub enum ControlEvent {
    /// A new client connected.
    ClientConnected { client_id: usize },
    /// A client sent a command.
    Command {
        client_id: usize,
        request_id: u32,
        cmd: proto::command::Cmd,
    },
    /// A client sent a stream message (terminal I/O, etc.).
    Stream {
        client_id: usize,
        stream: proto::Stream,
    },
    /// A client disconnected.
    ClientDisconnected {
        client_id: usize,
        error: Option<Error>,
    },
}

/// A single client connection.
struct ClientConnection {
    stream: UnixStream,
    read_buffer: BytesMut,
}

impl ClientConnection {
    fn new(stream: UnixStream) -> Self {
        Self {
            stream,
            read_buffer: BytesMut::with_capacity(8192),
        }
    }

    /// Read a message from the client.
    async fn read_message(&mut self) -> Result<Message> {
        loop {
            // Try to decode a message from the buffer
            if let Some(msg) = Self::try_decode_message(&mut self.read_buffer)? {
                return Ok(msg);
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
                    "client disconnected",
                )));
            }
        }
    }

    /// Try to decode a message from the buffer.
    fn try_decode_message(buf: &mut BytesMut) -> Result<Option<Message>> {
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
        let msg = Message::decode(&payload[..]).map_err(|e| Error::Codec {
            message: format!("protobuf decode failed: {}", e),
        })?;

        Ok(Some(msg))
    }

    /// Send a message to the client.
    async fn send_message(&mut self, message: Message) -> Result<()> {
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

    /// Send raw bytes to the client (for pre-encoded messages).
    ///
    /// The bytes should already be framed (length prefix + payload).
    async fn send_bytes(&mut self, data: &[u8]) -> Result<()> {
        self.stream.write_all(data).await.map_err(Error::Io)?;
        self.stream.flush().await.map_err(Error::Io)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socket_path_xdg() {
        // SAFETY: Tests run serially and this is the only test modifying XDG_RUNTIME_DIR
        unsafe { std::env::set_var("XDG_RUNTIME_DIR", "/run/user/1000") };
        let path = socket_path("test-session");
        assert!(path.to_str().unwrap().contains("/run/user/1000/qsh/test-session.sock"));
    }

    #[test]
    fn test_socket_path_fallback() {
        // SAFETY: Tests run serially and this is the only test removing XDG_RUNTIME_DIR
        unsafe { std::env::remove_var("XDG_RUNTIME_DIR") };
        let path = socket_path("test-session");
        let uid = unsafe { libc::geteuid() };
        assert_eq!(
            path.to_str().unwrap(),
            format!("/tmp/qsh-{}-test-session.sock", uid)
        );
    }

    #[tokio::test]
    async fn test_socket_creation() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("test.sock");

        let (_guard, _listener) = create_socket(&path).unwrap();

        // Verify socket exists
        assert!(path.exists());

        // Verify permissions (0600)
        let metadata = std::fs::metadata(&path).unwrap();
        let perms = metadata.permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }

    #[tokio::test]
    async fn test_socket_cleanup() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("test.sock");

        {
            let (_guard, _listener) = create_socket(&path).unwrap();
            assert!(path.exists());
        }

        // Guard dropped, socket should be removed
        assert!(!path.exists());
    }
}
