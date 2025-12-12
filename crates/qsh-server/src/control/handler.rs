//! Server control socket handler.
//!
//! Handles incoming commands on the server control socket:
//! - StatusCmd: Return server status (uptime, session count)
//! - SessionsCmd: List active sessions
//! - PingCmd: Health check
//! - EnrollCmd: Generate new session key for bootstrap reuse

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, error, info, warn};

use qsh_control::{
    bind_server_socket, decode_message, encode_message, server_socket_path, ControlSocketGuard,
    SocketError, SocketResult,
};
use qsh_control::proto::{
    command, command_ok, command_result, event, message, Command, CommandError, CommandOk,
    CommandResult, EnrollResult, ErrorCode, Event, Message, PongResult, SessionsResult, StatusResult,
};

use crate::registry::ConnectionRegistry;
use crate::session::SessionAuthorizer;

/// Server control socket handler.
///
/// Listens on the server control socket and handles incoming commands.
pub struct ServerControlHandler {
    /// Unix socket listener.
    listener: UnixListener,
    /// Socket guard (removes socket on drop).
    #[allow(dead_code)]
    guard: ControlSocketGuard,
    /// Connection registry for session info.
    registry: Arc<ConnectionRegistry>,
    /// Session authorizer for enrolling new sessions.
    authorizer: Arc<SessionAuthorizer>,
    /// Server start time.
    start_time: Instant,
    /// Server info for enrollment responses.
    server_info: ServerInfo,
}

/// Server connection info needed for enrollment responses.
#[derive(Clone)]
pub struct ServerInfo {
    /// Server address (IP:port) for QUIC connections.
    pub server_addr: String,
    /// Server port for QUIC connections.
    pub server_port: u32,
    /// Server certificate hash for pinning.
    pub cert_hash: Vec<u8>,
    /// Connect mode string ("initiate" or "respond").
    pub connect_mode: String,
}

impl ServerControlHandler {
    /// Create and bind a new server control handler.
    ///
    /// Returns an error if the socket already exists and is in use (server
    /// already running), or if binding fails for other reasons.
    pub fn bind(
        registry: Arc<ConnectionRegistry>,
        authorizer: Arc<SessionAuthorizer>,
        server_info: ServerInfo,
    ) -> SocketResult<Self> {
        let path = server_socket_path();
        let (guard, listener) = bind_server_socket(&path)?;

        info!(path = %path.display(), "Control socket bound");

        Ok(Self {
            listener,
            guard,
            registry,
            authorizer,
            start_time: Instant::now(),
            server_info,
        })
    }

    /// Try to connect to an existing server control socket.
    ///
    /// Returns Ok(stream) if connection succeeds (server already running),
    /// or Err if no server is running.
    pub async fn try_connect_existing() -> SocketResult<UnixStream> {
        let path = server_socket_path();
        match UnixStream::connect(&path).await {
            Ok(stream) => Ok(stream),
            Err(e) => Err(SocketError::Io(e)),
        }
    }

    /// Run the control socket handler loop.
    ///
    /// This runs until shutdown is signaled or an unrecoverable error occurs.
    pub async fn run(&self) -> SocketResult<()> {
        info!("Server control handler running");

        loop {
            match self.listener.accept().await {
                Ok((stream, addr)) => {
                    debug!(?addr, "Control client connected");
                    let registry = Arc::clone(&self.registry);
                    let authorizer = Arc::clone(&self.authorizer);
                    let start_time = self.start_time;
                    let server_info = self.server_info.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_client(
                            stream,
                            registry,
                            authorizer,
                            start_time,
                            server_info,
                        )
                        .await
                        {
                            warn!("Control client error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Control socket accept error: {}", e);
                    // Brief backoff on accept errors
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
}

/// Handle a single control client connection.
async fn handle_client(
    mut stream: UnixStream,
    registry: Arc<ConnectionRegistry>,
    authorizer: Arc<SessionAuthorizer>,
    start_time: Instant,
    server_info: ServerInfo,
) -> SocketResult<()> {
    let mut buf = vec![0u8; 64 * 1024];

    loop {
        // Read length prefix
        let mut len_buf = [0u8; 4];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // Client disconnected cleanly
                debug!("Control client disconnected");
                return Ok(());
            }
            Err(e) => return Err(SocketError::Io(e)),
        }

        let len = u32::from_le_bytes(len_buf) as usize;
        if len > buf.len() {
            buf.resize(len, 0);
        }

        // Read message body
        stream
            .read_exact(&mut buf[..len])
            .await
            .map_err(SocketError::Io)?;

        // Decode message
        let msg = match decode_message(&buf[..len]) {
            Ok(m) => m,
            Err(e) => {
                warn!("Failed to decode control message: {}", e);
                continue;
            }
        };

        // Handle command
        let response = match msg.kind {
            Some(message::Kind::Command(cmd)) => {
                handle_command(
                    cmd,
                    &registry,
                    &authorizer,
                    start_time,
                    &server_info,
                )
                .await
            }
            _ => {
                // Ignore non-command messages
                continue;
            }
        };

        // Send response
        let response_bytes = encode_message(&response).map_err(|e| SocketError::Codec(e.to_string()))?;
        stream
            .write_all(&response_bytes)
            .await
            .map_err(SocketError::Io)?;
    }
}

/// Handle a single command and return a response message.
async fn handle_command(
    cmd: Command,
    registry: &Arc<ConnectionRegistry>,
    authorizer: &Arc<SessionAuthorizer>,
    start_time: Instant,
    server_info: &ServerInfo,
) -> Message {
    let request_id = cmd.request_id;

    let result = match cmd.cmd {
        Some(command::Cmd::Ping(ping)) => handle_ping(ping.timestamp),
        Some(command::Cmd::Status(_)) => handle_status(registry, start_time).await,
        Some(command::Cmd::Sessions(_)) => handle_sessions(registry).await,
        Some(command::Cmd::Enroll(_)) => handle_enroll(authorizer, server_info).await,
        _ => {
            // Unsupported command
            Err(CommandError {
                code: ErrorCode::Unavailable.into(),
                message: "command not supported by server".to_string(),
                details: String::new(),
            })
        }
    };

    Message {
        kind: Some(message::Kind::Event(Event {
            event_seq: 0,
            evt: Some(event::Evt::CommandResult(CommandResult {
                request_id,
                result: Some(match result {
                    Ok(ok) => command_result::Result::Ok(ok),
                    Err(err) => command_result::Result::Error(err),
                }),
            })),
        })),
    }
}

/// Handle PingCmd.
fn handle_ping(client_timestamp: u64) -> Result<CommandOk, CommandError> {
    Ok(CommandOk {
        data: Some(command_ok::Data::Pong(PongResult {
            timestamp: client_timestamp,
            server_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
        })),
    })
}

/// Handle StatusCmd.
async fn handle_status(
    registry: &Arc<ConnectionRegistry>,
    start_time: Instant,
) -> Result<CommandOk, CommandError> {
    let session_count = registry.session_count().await;
    let uptime_secs = start_time.elapsed().as_secs();

    Ok(CommandOk {
        data: Some(command_ok::Data::Status(StatusResult {
            state: "running".to_string(),
            server_addr: String::new(),  // Server doesn't know its own external address
            uptime_secs,
            bytes_sent: 0,     // TODO: Track actual bytes
            bytes_received: 0, // TODO: Track actual bytes
            rtt_ms: 0,
            resource_count: session_count as u32,
        })),
    })
}

/// Handle SessionsCmd.
async fn handle_sessions(
    registry: &Arc<ConnectionRegistry>,
) -> Result<CommandOk, CommandError> {
    let sessions = registry.list_sessions().await;

    Ok(CommandOk {
        data: Some(command_ok::Data::Sessions(SessionsResult { sessions })),
    })
}

/// Handle EnrollCmd - generate a new session key for bootstrap reuse.
async fn handle_enroll(
    authorizer: &Arc<SessionAuthorizer>,
    server_info: &ServerInfo,
) -> Result<CommandOk, CommandError> {
    // Generate and authorize a new session key
    let session_key = authorizer.allow_random().await;

    Ok(CommandOk {
        data: Some(command_ok::Data::Enroll(EnrollResult {
            server_addr: server_info.server_addr.clone(),
            server_port: server_info.server_port,
            session_key: session_key.to_vec(),
            cert_hash: server_info.cert_hash.clone(),
            connect_mode: server_info.connect_mode.clone(),
        })),
    })
}
