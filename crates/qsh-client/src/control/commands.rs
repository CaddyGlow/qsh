//! Command handlers for control socket requests.
//!
//! This module provides the core command handling logic for the control socket.
//! Each command type has a handler function that processes the request and
//! returns an appropriate response.

use std::sync::Arc;
use std::time::Instant;

use tokio::sync::mpsc;

use super::proto::{
    control_request, control_response, ChannelInfo, ControlRequest, ControlResponse,
    ErrorResponse, ForwardAddResponse, ForwardInfo, ForwardListResponse, ForwardRemoveResponse,
    PongResponse, SessionInfoResponse, StatusResponse, TerminalCloseResponse, TerminalInfo,
    TerminalListResponse, TerminalOpenResponse, TerminalResizeResponse,
};
use crate::forward::ForwardRegistry;

/// Error codes for control protocol errors.
#[repr(u32)]
#[allow(dead_code)]
pub enum ErrorCode {
    UnknownCommand = 1,
    InvalidRequest = 2,
    NotConnected = 3,
    ForwardExists = 4,
    ForwardNotFound = 5,
    PermissionDenied = 6,
    TerminalNotFound = 7,
    InternalError = 100,
}

/// Session state passed to command handlers.
///
/// This provides read-only access to session state for queries, and
/// channels for sending commands that modify state.
pub struct SessionState {
    /// Session name (e.g., "user@host" or explicit -S name).
    pub session_name: String,

    /// Remote host (if connected).
    pub remote_host: Option<String>,

    /// Remote user (if known).
    pub remote_user: Option<String>,

    /// Connection state.
    pub connection_state: ConnectionState,

    /// Server address (if connected).
    pub server_addr: Option<String>,

    /// Connection start time.
    pub connected_at: Option<Instant>,

    /// Forward registry for listing forwards.
    pub forward_registry: Arc<std::sync::Mutex<ForwardRegistry>>,

    /// Channel for sending forward add requests.
    pub forward_add_tx: Option<mpsc::Sender<ForwardAddCommand>>,

    /// Channel for sending forward remove requests.
    pub forward_remove_tx: Option<mpsc::Sender<String>>,

    /// Channel for sending terminal commands.
    pub terminal_cmd_tx: Option<mpsc::Sender<TerminalCommand>>,

    /// Current terminals (channel_id -> info).
    pub terminals: Vec<TerminalState>,

    /// RTT in milliseconds (if known).
    pub rtt_ms: Option<u32>,

    /// Bytes sent.
    pub bytes_sent: u64,

    /// Bytes received.
    pub bytes_received: u64,
}

/// Connection state enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Connected,
    Reconnecting,
    Disconnected,
}

impl ConnectionState {
    pub fn as_str(&self) -> &'static str {
        match self {
            ConnectionState::Connected => "connected",
            ConnectionState::Reconnecting => "reconnecting",
            ConnectionState::Disconnected => "disconnected",
        }
    }
}

/// Command to add a forward.
pub enum ForwardAddCommand {
    Local {
        bind_addr: Option<String>,
        bind_port: u32,
        dest_host: String,
        dest_port: u32,
        response_tx: tokio::sync::oneshot::Sender<Result<String, String>>,
    },
    Remote {
        bind_addr: Option<String>,
        bind_port: u32,
        dest_host: String,
        dest_port: u32,
        response_tx: tokio::sync::oneshot::Sender<Result<String, String>>,
    },
    Dynamic {
        bind_addr: Option<String>,
        bind_port: u32,
        response_tx: tokio::sync::oneshot::Sender<Result<String, String>>,
    },
}

/// Command to control terminals.
pub enum TerminalCommand {
    Open {
        cols: u32,
        rows: u32,
        term_type: String,
        shell: Option<String>,
        command: Option<String>,
        response_tx: tokio::sync::oneshot::Sender<Result<u64, String>>,
    },
    Close {
        terminal_id: u64,
        response_tx: tokio::sync::oneshot::Sender<Result<Option<i32>, String>>,
    },
    Resize {
        terminal_id: u64,
        cols: u32,
        rows: u32,
        response_tx: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
}

/// Terminal state for tracking.
#[derive(Debug, Clone)]
pub struct TerminalState {
    pub terminal_id: u64,
    pub cols: u32,
    pub rows: u32,
    pub status: String,
    pub shell: Option<String>,
    pub pid: Option<u64>,
}

impl Default for SessionState {
    fn default() -> Self {
        Self {
            session_name: String::new(),
            remote_host: None,
            remote_user: None,
            connection_state: ConnectionState::Disconnected,
            server_addr: None,
            connected_at: None,
            forward_registry: Arc::new(std::sync::Mutex::new(ForwardRegistry::new())),
            forward_add_tx: None,
            forward_remove_tx: None,
            terminal_cmd_tx: None,
            terminals: Vec::new(),
            rtt_ms: None,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }
}

/// Handle a control request and return a response.
///
/// This is the main entry point for processing control commands.
/// It dispatches to specific handlers based on the request type.
pub async fn handle_command(request: ControlRequest, state: &SessionState) -> ControlResponse {
    let id = request.id;

    let result = match request.command {
        Some(control_request::Command::GetStatus(_)) => handle_get_status(state),
        Some(control_request::Command::ForwardAdd(req)) => handle_forward_add(req, state).await,
        Some(control_request::Command::ForwardList(_)) => handle_forward_list(state),
        Some(control_request::Command::ForwardRemove(req)) => handle_forward_remove(req, state).await,
        Some(control_request::Command::SessionInfo(_)) => handle_session_info(state),
        Some(control_request::Command::Ping(req)) => handle_ping(req),
        Some(control_request::Command::TerminalOpen(req)) => handle_terminal_open(req, state).await,
        Some(control_request::Command::TerminalClose(req)) => handle_terminal_close(req, state).await,
        Some(control_request::Command::TerminalResize(req)) => handle_terminal_resize(req, state).await,
        Some(control_request::Command::TerminalList(_)) => handle_terminal_list(state),
        None => control_response::Result::Error(ErrorResponse {
            code: ErrorCode::InvalidRequest as u32,
            message: "no command specified".to_string(),
            details: None,
        }),
    };

    ControlResponse { id, result: Some(result) }
}

/// Handle GetStatus request.
fn handle_get_status(state: &SessionState) -> control_response::Result {
    let uptime_secs = state.connected_at.map(|t| t.elapsed().as_secs());

    control_response::Result::Status(StatusResponse {
        state: state.connection_state.as_str().to_string(),
        server_addr: state.server_addr.clone(),
        uptime_secs,
        bytes_sent: Some(state.bytes_sent),
        bytes_received: Some(state.bytes_received),
        rtt_ms: state.rtt_ms,
    })
}

/// Handle ForwardAdd request.
async fn handle_forward_add(
    req: super::proto::ForwardAddRequest,
    state: &SessionState,
) -> control_response::Result {
    let Some(ref forward_add_tx) = state.forward_add_tx else {
        return control_response::Result::Error(ErrorResponse {
            code: ErrorCode::NotConnected as u32,
            message: "forward commands not available".to_string(),
            details: None,
        });
    };

    let (forward_type, bind_addr, bind_port, dest_host, dest_port) = match &req.spec {
        Some(super::proto::forward_add_request::Spec::Local(spec)) => (
            "local",
            spec.bind_addr.clone(),
            spec.bind_port,
            Some(spec.dest_host.clone()),
            Some(spec.dest_port),
        ),
        Some(super::proto::forward_add_request::Spec::Remote(spec)) => (
            "remote",
            spec.bind_addr.clone(),
            spec.bind_port,
            Some(spec.dest_host.clone()),
            Some(spec.dest_port),
        ),
        Some(super::proto::forward_add_request::Spec::Dynamic(spec)) => (
            "dynamic",
            spec.bind_addr.clone(),
            spec.bind_port,
            None,
            None,
        ),
        None => {
            return control_response::Result::Error(ErrorResponse {
                code: ErrorCode::InvalidRequest as u32,
                message: "no forward spec provided".to_string(),
                details: None,
            });
        }
    };

    // Create oneshot channel for response
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();

    // Send command
    let cmd = match &req.spec {
        Some(super::proto::forward_add_request::Spec::Local(spec)) => ForwardAddCommand::Local {
            bind_addr: spec.bind_addr.clone(),
            bind_port: spec.bind_port,
            dest_host: spec.dest_host.clone(),
            dest_port: spec.dest_port,
            response_tx,
        },
        Some(super::proto::forward_add_request::Spec::Remote(spec)) => ForwardAddCommand::Remote {
            bind_addr: spec.bind_addr.clone(),
            bind_port: spec.bind_port,
            dest_host: spec.dest_host.clone(),
            dest_port: spec.dest_port,
            response_tx,
        },
        Some(super::proto::forward_add_request::Spec::Dynamic(spec)) => ForwardAddCommand::Dynamic {
            bind_addr: spec.bind_addr.clone(),
            bind_port: spec.bind_port,
            response_tx,
        },
        None => unreachable!(),
    };

    // Use try_send to avoid blocking - the response will come asynchronously
    // We can't await here because we're inside the select! loop and would deadlock
    if forward_add_tx.try_send(cmd).is_err() {
        return control_response::Result::Error(ErrorResponse {
            code: ErrorCode::InternalError as u32,
            message: "failed to send forward command (channel full or closed)".to_string(),
            details: None,
        });
    }

    // Wait for response with a timeout to avoid deadlock
    // The forward command handler will process this and send back a response
    match tokio::time::timeout(std::time::Duration::from_secs(5), response_rx).await {
        Ok(Ok(Ok(forward_id))) => {
            control_response::Result::ForwardAdded(ForwardAddResponse {
                forward_id: forward_id.clone(),
                info: Some(ForwardInfo {
                    id: forward_id,
                    r#type: forward_type.to_string(),
                    bind_addr: bind_addr.unwrap_or_else(|| "127.0.0.1".to_string()),
                    bind_port,
                    dest_host,
                    dest_port,
                    status: "active".to_string(),
                    connections: Some(0),
                    bytes_sent: Some(0),
                    bytes_received: Some(0),
                }),
            })
        }
        Ok(Ok(Err(e))) => control_response::Result::Error(ErrorResponse {
            code: ErrorCode::InternalError as u32,
            message: format!("forward add error: {}", e),
            details: None,
        }),
        Ok(Err(_)) => control_response::Result::Error(ErrorResponse {
            code: ErrorCode::InternalError as u32,
            message: "forward command channel closed".to_string(),
            details: None,
        }),
        Err(_) => control_response::Result::Error(ErrorResponse {
            code: ErrorCode::InternalError as u32,
            message: "forward command timed out".to_string(),
            details: None,
        }),
    }
}

/// Handle ForwardList request.
fn handle_forward_list(state: &SessionState) -> control_response::Result {
    let forwards = state.forward_registry.lock().unwrap().list();
    control_response::Result::ForwardList(ForwardListResponse { forwards })
}

/// Handle ForwardRemove request.
async fn handle_forward_remove(
    req: super::proto::ForwardRemoveRequest,
    state: &SessionState,
) -> control_response::Result {
    // Try to remove from registry
    let removed = state.forward_registry.lock().unwrap().remove(&req.forward_id);

    if removed.is_some() {
        // Also notify session to stop the forward
        if let Some(ref tx) = state.forward_remove_tx {
            let _ = tx.send(req.forward_id.clone()).await;
        }

        control_response::Result::ForwardRemoved(ForwardRemoveResponse {
            removed: true,
            message: Some(format!("removed forward {}", req.forward_id)),
        })
    } else {
        control_response::Result::Error(ErrorResponse {
            code: ErrorCode::ForwardNotFound as u32,
            message: format!("forward {} not found", req.forward_id),
            details: None,
        })
    }
}

/// Handle SessionInfo request.
fn handle_session_info(state: &SessionState) -> control_response::Result {
    let connected_at = state.connected_at
        .map(|t| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                - t.elapsed().as_secs()
        })
        .unwrap_or(0);

    let channels: Vec<ChannelInfo> = state.terminals
        .iter()
        .map(|t| ChannelInfo {
            channel_id: t.terminal_id,
            r#type: "terminal".to_string(),
            status: t.status.clone(),
            bytes_sent: None,
            bytes_received: None,
        })
        .collect();

    control_response::Result::SessionInfo(SessionInfoResponse {
        session_id: state.session_name.clone(),
        user: state.remote_user.clone(),
        host: state.remote_host.clone(),
        connected_at,
        channels,
    })
}

/// Handle Ping request.
fn handle_ping(req: super::proto::PingRequest) -> control_response::Result {
    control_response::Result::Pong(PongResponse {
        timestamp: req.timestamp,
        server_time: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    })
}

/// Handle TerminalOpen request.
async fn handle_terminal_open(
    req: super::proto::TerminalOpenRequest,
    state: &SessionState,
) -> control_response::Result {
    let Some(ref terminal_cmd_tx) = state.terminal_cmd_tx else {
        return control_response::Result::Error(ErrorResponse {
            code: ErrorCode::NotConnected as u32,
            message: "terminal commands not available".to_string(),
            details: None,
        });
    };

    let cols = req.cols.unwrap_or(80);
    let rows = req.rows.unwrap_or(24);
    let term_type = req.term_type.unwrap_or_else(|| "xterm-256color".to_string());

    let (response_tx, response_rx) = tokio::sync::oneshot::channel();

    let cmd = TerminalCommand::Open {
        cols,
        rows,
        term_type,
        shell: req.shell,
        command: req.command,
        response_tx,
    };

    if terminal_cmd_tx.send(cmd).await.is_err() {
        return control_response::Result::Error(ErrorResponse {
            code: ErrorCode::InternalError as u32,
            message: "failed to send terminal command".to_string(),
            details: None,
        });
    }

    match response_rx.await {
        Ok(Ok(terminal_id)) => {
            control_response::Result::TerminalOpened(TerminalOpenResponse {
                terminal_id,
                cols,
                rows,
            })
        }
        Ok(Err(e)) => control_response::Result::Error(ErrorResponse {
            code: ErrorCode::InternalError as u32,
            message: e,
            details: None,
        }),
        Err(_) => control_response::Result::Error(ErrorResponse {
            code: ErrorCode::InternalError as u32,
            message: "terminal command channel closed".to_string(),
            details: None,
        }),
    }
}

/// Handle TerminalClose request.
async fn handle_terminal_close(
    req: super::proto::TerminalCloseRequest,
    state: &SessionState,
) -> control_response::Result {
    let Some(ref terminal_cmd_tx) = state.terminal_cmd_tx else {
        return control_response::Result::Error(ErrorResponse {
            code: ErrorCode::NotConnected as u32,
            message: "terminal commands not available".to_string(),
            details: None,
        });
    };

    let (response_tx, response_rx) = tokio::sync::oneshot::channel();

    let cmd = TerminalCommand::Close {
        terminal_id: req.terminal_id,
        response_tx,
    };

    if terminal_cmd_tx.send(cmd).await.is_err() {
        return control_response::Result::Error(ErrorResponse {
            code: ErrorCode::InternalError as u32,
            message: "failed to send terminal command".to_string(),
            details: None,
        });
    }

    match response_rx.await {
        Ok(Ok(exit_code)) => {
            control_response::Result::TerminalClosed(TerminalCloseResponse {
                closed: true,
                exit_code,
            })
        }
        Ok(Err(e)) => control_response::Result::Error(ErrorResponse {
            code: ErrorCode::TerminalNotFound as u32,
            message: e,
            details: None,
        }),
        Err(_) => control_response::Result::Error(ErrorResponse {
            code: ErrorCode::InternalError as u32,
            message: "terminal command channel closed".to_string(),
            details: None,
        }),
    }
}

/// Handle TerminalResize request.
async fn handle_terminal_resize(
    req: super::proto::TerminalResizeRequest,
    state: &SessionState,
) -> control_response::Result {
    let Some(ref terminal_cmd_tx) = state.terminal_cmd_tx else {
        return control_response::Result::Error(ErrorResponse {
            code: ErrorCode::NotConnected as u32,
            message: "terminal commands not available".to_string(),
            details: None,
        });
    };

    let (response_tx, response_rx) = tokio::sync::oneshot::channel();

    let cmd = TerminalCommand::Resize {
        terminal_id: req.terminal_id,
        cols: req.cols,
        rows: req.rows,
        response_tx,
    };

    if terminal_cmd_tx.send(cmd).await.is_err() {
        return control_response::Result::Error(ErrorResponse {
            code: ErrorCode::InternalError as u32,
            message: "failed to send terminal command".to_string(),
            details: None,
        });
    }

    match response_rx.await {
        Ok(Ok(())) => {
            control_response::Result::TerminalResized(TerminalResizeResponse { resized: true })
        }
        Ok(Err(e)) => control_response::Result::Error(ErrorResponse {
            code: ErrorCode::TerminalNotFound as u32,
            message: e,
            details: None,
        }),
        Err(_) => control_response::Result::Error(ErrorResponse {
            code: ErrorCode::InternalError as u32,
            message: "terminal command channel closed".to_string(),
            details: None,
        }),
    }
}

/// Handle TerminalList request.
fn handle_terminal_list(state: &SessionState) -> control_response::Result {
    let terminals: Vec<TerminalInfo> = state.terminals
        .iter()
        .map(|t| TerminalInfo {
            terminal_id: t.terminal_id,
            cols: t.cols,
            rows: t.rows,
            status: t.status.clone(),
            shell: t.shell.clone(),
            pid: t.pid,
        })
        .collect();

    control_response::Result::TerminalList(TerminalListResponse { terminals })
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::proto::{
        ForwardAddRequest, LocalForwardSpec, PingRequest, forward_add_request,
    };

    fn make_test_state() -> SessionState {
        SessionState {
            session_name: "test-session".to_string(),
            remote_host: Some("example.com".to_string()),
            remote_user: Some("testuser".to_string()),
            connection_state: ConnectionState::Connected,
            server_addr: Some("192.168.1.1:4433".to_string()),
            connected_at: Some(Instant::now()),
            forward_registry: Arc::new(std::sync::Mutex::new(ForwardRegistry::new())),
            forward_add_tx: None,
            forward_remove_tx: None,
            terminal_cmd_tx: None,
            terminals: vec![
                TerminalState {
                    terminal_id: 1,
                    cols: 80,
                    rows: 24,
                    status: "open".to_string(),
                    shell: Some("/bin/bash".to_string()),
                    pid: Some(12345),
                },
            ],
            rtt_ms: Some(25),
            bytes_sent: 1024,
            bytes_received: 2048,
        }
    }

    #[tokio::test]
    async fn test_handle_get_status() {
        let state = make_test_state();
        let request = ControlRequest {
            id: 1,
            command: Some(control_request::Command::GetStatus(super::super::proto::GetStatusRequest {})),
        };

        let response = handle_command(request, &state).await;
        assert_eq!(response.id, 1);

        match response.result {
            Some(control_response::Result::Status(status)) => {
                assert_eq!(status.state, "connected");
                assert_eq!(status.server_addr, Some("192.168.1.1:4433".to_string()));
                assert_eq!(status.rtt_ms, Some(25));
            }
            _ => panic!("expected status response"),
        }
    }

    #[tokio::test]
    async fn test_handle_session_info() {
        let state = make_test_state();
        let request = ControlRequest {
            id: 2,
            command: Some(control_request::Command::SessionInfo(super::super::proto::SessionInfoRequest {})),
        };

        let response = handle_command(request, &state).await;
        assert_eq!(response.id, 2);

        match response.result {
            Some(control_response::Result::SessionInfo(info)) => {
                assert_eq!(info.session_id, "test-session");
                assert_eq!(info.user, Some("testuser".to_string()));
                assert_eq!(info.host, Some("example.com".to_string()));
                assert_eq!(info.channels.len(), 1);
            }
            _ => panic!("expected session info response"),
        }
    }

    #[tokio::test]
    async fn test_handle_terminal_list() {
        let state = make_test_state();
        let request = ControlRequest {
            id: 3,
            command: Some(control_request::Command::TerminalList(super::super::proto::TerminalListRequest {})),
        };

        let response = handle_command(request, &state).await;
        assert_eq!(response.id, 3);

        match response.result {
            Some(control_response::Result::TerminalList(list)) => {
                assert_eq!(list.terminals.len(), 1);
                let term = &list.terminals[0];
                assert_eq!(term.terminal_id, 1);
                assert_eq!(term.cols, 80);
                assert_eq!(term.rows, 24);
            }
            _ => panic!("expected terminal list response"),
        }
    }

    #[tokio::test]
    async fn test_handle_ping() {
        let state = make_test_state();
        let timestamp = 1234567890;
        let request = ControlRequest {
            id: 4,
            command: Some(control_request::Command::Ping(PingRequest { timestamp })),
        };

        let response = handle_command(request, &state).await;
        assert_eq!(response.id, 4);

        match response.result {
            Some(control_response::Result::Pong(pong)) => {
                assert_eq!(pong.timestamp, timestamp);
                assert!(pong.server_time > 0);
            }
            _ => panic!("expected pong response"),
        }
    }

    #[tokio::test]
    async fn test_handle_forward_list_empty() {
        let state = make_test_state();
        let request = ControlRequest {
            id: 5,
            command: Some(control_request::Command::ForwardList(super::super::proto::ForwardListRequest {})),
        };

        let response = handle_command(request, &state).await;
        assert_eq!(response.id, 5);

        match response.result {
            Some(control_response::Result::ForwardList(list)) => {
                assert!(list.forwards.is_empty());
            }
            _ => panic!("expected forward list response"),
        }
    }
}
