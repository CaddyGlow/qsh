//! Interactive REPL for control commands.
//!
//! Provides a readline-based interactive shell for managing qsh sessions.
//! Commands include:
//! - forward add/list/remove
//! - status
//! - session info
//! - ping
//! - exit/quit

use qsh_core::error::{Error, Result};
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;

use super::ControlClient;

/// Run an interactive REPL for control commands.
///
/// If session_name is None, attempts to discover the latest session.
pub async fn run_repl(session_name: Option<&str>) -> Result<i32> {
    // Resolve session name
    let resolved_name = match session_name {
        Some(name) => name.to_string(),
        None => discover_latest_session()?,
    };

    println!("Connecting to session: {}", resolved_name);

    // Connect to the control socket
    let mut client = ControlClient::connect(&resolved_name).await?;

    println!("Connected to qsh control socket");
    println!("Type 'help' for available commands, 'exit' to quit");
    println!();

    // Create readline editor
    let mut rl = DefaultEditor::new().map_err(|e| Error::Transport {
        message: format!("failed to create readline: {}", e),
    })?;

    loop {
        let readline = rl.readline("qsh> ");
        match readline {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                // Add to history
                let _ = rl.add_history_entry(line);

                // Parse and execute command
                match execute_command(&mut client, line).await {
                    Ok(should_exit) => {
                        if should_exit {
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("Error: {}", e);
                    }
                }
            }
            Err(ReadlineError::Interrupted) => {
                // Ctrl-C
                println!("^C");
                continue;
            }
            Err(ReadlineError::Eof) => {
                // Ctrl-D
                println!("exit");
                break;
            }
            Err(err) => {
                eprintln!("Error: {}", err);
                return Ok(1);
            }
        }
    }

    Ok(0)
}

/// Execute a single command from the REPL.
///
/// Returns Ok(true) if the REPL should exit, Ok(false) to continue.
async fn execute_command(client: &mut ControlClient, line: &str) -> Result<bool> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return Ok(false);
    }

    match parts[0] {
        "help" | "?" => {
            print_help();
        }
        "status" => {
            let status = client.get_status().await?;
            println!("State: {}", status.state);
            println!("Server: {}", status.server_addr);
            println!("Uptime: {}s", status.uptime_secs);
            println!("RTT: {}ms", status.rtt_ms);
            println!("Sent: {} bytes", status.bytes_sent);
            println!("Received: {} bytes", status.bytes_received);
            println!("Resources: {}", status.resource_count);
        }
        "resources" | "ls" => {
            let resources = client.list_resources(None).await?;
            if resources.is_empty() {
                println!("No resources");
            } else {
                for info in resources {
                    print!("{:<12} {:<12} {:<10}", info.id, info.kind, info.state);
                    // Show socket path for terminals
                    if let crate::control::ResourceDetails::Terminal(t) = &info.details {
                        if let Some(socket) = &t.socket_path {
                            print!("  {}", socket);
                        }
                    }
                    println!();
                }
            }
        }
        "describe" => {
            if parts.len() < 2 {
                eprintln!("Usage: describe <resource_id>");
                return Ok(false);
            }
            let info = client.describe_resource(parts[1]).await?;
            println!("ID: {}", info.id);
            println!("Kind: {}", info.kind);
            println!("State: {}", info.state);
            println!("Created: {} (epoch)", info.stats.created_at);
            println!("Bytes in: {}", info.stats.bytes_in);
            println!("Bytes out: {}", info.stats.bytes_out);
            match &info.details {
                crate::control::ResourceDetails::Terminal(t) => {
                    println!("Terminal:");
                    println!("  Size: {}x{}", t.cols, t.rows);
                    println!("  Shell: {}", t.shell);
                    println!("  Term type: {}", t.term_type);
                    if let Some(cmd) = &t.command {
                        println!("  Command: {}", cmd);
                    }
                    println!("  Output mode: {:?}", t.output_mode);
                    println!("  PTY: {}", t.allocate_pty);
                    println!("  Attached: {}", t.attached);
                    if let Some(pid) = t.pid {
                        println!("  PID: {}", pid);
                    }
                    if let Some(socket) = &t.socket_path {
                        println!("  Socket: {}", socket);
                    }
                }
                crate::control::ResourceDetails::Forward(f) => {
                    println!("Forward:");
                    println!("  Type: {:?}", f.forward_type);
                    println!("  Bind: {}:{}", f.bind_addr, f.bind_port);
                    if let (Some(host), Some(port)) = (&f.dest_host, f.dest_port) {
                        println!("  Dest: {}:{}", host, port);
                    }
                    println!("  Connections: {}", f.active_connections);
                }
                crate::control::ResourceDetails::FileTransfer(ft) => {
                    println!("File Transfer:");
                    println!("  Local: {}", ft.local_path);
                    println!("  Remote: {}", ft.remote_path);
                    println!("  Upload: {}", ft.upload);
                    println!("  Progress: {}/{} bytes", ft.transferred_bytes, ft.total_bytes);
                    println!("  Files: {}/{} done, {} failed", ft.files_done, ft.files_total, ft.files_failed);
                }
            }
        }
        "close" => {
            if parts.len() < 2 {
                eprintln!("Usage: close <resource_id>");
                return Ok(false);
            }
            client.close_resource(parts[1]).await?;
            println!("Closed resource: {}", parts[1]);
        }
        "ping" => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let pong = client.ping(now).await?;
            println!("Pong! timestamp={}, server_time={}", pong.timestamp, pong.server_time);
        }
        "attach" => {
            if parts.len() < 2 {
                eprintln!("Usage: attach <resource_id>");
                return Ok(false);
            }
            let socket_path = client.attach_terminal(parts[1]).await?;
            println!("Terminal I/O socket: {}", socket_path.display());
            println!("Connect with: socat - UNIX-CONNECT:{}", socket_path.display());
        }
        "detach" => {
            if parts.len() < 2 {
                eprintln!("Usage: detach <resource_id>");
                return Ok(false);
            }
            client.detach_terminal(parts[1]).await?;
            println!("Detached from: {}", parts[1]);
        }
        "resize" => {
            if parts.len() < 4 {
                eprintln!("Usage: resize <resource_id> <cols> <rows>");
                return Ok(false);
            }
            let cols: u32 = parts[2].parse().map_err(|_| Error::Transport {
                message: "invalid cols value".to_string(),
            })?;
            let rows: u32 = parts[3].parse().map_err(|_| Error::Transport {
                message: "invalid rows value".to_string(),
            })?;
            client.resize_terminal(parts[1], cols, rows).await?;
            println!("Resized {} to {}x{}", parts[1], cols, rows);
        }
        "exit" | "quit" => {
            return Ok(true);
        }
        _ => {
            eprintln!("Unknown command: {}", parts[0]);
            eprintln!("Type 'help' for available commands");
        }
    }

    Ok(false)
}

/// Print help text.
fn print_help() {
    println!("Available commands:");
    println!("  status                      - Show connection status");
    println!("  resources, ls               - List all resources");
    println!("  describe <id>               - Show resource details");
    println!("  close <id>                  - Close a resource");
    println!("  ping                        - Send a ping to the session");
    println!("  attach <id>                 - Attach to a terminal");
    println!("  detach <id>                 - Detach from a terminal");
    println!("  resize <id> <cols> <rows>   - Resize a terminal");
    println!("  help, ?                     - Show this help");
    println!("  exit, quit                  - Exit the REPL");
}

/// Discover the latest session by scanning socket directory.
///
/// This is similar to attach.rs's find_latest_pipe() logic.
/// Returns the session name of the most recently modified socket.
pub fn discover_latest_session() -> Result<String> {
    use std::fs;
    use std::path::PathBuf;
    use std::time::SystemTime;

    // Check XDG_RUNTIME_DIR first
    if let Ok(xdg_runtime) = std::env::var("XDG_RUNTIME_DIR") {
        let dir = PathBuf::from(xdg_runtime).join("qsh");
        if dir.exists() {
            if let Some(name) = find_latest_in_dir(&dir)? {
                return Ok(name);
            }
        }
    }

    // Fallback to /tmp
    let uid = unsafe { libc::geteuid() as u32 };
    let prefix = format!("qsh-{}-", uid);
    let tmp_dir = PathBuf::from("/tmp");

    let mut newest: Option<(SystemTime, String)> = None;

    let entries = fs::read_dir(&tmp_dir).map_err(Error::Io)?;
    for entry in entries.flatten() {
        let path = entry.path();

        // Only consider .sock files
        if !path.extension().map(|e| e == "sock").unwrap_or(false) {
            continue;
        }

        if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
            if !name.starts_with(&prefix) {
                continue;
            }
        } else {
            continue;
        }

        if let Ok(meta) = entry.metadata() {
            if let Ok(modified) = meta.modified() {
                let session_name = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .map(|s| s.to_string())
                    .unwrap_or_default();

                match &mut newest {
                    Some((ts, _)) if modified <= *ts => {}
                    _ => newest = Some((modified, session_name)),
                }
            }
        }
    }

    if let Some((_, name)) = newest {
        Ok(name)
    } else {
        Err(Error::Transport {
            message: "no active qsh sessions found".to_string(),
        })
    }
}

/// Find the latest session in a directory.
fn find_latest_in_dir(dir: &std::path::Path) -> Result<Option<String>> {
    use std::fs;
    use std::time::SystemTime;

    let mut newest: Option<(SystemTime, String)> = None;

    let entries = fs::read_dir(dir).map_err(Error::Io)?;
    for entry in entries.flatten() {
        let path = entry.path();

        // Only consider .sock files
        if !path.extension().map(|e| e == "sock").unwrap_or(false) {
            continue;
        }

        if let Ok(meta) = entry.metadata() {
            if let Ok(modified) = meta.modified() {
                let session_name = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .map(|s| s.to_string())
                    .unwrap_or_default();

                match &mut newest {
                    Some((ts, _)) if modified <= *ts => {}
                    _ => newest = Some((modified, session_name)),
                }
            }
        }
    }

    Ok(newest.map(|(_, name)| name))
}

/// Information about a discovered session.
#[derive(Debug)]
pub struct SessionInfo {
    /// Session name (derived from socket filename).
    pub name: String,
    /// Socket path.
    pub socket_path: std::path::PathBuf,
    /// Last modified time of the socket.
    pub modified: std::time::SystemTime,
}

/// List all active sessions by scanning socket directories.
///
/// Returns a list of session info structs sorted by modification time (newest first).
pub fn list_sessions() -> Result<Vec<SessionInfo>> {
    use std::fs;
    use std::path::PathBuf;

    let mut sessions = Vec::new();

    // Check XDG_RUNTIME_DIR first
    if let Ok(xdg_runtime) = std::env::var("XDG_RUNTIME_DIR") {
        let dir = PathBuf::from(xdg_runtime).join("qsh");
        if dir.exists() {
            collect_sessions_from_dir(&dir, &mut sessions)?;
        }
    }

    // Also check /tmp for fallback sockets
    let uid = unsafe { libc::geteuid() as u32 };
    let prefix = format!("qsh-{}-", uid);
    let tmp_dir = PathBuf::from("/tmp");

    if tmp_dir.exists() {
        if let Ok(entries) = fs::read_dir(&tmp_dir) {
            for entry in entries.flatten() {
                let path = entry.path();

                // Only consider .sock files with our prefix
                if !path.extension().map(|e| e == "sock").unwrap_or(false) {
                    continue;
                }

                if let Some(filename) = path.file_name().and_then(|s| s.to_str()) {
                    if !filename.starts_with(&prefix) {
                        continue;
                    }
                } else {
                    continue;
                }

                if let Ok(meta) = entry.metadata() {
                    if let Ok(modified) = meta.modified() {
                        let session_name = path
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .map(|s| {
                                // Strip the prefix to get just the session name
                                s.strip_prefix(&prefix).unwrap_or(s).to_string()
                            })
                            .unwrap_or_default();

                        sessions.push(SessionInfo {
                            name: session_name,
                            socket_path: path,
                            modified,
                        });
                    }
                }
            }
        }
    }

    // Sort by modification time (newest first)
    sessions.sort_by(|a, b| b.modified.cmp(&a.modified));

    Ok(sessions)
}

/// Collect sessions from a directory.
fn collect_sessions_from_dir(dir: &std::path::Path, sessions: &mut Vec<SessionInfo>) -> Result<()> {
    use std::fs;

    let entries = fs::read_dir(dir).map_err(Error::Io)?;
    for entry in entries.flatten() {
        let path = entry.path();

        // Only consider .sock files
        if !path.extension().map(|e| e == "sock").unwrap_or(false) {
            continue;
        }

        if let Ok(meta) = entry.metadata() {
            if let Ok(modified) = meta.modified() {
                let session_name = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .map(|s| s.to_string())
                    .unwrap_or_default();

                sessions.push(SessionInfo {
                    name: session_name,
                    socket_path: path,
                    modified,
                });
            }
        }
    }

    Ok(())
}
