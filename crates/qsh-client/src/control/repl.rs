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

use super::client::ControlClient;

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
            if let Some(addr) = status.server_addr {
                println!("Server: {}", addr);
            }
            if let Some(uptime) = status.uptime_secs {
                println!("Uptime: {}s", uptime);
            }
            if let Some(rtt) = status.rtt_ms {
                println!("RTT: {}ms", rtt);
            }
            if let Some(sent) = status.bytes_sent {
                println!("Sent: {} bytes", sent);
            }
            if let Some(recv) = status.bytes_received {
                println!("Received: {} bytes", recv);
            }
        }
        "session" => {
            let info = client.get_session_info().await?;
            println!("Session ID: {}", info.session_id);
            if let Some(user) = info.user {
                print!("User: {}", user);
                if let Some(host) = info.host {
                    println!("@{}", host);
                } else {
                    println!();
                }
            }
            println!("Connected at: {}", info.connected_at);
            println!("Channels:");
            for ch in info.channels {
                println!(
                    "  {} (type={}, status={})",
                    ch.channel_id, ch.r#type, ch.status
                );
            }
        }
        "ping" => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let pong = client.ping(now).await?;
            println!("Pong! timestamp={}, server_time={}", pong.timestamp, pong.server_time);
        }
        "forward" => {
            if parts.len() < 2 {
                eprintln!("Usage: forward <add|list|remove> [args]");
                return Ok(false);
            }

            match parts[1] {
                "add" => {
                    if parts.len() < 4 {
                        eprintln!("Usage: forward add <local|remote|dynamic> <spec>");
                        eprintln!("  local:   [bind_addr:]port:host:hostport");
                        eprintln!("  remote:  [bind_addr:]port:host:hostport");
                        eprintln!("  dynamic: [bind_addr:]port");
                        return Ok(false);
                    }

                    let forward_type = parts[2];
                    let spec = parts[3];

                    let response = match forward_type {
                        "local" | "l" => client.add_forward_local(spec).await?,
                        "remote" | "r" => client.add_forward_remote(spec).await?,
                        "dynamic" | "d" => client.add_forward_dynamic(spec).await?,
                        _ => {
                            eprintln!("Invalid forward type: {}", forward_type);
                            eprintln!("Must be one of: local, remote, dynamic");
                            return Ok(false);
                        }
                    };

                    println!("Forward added: {}", response.forward_id);
                    if let Some(info) = response.info {
                        println!("  Type: {}", info.r#type);
                        println!(
                            "  Bind: {}:{}",
                            info.bind_addr, info.bind_port
                        );
                        if let Some(dest_host) = info.dest_host {
                            if let Some(dest_port) = info.dest_port {
                                println!("  Dest: {}:{}", dest_host, dest_port);
                            }
                        }
                        println!("  Status: {}", info.status);
                    }
                }
                "list" | "ls" => {
                    let list = client.list_forwards().await?;
                    if list.forwards.is_empty() {
                        println!("No active forwards");
                    } else {
                        println!("Active forwards:");
                        for fwd in list.forwards {
                            print!("  {} - {}:{}", fwd.id, fwd.bind_addr, fwd.bind_port);
                            if let Some(dest_host) = fwd.dest_host {
                                if let Some(dest_port) = fwd.dest_port {
                                    print!(" -> {}:{}", dest_host, dest_port);
                                }
                            }
                            println!(" ({})", fwd.status);
                        }
                    }
                }
                "remove" | "rm" => {
                    if parts.len() < 3 {
                        eprintln!("Usage: forward remove <forward_id>");
                        return Ok(false);
                    }

                    let forward_id = parts[2];
                    let response = client.remove_forward(forward_id).await?;
                    if response.removed {
                        println!("Forward removed: {}", forward_id);
                    } else {
                        println!("Failed to remove forward: {}", forward_id);
                    }
                }
                _ => {
                    eprintln!("Unknown forward subcommand: {}", parts[1]);
                    eprintln!("Available: add, list, remove");
                }
            }
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
    println!("  status               - Show connection status");
    println!("  session              - Show session information");
    println!("  ping                 - Send a ping to the session");
    println!("  forward add <type> <spec>  - Add a port forward");
    println!("    Types: local, remote, dynamic");
    println!("    Spec: [bind_addr:]port:host:hostport (local/remote)");
    println!("          [bind_addr:]port (dynamic)");
    println!("  forward list         - List active forwards");
    println!("  forward remove <id>  - Remove a forward by ID");
    println!("  help, ?              - Show this help");
    println!("  exit, quit           - Exit the REPL");
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
    use std::time::SystemTime;

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
