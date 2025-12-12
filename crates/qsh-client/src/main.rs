//! qsh client binary entry point.
//!
//! Modern roaming-capable remote terminal client.

use std::net::ToSocketAddrs;
use std::time::Duration;

use clap::Parser;
use tracing::{debug, error, info, warn};

use qsh_client::cli::SshBootstrapMode;
use qsh_client::{
    BootstrapMode, ChannelConnection, Cli, ConnectionConfig, ReconnectableConnection, Session,
    SessionContext, SshConfig, bootstrap, get_terminal_size, random_local_port,
};
use qsh_core::protocol::Message;

#[cfg(feature = "standalone")]
use qsh_client::standalone::authenticate as standalone_authenticate;
#[cfg(feature = "standalone")]
use qsh_client::{DirectAuthenticator, DirectConfig, establish_quic_connection};

use qsh_core::protocol::TermSize;

/// Format a duration in human-readable form.
fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else if secs < 86400 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}d {}h", secs / 86400, (secs % 86400) / 3600)
    }
}

/// Resolve session name: use explicit -S flag or auto-discover latest.
fn resolve_session_name(cli: &Cli) -> qsh_core::Result<String> {
    use qsh_client::control::discover_latest_session;

    if let Some(ref name) = cli.session {
        Ok(name.clone())
    } else {
        discover_latest_session()
    }
}

/// Attach to a terminal in an existing qsh session.
///
/// This creates an interactive session with the specified terminal,
/// connecting directly to the terminal's raw I/O socket for low latency.
async fn run_terminal_attach(
    session_name: &str,
    resource_id: Option<String>,
) -> qsh_core::Result<i32> {
    use qsh_client::control::ControlClient;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    let mut client = ControlClient::connect(session_name).await?;

    // Get terminal list to find the target terminal
    let resources = client
        .list_resources(Some(qsh_client::control::ProtoResourceKind::Terminal))
        .await?;

    if resources.is_empty() {
        return Err(qsh_core::Error::Transport {
            message: "no terminals available in session".to_string(),
        });
    }

    // Find the target terminal
    let terminal_id = if let Some(ref id) = resource_id {
        let _ = resources
            .iter()
            .find(|r| r.id == *id)
            .ok_or_else(|| qsh_core::Error::Transport {
                message: format!("terminal {} not found", id),
            })?;
        id.clone()
    } else {
        // Use the most recent (last) terminal
        resources.last().unwrap().id.clone()
    };

    // Get the I/O socket path
    let io_socket_path = client.attach_terminal(&terminal_id).await?;

    // Get terminal size for display
    let info = client.describe_resource(&terminal_id).await?;
    let (cols, rows) = match &info.details {
        qsh_client::control::ResourceDetails::Terminal(t) => (t.cols, t.rows),
        _ => (80, 24),
    };

    // Connect directly to the raw I/O socket
    let io_socket = UnixStream::connect(&io_socket_path).await.map_err(|e| {
        qsh_core::Error::Transport {
            message: format!("failed to connect to terminal I/O socket: {}", e),
        }
    })?;

    // Enter raw mode
    let _raw_guard = qsh_client::RawModeGuard::enter()?;

    // Resize terminal to current tty size
    if let Ok(size) = qsh_client::get_terminal_size() {
        let (term_cols, term_rows) = (size.cols, size.rows);
        let _ = client.resize_terminal(&terminal_id, term_cols as u32, term_rows as u32).await;
    }

    eprintln!("\r\n[Attached to {} ({}x{}). Press Ctrl+] then 'd' to detach]\r\n", terminal_id, cols, rows);

    // Set up SIGWINCH handler for terminal resize
    let mut sigwinch = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
        .map_err(|e| qsh_core::Error::Transport {
            message: format!("failed to set up SIGWINCH handler: {}", e),
        })?;

    // Split the I/O socket
    let (mut io_reader, mut io_writer) = io_socket.into_split();

    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut in_buf = [0u8; 4096];
    let mut out_buf = [0u8; 4096];
    let mut escape_pending = false;

    loop {
        tokio::select! {
            biased;

            // Handle terminal resize (SIGWINCH)
            _ = sigwinch.recv() => {
                if let Ok(size) = qsh_client::get_terminal_size() {
                    let _ = client.resize_terminal(&terminal_id, size.cols as u32, size.rows as u32).await;
                }
            }

            // Read from stdin (higher priority)
            result = stdin.read(&mut in_buf) => {
                match result {
                    Ok(0) => {
                        // EOF on stdin
                        break;
                    }
                    Ok(n) => {
                        let data = &in_buf[..n];

                        // Check for escape sequence: Ctrl+] (0x1d) followed by 'd'
                        if escape_pending {
                            escape_pending = false;
                            if data.first() == Some(&b'd') {
                                eprintln!("\r\n[Detached from {}]\r\n", terminal_id);
                                break;
                            }
                            // Not a detach command, send the Ctrl+] we held back
                            let _ = io_writer.write_all(&[0x1d]).await;
                        }

                        // Check if this chunk contains Ctrl+]
                        if let Some(pos) = data.iter().position(|&b| b == 0x1d) {
                            // Send data before the escape
                            if pos > 0 {
                                let _ = io_writer.write_all(&data[..pos]).await;
                            }
                            // If there's more after Ctrl+], check for 'd'
                            if pos + 1 < data.len() {
                                if data[pos + 1] == b'd' {
                                    eprintln!("\r\n[Detached from {}]\r\n", terminal_id);
                                    break;
                                }
                                // Not 'd', send everything including Ctrl+]
                                let _ = io_writer.write_all(&data[pos..]).await;
                            } else {
                                // Ctrl+] is the last byte, wait for next read
                                escape_pending = true;
                            }
                        } else {
                            // No escape sequence, send all data
                            let _ = io_writer.write_all(data).await;
                        }
                    }
                    Err(e) => {
                        eprintln!("\r\n[stdin error: {}]\r\n", e);
                        break;
                    }
                }
            }

            // Read from terminal I/O socket
            result = io_reader.read(&mut out_buf) => {
                match result {
                    Ok(0) => {
                        // Terminal closed
                        eprintln!("\r\n[Terminal closed]\r\n");
                        break;
                    }
                    Ok(n) => {
                        stdout.write_all(&out_buf[..n]).await?;
                        stdout.flush().await?;
                    }
                    Err(e) => {
                        eprintln!("\r\n[I/O socket error: {}]\r\n", e);
                        break;
                    }
                }
            }
        }
    }

    // Detach from terminal (mainly for cleanup on server side)
    let _ = client.detach_terminal(&terminal_id).await;

    Ok(0)
}

/// Run a control subcommand.
async fn run_control_command(
    cli: &Cli,
    subcommand: &qsh_client::cli::Command,
) -> qsh_core::Result<i32> {
    use qsh_client::cli::{Command, ForwardAction, TerminalAction};
    use qsh_client::control::ControlClient;

    match subcommand {
        Command::Ctl(_) => {
            // Run interactive REPL
            qsh_client::control::run_repl(cli.session.as_deref()).await
        }
        Command::Status(args) => {
            // Get and display status
            let session_name = resolve_session_name(cli)?;

            let mut client = ControlClient::connect(&session_name).await?;
            let status = client.get_status().await?;

            println!("State: {}", status.state);
            println!("Server: {}", status.server_addr);
            println!("Uptime: {}s", status.uptime_secs);
            println!("RTT: {}ms", status.rtt_ms);
            println!("Resources: {}", status.resource_count);

            if args.detailed {
                println!("Bytes sent: {}", status.bytes_sent);
                println!("Bytes received: {}", status.bytes_received);
            }

            Ok(0)
        }
        Command::Forward(fwd_cmd) => {
            let session_name = resolve_session_name(cli)?;
            let mut client = ControlClient::connect(&session_name).await?;

            match &fwd_cmd.action {
                ForwardAction::Add(args) => {
                    use qsh_client::control::ProtoForwardType;

                    // Determine forward type and parse spec
                    let (forward_type, bind_addr, bind_port, dest_host, dest_port) =
                        if let Some(spec) = &args.local {
                            let (bind, host, port) = qsh_client::parse_local_forward(spec)?;
                            (
                                ProtoForwardType::Local,
                                bind.ip().to_string(),
                                bind.port() as u32,
                                Some(host),
                                Some(port as u32),
                            )
                        } else if let Some(spec) = &args.remote {
                            let (bind_addr, bind_port, host, port) =
                                qsh_client::parse_remote_forward(spec)?;
                            (
                                ProtoForwardType::Remote,
                                bind_addr,
                                bind_port as u32,
                                Some(host),
                                Some(port as u32),
                            )
                        } else if let Some(spec) = &args.dynamic {
                            let bind = qsh_client::parse_dynamic_forward(spec)?;
                            (
                                ProtoForwardType::Dynamic,
                                bind.ip().to_string(),
                                bind.port() as u32,
                                None,
                                None,
                            )
                        } else {
                            eprintln!("Must specify -L, -R, or -D");
                            return Ok(1);
                        };

                    // Create the forward via control socket
                    let info = client
                        .create_forward(
                            forward_type,
                            &bind_addr,
                            bind_port,
                            dest_host.as_deref(),
                            dest_port,
                        )
                        .await?;

                    println!("Created forward: {}", info.id);
                    if let qsh_client::control::ResourceDetails::Forward(f) = &info.details {
                        print!("  {}:{}", f.bind_addr, f.bind_port);
                        if let (Some(dest_host), Some(dest_port)) = (&f.dest_host, f.dest_port) {
                            print!(" -> {}:{}", dest_host, dest_port);
                        }
                        println!(" ({:?})", f.forward_type);
                    }
                    Ok(0)
                }
                ForwardAction::List => {
                    // List forward resources
                    let resources = client
                        .list_resources(Some(qsh_client::control::ProtoResourceKind::Forward))
                        .await?;
                    if resources.is_empty() {
                        println!("No active forwards");
                    } else {
                        for info in resources {
                            if let qsh_client::control::ResourceDetails::Forward(f) = &info.details
                            {
                                print!("[{}] {}:{}", info.id, f.bind_addr, f.bind_port);
                                if let (Some(dest_host), Some(dest_port)) =
                                    (&f.dest_host, f.dest_port)
                                {
                                    print!(" -> {}:{}", dest_host, dest_port);
                                }
                                println!(" ({:?}, {})", f.forward_type, info.state);
                            }
                        }
                    }
                    Ok(0)
                }
                ForwardAction::Remove(args) => {
                    client.close_resource(&args.forward_id).await?;
                    println!("Forward removed");
                    Ok(0)
                }
                ForwardAction::Drain(args) => {
                    let timeout = args.timeout.unwrap_or(30);
                    client
                        .drain_resource(&args.forward_id, timeout as u64 * 1000)
                        .await?;
                    println!("Forward drained");
                    Ok(0)
                }
                ForwardAction::Close(args) => {
                    client.close_resource(&args.forward_id).await?;
                    println!("Forward closed");
                    Ok(0)
                }
                ForwardAction::ForceClose(args) => {
                    let _ = client.close_resource(&args.forward_id).await;
                    println!("Forward force closed");
                    Ok(0)
                }
            }
        }
        Command::Sessions => {
            // List active sessions
            use qsh_client::control::list_sessions;
            use std::time::SystemTime;

            let sessions = list_sessions()?;

            if sessions.is_empty() {
                println!("No active qsh sessions found.");
                return Ok(0);
            }

            println!("Active qsh sessions:");
            println!("{:<20} {:<40} {}", "NAME", "SOCKET", "AGE");
            println!("{}", "-".repeat(70));

            for session in sessions {
                let age = SystemTime::now()
                    .duration_since(session.modified)
                    .map(|d| format_duration(d))
                    .unwrap_or_else(|_| "?".to_string());

                println!(
                    "{:<20} {:<40} {}",
                    session.name,
                    session.socket_path.display(),
                    age
                );
            }

            Ok(0)
        }
        Command::Terminal(term_cmd) => {
            let session_name = resolve_session_name(cli)?;
            let mut client = ControlClient::connect(&session_name).await?;

            match &term_cmd.action {
                TerminalAction::Add(args) => {
                    let info = client
                        .create_terminal(
                            args.cols,
                            args.rows,
                            Some(&args.term_type),
                            args.shell.as_deref(),
                            args.command.as_deref(),
                            args.parse_env(),
                            args.output_mode,
                            args.effective_allocate_pty(),
                        )
                        .await?;
                    println!("Terminal created: {}", info.id);
                    if let qsh_client::control::ResourceDetails::Terminal(t) = &info.details {
                        println!("  Size: {}x{}", t.cols, t.rows);
                        println!("  Shell: {}", t.shell);
                        println!("  Term type: {}", t.term_type);
                        if let Some(cmd) = &t.command {
                            println!("  Command: {}", cmd);
                        }
                        println!("  Output mode: {:?}", t.output_mode);
                        println!("  PTY: {}", t.allocate_pty);
                        if let Some(socket) = &t.socket_path {
                            println!("  Socket: {}", socket);
                        }
                    }
                    Ok(0)
                }
                TerminalAction::Close(args) => {
                    // Use resource ID format (e.g., "term-0")
                    let resource_id = if args.resource_id.starts_with("term-") {
                        args.resource_id.clone()
                    } else {
                        format!("term-{}", args.resource_id)
                    };
                    client.close_resource(&resource_id).await?;
                    println!("Terminal closed");
                    Ok(0)
                }
                TerminalAction::List => {
                    let resources = client
                        .list_resources(Some(qsh_client::control::ProtoResourceKind::Terminal))
                        .await?;
                    if resources.is_empty() {
                        println!("No active terminals");
                    } else {
                        for info in resources {
                            if let qsh_client::control::ResourceDetails::Terminal(t) = &info.details
                            {
                                print!(
                                    "{:<12} {}x{:<6} {:<10}",
                                    info.id, t.cols, t.rows, info.state
                                );
                                if let Some(socket) = &t.socket_path {
                                    print!("  {}", socket);
                                }
                                println!();
                            }
                        }
                    }
                    Ok(0)
                }
                TerminalAction::Attach(args) => {
                    // Use resource ID format
                    let resource_id = if args.resource_id.is_empty() {
                        None
                    } else if args.resource_id.starts_with("term-") {
                        Some(args.resource_id.clone())
                    } else {
                        Some(format!("term-{}", args.resource_id))
                    };
                    // Attach requires raw terminal and interactive I/O
                    run_terminal_attach(&session_name, resource_id).await
                }
                TerminalAction::Detach(_args) => {
                    // Detach is handled via escape sequence during attach, not as standalone command
                    println!("Use Ctrl+^ then d to detach from an attached terminal");
                    Ok(0)
                }
                TerminalAction::Resize(args) => {
                    // Use resource ID format
                    let resource_id = if args.resource_id.starts_with("term-") {
                        args.resource_id.clone()
                    } else {
                        format!("term-{}", args.resource_id)
                    };
                    client
                        .resize_terminal(&resource_id, args.cols, args.rows)
                        .await?;
                    println!("Terminal resized to {}x{}", args.cols, args.rows);
                    Ok(0)
                }
            }
        }
        Command::File(file_cmd) => {
            use qsh_client::cli::{FileAction, FilePath};
            use qsh_client::control::proto::FileTransferOptions;

            let session_name = resolve_session_name(cli)?;
            let mut client = ControlClient::connect(&session_name).await?;

            match &file_cmd.action {
                FileAction::Upload(args) => {
                    let options = FileTransferOptions {
                        recursive: args.recursive,
                        resume: args.resume,
                        delta: args.delta && !args.no_delta,
                        compress: args.compress && !args.no_compress,
                        parallel: args.parallel,
                        skip_unchanged: args.skip_unchanged,
                    };

                    let info = client
                        .upload_file(
                            args.local_path.to_string_lossy().as_ref(),
                            &args.remote_path,
                            options,
                        )
                        .await?;

                    println!("Started upload: {}", info.id);
                    if let qsh_client::control::ResourceDetails::FileTransfer(f) = &info.details {
                        println!("  {} -> {}", f.local_path, f.remote_path);
                    }
                    Ok(0)
                }
                FileAction::Download(args) => {
                    let options = FileTransferOptions {
                        recursive: args.recursive,
                        resume: args.resume,
                        delta: args.delta && !args.no_delta,
                        compress: args.compress && !args.no_compress,
                        parallel: args.parallel,
                        skip_unchanged: args.skip_unchanged,
                    };

                    let info = client
                        .download_file(
                            &args.remote_path,
                            args.local_path.to_string_lossy().as_ref(),
                            options,
                        )
                        .await?;

                    println!("Started download: {}", info.id);
                    if let qsh_client::control::ResourceDetails::FileTransfer(f) = &info.details {
                        println!("  {} -> {}", f.remote_path, f.local_path);
                    }
                    Ok(0)
                }
                FileAction::Cp(args) => {
                    // Auto-detect direction from paths
                    let source = FilePath::parse(&args.source);
                    let dest = FilePath::parse(&args.dest);

                    let options = FileTransferOptions {
                        recursive: args.recursive,
                        resume: args.resume,
                        delta: args.delta && !args.no_delta,
                        compress: args.compress && !args.no_compress,
                        parallel: args.parallel,
                        skip_unchanged: args.skip_unchanged,
                    };

                    match (&source, &dest) {
                        (FilePath::Local(local), FilePath::Remote { path: remote, .. }) => {
                            // Upload
                            let info = client
                                .upload_file(
                                    local.to_string_lossy().as_ref(),
                                    remote,
                                    options,
                                )
                                .await?;
                            println!("Started upload: {}", info.id);
                        }
                        (FilePath::Remote { path: remote, .. }, FilePath::Local(local)) => {
                            // Download
                            let info = client
                                .download_file(
                                    remote,
                                    local.to_string_lossy().as_ref(),
                                    options,
                                )
                                .await?;
                            println!("Started download: {}", info.id);
                        }
                        (FilePath::Local(_), FilePath::Local(_)) => {
                            eprintln!("Both source and destination are local paths");
                            eprintln!("For local copy, use 'cp' command");
                            return Ok(1);
                        }
                        (FilePath::Remote { .. }, FilePath::Remote { .. }) => {
                            eprintln!("Remote-to-remote copy not supported");
                            return Ok(1);
                        }
                    }
                    Ok(0)
                }
                FileAction::List => {
                    let transfers = client.list_file_transfers().await?;

                    if transfers.is_empty() {
                        println!("No active file transfers");
                    } else {
                        println!("Active file transfers:");
                        for info in transfers {
                            print!("  {} [{:?}]", info.id, info.state);
                            if let qsh_client::control::ResourceDetails::FileTransfer(f) = &info.details {
                                let direction = if f.upload { "upload" } else { "download" };
                                print!(" {} ", direction);
                                if f.upload {
                                    print!("{} -> {}", f.local_path, f.remote_path);
                                } else {
                                    print!("{} -> {}", f.remote_path, f.local_path);
                                }
                                if f.total_bytes > 0 {
                                    let pct = (f.transferred_bytes as f64 / f.total_bytes as f64) * 100.0;
                                    print!(" ({:.1}%)", pct);
                                }
                            }
                            println!();
                        }
                    }
                    Ok(0)
                }
                FileAction::Cancel(args) => {
                    // Use resource ID format
                    let resource_id = if args.transfer_id.starts_with("xfer-") {
                        args.transfer_id.clone()
                    } else {
                        format!("xfer-{}", args.transfer_id)
                    };

                    client.cancel_file_transfer(&resource_id).await?;
                    println!("Canceled file transfer: {}", resource_id);
                    Ok(0)
                }
            }
        }
    }
}

fn main() {
    // Parse CLI arguments
    let cli = Cli::parse();

    // Check for control subcommands first (before validation)
    if let Some(ref subcommand) = cli.subcommand {
        // Control subcommands have their own flow
        let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
        let result = rt.block_on(async { run_control_command(&cli, subcommand).await });

        match result {
            Ok(exit_code) => std::process::exit(exit_code),
            Err(e) => {
                eprintln!("qsh: {}", e);
                std::process::exit(1);
            }
        }
    }

    // Validate CLI arguments and infer connect mode before doing anything else
    let _effective_connect_mode = match cli.validate_and_infer_connect_mode() {
        Ok(mode) => mode,
        Err(e) => {
            eprintln!("qsh: {}", e);
            std::process::exit(1);
        }
    };

    // Initialize logging
    let log_format = cli.log_format.into();
    if let Err(e) = qsh_core::init_logging(cli.verbose, cli.log_file.as_deref(), log_format) {
        eprintln!("Failed to initialize logging: {}", e);
        std::process::exit(1);
    }

    // Log startup
    info!(version = env!("CARGO_PKG_VERSION"), "qsh client starting");

    // Check for bootstrap mode
    if cli.bootstrap {
        // Run in bootstrap/responder mode
        let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
        let result = rt.block_on(async { run_bootstrap_mode(&cli).await });

        match result {
            Ok(exit_code) => std::process::exit(exit_code),
            Err(e) => {
                error!(error = %e, "Bootstrap mode failed");
                eprintln!("qsh: {}", e);
                std::process::exit(1);
            }
        }
    }

    // Check for attach mode
    if cli.attach.is_some() {
        // Run in attach mode - connect to existing bootstrap session
        let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
        let result = rt.block_on(async { run_attach_mode(cli.attach.as_deref()).await });

        match result {
            Ok(exit_code) => std::process::exit(exit_code),
            Err(e) => {
                error!(error = %e, "Attach mode failed");
                eprintln!("qsh: {}", e);
                std::process::exit(1);
            }
        }
    }

    // Extract connection info
    let Some(host) = cli.host() else {
        error!("No destination specified");
        eprintln!("Usage: qsh [user@]host[:port] [command]");
        std::process::exit(1);
    };

    let user = cli.effective_user();

    info!(host = host, user = user, port = cli.port, "Connecting");

    // Parse forward specifications
    for spec in &cli.local_forward {
        info!(spec = spec.as_str(), "Local forward requested");
    }
    for spec in &cli.remote_forward {
        info!(spec = spec.as_str(), "Remote forward requested");
    }
    for spec in &cli.dynamic_forward {
        info!(spec = spec.as_str(), "Dynamic forward requested");
    }

    // Create tokio runtime
    let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");

    // Run the async connection logic
    let result = rt.block_on(async { run_client(&cli, host, user).await });

    match result {
        Ok(exit_code) => std::process::exit(exit_code),
        Err(e) => {
            error!(error = %e, "Connection failed");
            eprintln!("qsh: {}", e);
            std::process::exit(1);
        }
    }
}

/// Run client in bootstrap/responder mode.
///
/// This is invoked by a remote qsh-server via SSH. The client:
/// 1. Creates a named pipe for attach (stdin/stdout/stderr)
/// 2. Creates a BootstrapEndpoint (generates session key, cert, binds port)
/// 3. Prints bootstrap JSON to stdout (with attach_pipe path)
/// 4. Creates a QUIC acceptor and waits for a single connection
/// 5. Performs handshake as responder
/// 6. Waits for attach client to connect to pipe
/// 7. Runs the Session with pipe as stdin/stdout
async fn run_bootstrap_mode(cli: &Cli) -> qsh_core::Result<i32> {
    use qsh_client::attach::{accept_attach, create_pipe, pipe_path};
    use qsh_core::ConnectMode;
    use qsh_core::bootstrap::{BootstrapEndpoint, BootstrapOptions};
    use qsh_core::transport::{ListenerConfig, QuicAcceptor};
    use std::net::IpAddr;

    info!("Starting bootstrap/responder mode");

    // Create named pipe for attach (handles stdin, stdout, stderr)
    let attach_pipe_path = pipe_path();
    let (_pipe_guard, pipe_listener) = create_pipe(&attach_pipe_path)?;
    info!(pipe = %attach_pipe_path.display(), "Created attach pipe");

    // Parse bind IP
    let bind_ip: IpAddr =
        cli.bootstrap_bind_ip
            .parse()
            .map_err(|e| qsh_core::Error::Transport {
                message: format!("invalid bind IP '{}': {}", cli.bootstrap_bind_ip, e),
            })?;

    // Create bootstrap options
    let mut bootstrap_options = BootstrapOptions::default();
    bootstrap_options.port_range = cli.bootstrap_port_range;
    bootstrap_options.timeout = Duration::from_secs(cli.bootstrap_timeout_secs);

    // Create bootstrap endpoint
    let endpoint = BootstrapEndpoint::new(bind_ip, &bootstrap_options).await?;
    info!(addr = %endpoint.bind_addr, "Bootstrap endpoint created");

    // Print bootstrap response to stdout (with attach_pipe path)
    endpoint.print_response_with_pipe(
        ConnectMode::Respond,
        attach_pipe_path.to_string_lossy().as_ref(),
    )?;
    info!("Bootstrap response sent");

    // Create QUIC acceptor with the endpoint's certificate and key
    // In reverse-attach mode: QUIC server (us) = logical client
    let listener_config = ListenerConfig {
        cert_pem: endpoint.cert_pem.clone(),
        key_pem: endpoint.key_pem.clone(),
        idle_timeout: cli.max_idle_timeout(),
        ticket_key: None,
        // Reverse mode: client is listening, so QUIC server = logical client
        logical_role: qsh_core::transport::EndpointRole::Client,
    };

    let mut acceptor = QuicAcceptor::bind(endpoint.bind_addr, listener_config).await?;
    info!(local_addr = %acceptor.local_addr(), "QUIC acceptor bound, waiting for connection");

    // Accept a single QUIC connection with timeout
    let timeout = Duration::from_secs(cli.bootstrap_timeout_secs);
    let (quic_conn, peer_addr) = tokio::time::timeout(timeout, acceptor.accept())
        .await
        .map_err(|_| qsh_core::Error::Transport {
            message: format!("bootstrap timeout after {}s", cli.bootstrap_timeout_secs),
        })??;

    info!(peer = %peer_addr, "Accepted QUIC connection from initiator (server)");

    // Build connection config for responder mode
    let config = ConnectionConfig {
        server_addr: peer_addr,
        session_key: endpoint.session_key,
        cert_hash: None,
        term_size: TermSize { cols: 80, rows: 24 }, // Placeholder, will be set by attach client
        term_type: "xterm-256color".to_string(),
        env: vec![],
        predictive_echo: false, // No prediction in bootstrap mode
        connect_timeout: Duration::from_secs(5),
        zero_rtt_available: false,
        keep_alive_interval: cli.keep_alive_interval(),
        max_idle_timeout: cli.max_idle_timeout(),
        session_data: None,
        local_port: None,
        connect_mode: ConnectMode::Respond,
    };

    // Complete qsh protocol handshake as responder
    let conn = std::sync::Arc::new(ChannelConnection::from_quic(quic_conn, config.clone()).await?);
    info!(
        rtt = ?conn.rtt().await,
        session_id = ?conn.session_id(),
        "Bootstrap handshake complete"
    );

    // Open terminal channel IMMEDIATELY after handshake
    // This starts the shell on the server side so it's ready when attach connects
    let terminal_params = qsh_core::protocol::TerminalParams {
        term_size: TermSize { cols: 80, rows: 24 }, // Default size, attach client can resize
        term_type: std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string()),
        env: vec![],
        shell: None,
        command: None,
        allocate_pty: true,
        last_generation: 0,
        last_input_seq: 0,
        output_mode: cli.output_mode(),
    };

    let terminal = conn.open_terminal(terminal_params).await?;
    info!(channel_id = ?terminal.channel_id(), "Terminal channel opened, shell is running");

    // Buffer for terminal output received before attach connects
    let mut output_buffer: Vec<u8> = Vec::new();

    // Wait for attach client to connect.
    // We must process control messages (heartbeats) AND terminal output from the server
    // to keep the connection alive and buffer any shell output.
    info!(
        "Waiting for attach client on {}",
        attach_pipe_path.display()
    );

    // Use a channel to signal when attach client connects
    let (attach_tx, attach_rx) = tokio::sync::oneshot::channel();

    // Spawn task to accept attach client
    let attach_task = tokio::spawn(async move {
        let result = accept_attach(&pipe_listener).await;
        let _ = attach_tx.send(result);
    });

    // Process control messages and terminal output until attach client connects
    let mut attach_rx = attach_rx;
    let attach_result = loop {
        tokio::select! {
            biased;

            // Check if attach client connected
            result = &mut attach_rx => {
                match result {
                    Ok(r) => break r,
                    Err(_) => {
                        return Err(qsh_core::Error::Transport {
                            message: "attach accept task failed".to_string(),
                        });
                    }
                }
            }

            // Read terminal output and buffer it
            event = terminal.recv_event() => {
                match event {
                    Ok(qsh_client::channel::TerminalEvent::Output(output)) => {
                        debug!(len = output.data.len(), "Buffering terminal output while waiting for attach");
                        output_buffer.extend_from_slice(&output.data);
                    }
                    Ok(qsh_client::channel::TerminalEvent::StateSync(_)) => {
                        debug!("Received state sync while waiting for attach");
                    }
                    Err(e) => {
                        warn!(error = %e, "Terminal output error while waiting for attach");
                        // Terminal may have closed - continue waiting for attach
                    }
                }
            }

            // Process control messages from server (mainly heartbeats)
            msg = conn.recv_control() => {
                match msg {
                    Ok(Message::Heartbeat(hb)) => {
                        // Echo heartbeat back to server
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| (d.as_millis() % 65536) as u16)
                            .unwrap_or(0);
                        let reply = Message::Heartbeat(qsh_core::protocol::HeartbeatPayload::reply(
                            now_ms,
                            hb.timestamp,
                            hb.seq,
                        ));
                        if let Err(e) = conn.send_control(&reply).await {
                            warn!(error = %e, "Failed to send heartbeat reply while waiting for attach");
                        } else {
                            debug!(seq = hb.seq, "Replied to heartbeat while waiting for attach");
                        }
                    }
                    Ok(msg) => {
                        debug!(?msg, "Received control message while waiting for attach");
                    }
                    Err(e) => {
                        warn!(error = %e, "Control stream error while waiting for attach");
                    }
                }
            }
        }
    };

    // Clean up attach task if it's still running
    attach_task.abort();

    let attach_stream = attach_result?;
    info!(
        buffered_output = output_buffer.len(),
        "Attach client connected"
    );

    // Flush buffered output to attach client
    use tokio::io::AsyncWriteExt;
    let (mut attach_rx, mut attach_tx) = attach_stream.into_split();
    if !output_buffer.is_empty() {
        info!(
            len = output_buffer.len(),
            "Flushing buffered terminal output to attach client"
        );
        attach_tx
            .write_all(&output_buffer)
            .await
            .map_err(|e| qsh_core::Error::Io(e))?;
    }

    // Simple relay loop: attach <-> terminal channel
    // Also process heartbeats to keep connection alive
    info!("Starting bootstrap relay loop");

    let mut attach_buf = [0u8; 4096];
    let mut heartbeat_interval = tokio::time::interval(Duration::from_secs(5));
    heartbeat_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            biased;

            // Attach client input -> terminal channel
            result = tokio::io::AsyncReadExt::read(&mut attach_rx, &mut attach_buf) => {
                match result {
                    Ok(0) => {
                        info!("Attach client disconnected");
                        break;
                    }
                    Ok(n) => {
                        // send_input takes (data, predictable) - not predictable for bootstrap relay
                        if let Err(e) = terminal.send_input(&attach_buf[..n], false).await {
                            warn!(error = %e, "Failed to send to terminal channel");
                            break;
                        } else {
                            debug!(len = n, "Forwarded attach input to terminal");
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to read from attach client");
                        break;
                    }
                }
            }

            // Terminal channel output -> attach client
            event = terminal.recv_event() => {
                match event {
                    Ok(qsh_client::channel::TerminalEvent::Output(output)) => {
                        if let Err(e) = attach_tx.write_all(&output.data).await {
                            warn!(error = %e, "Failed to write to attach client");
                            break;
                        }
                    }
                    Ok(qsh_client::channel::TerminalEvent::StateSync(_)) => {
                        // State sync is for reconnection, not relevant for bootstrap relay
                        debug!("Ignoring state sync in bootstrap relay");
                    }
                    Err(e) => {
                        warn!(error = %e, "Terminal channel closed");
                        break;
                    }
                }
            }

            // Process control messages (heartbeats)
            msg = conn.recv_control() => {
                match msg {
                    Ok(Message::Heartbeat(hb)) => {
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| (d.as_millis() % 65536) as u16)
                            .unwrap_or(0);
                        let reply = Message::Heartbeat(qsh_core::protocol::HeartbeatPayload::reply(
                            now_ms,
                            hb.timestamp,
                            hb.seq,
                        ));
                        if let Err(e) = conn.send_control(&reply).await {
                            warn!(error = %e, "Failed to send heartbeat reply");
                        }
                    }
                    Ok(Message::ChannelClose(_)) => {
                        info!("Server closed terminal channel");
                        break;
                    }
                    Ok(msg) => {
                        debug!(?msg, "Received control message");
                    }
                    Err(e) => {
                        warn!(error = %e, "Control stream error");
                        break;
                    }
                }
            }
        }
    }

    info!("Bootstrap session ended");
    Ok(0)
}

/// Run client in attach mode.
///
/// Connects to an existing bootstrap session via named pipe.
/// Provides stdin/stdout/stderr access to the remote shell.
async fn run_attach_mode(pipe_path: Option<&str>) -> qsh_core::Result<i32> {
    use qsh_client::attach::{connect_attach, find_latest_pipe};
    use qsh_client::terminal::RawModeGuard;
    use std::path::Path;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let resolved_path = match pipe_path {
        Some(p) if !p.is_empty() => Path::new(p).to_path_buf(),
        _ => find_latest_pipe()?,
    };

    info!(pipe = %resolved_path.display(), "Attaching to bootstrap session");

    // Connect to the pipe
    let mut pipe = connect_attach(&resolved_path).await?;
    info!("Connected to bootstrap session");

    // Put terminal in raw mode
    let _raw_guard = RawModeGuard::enter()?;

    // Get stdin and stdout/stderr
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let stderr = tokio::io::stderr();

    // Relay I/O between local terminal and pipe
    // Pipe output goes to both stdout and stderr (PTY merges them)
    let mut stdin_buf = [0u8; 4096];
    let mut pipe_buf = [0u8; 4096];

    loop {
        tokio::select! {
            // Local stdin -> Pipe
            result = stdin.read(&mut stdin_buf) => {
                match result {
                    Ok(0) => {
                        info!("Stdin closed");
                        break;
                    }
                    Ok(n) => {
                        debug!(len = n, "Attach stdin read");
                        if let Err(e) = pipe.write_all(&stdin_buf[..n]).await {
                            warn!(error = %e, "Failed to write to pipe");
                            break;
                        }
                        let _ = pipe.flush().await;
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to read from stdin");
                        break;
                    }
                }
            }

            // Pipe -> Local stdout (PTY output includes both stdout and stderr)
            result = pipe.read(&mut pipe_buf) => {
                match result {
                    Ok(0) => {
                        info!("Pipe closed");
                        break;
                    }
                    Ok(n) => {
                        // Write to stdout (PTY merges stdout/stderr)
                        if let Err(e) = stdout.write_all(&pipe_buf[..n]).await {
                            warn!(error = %e, "Failed to write to stdout");
                            break;
                        }
                        let _ = stdout.flush().await;
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to read from pipe");
                        break;
                    }
                }
            }
        }
    }

    // Suppress unused variable warning
    let _ = stderr;

    info!("Attach session ended");
    Ok(0)
}

#[cfg(feature = "standalone")]
async fn run_client_standalone(cli: &Cli, host: &str, user: Option<&str>) -> qsh_core::Result<i32> {
    use rand::RngCore;

    // Determine server address for direct mode
    let server_addr_str = if let Some(ref server) = cli.server {
        server.clone()
    } else {
        // Default to host:4433 if not specified
        format!("{}:4433", host)
    };

    let direct_config = DirectConfig {
        server_addr: server_addr_str.clone(),
        key_path: cli.key.clone(),
        known_hosts_path: cli.known_hosts.clone(),
        accept_unknown_host: cli.accept_unknown_host,
        no_agent: cli.no_agent,
    };

    // Build direct authenticator (loads known_hosts and signing key)
    let mut authenticator = DirectAuthenticator::new(&direct_config).await?;

    // Resolve server address for QUIC
    let server_sock_addr = server_addr_str
        .to_socket_addrs()
        .map_err(|e| qsh_core::Error::Transport {
            message: format!("failed to resolve server address: {}", e),
        })?
        .next()
        .ok_or_else(|| qsh_core::Error::Transport {
            message: "no addresses found for server".to_string(),
        })?;

    // Generate a fresh session key (not authenticated by standalone auth;
    // used for session identification and reconnection).
    let mut session_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut session_key);

    let conn_config = ConnectionConfig {
        server_addr: server_sock_addr,
        session_key,
        cert_hash: None,
        term_size: get_term_size(),
        term_type: std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string()),
        env: collect_terminal_env(),
        predictive_echo: !cli.no_prediction,
        connect_timeout: cli.connect_timeout(),
        zero_rtt_available: false,
        keep_alive_interval: cli.keep_alive_interval(),
        max_idle_timeout: cli.max_idle_timeout(),
        session_data: None,
        local_port: Some(random_local_port()),
        connect_mode: cli.connect_mode.into(),
    };

    info!(addr = %conn_config.server_addr, local_port = ?conn_config.local_port, "Connecting directly to server");
    let quic_conn = establish_quic_connection(&conn_config).await?;

    // Perform standalone authentication on a dedicated server-initiated stream.
    // Server opens the stream and sends AuthChallenge; client accepts and responds.
    let (mut send, mut recv) =
        quic_conn
            .accept_bi()
            .await
            .map_err(|e| qsh_core::Error::Transport {
                message: format!("failed to accept auth stream: {}", e),
            })?;

    standalone_authenticate(&mut authenticator, &mut send, &mut recv).await?;
    info!("Standalone authentication succeeded");

    // Complete qsh protocol handshake using channel model.
    let conn = ChannelConnection::from_quic(quic_conn, conn_config.clone()).await?;
    info!(rtt = ?conn.rtt().await, session_id = ?conn.session_id(), "Connected to server");

    // Create session context for reconnection support (with authenticator for re-auth)
    let context =
        SessionContext::new(conn_config, conn.session_id()).with_authenticator(authenticator);

    // Create reconnectable connection wrapper
    let reconnectable = std::sync::Arc::new(ReconnectableConnection::new(conn, context));

    // Cache session data for 0-RTT reconnection (critical for Mosh-style fast recovery)
    reconnectable.store_session_data().await;

    // Build and run unified session (handles both terminal and forwards)
    let user_host = format_user_host(user, host);
    let session = Session::from_cli(reconnectable, cli, Some(user_host))?;
    session.run().await
}

/// Run client using SSH bootstrap mode.
///
/// This uses SSH to bootstrap the qsh server, then connects via QUIC.
/// Uses `ChannelConnection` which does not open a terminal automatically.
/// Instead, we explicitly open a terminal channel after the handshake.
async fn run_client_ssh_bootstrap(
    cli: &Cli,
    host: &str,
    user: Option<&str>,
) -> qsh_core::Result<i32> {
    // Build server args, adding --mode if requested
    let mut server_args = cli.bootstrap_server_args.clone().unwrap_or_default();

    // Pass output mode to server
    let output_mode = cli.output_mode();
    if !server_args.is_empty() {
        server_args.push(' ');
    }
    server_args.push_str("--mode ");
    server_args.push_str(match output_mode {
        qsh_core::protocol::OutputMode::Direct => "direct",
        qsh_core::protocol::OutputMode::Mosh => "mosh",
        qsh_core::protocol::OutputMode::StateDiff => "state-diff",
    });

    // Build SSH config from CLI options
    let mut bootstrap_options = qsh_core::bootstrap::BootstrapOptions::default();
    bootstrap_options.port_range = cli.bootstrap_port_range;
    bootstrap_options.extra_env = cli.parse_bootstrap_server_env()?;
    bootstrap_options.extra_args = if server_args.is_empty() {
        None
    } else {
        Some(server_args)
    };
    bootstrap_options.timeout = std::time::Duration::from_secs(30);

    let ssh_config = SshConfig {
        connect_timeout: std::time::Duration::from_secs(30),
        identity_file: cli.identity.first().cloned(),
        skip_host_key_check: false,
        bootstrap_options,
        mode: match cli.ssh_bootstrap_mode {
            SshBootstrapMode::Ssh => BootstrapMode::SshCli,
            SshBootstrapMode::Russh => BootstrapMode::Russh,
        },
    };

    // Bootstrap returns a handle that keeps the SSH process alive
    let bootstrap_handle = bootstrap(host, cli.port, user, &ssh_config).await?;
    let endpoint_info = &bootstrap_handle.endpoint_info;

    // Use bootstrap info to connect
    let connect_host = if endpoint_info.address == "0.0.0.0"
        || endpoint_info.address == "::"
        || endpoint_info.address.starts_with("0.")
    {
        host.to_string()
    } else {
        endpoint_info.address.clone()
    };

    let addr = format!("{}:{}", connect_host, endpoint_info.port)
        .to_socket_addrs()
        .map_err(|e| qsh_core::Error::Transport {
            message: format!("failed to resolve server address: {}", e),
        })?
        .next()
        .ok_or_else(|| qsh_core::Error::Transport {
            message: "no addresses found for server".to_string(),
        })?;

    let session_key = endpoint_info.decode_session_key()?;
    let cert_hash = endpoint_info.decode_cert_hash().ok();

    let config = ConnectionConfig {
        server_addr: addr,
        session_key,
        cert_hash,
        term_size: get_term_size(),
        term_type: std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string()),
        env: collect_terminal_env(),
        predictive_echo: !cli.no_prediction,
        connect_timeout: cli.connect_timeout(),
        zero_rtt_available: false,
        keep_alive_interval: cli.keep_alive_interval(),
        max_idle_timeout: cli.max_idle_timeout(),
        session_data: None,
        local_port: Some(random_local_port()), // Mosh-style port range
        connect_mode: cli.connect_mode.into(),
    };

    // Connect using the channel model (no implicit terminal)
    let conn = ChannelConnection::connect(config.clone()).await?;
    info!(
        rtt = ?conn.rtt().await,
        session_id = ?conn.session_id(),
        "Connection established"
    );

    // Drop the bootstrap handle now that QUIC connection is established
    drop(bootstrap_handle);

    // Create session context for reconnection support
    let context = SessionContext::new(config, conn.session_id());

    // Create reconnectable connection wrapper
    let reconnectable = std::sync::Arc::new(ReconnectableConnection::new(conn, context));

    // Cache session data for 0-RTT reconnection (critical for Mosh-style fast recovery)
    reconnectable.store_session_data().await;

    // Build and run unified session (handles both terminal and forwards)
    let user_host = format_user_host(user, host);
    let session = Session::from_cli(reconnectable, cli, Some(user_host))?;
    session.run().await
}

async fn run_client(cli: &Cli, host: &str, user: Option<&str>) -> qsh_core::Result<i32> {
    #[cfg(feature = "standalone")]
    if cli.direct {
        return run_client_standalone(cli, host, user).await;
    }

    // Use SSH bootstrap mode
    run_client_ssh_bootstrap(cli, host, user).await
}

fn get_term_size() -> TermSize {
    match get_terminal_size() {
        Ok(size) => size,
        Err(_) => TermSize { cols: 80, rows: 24 },
    }
}

/// Collect terminal-related environment variables to pass to the remote PTY.
///
/// Note: TERM is handled separately as part of the PTY request (like SSH does),
/// not as an environment variable here.
fn collect_terminal_env() -> Vec<(String, String)> {
    let mut env = Vec::new();

    // COLORTERM indicates true color support (truecolor/24bit)
    if let Ok(val) = std::env::var("COLORTERM") {
        env.push(("COLORTERM".to_string(), val));
    }

    // NO_COLOR disables color output (https://no-color.org/)
    if let Ok(val) = std::env::var("NO_COLOR") {
        env.push(("NO_COLOR".to_string(), val));
    }

    // Locale variables (LANG and LC_*)
    if let Ok(val) = std::env::var("LANG") {
        env.push(("LANG".to_string(), val));
    }
    for (key, val) in std::env::vars() {
        if key.starts_with("LC_") {
            env.push((key, val));
        }
    }

    env
}

/// Format user@host string for overlay display.
fn format_user_host(user: Option<&str>, host: &str) -> String {
    match user {
        Some(u) => format!("{}@{}", u, host),
        None => host.to_string(),
    }
}
