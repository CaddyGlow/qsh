//! qsh client binary entry point.
//!
//! Modern roaming-capable remote terminal client.

use clap::Parser;
use tracing::{error, info};

use qsh_client::Cli;

fn main() {
    // Parse CLI arguments
    let cli = Cli::parse();

    // Initialize logging
    let log_format = cli.log_format.into();
    if let Err(e) = qsh_core::init_logging(cli.verbose, cli.log_file.as_deref(), log_format) {
        eprintln!("Failed to initialize logging: {}", e);
        std::process::exit(1);
    }

    // Log startup
    info!(version = env!("CARGO_PKG_VERSION"), "qsh client starting");

    // Extract connection info
    let Some(host) = cli.host() else {
        error!("No destination specified");
        std::process::exit(1);
    };

    let user = cli.effective_user();
    let command = cli.command_string();

    info!(
        host = host,
        user = user,
        port = cli.port,
        command = command.as_deref(),
        "Connecting"
    );

    // TODO: Implement actual connection logic
    // 1. Bootstrap via SSH to discover QUIC endpoint
    // 2. Establish QUIC connection
    // 3. Authenticate and set up session
    // 4. Handle terminal I/O with prediction
    // 5. Set up port forwards if specified

    // Parse forward specifications
    for spec in &cli.local_forward {
        info!(spec = spec.as_str(), "Local forward");
    }
    for spec in &cli.remote_forward {
        info!(spec = spec.as_str(), "Remote forward");
    }
    for spec in &cli.dynamic_forward {
        info!(spec = spec.as_str(), "Dynamic forward");
    }

    // Placeholder for connection logic
    eprintln!(
        "qsh: connecting to {}@{}:{} - not yet fully implemented",
        user.unwrap_or("(default)"),
        host,
        cli.port
    );

    // For now, just exit with a message
    eprintln!("Connection logic is a TODO stub. See Phase 5 in IMPL-SPEC.");
}
