//! qsh server binary entry point.
//!
//! QUIC endpoint for qsh connections.

use clap::Parser;
use tracing::{info, warn};

use qsh_server::Cli;

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
    info!(version = env!("CARGO_PKG_VERSION"), "qsh-server starting");

    // Check TLS configuration
    if !cli.has_tls_config() && !cli.self_signed {
        warn!("No TLS certificate configured. Use --cert/--key or --self-signed");
    }

    let bind_addr = cli.socket_addr();
    info!(
        addr = %bind_addr,
        max_connections = cli.max_connections,
        max_forwards = cli.max_forwards,
        "Binding server"
    );

    if let Some(ipv6_addr) = cli.ipv6_socket_addr() {
        info!(addr = %ipv6_addr, "Also binding IPv6");
    }

    // Log configuration
    if cli.allow_remote_forwards {
        info!("Remote forwards enabled");
    }

    if cli.compress {
        info!("Compression enabled");
    }

    // Log environment variables
    for (name, value) in cli.parse_env_vars() {
        info!(
            name = name.as_str(),
            value = value.as_str(),
            "Environment variable"
        );
    }

    // TODO: Implement actual server logic
    // 1. Load or generate TLS certificates
    // 2. Create QUIC endpoint
    // 3. Accept incoming connections
    // 4. Handle session negotiation
    // 5. Spawn PTY and relay I/O
    // 6. Handle port forwards

    // Placeholder for server logic
    eprintln!(
        "qsh-server: listening on {} - not yet fully implemented",
        bind_addr
    );

    // For now, just exit with a message
    eprintln!("Server logic is a TODO stub. See Phase 5 in IMPL-SPEC.");
}
