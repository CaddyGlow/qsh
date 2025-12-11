//! qsh server binary entry point.
//!
//! QUIC endpoint for qsh connections using the SSH-style channel model.

use std::net::SocketAddr;
use std::sync::Arc;

/// Enable the single-instance-per-user singleton via named pipe.
/// When enabled, bootstrap mode will reuse an existing server instance if one is running.
/// Set to false to allow multiple independent bootstrap instances (useful for debugging).
const ENABLE_BOOTSTRAP_SINGLETON: bool = false;

use clap::Parser;
use tracing::{error, info, warn};

use qsh_core::protocol::Capabilities;
use qsh_core::transport::generate_self_signed_cert;
use qsh_server::listener::{QshListener, ServerConfig};
use qsh_server::{BootstrapServer, Cli, ConnectionConfig, SessionAuthorizer, SessionConfig};

#[cfg(feature = "standalone")]
use qsh_server::{StandaloneAuthenticator, StandaloneConfig};

fn main() {
    // Parse CLI arguments
    let cli = Cli::parse();

    // Standalone mode is incompatible with bootstrap mode (they use different auth flows).
    #[cfg(feature = "standalone")]
    if cli.standalone && cli.bootstrap {
        eprintln!("qsh-server: --standalone cannot be used with --bootstrap");
        std::process::exit(1);
    }

    // Bootstrap mode: minimal logging to stderr, JSON output to stdout
    if cli.bootstrap {
        // Only log errors in bootstrap mode (to stderr)
        let log_path = cli.log_file.as_deref();
        if let Err(e) = qsh_core::init_logging(cli.verbose, log_path, cli.log_format.into()) {
            eprintln!("Failed to initialize logging: {}", e);
            std::process::exit(1);
        }

        let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
        let result = rt.block_on(run_bootstrap(&cli));

        if let Err(e) = result {
            // Output error as JSON
            let resp = qsh_core::bootstrap::BootstrapResponse::error(e.to_string());
            if let Ok(json) = resp.to_json() {
                println!("{}", json);
            } else {
                eprintln!("qsh-server: {}", e);
            }
            std::process::exit(1);
        }
        return;
    }

    // Normal server mode
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
        warn!("Generating self-signed certificate for this session");
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

    // Create tokio runtime
    let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");

    // Run the server
    let result = rt.block_on(run_server(&cli, bind_addr));

    if let Err(e) = result {
        error!(error = %e, "Server error");
        eprintln!("qsh-server: {}", e);
        std::process::exit(1);
    }
}

/// Run the server in bootstrap mode.
///
/// This mode:
/// 1. Generates session key and self-signed certificate
/// 2. Binds to an available port (or specified port)
/// 3. Outputs JSON with connection info to stdout
/// 4. Accepts a single connection
/// 5. Handles that session then exits
async fn run_bootstrap(cli: &Cli) -> qsh_core::Result<()> {
    // Singleton mode: try to reuse an existing server instance via named pipe.
    if ENABLE_BOOTSTRAP_SINGLETON {
        let pipe_path = qsh_server::bootstrap::bootstrap_pipe_path();
        if let Some(json) = qsh_server::bootstrap::try_existing_bootstrap(&pipe_path).await? {
            println!("{}", json);
            return Ok(());
        }
    }

    // Use port 0 to auto-select from range, or specified port
    let port = if cli.port == 4433 { 0 } else { cli.port };

    // Create bootstrap server
    let bootstrap = Arc::new(BootstrapServer::new(cli.bind_addr, port, cli.port_range).await?);

    // Authorize the initial session key and keep registry aligned.
    let authorizer = Arc::new(SessionAuthorizer::new());
    authorizer.allow(bootstrap.session_key()).await;

    // Singleton mode: create pipe for subsequent bootstrap requests.
    let _pipe_guard;
    let _pipe_task;
    if ENABLE_BOOTSTRAP_SINGLETON {
        let pipe_path = qsh_server::bootstrap::bootstrap_pipe_path();
        _pipe_guard = Some(qsh_server::bootstrap::create_pipe(&pipe_path).map_err(|e| {
            qsh_core::Error::Transport {
                message: format!("failed to create bootstrap pipe: {}", e),
            }
        })?);
        _pipe_task = Some(qsh_server::bootstrap::spawn_pipe_listener(
            pipe_path,
            bootstrap.clone(),
            authorizer.clone(),
        ));
    } else {
        _pipe_guard = None;
        _pipe_task = None;
    }

    // Output connection info to stdout
    bootstrap.print_response(None)?;

    // Build session config
    let session_config = SessionConfig {
        capabilities: Capabilities {
            predictive_echo: true,
            compression: cli.compress,
            max_forwards: cli.max_forwards,
            tunnel: false,
        },
        idle_timeout: std::time::Duration::from_secs(300),
        max_forwards: cli.max_forwards,
        allow_remote_forwards: cli.allow_remote_forwards,
    };

    // Build connection config
    let conn_config = ConnectionConfig {
        max_forwards: cli.max_forwards,
        allow_remote_forwards: cli.allow_remote_forwards,
        output_mode: cli.output_mode,
        ..Default::default()
    };

    // Build server config
    let server_config = ServerConfig {
        bind_addr: bootstrap.local_addr(),
        cert_pem: bootstrap.cert_pem().to_vec(),
        key_pem: bootstrap.key_pem().to_vec(),
        session_config,
        conn_config,
        bootstrap_mode: true,
    };

    // Create listener
    // For quiche backend, we share the socket that bootstrap already bound
    // For s2n backend, we let the listener bind its own socket
    #[cfg(feature = "quiche-backend")]
    let listener = QshListener::with_socket(bootstrap.socket(), server_config)
        .await?
        .with_authorizer(authorizer);

    #[cfg(not(feature = "quiche-backend"))]
    let listener = QshListener::bind(server_config)
        .await?
        .with_authorizer(authorizer);

    // Bootstrap mode: run until session expires
    listener.run(true).await
}

async fn run_server(cli: &Cli, bind_addr: SocketAddr) -> qsh_core::Result<()> {
    // Generate or load TLS certificate (now expects PEM format)
    let (cert_pem, key_pem) = if cli.has_tls_config() {
        // Load from files (expect PEM format)
        let cert_path = cli.cert_file.as_ref().unwrap();
        let key_path = cli.key_file.as_ref().unwrap();

        let cert = tokio::fs::read(cert_path)
            .await
            .map_err(|e| qsh_core::Error::Transport {
                message: format!("failed to read certificate: {}", e),
            })?;
        let key = tokio::fs::read(key_path)
            .await
            .map_err(|e| qsh_core::Error::Transport {
                message: format!("failed to read key: {}", e),
            })?;

        (cert, key)
    } else {
        // Generate self-signed certificate (returns PEM)
        info!("Generating self-signed certificate");
        generate_self_signed_cert()?
    };

    // Build session config
    let session_config = SessionConfig {
        capabilities: Capabilities {
            predictive_echo: true,
            compression: cli.compress,
            max_forwards: cli.max_forwards,
            tunnel: false,
        },
        idle_timeout: std::time::Duration::from_secs(300),
        max_forwards: cli.max_forwards,
        allow_remote_forwards: cli.allow_remote_forwards,
    };

    // Build connection config
    let conn_config = ConnectionConfig {
        max_forwards: cli.max_forwards,
        allow_remote_forwards: cli.allow_remote_forwards,
        output_mode: cli.output_mode,
        ..Default::default()
    };

    // Build server config
    let server_config = ServerConfig {
        bind_addr,
        cert_pem,
        key_pem,
        session_config,
        conn_config,
        bootstrap_mode: false,
    };

    // Create and run listener
    let listener = QshListener::bind(server_config).await?;
    info!("Server listening on {}", listener.local_addr());
    listener.run(false).await
}

// Old serve_quiche_server code removed - now using QshListener in listener.rs
