//! End-to-end tests for qsh.
//!
//! These tests spawn real binaries and test actual functionality.
//! Marked with #[ignore] as they require built binaries and may
//! need network access or elevated privileges.

use std::process::Command;

#[allow(dead_code)]
use std::process::Stdio;
#[allow(dead_code)]
use std::time::Duration;

/// Get the path to the qsh binary.
fn qsh_binary() -> String {
    // CARGO_MANIFEST_DIR points to crates/qsh-client
    // Binaries are in {workspace}/target/debug/
    let manifest = env!("CARGO_MANIFEST_DIR");
    let workspace = std::path::Path::new(manifest)
        .parent()
        .and_then(|p| p.parent())
        .expect("Could not find workspace root");

    let debug_path = workspace.join("target/debug/qsh");
    if debug_path.exists() {
        return debug_path.to_string_lossy().to_string();
    }

    let release_path = workspace.join("target/release/qsh");
    if release_path.exists() {
        return release_path.to_string_lossy().to_string();
    }

    // Fall back to PATH
    "qsh".to_string()
}

/// Get the path to the qsh-server binary.
fn qsh_server_binary() -> String {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let workspace = std::path::Path::new(manifest)
        .parent()
        .and_then(|p| p.parent())
        .expect("Could not find workspace root");

    let debug_path = workspace.join("target/debug/qsh-server");
    if debug_path.exists() {
        return debug_path.to_string_lossy().to_string();
    }

    let release_path = workspace.join("target/release/qsh-server");
    if release_path.exists() {
        return release_path.to_string_lossy().to_string();
    }

    // Fall back to PATH
    "qsh-server".to_string()
}

// =============================================================================
// CLI Tests (don't require network)
// =============================================================================

#[test]
fn client_help() {
    let output = Command::new(qsh_binary())
        .arg("--help")
        .output()
        .expect("Failed to run qsh --help");

    assert!(output.status.success(), "qsh --help should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Modern roaming-capable remote terminal"));
    assert!(stdout.contains("-p, --port"));
    assert!(stdout.contains("-L, --local"));
    assert!(stdout.contains("-D, --dynamic"));
}

#[test]
fn client_version() {
    let output = Command::new(qsh_binary())
        .arg("--version")
        .output()
        .expect("Failed to run qsh --version");

    assert!(output.status.success(), "qsh --version should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("qsh"));
}

#[test]
fn server_help() {
    let output = Command::new(qsh_server_binary())
        .arg("--help")
        .output()
        .expect("Failed to run qsh-server --help");

    assert!(output.status.success(), "qsh-server --help should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("qsh server"));
    assert!(stdout.contains("--bind"));
    assert!(stdout.contains("--port"));
    assert!(stdout.contains("--cert"));
}

#[test]
fn server_version() {
    let output = Command::new(qsh_server_binary())
        .arg("--version")
        .output()
        .expect("Failed to run qsh-server --version");

    assert!(output.status.success(), "qsh-server --version should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("qsh-server"));
}

// =============================================================================
// E2E Tests (require network, marked #[ignore])
// =============================================================================

/// Test basic connection workflow.
///
/// This test:
/// 1. Starts a qsh-server with self-signed cert
/// 2. Connects with qsh client
/// 3. Sends some input
/// 4. Verifies output
/// 5. Exits cleanly
#[test]
#[ignore = "Requires built binaries and network"]
fn basic_connection() {
    // TODO: Implement when connection logic is complete
    //
    // Steps:
    // 1. Start server: qsh-server --self-signed -p 0 (random port)
    // 2. Parse server output to get actual port
    // 3. Connect: qsh -p PORT localhost
    // 4. Send "echo hello" and verify output
    // 5. Send "exit" to close
    // 6. Verify clean exit codes

    eprintln!("basic_connection: TODO - implement when connection logic is ready");
}

/// Test reconnection after network interruption.
///
/// This test:
/// 1. Establishes connection
/// 2. Simulates network drop (kill connection)
/// 3. Verifies reconnection
/// 4. Verifies state recovery
#[test]
#[ignore = "Requires built binaries and network"]
fn reconnection() {
    // TODO: Implement when reconnection is complete
    //
    // Steps:
    // 1. Start server
    // 2. Connect client
    // 3. Run a long command (sleep 10)
    // 4. Kill network (maybe iptables or similar)
    // 5. Restore network
    // 6. Verify session continues
    // 7. Verify terminal state matches

    eprintln!("reconnection: TODO - implement when reconnection logic is ready");
}

/// Test local port forwarding.
///
/// This test:
/// 1. Starts qsh with -L 8080:localhost:80
/// 2. Verifies local port is bound
/// 3. Connects to local port
/// 4. Verifies traffic is forwarded
#[test]
#[ignore = "Requires built binaries and network"]
fn local_forward() {
    // TODO: Implement when forward logic is complete
    //
    // Steps:
    // 1. Start a simple HTTP server on localhost:80 (or use httpbin)
    // 2. Start server
    // 3. Connect: qsh -L 8080:localhost:80 localhost
    // 4. curl localhost:8080
    // 5. Verify response matches

    eprintln!("local_forward: TODO - implement when forward logic is ready");
}

/// Test dynamic SOCKS5 forwarding.
///
/// This test:
/// 1. Starts qsh with -D 1080
/// 2. Verifies SOCKS5 handshake works
/// 3. Routes traffic through proxy
/// 4. Verifies connectivity
#[test]
#[ignore = "Requires built binaries and network"]
fn dynamic_forward() {
    // TODO: Implement when SOCKS5 is integrated
    //
    // Steps:
    // 1. Start server
    // 2. Connect: qsh -D 1080 localhost
    // 3. curl --socks5 localhost:1080 http://httpbin.org/ip
    // 4. Verify response

    eprintln!("dynamic_forward: TODO - implement when SOCKS5 integration is ready");
}

/// Test remote port forwarding.
///
/// This test:
/// 1. Starts qsh with -R 9090:localhost:8080
/// 2. Verifies server binds port
/// 3. Connects to server port
/// 4. Verifies traffic is forwarded back to client
#[test]
#[ignore = "Requires built binaries and network"]
fn remote_forward() {
    // TODO: Implement when remote forward is complete
    //
    // Steps:
    // 1. Start local HTTP server on 8080
    // 2. Start server with --allow-remote-forwards
    // 3. Connect: qsh -R 9090:localhost:8080 localhost
    // 4. From server side, curl localhost:9090
    // 5. Verify response from client's local server

    eprintln!("remote_forward: TODO - implement when remote forward logic is ready");
}

/// Test multiple concurrent connections.
///
/// This test:
/// 1. Starts server
/// 2. Opens multiple clients
/// 3. Runs commands in parallel
/// 4. Verifies all complete successfully
#[test]
#[ignore = "Requires built binaries and network"]
fn concurrent_connections() {
    // TODO: Implement concurrency test

    eprintln!("concurrent_connections: TODO - implement concurrency test");
}

/// Test graceful shutdown.
///
/// This test:
/// 1. Starts server
/// 2. Connects client
/// 3. Sends SIGTERM to server
/// 4. Verifies client receives disconnect
/// 5. Verifies no data loss
#[test]
#[ignore = "Requires built binaries and network"]
fn graceful_shutdown() {
    // TODO: Implement shutdown test

    eprintln!("graceful_shutdown: TODO - implement graceful shutdown test");
}

/// Test terminal state synchronization.
///
/// This test:
/// 1. Connects to server
/// 2. Runs commands that modify terminal state (colors, cursor position)
/// 3. Forces reconnect
/// 4. Verifies terminal state is restored
#[test]
#[ignore = "Requires built binaries and network"]
fn terminal_state_sync() {
    // TODO: Implement terminal state sync test

    eprintln!("terminal_state_sync: TODO - implement terminal state sync test");
}
