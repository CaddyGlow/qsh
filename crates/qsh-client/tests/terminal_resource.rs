//! Integration tests for the Terminal resource.
//!
//! Tests the Terminal resource implementation including:
//! - Creation and lifecycle management
//! - Attach/detach flows
//! - State transitions
//! - Resize operations

use qsh_client::control::resource::{Resource, ResourceKind, ResourceState};
use qsh_client::control::resources::Terminal;
use qsh_core::protocol::{TerminalParams, TermSize};

fn make_params(cols: u16, rows: u16, shell: Option<String>) -> TerminalParams {
    TerminalParams {
        term_size: TermSize { cols, rows },
        term_type: "xterm-256color".to_string(),
        shell,
        command: None,
        env: vec![],
        ..Default::default()
    }
}

#[test]
fn test_terminal_creation() {
    let params = make_params(80, 24, None);

    let terminal = Terminal::new("term-0".to_string(), params);
    assert_eq!(terminal.id(), "term-0");
    assert_eq!(terminal.kind(), ResourceKind::Terminal);
    assert_eq!(terminal.state(), &ResourceState::Pending);
}

#[test]
fn test_terminal_from_params() {
    let terminal = Terminal::from_params(
        "term-1".to_string(),
        Some(120),
        Some(40),
        Some("xterm".to_string()),
        Some("/bin/zsh".to_string()),
        None,
        vec![("FOO".to_string(), "bar".to_string())],
    );

    assert_eq!(terminal.id(), "term-1");
    assert_eq!(terminal.kind(), ResourceKind::Terminal);

    let info = terminal.describe();
    assert_eq!(info.id, "term-1");
    assert_eq!(info.kind, ResourceKind::Terminal);
}

#[test]
fn test_describe() {
    let params = make_params(100, 30, Some("/bin/bash".to_string()));

    let terminal = Terminal::new("term-2".to_string(), params);
    let info = terminal.describe();

    assert_eq!(info.id, "term-2");
    assert_eq!(info.kind, ResourceKind::Terminal);
    assert!(matches!(info.state, ResourceState::Pending));

    // Check terminal details
    use qsh_client::control::resource::ResourceDetails;
    if let ResourceDetails::Terminal(details) = info.details {
        assert_eq!(details.cols, 100);
        assert_eq!(details.rows, 30);
        assert_eq!(details.shell, "/bin/bash");
        assert!(!details.attached);
    } else {
        panic!("Expected Terminal details");
    }
}

// Note: Full integration tests with actual connections require a test server
// and are better suited for end-to-end tests. These tests focus on the
// resource structure and state management.

#[tokio::test]
async fn test_attach_detach_without_connection() {
    let params = make_params(80, 24, None);

    let terminal = Terminal::new("term-3".to_string(), params);

    // Attempting to attach to a terminal in Pending state should fail
    let result = terminal.attach().await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_resize_without_connection() {
    let params = make_params(80, 24, None);

    let terminal = Terminal::new("term-4".to_string(), params);

    // Attempting to resize a terminal in Pending state should fail
    let result = terminal.resize(100, 30).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_is_attached() {
    let params = make_params(80, 24, None);

    let terminal = Terminal::new("term-5".to_string(), params);
    assert!(!terminal.is_attached().await);
}
