//! Integration tests for the unified resource control system.
//!
//! Tests the ResourceManager, resource lifecycle, and event flow.

use qsh_client::control::resource::{Resource, ResourceKind, ResourceState};
use qsh_client::control::resources::{Forward, ForwardParams, Terminal};
use qsh_client::control::{ForwardType, ResourceEvent, ResourceManager};
use qsh_core::protocol::{TerminalParams, TermSize};

fn make_terminal_params() -> TerminalParams {
    TerminalParams {
        term_size: TermSize { cols: 80, rows: 24 },
        term_type: "xterm-256color".to_string(),
        shell: None,
        command: None,
        env: vec![],
        ..Default::default()
    }
}

fn make_forward_params() -> ForwardParams {
    ForwardParams {
        forward_type: ForwardType::Local,
        bind_addr: "127.0.0.1".to_string(),
        bind_port: 0, // ephemeral
        dest_host: Some("localhost".to_string()),
        dest_port: Some(80),
    }
}

#[tokio::test]
async fn test_resource_manager_creation() {
    let (manager, _rx) = ResourceManager::new();

    // Initially empty
    let list = manager.list(None).await;
    assert!(list.is_empty());
}

#[tokio::test]
async fn test_add_terminal_resource() {
    let (manager, mut event_rx) = ResourceManager::new();

    let terminal = Terminal::new("test-term".to_string(), make_terminal_params());
    let id = manager.add(Box::new(terminal)).await;

    // ID should follow the pattern "term-N"
    assert!(id.starts_with("term-"), "ID should start with 'term-', got: {}", id);

    // Should receive an event for the add
    let event = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        event_rx.recv()
    ).await;

    assert!(event.is_ok(), "Should receive event within timeout");
    let event = event.unwrap().unwrap();
    assert_eq!(event.kind, ResourceKind::Terminal);
    assert!(matches!(event.state, ResourceState::Pending));
}

#[tokio::test]
async fn test_add_forward_resource() {
    let (manager, mut event_rx) = ResourceManager::new();

    let forward = Forward::new("test-fwd", make_forward_params());
    let id = manager.add(Box::new(forward)).await;

    // ID should follow the pattern "fwd-N"
    assert!(id.starts_with("fwd-"), "ID should start with 'fwd-', got: {}", id);

    // Should receive an event for the add
    let event = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        event_rx.recv()
    ).await;

    assert!(event.is_ok(), "Should receive event within timeout");
    let event = event.unwrap().unwrap();
    assert_eq!(event.kind, ResourceKind::Forward);
    assert!(matches!(event.state, ResourceState::Pending));
}

#[tokio::test]
async fn test_list_resources_by_kind() {
    let (manager, _rx) = ResourceManager::new();

    // Add a terminal
    let terminal = Terminal::new("t1".to_string(), make_terminal_params());
    manager.add(Box::new(terminal)).await;

    // Add a forward
    let forward = Forward::new("f1", make_forward_params());
    manager.add(Box::new(forward)).await;

    // List all
    let all = manager.list(None).await;
    assert_eq!(all.len(), 2);

    // List terminals only
    let terminals = manager.list(Some(ResourceKind::Terminal)).await;
    assert_eq!(terminals.len(), 1);
    assert_eq!(terminals[0].kind, ResourceKind::Terminal);

    // List forwards only
    let forwards = manager.list(Some(ResourceKind::Forward)).await;
    assert_eq!(forwards.len(), 1);
    assert_eq!(forwards[0].kind, ResourceKind::Forward);
}

#[tokio::test]
async fn test_describe_resource() {
    let (manager, _rx) = ResourceManager::new();

    let terminal = Terminal::new("desc-test".to_string(), make_terminal_params());
    let id = manager.add(Box::new(terminal)).await;

    // Describe the resource
    let info = manager.describe(&id).await;
    assert!(info.is_some());

    let info = info.unwrap();
    assert_eq!(info.kind, ResourceKind::Terminal);
    assert!(matches!(info.state, ResourceState::Pending));
}

#[tokio::test]
async fn test_describe_nonexistent_resource() {
    let (manager, _rx) = ResourceManager::new();

    let info = manager.describe("nonexistent-id").await;
    assert!(info.is_none());
}

#[tokio::test]
async fn test_unique_id_generation() {
    let (manager, _rx) = ResourceManager::new();

    // Add multiple terminals
    let t1 = Terminal::new("t1".to_string(), make_terminal_params());
    let id1 = manager.add(Box::new(t1)).await;

    let t2 = Terminal::new("t2".to_string(), make_terminal_params());
    let id2 = manager.add(Box::new(t2)).await;

    let t3 = Terminal::new("t3".to_string(), make_terminal_params());
    let id3 = manager.add(Box::new(t3)).await;

    // All IDs should be unique
    assert_ne!(id1, id2);
    assert_ne!(id2, id3);
    assert_ne!(id1, id3);

    // IDs should follow sequence: term-0, term-1, term-2
    assert_eq!(id1, "term-0");
    assert_eq!(id2, "term-1");
    assert_eq!(id3, "term-2");
}

#[tokio::test]
async fn test_event_sequence_numbers() {
    let (manager, mut event_rx) = ResourceManager::new();

    // Add resources and check event sequence numbers are monotonic
    let t1 = Terminal::new("t1".to_string(), make_terminal_params());
    manager.add(Box::new(t1)).await;

    let event1 = event_rx.recv().await.unwrap();

    let t2 = Terminal::new("t2".to_string(), make_terminal_params());
    manager.add(Box::new(t2)).await;

    let event2 = event_rx.recv().await.unwrap();

    // Event sequence numbers should be increasing
    assert!(event2.event_seq > event1.event_seq,
        "Event seq should increase: {} should be > {}", event2.event_seq, event1.event_seq);
}

#[tokio::test]
async fn test_count_resources() {
    let (manager, _rx) = ResourceManager::new();

    assert_eq!(manager.count(None).await, 0);
    assert_eq!(manager.count(Some(ResourceKind::Terminal)).await, 0);

    // Add terminal
    let t = Terminal::new("t".to_string(), make_terminal_params());
    manager.add(Box::new(t)).await;

    assert_eq!(manager.count(None).await, 1);
    assert_eq!(manager.count(Some(ResourceKind::Terminal)).await, 1);
    assert_eq!(manager.count(Some(ResourceKind::Forward)).await, 0);

    // Add forward
    let f = Forward::new("f", make_forward_params());
    manager.add(Box::new(f)).await;

    assert_eq!(manager.count(None).await, 2);
    assert_eq!(manager.count(Some(ResourceKind::Terminal)).await, 1);
    assert_eq!(manager.count(Some(ResourceKind::Forward)).await, 1);
}

#[tokio::test]
async fn test_subscriber_receives_events() {
    let (manager, _rx) = ResourceManager::new();

    // Create a new subscriber
    let mut subscriber = manager.subscribe();

    // Add a resource
    let t = Terminal::new("t".to_string(), make_terminal_params());
    manager.add(Box::new(t)).await;

    // Subscriber should receive the event
    let event = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        subscriber.recv()
    ).await;

    assert!(event.is_ok(), "Subscriber should receive event");
    let event = event.unwrap().unwrap();
    assert_eq!(event.kind, ResourceKind::Terminal);
}

#[tokio::test]
async fn test_multiple_subscribers() {
    let (manager, mut rx1) = ResourceManager::new();
    let mut rx2 = manager.subscribe();
    let mut rx3 = manager.subscribe();

    // Add a resource
    let t = Terminal::new("t".to_string(), make_terminal_params());
    manager.add(Box::new(t)).await;

    // All subscribers should receive the event
    let e1 = rx1.recv().await.unwrap();
    let e2 = rx2.recv().await.unwrap();
    let e3 = rx3.recv().await.unwrap();

    // All events should have the same sequence number
    assert_eq!(e1.event_seq, e2.event_seq);
    assert_eq!(e2.event_seq, e3.event_seq);
}
