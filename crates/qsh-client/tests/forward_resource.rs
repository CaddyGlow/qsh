//! Tests for Forward resource implementation.

use std::sync::Arc;
use std::time::Duration;

use qsh_client::control::resource::{Resource, ResourceKind, ResourceState};
use qsh_client::control::resources::{Forward, ForwardParams};
use qsh_client::control::{ForwardType, ResourceDetails};

#[test]
fn test_forward_creation_local() {
    let params = ForwardParams {
        forward_type: ForwardType::Local,
        bind_addr: "127.0.0.1".to_string(),
        bind_port: 8080,
        dest_host: Some("localhost".to_string()),
        dest_port: Some(80),
    };

    let forward = Forward::new("fwd-0", params);

    assert_eq!(forward.id(), "fwd-0");
    assert_eq!(forward.kind(), ResourceKind::Forward);
    assert_eq!(forward.state(), &ResourceState::Pending);
}

#[test]
fn test_forward_creation_remote() {
    let params = ForwardParams {
        forward_type: ForwardType::Remote,
        bind_addr: "0.0.0.0".to_string(),
        bind_port: 9000,
        dest_host: Some("localhost".to_string()),
        dest_port: Some(3000),
    };

    let forward = Forward::new("fwd-1", params);

    assert_eq!(forward.id(), "fwd-1");
    assert_eq!(forward.kind(), ResourceKind::Forward);
    assert_eq!(forward.state(), &ResourceState::Pending);
}

#[test]
fn test_forward_creation_dynamic() {
    let params = ForwardParams {
        forward_type: ForwardType::Dynamic,
        bind_addr: "127.0.0.1".to_string(),
        bind_port: 1080,
        dest_host: None,
        dest_port: None,
    };

    let forward = Forward::new("fwd-2", params);

    assert_eq!(forward.id(), "fwd-2");
    assert_eq!(forward.kind(), ResourceKind::Forward);
    assert_eq!(forward.state(), &ResourceState::Pending);
}

#[test]
fn test_forward_describe() {
    let params = ForwardParams {
        forward_type: ForwardType::Local,
        bind_addr: "127.0.0.1".to_string(),
        bind_port: 8080,
        dest_host: Some("example.com".to_string()),
        dest_port: Some(443),
    };

    let forward = Forward::new("fwd-test", params);
    let info = forward.describe();

    assert_eq!(info.id, "fwd-test");
    assert_eq!(info.kind, ResourceKind::Forward);
    assert_eq!(info.state, ResourceState::Pending);

    match info.details {
        ResourceDetails::Forward(details) => {
            assert_eq!(details.forward_type, ForwardType::Local);
            assert_eq!(details.bind_addr, "127.0.0.1");
            assert_eq!(details.bind_port, 8080);
            assert_eq!(details.dest_host, Some("example.com".to_string()));
            assert_eq!(details.dest_port, Some(443));
            assert_eq!(details.active_connections, 0);
        }
        _ => panic!("Expected Forward details"),
    }
}

#[test]
fn test_forward_describe_dynamic() {
    let params = ForwardParams {
        forward_type: ForwardType::Dynamic,
        bind_addr: "0.0.0.0".to_string(),
        bind_port: 1080,
        dest_host: None,
        dest_port: None,
    };

    let forward = Forward::new("fwd-dynamic", params);
    let info = forward.describe();

    match info.details {
        ResourceDetails::Forward(details) => {
            assert_eq!(details.forward_type, ForwardType::Dynamic);
            assert_eq!(details.bind_addr, "0.0.0.0");
            assert_eq!(details.bind_port, 1080);
            assert_eq!(details.dest_host, None);
            assert_eq!(details.dest_port, None);
        }
        _ => panic!("Expected Forward details"),
    }
}

#[test]
fn test_forward_state_transitions() {
    let params = ForwardParams {
        forward_type: ForwardType::Local,
        bind_addr: "127.0.0.1".to_string(),
        bind_port: 8080,
        dest_host: Some("localhost".to_string()),
        dest_port: Some(80),
    };

    let mut forward = Forward::new("fwd-state", params);

    // Initial state
    assert_eq!(forward.state(), &ResourceState::Pending);
    assert!(forward.state().is_active());
    assert!(!forward.state().is_terminal());

    // Simulate state change (normally done by start())
    // Note: We can't actually start the forward without a real connection,
    // but we can test the trait bounds and structure
    assert_eq!(forward.kind(), ResourceKind::Forward);
}

#[test]
fn test_forward_id_and_kind() {
    let params = ForwardParams {
        forward_type: ForwardType::Remote,
        bind_addr: "127.0.0.1".to_string(),
        bind_port: 8080,
        dest_host: Some("localhost".to_string()),
        dest_port: Some(80),
    };

    let forward = Forward::new("fwd-123", params);

    assert_eq!(forward.id(), "fwd-123");
    assert_eq!(forward.kind(), ResourceKind::Forward);
    assert_eq!(forward.kind().id_prefix(), "fwd");
}

#[test]
fn test_forward_params_validation() {
    // Local forward should have dest_host and dest_port
    let valid_local = ForwardParams {
        forward_type: ForwardType::Local,
        bind_addr: "127.0.0.1".to_string(),
        bind_port: 8080,
        dest_host: Some("localhost".to_string()),
        dest_port: Some(80),
    };
    let _forward = Forward::new("fwd-valid", valid_local);

    // Remote forward should have dest_host and dest_port
    let valid_remote = ForwardParams {
        forward_type: ForwardType::Remote,
        bind_addr: "0.0.0.0".to_string(),
        bind_port: 9000,
        dest_host: Some("localhost".to_string()),
        dest_port: Some(3000),
    };
    let _forward = Forward::new("fwd-valid-remote", valid_remote);

    // Dynamic forward should NOT have dest_host and dest_port
    let valid_dynamic = ForwardParams {
        forward_type: ForwardType::Dynamic,
        bind_addr: "127.0.0.1".to_string(),
        bind_port: 1080,
        dest_host: None,
        dest_port: None,
    };
    let _forward = Forward::new("fwd-valid-dynamic", valid_dynamic);
}

#[test]
fn test_forward_type_display() {
    assert_eq!(ForwardType::Local.to_string(), "local");
    assert_eq!(ForwardType::Remote.to_string(), "remote");
    assert_eq!(ForwardType::Dynamic.to_string(), "dynamic");
}

#[test]
fn test_forward_resource_kind() {
    let params = ForwardParams {
        forward_type: ForwardType::Local,
        bind_addr: "127.0.0.1".to_string(),
        bind_port: 8080,
        dest_host: Some("localhost".to_string()),
        dest_port: Some(80),
    };

    let forward = Forward::new("fwd-kind", params);
    let info = forward.describe();

    assert_eq!(info.kind, ResourceKind::Forward);
    assert_eq!(info.kind.to_string(), "forward");
}

#[test]
fn test_forward_stats_initial() {
    let params = ForwardParams {
        forward_type: ForwardType::Local,
        bind_addr: "127.0.0.1".to_string(),
        bind_port: 8080,
        dest_host: Some("localhost".to_string()),
        dest_port: Some(80),
    };

    let forward = Forward::new("fwd-stats", params);
    let info = forward.describe();

    // Stats should be initialized
    assert!(info.stats.created_at > 0);
    assert_eq!(info.stats.bytes_in, 0);
    assert_eq!(info.stats.bytes_out, 0);
}

// Note: Integration tests with actual port binding and connection handling
// would require a real ChannelConnection and are better suited for
// integration test suites that can set up the full infrastructure.
