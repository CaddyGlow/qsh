//! Tests for port forward specification parsing.
//!
//! Per IMPL-SPEC Task 3.1: Write tests for port forward specification parsing.
//! Formats:
//! - Local/Remote: [bind_addr:]port:host:hostport
//! - Dynamic: [bind_addr:]port

use super::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

// =============================================================================
// Local Forward Tests (-L)
// =============================================================================

#[test]
fn parse_local_full() {
    // -L 127.0.0.1:5432:db.internal:5432
    let spec = ForwardSpec::parse_local("127.0.0.1:5432:db.internal:5432").unwrap();

    match spec {
        ForwardSpec::Local {
            bind_addr,
            target_host,
            target_port,
        } => {
            assert_eq!(
                bind_addr,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5432)
            );
            assert_eq!(target_host, "db.internal");
            assert_eq!(target_port, 5432);
        }
        _ => panic!("expected Local variant"),
    }
}

#[test]
fn parse_local_short() {
    // -L 5432:db.internal:5432 (defaults to localhost)
    let spec = ForwardSpec::parse_local("5432:db.internal:5432").unwrap();

    match spec {
        ForwardSpec::Local {
            bind_addr,
            target_host,
            target_port,
        } => {
            assert_eq!(bind_addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
            assert_eq!(bind_addr.port(), 5432);
            assert_eq!(target_host, "db.internal");
            assert_eq!(target_port, 5432);
        }
        _ => panic!("expected Local variant"),
    }
}

#[test]
fn parse_local_ipv6_bind() {
    // -L [::1]:8080:localhost:80
    let spec = ForwardSpec::parse_local("[::1]:8080:localhost:80").unwrap();

    match spec {
        ForwardSpec::Local {
            bind_addr,
            target_host,
            target_port,
        } => {
            assert_eq!(bind_addr.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
            assert_eq!(bind_addr.port(), 8080);
            assert_eq!(target_host, "localhost");
            assert_eq!(target_port, 80);
        }
        _ => panic!("expected Local variant"),
    }
}

#[test]
fn parse_local_wildcard_bind() {
    // -L 0.0.0.0:3000:backend:3000
    let spec = ForwardSpec::parse_local("0.0.0.0:3000:backend:3000").unwrap();

    match spec {
        ForwardSpec::Local {
            bind_addr,
            target_host,
            target_port,
        } => {
            assert_eq!(bind_addr.ip(), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            assert_eq!(bind_addr.port(), 3000);
            assert_eq!(target_host, "backend");
            assert_eq!(target_port, 3000);
        }
        _ => panic!("expected Local variant"),
    }
}

#[test]
fn parse_local_different_ports() {
    // -L 8080:internal-service:80
    let spec = ForwardSpec::parse_local("8080:internal-service:80").unwrap();

    match spec {
        ForwardSpec::Local {
            bind_addr,
            target_host,
            target_port,
        } => {
            assert_eq!(bind_addr.port(), 8080);
            assert_eq!(target_host, "internal-service");
            assert_eq!(target_port, 80);
        }
        _ => panic!("expected Local variant"),
    }
}

// =============================================================================
// Remote Forward Tests (-R)
// =============================================================================

#[test]
fn parse_remote_full() {
    // -R 0.0.0.0:8080:localhost:3000
    let spec = ForwardSpec::parse_remote("0.0.0.0:8080:localhost:3000").unwrap();

    match spec {
        ForwardSpec::Remote {
            bind_addr,
            target_host,
            target_port,
        } => {
            assert_eq!(
                bind_addr,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080)
            );
            assert_eq!(target_host, "localhost");
            assert_eq!(target_port, 3000);
        }
        _ => panic!("expected Remote variant"),
    }
}

#[test]
fn parse_remote_short() {
    // -R 8080:localhost:80 (defaults to localhost bind on server)
    let spec = ForwardSpec::parse_remote("8080:localhost:80").unwrap();

    match spec {
        ForwardSpec::Remote {
            bind_addr,
            target_host,
            target_port,
        } => {
            assert_eq!(bind_addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
            assert_eq!(bind_addr.port(), 8080);
            assert_eq!(target_host, "localhost");
            assert_eq!(target_port, 80);
        }
        _ => panic!("expected Remote variant"),
    }
}

// =============================================================================
// Dynamic Forward Tests (-D SOCKS5)
// =============================================================================

#[test]
fn parse_dynamic_port_only() {
    // -D 1080
    let spec = ForwardSpec::parse_dynamic("1080").unwrap();

    match spec {
        ForwardSpec::Dynamic { bind_addr } => {
            assert_eq!(bind_addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
            assert_eq!(bind_addr.port(), 1080);
        }
        _ => panic!("expected Dynamic variant"),
    }
}

#[test]
fn parse_dynamic_with_bind() {
    // -D 0.0.0.0:1080
    let spec = ForwardSpec::parse_dynamic("0.0.0.0:1080").unwrap();

    match spec {
        ForwardSpec::Dynamic { bind_addr } => {
            assert_eq!(bind_addr.ip(), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            assert_eq!(bind_addr.port(), 1080);
        }
        _ => panic!("expected Dynamic variant"),
    }
}

#[test]
fn parse_dynamic_ipv6() {
    // -D [::]:1080
    let spec = ForwardSpec::parse_dynamic("[::]:1080").unwrap();

    match spec {
        ForwardSpec::Dynamic { bind_addr } => {
            assert_eq!(bind_addr.ip(), IpAddr::V6(Ipv6Addr::UNSPECIFIED));
            assert_eq!(bind_addr.port(), 1080);
        }
        _ => panic!("expected Dynamic variant"),
    }
}

// =============================================================================
// Error Cases
// =============================================================================

#[test]
fn parse_local_invalid_format() {
    // Missing target port
    assert!(ForwardSpec::parse_local("invalid").is_err());
    assert!(ForwardSpec::parse_local("").is_err());
    assert!(ForwardSpec::parse_local("8080:host").is_err());
}

#[test]
fn parse_local_invalid_port() {
    // Port out of range
    assert!(ForwardSpec::parse_local("abc:def:ghi").is_err());
    assert!(ForwardSpec::parse_local("70000:localhost:80").is_err());
    assert!(ForwardSpec::parse_local("8080:localhost:70000").is_err());
}

#[test]
fn parse_local_invalid_bind_addr() {
    // Invalid IP address
    assert!(ForwardSpec::parse_local("999.999.999.999:8080:localhost:80").is_err());
}

#[test]
fn parse_remote_invalid_format() {
    assert!(ForwardSpec::parse_remote("invalid").is_err());
    assert!(ForwardSpec::parse_remote("").is_err());
}

#[test]
fn parse_dynamic_invalid_format() {
    assert!(ForwardSpec::parse_dynamic("").is_err());
    assert!(ForwardSpec::parse_dynamic("abc").is_err());
    assert!(ForwardSpec::parse_dynamic("70000").is_err());
}

// =============================================================================
// Target extraction
// =============================================================================

#[test]
fn local_target_info() {
    let spec = ForwardSpec::parse_local("8080:db.internal:5432").unwrap();
    let (host, port) = spec.target().unwrap();
    assert_eq!(host, "db.internal");
    assert_eq!(port, 5432);
}

#[test]
fn remote_target_info() {
    let spec = ForwardSpec::parse_remote("8080:localhost:3000").unwrap();
    let (host, port) = spec.target().unwrap();
    assert_eq!(host, "localhost");
    assert_eq!(port, 3000);
}

#[test]
fn dynamic_no_target() {
    let spec = ForwardSpec::parse_dynamic("1080").unwrap();
    assert!(spec.target().is_none());
}

// =============================================================================
// Bind address extraction
// =============================================================================

#[test]
fn bind_addr_extraction() {
    let local = ForwardSpec::parse_local("0.0.0.0:8080:localhost:80").unwrap();
    assert_eq!(local.bind_addr().port(), 8080);

    let remote = ForwardSpec::parse_remote("8080:localhost:80").unwrap();
    assert_eq!(remote.bind_addr().port(), 8080);

    let dynamic = ForwardSpec::parse_dynamic("1080").unwrap();
    assert_eq!(dynamic.bind_addr().port(), 1080);
}

// =============================================================================
// Display/Debug
// =============================================================================

#[test]
fn forward_spec_debug() {
    let spec = ForwardSpec::parse_local("8080:localhost:80").unwrap();
    let debug = format!("{:?}", spec);
    assert!(debug.contains("Local"));
    assert!(debug.contains("8080"));
}
