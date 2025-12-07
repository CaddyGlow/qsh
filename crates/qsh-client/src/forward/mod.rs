//! Port forwarding handlers for qsh client.
//!
//! This module provides:
//! - `LocalForwarder`: Local port forward (-L) - listens locally, forwards to server target
//! - `Socks5Proxy`: Dynamic SOCKS5 forward (-D) - listens locally, handles SOCKS5 protocol
//! - `RemoteForwarder`: Remote port forward (-R) - server listens, client connects to local target

mod local;
mod remote;
mod socks;

pub use local::{ForwarderHandle, LocalForwarder};
pub use remote::{RemoteForwarder, RemoteForwarderHandle};
pub use socks::{ProxyHandle, Socks5Proxy};

use std::net::SocketAddr;

use qsh_core::error::{Error, Result};

/// Parse a local forward spec: [bind_addr:]port:host:hostport
///
/// Examples:
/// - "8080:localhost:80" -> binds 0.0.0.0:8080, forwards to localhost:80
/// - "127.0.0.1:8080:db.example.com:5432" -> binds 127.0.0.1:8080, forwards to db.example.com:5432
pub fn parse_local_forward(spec: &str) -> Result<(SocketAddr, String, u16)> {
    let parts: Vec<&str> = spec.split(':').collect();

    match parts.len() {
        // port:host:hostport
        3 => {
            let bind_port: u16 = parts[0].parse().map_err(|_| Error::Forward {
                message: format!("invalid bind port: {}", parts[0]),
            })?;
            let target_host = parts[1].to_string();
            let target_port: u16 = parts[2].parse().map_err(|_| Error::Forward {
                message: format!("invalid target port: {}", parts[2]),
            })?;
            Ok((
                SocketAddr::from(([0, 0, 0, 0], bind_port)),
                target_host,
                target_port,
            ))
        }
        // bind_addr:port:host:hostport
        4 => {
            let bind_addr: SocketAddr =
                format!("{}:{}", parts[0], parts[1]).parse().map_err(|_| Error::Forward {
                    message: format!("invalid bind address: {}:{}", parts[0], parts[1]),
                })?;
            let target_host = parts[2].to_string();
            let target_port: u16 = parts[3].parse().map_err(|_| Error::Forward {
                message: format!("invalid target port: {}", parts[3]),
            })?;
            Ok((bind_addr, target_host, target_port))
        }
        _ => Err(Error::Forward {
            message: format!(
                "invalid forward spec '{}': expected [bind_addr:]port:host:hostport",
                spec
            ),
        }),
    }
}

/// Parse a remote forward spec: [bind_addr:]port:host:hostport
///
/// Examples:
/// - "8080:localhost:3000" -> server binds 0.0.0.0:8080, client connects to localhost:3000
/// - "0.0.0.0:8080:127.0.0.1:3000" -> server binds 0.0.0.0:8080, client connects to 127.0.0.1:3000
///
/// Returns (bind_host, bind_port, target_host, target_port).
pub fn parse_remote_forward(spec: &str) -> Result<(String, u16, String, u16)> {
    let parts: Vec<&str> = spec.split(':').collect();

    match parts.len() {
        // port:host:hostport (bind to 0.0.0.0 by default)
        3 => {
            let bind_port: u16 = parts[0].parse().map_err(|_| Error::Forward {
                message: format!("invalid bind port: {}", parts[0]),
            })?;
            let target_host = parts[1].to_string();
            let target_port: u16 = parts[2].parse().map_err(|_| Error::Forward {
                message: format!("invalid target port: {}", parts[2]),
            })?;
            Ok(("0.0.0.0".to_string(), bind_port, target_host, target_port))
        }
        // bind_addr:port:host:hostport
        4 => {
            let bind_host = parts[0].to_string();
            let bind_port: u16 = parts[1].parse().map_err(|_| Error::Forward {
                message: format!("invalid bind port: {}", parts[1]),
            })?;
            let target_host = parts[2].to_string();
            let target_port: u16 = parts[3].parse().map_err(|_| Error::Forward {
                message: format!("invalid target port: {}", parts[3]),
            })?;
            Ok((bind_host, bind_port, target_host, target_port))
        }
        _ => Err(Error::Forward {
            message: format!(
                "invalid remote forward spec '{}': expected [bind_addr:]port:host:hostport",
                spec
            ),
        }),
    }
}

/// Parse a dynamic forward spec: [bind_addr:]port
///
/// Examples:
/// - "1080" -> binds 0.0.0.0:1080
/// - "127.0.0.1:1080" -> binds 127.0.0.1:1080
pub fn parse_dynamic_forward(spec: &str) -> Result<SocketAddr> {
    // Try parsing as just a port
    if let Ok(port) = spec.parse::<u16>() {
        return Ok(SocketAddr::from(([0, 0, 0, 0], port)));
    }

    // Try parsing as addr:port
    spec.parse().map_err(|_| Error::Forward {
        message: format!(
            "invalid dynamic forward spec '{}': expected [bind_addr:]port",
            spec
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_local_forward_simple() {
        let (bind, host, port) = parse_local_forward("8080:localhost:80").unwrap();
        assert_eq!(bind.port(), 8080);
        assert_eq!(host, "localhost");
        assert_eq!(port, 80);
    }

    #[test]
    fn test_parse_local_forward_with_bind_addr() {
        let (bind, host, port) = parse_local_forward("127.0.0.1:8080:db.example.com:5432").unwrap();
        assert_eq!(bind.to_string(), "127.0.0.1:8080");
        assert_eq!(host, "db.example.com");
        assert_eq!(port, 5432);
    }

    #[test]
    fn test_parse_local_forward_invalid() {
        assert!(parse_local_forward("8080").is_err());
        assert!(parse_local_forward("8080:localhost").is_err());
    }

    #[test]
    fn test_parse_dynamic_forward_port_only() {
        let addr = parse_dynamic_forward("1080").unwrap();
        assert_eq!(addr.port(), 1080);
    }

    #[test]
    fn test_parse_dynamic_forward_with_addr() {
        let addr = parse_dynamic_forward("127.0.0.1:1080").unwrap();
        assert_eq!(addr.to_string(), "127.0.0.1:1080");
    }

    #[test]
    fn test_parse_dynamic_forward_invalid() {
        assert!(parse_dynamic_forward("not:valid:format").is_err());
    }

    #[test]
    fn test_parse_remote_forward_simple() {
        let (bind_host, bind_port, target_host, target_port) =
            parse_remote_forward("8080:localhost:3000").unwrap();
        assert_eq!(bind_host, "0.0.0.0");
        assert_eq!(bind_port, 8080);
        assert_eq!(target_host, "localhost");
        assert_eq!(target_port, 3000);
    }

    #[test]
    fn test_parse_remote_forward_with_bind_addr() {
        let (bind_host, bind_port, target_host, target_port) =
            parse_remote_forward("0.0.0.0:8080:127.0.0.1:3000").unwrap();
        assert_eq!(bind_host, "0.0.0.0");
        assert_eq!(bind_port, 8080);
        assert_eq!(target_host, "127.0.0.1");
        assert_eq!(target_port, 3000);
    }

    #[test]
    fn test_parse_remote_forward_invalid() {
        assert!(parse_remote_forward("8080").is_err());
        assert!(parse_remote_forward("8080:localhost").is_err());
    }
}
