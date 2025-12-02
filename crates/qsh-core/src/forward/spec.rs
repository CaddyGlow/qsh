//! Port forward specification parsing.
//!
//! Provides SSH-style forward specification parsing:
//! - Local forward (-L): [bind_addr:]port:host:hostport
//! - Remote forward (-R): [bind_addr:]port:host:hostport
//! - Dynamic forward (-D): [bind_addr:]port

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::{Error, Result};

// Re-export the wire protocol type
pub use crate::protocol::ForwardSpec;

/// Parsed forward specification with full addressing information.
///
/// This is the client-side parsed representation that includes bind addresses
/// and target information. The wire protocol uses the simpler `ForwardSpec`.
#[derive(Debug, Clone, PartialEq)]
pub enum ParsedForwardSpec {
    /// Local port forward (-L): client listens, server connects to target.
    Local {
        /// Local address to bind on client.
        bind_addr: SocketAddr,
        /// Target hostname on server side.
        target_host: String,
        /// Target port on server side.
        target_port: u16,
    },
    /// Remote port forward (-R): server listens, client connects to target.
    Remote {
        /// Address to bind on server.
        bind_addr: SocketAddr,
        /// Target hostname on client side.
        target_host: String,
        /// Target port on client side.
        target_port: u16,
    },
    /// Dynamic SOCKS5 forward (-D): client runs SOCKS5 proxy.
    Dynamic {
        /// Local address for SOCKS5 proxy.
        bind_addr: SocketAddr,
    },
}

impl ParsedForwardSpec {
    /// Parse a local forward specification (-L).
    ///
    /// Formats:
    /// - `[bind_addr:]port:host:hostport`
    /// - `port:host:hostport` (binds to localhost)
    ///
    /// Examples:
    /// - `127.0.0.1:5432:db.internal:5432`
    /// - `5432:db.internal:5432`
    /// - `[::1]:8080:localhost:80`
    pub fn parse_local(s: &str) -> Result<Self> {
        let (bind_addr, target_host, target_port) = parse_forward_spec(s)?;
        Ok(Self::Local {
            bind_addr,
            target_host,
            target_port,
        })
    }

    /// Parse a remote forward specification (-R).
    ///
    /// Formats:
    /// - `[bind_addr:]port:host:hostport`
    /// - `port:host:hostport` (binds to localhost on server)
    ///
    /// Examples:
    /// - `0.0.0.0:8080:localhost:3000`
    /// - `8080:localhost:80`
    pub fn parse_remote(s: &str) -> Result<Self> {
        let (bind_addr, target_host, target_port) = parse_forward_spec(s)?;
        Ok(Self::Remote {
            bind_addr,
            target_host,
            target_port,
        })
    }

    /// Parse a dynamic forward specification (-D).
    ///
    /// Formats:
    /// - `[bind_addr:]port`
    /// - `port` (binds to localhost)
    ///
    /// Examples:
    /// - `1080`
    /// - `0.0.0.0:1080`
    /// - `[::]:1080`
    pub fn parse_dynamic(s: &str) -> Result<Self> {
        let bind_addr = parse_bind_spec(s)?;
        Ok(Self::Dynamic { bind_addr })
    }

    /// Convert to wire protocol ForwardSpec.
    pub fn to_wire_spec(&self) -> ForwardSpec {
        match self {
            Self::Local { bind_addr, .. } => ForwardSpec::Local {
                bind_port: bind_addr.port(),
            },
            Self::Remote { bind_addr, .. } => ForwardSpec::Remote {
                bind_port: bind_addr.port(),
            },
            Self::Dynamic { .. } => ForwardSpec::Dynamic,
        }
    }

    /// Get the target host and port (if applicable).
    pub fn target(&self) -> Option<(&str, u16)> {
        match self {
            Self::Local {
                target_host,
                target_port,
                ..
            } => Some((target_host.as_str(), *target_port)),
            Self::Remote {
                target_host,
                target_port,
                ..
            } => Some((target_host.as_str(), *target_port)),
            Self::Dynamic { .. } => None,
        }
    }

    /// Get the bind address.
    pub fn bind_addr(&self) -> SocketAddr {
        match self {
            Self::Local { bind_addr, .. } => *bind_addr,
            Self::Remote { bind_addr, .. } => *bind_addr,
            Self::Dynamic { bind_addr } => *bind_addr,
        }
    }
}

/// Parse a forward specification in format `[bind_addr:]port:host:hostport`.
fn parse_forward_spec(s: &str) -> Result<(SocketAddr, String, u16)> {
    if s.is_empty() {
        return Err(Error::InvalidForwardSpec {
            message: "empty specification".into(),
        });
    }

    // Check for IPv6 bind address (starts with '[')
    if s.starts_with('[') {
        return parse_forward_spec_ipv6(s);
    }

    let parts: Vec<&str> = s.split(':').collect();

    match parts.len() {
        // port:host:hostport
        3 => {
            let bind_port = parse_port(parts[0])?;
            let target_host = parts[1].to_string();
            let target_port = parse_port(parts[2])?;

            let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), bind_port);
            Ok((bind_addr, target_host, target_port))
        }
        // bind_addr:port:host:hostport (IPv4)
        4 => {
            let bind_ip: IpAddr = parts[0].parse().map_err(|_| Error::InvalidForwardSpec {
                message: format!("invalid bind address: {}", parts[0]),
            })?;
            let bind_port = parse_port(parts[1])?;
            let target_host = parts[2].to_string();
            let target_port = parse_port(parts[3])?;

            let bind_addr = SocketAddr::new(bind_ip, bind_port);
            Ok((bind_addr, target_host, target_port))
        }
        _ => Err(Error::InvalidForwardSpec {
            message: format!("invalid format: expected [bind_addr:]port:host:hostport, got: {}", s),
        }),
    }
}

/// Parse a forward specification with IPv6 bind address.
fn parse_forward_spec_ipv6(s: &str) -> Result<(SocketAddr, String, u16)> {
    // Format: [ipv6]:port:host:hostport
    let close_bracket = s.find(']').ok_or_else(|| Error::InvalidForwardSpec {
        message: "unclosed IPv6 bracket".into(),
    })?;

    let ipv6_str = &s[1..close_bracket];
    let bind_ip: IpAddr = ipv6_str.parse().map_err(|_| Error::InvalidForwardSpec {
        message: format!("invalid IPv6 address: {}", ipv6_str),
    })?;

    let remainder = &s[close_bracket + 1..];
    if !remainder.starts_with(':') {
        return Err(Error::InvalidForwardSpec {
            message: "expected ':' after IPv6 address".into(),
        });
    }

    let parts: Vec<&str> = remainder[1..].split(':').collect();
    if parts.len() != 3 {
        return Err(Error::InvalidForwardSpec {
            message: format!("invalid format after IPv6 address: {}", remainder),
        });
    }

    let bind_port = parse_port(parts[0])?;
    let target_host = parts[1].to_string();
    let target_port = parse_port(parts[2])?;

    let bind_addr = SocketAddr::new(bind_ip, bind_port);
    Ok((bind_addr, target_host, target_port))
}

/// Parse a bind specification in format `[bind_addr:]port`.
fn parse_bind_spec(s: &str) -> Result<SocketAddr> {
    if s.is_empty() {
        return Err(Error::InvalidForwardSpec {
            message: "empty specification".into(),
        });
    }

    // Check for IPv6 bind address (starts with '[')
    if s.starts_with('[') {
        return parse_bind_spec_ipv6(s);
    }

    let parts: Vec<&str> = s.split(':').collect();

    match parts.len() {
        // port only
        1 => {
            let port = parse_port(parts[0])?;
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))
        }
        // bind_addr:port (IPv4)
        2 => {
            let bind_ip: IpAddr = parts[0].parse().map_err(|_| Error::InvalidForwardSpec {
                message: format!("invalid bind address: {}", parts[0]),
            })?;
            let port = parse_port(parts[1])?;
            Ok(SocketAddr::new(bind_ip, port))
        }
        _ => Err(Error::InvalidForwardSpec {
            message: format!("invalid format: expected [bind_addr:]port, got: {}", s),
        }),
    }
}

/// Parse a bind specification with IPv6 address.
fn parse_bind_spec_ipv6(s: &str) -> Result<SocketAddr> {
    // Format: [ipv6]:port
    let close_bracket = s.find(']').ok_or_else(|| Error::InvalidForwardSpec {
        message: "unclosed IPv6 bracket".into(),
    })?;

    let ipv6_str = &s[1..close_bracket];
    let bind_ip: IpAddr = ipv6_str.parse().map_err(|_| Error::InvalidForwardSpec {
        message: format!("invalid IPv6 address: {}", ipv6_str),
    })?;

    let remainder = &s[close_bracket + 1..];
    if !remainder.starts_with(':') {
        return Err(Error::InvalidForwardSpec {
            message: "expected ':' after IPv6 address".into(),
        });
    }

    let port = parse_port(&remainder[1..])?;
    Ok(SocketAddr::new(bind_ip, port))
}

/// Parse a port number string.
fn parse_port(s: &str) -> Result<u16> {
    s.parse::<u16>().map_err(|_| Error::InvalidForwardSpec {
        message: format!("invalid port: {}", s),
    })
}
