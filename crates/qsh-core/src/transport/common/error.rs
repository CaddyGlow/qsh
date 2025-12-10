//! Error handling utilities for I/O operations.
//!
//! Provides functions for classifying I/O errors and enabling error queues
//! on UDP sockets for immediate ICMP error delivery.

use crate::error::Error;
use std::io;

/// Classify an I/O error into a specific qsh error type.
pub fn classify_io_error(e: std::io::Error) -> Error {
    match e.raw_os_error() {
        #[cfg(target_os = "linux")]
        Some(libc::ENETUNREACH) => Error::NetworkUnreachable(e),
        #[cfg(target_os = "linux")]
        Some(libc::EHOSTUNREACH) => Error::HostUnreachable(e),
        #[cfg(target_os = "linux")]
        Some(libc::ECONNREFUSED) => Error::ConnectionRefused,
        #[cfg(target_os = "linux")]
        Some(libc::ENETDOWN) | Some(libc::ENODEV) => Error::InterfaceDown,
        #[cfg(target_os = "linux")]
        Some(libc::EACCES) | Some(libc::EPERM) => Error::PermissionDenied(e),
        _ => Error::Io(e),
    }
}

/// Enable IP_RECVERR on a connected UDP socket for immediate ICMP error delivery.
#[cfg(target_os = "linux")]
pub fn enable_error_queue(socket: &tokio::net::UdpSocket) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;

    let fd = socket.as_raw_fd();
    let optval: libc::c_int = 1;

    let local_addr = socket.local_addr()?;
    let (level, optname) = if local_addr.is_ipv4() {
        (libc::IPPROTO_IP, libc::IP_RECVERR)
    } else {
        (libc::IPPROTO_IPV6, libc::IPV6_RECVERR)
    };

    unsafe {
        if libc::setsockopt(
            fd,
            level,
            optname,
            &optval as *const _ as _,
            std::mem::size_of_val(&optval) as _,
        ) < 0
        {
            return Err(io::Error::last_os_error());
        }
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn enable_error_queue(_socket: &tokio::net::UdpSocket) -> io::Result<()> {
    // IP_RECVERR is Linux-specific
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_io_errors() {
        // Test that we handle basic I/O errors
        let err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "test");
        let classified = classify_io_error(err);
        assert!(matches!(classified, Error::Io(_)));
    }
}
