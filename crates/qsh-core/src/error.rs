//! Error types for qsh-core.

use thiserror::Error;

/// Main error type for qsh operations.
#[derive(Debug, Error)]
pub enum Error {
    /// I/O error from underlying system calls.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Protocol violation or malformed message.
    #[error("protocol error: {message}")]
    Protocol { message: String },

    /// Codec error during encoding/decoding.
    #[error("codec error: {message}")]
    Codec { message: String },

    /// Session not found for given ID.
    #[error("session not found: {0}")]
    SessionNotFound(u64),

    /// Session has expired due to timeout.
    #[error("session expired")]
    SessionExpired,

    /// Authentication failed.
    #[error("authentication failed")]
    AuthenticationFailed,

    /// Connection was closed.
    #[error("connection closed")]
    ConnectionClosed,

    /// Invalid state transition.
    #[error("invalid state: expected {expected}, got {actual}")]
    InvalidState { expected: String, actual: String },

    /// Operation timed out.
    #[error("operation timed out")]
    Timeout,

    /// Invalid forward specification.
    #[error("invalid forward spec: {message}")]
    InvalidForwardSpec { message: String },

    /// Transport layer error.
    #[error("transport error: {message}")]
    Transport { message: String },

    /// PTY error.
    #[error("pty error: {message}")]
    Pty { message: String },

    /// File transfer error.
    #[error("file transfer error: {message}")]
    FileTransfer { message: String },

    /// Port forward error.
    #[error("forward error: {message}")]
    Forward { message: String },

    /// Channel error.
    #[error("channel error: {message}")]
    Channel { message: String },
}

impl Error {
    /// Returns true if this error is transient and reconnection may help.
    ///
    /// Transient errors include network/transport failures where the server
    /// session may still be alive and reconnection could succeed.
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            Error::Transport { .. }
                | Error::ConnectionClosed
                | Error::Timeout
                | Error::Io(_)
        )
    }

    /// Returns true if this error is fatal and reconnection won't help.
    ///
    /// Fatal errors indicate the session is unrecoverable - the server
    /// rejected the session or there's a protocol-level issue.
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            Error::AuthenticationFailed
                | Error::SessionExpired
                | Error::SessionNotFound(_)
                | Error::Protocol { .. }
        )
    }
}

/// Convenience result type for qsh operations.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_protocol() {
        let err = Error::Protocol {
            message: "invalid message type".into(),
        };
        assert_eq!(err.to_string(), "protocol error: invalid message type");
    }

    #[test]
    fn error_display_session_not_found() {
        let err = Error::SessionNotFound(42);
        assert_eq!(err.to_string(), "session not found: 42");
    }

    #[test]
    fn error_display_invalid_state() {
        let err = Error::InvalidState {
            expected: "Connected".into(),
            actual: "Disconnected".into(),
        };
        assert_eq!(
            err.to_string(),
            "invalid state: expected Connected, got Disconnected"
        );
    }

    #[test]
    fn io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err: Error = io_err.into();
        assert!(matches!(err, Error::Io(_)));
    }

    #[test]
    fn transient_errors() {
        assert!(Error::Transport {
            message: "connection lost".into()
        }
        .is_transient());
        assert!(Error::ConnectionClosed.is_transient());
        assert!(Error::Timeout.is_transient());
        assert!(Error::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "reset"
        ))
        .is_transient());

        // These should not be transient
        assert!(!Error::AuthenticationFailed.is_transient());
        assert!(!Error::SessionExpired.is_transient());
        assert!(!Error::Protocol {
            message: "bad".into()
        }
        .is_transient());
    }

    #[test]
    fn fatal_errors() {
        assert!(Error::AuthenticationFailed.is_fatal());
        assert!(Error::SessionExpired.is_fatal());
        assert!(Error::SessionNotFound(42).is_fatal());
        assert!(Error::Protocol {
            message: "invalid".into()
        }
        .is_fatal());

        // These should not be fatal
        assert!(!Error::Transport {
            message: "lost".into()
        }
        .is_fatal());
        assert!(!Error::ConnectionClosed.is_fatal());
        assert!(!Error::Timeout.is_fatal());
    }
}
