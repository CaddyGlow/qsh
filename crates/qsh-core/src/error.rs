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
}
