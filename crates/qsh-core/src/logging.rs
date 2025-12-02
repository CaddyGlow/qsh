//! Tracing integration for structured logging.
//!
//! Provides logging setup for both client and server with:
//! - Configurable verbosity levels
//! - Optional file output
//! - JSON or text format

use std::path::Path;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::Result;

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogFormat {
    /// Human-readable text output.
    #[default]
    Text,
    /// Structured JSON output.
    Json,
}

/// Initialize the logging system.
///
/// # Arguments
///
/// * `verbosity` - Verbosity level (0=error, 1=warn, 2=info, 3=debug, 4+=trace)
/// * `log_file` - Optional path to write logs to file
/// * `format` - Output format (text or JSON)
///
/// # Example
///
/// ```ignore
/// use qsh_core::logging::{init_logging, LogFormat};
///
/// // Basic setup with info level
/// init_logging(2, None, LogFormat::Text).unwrap();
///
/// // Debug level with JSON to file
/// init_logging(3, Some(Path::new("/tmp/qsh.log")), LogFormat::Json).unwrap();
/// ```
pub fn init_logging(verbosity: u8, log_file: Option<&Path>, format: LogFormat) -> Result<()> {
    let level = match verbosity {
        0 => "error",
        1 => "warn",
        2 => "info",
        3 => "debug",
        _ => "trace",
    };

    // Build filter with level and allow RUST_LOG override
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(format!(
            "qsh={},qsh_core={},qsh_client={},qsh_server={}",
            level, level, level, level
        ))
    });

    match (log_file, format) {
        (None, LogFormat::Text) => {
            // Simple stderr text output
            tracing_subscriber::registry()
                .with(filter)
                .with(
                    fmt::layer()
                        .with_target(true)
                        .with_thread_ids(false)
                        .with_file(verbosity >= 3)
                        .with_line_number(verbosity >= 3),
                )
                .try_init()
                .map_err(|e| crate::Error::Io(std::io::Error::other(e.to_string())))?;
        }
        (None, LogFormat::Json) => {
            // JSON to stderr
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().json())
                .try_init()
                .map_err(|e| crate::Error::Io(std::io::Error::other(e.to_string())))?;
        }
        (Some(path), LogFormat::Text) => {
            // Text to file
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)?;
            tracing_subscriber::registry()
                .with(filter)
                .with(
                    fmt::layer()
                        .with_writer(file)
                        .with_ansi(false)
                        .with_target(true)
                        .with_file(verbosity >= 3)
                        .with_line_number(verbosity >= 3),
                )
                .try_init()
                .map_err(|e| crate::Error::Io(std::io::Error::other(e.to_string())))?;
        }
        (Some(path), LogFormat::Json) => {
            // JSON to file
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)?;
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().json().with_writer(file))
                .try_init()
                .map_err(|e| crate::Error::Io(std::io::Error::other(e.to_string())))?;
        }
    }

    Ok(())
}

/// Initialize logging with defaults for testing.
///
/// Uses info level with text format to stderr.
/// Silently ignores errors (logging may already be initialized).
pub fn init_test_logging() {
    let _ = init_logging(2, None, LogFormat::Text);
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_format_default() {
        assert_eq!(LogFormat::default(), LogFormat::Text);
    }

    #[test]
    fn log_format_equality() {
        assert_eq!(LogFormat::Text, LogFormat::Text);
        assert_eq!(LogFormat::Json, LogFormat::Json);
        assert_ne!(LogFormat::Text, LogFormat::Json);
    }

    // Note: Can't easily test init_logging multiple times in the same process
    // since tracing subscriber can only be set once. These would be integration tests.

    #[test]
    fn verbosity_mapping() {
        // Just verify the function compiles with various inputs
        // Actual logging behavior tested in integration tests
        let _ = init_test_logging();
    }
}
