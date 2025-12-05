//! File transfer client for qsh.
//!
//! Provides:
//! - File upload and download
//! - Progress reporting
//! - Delta sync support
//! - Parallel transfers

pub mod progress;
pub mod transfer;

pub use progress::ProgressReporter;
pub use transfer::{FileTransfer, TransferResult};
