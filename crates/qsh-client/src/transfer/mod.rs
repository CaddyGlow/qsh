//! File transfer engine (refactored from qscp).
//!
//! This module provides a library interface for file transfers, extracted from
//! the qscp binary. It supports:
//!
//! - Upload/download with progress callbacks
//! - Skip/resume/delta logic
//! - Compression and delta sync
//! - Parallel directory transfers
//!
//! The engine accepts an Arc<ChannelConnection> and emits progress events via
//! callbacks instead of using indicatif directly.

pub mod engine;
pub mod progress;

pub use engine::{TransferEngine, TransferStats};
pub use progress::{IndicatifCallback, NoOpCallback, ProgressCallback, ProgressEvent, callback};
