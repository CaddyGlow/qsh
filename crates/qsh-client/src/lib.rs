//! qsh-client: Client library for qsh remote terminal.
//!
//! Provides:
//! - Prediction engine for local echo
//! - Overlay rendering for status and predictions
//! - Bootstrap client for SSH-based server discovery
//! - Session management

pub mod overlay;
pub mod prediction;
