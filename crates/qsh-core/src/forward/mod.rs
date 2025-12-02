//! Port forwarding types and specification parsing.
//!
//! This module provides:
//! - Forward specification parsing (SSH-style -L/-R/-D syntax)
//! - Forward connection tracking
//! - Forward manager for handling multiple forwards

mod spec;

pub use spec::{ForwardSpec, ParsedForwardSpec};

#[cfg(test)]
mod tests;
