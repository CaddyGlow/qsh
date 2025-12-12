//! Concrete resource implementations for the control plane.
//!
//! This module contains the actual resource implementations:
//!
//! - [`forward::Forward`]: Port forwarding (local, remote, dynamic/SOCKS5)
//! - [`terminal::Terminal`]: PTY terminals with attach/detach
//! - [`file_transfer::FileTransfer`]: File uploads/downloads via qscp engine
//!
//! Each resource implements the [`super::Resource`] trait and can be managed
//! by the [`super::ResourceManager`].

pub mod forward;
pub mod terminal;
pub mod file_transfer;

pub use forward::{Forward, ForwardParams};
pub use terminal::Terminal;
pub use file_transfer::FileTransfer;
