//! Concrete resource implementations for the control plane.
//!
//! This module contains the actual resource implementations:
//!
//! - [`terminal::Terminal`]: PTY terminals with attach/detach
//! - [`forward::Forward`]: Port forwards (local, remote, dynamic/SOCKS5)
//! - [`file_transfer::FileTransfer`]: File transfers via qscp engine
//!
//! Each resource implements the [`super::Resource`] trait and can be managed
//! by the [`super::ResourceManager`].

pub mod file_transfer;
pub mod forward;
pub mod terminal;

pub use file_transfer::FileTransfer;
pub use forward::{Forward, ForwardParams};
pub use terminal::Terminal;
