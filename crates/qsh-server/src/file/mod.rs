//! File transfer handling for qsh server.
//!
//! Provides server-side file transfer functionality:
//! - Handling file requests (upload/download)
//! - Computing and sending file metadata
//! - Delta transfer support
//! - Parallel chunk assembly

pub mod handler;

pub use handler::FileHandler;
