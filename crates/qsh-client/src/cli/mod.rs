//! Client CLI implementation.
//!
//! Provides command-line argument parsing using clap.

mod file;
mod parsing;
pub mod terminal;
mod types;

#[cfg(test)]
mod tests;

pub use file::FilePath;
// Re-export from types which re-exports terminal types to avoid ambiguity
pub use types::*;
