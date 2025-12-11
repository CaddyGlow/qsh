//! Client CLI implementation.
//!
//! Provides command-line argument parsing using clap.

mod file;
mod parsing;
mod types;

#[cfg(test)]
mod tests;

pub use file::FilePath;
pub use types::*;
