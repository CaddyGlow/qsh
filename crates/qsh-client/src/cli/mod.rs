//! Client CLI implementation.
//!
//! Provides command-line argument parsing using clap.

mod types;
mod parsing;
mod file;

#[cfg(test)]
mod tests;

pub use types::*;
pub use file::FilePath;
