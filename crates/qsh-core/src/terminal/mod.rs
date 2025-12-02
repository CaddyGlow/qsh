//! Terminal state and parsing for qsh.
//!
//! This module provides:
//! - Terminal state types (cells, screens, cursor)
//! - VTE-based ANSI escape sequence parser
//! - State diffing for efficient updates

mod parser;
mod state;

pub use parser::TerminalParser;
pub use state::{Cell, CellAttrs, Color, Cursor, CursorShape, Screen, TerminalState};
