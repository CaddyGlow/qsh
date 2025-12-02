//! Terminal state types for qsh.
//!
//! This module provides:
//! - Cell representation (grapheme, colors, attributes)
//! - Screen buffer (2D grid of cells)
//! - Cursor state
//! - Complete terminal state snapshots

use serde::{Deserialize, Serialize};

// =============================================================================
// Color Types
// =============================================================================

/// Terminal color representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Color {
    /// Default foreground/background color.
    Default,
    /// Standard 8/16 color palette (0-15).
    Indexed(u8),
    /// 24-bit RGB color.
    Rgb(u8, u8, u8),
}

impl Default for Color {
    fn default() -> Self {
        Color::Default
    }
}

impl std::fmt::Display for Color {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Color::Default => write!(f, ""),
            Color::Indexed(n) => {
                // ANSI escape codes for indexed colors
                if *n < 8 {
                    write!(f, "\x1b[{}m", 30 + n)
                } else if *n < 16 {
                    write!(f, "\x1b[{}m", 90 + n - 8)
                } else {
                    write!(f, "\x1b[38;5;{}m", n)
                }
            }
            Color::Rgb(r, g, b) => write!(f, "\x1b[38;2;{};{};{}m", r, g, b),
        }
    }
}

// =============================================================================
// Cell Attributes
// =============================================================================

/// Cell display attributes (bold, italic, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CellAttrs {
    pub bold: bool,
    pub italic: bool,
    pub underline: bool,
    pub strikethrough: bool,
    pub dim: bool,
    pub blink: bool,
    pub reverse: bool,
    pub hidden: bool,
}

impl CellAttrs {
    /// Returns true if all attributes are default (off).
    pub fn is_default(&self) -> bool {
        !self.bold
            && !self.italic
            && !self.underline
            && !self.strikethrough
            && !self.dim
            && !self.blink
            && !self.reverse
            && !self.hidden
    }

    /// Reset all attributes to default.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// =============================================================================
// Cell
// =============================================================================

/// A single terminal cell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cell {
    /// The character displayed (space for empty).
    pub ch: char,
    /// Foreground color.
    pub fg: Color,
    /// Background color.
    pub bg: Color,
    /// Display attributes.
    pub attrs: CellAttrs,
}

impl Default for Cell {
    fn default() -> Self {
        Self {
            ch: ' ',
            fg: Color::Default,
            bg: Color::Default,
            attrs: CellAttrs::default(),
        }
    }
}

impl Cell {
    /// Create a new cell with a character and default styling.
    pub fn new(ch: char) -> Self {
        Self {
            ch,
            ..Default::default()
        }
    }

    /// Create a cell with full styling.
    pub fn with_style(ch: char, fg: Color, bg: Color, attrs: CellAttrs) -> Self {
        Self { ch, fg, bg, attrs }
    }

    /// Check if this is a default (empty space, default colors) cell.
    pub fn is_default(&self) -> bool {
        self.ch == ' '
            && self.fg == Color::Default
            && self.bg == Color::Default
            && self.attrs.is_default()
    }
}

// =============================================================================
// Cursor
// =============================================================================

/// Cursor shape enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum CursorShape {
    #[default]
    Block,
    Underline,
    Bar,
}

/// Cursor state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cursor {
    pub col: u16,
    pub row: u16,
    pub visible: bool,
    pub shape: CursorShape,
}

impl Default for Cursor {
    fn default() -> Self {
        Self {
            col: 0,
            row: 0,
            visible: true,
            shape: CursorShape::Block,
        }
    }
}

// =============================================================================
// Screen
// =============================================================================

/// A terminal screen buffer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Screen {
    cells: Vec<Cell>,
    cols: u16,
    rows: u16,
}

impl Screen {
    /// Create a new screen with given dimensions, filled with default cells.
    pub fn new(cols: u16, rows: u16) -> Self {
        let size = cols as usize * rows as usize;
        Self {
            cells: vec![Cell::default(); size],
            cols,
            rows,
        }
    }

    /// Get screen width in columns.
    pub fn cols(&self) -> u16 {
        self.cols
    }

    /// Get screen height in rows.
    pub fn rows(&self) -> u16 {
        self.rows
    }

    /// Convert (col, row) to linear index.
    fn index(&self, col: u16, row: u16) -> usize {
        row as usize * self.cols as usize + col as usize
    }

    /// Get a cell by position.
    pub fn get(&self, col: u16, row: u16) -> Option<&Cell> {
        if col < self.cols && row < self.rows {
            Some(&self.cells[self.index(col, row)])
        } else {
            None
        }
    }

    /// Get a mutable reference to a cell.
    pub fn get_mut(&mut self, col: u16, row: u16) -> Option<&mut Cell> {
        if col < self.cols && row < self.rows {
            let idx = self.index(col, row);
            Some(&mut self.cells[idx])
        } else {
            None
        }
    }

    /// Set a cell at position.
    pub fn set(&mut self, col: u16, row: u16, cell: Cell) {
        if col < self.cols && row < self.rows {
            let idx = self.index(col, row);
            self.cells[idx] = cell;
        }
    }

    /// Clear the entire screen with default cells.
    pub fn clear(&mut self) {
        for cell in &mut self.cells {
            *cell = Cell::default();
        }
    }

    /// Clear a single row.
    pub fn clear_row(&mut self, row: u16) {
        if row < self.rows {
            let start = self.index(0, row);
            let end = start + self.cols as usize;
            for cell in &mut self.cells[start..end] {
                *cell = Cell::default();
            }
        }
    }

    /// Clear cells from (col, row) to end of line.
    pub fn clear_to_eol(&mut self, col: u16, row: u16) {
        if row < self.rows {
            let start = self.index(col.min(self.cols), row);
            let end = self.index(self.cols, row);
            for cell in &mut self.cells[start..end] {
                *cell = Cell::default();
            }
        }
    }

    /// Resize the screen, preserving content where possible.
    pub fn resize(&mut self, new_cols: u16, new_rows: u16) {
        if new_cols == self.cols && new_rows == self.rows {
            return;
        }

        let new_size = new_cols as usize * new_rows as usize;
        let mut new_cells = vec![Cell::default(); new_size];

        // Copy existing content
        let copy_cols = self.cols.min(new_cols);
        let copy_rows = self.rows.min(new_rows);

        for row in 0..copy_rows {
            for col in 0..copy_cols {
                let old_idx = row as usize * self.cols as usize + col as usize;
                let new_idx = row as usize * new_cols as usize + col as usize;
                new_cells[new_idx] = self.cells[old_idx].clone();
            }
        }

        self.cells = new_cells;
        self.cols = new_cols;
        self.rows = new_rows;
    }

    /// Scroll the screen up by n lines, filling bottom with empty lines.
    pub fn scroll_up(&mut self, n: u16) {
        if n == 0 {
            return;
        }

        if n >= self.rows {
            self.clear();
            return;
        }

        // Shift cells up (Cell is not Copy, so we rotate and clear)
        let shift = n as usize * self.cols as usize;
        self.cells.rotate_left(shift);

        // Clear bottom rows
        let total = self.cells.len();
        for cell in self.cells[(total - shift)..].iter_mut() {
            *cell = Cell::default();
        }
    }

    /// Scroll the screen down by n lines, filling top with empty lines.
    pub fn scroll_down(&mut self, n: u16) {
        if n == 0 {
            return;
        }

        if n >= self.rows {
            self.clear();
            return;
        }

        let shift = n as usize * self.cols as usize;
        self.cells.rotate_right(shift);

        // Clear top rows
        for cell in self.cells[..shift].iter_mut() {
            *cell = Cell::default();
        }
    }

    /// Iterator over all cells with their positions.
    pub fn iter(&self) -> impl Iterator<Item = (u16, u16, &Cell)> {
        self.cells.iter().enumerate().map(move |(idx, cell)| {
            let row = (idx / self.cols as usize) as u16;
            let col = (idx % self.cols as usize) as u16;
            (col, row, cell)
        })
    }
}

// =============================================================================
// Terminal State
// =============================================================================

/// Complete terminal state snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminalState {
    /// Monotonic generation number for ordering.
    pub generation: u64,
    /// Primary screen buffer.
    pub primary: Screen,
    /// Alternate screen buffer.
    pub alternate: Screen,
    /// Cursor state.
    pub cursor: Cursor,
    /// Whether alternate screen is active.
    pub alternate_active: bool,
    /// Window/tab title.
    pub title: Option<String>,
    /// Current foreground color for new cells.
    pub current_fg: Color,
    /// Current background color for new cells.
    pub current_bg: Color,
    /// Current attributes for new cells.
    pub current_attrs: CellAttrs,
}

impl TerminalState {
    /// Create a new terminal state with given dimensions.
    pub fn new(cols: u16, rows: u16) -> Self {
        Self {
            generation: 0,
            primary: Screen::new(cols, rows),
            alternate: Screen::new(cols, rows),
            cursor: Cursor::default(),
            alternate_active: false,
            title: None,
            current_fg: Color::Default,
            current_bg: Color::Default,
            current_attrs: CellAttrs::default(),
        }
    }

    /// Get the active screen.
    pub fn screen(&self) -> &Screen {
        if self.alternate_active {
            &self.alternate
        } else {
            &self.primary
        }
    }

    /// Get the active screen mutably.
    pub fn screen_mut(&mut self) -> &mut Screen {
        if self.alternate_active {
            &mut self.alternate
        } else {
            &mut self.primary
        }
    }

    /// Get screen dimensions.
    pub fn size(&self) -> (u16, u16) {
        (self.screen().cols(), self.screen().rows())
    }

    /// Resize both screens.
    pub fn resize(&mut self, cols: u16, rows: u16) {
        self.primary.resize(cols, rows);
        self.alternate.resize(cols, rows);
        // Clamp cursor to new bounds
        self.cursor.col = self.cursor.col.min(cols.saturating_sub(1));
        self.cursor.row = self.cursor.row.min(rows.saturating_sub(1));
    }

    /// Switch to alternate screen.
    pub fn enter_alternate(&mut self) {
        if !self.alternate_active {
            self.alternate_active = true;
            self.alternate.clear();
            self.cursor = Cursor::default();
        }
    }

    /// Switch back to primary screen.
    pub fn exit_alternate(&mut self) {
        if self.alternate_active {
            self.alternate_active = false;
            // Cursor should be restored to saved position (not implemented in simple version)
        }
    }

    /// Reset all SGR attributes.
    pub fn reset_attrs(&mut self) {
        self.current_fg = Color::Default;
        self.current_bg = Color::Default;
        self.current_attrs = CellAttrs::default();
    }
}

impl Default for TerminalState {
    fn default() -> Self {
        Self::new(80, 24)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn screen_new_creates_correct_size() {
        let screen = Screen::new(80, 24);
        assert_eq!(screen.cols(), 80);
        assert_eq!(screen.rows(), 24);
        assert_eq!(screen.cells.len(), 80 * 24);
    }

    #[test]
    fn screen_get_set_cell() {
        let mut screen = Screen::new(80, 24);

        // Set a cell
        screen.set(5, 10, Cell::new('X'));

        // Get it back
        let cell = screen.get(5, 10).unwrap();
        assert_eq!(cell.ch, 'X');

        // Out of bounds returns None
        assert!(screen.get(100, 0).is_none());
        assert!(screen.get(0, 100).is_none());
    }

    #[test]
    fn screen_resize_preserves_content() {
        let mut screen = Screen::new(80, 24);
        screen.set(0, 0, Cell::new('A'));
        screen.set(79, 23, Cell::new('Z'));
        screen.set(10, 5, Cell::new('M'));

        // Grow
        screen.resize(100, 30);
        assert_eq!(screen.cols(), 100);
        assert_eq!(screen.rows(), 30);
        assert_eq!(screen.get(0, 0).unwrap().ch, 'A');
        assert_eq!(screen.get(79, 23).unwrap().ch, 'Z');
        assert_eq!(screen.get(10, 5).unwrap().ch, 'M');

        // Shrink
        screen.resize(50, 10);
        assert_eq!(screen.cols(), 50);
        assert_eq!(screen.rows(), 10);
        assert_eq!(screen.get(0, 0).unwrap().ch, 'A');
        assert_eq!(screen.get(10, 5).unwrap().ch, 'M');
        // Z is now out of bounds and lost
    }

    #[test]
    fn screen_resize_same_size_noop() {
        let mut screen = Screen::new(80, 24);
        screen.set(0, 0, Cell::new('X'));
        screen.resize(80, 24);
        assert_eq!(screen.get(0, 0).unwrap().ch, 'X');
    }

    #[test]
    fn cell_default_is_space() {
        let cell = Cell::default();
        assert_eq!(cell.ch, ' ');
        assert_eq!(cell.fg, Color::Default);
        assert_eq!(cell.bg, Color::Default);
        assert!(cell.attrs.is_default());
        assert!(cell.is_default());
    }

    #[test]
    fn terminal_state_new_creates_screens() {
        let state = TerminalState::new(80, 24);
        assert_eq!(state.primary.cols(), 80);
        assert_eq!(state.primary.rows(), 24);
        assert_eq!(state.alternate.cols(), 80);
        assert_eq!(state.alternate.rows(), 24);
        assert_eq!(state.generation, 0);
        assert!(!state.alternate_active);
    }

    #[test]
    fn terminal_state_clone_is_deep_copy() {
        let mut state = TerminalState::new(80, 24);
        state.screen_mut().set(0, 0, Cell::new('X'));
        state.generation = 42;

        let cloned = state.clone();
        assert_eq!(cloned.generation, 42);
        assert_eq!(cloned.screen().get(0, 0).unwrap().ch, 'X');

        // Modifying original doesn't affect clone
        state.screen_mut().set(0, 0, Cell::new('Y'));
        assert_eq!(cloned.screen().get(0, 0).unwrap().ch, 'X');
    }

    #[test]
    fn screen_scroll_up() {
        let mut screen = Screen::new(80, 5);
        for row in 0..5 {
            screen.set(0, row, Cell::new((b'A' + row as u8) as char));
        }

        screen.scroll_up(2);

        // Row 2 should now be at row 0
        assert_eq!(screen.get(0, 0).unwrap().ch, 'C');
        assert_eq!(screen.get(0, 1).unwrap().ch, 'D');
        assert_eq!(screen.get(0, 2).unwrap().ch, 'E');
        // Bottom rows should be empty
        assert_eq!(screen.get(0, 3).unwrap().ch, ' ');
        assert_eq!(screen.get(0, 4).unwrap().ch, ' ');
    }

    #[test]
    fn screen_scroll_down() {
        let mut screen = Screen::new(80, 5);
        for row in 0..5 {
            screen.set(0, row, Cell::new((b'A' + row as u8) as char));
        }

        screen.scroll_down(2);

        // Top rows should be empty
        assert_eq!(screen.get(0, 0).unwrap().ch, ' ');
        assert_eq!(screen.get(0, 1).unwrap().ch, ' ');
        // Original content shifted down
        assert_eq!(screen.get(0, 2).unwrap().ch, 'A');
        assert_eq!(screen.get(0, 3).unwrap().ch, 'B');
        assert_eq!(screen.get(0, 4).unwrap().ch, 'C');
    }

    #[test]
    fn screen_clear_row() {
        let mut screen = Screen::new(80, 24);
        for col in 0..80 {
            screen.set(col, 5, Cell::new('X'));
        }

        screen.clear_row(5);

        for col in 0..80 {
            assert_eq!(screen.get(col, 5).unwrap().ch, ' ');
        }
    }

    #[test]
    fn alternate_screen_switch() {
        let mut state = TerminalState::new(80, 24);

        // Write to primary
        state.screen_mut().set(0, 0, Cell::new('P'));
        assert!(!state.alternate_active);

        // Switch to alternate
        state.enter_alternate();
        assert!(state.alternate_active);
        assert_eq!(state.screen().get(0, 0).unwrap().ch, ' '); // Alternate was cleared

        // Write to alternate
        state.screen_mut().set(0, 0, Cell::new('A'));

        // Switch back
        state.exit_alternate();
        assert!(!state.alternate_active);
        assert_eq!(state.screen().get(0, 0).unwrap().ch, 'P'); // Primary preserved
    }

    #[test]
    fn color_display() {
        assert_eq!(format!("{}", Color::Default), "");
        assert_eq!(format!("{}", Color::Indexed(1)), "\x1b[31m");
        assert_eq!(format!("{}", Color::Indexed(9)), "\x1b[91m");
        assert_eq!(format!("{}", Color::Indexed(200)), "\x1b[38;5;200m");
        assert_eq!(
            format!("{}", Color::Rgb(255, 128, 0)),
            "\x1b[38;2;255;128;0m"
        );
    }

    #[test]
    fn cell_attrs_reset() {
        let mut attrs = CellAttrs {
            bold: true,
            italic: true,
            underline: true,
            strikethrough: true,
            dim: true,
            blink: true,
            reverse: true,
            hidden: true,
        };
        assert!(!attrs.is_default());

        attrs.reset();
        assert!(attrs.is_default());
    }
}
