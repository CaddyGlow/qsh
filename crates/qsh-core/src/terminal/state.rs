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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Color {
    /// Default foreground/background color.
    #[default]
    Default,
    /// Standard 8/16 color palette (0-15).
    Indexed(u8),
    /// 24-bit RGB color.
    Rgb(u8, u8, u8),
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

    /// Check if this cell is empty (space or default).
    pub fn is_empty(&self) -> bool {
        self.ch == ' ' || self.is_default()
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
// Scroll Region
// =============================================================================

/// Scroll region (top and bottom margins for DECSTBM).
/// Both values are 0-indexed row numbers. The region is inclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScrollRegion {
    pub top: u16,
    pub bottom: u16,
}

impl ScrollRegion {
    /// Create a new scroll region with given top and bottom margins.
    pub fn new(top: u16, bottom: u16) -> Self {
        Self { top, bottom }
    }

    /// Check if a row is within the scroll region.
    pub fn contains(&self, row: u16) -> bool {
        row >= self.top && row <= self.bottom
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

    /// Get a row of cells as a slice.
    pub fn row(&self, row: u16) -> Option<&[Cell]> {
        if row < self.rows {
            let start = self.index(0, row);
            let end = start + self.cols as usize;
            Some(&self.cells[start..end])
        } else {
            None
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
    /// This scrolls the entire screen (for backwards compatibility).
    pub fn scroll_up(&mut self, n: u16) {
        self.scroll_up_region(n, 0, self.rows.saturating_sub(1));
    }

    /// Scroll the screen down by n lines, filling top with empty lines.
    /// This scrolls the entire screen (for backwards compatibility).
    pub fn scroll_down(&mut self, n: u16) {
        self.scroll_down_region(n, 0, self.rows.saturating_sub(1));
    }

    /// Scroll a region up by n lines, filling bottom of region with empty lines.
    /// top and bottom are 0-indexed inclusive row numbers.
    pub fn scroll_up_region(&mut self, n: u16, top: u16, bottom: u16) {
        if n == 0 || top > bottom || bottom >= self.rows {
            return;
        }

        let region_height = bottom - top + 1;
        let n = n.min(region_height);

        if n >= region_height {
            // Clear entire region
            for row in top..=bottom {
                self.clear_row(row);
            }
            return;
        }

        // Move lines up within the region
        let cols = self.cols as usize;
        for dst_row in top..(bottom - n + 1) {
            let src_row = dst_row + n;
            let dst_start = dst_row as usize * cols;
            let src_start = src_row as usize * cols;

            // Copy row by row (can't use rotate for partial regions)
            for col in 0..cols {
                self.cells[dst_start + col] = self.cells[src_start + col].clone();
            }
        }

        // Clear bottom n rows of the region
        for row in (bottom - n + 1)..=bottom {
            self.clear_row(row);
        }
    }

    /// Scroll a region down by n lines, filling top of region with empty lines.
    /// top and bottom are 0-indexed inclusive row numbers.
    pub fn scroll_down_region(&mut self, n: u16, top: u16, bottom: u16) {
        if n == 0 || top > bottom || bottom >= self.rows {
            return;
        }

        let region_height = bottom - top + 1;
        let n = n.min(region_height);

        if n >= region_height {
            // Clear entire region
            for row in top..=bottom {
                self.clear_row(row);
            }
            return;
        }

        // Move lines down within the region (iterate backwards to avoid overwriting)
        let cols = self.cols as usize;
        for dst_row in ((top + n)..=bottom).rev() {
            let src_row = dst_row - n;
            let dst_start = dst_row as usize * cols;
            let src_start = src_row as usize * cols;

            for col in 0..cols {
                self.cells[dst_start + col] = self.cells[src_start + col].clone();
            }
        }

        // Clear top n rows of the region
        for row in top..(top + n) {
            self.clear_row(row);
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
    /// Scroll region (top/bottom margins). None means full screen.
    pub scroll_region: Option<ScrollRegion>,
    /// Window/tab title (OSC 0/1/2).
    pub title: Option<String>,
    /// Current working directory (OSC 7).
    pub cwd: Option<String>,
    /// Pending clipboard content (OSC 52). Tuple of (selection, base64-encoded data).
    /// Selection is typically "c" (clipboard) or "p" (primary).
    pub clipboard: Option<(String, String)>,
    /// Current foreground color for new cells.
    pub current_fg: Color,
    /// Current background color for new cells.
    pub current_bg: Color,
    /// Current attributes for new cells.
    pub current_attrs: CellAttrs,
    /// Mouse reporting mode (DECSET 9/1000/1002/1003).
    #[serde(default)]
    pub mouse_reporting_mode: MouseReportingMode,
    /// Mouse focus event reporting (DECSET 1004).
    #[serde(default)]
    pub mouse_focus_event: bool,
    /// Mouse alternate scroll mode (DECSET 1007).
    #[serde(default)]
    pub mouse_alternate_scroll: bool,
    /// Mouse encoding mode (DECSET 1005/1006/1015).
    #[serde(default)]
    pub mouse_encoding_mode: MouseEncodingMode,
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
            scroll_region: None,
            title: None,
            cwd: None,
            clipboard: None,
            current_fg: Color::Default,
            current_bg: Color::Default,
            current_attrs: CellAttrs::default(),
            mouse_reporting_mode: MouseReportingMode::default(),
            mouse_focus_event: false,
            mouse_alternate_scroll: false,
            mouse_encoding_mode: MouseEncodingMode::default(),
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

    /// Get the width (columns) of the terminal.
    pub fn cols(&self) -> u16 {
        self.screen().cols()
    }

    /// Get the height (rows) of the terminal.
    pub fn rows(&self) -> u16 {
        self.screen().rows()
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
        // Reset scroll region on resize
        self.scroll_region = None;
    }

    /// Set the scroll region (DECSTBM).
    /// Top and bottom are 1-indexed (VT100 convention), converted internally to 0-indexed.
    /// Pass (0, 0) or (1, rows) to reset to full screen.
    pub fn set_scroll_region(&mut self, top: u16, bottom: u16) {
        let rows = self.screen().rows();
        let top = if top == 0 { 1 } else { top };
        let bottom = if bottom == 0 { rows } else { bottom };

        // Validate and convert to 0-indexed
        if top < bottom && bottom <= rows {
            let top_0 = top.saturating_sub(1);
            let bottom_0 = bottom.saturating_sub(1);

            // If it covers the full screen, just clear the region
            if top_0 == 0 && bottom_0 == rows - 1 {
                self.scroll_region = None;
            } else {
                self.scroll_region = Some(ScrollRegion::new(top_0, bottom_0));
            }

            // DECSTBM moves cursor to home position
            self.cursor.col = 0;
            self.cursor.row = 0;
        }
    }

    /// Get the effective scroll region (returns full screen if None).
    pub fn effective_scroll_region(&self) -> ScrollRegion {
        self.scroll_region
            .unwrap_or_else(|| ScrollRegion::new(0, self.screen().rows().saturating_sub(1)))
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

    /// Render the terminal state to ANSI escape sequences.
    ///
    /// This is used after reconnection to sync the client's display with the
    /// server's terminal state. Returns bytes that can be written directly to
    /// the terminal to reproduce the visual state.
    pub fn render_to_ansi(&self) -> Vec<u8> {
        use std::fmt::Write;
        let mut output = String::with_capacity(self.screen().cells.len() * 2);

        // Reset terminal and clear screen
        output.push_str("\x1b[2J"); // Clear entire screen
        output.push_str("\x1b[H"); // Move cursor to home position
        output.push_str("\x1b[0m"); // Reset all attributes

        // Mouse modes (best-effort on resync)
        if let Some(code) = self.mouse_reporting_mode.as_dec_private() {
            let _ = write!(output, "\x1b[?{}h", code);
        }
        if self.mouse_focus_event {
            output.push_str("\x1b[?1004h");
        }
        if self.mouse_alternate_scroll {
            output.push_str("\x1b[?1007h");
        }
        if let Some(code) = self.mouse_encoding_mode.as_dec_private() {
            let _ = write!(output, "\x1b[?{}h", code);
        }

        let screen = self.screen();
        let mut last_fg = Color::Default;
        let mut last_bg = Color::Default;
        let mut last_attrs = CellAttrs::default();

        for row in 0..screen.rows() {
            // Move to start of row
            let _ = write!(output, "\x1b[{};1H", row + 1);

            for col in 0..screen.cols() {
                if let Some(cell) = screen.get(col, row) {
                    // Update attributes if changed
                    if cell.attrs != last_attrs || cell.fg != last_fg || cell.bg != last_bg {
                        // Reset and reapply
                        output.push_str("\x1b[0m");

                        // Apply cell attributes
                        if cell.attrs.bold {
                            output.push_str("\x1b[1m");
                        }
                        if cell.attrs.dim {
                            output.push_str("\x1b[2m");
                        }
                        if cell.attrs.italic {
                            output.push_str("\x1b[3m");
                        }
                        if cell.attrs.underline {
                            output.push_str("\x1b[4m");
                        }
                        if cell.attrs.blink {
                            output.push_str("\x1b[5m");
                        }
                        if cell.attrs.reverse {
                            output.push_str("\x1b[7m");
                        }
                        if cell.attrs.hidden {
                            output.push_str("\x1b[8m");
                        }
                        if cell.attrs.strikethrough {
                            output.push_str("\x1b[9m");
                        }

                        // Apply foreground color
                        match cell.fg {
                            Color::Default => {}
                            Color::Indexed(n) if n < 8 => {
                                let _ = write!(output, "\x1b[{}m", 30 + n);
                            }
                            Color::Indexed(n) if n < 16 => {
                                let _ = write!(output, "\x1b[{}m", 90 + n - 8);
                            }
                            Color::Indexed(n) => {
                                let _ = write!(output, "\x1b[38;5;{}m", n);
                            }
                            Color::Rgb(r, g, b) => {
                                let _ = write!(output, "\x1b[38;2;{};{};{}m", r, g, b);
                            }
                        }

                        // Apply background color
                        match cell.bg {
                            Color::Default => {}
                            Color::Indexed(n) if n < 8 => {
                                let _ = write!(output, "\x1b[{}m", 40 + n);
                            }
                            Color::Indexed(n) if n < 16 => {
                                let _ = write!(output, "\x1b[{}m", 100 + n - 8);
                            }
                            Color::Indexed(n) => {
                                let _ = write!(output, "\x1b[48;5;{}m", n);
                            }
                            Color::Rgb(r, g, b) => {
                                let _ = write!(output, "\x1b[48;2;{};{};{}m", r, g, b);
                            }
                        }

                        last_attrs = cell.attrs;
                        last_fg = cell.fg;
                        last_bg = cell.bg;
                    }

                    output.push(cell.ch);
                }
            }
        }

        // Reset attributes and move cursor to stored position
        output.push_str("\x1b[0m");
        let _ = write!(
            output,
            "\x1b[{};{}H",
            self.cursor.row + 1,
            self.cursor.col + 1
        );

        // Show/hide cursor based on visibility
        if self.cursor.visible {
            output.push_str("\x1b[?25h"); // Show cursor
        } else {
            output.push_str("\x1b[?25l"); // Hide cursor
        }

        output.into_bytes()
    }
}

/// Mouse reporting modes (DECSET 9/1000/1002/1003).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MouseReportingMode {
    None,
    /// X10 reporting (DECSET 9) - no button motion
    X10,
    /// X11 normal tracking (DECSET 1000)
    NormalTracking,
    /// Button-event tracking (DECSET 1002)
    ButtonTracking,
    /// Any-motion tracking (DECSET 1003)
    AnyEventTracking,
}

impl Default for MouseReportingMode {
    fn default() -> Self {
        MouseReportingMode::None
    }
}

impl MouseReportingMode {
    pub fn from_dec_private(code: u16) -> Self {
        match code {
            9 => MouseReportingMode::X10,
            1000 => MouseReportingMode::NormalTracking,
            1002 => MouseReportingMode::ButtonTracking,
            1003 => MouseReportingMode::AnyEventTracking,
            _ => MouseReportingMode::None,
        }
    }

    pub fn as_dec_private(self) -> Option<u16> {
        match self {
            MouseReportingMode::None => None,
            MouseReportingMode::X10 => Some(9),
            MouseReportingMode::NormalTracking => Some(1000),
            MouseReportingMode::ButtonTracking => Some(1002),
            MouseReportingMode::AnyEventTracking => Some(1003),
        }
    }
}

/// Mouse encoding modes (DECSET 1005/1006/1015).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MouseEncodingMode {
    Default,
    Utf8,  // 1005
    Sgr,   // 1006
    Urxvt, // 1015
}

impl Default for MouseEncodingMode {
    fn default() -> Self {
        MouseEncodingMode::Default
    }
}

impl MouseEncodingMode {
    pub fn from_dec_private(code: u16) -> Self {
        match code {
            1005 => MouseEncodingMode::Utf8,
            1006 => MouseEncodingMode::Sgr,
            1015 => MouseEncodingMode::Urxvt,
            _ => MouseEncodingMode::Default,
        }
    }

    pub fn as_dec_private(self) -> Option<u16> {
        match self {
            MouseEncodingMode::Default => None,
            MouseEncodingMode::Utf8 => Some(1005),
            MouseEncodingMode::Sgr => Some(1006),
            MouseEncodingMode::Urxvt => Some(1015),
        }
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

    #[test]
    fn scroll_region_contains() {
        let region = ScrollRegion::new(2, 5);
        assert!(!region.contains(0));
        assert!(!region.contains(1));
        assert!(region.contains(2));
        assert!(region.contains(3));
        assert!(region.contains(5));
        assert!(!region.contains(6));
    }

    #[test]
    fn set_scroll_region_basic() {
        let mut state = TerminalState::new(80, 24);

        // Set scroll region (1-indexed input as per VT100)
        state.set_scroll_region(5, 15);

        let region = state.scroll_region.unwrap();
        assert_eq!(region.top, 4); // Converted to 0-indexed
        assert_eq!(region.bottom, 14);

        // Cursor should move to home
        assert_eq!(state.cursor.row, 0);
        assert_eq!(state.cursor.col, 0);
    }

    #[test]
    fn set_scroll_region_full_screen_clears() {
        let mut state = TerminalState::new(80, 24);

        // First set a region
        state.set_scroll_region(5, 15);
        assert!(state.scroll_region.is_some());

        // Now set full screen region (should clear)
        state.set_scroll_region(1, 24);
        assert!(state.scroll_region.is_none());

        // Reset with 0,0 also clears
        state.set_scroll_region(5, 15);
        state.set_scroll_region(0, 0);
        assert!(state.scroll_region.is_none());
    }

    #[test]
    fn effective_scroll_region_returns_full_when_none() {
        let state = TerminalState::new(80, 24);
        let region = state.effective_scroll_region();
        assert_eq!(region.top, 0);
        assert_eq!(region.bottom, 23);
    }

    #[test]
    fn screen_scroll_up_region() {
        let mut screen = Screen::new(80, 10);
        // Fill rows with letters
        for row in 0..10 {
            screen.set(0, row, Cell::new((b'A' + row as u8) as char));
        }

        // Scroll region 2-6 (rows C-G) up by 2
        screen.scroll_up_region(2, 2, 6);

        // Rows 0-1 unchanged
        assert_eq!(screen.get(0, 0).unwrap().ch, 'A');
        assert_eq!(screen.get(0, 1).unwrap().ch, 'B');
        // Rows 2-4 should have shifted content from 4-6
        assert_eq!(screen.get(0, 2).unwrap().ch, 'E');
        assert_eq!(screen.get(0, 3).unwrap().ch, 'F');
        assert_eq!(screen.get(0, 4).unwrap().ch, 'G');
        // Rows 5-6 should be cleared
        assert_eq!(screen.get(0, 5).unwrap().ch, ' ');
        assert_eq!(screen.get(0, 6).unwrap().ch, ' ');
        // Rows 7-9 unchanged
        assert_eq!(screen.get(0, 7).unwrap().ch, 'H');
        assert_eq!(screen.get(0, 8).unwrap().ch, 'I');
        assert_eq!(screen.get(0, 9).unwrap().ch, 'J');
    }

    #[test]
    fn screen_scroll_down_region() {
        let mut screen = Screen::new(80, 10);
        // Fill rows with letters
        for row in 0..10 {
            screen.set(0, row, Cell::new((b'A' + row as u8) as char));
        }

        // Scroll region 2-6 (rows C-G) down by 2
        screen.scroll_down_region(2, 2, 6);

        // Rows 0-1 unchanged
        assert_eq!(screen.get(0, 0).unwrap().ch, 'A');
        assert_eq!(screen.get(0, 1).unwrap().ch, 'B');
        // Rows 2-3 should be cleared
        assert_eq!(screen.get(0, 2).unwrap().ch, ' ');
        assert_eq!(screen.get(0, 3).unwrap().ch, ' ');
        // Rows 4-6 should have shifted content from 2-4
        assert_eq!(screen.get(0, 4).unwrap().ch, 'C');
        assert_eq!(screen.get(0, 5).unwrap().ch, 'D');
        assert_eq!(screen.get(0, 6).unwrap().ch, 'E');
        // Rows 7-9 unchanged
        assert_eq!(screen.get(0, 7).unwrap().ch, 'H');
        assert_eq!(screen.get(0, 8).unwrap().ch, 'I');
        assert_eq!(screen.get(0, 9).unwrap().ch, 'J');
    }

    #[test]
    fn resize_clears_scroll_region() {
        let mut state = TerminalState::new(80, 24);
        state.set_scroll_region(5, 15);
        assert!(state.scroll_region.is_some());

        state.resize(100, 30);
        assert!(state.scroll_region.is_none());
    }
}
