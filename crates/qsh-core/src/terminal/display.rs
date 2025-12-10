//! Mosh-style display renderer for terminal state.
//!
//! Converts terminal state diffs into minimal ANSI escape sequences,
//! optimizing for bandwidth efficiency.

use super::state::{Cell, CellAttrs, Color, Cursor, CursorShape, Screen, TerminalState};

/// Mosh-style display renderer that generates ANSI escape sequences
/// from terminal state diffs.
pub struct Display {
    /// Last rendered state (None if first frame).
    last_state: Option<TerminalState>,
    /// Current rendition state for optimization.
    current_rendition: Rendition,
    /// Current cursor position for optimization.
    current_cursor: (u16, u16),
    /// Current cursor visibility.
    cursor_visible: bool,
}

/// Current text rendition state (colors and attributes).
#[derive(Debug, Clone, PartialEq)]
struct Rendition {
    fg: Color,
    bg: Color,
    attrs: CellAttrs,
}

impl Default for Rendition {
    fn default() -> Self {
        Self {
            fg: Color::Default,
            bg: Color::Default,
            attrs: CellAttrs::default(),
        }
    }
}

impl Display {
    /// Create a new Display renderer.
    pub fn new() -> Self {
        Self {
            last_state: None,
            current_rendition: Rendition::default(),
            current_cursor: (0, 0),
            cursor_visible: false,
        }
    }

    /// Reset the renderer (forces full state send on next frame).
    pub fn reset(&mut self) {
        self.last_state = None;
        self.current_rendition = Rendition::default();
        self.current_cursor = (0, 0);
        self.cursor_visible = false;
    }

    /// Generate ANSI escape sequences to transform last state into new state.
    ///
    /// This is equivalent to mosh's Display::new_frame().
    pub fn new_frame(&mut self, new_state: &TerminalState) -> Vec<u8> {
        let mut output = Vec::new();
        let initialized = self.last_state.is_some();

        // Get last state or create empty one for comparison
        let last = self.last_state.as_ref();

        // 1. Bell if changed
        // Note: TerminalState doesn't track bell count yet
        // This would be added when implementing full mosh compatibility

        // 2. Title (OSC 0, OSC 1, OSC 2)
        if !initialized || (last.is_some() && last.unwrap().title != new_state.title) {
            if let Some(ref title) = new_state.title {
                self.append_osc_title(&mut output, title);
            }
        }

        // 3. Clipboard (OSC 52)
        if !initialized || (last.is_some() && last.unwrap().clipboard != new_state.clipboard) {
            if let Some((ref selection, ref content)) = new_state.clipboard {
                self.append_osc_clipboard(&mut output, selection, content);
            }
        }

        // 4. Reverse video mode (we don't track this yet)
        // Skip for now

        // 5. Size changes
        let cols = new_state.cols();
        let rows = new_state.rows();
        let size_changed = if let Some(last) = last {
            last.cols() != cols || last.rows() != rows
        } else {
            true
        };

        if size_changed {
            // Reset scrolling region
            output.extend_from_slice(b"\x1b[r");
            // Clear screen
            output.extend_from_slice(b"\x1b[0m\x1b[H\x1b[2J");
            self.current_cursor = (0, 0);
            self.current_rendition = Rendition::default();
            self.cursor_visible = false;
        }

        // 6. Scroll detection optimization
        // TODO: Implement scroll detection (check if rows 0..N match rows K..K+N)
        // For now, skip this optimization

        // 7. Update each row
        // Collect row data first to avoid borrow checker issues
        let rows_data: Vec<(Option<Vec<Cell>>, Option<Vec<Cell>>)> = (0..rows)
            .map(|row| {
                let new_row = new_state.screen().row(row).map(|r| r.to_vec());
                let old_row = if !size_changed && initialized {
                    last.and_then(|l| l.screen().row(row)).map(|r| r.to_vec())
                } else {
                    None
                };
                (new_row, old_row)
            })
            .collect();

        for (row, (new_row, old_row)) in rows_data.iter().enumerate() {
            let new_row_slice = new_row.as_ref().map(|v| v.as_slice());
            let old_row_slice = old_row.as_ref().map(|v| v.as_slice());
            self.put_row(&mut output, row as u16, new_row_slice, old_row_slice, cols);
        }

        // 8. Update cursor position
        let target_cursor = (new_state.cursor.col, new_state.cursor.row);
        if self.current_cursor != target_cursor {
            self.append_move(&mut output, target_cursor.1, target_cursor.0);
            self.current_cursor = target_cursor;
        }

        // 9. Update cursor visibility
        let target_visible = new_state.cursor.visible;
        if self.cursor_visible != target_visible {
            if target_visible {
                output.extend_from_slice(b"\x1b[?25h");
            } else {
                output.extend_from_slice(b"\x1b[?25l");
            }
            self.cursor_visible = target_visible;
        }

        // 10. Update text renditions (reset at end for cleanliness)
        // This is handled per-cell in put_row()

        // Store current state for next diff
        self.last_state = Some(new_state.clone());

        output
    }

    /// Update a single row with minimal escape sequences.
    ///
    /// This is equivalent to mosh's Display::put_row().
    fn put_row(
        &mut self,
        output: &mut Vec<u8>,
        row_idx: u16,
        new_row: Option<&[Cell]>,
        old_row: Option<&[Cell]>,
        cols: u16,
    ) {
        let new_cells = match new_row {
            Some(cells) => cells,
            None => return,
        };

        // Quick check: if rows are identical, skip
        if let Some(old_cells) = old_row {
            if new_cells == old_cells {
                return;
            }
        }

        let mut col = 0;
        let mut clear_count = 0;
        let default_cell = Cell::default();

        while col < cols {
            let new_cell = new_cells.get(col as usize).unwrap_or(&default_cell);

            // Check if cell changed
            let changed = if let Some(old_cells) = old_row {
                old_cells.get(col as usize) != Some(new_cell)
            } else {
                !new_cell.is_empty()
            };

            if !changed {
                col += 1;
                continue;
            }

            // Cell changed or is new
            if new_cell.is_empty() {
                // Accumulate blanks for ECH optimization
                clear_count += 1;
                col += 1;
                continue;
            }

            // Non-blank cell: flush any pending blanks first
            if clear_count > 0 {
                // Move to start of blank run
                let blank_start_col = col - clear_count;
                if self.current_cursor != (blank_start_col, row_idx) {
                    self.append_move(output, row_idx, blank_start_col);
                    self.current_cursor = (blank_start_col, row_idx);
                }

                // Use ECH if run > 4 characters, otherwise spaces
                if clear_count > 4 {
                    self.append_ech(output, clear_count);
                } else {
                    for _ in 0..clear_count {
                        output.push(b' ');
                    }
                }
                self.current_cursor.0 += clear_count;
                clear_count = 0;
            }

            // Move cursor to cell position
            if self.current_cursor != (col, row_idx) {
                self.append_move(output, row_idx, col);
                self.current_cursor = (col, row_idx);
            }

            // Update rendition if needed
            self.update_rendition(output, new_cell);

            // Output the character
            self.append_cell(output, new_cell);

            // Advance cursor (handle wide chars if needed)
            col += 1;
            self.current_cursor.0 += 1;
        }

        // Handle remaining blanks at end of line
        if clear_count > 0 {
            let blank_start_col = col - clear_count;
            if self.current_cursor != (blank_start_col, row_idx) {
                self.append_move(output, row_idx, blank_start_col);
                self.current_cursor = (blank_start_col, row_idx);
            }

            // Use EL (Erase in Line) for end-of-line clears
            output.extend_from_slice(b"\x1b[K");
            self.current_cursor.0 = cols;
        }
    }

    /// Append cursor movement escape sequence.
    fn append_move(&self, output: &mut Vec<u8>, row: u16, col: u16) {
        // ESC [ row+1 ; col+1 H
        output.extend_from_slice(b"\x1b[");
        output.extend_from_slice((row + 1).to_string().as_bytes());
        output.push(b';');
        output.extend_from_slice((col + 1).to_string().as_bytes());
        output.push(b'H');
    }

    /// Append ECH (Erase Character) escape sequence.
    fn append_ech(&self, output: &mut Vec<u8>, count: u16) {
        // ESC [ count X
        output.extend_from_slice(b"\x1b[");
        output.extend_from_slice(count.to_string().as_bytes());
        output.push(b'X');
    }

    /// Update text rendition (colors and attributes) if changed.
    fn update_rendition(&mut self, output: &mut Vec<u8>, cell: &Cell) {
        let target = Rendition {
            fg: cell.fg,
            bg: cell.bg,
            attrs: cell.attrs,
        };

        if self.current_rendition == target {
            return;
        }

        // Build SGR (Select Graphic Rendition) sequence
        // ESC [ params m
        let mut params = Vec::new();

        // Check if we should reset all attributes
        let need_reset = self.current_rendition.attrs != CellAttrs::default()
            && target.attrs == CellAttrs::default()
            && target.fg == Color::Default
            && target.bg == Color::Default;

        if need_reset {
            params.push("0".to_string());
            self.current_rendition = Rendition::default();
        }

        // Attributes
        if target.attrs.bold != self.current_rendition.attrs.bold {
            params.push(if target.attrs.bold { "1" } else { "22" }.to_string());
        }
        if target.attrs.dim != self.current_rendition.attrs.dim {
            params.push(if target.attrs.dim { "2" } else { "22" }.to_string());
        }
        if target.attrs.italic != self.current_rendition.attrs.italic {
            params.push(if target.attrs.italic { "3" } else { "23" }.to_string());
        }
        if target.attrs.underline != self.current_rendition.attrs.underline {
            params.push(if target.attrs.underline {
                "4"
            } else {
                "24"
            }
            .to_string());
        }
        if target.attrs.blink != self.current_rendition.attrs.blink {
            params.push(if target.attrs.blink { "5" } else { "25" }.to_string());
        }
        if target.attrs.reverse != self.current_rendition.attrs.reverse {
            params.push(if target.attrs.reverse { "7" } else { "27" }.to_string());
        }
        if target.attrs.hidden != self.current_rendition.attrs.hidden {
            params.push(if target.attrs.hidden { "8" } else { "28" }.to_string());
        }
        if target.attrs.strikethrough != self.current_rendition.attrs.strikethrough {
            params.push(if target.attrs.strikethrough {
                "9"
            } else {
                "29"
            }
            .to_string());
        }

        // Foreground color
        if target.fg != self.current_rendition.fg {
            params.extend(self.color_to_sgr_params(target.fg, true));
        }

        // Background color
        if target.bg != self.current_rendition.bg {
            params.extend(self.color_to_sgr_params(target.bg, false));
        }

        if !params.is_empty() {
            output.extend_from_slice(b"\x1b[");
            output.extend_from_slice(params.join(";").as_bytes());
            output.push(b'm');
            self.current_rendition = target;
        }
    }

    /// Convert a Color to SGR parameters.
    fn color_to_sgr_params(&self, color: Color, foreground: bool) -> Vec<String> {
        let base = if foreground { 30 } else { 40 };
        let bright_base = if foreground { 90 } else { 100 };

        match color {
            Color::Default => vec![if foreground { "39" } else { "49" }.to_string()],
            Color::Indexed(idx) => {
                if idx < 8 {
                    vec![(base + idx).to_string()]
                } else if idx < 16 {
                    vec![(bright_base + (idx - 8)).to_string()]
                } else {
                    vec![
                        if foreground { "38" } else { "48" }.to_string(),
                        "5".to_string(),
                        idx.to_string(),
                    ]
                }
            }
            Color::Rgb(r, g, b) => vec![
                if foreground { "38" } else { "48" }.to_string(),
                "2".to_string(),
                r.to_string(),
                g.to_string(),
                b.to_string(),
            ],
        }
    }

    /// Append a cell's character(s) to output.
    fn append_cell(&self, output: &mut Vec<u8>, cell: &Cell) {
        // For now, just append the character as UTF-8
        let mut buf = [0u8; 4];
        let encoded = cell.ch.encode_utf8(&mut buf);
        output.extend_from_slice(encoded.as_bytes());
    }

    /// Append OSC title sequence.
    fn append_osc_title(&self, output: &mut Vec<u8>, title: &str) {
        // OSC 0 ; title BEL
        output.extend_from_slice(b"\x1b]0;");
        output.extend_from_slice(title.as_bytes());
        output.push(0x07); // BEL
    }

    /// Append OSC clipboard sequence.
    fn append_osc_clipboard(&self, output: &mut Vec<u8>, selection: &str, content: &str) {
        // OSC 52 ; selection ; content BEL
        output.extend_from_slice(b"\x1b]52;");
        output.extend_from_slice(selection.as_bytes());
        output.push(b';');
        output.extend_from_slice(content.as_bytes());
        output.push(0x07); // BEL
    }
}

impl Default for Display {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_empty_diff() {
        let mut display = Display::new();
        let state = TerminalState::new(80, 24);
        let output = display.new_frame(&state);

        // First frame should clear screen and hide cursor
        assert!(!output.is_empty());
        assert!(output.windows(4).any(|w| w == b"\x1b[2J")); // Clear screen
    }

    #[test]
    fn test_display_cursor_only() {
        let mut display = Display::new();
        let mut state1 = TerminalState::new(80, 24);
        let _ = display.new_frame(&state1);

        // Move cursor
        state1.cursor.col = 10;
        state1.cursor.row = 5;
        let output = display.new_frame(&state1);

        // Should contain cursor movement
        let output_str = String::from_utf8_lossy(&output);
        assert!(output_str.contains("\x1b["));
    }

    #[test]
    fn test_display_single_char() {
        let mut display = Display::new();
        let mut state = TerminalState::new(80, 24);
        let _ = display.new_frame(&state);

        // Add a character
        state.screen_mut().set(5, 10, Cell::new('X'));
        let output = display.new_frame(&state);

        // Should contain the character
        assert!(output.contains(&b'X'));
    }

    #[test]
    fn test_display_color_change() {
        let mut display = Display::new();
        let state = TerminalState::new(80, 24);
        let _ = display.new_frame(&state);

        // Add colored character
        let mut state2 = state.clone();
        state2.screen_mut().set(
            0,
            0,
            Cell::with_style('R', Color::Rgb(255, 0, 0), Color::Default, CellAttrs::default()),
        );
        let output = display.new_frame(&state2);

        // Should contain RGB color sequence
        let output_str = String::from_utf8_lossy(&output);
        assert!(output_str.contains("38;2")); // Foreground RGB
    }

    #[test]
    fn test_display_title_change() {
        let mut display = Display::new();
        let state = TerminalState::new(80, 24);
        let _ = display.new_frame(&state);

        // Change title
        let mut state2 = state.clone();
        state2.title = Some("Test Title".to_string());
        let output = display.new_frame(&state2);

        // Should contain OSC 0 sequence
        assert!(output.windows(4).any(|w| w == b"\x1b]0;"));
        assert!(output.windows(10).any(|w| w == b"Test Title"));
    }
}
