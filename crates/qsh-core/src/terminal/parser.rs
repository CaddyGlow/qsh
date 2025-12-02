//! VTE-based terminal parser.
//!
//! This module wraps the `vte` crate to parse ANSI escape sequences
//! and update terminal state accordingly.

use unicode_width::UnicodeWidthChar;
use vte::{Params, Parser, Perform};

use super::state::{Cell, Color, Cursor, CursorShape, TerminalState};

/// Terminal parser that processes raw bytes and updates state.
pub struct TerminalParser {
    state: TerminalState,
    parser: Parser,
    saved_cursor: Option<Cursor>,
}

impl TerminalParser {
    /// Create a new parser with given terminal dimensions.
    pub fn new(cols: u16, rows: u16) -> Self {
        Self {
            state: TerminalState::new(cols, rows),
            parser: Parser::new(),
            saved_cursor: None,
        }
    }

    /// Process raw bytes from PTY output.
    pub fn process(&mut self, data: &[u8]) {
        for &byte in data {
            // Use a temporary performer that borrows our state
            let mut performer = Performer {
                state: &mut self.state,
                saved_cursor: &mut self.saved_cursor,
            };
            self.parser.advance(&mut performer, byte);
        }
        self.state.generation += 1;
    }

    /// Get a reference to the current terminal state.
    pub fn state(&self) -> &TerminalState {
        &self.state
    }

    /// Take the current state (for sending to client).
    pub fn take_state(&self) -> TerminalState {
        self.state.clone()
    }

    /// Resize the terminal.
    pub fn resize(&mut self, cols: u16, rows: u16) {
        self.state.resize(cols, rows);
    }
}

/// Internal performer struct that implements vte::Perform.
struct Performer<'a> {
    state: &'a mut TerminalState,
    saved_cursor: &'a mut Option<Cursor>,
}

impl Perform for Performer<'_> {
    fn print(&mut self, c: char) {
        put_char(self.state, c);
    }

    fn execute(&mut self, byte: u8) {
        let state = &mut self.state;

        match byte {
            // Backspace
            0x08 => state.cursor.col = state.cursor.col.saturating_sub(1),
            // Tab
            0x09 => {
                let next_tab = ((state.cursor.col / 8) + 1) * 8;
                let max = state.screen().cols().saturating_sub(1);
                state.cursor.col = next_tab.min(max);
            }
            // Newline (LF) - in "newline mode" also does CR
            0x0A => {
                state.cursor.col = 0; // Implicit CR
                let rows = state.screen().rows();
                if state.cursor.row + 1 >= rows {
                    state.screen_mut().scroll_up(1);
                } else {
                    state.cursor.row += 1;
                }
            }
            // Carriage return
            0x0D => state.cursor.col = 0,
            _ => {}
        }
    }

    fn csi_dispatch(&mut self, params: &Params, intermediates: &[u8], _ignore: bool, action: char) {
        let state = &mut self.state;
        let saved_cursor = &mut self.saved_cursor;

        let param0 = params
            .iter()
            .next()
            .and_then(|p| p.first().copied())
            .unwrap_or(0) as u16;
        let param1 = params
            .iter()
            .nth(1)
            .and_then(|p| p.first().copied())
            .unwrap_or(0) as u16;

        match (action, intermediates) {
            // Cursor Up (CUU)
            ('A', []) => {
                let n = param0.max(1);
                state.cursor.row = state.cursor.row.saturating_sub(n);
            }
            // Cursor Down (CUD)
            ('B', []) => {
                let n = param0.max(1);
                let max = state.screen().rows().saturating_sub(1);
                state.cursor.row = (state.cursor.row + n).min(max);
            }
            // Cursor Forward (CUF)
            ('C', []) => {
                let n = param0.max(1);
                let max = state.screen().cols().saturating_sub(1);
                state.cursor.col = (state.cursor.col + n).min(max);
            }
            // Cursor Back (CUB)
            ('D', []) => {
                let n = param0.max(1);
                state.cursor.col = state.cursor.col.saturating_sub(n);
            }
            // Cursor Position (CUP) / Home (H)
            ('H', []) | ('f', []) => {
                let row = if param0 == 0 { 1 } else { param0 };
                let col = if param1 == 0 { 1 } else { param1 };
                let max_row = state.screen().rows().saturating_sub(1);
                let max_col = state.screen().cols().saturating_sub(1);
                state.cursor.row = row.saturating_sub(1).min(max_row);
                state.cursor.col = col.saturating_sub(1).min(max_col);
            }
            // Erase Display (ED)
            ('J', []) => {
                let cursor = state.cursor;
                let rows = state.screen().rows();

                match param0 {
                    0 => {
                        // Clear from cursor to end of screen
                        state.screen_mut().clear_to_eol(cursor.col, cursor.row);
                        for row in (cursor.row + 1)..rows {
                            state.screen_mut().clear_row(row);
                        }
                    }
                    1 => {
                        // Clear from start to cursor
                        for row in 0..cursor.row {
                            state.screen_mut().clear_row(row);
                        }
                        for col in 0..=cursor.col {
                            state.screen_mut().set(col, cursor.row, Cell::default());
                        }
                    }
                    2 | 3 => {
                        state.screen_mut().clear();
                    }
                    _ => {}
                }
            }
            // Erase Line (EL)
            ('K', []) => {
                let cursor = state.cursor;

                match param0 {
                    0 => state.screen_mut().clear_to_eol(cursor.col, cursor.row),
                    1 => {
                        for col in 0..=cursor.col {
                            state.screen_mut().set(col, cursor.row, Cell::default());
                        }
                    }
                    2 => state.screen_mut().clear_row(cursor.row),
                    _ => {}
                }
            }
            // SGR (Select Graphic Rendition)
            ('m', []) => handle_sgr(state, params),
            // Save cursor (SCP/DECSC)
            ('s', []) => **saved_cursor = Some(state.cursor),
            // Restore cursor (RCP/DECRC)
            ('u', []) => {
                if let Some(cursor) = **saved_cursor {
                    state.cursor = cursor;
                }
            }
            // Private modes (DEC)
            ('h', [b'?']) | ('l', [b'?']) => {
                let enable = action == 'h';
                match param0 {
                    // Show/hide cursor (DECTCEM)
                    25 => state.cursor.visible = enable,
                    // Alternate screen buffer (ALTBUF)
                    1049 => {
                        if enable {
                            **saved_cursor = Some(state.cursor);
                            state.enter_alternate();
                        } else {
                            state.exit_alternate();
                            if let Some(cursor) = saved_cursor.take() {
                                state.cursor = cursor;
                            }
                        }
                    }
                    _ => {}
                }
            }
            // Cursor shape (DECSCUSR)
            ('q', [b' ']) => {
                state.cursor.shape = match param0 {
                    0 | 1 | 2 => CursorShape::Block,
                    3 | 4 => CursorShape::Underline,
                    5 | 6 => CursorShape::Bar,
                    _ => CursorShape::Block,
                };
            }
            _ => {}
        }
    }

    fn osc_dispatch(&mut self, params: &[&[u8]], _bell_terminated: bool) {
        if params.is_empty() {
            return;
        }

        let cmd = std::str::from_utf8(params[0])
            .ok()
            .and_then(|s| s.parse::<u8>().ok());

        match cmd {
            Some(0 | 1 | 2) => {
                if let Some(title) = params.get(1) {
                    if let Ok(title) = std::str::from_utf8(title) {
                        self.state.title = Some(title.to_string());
                    }
                }
            }
            _ => {}
        }
    }

    fn hook(&mut self, _params: &Params, _intermediates: &[u8], _ignore: bool, _action: char) {}
    fn put(&mut self, _byte: u8) {}
    fn unhook(&mut self) {}
    fn esc_dispatch(&mut self, _intermediates: &[u8], _ignore: bool, _byte: u8) {}
}

/// Put a character at the cursor position and advance.
fn put_char(state: &mut TerminalState, c: char) {
    let width = c.width().unwrap_or(1);
    let cols = state.screen().cols();
    let rows = state.screen().rows();

    // Handle line wrap
    if state.cursor.col >= cols {
        state.cursor.col = 0;
        if state.cursor.row + 1 >= rows {
            state.screen_mut().scroll_up(1);
        } else {
            state.cursor.row += 1;
        }
    }

    // Create cell with current attributes
    let cell = Cell::with_style(c, state.current_fg, state.current_bg, state.current_attrs);

    let col = state.cursor.col;
    let row = state.cursor.row;
    state.screen_mut().set(col, row, cell);

    // For wide characters, fill the next cell with a placeholder
    if width == 2 && col + 1 < cols {
        state.screen_mut().set(col + 1, row, Cell::default());
    }

    // Advance cursor
    state.cursor.col += width as u16;
}

/// Handle SGR (Select Graphic Rendition) parameters.
fn handle_sgr(state: &mut TerminalState, params: &Params) {
    let mut iter = params.iter();

    while let Some(param) = iter.next() {
        let n = param.first().copied().unwrap_or(0);

        match n {
            0 => state.reset_attrs(),
            1 => state.current_attrs.bold = true,
            2 => state.current_attrs.dim = true,
            3 => state.current_attrs.italic = true,
            4 => state.current_attrs.underline = true,
            5 => state.current_attrs.blink = true,
            7 => state.current_attrs.reverse = true,
            8 => state.current_attrs.hidden = true,
            9 => state.current_attrs.strikethrough = true,
            22 => {
                state.current_attrs.bold = false;
                state.current_attrs.dim = false;
            }
            23 => state.current_attrs.italic = false,
            24 => state.current_attrs.underline = false,
            25 => state.current_attrs.blink = false,
            27 => state.current_attrs.reverse = false,
            28 => state.current_attrs.hidden = false,
            29 => state.current_attrs.strikethrough = false,

            // Standard foreground colors (30-37)
            30..=37 => state.current_fg = Color::Indexed((n - 30) as u8),
            // Default foreground
            39 => state.current_fg = Color::Default,

            // Standard background colors (40-47)
            40..=47 => state.current_bg = Color::Indexed((n - 40) as u8),
            // Default background
            49 => state.current_bg = Color::Default,

            // Bright foreground colors (90-97)
            90..=97 => state.current_fg = Color::Indexed((n - 90 + 8) as u8),
            // Bright background colors (100-107)
            100..=107 => state.current_bg = Color::Indexed((n - 100 + 8) as u8),

            // 256-color and true color foreground
            38 => {
                if let Some(sub) = iter.next() {
                    match sub.first().copied().unwrap_or(0) {
                        5 => {
                            if let Some(color) = iter.next() {
                                let idx = color.first().copied().unwrap_or(0) as u8;
                                state.current_fg = Color::Indexed(idx);
                            }
                        }
                        2 => {
                            let r =
                                iter.next().and_then(|p| p.first().copied()).unwrap_or(0) as u8;
                            let g =
                                iter.next().and_then(|p| p.first().copied()).unwrap_or(0) as u8;
                            let b =
                                iter.next().and_then(|p| p.first().copied()).unwrap_or(0) as u8;
                            state.current_fg = Color::Rgb(r, g, b);
                        }
                        _ => {}
                    }
                }
            }

            // 256-color and true color background
            48 => {
                if let Some(sub) = iter.next() {
                    match sub.first().copied().unwrap_or(0) {
                        5 => {
                            if let Some(color) = iter.next() {
                                let idx = color.first().copied().unwrap_or(0) as u8;
                                state.current_bg = Color::Indexed(idx);
                            }
                        }
                        2 => {
                            let r =
                                iter.next().and_then(|p| p.first().copied()).unwrap_or(0) as u8;
                            let g =
                                iter.next().and_then(|p| p.first().copied()).unwrap_or(0) as u8;
                            let b =
                                iter.next().and_then(|p| p.first().copied()).unwrap_or(0) as u8;
                            state.current_bg = Color::Rgb(r, g, b);
                        }
                        _ => {}
                    }
                }
            }

            _ => {}
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn print_ascii_moves_cursor_sets_cells() {
        let mut parser = TerminalParser::new(80, 24);
        parser.process(b"ABC");

        let state = parser.state();
        assert_eq!(state.cursor.col, 3);
        assert_eq!(state.cursor.row, 0);
        assert_eq!(state.screen().get(0, 0).unwrap().ch, 'A');
        assert_eq!(state.screen().get(1, 0).unwrap().ch, 'B');
        assert_eq!(state.screen().get(2, 0).unwrap().ch, 'C');
    }

    #[test]
    fn print_unicode_wide_char() {
        let mut parser = TerminalParser::new(80, 24);
        parser.process("X".as_bytes());
        parser.process("\u{4E2D}".as_bytes()); // Chinese character
        parser.process("Y".as_bytes());

        let state = parser.state();
        assert_eq!(state.screen().get(0, 0).unwrap().ch, 'X');
        assert_eq!(state.screen().get(1, 0).unwrap().ch, '\u{4E2D}');
        assert_eq!(state.cursor.col, 4);
    }

    #[test]
    fn newline_moves_cursor_down() {
        let mut parser = TerminalParser::new(80, 24);
        parser.process(b"A\nB");

        let state = parser.state();
        assert_eq!(state.screen().get(0, 0).unwrap().ch, 'A');
        assert_eq!(state.screen().get(0, 1).unwrap().ch, 'B');
        assert_eq!(state.cursor.row, 1);
    }

    #[test]
    fn carriage_return_moves_cursor_to_column_0() {
        let mut parser = TerminalParser::new(80, 24);
        parser.process(b"ABCDE\rX");

        let state = parser.state();
        assert_eq!(state.screen().get(0, 0).unwrap().ch, 'X');
        assert_eq!(state.screen().get(1, 0).unwrap().ch, 'B');
        assert_eq!(state.cursor.col, 1);
    }

    #[test]
    fn backspace_moves_cursor_left() {
        let mut parser = TerminalParser::new(80, 24);
        parser.process(b"ABC\x08X");

        let state = parser.state();
        assert_eq!(state.screen().get(0, 0).unwrap().ch, 'A');
        assert_eq!(state.screen().get(1, 0).unwrap().ch, 'B');
        assert_eq!(state.screen().get(2, 0).unwrap().ch, 'X');
    }

    #[test]
    fn tab_moves_to_next_tab_stop() {
        let mut parser = TerminalParser::new(80, 24);
        parser.process(b"A\tB");

        let state = parser.state();
        assert_eq!(state.screen().get(0, 0).unwrap().ch, 'A');
        assert_eq!(state.screen().get(8, 0).unwrap().ch, 'B');
        assert_eq!(state.cursor.col, 9);
    }

    #[test]
    fn csi_cursor_up() {
        let mut parser = TerminalParser::new(80, 24);
        parser.process(b"\x1b[5;10H");
        parser.process(b"\x1b[2A");

        let state = parser.state();
        assert_eq!(state.cursor.row, 2);
        assert_eq!(state.cursor.col, 9);
    }

    #[test]
    fn csi_cursor_down() {
        let mut parser = TerminalParser::new(80, 24);
        parser.process(b"\x1b[3B");

        let state = parser.state();
        assert_eq!(state.cursor.row, 3);
    }

    #[test]
    fn csi_cursor_forward() {
        let mut parser = TerminalParser::new(80, 24);
        parser.process(b"\x1b[5C");

        let state = parser.state();
        assert_eq!(state.cursor.col, 5);
    }

    #[test]
    fn csi_cursor_back() {
        let mut parser = TerminalParser::new(80, 24);
        parser.process(b"\x1b[10C");
        parser.process(b"\x1b[3D");

        let state = parser.state();
        assert_eq!(state.cursor.col, 7);
    }

    #[test]
    fn csi_cursor_position() {
        let mut parser = TerminalParser::new(80, 24);

        parser.process(b"\x1b[H");
        assert_eq!(parser.state().cursor.row, 0);
        assert_eq!(parser.state().cursor.col, 0);

        parser.process(b"\x1b[5;10H");
        assert_eq!(parser.state().cursor.row, 4);
        assert_eq!(parser.state().cursor.col, 9);
    }

    #[test]
    fn csi_erase_display_to_end() {
        let mut parser = TerminalParser::new(80, 24);
        parser.process(b"ABCDE\x1b[H\x1b[2C\x1b[J");

        let state = parser.state();
        assert_eq!(state.screen().get(0, 0).unwrap().ch, 'A');
        assert_eq!(state.screen().get(1, 0).unwrap().ch, 'B');
        assert_eq!(state.screen().get(2, 0).unwrap().ch, ' ');
    }

    #[test]
    fn csi_erase_line_to_end() {
        let mut parser = TerminalParser::new(80, 24);
        parser.process(b"ABCDE\x1b[H\x1b[2C\x1b[K");

        let state = parser.state();
        assert_eq!(state.screen().get(0, 0).unwrap().ch, 'A');
        assert_eq!(state.screen().get(1, 0).unwrap().ch, 'B');
        assert_eq!(state.screen().get(2, 0).unwrap().ch, ' ');
    }

    #[test]
    fn sgr_reset() {
        let mut parser = TerminalParser::new(80, 24);
        parser.process(b"\x1b[1;31mRED\x1b[0mNORMAL");

        let state = parser.state();
        let r_cell = state.screen().get(0, 0).unwrap();
        assert_eq!(r_cell.ch, 'R');
        assert!(r_cell.attrs.bold);
        assert_eq!(r_cell.fg, Color::Indexed(1));

        let n_cell = state.screen().get(3, 0).unwrap();
        assert_eq!(n_cell.ch, 'N');
        assert!(!n_cell.attrs.bold);
        assert_eq!(n_cell.fg, Color::Default);
    }

    #[test]
    fn sgr_bold() {
        let mut parser = TerminalParser::new(80, 24);
        parser.process(b"\x1b[1mB");

        let state = parser.state();
        assert!(state.screen().get(0, 0).unwrap().attrs.bold);
    }

    #[test]
    fn sgr_fg_color() {
        let mut parser = TerminalParser::new(80, 24);
        parser.process(b"\x1b[31mR");

        let state = parser.state();
        assert_eq!(state.screen().get(0, 0).unwrap().fg, Color::Indexed(1));
    }

    #[test]
    fn sgr_bg_color() {
        let mut parser = TerminalParser::new(80, 24);
        parser.process(b"\x1b[44mB");

        let state = parser.state();
        assert_eq!(state.screen().get(0, 0).unwrap().bg, Color::Indexed(4));
    }

    #[test]
    fn sgr_256_color() {
        let mut parser = TerminalParser::new(80, 24);
        parser.process(b"\x1b[38;5;196mR");

        let state = parser.state();
        assert_eq!(state.screen().get(0, 0).unwrap().fg, Color::Indexed(196));
    }

    #[test]
    fn sgr_rgb_color() {
        let mut parser = TerminalParser::new(80, 24);
        parser.process(b"\x1b[38;2;255;128;0mO");

        let state = parser.state();
        assert_eq!(state.screen().get(0, 0).unwrap().fg, Color::Rgb(255, 128, 0));
    }

    #[test]
    fn alternate_screen_on_off() {
        let mut parser = TerminalParser::new(80, 24);

        parser.process(b"MAIN");
        assert!(!parser.state().alternate_active);

        parser.process(b"\x1b[?1049h");
        assert!(parser.state().alternate_active);
        assert_eq!(parser.state().screen().get(0, 0).unwrap().ch, ' ');

        parser.process(b"ALT");
        assert_eq!(parser.state().screen().get(0, 0).unwrap().ch, 'A');

        parser.process(b"\x1b[?1049l");
        assert!(!parser.state().alternate_active);
        assert_eq!(parser.state().screen().get(0, 0).unwrap().ch, 'M');
    }

    #[test]
    fn set_title_osc() {
        let mut parser = TerminalParser::new(80, 24);
        parser.process(b"\x1b]0;My Title\x07");

        assert_eq!(parser.state().title, Some("My Title".to_string()));
    }

    #[test]
    fn cursor_visibility() {
        let mut parser = TerminalParser::new(80, 24);
        assert!(parser.state().cursor.visible);

        parser.process(b"\x1b[?25l");
        assert!(!parser.state().cursor.visible);

        parser.process(b"\x1b[?25h");
        assert!(parser.state().cursor.visible);
    }

    #[test]
    fn scroll_at_bottom() {
        let mut parser = TerminalParser::new(80, 5);

        for i in 0..5 {
            parser.process(format!("{}\n", i).as_bytes());
        }

        let state = parser.state();
        assert_eq!(state.screen().get(0, 0).unwrap().ch, '1');
    }

    #[test]
    fn generation_increments() {
        let mut parser = TerminalParser::new(80, 24);
        assert_eq!(parser.state().generation, 0);

        parser.process(b"A");
        assert_eq!(parser.state().generation, 1);

        parser.process(b"B");
        assert_eq!(parser.state().generation, 2);
    }
}
