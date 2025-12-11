//! Mosh-style display renderer for terminal state.
//!
//! Converts terminal state diffs into minimal ANSI/ECMA-48 escape sequences,
//! matching mosh's terminaldisplay implementation as closely as possible.

use std::fmt::Write;

use terminfo::{Database, capability as cap};

use super::state::{Cell, Color, MouseEncodingMode, MouseReportingMode, TerminalState};

/// Terminal capability flags sourced from terminfo.
#[derive(Debug, Clone)]
struct TerminfoCaps {
    has_ech: bool,
    has_bce: bool,
    has_title: bool,
    smcup: Option<String>,
    rmcup: Option<String>,
}

impl TerminfoCaps {
    fn detect() -> Self {
        // Safe defaults if terminfo lookup fails.
        let mut caps = TerminfoCaps {
            has_ech: false,
            has_bce: false,
            has_title: true,
            smcup: None,
            rmcup: None,
        };

        if let Ok(db) = Database::from_env() {
            caps.has_ech = db.get::<cap::EraseChars>().is_some();
            caps.has_bce = db
                .get::<cap::BackColorErase>()
                .map(bool::from)
                .unwrap_or(false);

            // Title whitelist (same prefixes mosh uses).
            const TITLE_PREFIXES: [&str; 7] = [
                "xterm",
                "rxvt",
                "kterm",
                "Eterm",
                "alacritty",
                "screen",
                "tmux",
            ];
            let names: Vec<&str> = std::iter::once(db.name())
                .chain(db.aliases().iter().map(|s| s.as_str()))
                .collect();
            caps.has_title = names
                .iter()
                .any(|name| TITLE_PREFIXES.iter().any(|prefix| name.starts_with(prefix)));

            if std::env::var_os("MOSH_NO_TERM_INIT").is_none() {
                caps.smcup = db
                    .get::<cap::EnterCaMode>()
                    .map(|s| String::from_utf8_lossy(s.as_ref()).into_owned());
                caps.rmcup = db
                    .get::<cap::ExitCaMode>()
                    .map(|s| String::from_utf8_lossy(s.as_ref()).into_owned());
            }
        }

        caps
    }
}

/// A compact rendition (attributes + colors) that can render itself to SGR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Rendition {
    fg: u32,
    bg: u32,
    attrs: RenditionAttrs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct RenditionAttrs {
    bold: bool,
    faint: bool,
    italic: bool,
    underline: bool,
    blink: bool,
    inverse: bool,
    invisible: bool,
}

impl Default for Rendition {
    fn default() -> Self {
        Self {
            fg: 0,
            bg: 0,
            attrs: RenditionAttrs::default(),
        }
    }
}

impl Rendition {
    fn from_cell(cell: &Cell) -> Self {
        Rendition {
            fg: color_to_code(cell.fg, true),
            bg: color_to_code(cell.bg, false),
            attrs: RenditionAttrs {
                bold: cell.attrs.bold,
                faint: cell.attrs.dim,
                italic: cell.attrs.italic,
                underline: cell.attrs.underline,
                blink: cell.attrs.blink,
                inverse: cell.attrs.reverse,
                invisible: cell.attrs.hidden,
            },
        }
    }

    fn from_state_defaults(state: &TerminalState) -> Self {
        Rendition {
            fg: color_to_code(state.current_fg, true),
            bg: color_to_code(state.current_bg, false),
            attrs: RenditionAttrs {
                bold: state.current_attrs.bold,
                faint: state.current_attrs.dim,
                italic: state.current_attrs.italic,
                underline: state.current_attrs.underline,
                blink: state.current_attrs.blink,
                inverse: state.current_attrs.reverse,
                invisible: state.current_attrs.hidden,
            },
        }
    }

    fn sgr(&self) -> String {
        // Matches terminaldisplay.cc Renditions::sgr() (bold/italic/underline/blink/reverse/invisible).
        let mut out = String::from("\x1b[0");

        if self.attrs.bold {
            out.push_str(";1");
        }
        if self.attrs.italic {
            out.push_str(";3");
        }
        if self.attrs.underline {
            out.push_str(";4");
        }
        if self.attrs.blink {
            out.push_str(";5");
        }
        if self.attrs.inverse {
            out.push_str(";7");
        }
        if self.attrs.invisible {
            out.push_str(";8");
        }

        if self.fg != 0 {
            if is_true_color(self.fg) {
                let (r, g, b) = decode_true_color(self.fg);
                let _ = write!(out, ";38;2;{};{};{}", r, g, b);
            } else if self.fg > 37 {
                let _ = write!(out, ";38;5;{}", self.fg - 30);
            } else {
                let _ = write!(out, ";{}", self.fg);
            }
        }

        if self.bg != 0 {
            if is_true_color(self.bg) {
                let (r, g, b) = decode_true_color(self.bg);
                let _ = write!(out, ";48;2;{};{};{}", r, g, b);
            } else if self.bg > 47 {
                let _ = write!(out, ";48;5;{}", self.bg - 40);
            } else {
                let _ = write!(out, ";{}", self.bg);
            }
        }

        out.push('m');
        out
    }
}

/// Frame builder for constructing ANSI escape sequences (equivalent to mosh's FrameState).
///
/// Cursor coordinates of -1 mean "unknown" to enable CUP optimizations.
struct FrameBuilder {
    output: Vec<u8>,
    cursor_x: i32,
    cursor_y: i32,
    current_rendition: Rendition,
    cursor_visible: bool,
}

impl FrameBuilder {
    fn new() -> Self {
        Self {
            output: Vec::with_capacity(4096),
            cursor_x: 0,
            cursor_y: 0,
            current_rendition: Rendition::default(),
            cursor_visible: false,
        }
    }

    fn append(&mut self, byte: u8) {
        self.output.push(byte);
    }

    fn append_bytes(&mut self, bytes: &[u8]) {
        self.output.extend_from_slice(bytes);
    }

    fn append_str(&mut self, s: &str) {
        self.output.extend_from_slice(s.as_bytes());
    }

    fn append_repeat(&mut self, byte: u8, count: u16) {
        self.output
            .extend(std::iter::repeat(byte).take(count as usize));
    }

    /// Move cursor with simple optimizations (CR/LF/backspace) when previous
    /// position is known.
    fn append_move(&mut self, row: u16, col: u16) {
        let last_x = self.cursor_x;
        let last_y = self.cursor_y;
        self.cursor_x = col as i32;
        self.cursor_y = row as i32;

        if last_x != -1 && last_y != -1 {
            if col == 0 && row as i32 - last_y >= 0 && row as i32 - last_y < 5 {
                if last_x != 0 {
                    self.append(b'\r');
                }
                self.append_repeat(b'\n', (row as i32 - last_y) as u16);
                return;
            }
            if row as i32 == last_y && col as i32 - last_x < 0 && (last_x - col as i32) < 5 {
                self.append_repeat(b'\x08', (last_x - col as i32) as u16);
                return;
            }
        }

        self.append_str(&format!("\x1b[{};{}H", row + 1, col + 1));
    }

    /// Move cursor, hiding it first if needed.
    fn append_silent_move(&mut self, row: u16, col: u16) {
        if self.cursor_x == col as i32 && self.cursor_y == row as i32 {
            return;
        }
        if self.cursor_visible {
            self.append_bytes(b"\x1b[?25l");
            self.cursor_visible = false;
        }
        self.append_move(row, col);
    }

    fn update_rendition(&mut self, target: Rendition, force: bool) {
        if force || self.current_rendition != target {
            self.append_str(&target.sgr());
            self.current_rendition = target;
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        self.output
    }
}

/// Mosh-style display renderer that generates ANSI escape sequences from terminal diffs.
pub struct Display {
    last_state: Option<TerminalState>,
    caps: TerminfoCaps,
}

impl Display {
    /// Create a new Display renderer.
    pub fn new() -> Self {
        Self {
            last_state: None,
            caps: TerminfoCaps::detect(),
        }
    }

    /// Enter alternate screen + application cursor mode (matches mosh's Display::open()).
    pub fn open(&self) -> String {
        let mut s = String::new();
        if let Some(ref smcup) = self.caps.smcup {
            s.push_str(smcup);
        }
        s.push_str("\x1b[?1h");
        s
    }

    /// Leave alternate screen (matches mosh's Display::close()).
    pub fn close(&self) -> String {
        let mut s = String::from(
            "\x1b[?1l\x1b[0m\x1b[?25h\x1b[?1003l\x1b[?1002l\x1b[?1001l\x1b[?1000l\x1b[?1015l\x1b[?1006l\x1b[?1005l",
        );
        if let Some(ref rmcup) = self.caps.rmcup {
            s.push_str(rmcup);
        }
        s
    }

    /// Reset the renderer (forces full state send on next frame).
    pub fn reset(&mut self) {
        self.last_state = None;
    }

    /// Generate ANSI escape sequences to transform last state into new state.
    ///
    /// This mirrors mosh's Display::new_frame().
    pub fn new_frame(&mut self, new_state: &TerminalState) -> Vec<u8> {
        let cols = new_state.cols();
        let rows = new_state.rows();
        let mut frame = FrameBuilder::new();

        // Track prior state for size/alt transitions.
        let size_matches = self
            .last_state
            .as_ref()
            .map_or(false, |last| last.cols() == cols && last.rows() == rows);
        let initialized = self.last_state.is_some() && size_matches;

        if !initialized {
            frame.append_bytes(b"\x1b[r");
            frame.append_bytes(b"\x1b[0m\x1b[H\x1b[2J");
            frame.cursor_x = 0;
            frame.cursor_y = 0;
            frame.current_rendition = Rendition::default();
            frame.cursor_visible = false;
            frame.append_bytes(b"\x1b[?25l");
        } else if let Some(ref last) = self.last_state {
            frame.cursor_x = last.cursor.col as i32;
            frame.cursor_y = last.cursor.row as i32;
            frame.cursor_visible = last.cursor.visible;
            frame.current_rendition = Rendition::from_state_defaults(last);
        }

        // Alternate screen transitions (enter/exit) based on state.
        let last_alt = self
            .last_state
            .as_ref()
            .map(|s| s.alternate_active)
            .unwrap_or(false);
        if new_state.alternate_active != last_alt {
            if new_state.alternate_active {
                if let Some(ref smcup) = self.caps.smcup {
                    frame.append_str(smcup);
                } else {
                    frame.append_bytes(b"\x1b[?1049h");
                }
            } else if let Some(ref rmcup) = self.caps.rmcup {
                frame.append_str(rmcup);
            } else {
                frame.append_bytes(b"\x1b[?1049l");
            }
            // After screen switch, cursor position is unknown.
            frame.cursor_x = -1;
            frame.cursor_y = -1;
        }

        // Title/icon name (OSC 0/1/2)
        if self.caps.has_title {
            if let Some(ref title) = new_state.title {
                self.append_osc_title(&mut frame.output, title);
            }
        }

        // Clipboard (OSC 52)
        if let Some((ref selection, ref content)) = new_state.clipboard {
            self.append_osc_clipboard(&mut frame.output, selection, content);
        }

        // Mouse reporting mode changes
        let last_mouse_mode = self
            .last_state
            .as_ref()
            .map(|s| s.mouse_reporting_mode)
            .unwrap_or(MouseReportingMode::None);
        if !initialized || new_state.mouse_reporting_mode != last_mouse_mode {
            match new_state.mouse_reporting_mode.as_dec_private() {
                Some(code) => frame.append_str(&format!("\x1b[?{}h", code)),
                None => {
                    if let Some(code) = last_mouse_mode.as_dec_private() {
                        frame.append_str(&format!("\x1b[?{}l", code));
                    }
                }
            }
        }

        // Mouse focus events (1004)
        let last_focus = self
            .last_state
            .as_ref()
            .map(|s| s.mouse_focus_event)
            .unwrap_or(false);
        if !initialized || new_state.mouse_focus_event != last_focus {
            frame.append_str(if new_state.mouse_focus_event {
                "\x1b[?1004h"
            } else {
                "\x1b[?1004l"
            });
        }

        // Mouse alternate scroll (1007)
        let last_alt_scroll = self
            .last_state
            .as_ref()
            .map(|s| s.mouse_alternate_scroll)
            .unwrap_or(false);
        if !initialized || new_state.mouse_alternate_scroll != last_alt_scroll {
            frame.append_str(if new_state.mouse_alternate_scroll {
                "\x1b[?1007h"
            } else {
                "\x1b[?1007l"
            });
        }

        // Mouse encoding mode (1005/1006/1015)
        let last_mouse_encoding = self
            .last_state
            .as_ref()
            .map(|s| s.mouse_encoding_mode)
            .unwrap_or(MouseEncodingMode::Default);
        if !initialized || new_state.mouse_encoding_mode != last_mouse_encoding {
            match new_state.mouse_encoding_mode.as_dec_private() {
                Some(code) => frame.append_str(&format!("\x1b[?{}h", code)),
                None => {
                    if let Some(code) = last_mouse_encoding.as_dec_private() {
                        frame.append_str(&format!("\x1b[?{}l", code));
                    }
                }
            }
        }

        // Render rows, diffing against last frame when available.
        for row in 0..rows {
            let new_row = new_state.screen().row(row);
            let old_row = if initialized {
                self.last_state
                    .as_ref()
                    .and_then(|last| last.screen().row(row))
            } else {
                None
            };
            self.put_row(&mut frame, initialized, row, new_row, old_row, cols);
        }

        // Cursor position.
        let target_cursor = (new_state.cursor.col, new_state.cursor.row);
        frame.append_move(target_cursor.1, target_cursor.0);

        // Cursor visibility.
        if new_state.cursor.visible {
            frame.append_bytes(b"\x1b[?25h");
            frame.cursor_visible = true;
        } else {
            frame.append_bytes(b"\x1b[?25l");
            frame.cursor_visible = false;
        }

        // Reset rendition tracking to match the new state's defaults.
        frame.update_rendition(Rendition::from_state_defaults(new_state), true);

        self.last_state = Some(new_state.clone());
        frame.into_bytes()
    }

    /// Update a single row with minimal escape sequences (mosh's put_row()).
    fn put_row(
        &self,
        frame: &mut FrameBuilder,
        initialized: bool,
        row_idx: u16,
        new_row: Option<&[Cell]>,
        old_row: Option<&[Cell]>,
        cols: u16,
    ) {
        let new_cells = match new_row {
            Some(cells) => cells,
            None => return,
        };
        let old_cells = old_row.unwrap_or(&[]);

        if initialized && !old_cells.is_empty() && new_cells == old_cells {
            return;
        }

        // Ensure cursor is at start of the row before emitting row content.
        frame.append_silent_move(row_idx, 0);

        let row_width = cols as usize;
        let mut frame_x: usize = 0;
        let mut clear_count: usize = 0;
        let mut blank_rendition = Rendition::default();
        let default_cell = Cell::default();

        while frame_x < row_width {
            let cell = new_cells.get(frame_x).unwrap_or(&default_cell);

            if initialized
                && clear_count == 0
                && old_cells.get(frame_x).map(|c| c == cell).unwrap_or(false)
            {
                frame_x += 1;
                continue;
            }

            if cell.is_empty() {
                if clear_count == 0 {
                    blank_rendition = Rendition::from_cell(cell);
                }
                if Rendition::from_cell(cell) == blank_rendition {
                    clear_count += 1;
                    frame_x += 1;
                    continue;
                }
            }

            if clear_count > 0 {
                let blank_start_col = frame_x - clear_count;
                frame.append_silent_move(row_idx, blank_start_col as u16);
                frame.update_rendition(blank_rendition, false);

                let can_use_erase =
                    self.caps.has_bce || frame.current_rendition == Rendition::default();
                if can_use_erase && self.caps.has_ech && clear_count > 4 {
                    frame.append_str(&format!("\x1b[{}X", clear_count));
                } else {
                    frame.append_repeat(b' ', clear_count as u16);
                    frame.cursor_x = (blank_start_col + clear_count) as i32;
                }
                clear_count = 0;

                if cell.is_empty() {
                    blank_rendition = Rendition::from_cell(cell);
                    clear_count = 1;
                    frame_x += 1;
                    continue;
                }
            }

            frame.append_silent_move(row_idx, frame_x as u16);
            frame.update_rendition(Rendition::from_cell(cell), false);

            let mut buf = [0u8; 4];
            let encoded = cell.ch.encode_utf8(&mut buf);
            frame.append_bytes(encoded.as_bytes());
            frame_x += 1;
            frame.cursor_x += 1;
        }

        if clear_count > 0 {
            let blank_start_col = frame_x - clear_count;
            frame.append_silent_move(row_idx, blank_start_col as u16);
            frame.update_rendition(blank_rendition, false);

            let can_use_erase =
                self.caps.has_bce || frame.current_rendition == Rendition::default();
            if can_use_erase {
                frame.append_bytes(b"\x1b[K");
            } else {
                frame.append_repeat(b' ', clear_count as u16);
                frame.cursor_x = (blank_start_col + clear_count) as i32;
            }
        }
    }

    /// Append OSC title sequence.
    fn append_osc_title(&self, output: &mut Vec<u8>, title: &str) {
        output.extend_from_slice(b"\x1b]0;");
        output.extend_from_slice(title.as_bytes());
        output.push(0x07); // BEL
    }

    /// Append OSC clipboard sequence.
    fn append_osc_clipboard(&self, output: &mut Vec<u8>, selection: &str, content: &str) {
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

// Helper functions -----------------------------------------------------------

fn color_to_code(color: Color, foreground: bool) -> u32 {
    match color {
        Color::Default => 0,
        Color::Indexed(idx) => {
            let base = if foreground { 30 } else { 40 };
            base + idx as u32
        }
        Color::Rgb(r, g, b) => 0x1000000 | ((r as u32) << 16) | ((g as u32) << 8) | b as u32,
    }
}

fn is_true_color(color: u32) -> bool {
    (color & 0x1000000) != 0
}

fn decode_true_color(color: u32) -> (u32, u32, u32) {
    ((color >> 16) & 0xff, (color >> 8) & 0xff, color & 0xff)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terminal::state::CellAttrs;

    #[test]
    fn test_display_empty_diff() {
        let mut display = Display::new();
        let state = TerminalState::new(80, 24);
        let output = display.new_frame(&state);

        assert!(!output.is_empty());
        assert!(output.windows(4).any(|w| w == b"\x1b[2J")); // Clear screen
    }

    #[test]
    fn test_display_cursor_only() {
        let mut display = Display::new();
        let mut state1 = TerminalState::new(80, 24);
        let _ = display.new_frame(&state1);

        state1.cursor.col = 10;
        state1.cursor.row = 5;
        let output = display.new_frame(&state1);

        let output_str = String::from_utf8_lossy(&output);
        assert!(
            output_str.contains("\x1b[6;11H") || output_str.contains("\r\n"),
            "should move cursor"
        );
    }

    #[test]
    fn test_display_single_char() {
        let mut display = Display::new();
        let mut state = TerminalState::new(80, 24);
        let _ = display.new_frame(&state);

        state.screen_mut().set(5, 10, Cell::new('X'));
        let output = display.new_frame(&state);

        assert!(output.contains(&b'X'));
    }

    #[test]
    fn test_display_color_change() {
        let mut display = Display::new();
        let state = TerminalState::new(80, 24);
        let _ = display.new_frame(&state);

        let mut state2 = state.clone();
        state2.screen_mut().set(
            0,
            0,
            Cell::with_style(
                'R',
                Color::Rgb(255, 0, 0),
                Color::Default,
                CellAttrs::default(),
            ),
        );
        let output = display.new_frame(&state2);

        let output_str = String::from_utf8_lossy(&output);
        assert!(
            output_str.contains("38;2;255;0;0"),
            "should contain RGB foreground"
        );
    }

    #[test]
    fn test_display_title_change() {
        let mut display = Display::new();
        let state = TerminalState::new(80, 24);
        let _ = display.new_frame(&state);

        let mut state2 = state.clone();
        state2.title = Some("Test Title".to_string());
        let output = display.new_frame(&state2);

        assert!(output.windows(4).any(|w| w == b"\x1b]0;"));
        assert!(output.windows(10).any(|w| w == b"Test Title"));
    }
}
