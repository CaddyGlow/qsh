//! Mosh-style terminal renderer.
//!
//! Renders terminal state to stdout with differential updates.
//! Based on mosh's Display::new_frame() approach:
//! 1. Start with empty local framebuffer
//! 2. Get server state, apply overlays
//! 3. Diff against local state
//! 4. Write diff to terminal
//! 5. Update local state

use std::fmt::Write;

use qsh_core::terminal::{Cell, CellAttrs, Color, Screen, TerminalState};

use crate::overlay::PredictionOverlay;
use crate::prediction::PredictedStyle;

/// Mosh-style renderer that maintains local framebuffer state.
pub struct StateRenderer {
    /// What we believe is currently on the terminal screen.
    local_framebuffer: Option<TerminalState>,
    /// Current cursor position we've drawn.
    cursor_x: i32,
    cursor_y: i32,
    /// Current renditions we've set.
    current_attrs: CellAttrs,
    current_fg: Color,
    current_bg: Color,
    /// Last title we set on the terminal (OSC 0).
    current_title: Option<String>,
    /// Last CWD we set on the terminal (OSC 7).
    current_cwd: Option<String>,
    /// Last clipboard sent (OSC 52). Track to avoid re-sending same data.
    last_clipboard: Option<(String, String)>,
}

impl StateRenderer {
    /// Create a new renderer.
    pub fn new() -> Self {
        Self {
            local_framebuffer: None,
            cursor_x: -1,
            cursor_y: -1,
            current_attrs: CellAttrs::default(),
            current_fg: Color::Default,
            current_bg: Color::Default,
            current_title: None,
            current_cwd: None,
            last_clipboard: None,
        }
    }

    /// Render the terminal state with predictions composited.
    ///
    /// This is the main entry point, equivalent to mosh's output_new_frame().
    pub fn render(
        &mut self,
        server_state: &TerminalState,
        predictions: &PredictionOverlay,
    ) -> String {
        // Create a copy of server state and apply overlays
        let mut display_state = server_state.clone();
        self.apply_overlays(&mut display_state, predictions);

        // Generate diff output
        let output = self.new_frame(&display_state);

        // Update local framebuffer to match what's now on screen
        self.local_framebuffer = Some(display_state);

        output
    }

    /// Apply prediction overlays to the framebuffer.
    fn apply_overlays(&self, state: &mut TerminalState, predictions: &PredictionOverlay) {
        let screen = state.screen_mut();
        for pred in predictions.iter() {
            if pred.col < screen.cols() && pred.row < screen.rows() {
                if let Some(cell) = screen.get_mut(pred.col, pred.row) {
                    // Set the predicted character
                    cell.ch = pred.char;
                    // Apply prediction styling based on style
                    match pred.style {
                        PredictedStyle::Underline => cell.attrs.underline = true,
                        PredictedStyle::Dim => cell.attrs.dim = true,
                        PredictedStyle::Normal => {} // No styling for fast connections
                    }
                }
            }
        }
    }

    /// Generate ANSI escape sequences to update terminal from local state to new state.
    /// Equivalent to mosh's Display::new_frame().
    fn new_frame(&mut self, new_state: &TerminalState) -> String {
        let mut output = String::new();
        let screen = new_state.screen();
        let (cols, rows) = (screen.cols(), screen.rows());

        // Check if this is first frame or size changed
        let initialized = self.local_framebuffer.as_ref().map_or(false, |local| {
            local.screen().cols() == cols && local.screen().rows() == rows
        });

        if !initialized {
            // First frame or size change: reset scrolling region, clear screen
            output.push_str("\x1b[r"); // Reset scrolling region
            output.push_str("\x1b[0m\x1b[H\x1b[2J"); // Reset attrs, home, clear
            self.cursor_x = 0;
            self.cursor_y = 0;
            self.current_attrs = CellAttrs::default();
            self.current_fg = Color::Default;
            self.current_bg = Color::Default;

            // Hide cursor during render
            output.push_str("\x1b[?25l");
        }

        // Render each row - take ownership of old state temporarily
        let old_state = self.local_framebuffer.take();
        for row in 0..rows {
            self.put_row(
                &mut output,
                screen,
                old_state.as_ref().map(|s| s.screen()),
                row,
                cols,
                initialized,
            );
        }
        self.local_framebuffer = old_state;

        // Move cursor to final position
        let target_row = new_state.cursor.row as i32;
        let target_col = new_state.cursor.col as i32;
        if !initialized || self.cursor_x != target_col || self.cursor_y != target_row {
            self.append_move(&mut output, target_row, target_col);
        }

        // Show/hide cursor based on state
        if new_state.cursor.visible {
            output.push_str("\x1b[?25h");
        } else {
            output.push_str("\x1b[?25l");
        }

        // Emit title OSC if changed
        if new_state.title != self.current_title {
            if let Some(ref title) = new_state.title {
                // OSC 0 sets both icon name and window title
                let _ = write!(output, "\x1b]0;{}\x07", title);
            } else {
                // Clear title by setting empty string
                output.push_str("\x1b]0;\x07");
            }
            self.current_title = new_state.title.clone();
        }

        // Emit CWD OSC 7 if changed
        if new_state.cwd != self.current_cwd {
            if let Some(ref cwd) = new_state.cwd {
                // OSC 7 sets current working directory
                let _ = write!(output, "\x1b]7;{}\x07", cwd);
            }
            // Note: There's no standard way to "clear" CWD, so we only emit when set
            self.current_cwd = new_state.cwd.clone();
        }

        // Emit clipboard OSC 52 if changed
        if new_state.clipboard != self.last_clipboard {
            if let Some((ref selection, ref data)) = new_state.clipboard {
                // OSC 52 ; selection ; base64-data ST
                let _ = write!(output, "\x1b]52;{};{}\x07", selection, data);
            }
            self.last_clipboard = new_state.clipboard.clone();
        }

        // Emit any pending OSC sequences verbatim (already includes ESC ] and terminator)
        for osc in &new_state.pending_osc {
            output.push_str(osc);
        }

        output
    }

    /// Render a single row, only outputting changed cells.
    fn put_row(
        &mut self,
        output: &mut String,
        screen: &Screen,
        old_screen: Option<&Screen>,
        row: u16,
        cols: u16,
        initialized: bool,
    ) {
        for col in 0..cols {
            let cell = screen.get(col, row).cloned().unwrap_or_default();
            let old_cell = old_screen.and_then(|s| s.get(col, row));

            // Skip if cell unchanged
            if initialized {
                if let Some(old) = old_cell {
                    if *old == cell {
                        continue;
                    }
                }
            }

            // Move cursor if needed
            self.append_silent_move(output, row as i32, col as i32);

            // Update renditions if needed
            self.update_rendition(output, &cell);

            // Write the character
            output.push(cell.ch);
            self.cursor_x = col as i32 + 1;

            // Handle cursor wrap at end of line
            if self.cursor_x >= cols as i32 {
                self.cursor_x = -1; // Unknown position after potential wrap
            }
        }
    }

    /// Move cursor, hiding it first if visible.
    fn append_silent_move(&mut self, output: &mut String, row: i32, col: i32) {
        if self.cursor_x == col && self.cursor_y == row {
            return;
        }
        self.append_move(output, row, col);
    }

    /// Move cursor to position using most efficient escape sequence.
    fn append_move(&mut self, output: &mut String, row: i32, col: i32) {
        let last_x = self.cursor_x;
        let last_y = self.cursor_y;
        self.cursor_x = col;
        self.cursor_y = row;

        // Optimize common cases if cursor position is known
        if last_x != -1 && last_y != -1 {
            // CR + LF for start of next rows
            if col == 0 && row >= last_y && row - last_y < 5 {
                if last_x != 0 {
                    output.push('\r');
                }
                for _ in 0..(row - last_y) {
                    output.push('\n');
                }
                return;
            }
            // Backspaces for small leftward moves on same row
            if row == last_y && col < last_x && last_x - col < 5 {
                for _ in 0..(last_x - col) {
                    output.push('\x08');
                }
                return;
            }
        }

        // Default: use CUP (cursor position)
        let _ = write!(output, "\x1b[{};{}H", row + 1, col + 1);
    }

    /// Update terminal renditions to match cell.
    fn update_rendition(&mut self, output: &mut String, cell: &Cell) {
        // Check if we need to change anything
        if self.current_attrs == cell.attrs
            && self.current_fg == cell.fg
            && self.current_bg == cell.bg
        {
            return;
        }

        // Build SGR sequence
        let mut params = Vec::new();

        // Reset if attributes changed significantly
        if self.current_attrs != cell.attrs {
            params.push(0); // Reset all
            self.current_attrs = CellAttrs::default();
            self.current_fg = Color::Default;
            self.current_bg = Color::Default;
        }

        // Add attributes
        if cell.attrs.bold && !self.current_attrs.bold {
            params.push(1);
        }
        if cell.attrs.dim && !self.current_attrs.dim {
            params.push(2);
        }
        if cell.attrs.italic && !self.current_attrs.italic {
            params.push(3);
        }
        if cell.attrs.underline && !self.current_attrs.underline {
            params.push(4);
        }
        if cell.attrs.blink && !self.current_attrs.blink {
            params.push(5);
        }
        if cell.attrs.reverse && !self.current_attrs.reverse {
            params.push(7);
        }
        if cell.attrs.hidden && !self.current_attrs.hidden {
            params.push(8);
        }
        if cell.attrs.strikethrough && !self.current_attrs.strikethrough {
            params.push(9);
        }

        // Write SGR if we have params
        if !params.is_empty() {
            output.push_str("\x1b[");
            for (i, p) in params.iter().enumerate() {
                if i > 0 {
                    output.push(';');
                }
                let _ = write!(output, "{}", p);
            }
            output.push('m');
        }

        // Foreground color
        if self.current_fg != cell.fg {
            self.write_fg_color(output, cell.fg);
            self.current_fg = cell.fg;
        }

        // Background color
        if self.current_bg != cell.bg {
            self.write_bg_color(output, cell.bg);
            self.current_bg = cell.bg;
        }

        self.current_attrs = cell.attrs;
    }

    fn write_fg_color(&self, output: &mut String, color: Color) {
        match color {
            Color::Default => output.push_str("\x1b[39m"),
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
    }

    fn write_bg_color(&self, output: &mut String, color: Color) {
        match color {
            Color::Default => output.push_str("\x1b[49m"),
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
    }

    /// Force a full redraw on next render.
    pub fn invalidate(&mut self) {
        self.local_framebuffer = None;
        self.cursor_x = -1;
        self.cursor_y = -1;
        self.current_title = None;
        self.current_cwd = None;
        self.last_clipboard = None;
    }
}

impl Default for StateRenderer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::overlay::PredictionOverlay;

    #[test]
    fn renders_title_osc_on_change() {
        let mut renderer = StateRenderer::new();
        let overlay = PredictionOverlay::new();

        // Initial state with no title - no OSC emitted (None == None)
        let state = TerminalState::new(80, 24);
        let output = renderer.render(&state, &overlay);
        assert!(
            !output.contains("\x1b]0;"),
            "should not emit title OSC when both are None"
        );

        // Set a title
        let mut state_with_title = TerminalState::new(80, 24);
        state_with_title.title = Some("My Title".to_string());
        let output = renderer.render(&state_with_title, &overlay);

        assert!(
            output.contains("\x1b]0;My Title\x07"),
            "should emit title OSC: {:?}",
            output
        );

        // Render again with same title - should not emit
        let output = renderer.render(&state_with_title, &overlay);
        assert!(
            !output.contains("\x1b]0;"),
            "should not re-emit unchanged title"
        );
    }

    #[test]
    fn clears_title_when_removed() {
        let mut renderer = StateRenderer::new();
        let overlay = PredictionOverlay::new();

        // Set initial title
        let mut state = TerminalState::new(80, 24);
        state.title = Some("Title".to_string());
        renderer.render(&state, &overlay);

        // Remove title
        state.title = None;
        let output = renderer.render(&state, &overlay);

        assert!(
            output.contains("\x1b]0;\x07"),
            "should emit empty title OSC to clear"
        );
    }

    #[test]
    fn invalidate_resets_title_tracking() {
        let mut renderer = StateRenderer::new();
        let overlay = PredictionOverlay::new();

        // Set a title
        let mut state = TerminalState::new(80, 24);
        state.title = Some("Title".to_string());
        renderer.render(&state, &overlay);

        // Invalidate
        renderer.invalidate();

        // Same title should be re-emitted
        let output = renderer.render(&state, &overlay);
        assert!(
            output.contains("\x1b]0;Title\x07"),
            "should re-emit title after invalidate"
        );
    }

    #[test]
    fn renders_cwd_osc7_on_change() {
        let mut renderer = StateRenderer::new();
        let overlay = PredictionOverlay::new();

        // Initial state with no CWD - no OSC emitted
        let state = TerminalState::new(80, 24);
        let output = renderer.render(&state, &overlay);
        assert!(
            !output.contains("\x1b]7;"),
            "should not emit CWD OSC when None"
        );

        // Set a CWD
        let mut state_with_cwd = TerminalState::new(80, 24);
        state_with_cwd.cwd = Some("file://localhost/home/user".to_string());
        let output = renderer.render(&state_with_cwd, &overlay);

        assert!(
            output.contains("\x1b]7;file://localhost/home/user\x07"),
            "should emit CWD OSC: {:?}",
            output
        );

        // Render again with same CWD - should not emit
        let output = renderer.render(&state_with_cwd, &overlay);
        assert!(
            !output.contains("\x1b]7;"),
            "should not re-emit unchanged CWD"
        );
    }

    #[test]
    fn renders_clipboard_osc52_on_change() {
        let mut renderer = StateRenderer::new();
        let overlay = PredictionOverlay::new();

        // Initial state with no clipboard - no OSC emitted
        let state = TerminalState::new(80, 24);
        let output = renderer.render(&state, &overlay);
        assert!(
            !output.contains("\x1b]52;"),
            "should not emit clipboard OSC when None"
        );

        // Set clipboard
        let mut state_with_clipboard = TerminalState::new(80, 24);
        state_with_clipboard.clipboard = Some(("c".to_string(), "SGVsbG8=".to_string()));
        let output = renderer.render(&state_with_clipboard, &overlay);

        assert!(
            output.contains("\x1b]52;c;SGVsbG8=\x07"),
            "should emit clipboard OSC: {:?}",
            output
        );

        // Render again with same clipboard - should not re-emit
        let output = renderer.render(&state_with_clipboard, &overlay);
        assert!(
            !output.contains("\x1b]52;"),
            "should not re-emit unchanged clipboard"
        );
    }

    #[test]
    fn renders_pending_osc_verbatim() {
        let mut renderer = StateRenderer::new();
        let overlay = PredictionOverlay::new();

        // State with pending OSC (e.g., hyperlink)
        let mut state = TerminalState::new(80, 24);
        state
            .pending_osc
            .push("\x1b]8;;https://example.com\x07".to_string());
        let output = renderer.render(&state, &overlay);

        assert!(
            output.contains("\x1b]8;;https://example.com\x07"),
            "should emit pending OSC verbatim: {:?}",
            output
        );
    }
}
