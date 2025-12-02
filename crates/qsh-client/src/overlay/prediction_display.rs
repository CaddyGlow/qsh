//! Prediction display overlay.
//!
//! Renders predicted characters with visual distinction (underline/dim).

use crate::prediction::{PredictedStyle, Prediction};

/// Overlay for displaying predicted characters.
#[derive(Debug, Default)]
pub struct PredictionOverlay {
    /// Currently displayed predictions.
    predictions: Vec<PredictionDisplay>,
}

/// A prediction ready for display.
#[derive(Debug, Clone)]
pub struct PredictionDisplay {
    /// Column position.
    pub col: u16,
    /// Row position.
    pub row: u16,
    /// Character to display.
    pub char: char,
    /// Sequence number for tracking.
    pub sequence: u64,
    /// Display style.
    pub style: PredictedStyle,
}

impl PredictionOverlay {
    /// Create a new empty overlay.
    pub fn new() -> Self {
        Self {
            predictions: Vec::new(),
        }
    }

    /// Add a prediction to the overlay.
    pub fn add(&mut self, prediction: &Prediction, style: PredictedStyle) {
        self.predictions.push(PredictionDisplay {
            col: prediction.col,
            row: prediction.row,
            char: prediction.char,
            sequence: prediction.sequence,
            style,
        });
    }

    /// Clear confirmed predictions up to the given sequence.
    pub fn clear_confirmed(&mut self, up_to_seq: u64) {
        self.predictions.retain(|p| p.sequence > up_to_seq);
    }

    /// Clear all predictions (on misprediction or state reset).
    pub fn clear_all(&mut self) {
        self.predictions.clear();
    }

    /// Get the number of pending predictions.
    pub fn count(&self) -> usize {
        self.predictions.len()
    }

    /// Check if overlay is empty.
    pub fn is_empty(&self) -> bool {
        self.predictions.is_empty()
    }

    /// Render the overlay as ANSI escape sequences.
    ///
    /// Returns escape sequences that:
    /// 1. Save cursor position
    /// 2. Move to each prediction position and render with style
    /// 3. Restore cursor position
    pub fn render(&self) -> String {
        if self.predictions.is_empty() {
            return String::new();
        }

        let mut output = String::new();

        // Save cursor position
        output.push_str("\x1b[s");

        for pred in &self.predictions {
            // Move to position (1-indexed for ANSI)
            output.push_str(&format!(
                "\x1b[{};{}H",
                pred.row + 1,
                pred.col + 1
            ));

            // Apply style
            match pred.style {
                PredictedStyle::Underline => {
                    output.push_str("\x1b[4m"); // Underline
                }
                PredictedStyle::Dim => {
                    output.push_str("\x1b[2m"); // Dim
                }
            }

            // Print character
            output.push(pred.char);

            // Reset style
            output.push_str("\x1b[0m");
        }

        // Restore cursor position
        output.push_str("\x1b[u");

        output
    }

    /// Render restoration sequence to clear predictions from display.
    ///
    /// This renders the original characters at prediction positions,
    /// effectively "removing" the prediction styling.
    pub fn render_clear(&self, get_original: impl Fn(u16, u16) -> char) -> String {
        if self.predictions.is_empty() {
            return String::new();
        }

        let mut output = String::new();

        // Save cursor position
        output.push_str("\x1b[s");

        for pred in &self.predictions {
            // Move to position
            output.push_str(&format!(
                "\x1b[{};{}H",
                pred.row + 1,
                pred.col + 1
            ));

            // Print original character (no special styling)
            let original = get_original(pred.col, pred.row);
            output.push(original);
        }

        // Restore cursor position
        output.push_str("\x1b[u");

        output
    }

    /// Get iterator over predictions.
    pub fn iter(&self) -> impl Iterator<Item = &PredictionDisplay> {
        self.predictions.iter()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn make_prediction(seq: u64, ch: char, col: u16, row: u16) -> Prediction {
        Prediction {
            sequence: seq,
            char: ch,
            col,
            row,
            timestamp: Instant::now(),
        }
    }

    #[test]
    fn overlay_new_is_empty() {
        let overlay = PredictionOverlay::new();
        assert!(overlay.is_empty());
        assert_eq!(overlay.count(), 0);
    }

    #[test]
    fn overlay_add_prediction() {
        let mut overlay = PredictionOverlay::new();
        let pred = make_prediction(0, 'a', 5, 10);

        overlay.add(&pred, PredictedStyle::Underline);

        assert_eq!(overlay.count(), 1);
        assert!(!overlay.is_empty());

        let displayed: Vec<_> = overlay.iter().collect();
        assert_eq!(displayed[0].char, 'a');
        assert_eq!(displayed[0].col, 5);
        assert_eq!(displayed[0].row, 10);
    }

    #[test]
    fn overlay_clear_confirmed() {
        let mut overlay = PredictionOverlay::new();

        overlay.add(&make_prediction(0, 'a', 0, 0), PredictedStyle::Underline);
        overlay.add(&make_prediction(1, 'b', 1, 0), PredictedStyle::Underline);
        overlay.add(&make_prediction(2, 'c', 2, 0), PredictedStyle::Underline);

        assert_eq!(overlay.count(), 3);

        overlay.clear_confirmed(1);
        assert_eq!(overlay.count(), 1);

        let remaining: Vec<_> = overlay.iter().collect();
        assert_eq!(remaining[0].char, 'c');
    }

    #[test]
    fn overlay_clear_all() {
        let mut overlay = PredictionOverlay::new();

        overlay.add(&make_prediction(0, 'a', 0, 0), PredictedStyle::Underline);
        overlay.add(&make_prediction(1, 'b', 1, 0), PredictedStyle::Dim);

        assert_eq!(overlay.count(), 2);

        overlay.clear_all();
        assert!(overlay.is_empty());
    }

    #[test]
    fn overlay_render_empty() {
        let overlay = PredictionOverlay::new();
        assert!(overlay.render().is_empty());
    }

    #[test]
    fn overlay_render_underline() {
        let mut overlay = PredictionOverlay::new();
        overlay.add(&make_prediction(0, 'X', 5, 10), PredictedStyle::Underline);

        let rendered = overlay.render();

        // Should contain cursor save, position, underline SGR, char, reset, cursor restore
        assert!(rendered.contains("\x1b[s")); // Save
        assert!(rendered.contains("\x1b[11;6H")); // Position (1-indexed)
        assert!(rendered.contains("\x1b[4m")); // Underline
        assert!(rendered.contains('X'));
        assert!(rendered.contains("\x1b[0m")); // Reset
        assert!(rendered.contains("\x1b[u")); // Restore
    }

    #[test]
    fn overlay_render_dim() {
        let mut overlay = PredictionOverlay::new();
        overlay.add(&make_prediction(0, 'Y', 0, 0), PredictedStyle::Dim);

        let rendered = overlay.render();

        assert!(rendered.contains("\x1b[2m")); // Dim
        assert!(rendered.contains('Y'));
    }

    #[test]
    fn overlay_render_multiple() {
        let mut overlay = PredictionOverlay::new();
        overlay.add(&make_prediction(0, 'A', 0, 0), PredictedStyle::Underline);
        overlay.add(&make_prediction(1, 'B', 1, 0), PredictedStyle::Dim);

        let rendered = overlay.render();

        assert!(rendered.contains('A'));
        assert!(rendered.contains('B'));
        assert!(rendered.contains("\x1b[4m")); // Underline
        assert!(rendered.contains("\x1b[2m")); // Dim
    }

    #[test]
    fn overlay_render_clear() {
        let mut overlay = PredictionOverlay::new();
        overlay.add(&make_prediction(0, 'X', 5, 10), PredictedStyle::Underline);

        // Provide a function that returns original character
        let rendered = overlay.render_clear(|_, _| ' ');

        // Should move to position and print original char
        assert!(rendered.contains("\x1b[s")); // Save
        assert!(rendered.contains("\x1b[11;6H")); // Position
        assert!(rendered.contains(' ')); // Original char
        assert!(rendered.contains("\x1b[u")); // Restore
    }
}
