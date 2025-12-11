//! Cursor position tracking and character-by-character prediction.
//!
//! Handles cursor movement and cell predictions based on user input bytes.

use std::collections::{HashMap, VecDeque};
use std::time::Instant;

use super::state::{PredictedStyle, PredictionState};
use super::types::{CellPrediction, PredictedEcho, Prediction};

/// Cursor and cell prediction tracking for the prediction engine.
#[derive(Debug)]
pub struct CursorPredictor {
    /// Predicted cursor position (col, row).
    pub predicted_cursor: Option<(u16, u16)>,
    /// Cell predictions by position.
    pub cell_predictions: HashMap<(u16, u16), CellPrediction>,
    /// Current prediction epoch (increments on each new_user_byte batch).
    pub prediction_epoch: u64,
    /// Last epoch that was confirmed.
    pub confirmed_epoch: u64,
}

impl Default for CursorPredictor {
    fn default() -> Self {
        Self::new()
    }
}

impl CursorPredictor {
    /// Create a new cursor predictor.
    pub fn new() -> Self {
        Self {
            predicted_cursor: None,
            cell_predictions: HashMap::new(),
            prediction_epoch: 0,
            confirmed_epoch: 0,
        }
    }

    /// Initialize cursor position from terminal state.
    ///
    /// Call this when starting predictions or after reconnection.
    pub fn init_cursor(&mut self, col: u16, row: u16) {
        self.predicted_cursor = Some((col, row));
    }

    /// Get the predicted cursor position.
    pub fn get_predicted_cursor(&self) -> Option<(u16, u16)> {
        self.predicted_cursor
    }

    /// Get iterator over cell predictions.
    pub fn get_cell_predictions(&self) -> impl Iterator<Item = ((u16, u16), &CellPrediction)> {
        self.cell_predictions.iter().map(|(&pos, pred)| (pos, pred))
    }

    /// Clear confirmed cell predictions up to the given sequence.
    pub fn confirm_cells(&mut self, sequence: u64) {
        self.cell_predictions
            .retain(|_, pred| pred.sequence > sequence);
    }

    /// Reset cursor and cell predictions.
    pub fn reset(&mut self) {
        self.predicted_cursor = None;
        self.cell_predictions.clear();
        self.prediction_epoch += 1;
        self.confirmed_epoch = self.prediction_epoch;
    }

    /// Process a user input byte with cursor context.
    ///
    /// This handles different input types:
    /// - Printable ASCII (0x20-0x7E): Creates cell prediction, advances cursor
    /// - Backspace (0x08, 0x7F): Moves cursor left
    /// - Carriage Return (0x0D): Moves cursor to column 0, becomes tentative
    /// - Other control chars: Becomes tentative (unpredictable effects)
    ///
    /// Returns `Some(PredictedEcho)` if a prediction should be displayed.
    #[allow(clippy::too_many_arguments)]
    pub fn new_user_byte(
        &mut self,
        byte: u8,
        cursor: (u16, u16),
        term_width: u16,
        input_seq: u64,
        state: PredictionState,
        current_style: PredictedStyle,
        pending: &mut VecDeque<Prediction>,
        should_predict_fn: impl Fn(char, PredictionState) -> bool,
        become_tentative_fn: impl Fn(PredictionState) -> bool,
    ) -> (Option<PredictedEcho>, PredictionState) {
        // Initialize predicted cursor if not set
        if self.predicted_cursor.is_none() {
            self.predicted_cursor = Some(cursor);
        }

        let (mut pred_col, mut pred_row) = self.predicted_cursor.unwrap_or(cursor);
        let mut new_state = state;

        let result = match byte {
            // Printable ASCII (0x20 space through 0x7E tilde)
            0x20..=0x7E => {
                let ch = byte as char;

                // Check if we should predict this character
                if !should_predict_fn(ch, state) {
                    // Become tentative but don't display
                    if become_tentative_fn(state) {
                        new_state = PredictionState::Tentative;
                    }
                    None
                } else {
                    // Create cell prediction at current predicted cursor
                    let cell_pred = CellPrediction {
                        char: ch,
                        style: current_style,
                        sequence: input_seq,
                        epoch: self.prediction_epoch,
                        timestamp: Instant::now(),
                    };
                    self.cell_predictions
                        .insert((pred_col, pred_row), cell_pred);

                    // Also add to pending queue for legacy tracking
                    pending.push_back(Prediction {
                        sequence: input_seq,
                        char: ch,
                        col: pred_col,
                        row: pred_row,
                        timestamp: Instant::now(),
                    });

                    // Advance predicted cursor
                    pred_col += 1;
                    if pred_col >= term_width {
                        // Wrap to next line
                        pred_col = 0;
                        pred_row += 1;
                        // Note: We don't scroll here - server will handle that
                    }
                    self.predicted_cursor = Some((pred_col, pred_row));

                    Some(PredictedEcho {
                        sequence: input_seq,
                        char: ch,
                        style: current_style,
                    })
                }
            }

            // Backspace (BS) or DEL
            0x08 | 0x7F => {
                // Move predicted cursor left
                if pred_col > 0 {
                    pred_col -= 1;
                    self.predicted_cursor = Some((pred_col, pred_row));
                    // Optionally remove cell prediction at new position
                    self.cell_predictions.remove(&(pred_col, pred_row));
                }
                None
            }

            // Carriage Return
            0x0D => {
                // Move to column 0
                pred_col = 0;
                self.predicted_cursor = Some((pred_col, pred_row));
                // CR may have side effects (like Enter), become tentative
                if become_tentative_fn(state) {
                    new_state = PredictionState::Tentative;
                }
                None
            }

            // Line Feed
            0x0A => {
                // Move to next row, col 0 (typical newline behavior)
                pred_col = 0;
                pred_row += 1;
                self.predicted_cursor = Some((pred_col, pred_row));
                // LF has side effects, become tentative
                if become_tentative_fn(state) {
                    new_state = PredictionState::Tentative;
                }
                None
            }

            // Tab
            0x09 => {
                // Advance to next tab stop (every 8 columns)
                let next_tab = ((pred_col / 8) + 1) * 8;
                pred_col = next_tab.min(term_width.saturating_sub(1));
                self.predicted_cursor = Some((pred_col, pred_row));
                None
            }

            // Escape - start of escape sequence, become tentative
            0x1B => {
                if become_tentative_fn(state) {
                    new_state = PredictionState::Tentative;
                }
                None
            }

            // Other control characters - unpredictable, become tentative
            _ => {
                if become_tentative_fn(state) {
                    new_state = PredictionState::Tentative;
                }
                None
            }
        };

        (result, new_state)
    }
}
