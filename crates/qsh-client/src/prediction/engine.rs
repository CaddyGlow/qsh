//! Core prediction engine implementation.
//!
//! Based on mosh's prediction engine with adaptive display:
//! - Only show predictions when RTT > SRTT_TRIGGER_HIGH (30ms)
//! - Only underline when RTT > FLAG_TRIGGER_HIGH (80ms) or glitches occur
//! - Validate predictions against actual server state

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use qsh_core::terminal::TerminalState;

use super::cursor::CursorPredictor;
use super::state::{DisplayPreference, PredictedStyle, PredictionState};
use super::types::{CellPrediction, PredictedEcho, Prediction};

/// RTT threshold below which predictions are hidden (connection is fast enough).
const SRTT_TRIGGER_LOW: Duration = Duration::from_millis(20);
/// RTT threshold above which predictions are shown.
const SRTT_TRIGGER_HIGH: Duration = Duration::from_millis(30);
/// RTT threshold below which predictions are not underlined.
const FLAG_TRIGGER_LOW: Duration = Duration::from_millis(50);
/// RTT threshold above which predictions are underlined.
const FLAG_TRIGGER_HIGH: Duration = Duration::from_millis(80);
/// Prediction outstanding this long is considered a glitch.
const GLITCH_THRESHOLD: Duration = Duration::from_millis(250);
/// Number of quick confirmations needed to clear glitch trigger.
const GLITCH_REPAIR_COUNT: u32 = 10;

/// Engine for managing predictive local echo.
#[derive(Debug)]
pub struct PredictionEngine {
    /// Pending predictions awaiting confirmation.
    pending: VecDeque<Prediction>,
    /// Last confirmed sequence number.
    confirmed_sequence: u64,
    /// Current prediction state/confidence.
    state: PredictionState,
    /// Count of consecutive mispredictions.
    misprediction_count: u8,
    /// Display preference.
    display_preference: DisplayPreference,
    /// Whether RTT-based trigger is active (show predictions).
    srtt_trigger: bool,
    /// Whether flagging (underlining) is active.
    flagging: bool,
    /// Glitch trigger count (long-pending predictions).
    glitch_trigger: u32,
    /// Current smoothed RTT.
    current_rtt: Duration,

    /// Cursor and cell prediction tracking.
    cursor_predictor: CursorPredictor,
}

impl Default for PredictionEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PredictionEngine {
    /// Create a new prediction engine in confident mode.
    pub fn new() -> Self {
        Self {
            pending: VecDeque::new(),
            confirmed_sequence: 0,
            state: PredictionState::Confident,
            misprediction_count: 0,
            display_preference: DisplayPreference::Adaptive,
            srtt_trigger: false,
            flagging: false,
            glitch_trigger: 0,
            current_rtt: Duration::ZERO,
            cursor_predictor: CursorPredictor::new(),
        }
    }

    /// Update the current RTT and adjust triggers accordingly.
    pub fn update_rtt(&mut self, rtt: Duration) {
        self.current_rtt = rtt;

        // Control srtt_trigger with hysteresis (mosh-style)
        if rtt > SRTT_TRIGGER_HIGH {
            self.srtt_trigger = true;
        } else if self.srtt_trigger && rtt <= SRTT_TRIGGER_LOW && !self.has_active_predictions() {
            // Only turn off when no predictions are being shown
            self.srtt_trigger = false;
        }

        // Control flagging (underlining) with hysteresis
        if rtt > FLAG_TRIGGER_HIGH {
            self.flagging = true;
        } else if rtt <= FLAG_TRIGGER_LOW {
            self.flagging = false;
        }

        // High glitch count also activates flagging
        if self.glitch_trigger > GLITCH_REPAIR_COUNT {
            self.flagging = true;
        }
    }

    /// Set display preference.
    pub fn set_display_preference(&mut self, pref: DisplayPreference) {
        self.display_preference = pref;
    }

    /// Check if predictions should be displayed based on current triggers.
    pub fn should_display(&self) -> bool {
        match self.display_preference {
            DisplayPreference::Never => false,
            DisplayPreference::Always | DisplayPreference::Experimental => true,
            DisplayPreference::Adaptive => self.srtt_trigger || self.glitch_trigger > 0,
        }
    }

    /// Check if there are any active predictions.
    fn has_active_predictions(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Check if we should predict echo for this character.
    pub fn should_predict(&self, c: char) -> bool {
        match self.state {
            PredictionState::Disabled => false,
            PredictionState::Tentative => c.is_ascii_alphanumeric(),
            PredictionState::Confident => c.is_ascii() && !c.is_ascii_control(),
        }
    }

    /// Make a prediction for a character at the given position.
    ///
    /// The `input_seq` should be the input message sequence number from
    /// the input tracker, allowing confirmation when that input is acknowledged.
    ///
    /// Returns `Some(PredictedEcho)` if prediction should be displayed,
    /// `None` if prediction was skipped.
    pub fn predict(
        &mut self,
        c: char,
        col: u16,
        row: u16,
        input_seq: u64,
    ) -> Option<PredictedEcho> {
        if !self.should_predict(c) {
            return None;
        }

        self.pending.push_back(Prediction {
            sequence: input_seq,
            char: c,
            col,
            row,
            timestamp: Instant::now(),
        });

        // Determine style based on state and flagging
        let style = self.current_style();

        Some(PredictedEcho {
            sequence: input_seq,
            char: c,
            style,
        })
    }

    /// Confirm that input up to and including the given sequence was processed correctly.
    pub fn confirm(&mut self, sequence: u64) {
        let now = Instant::now();
        self.confirmed_sequence = sequence;

        // Remove confirmed predictions and check for quick confirmations
        while let Some(p) = self.pending.front() {
            if p.sequence <= sequence {
                // Quick confirmation reduces glitch trigger
                if now.duration_since(p.timestamp) < GLITCH_THRESHOLD && self.glitch_trigger > 0 {
                    self.glitch_trigger = self.glitch_trigger.saturating_sub(1);
                }
                self.pending.pop_front();
            } else {
                break;
            }
        }

        // Successful confirmations restore confidence
        if self.state == PredictionState::Tentative {
            self.misprediction_count = 0;
            self.state = PredictionState::Confident;
        }
    }

    /// Check for long-pending predictions (glitches) and update triggers.
    pub fn check_glitches(&mut self) {
        let now = Instant::now();
        for pred in &self.pending {
            let age = now.duration_since(pred.timestamp);
            if age >= GLITCH_THRESHOLD {
                // Long-pending prediction detected
                if self.glitch_trigger < GLITCH_REPAIR_COUNT {
                    self.glitch_trigger = GLITCH_REPAIR_COUNT;
                }
            }
        }
    }

    /// Handle a misprediction - server state doesn't match what we predicted.
    pub fn misprediction(&mut self) {
        // Clear all pending predictions
        self.pending.clear();

        self.misprediction_count = self.misprediction_count.saturating_add(1);

        // Degrade state based on consecutive mispredictions
        self.state = match self.state {
            PredictionState::Confident => PredictionState::Tentative,
            PredictionState::Tentative => {
                if self.misprediction_count >= 3 {
                    PredictionState::Disabled
                } else {
                    PredictionState::Tentative
                }
            }
            PredictionState::Disabled => PredictionState::Disabled,
        };
    }

    /// Reset the engine after a full state sync.
    pub fn reset(&mut self) {
        self.pending.clear();
        self.state = PredictionState::Confident;
        self.misprediction_count = 0;
        self.glitch_trigger = 0;
        self.cursor_predictor.reset();
    }

    /// Get current prediction state.
    pub fn state(&self) -> PredictionState {
        self.state
    }

    /// Get pending predictions for display.
    pub fn pending(&self) -> &VecDeque<Prediction> {
        &self.pending
    }

    /// Get the last confirmed sequence number.
    pub fn confirmed_sequence(&self) -> u64 {
        self.confirmed_sequence
    }

    /// Check if flagging (underlining) is active.
    pub fn is_flagging(&self) -> bool {
        self.flagging
    }

    // =========================================================================
    // Position-based prediction methods (delegated to CursorPredictor)
    // =========================================================================

    /// Initialize cursor position from terminal state.
    ///
    /// Call this when starting predictions or after reconnection.
    pub fn init_cursor(&mut self, col: u16, row: u16) {
        self.cursor_predictor.init_cursor(col, row);
    }

    /// Get the predicted cursor position.
    pub fn get_predicted_cursor(&self) -> Option<(u16, u16)> {
        self.cursor_predictor.get_predicted_cursor()
    }

    /// Get iterator over cell predictions.
    pub fn get_cell_predictions(&self) -> impl Iterator<Item = ((u16, u16), &CellPrediction)> {
        self.cursor_predictor.get_cell_predictions()
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
    pub fn new_user_byte(
        &mut self,
        byte: u8,
        cursor: (u16, u16),
        term_width: u16,
        input_seq: u64,
    ) -> Option<PredictedEcho> {
        let current_style = self.current_style();
        let (result, new_state) = self.cursor_predictor.new_user_byte(
            byte,
            cursor,
            term_width,
            input_seq,
            self.state,
            current_style,
            &mut self.pending,
            |c, state| match state {
                PredictionState::Disabled => false,
                PredictionState::Tentative => c.is_ascii_alphanumeric(),
                PredictionState::Confident => c.is_ascii() && !c.is_ascii_control(),
            },
            |state| state == PredictionState::Confident,
        );
        self.state = new_state;
        result
    }

    /// Get the current display style based on state and flagging.
    fn current_style(&self) -> PredictedStyle {
        match self.state {
            PredictionState::Confident => {
                if self.flagging {
                    PredictedStyle::Underline
                } else {
                    PredictedStyle::Normal
                }
            }
            PredictionState::Tentative => PredictedStyle::Dim,
            PredictionState::Disabled => PredictedStyle::Normal, // Shouldn't display anyway
        }
    }

    /// Validate predictions against server state.
    ///
    /// Compares predicted cells against actual server terminal state
    /// and handles mispredictions.
    pub fn validate(&mut self, server_state: &TerminalState) {
        let screen = server_state.screen();
        let server_cursor = (server_state.cursor.col, server_state.cursor.row);

        // Check cursor prediction
        if let Some((pred_col, pred_row)) = self.get_predicted_cursor() {
            if server_cursor.0 != pred_col || server_cursor.1 != pred_row {
                // Cursor misprediction - clear cursor prediction
                // but don't count as full misprediction (cursor position can drift)
                self.cursor_predictor.predicted_cursor = None;
            }
        }

        // Check cell predictions
        let mut to_remove = Vec::new();
        let mut had_misprediction = false;

        for ((col, row), pred) in self.get_cell_predictions() {
            if let Some(actual_cell) = screen.get(col, row) {
                if actual_cell.ch == pred.char {
                    // Correct prediction - mark for removal (will be cleaned by confirm)
                    to_remove.push((col, row));
                } else {
                    // Misprediction - character doesn't match
                    to_remove.push((col, row));
                    had_misprediction = true;
                }
            }
        }

        // Remove validated/mispredicted cells
        for pos in to_remove {
            self.cursor_predictor.cell_predictions.remove(&pos);
        }

        // Handle misprediction
        if had_misprediction {
            self.misprediction();
        }
    }

    /// Clear confirmed cell predictions up to the given sequence.
    pub fn confirm_cells(&mut self, sequence: u64) {
        self.cursor_predictor.confirm_cells(sequence);
    }
}
