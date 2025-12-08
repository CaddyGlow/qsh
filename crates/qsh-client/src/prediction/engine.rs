//! Core prediction engine implementation.
//!
//! Based on mosh's prediction engine with adaptive display:
//! - Only show predictions when RTT > SRTT_TRIGGER_HIGH (30ms)
//! - Only underline when RTT > FLAG_TRIGGER_HIGH (80ms) or glitches occur
//! - Validate predictions against actual server state

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use qsh_core::terminal::TerminalState;

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

/// State of the prediction engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredictionState {
    /// Confident mode - predict all printable ASCII characters.
    Confident,
    /// Tentative mode - only predict alphanumeric characters after recent misprediction.
    Tentative,
    /// Disabled mode - too many mispredictions, wait for full state sync.
    Disabled,
}

/// Display preference for predictions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DisplayPreference {
    /// Always show predictions.
    Always,
    /// Never show predictions.
    Never,
    /// Show predictions adaptively based on RTT (default, mosh-style).
    #[default]
    Adaptive,
    /// Experimental: More aggressive prediction with position-based validation.
    Experimental,
}

/// Style for displaying predicted characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredictedStyle {
    /// Show with underline (high latency).
    Underline,
    /// Show without special styling (moderate latency).
    Normal,
    /// Show with dim/faded appearance (tentative state).
    Dim,
}

/// A pending prediction awaiting confirmation.
#[derive(Debug, Clone)]
pub struct Prediction {
    /// Input sequence number for this prediction.
    pub sequence: u64,
    /// The predicted character.
    pub char: char,
    /// Column position where character should appear.
    pub col: u16,
    /// Row position where character should appear.
    pub row: u16,
    /// When this prediction was made.
    pub timestamp: Instant,
}

/// Result of making a prediction.
#[derive(Debug, Clone)]
pub struct PredictedEcho {
    /// Sequence number for tracking.
    pub sequence: u64,
    /// Character to display.
    pub char: char,
    /// Display style.
    pub style: PredictedStyle,
}

/// A cell prediction with position and metadata.
#[derive(Debug, Clone)]
pub struct CellPrediction {
    /// The predicted character.
    pub char: char,
    /// Display style.
    pub style: PredictedStyle,
    /// Input sequence number.
    pub sequence: u64,
    /// Epoch when this prediction was made.
    pub epoch: u64,
    /// When this prediction was made.
    pub timestamp: Instant,
}

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

    // Position-based prediction tracking (mosh-style)
    /// Predicted cursor position (col, row).
    predicted_cursor: Option<(u16, u16)>,
    /// Cell predictions by position.
    cell_predictions: HashMap<(u16, u16), CellPrediction>,
    /// Current prediction epoch (increments on each new_user_byte batch).
    prediction_epoch: u64,
    /// Last epoch that was confirmed.
    confirmed_epoch: u64,
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
            // Position-based tracking
            predicted_cursor: None,
            cell_predictions: HashMap::new(),
            prediction_epoch: 0,
            confirmed_epoch: 0,
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
        let style = match self.state {
            PredictionState::Confident => {
                if self.flagging {
                    PredictedStyle::Underline
                } else {
                    PredictedStyle::Normal
                }
            }
            PredictionState::Tentative => PredictedStyle::Dim,
            PredictionState::Disabled => unreachable!(),
        };

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
        // Reset position-based tracking
        self.predicted_cursor = None;
        self.cell_predictions.clear();
        self.prediction_epoch += 1;
        self.confirmed_epoch = self.prediction_epoch;
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
    // Position-based prediction methods (mosh-style)
    // =========================================================================

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
        // Initialize predicted cursor if not set
        if self.predicted_cursor.is_none() {
            self.predicted_cursor = Some(cursor);
        }

        let (mut pred_col, mut pred_row) = self.predicted_cursor.unwrap_or(cursor);

        match byte {
            // Printable ASCII (0x20 space through 0x7E tilde)
            0x20..=0x7E => {
                let ch = byte as char;

                // Check if we should predict this character
                if !self.should_predict(ch) {
                    // Become tentative but don't display
                    if self.state == PredictionState::Confident {
                        self.become_tentative();
                    }
                    return None;
                }

                // Create cell prediction at current predicted cursor
                let style = self.current_style();
                let cell_pred = CellPrediction {
                    char: ch,
                    style,
                    sequence: input_seq,
                    epoch: self.prediction_epoch,
                    timestamp: Instant::now(),
                };
                self.cell_predictions.insert((pred_col, pred_row), cell_pred);

                // Also add to pending queue for legacy tracking
                self.pending.push_back(Prediction {
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
                    style,
                })
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
                self.become_tentative();
                None
            }

            // Line Feed
            0x0A => {
                // Move to next row, col 0 (typical newline behavior)
                pred_col = 0;
                pred_row += 1;
                self.predicted_cursor = Some((pred_col, pred_row));
                // LF has side effects, become tentative
                self.become_tentative();
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
                self.become_tentative();
                None
            }

            // Other control characters - unpredictable, become tentative
            _ => {
                self.become_tentative();
                None
            }
        }
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

    /// Transition to tentative state without triggering full misprediction.
    fn become_tentative(&mut self) {
        if self.state == PredictionState::Confident {
            self.state = PredictionState::Tentative;
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
        if let Some((pred_col, pred_row)) = self.predicted_cursor {
            if server_cursor.0 != pred_col || server_cursor.1 != pred_row {
                // Cursor misprediction - clear cursor prediction
                // but don't count as full misprediction (cursor position can drift)
                self.predicted_cursor = None;
            }
        }

        // Check cell predictions
        let mut to_remove = Vec::new();
        let mut had_misprediction = false;

        for (&(col, row), pred) in &self.cell_predictions {
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
            self.cell_predictions.remove(&pos);
        }

        // Handle misprediction
        if had_misprediction {
            self.misprediction();
        }
    }

    /// Clear confirmed cell predictions up to the given sequence.
    pub fn confirm_cells(&mut self, sequence: u64) {
        self.cell_predictions.retain(|_, pred| pred.sequence > sequence);
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_state_is_confident() {
        let engine = PredictionEngine::new();
        assert_eq!(engine.state(), PredictionState::Confident);
    }

    #[test]
    fn should_predict_printable_in_confident() {
        let engine = PredictionEngine::new();

        assert!(engine.should_predict('a'));
        assert!(engine.should_predict('Z'));
        assert!(engine.should_predict('5'));
        assert!(engine.should_predict('-'));
        assert!(engine.should_predict(' '));
        assert!(engine.should_predict('~'));
    }

    #[test]
    fn should_not_predict_control_chars() {
        let engine = PredictionEngine::new();

        assert!(!engine.should_predict('\x03')); // Ctrl-C
        assert!(!engine.should_predict('\x1b')); // Escape
        assert!(!engine.should_predict('\n')); // Newline
        assert!(!engine.should_predict('\r')); // Carriage return
        assert!(!engine.should_predict('\t')); // Tab
    }

    #[test]
    fn should_predict_alphanumeric_only_in_tentative() {
        let mut engine = PredictionEngine::new();
        engine.misprediction(); // -> Tentative
        assert_eq!(engine.state(), PredictionState::Tentative);

        assert!(engine.should_predict('a'));
        assert!(engine.should_predict('Z'));
        assert!(engine.should_predict('5'));

        assert!(!engine.should_predict('-'));
        assert!(!engine.should_predict(' '));
        assert!(!engine.should_predict('~'));
    }

    #[test]
    fn should_not_predict_in_disabled() {
        let mut engine = PredictionEngine::new();
        // Three mispredictions to reach Disabled
        engine.misprediction();
        engine.misprediction();
        engine.misprediction();
        assert_eq!(engine.state(), PredictionState::Disabled);

        assert!(!engine.should_predict('a'));
        assert!(!engine.should_predict('5'));
    }

    #[test]
    fn predict_adds_to_pending() {
        let mut engine = PredictionEngine::new();

        // Predictions with same input_seq (simulates multiple chars in one input message)
        let echo = engine.predict('a', 0, 0, 1).unwrap();
        assert_eq!(echo.sequence, 1);
        assert_eq!(echo.char, 'a');
        assert_eq!(engine.pending().len(), 1);

        let echo = engine.predict('b', 1, 0, 1).unwrap();
        assert_eq!(echo.sequence, 1);
        assert_eq!(engine.pending().len(), 2);

        // New input message
        let echo = engine.predict('c', 2, 0, 2).unwrap();
        assert_eq!(echo.sequence, 2);
        assert_eq!(engine.pending().len(), 3);
    }

    #[test]
    fn predict_returns_none_for_unpredictable() {
        let mut engine = PredictionEngine::new();
        assert!(engine.predict('\x03', 0, 0, 1).is_none());
    }

    #[test]
    fn confirm_removes_from_pending() {
        let mut engine = PredictionEngine::new();

        // Two chars in seq 1, one char in seq 2
        engine.predict('a', 0, 0, 1);
        engine.predict('b', 1, 0, 1);
        engine.predict('c', 2, 0, 2);
        assert_eq!(engine.pending().len(), 3);

        // Confirm seq 1 removes both 'a' and 'b'
        engine.confirm(1);
        assert_eq!(engine.pending().len(), 1);

        let remaining = engine.pending().front().unwrap();
        assert_eq!(remaining.char, 'c');
        assert_eq!(remaining.sequence, 2);
    }

    #[test]
    fn misprediction_clears_pending() {
        let mut engine = PredictionEngine::new();

        engine.predict('a', 0, 0, 1);
        engine.predict('b', 1, 0, 1);
        assert_eq!(engine.pending().len(), 2);

        engine.misprediction();
        assert_eq!(engine.pending().len(), 0);
    }

    #[test]
    fn misprediction_degrades_state() {
        let mut engine = PredictionEngine::new();
        assert_eq!(engine.state(), PredictionState::Confident);

        engine.misprediction();
        assert_eq!(engine.state(), PredictionState::Tentative);

        engine.misprediction();
        engine.misprediction();
        assert_eq!(engine.state(), PredictionState::Disabled);
    }

    #[test]
    fn three_mispredictions_disables() {
        let mut engine = PredictionEngine::new();

        engine.misprediction(); // -> Tentative
        engine.misprediction(); // count = 2, still Tentative
        engine.misprediction(); // count = 3 -> Disabled

        assert_eq!(engine.state(), PredictionState::Disabled);
    }

    #[test]
    fn disabled_stays_disabled() {
        let mut engine = PredictionEngine::new();

        // Get to disabled state
        engine.misprediction();
        engine.misprediction();
        engine.misprediction();
        assert_eq!(engine.state(), PredictionState::Disabled);

        // More mispredictions don't change anything
        engine.misprediction();
        assert_eq!(engine.state(), PredictionState::Disabled);
    }

    #[test]
    fn confirmation_restores_confidence() {
        let mut engine = PredictionEngine::new();

        engine.misprediction(); // -> Tentative
        assert_eq!(engine.state(), PredictionState::Tentative);

        engine.predict('a', 0, 0, 1);
        engine.confirm(1);
        assert_eq!(engine.state(), PredictionState::Confident);
    }

    #[test]
    fn reset_restores_confident() {
        let mut engine = PredictionEngine::new();

        engine.misprediction();
        engine.misprediction();
        engine.misprediction();
        assert_eq!(engine.state(), PredictionState::Disabled);

        engine.reset();
        assert_eq!(engine.state(), PredictionState::Confident);
        assert_eq!(engine.pending().len(), 0);
    }

    #[test]
    fn prediction_positions_tracked() {
        let mut engine = PredictionEngine::new();

        engine.predict('a', 5, 10, 1);
        engine.predict('b', 6, 10, 1);

        let pending: Vec<_> = engine.pending().iter().collect();
        assert_eq!(pending[0].col, 5);
        assert_eq!(pending[0].row, 10);
        assert_eq!(pending[1].col, 6);
        assert_eq!(pending[1].row, 10);
    }

    #[test]
    fn style_varies_by_state_and_flagging() {
        let mut engine = PredictionEngine::new();

        // Confident + no flagging -> Normal (fast connection)
        let echo = engine.predict('a', 0, 0, 1).unwrap();
        assert_eq!(echo.style, PredictedStyle::Normal);

        // Enable flagging via high RTT
        engine.update_rtt(Duration::from_millis(100));
        assert!(engine.is_flagging());

        // Confident + flagging -> Underline
        let echo = engine.predict('b', 1, 0, 2).unwrap();
        assert_eq!(echo.style, PredictedStyle::Underline);

        engine.misprediction(); // -> Tentative

        // Tentative -> Dim (regardless of flagging)
        let echo = engine.predict('c', 2, 0, 3).unwrap();
        assert_eq!(echo.style, PredictedStyle::Dim);
    }

    #[test]
    fn adaptive_display_based_on_rtt() {
        let mut engine = PredictionEngine::new();

        // Initially no RTT, should not display
        assert!(!engine.should_display());

        // Low RTT, should not display
        engine.update_rtt(Duration::from_millis(10));
        assert!(!engine.should_display());

        // High RTT, should display
        engine.update_rtt(Duration::from_millis(50));
        assert!(engine.should_display());

        // With Always preference, always display
        engine.set_display_preference(DisplayPreference::Always);
        engine.update_rtt(Duration::from_millis(5));
        assert!(engine.should_display());

        // With Never preference, never display
        engine.set_display_preference(DisplayPreference::Never);
        engine.update_rtt(Duration::from_millis(100));
        assert!(!engine.should_display());
    }

    // =========================================================================
    // Tests for new_user_byte() and position-based prediction
    // =========================================================================

    #[test]
    fn new_user_byte_initializes_cursor() {
        let mut engine = PredictionEngine::new();
        engine.set_display_preference(DisplayPreference::Always);

        // Before any input, cursor should be None
        assert!(engine.get_predicted_cursor().is_none());

        // After processing a byte, cursor should be set
        engine.new_user_byte(b'a', (5, 10), 80, 1);
        assert!(engine.get_predicted_cursor().is_some());
    }

    #[test]
    fn new_user_byte_advances_cursor() {
        let mut engine = PredictionEngine::new();
        engine.set_display_preference(DisplayPreference::Always);

        // Start at col 0, row 0
        engine.new_user_byte(b'a', (0, 0), 80, 1);
        assert_eq!(engine.get_predicted_cursor(), Some((1, 0)));

        engine.new_user_byte(b'b', (1, 0), 80, 1);
        assert_eq!(engine.get_predicted_cursor(), Some((2, 0)));

        engine.new_user_byte(b'c', (2, 0), 80, 1);
        assert_eq!(engine.get_predicted_cursor(), Some((3, 0)));
    }

    #[test]
    fn new_user_byte_wraps_at_terminal_width() {
        let mut engine = PredictionEngine::new();
        engine.set_display_preference(DisplayPreference::Always);

        // Start at the last column
        engine.init_cursor(79, 0);

        // Typing should wrap to next line
        engine.new_user_byte(b'a', (79, 0), 80, 1);
        assert_eq!(engine.get_predicted_cursor(), Some((0, 1)));
    }

    #[test]
    fn new_user_byte_backspace_moves_cursor_back() {
        let mut engine = PredictionEngine::new();
        engine.set_display_preference(DisplayPreference::Always);
        engine.init_cursor(5, 0);

        // Backspace should move cursor back
        engine.new_user_byte(0x08, (5, 0), 80, 1); // BS
        assert_eq!(engine.get_predicted_cursor(), Some((4, 0)));

        // DEL should also move back
        engine.new_user_byte(0x7F, (4, 0), 80, 1);
        assert_eq!(engine.get_predicted_cursor(), Some((3, 0)));

        // But not past column 0
        engine.init_cursor(0, 0);
        engine.new_user_byte(0x08, (0, 0), 80, 1);
        assert_eq!(engine.get_predicted_cursor(), Some((0, 0)));
    }

    #[test]
    fn new_user_byte_carriage_return_moves_to_col_0() {
        let mut engine = PredictionEngine::new();
        engine.set_display_preference(DisplayPreference::Always);
        engine.init_cursor(40, 5);

        engine.new_user_byte(0x0D, (40, 5), 80, 1); // CR
        assert_eq!(engine.get_predicted_cursor(), Some((0, 5)));
    }

    #[test]
    fn new_user_byte_line_feed_moves_to_next_row() {
        let mut engine = PredictionEngine::new();
        engine.set_display_preference(DisplayPreference::Always);
        engine.init_cursor(20, 5);

        engine.new_user_byte(0x0A, (20, 5), 80, 1); // LF
        assert_eq!(engine.get_predicted_cursor(), Some((0, 6)));
    }

    #[test]
    fn new_user_byte_tab_advances_to_tab_stop() {
        let mut engine = PredictionEngine::new();
        engine.set_display_preference(DisplayPreference::Always);

        // From col 0, tab should go to col 8
        engine.init_cursor(0, 0);
        engine.new_user_byte(0x09, (0, 0), 80, 1); // TAB
        assert_eq!(engine.get_predicted_cursor(), Some((8, 0)));

        // From col 5, tab should go to col 8
        engine.init_cursor(5, 0);
        engine.new_user_byte(0x09, (5, 0), 80, 1);
        assert_eq!(engine.get_predicted_cursor(), Some((8, 0)));

        // From col 8, tab should go to col 16
        engine.init_cursor(8, 0);
        engine.new_user_byte(0x09, (8, 0), 80, 1);
        assert_eq!(engine.get_predicted_cursor(), Some((16, 0)));
    }

    #[test]
    fn new_user_byte_creates_cell_predictions() {
        let mut engine = PredictionEngine::new();
        engine.set_display_preference(DisplayPreference::Always);
        engine.init_cursor(0, 0);

        engine.new_user_byte(b'h', (0, 0), 80, 1);
        engine.new_user_byte(b'i', (1, 0), 80, 1);

        let predictions: Vec<_> = engine.get_cell_predictions().collect();
        assert_eq!(predictions.len(), 2);

        // Check that predictions exist at correct positions
        let has_h_at_0_0 = predictions.iter().any(|((col, row), p)| {
            *col == 0 && *row == 0 && p.char == 'h'
        });
        let has_i_at_1_0 = predictions.iter().any(|((col, row), p)| {
            *col == 1 && *row == 0 && p.char == 'i'
        });
        assert!(has_h_at_0_0);
        assert!(has_i_at_1_0);
    }

    #[test]
    fn new_user_byte_escape_becomes_tentative() {
        let mut engine = PredictionEngine::new();
        engine.set_display_preference(DisplayPreference::Always);
        assert_eq!(engine.state(), PredictionState::Confident);

        engine.new_user_byte(0x1B, (0, 0), 80, 1); // ESC
        assert_eq!(engine.state(), PredictionState::Tentative);
    }

    #[test]
    fn confirm_cells_removes_confirmed() {
        let mut engine = PredictionEngine::new();
        engine.set_display_preference(DisplayPreference::Always);
        engine.init_cursor(0, 0);

        // Create predictions with different sequences
        engine.new_user_byte(b'a', (0, 0), 80, 1);
        engine.new_user_byte(b'b', (1, 0), 80, 2);
        engine.new_user_byte(b'c', (2, 0), 80, 3);

        let count_before = engine.get_cell_predictions().count();
        assert_eq!(count_before, 3);

        // Confirm up to sequence 2
        engine.confirm_cells(2);

        let count_after = engine.get_cell_predictions().count();
        assert_eq!(count_after, 1);

        // Only sequence 3 should remain
        let remaining: Vec<_> = engine.get_cell_predictions().collect();
        assert_eq!(remaining[0].1.char, 'c');
        assert_eq!(remaining[0].1.sequence, 3);
    }

    #[test]
    fn reset_clears_cell_predictions() {
        let mut engine = PredictionEngine::new();
        engine.set_display_preference(DisplayPreference::Always);
        engine.init_cursor(0, 0);

        engine.new_user_byte(b'a', (0, 0), 80, 1);
        engine.new_user_byte(b'b', (1, 0), 80, 1);
        assert!(engine.get_cell_predictions().count() > 0);

        engine.reset();
        assert_eq!(engine.get_cell_predictions().count(), 0);
        assert!(engine.get_predicted_cursor().is_none());
    }

    #[test]
    fn validate_clears_matching_predictions() {
        use qsh_core::terminal::TerminalState;

        let mut engine = PredictionEngine::new();
        engine.set_display_preference(DisplayPreference::Always);
        engine.init_cursor(0, 0);

        // Create prediction
        engine.new_user_byte(b'X', (0, 0), 80, 1);
        assert_eq!(engine.get_cell_predictions().count(), 1);

        // Create terminal state with matching character
        let mut state = TerminalState::new(80, 24);
        state.screen_mut().set(0, 0, qsh_core::terminal::Cell::new('X'));
        state.cursor.col = 1;
        state.cursor.row = 0;

        // Validate should clear the matching prediction
        engine.validate(&state);
        assert_eq!(engine.get_cell_predictions().count(), 0);
    }

    #[test]
    fn validate_misprediction_triggers_degradation() {
        use qsh_core::terminal::TerminalState;

        let mut engine = PredictionEngine::new();
        engine.set_display_preference(DisplayPreference::Always);
        engine.init_cursor(0, 0);
        assert_eq!(engine.state(), PredictionState::Confident);

        // Create prediction for 'X'
        engine.new_user_byte(b'X', (0, 0), 80, 1);

        // But server has 'Y' - this is a misprediction
        let mut state = TerminalState::new(80, 24);
        state.screen_mut().set(0, 0, qsh_core::terminal::Cell::new('Y'));
        state.cursor.col = 1;
        state.cursor.row = 0;

        // Validate should detect misprediction and degrade state
        engine.validate(&state);
        assert_eq!(engine.state(), PredictionState::Tentative);
    }
}
