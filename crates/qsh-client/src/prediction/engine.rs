//! Core prediction engine implementation.
//!
//! Based on mosh's prediction engine with adaptive display:
//! - Only show predictions when RTT > SRTT_TRIGGER_HIGH (30ms)
//! - Only underline when RTT > FLAG_TRIGGER_HIGH (80ms) or glitches occur
//! - Validate predictions against actual server state

use std::collections::VecDeque;
use std::time::{Duration, Instant};

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
            DisplayPreference::Always => true,
            DisplayPreference::Adaptive => {
                self.srtt_trigger || self.glitch_trigger > 0
            }
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
    pub fn predict(&mut self, c: char, col: u16, row: u16, input_seq: u64) -> Option<PredictedEcho> {
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
}
