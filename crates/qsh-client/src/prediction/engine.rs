//! Core prediction engine implementation.

use std::collections::VecDeque;
use std::time::Instant;

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

/// Style for displaying predicted characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredictedStyle {
    /// Show with underline.
    Underline,
    /// Show with dim/faded appearance.
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
    /// Next sequence number to assign.
    next_sequence: u64,
    /// Last confirmed sequence number.
    confirmed_sequence: u64,
    /// Current prediction state/confidence.
    state: PredictionState,
    /// Count of consecutive mispredictions.
    misprediction_count: u8,
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
            next_sequence: 0,
            confirmed_sequence: 0,
            state: PredictionState::Confident,
            misprediction_count: 0,
        }
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
    /// Returns `Some(PredictedEcho)` if prediction should be displayed,
    /// `None` if prediction was skipped.
    pub fn predict(&mut self, c: char, col: u16, row: u16) -> Option<PredictedEcho> {
        if !self.should_predict(c) {
            return None;
        }

        let seq = self.next_sequence;
        self.next_sequence += 1;

        self.pending.push_back(Prediction {
            sequence: seq,
            char: c,
            col,
            row,
            timestamp: Instant::now(),
        });

        let style = match self.state {
            PredictionState::Confident => PredictedStyle::Underline,
            PredictionState::Tentative => PredictedStyle::Dim,
            PredictionState::Disabled => unreachable!(),
        };

        Some(PredictedEcho {
            sequence: seq,
            char: c,
            style,
        })
    }

    /// Confirm that input up to and including the given sequence was processed correctly.
    pub fn confirm(&mut self, sequence: u64) {
        self.confirmed_sequence = sequence;

        // Remove confirmed predictions
        while let Some(p) = self.pending.front() {
            if p.sequence <= sequence {
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
    }

    /// Get current prediction state.
    pub fn state(&self) -> PredictionState {
        self.state
    }

    /// Get pending predictions for display.
    pub fn pending(&self) -> &VecDeque<Prediction> {
        &self.pending
    }

    /// Get the next sequence number that will be assigned.
    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    /// Get the last confirmed sequence number.
    pub fn confirmed_sequence(&self) -> u64 {
        self.confirmed_sequence
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

        let echo = engine.predict('a', 0, 0).unwrap();
        assert_eq!(echo.sequence, 0);
        assert_eq!(echo.char, 'a');
        assert_eq!(engine.pending().len(), 1);

        let echo = engine.predict('b', 1, 0).unwrap();
        assert_eq!(echo.sequence, 1);
        assert_eq!(engine.pending().len(), 2);
    }

    #[test]
    fn predict_returns_none_for_unpredictable() {
        let mut engine = PredictionEngine::new();
        assert!(engine.predict('\x03', 0, 0).is_none());
    }

    #[test]
    fn confirm_removes_from_pending() {
        let mut engine = PredictionEngine::new();

        engine.predict('a', 0, 0);
        engine.predict('b', 1, 0);
        engine.predict('c', 2, 0);
        assert_eq!(engine.pending().len(), 3);

        engine.confirm(1);
        assert_eq!(engine.pending().len(), 1);

        let remaining = engine.pending().front().unwrap();
        assert_eq!(remaining.char, 'c');
        assert_eq!(remaining.sequence, 2);
    }

    #[test]
    fn misprediction_clears_pending() {
        let mut engine = PredictionEngine::new();

        engine.predict('a', 0, 0);
        engine.predict('b', 1, 0);
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

        engine.predict('a', 0, 0);
        engine.confirm(0);
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

        engine.predict('a', 5, 10);
        engine.predict('b', 6, 10);

        let pending: Vec<_> = engine.pending().iter().collect();
        assert_eq!(pending[0].col, 5);
        assert_eq!(pending[0].row, 10);
        assert_eq!(pending[1].col, 6);
        assert_eq!(pending[1].row, 10);
    }

    #[test]
    fn style_varies_by_state() {
        let mut engine = PredictionEngine::new();

        // Confident -> Underline
        let echo = engine.predict('a', 0, 0).unwrap();
        assert_eq!(echo.style, PredictedStyle::Underline);

        engine.misprediction(); // -> Tentative

        // Tentative -> Dim
        let echo = engine.predict('b', 1, 0).unwrap();
        assert_eq!(echo.style, PredictedStyle::Dim);
    }
}
