//! Tests for the prediction engine.

#[cfg(test)]
mod tests {
    use super::super::engine::PredictionEngine;
    use super::super::state::{DisplayPreference, PredictedStyle, PredictionState};

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
        use std::time::Duration;

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
        use std::time::Duration;

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
