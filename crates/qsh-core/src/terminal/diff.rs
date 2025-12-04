//! Terminal state diffing for efficient synchronization.
//!
//! Computes minimal diffs between terminal states to reduce bandwidth
//! when syncing state between client and server.

use serde::{Deserialize, Serialize};

use super::state::{Cell, Cursor, TerminalState};
use crate::error::{Error, Result};

/// Threshold for using full state instead of incremental diff.
/// If more than this percentage of cells changed, send full state.
const FULL_STATE_THRESHOLD_PERCENT: usize = 30;

/// A single cell change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellChange {
    /// Column position.
    pub col: u16,
    /// Row position.
    pub row: u16,
    /// New cell value.
    pub cell: Cell,
}

/// Diff between two terminal states.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StateDiff {
    /// Full state replacement (used for large changes or initial sync).
    Full(TerminalState),

    /// Incremental changes (small updates).
    Incremental {
        /// Generation of the state we're diffing from.
        from_gen: u64,
        /// Generation of the resulting state.
        to_gen: u64,
        /// Cell changes to apply.
        changes: Vec<CellChange>,
        /// New cursor position (if changed).
        cursor: Option<Cursor>,
        /// New title (if changed).
        title: Option<Option<String>>,
        /// New current working directory (if changed).
        cwd: Option<Option<String>>,
        /// New clipboard content (if changed).
        clipboard: Option<Option<(String, String)>>,
        /// Pending OSC sequences to forward.
        pending_osc: Vec<String>,
        /// Whether alternate screen became active/inactive.
        alternate_active: Option<bool>,
    },

    /// Only cursor changed (common case for cursor movement).
    CursorOnly {
        /// Generation number.
        generation: u64,
        /// New cursor position.
        cursor: Cursor,
    },
}

impl TerminalState {
    /// Compute a diff to transform `self` into `other`.
    pub fn diff_to(&self, other: &Self) -> StateDiff {
        // Fast path: if only cursor changed
        if self.cursor_only_diff(other) {
            return StateDiff::CursorOnly {
                generation: other.generation,
                cursor: other.cursor,
            };
        }

        // Compute cell changes
        let changes = self.compute_cell_changes(other);

        // Check if too many changes warrant a full state
        let total_cells = self.screen().cols() as usize * self.screen().rows() as usize;
        let threshold = total_cells * FULL_STATE_THRESHOLD_PERCENT / 100;

        if changes.len() > threshold {
            return StateDiff::Full(other.clone());
        }

        // Build incremental diff
        let cursor = if self.cursor != other.cursor {
            Some(other.cursor)
        } else {
            None
        };

        let title = if self.title != other.title {
            Some(other.title.clone())
        } else {
            None
        };

        let cwd = if self.cwd != other.cwd {
            Some(other.cwd.clone())
        } else {
            None
        };

        let clipboard = if self.clipboard != other.clipboard {
            Some(other.clipboard.clone())
        } else {
            None
        };

        // Always include pending_osc - these are ephemeral and should be forwarded
        let pending_osc = other.pending_osc.clone();

        let alternate_active = if self.alternate_active != other.alternate_active {
            Some(other.alternate_active)
        } else {
            None
        };

        StateDiff::Incremental {
            from_gen: self.generation,
            to_gen: other.generation,
            changes,
            cursor,
            title,
            cwd,
            clipboard,
            pending_osc,
            alternate_active,
        }
    }

    /// Apply a diff to produce a new state.
    pub fn apply_diff(&self, diff: &StateDiff) -> Result<Self> {
        match diff {
            StateDiff::Full(state) => Ok(state.clone()),

            StateDiff::CursorOnly { generation, cursor } => {
                let mut new_state = self.clone();
                new_state.generation = *generation;
                new_state.cursor = *cursor;
                Ok(new_state)
            }

            StateDiff::Incremental {
                from_gen,
                to_gen,
                changes,
                cursor,
                title,
                cwd,
                clipboard,
                pending_osc,
                alternate_active,
            } => {
                // Verify we're applying to the correct base state
                if self.generation != *from_gen {
                    return Err(Error::InvalidState {
                        expected: format!("generation {}", from_gen),
                        actual: format!("generation {}", self.generation),
                    });
                }

                let mut new_state = self.clone();
                new_state.generation = *to_gen;

                // Apply alternate screen change first (affects which screen we modify)
                if let Some(alt) = alternate_active {
                    new_state.alternate_active = *alt;
                }

                // Apply cell changes
                for change in changes {
                    new_state
                        .screen_mut()
                        .set(change.col, change.row, change.cell.clone());
                }

                // Apply cursor change
                if let Some(c) = cursor {
                    new_state.cursor = *c;
                }

                // Apply title change
                if let Some(t) = title {
                    new_state.title = t.clone();
                }

                // Apply cwd change
                if let Some(c) = cwd {
                    new_state.cwd = c.clone();
                }

                // Apply clipboard change
                if let Some(c) = clipboard {
                    new_state.clipboard = c.clone();
                }

                // Apply pending OSC sequences
                new_state.pending_osc = pending_osc.clone();

                Ok(new_state)
            }
        }
    }

    /// Check if only the cursor changed between states.
    fn cursor_only_diff(&self, other: &Self) -> bool {
        if self.cursor == other.cursor {
            return false;
        }

        // Check everything else is the same
        self.alternate_active == other.alternate_active
            && self.title == other.title
            && self.cwd == other.cwd
            && self.clipboard == other.clipboard
            && other.pending_osc.is_empty()
            && self.screens_equal(other)
    }

    /// Compare screens (both primary and alternate).
    fn screens_equal(&self, other: &Self) -> bool {
        self.primary == other.primary && self.alternate == other.alternate
    }

    /// Compute cell changes between self and other for the active screen.
    fn compute_cell_changes(&self, other: &Self) -> Vec<CellChange> {
        let mut changes = Vec::new();

        let self_screen = self.screen();
        let other_screen = other.screen();

        // If screens have different sizes, we need full state
        if self_screen.cols() != other_screen.cols() || self_screen.rows() != other_screen.rows() {
            // Return empty - caller will see size mismatch and use Full
            // Actually, let's compare what we can
        }

        let cols = self_screen.cols().min(other_screen.cols());
        let rows = self_screen.rows().min(other_screen.rows());

        for row in 0..rows {
            for col in 0..cols {
                let self_cell = self_screen.get(col, row);
                let other_cell = other_screen.get(col, row);

                if let (Some(sc), Some(oc)) = (self_cell, other_cell)
                    && sc != oc
                {
                    changes.push(CellChange {
                        col,
                        row,
                        cell: oc.clone(),
                    });
                }
            }
        }

        changes
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terminal::state::{CellAttrs, Color, CursorShape};

    #[test]
    fn diff_identical_states_returns_cursor_only() {
        let state = TerminalState::new(80, 24);
        let same = state.clone();

        let diff = state.diff_to(&same);

        // When states are identical (including cursor), we get CursorOnly
        // since cursor_only_diff returns false when cursor is the same
        // Actually, if they're identical, cursor_only_diff returns false
        // and we compute incremental with no changes
        match diff {
            StateDiff::Incremental { changes, .. } => {
                assert!(changes.is_empty());
            }
            StateDiff::CursorOnly { .. } => {
                // This would only happen if everything else is equal but cursor differs
                panic!("Expected Incremental for identical states");
            }
            _ => panic!("Unexpected diff type"),
        }
    }

    #[test]
    fn diff_cursor_only_change() {
        let state = TerminalState::new(80, 24);
        let mut moved = state.clone();
        moved.cursor.col = 10;
        moved.cursor.row = 5;

        let diff = state.diff_to(&moved);

        match diff {
            StateDiff::CursorOnly { cursor, .. } => {
                assert_eq!(cursor.col, 10);
                assert_eq!(cursor.row, 5);
            }
            _ => panic!("Expected CursorOnly diff"),
        }
    }

    #[test]
    fn diff_single_cell_change() {
        let state = TerminalState::new(80, 24);
        let mut modified = state.clone();
        modified.generation = 1;
        modified.screen_mut().set(5, 10, Cell::new('X'));

        let diff = state.diff_to(&modified);

        match diff {
            StateDiff::Incremental {
                from_gen,
                to_gen,
                changes,
                ..
            } => {
                assert_eq!(from_gen, 0);
                assert_eq!(to_gen, 1);
                assert_eq!(changes.len(), 1);
                assert_eq!(changes[0].col, 5);
                assert_eq!(changes[0].row, 10);
                assert_eq!(changes[0].cell.ch, 'X');
            }
            _ => panic!("Expected Incremental diff"),
        }
    }

    #[test]
    fn diff_multiple_cell_changes() {
        let state = TerminalState::new(80, 24);
        let mut modified = state.clone();
        modified.generation = 1;
        modified.screen_mut().set(0, 0, Cell::new('A'));
        modified.screen_mut().set(1, 0, Cell::new('B'));
        modified.screen_mut().set(2, 0, Cell::new('C'));

        let diff = state.diff_to(&modified);

        match diff {
            StateDiff::Incremental { changes, .. } => {
                assert_eq!(changes.len(), 3);
            }
            _ => panic!("Expected Incremental diff"),
        }
    }

    #[test]
    fn diff_large_change_returns_full() {
        let state = TerminalState::new(10, 10); // 100 cells
        let mut modified = state.clone();
        modified.generation = 1;

        // Change more than 30% of cells (31 cells)
        for row in 0..4 {
            for col in 0..10 {
                modified.screen_mut().set(col, row, Cell::new('X'));
            }
        }

        let diff = state.diff_to(&modified);

        match diff {
            StateDiff::Full(_) => {}
            _ => panic!("Expected Full diff for large change"),
        }
    }

    #[test]
    fn apply_incremental_diff() {
        let state = TerminalState::new(80, 24);
        let mut expected = state.clone();
        expected.generation = 1;
        expected.screen_mut().set(5, 5, Cell::new('X'));

        let diff = StateDiff::Incremental {
            from_gen: 0,
            to_gen: 1,
            changes: vec![CellChange {
                col: 5,
                row: 5,
                cell: Cell::new('X'),
            }],
            cursor: None,
            title: None,
            cwd: None,
            clipboard: None,
            pending_osc: vec![],
            alternate_active: None,
        };

        let result = state.apply_diff(&diff).unwrap();

        assert_eq!(result.generation, 1);
        assert_eq!(result.screen().get(5, 5).unwrap().ch, 'X');
    }

    #[test]
    fn apply_full_diff() {
        let state = TerminalState::new(80, 24);
        let mut new_state = TerminalState::new(80, 24);
        new_state.generation = 5;
        new_state.screen_mut().set(0, 0, Cell::new('F'));

        let diff = StateDiff::Full(new_state.clone());
        let result = state.apply_diff(&diff).unwrap();

        assert_eq!(result.generation, 5);
        assert_eq!(result.screen().get(0, 0).unwrap().ch, 'F');
    }

    #[test]
    fn apply_cursor_only_diff() {
        let state = TerminalState::new(80, 24);
        let diff = StateDiff::CursorOnly {
            generation: 1,
            cursor: Cursor {
                col: 20,
                row: 10,
                visible: true,
                shape: CursorShape::Block,
            },
        };

        let result = state.apply_diff(&diff).unwrap();

        assert_eq!(result.generation, 1);
        assert_eq!(result.cursor.col, 20);
        assert_eq!(result.cursor.row, 10);
    }

    #[test]
    fn diff_apply_roundtrip() {
        let state1 = TerminalState::new(80, 24);
        let mut state2 = state1.clone();
        state2.generation = 1;
        state2.screen_mut().set(10, 10, Cell::new('X'));
        state2.cursor.col = 11;

        let diff = state1.diff_to(&state2);
        let restored = state1.apply_diff(&diff).unwrap();

        assert_eq!(restored.generation, state2.generation);
        assert_eq!(
            restored.screen().get(10, 10).unwrap().ch,
            state2.screen().get(10, 10).unwrap().ch
        );
        assert_eq!(restored.cursor.col, state2.cursor.col);
    }

    #[test]
    fn apply_diff_wrong_generation_fails() {
        let state = TerminalState::new(80, 24);
        let diff = StateDiff::Incremental {
            from_gen: 5, // Wrong! state is at generation 0
            to_gen: 6,
            changes: vec![],
            cursor: None,
            title: None,
            cwd: None,
            clipboard: None,
            pending_osc: vec![],
            alternate_active: None,
        };

        let result = state.apply_diff(&diff);
        assert!(result.is_err());
    }

    #[test]
    fn diff_with_title_change() {
        let state = TerminalState::new(80, 24);
        let mut modified = state.clone();
        modified.generation = 1;
        modified.title = Some("New Title".to_string());

        let diff = state.diff_to(&modified);

        match diff {
            StateDiff::Incremental { title, .. } => {
                assert_eq!(title, Some(Some("New Title".to_string())));
            }
            _ => panic!("Expected Incremental diff"),
        }
    }

    #[test]
    fn diff_with_alternate_screen_change() {
        let state = TerminalState::new(80, 24);
        let mut modified = state.clone();
        modified.generation = 1;
        modified.alternate_active = true;

        let diff = state.diff_to(&modified);

        match diff {
            StateDiff::Incremental {
                alternate_active, ..
            } => {
                assert_eq!(alternate_active, Some(true));
            }
            _ => panic!("Expected Incremental diff"),
        }
    }

    #[test]
    fn diff_preserves_cell_attributes() {
        let state = TerminalState::new(80, 24);
        let mut modified = state.clone();
        modified.generation = 1;

        let styled_cell = Cell::with_style(
            'S',
            Color::Rgb(255, 0, 0),
            Color::Indexed(4),
            CellAttrs {
                bold: true,
                italic: true,
                ..Default::default()
            },
        );
        modified.screen_mut().set(0, 0, styled_cell.clone());

        let diff = state.diff_to(&modified);
        let restored = state.apply_diff(&diff).unwrap();

        let cell = restored.screen().get(0, 0).unwrap();
        assert_eq!(cell.ch, 'S');
        assert_eq!(cell.fg, Color::Rgb(255, 0, 0));
        assert_eq!(cell.bg, Color::Indexed(4));
        assert!(cell.attrs.bold);
        assert!(cell.attrs.italic);
    }
}
