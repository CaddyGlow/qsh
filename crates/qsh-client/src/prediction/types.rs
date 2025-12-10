//! Prediction data types.
//!
//! Defines the core data structures used for tracking predictions.

use std::time::Instant;

use crate::prediction::state::PredictedStyle;

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
