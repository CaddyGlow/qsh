//! Prediction engine for local echo.
//!
//! Provides predictive local echo to hide network latency by
//! displaying typed characters immediately with visual distinction,
//! then confirming or rolling back based on server response.

mod cursor;
mod engine;
mod state;
mod types;

#[cfg(test)]
mod tests;

pub use engine::PredictionEngine;
pub use state::{DisplayPreference, PredictedStyle, PredictionState};
pub use types::{CellPrediction, PredictedEcho, Prediction};
