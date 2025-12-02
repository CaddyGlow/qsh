//! Prediction engine for local echo.
//!
//! Provides predictive local echo to hide network latency by
//! displaying typed characters immediately with visual distinction,
//! then confirming or rolling back based on server response.

mod engine;

pub use engine::{PredictedEcho, PredictedStyle, Prediction, PredictionEngine, PredictionState};
