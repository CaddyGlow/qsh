//! Prediction state types.
//!
//! Defines the various states and display preferences for the prediction engine.

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
