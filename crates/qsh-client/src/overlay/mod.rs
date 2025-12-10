//! Client overlay display.
//!
//! Provides visual overlays for:
//! - Predicted character display (underlined/dim)
//! - Mosh-style notification bar

pub mod notification;
mod prediction_display;

pub use notification::{NotificationEngine, NotificationStyle};
pub use prediction_display::PredictionOverlay;
