//! Client overlay display.
//!
//! Provides visual overlays for:
//! - Predicted character display (underlined/dim)
//! - Connection status widget
//! - RTT and metrics display

mod prediction_display;
mod status_widget;

pub use prediction_display::PredictionOverlay;
pub use status_widget::{ConnectionMetrics, OverlayPosition, StatusOverlay};
