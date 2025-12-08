//! Client overlay display.
//!
//! Provides visual overlays for:
//! - Predicted character display (underlined/dim)
//! - Connection status widget
//! - RTT and metrics display
//! - Mosh-style notification bar

mod notification;
mod prediction_display;
mod status_widget;

pub use notification::{NotificationEngine, NotificationStyle};
pub use prediction_display::PredictionOverlay;
pub use status_widget::{ConnectionMetrics, ConnectionStatus, OverlayPosition, StatusOverlay};
