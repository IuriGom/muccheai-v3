//! Terminal styling and UX helpers.

pub mod easter_eggs;
pub mod progress;
pub mod risk;
pub mod theme;
pub mod words;

use std::sync::atomic::AtomicBool;

/// Global flag that suppresses all decorative output.
/// Set to `true` when `--json` mode is active.
pub static JSON_MODE: AtomicBool = AtomicBool::new(false);

pub use progress::milk_progress_bar;
pub use risk::RiskLevel;
pub use theme::Theme;
