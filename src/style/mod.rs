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

pub use progress::{bell, milk_progress_bar, start_thinking_spinner};
pub use risk::{ConfirmationType, RiskLevel};
pub use theme::Theme;
pub use words::THINKING_WORDS;
