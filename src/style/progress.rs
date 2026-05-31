use indicatif::{ProgressBar, ProgressStyle};
use super::words::THINKING_WORDS;
pub fn milk_progress_bar(len: u64) -> ProgressBar {
    let pb = ProgressBar::new(len);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.cyan} 🥛 {msg} [{bar:40.cyan/blue}] {pos}/{len}")
            .unwrap()
            .progress_chars("▓▒░")
            .tick_strings(&["💧", "🥛", "💦", "🍼", "💧"]),
    );
    pb
}

/// Starts a background thinking spinner that cycles through hard words
/// with a cow emoji. Returns a flag to stop it.
///
/// Use this while waiting for the LLM to respond in blocking contexts.
pub fn start_thinking_spinner() -> std::sync::Arc<std::sync::atomic::AtomicBool> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();

    thread::spawn(move || {
        let mut idx = 0;
        while running_clone.load(Ordering::SeqCst) {
            let word = THINKING_WORDS[idx % THINKING_WORDS.len()];
            eprint!("\r🐄  {}... ", word);
            idx += 1;
            thread::sleep(Duration::from_millis(800));
        }
        eprint!("\r{: <60}\r", ""); // clear line
    });

    running
}

/// Prints a terminal bell character to stderr.
pub fn bell() {
    eprint!("\x07");
}

