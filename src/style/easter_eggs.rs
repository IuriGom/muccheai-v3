use super::JSON_MODE;
use rand::Rng;
use std::sync::atomic::Ordering;

/// 5 % chance to print a fun Italian phrase on high-risk approval success.
pub fn high_risk_approval() {
    maybe_say("Mamma mia, that was close.");
}

/// 5 % chance to print a fun Italian phrase on system lockdown.
pub fn lockdown() {
    maybe_say("Andiamo... everything is frozen.");
}

/// 5 % chance to print a fun Italian phrase on anomaly detection.
pub fn anomaly() {
    maybe_say("Mamma mia! Something's not right.");
}

/// 5 % chance to print a fun Italian phrase on setup completion.
pub fn setup_complete() {
    maybe_say("Perfetto! Your cows are secured.");
}

fn maybe_say(phrase: &str) {
    if JSON_MODE.load(Ordering::SeqCst) {
        return;
    }
    if rand::thread_rng().gen_ratio(5, 100) {
        println!("  ☕ {}", phrase);
    }
}
