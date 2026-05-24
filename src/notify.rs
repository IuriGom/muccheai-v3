//! Desktop notifications for macOS.
//!
//! Uses AppleScript via `osascript` to display native user notifications.

use tracing;

const MAX_TITLE_LEN: usize = 256;
const MAX_MESSAGE_LEN: usize = 1024;

/// Escape a string for safe inclusion in an AppleScript string literal.
/// Only permits a strict whitelist of characters to prevent injection
/// via backticks, $(), Unicode homoglyphs, or other AppleScript tricks.
/// Returns `None` if the input exceeds safe length limits or contains
/// disallowed characters.
fn escape_applescript(s: &str, max_len: usize) -> Option<String> {
    if s.len() > max_len {
        return None;
    }
    if !s.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || c == ' '
            || c == '.'
            || c == ','
            || c == '!'
            || c == '?'
            || c == ':'
            || c == '-'
            || c == '_'
    }) {
        return None;
    }
    Some(s.replace('"', "\"\""))
}

/// Send a native macOS notification with the given title and message.
/// Silently skips if inputs are too long or osascript fails.
pub fn notify(title: &str, message: &str) {
    let (safe_title, safe_message) = match (
        escape_applescript(title, MAX_TITLE_LEN),
        escape_applescript(message, MAX_MESSAGE_LEN),
    ) {
        (Some(t), Some(m)) => (t, m),
        _ => {
            tracing::warn!("Notification title/message too long; skipping");
            return;
        }
    };
    let script = format!(
        r#"display notification "{}" with title "{}""#,
        safe_message, safe_title
    );
    run_osascript(&script);
}

/// Send a warning notification.
pub fn notify_warning(title: &str, message: &str) {
    let (safe_title, safe_message) = match (
        escape_applescript(title, MAX_TITLE_LEN),
        escape_applescript(message, MAX_MESSAGE_LEN),
    ) {
        (Some(t), Some(m)) => (t, m),
        _ => {
            tracing::warn!("Notification title/message too long; skipping");
            return;
        }
    };
    let script = format!(
        r#"display notification "{}" with title "{}" sound name "Basso""#,
        safe_message, safe_title
    );
    run_osascript(&script);
}

/// Send an error notification.
pub fn notify_error(title: &str, message: &str) {
    let (safe_title, safe_message) = match (
        escape_applescript(title, MAX_TITLE_LEN),
        escape_applescript(message, MAX_MESSAGE_LEN),
    ) {
        (Some(t), Some(m)) => (t, m),
        _ => {
            tracing::warn!("Notification title/message too long; skipping");
            return;
        }
    };
    let script = format!(
        r#"display notification "{}" with title "{}" sound name "Basso""#,
        safe_message, safe_title
    );
    run_osascript(&script);
}

/// Run an AppleScript via osascript through stdin to avoid any command-line
/// injection or argument-parsing issues.
fn run_osascript(script: &str) {
    use std::io::Write;
    let osascript = match std::fs::canonicalize("/usr/bin/osascript") {
        Ok(p) => p,
        Err(_) => {
            tracing::warn!("osascript not found at /usr/bin/osascript");
            return;
        }
    };
    if !osascript.to_string_lossy().starts_with("/usr/bin/") {
        tracing::warn!("osascript path unexpected: {}", osascript.display());
        return;
    }
    if let Ok(mut child) = std::process::Command::new(&osascript)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(script.as_bytes());
        }
        match child.wait_with_output() {
            Ok(output) if !output.status.success() => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                tracing::warn!("osascript failed: {}", stderr);
            }
            Err(e) => {
                tracing::warn!("Failed to run osascript: {}", e);
            }
            _ => {}
        }
    }
}
