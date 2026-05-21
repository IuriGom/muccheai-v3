//! Desktop notifications for macOS.
//!
//! Uses AppleScript via `osascript` to display native user notifications.

use tracing;

const MAX_TITLE_LEN: usize = 256;
const MAX_MESSAGE_LEN: usize = 1024;

/// Escape a string for safe inclusion in an AppleScript string literal.
/// Replaces backslash first, then quotes, to prevent injection.
/// Returns `None` if the input exceeds safe length limits.
fn escape_applescript(s: &str, max_len: usize) -> Option<String> {
    if s.len() > max_len {
        return None;
    }
    Some(
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\r', " ")
            .replace('\n', " "),
    )
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
    match std::process::Command::new("osascript")
        .arg("-e")
        .arg(&script)
        .output()
    {
        Ok(output) if !output.status.success() => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!("osascript notification failed: {}", stderr);
        }
        Err(e) => {
            tracing::warn!("Failed to run osascript: {}", e);
        }
        _ => {}
    }
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
    match std::process::Command::new("osascript")
        .arg("-e")
        .arg(&script)
        .output()
    {
        Ok(output) if !output.status.success() => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!("osascript warning failed: {}", stderr);
        }
        Err(e) => {
            tracing::warn!("Failed to run osascript: {}", e);
        }
        _ => {}
    }
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
    match std::process::Command::new("osascript")
        .arg("-e")
        .arg(&script)
        .output()
    {
        Ok(output) if !output.status.success() => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!("osascript error notification failed: {}", stderr);
        }
        Err(e) => {
            tracing::warn!("Failed to run osascript: {}", e);
        }
        _ => {}
    }
}
