//! Desktop notifications for macOS.
//!
//! Uses AppleScript via `osascript` to display native user notifications.

/// Escape a string for safe inclusion in an AppleScript string literal.
/// Replaces backslash first, then quotes, to prevent injection.
fn escape_applescript(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace('\r', " ").replace('\n', " ")
}

/// Send a native macOS notification with the given title and message.
pub fn notify(title: &str, message: &str) {
    let safe_title = escape_applescript(title);
    let safe_message = escape_applescript(message);
    let script = format!(
        r#"display notification "{}" with title "{}""#,
        safe_message, safe_title
    );
    let _ = std::process::Command::new("osascript")
        .arg("-e")
        .arg(&script)
        .output();
}

/// Send a warning notification.
pub fn notify_warning(title: &str, message: &str) {
    let safe_title = escape_applescript(title);
    let safe_message = escape_applescript(message);
    let script = format!(
        r#"display notification "{}" with title "{}" sound name "Basso""#,
        safe_message, safe_title
    );
    let _ = std::process::Command::new("osascript")
        .arg("-e")
        .arg(&script)
        .output();
}

/// Send an error notification.
pub fn notify_error(title: &str, message: &str) {
    let safe_title = escape_applescript(title);
    let safe_message = escape_applescript(message);
    let script = format!(
        r#"display notification "{}" with title "{}" sound name "Basso""#,
        safe_message, safe_title
    );
    let _ = std::process::Command::new("osascript")
        .arg("-e")
        .arg(&script)
        .output();
}
