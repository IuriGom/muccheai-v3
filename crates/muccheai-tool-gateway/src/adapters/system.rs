//! System tool adapters
//!
//! Includes: notifications

use muccheai_types::{ToolError, ToolResult, ToolResultMetadata};
use serde_json::json;

/// Notifications adapter — send OS notifications via AppleScript on macOS.
pub fn notifications_send(params: &serde_json::Value) -> Result<ToolResult, ToolError> {
    let title = params
        .get("title")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ToolError::InvalidParams("Missing 'title'".to_string()))?;
    let message = params
        .get("message")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ToolError::InvalidParams("Missing 'message'".to_string()))?;

    // On macOS we could use `osascript -e 'display notification ...'`
    #[cfg(target_os = "macos")]
    {
        // Strictly restrict characters to a known-safe subset.
        // Only alphanumeric, space, and common punctuation are allowed.
        // This prevents any possible AppleScript injection via Unicode
        // homoglyphs, backslash escapes, shell-like substitutions, etc.
        let is_safe = |s: &str| {
            s.chars().all(|c| {
                c.is_ascii_alphanumeric()
                    || c == ' '
                    || c == '.'
                    || c == ','
                    || c == '!'
                    || c == '?'
                    || c == ':'
                    || c == '-'
                    || c == '_'
            })
        };
        if !is_safe(message) || !is_safe(title) {
            return Err(ToolError::InvalidParams(
                "Notification text contains invalid characters".to_string(),
            ));
        }
        // AppleScript uses "" to escape quotes, not \".
        let safe_message = message.replace('"', "\"\"");
        let safe_title = title.replace('"', "\"\"");
        let script = format!(
            r#"display notification "{}" with title "{}""#,
            safe_message, safe_title
        );
        // Pass the script via stdin instead of -e to avoid any command-line
        // injection or argument-parsing issues.
        use std::io::Write;
        if let Ok(mut child) = std::process::Command::new("osascript")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
        {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(script.as_bytes());
            }
            let _ = child.wait_with_output();
        }
    }

    Ok(ToolResult {
        success: true,
        data: json!({
            "status": "sent",
            "title": title,
            "message": message
        }),
        metadata: ToolResultMetadata {
            execution_time_ms: 0,
            tool_id: "notifications".to_string(),
            method: "send".to_string(),
        },
    })
}
