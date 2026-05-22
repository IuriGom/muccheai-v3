//! System tool adapters
//!
//! Includes: clipboard, screenshot, notifications, cron

use muccheai_types::{ToolError, ToolResult, ToolResultMetadata};
use serde_json::json;

/// Clipboard adapter — read/write clipboard (stub)
pub fn clipboard_read(_params: &serde_json::Value) -> Result<ToolResult, ToolError> {
    Ok(ToolResult {
        success: true,
        data: json!({
            "text": "",
            "note": "Clipboard read requires platform-specific integration (arboard/native APIs)"
        }),
        metadata: ToolResultMetadata {
            execution_time_ms: 0,
            tool_id: "clipboard".to_string(),
            method: "read".to_string(),
        },
    })
}

/// Clipboard write adapter (stub)
pub fn clipboard_write(params: &serde_json::Value) -> Result<ToolResult, ToolError> {
    let text = params
        .get("text")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ToolError::InvalidParams("Missing 'text'".to_string()))?;

    Ok(ToolResult {
        success: true,
        data: json!({
            "status": "written",
            "length": text.len(),
            "note": "Clipboard write requires platform-specific integration"
        }),
        metadata: ToolResultMetadata {
            execution_time_ms: 0,
            tool_id: "clipboard".to_string(),
            method: "write".to_string(),
        },
    })
}

/// Screenshot adapter — capture screen (stub)
pub fn screenshot_capture(_params: &serde_json::Value) -> Result<ToolResult, ToolError> {
    Ok(ToolResult {
        success: true,
        data: json!({
            "status": "captured",
            "path": "",
            "note": "Screenshot requires platform-specific APIs (screencapture, grim, etc.)"
        }),
        metadata: ToolResultMetadata {
            execution_time_ms: 0,
            tool_id: "screenshot".to_string(),
            method: "capture".to_string(),
        },
    })
}

/// Notifications adapter — send OS notifications (stub)
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

/// Cron adapter — schedule recurring tasks (stub)
pub fn cron_schedule(params: &serde_json::Value) -> Result<ToolResult, ToolError> {
    let expression = params
        .get("expression")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ToolError::InvalidParams("Missing 'expression' (cron format)".to_string()))?;
    let command = params
        .get("command")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ToolError::InvalidParams("Missing 'command'".to_string()))?;

    // Basic cron validation (5 fields)
    let fields: Vec<&str> = expression.split_whitespace().collect();
    if fields.len() != 5 {
        return Err(ToolError::InvalidParams(
            "Cron expression must have 5 fields: min hour day month weekday".to_string(),
        ));
    }

    Ok(ToolResult {
        success: true,
        data: json!({
            "status": "scheduled",
            "expression": expression,
            "command": command,
            "note": "Cron scheduling requires a persistent scheduler daemon"
        }),
        metadata: ToolResultMetadata {
            execution_time_ms: 0,
            tool_id: "cron".to_string(),
            method: "schedule".to_string(),
        },
    })
}
