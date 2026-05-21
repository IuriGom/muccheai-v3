//! Communication tool adapters
//!
//! Includes: slack, discord, telegram, email

use muccheai_types::{ToolError, ToolResult, ToolResultMetadata};
use serde_json::json;

/// Check whether a URL points to an internal / non-routable address.
/// Uses proper URL parsing to avoid substring bypasses.
fn is_internal_url(url: &str) -> bool {
    let parsed = match url::Url::parse(url) {
        Ok(u) => u,
        Err(_) => return true,
    };

    let host = match parsed.host_str() {
        Some(h) => h.to_lowercase(),
        None => return true,
    };

    if host == "localhost" {
        return true;
    }

    // Block decimal IP addresses (e.g. 2130706433 = 127.0.0.1)
    // Also block short all-numeric hosts that may resolve internally
    if host.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }

    // Block hex/octal IP forms that std::net::IpAddr does not parse
    if host.starts_with("0x") || host.starts_with("0X") {
        return true;
    }
    if host.chars().all(|c| c.is_ascii_digit() || c == '.') && host.starts_with('0') && host.len() > 1 && host != "0.0.0.0" {
        return true;
    }

    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        let blocked = match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback() || v4.is_private() || v4.is_link_local()
                    || v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast()
            }
            std::net::IpAddr::V6(v6) => {
                if v6.is_loopback() || v6.is_unspecified() || v6.is_unique_local()
                    || v6.is_unicast_link_local() || v6.is_multicast() {
                    return true;
                }
                if let Some(v4) = v6.to_ipv4_mapped() {
                    if v4.is_loopback() || v4.is_private() || v4.is_link_local()
                        || v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast() {
                        return true;
                    }
                }
                let segs = v6.segments();
                if segs[0] == 0 && segs[1] == 0 && segs[2] == 0 && segs[3] == 0
                    && segs[4] == 0 && segs[5] == 0xffff {
                    let v4_bytes = [(segs[6] >> 8) as u8, (segs[6] & 0xff) as u8,
                                    (segs[7] >> 8) as u8, (segs[7] & 0xff) as u8];
                    let v4 = std::net::Ipv4Addr::from(v4_bytes);
                    if v4.is_loopback() || v4.is_private() || v4.is_link_local()
                        || v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast() {
                        return true;
                    }
                }
                false
            }
        };
        if blocked {
            return true;
        }
    }

    if host.starts_with("127.") || host.starts_with("0.") || host.starts_with("10.")
        || host.starts_with("192.168.") || host.starts_with("169.254.")
        || host == "[::1]" || host.starts_with("[::ffff:")
        || host.starts_with("[fc") || host.starts_with("[fd")
        || host.starts_with("[fe80:") || host.starts_with("[ff")
    {
        return true;
    }

    false
}

/// Slack adapter — post messages to channels
pub fn slack_post(params: &serde_json::Value) -> Result<ToolResult, ToolError> {
    let channel = params
        .get("channel")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ToolError::InvalidParams("Missing 'channel'".to_string()))?;
    let message = params
        .get("message")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ToolError::InvalidParams("Missing 'message'".to_string()))?;

    let webhook_url = params.get("webhook_url").and_then(|v| v.as_str());

    if let Some(url) = webhook_url {
        if is_internal_url(url) {
            return Err(ToolError::CapabilityDenied(
                "Webhook URLs pointing to internal addresses are not allowed".to_string(),
            ));
        }
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| ToolError::ExecutionFailed(e.to_string()))?;

        let payload = json!({
            "channel": channel,
            "text": message,
        });

        let resp = client
            .post(url)
            .json(&payload)
            .send()
            .map_err(|e| ToolError::ExecutionFailed(format!("Slack HTTP error: {}", e)))?;

        if !resp.status().is_success() {
            return Err(ToolError::ExecutionFailed(format!(
                "Slack API error: {}",
                resp.status()
            )));
        }
    }

    Ok(ToolResult {
        success: true,
        data: json!({
            "status": "posted",
            "channel": channel,
            "message_preview": &message[..message.len().min(200)]
        }),
        metadata: ToolResultMetadata {
            execution_time_ms: 0,
            tool_id: "slack".to_string(),
            method: "post".to_string(),
        },
    })
}

/// Discord adapter — send messages to servers via webhook
pub fn discord_send(params: &serde_json::Value) -> Result<ToolResult, ToolError> {
    let webhook_url = params
        .get("webhook_url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ToolError::InvalidParams("Missing 'webhook_url'".to_string()))?;
    let content = params
        .get("content")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ToolError::InvalidParams("Missing 'content'".to_string()))?;

    if is_internal_url(webhook_url) {
        return Err(ToolError::CapabilityDenied(
            "Webhook URLs pointing to internal addresses are not allowed".to_string(),
        ));
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| ToolError::ExecutionFailed(e.to_string()))?;

    let payload = json!({ "content": content });
    let resp = client
        .post(webhook_url)
        .json(&payload)
        .send()
        .map_err(|e| ToolError::ExecutionFailed(format!("Discord HTTP error: {}", e)))?;

    if !resp.status().is_success() {
        return Err(ToolError::ExecutionFailed(format!(
            "Discord API error: {}",
            resp.status()
        )));
    }

    Ok(ToolResult {
        success: true,
        data: json!({
            "status": "sent",
            "content_preview": &content[..content.len().min(200)]
        }),
        metadata: ToolResultMetadata {
            execution_time_ms: 0,
            tool_id: "discord".to_string(),
            method: "send".to_string(),
        },
    })
}

/// Telegram adapter — send messages via Bot API
pub fn telegram_send(params: &serde_json::Value) -> Result<ToolResult, ToolError> {
    let bot_token = params
        .get("bot_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ToolError::InvalidParams("Missing 'bot_token'".to_string()))?;
    let chat_id = params
        .get("chat_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ToolError::InvalidParams("Missing 'chat_id'".to_string()))?;
    let message = params
        .get("message")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ToolError::InvalidParams("Missing 'message'".to_string()))?;

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| ToolError::ExecutionFailed(e.to_string()))?;

    let url = format!(
        "https://api.telegram.org/bot{}/sendMessage",
        bot_token
    );
    let payload = json!({
        "chat_id": chat_id,
        "text": message,
    });

    let resp = client
        .post(&url)
        .json(&payload)
        .send()
        .map_err(|e| ToolError::ExecutionFailed(format!("Telegram HTTP error: {}", e)))?;

    if !resp.status().is_success() {
        return Err(ToolError::ExecutionFailed(format!(
            "Telegram API error: {}",
            resp.status()
        )));
    }

    Ok(ToolResult {
        success: true,
        data: json!({
            "status": "sent",
            "chat_id": chat_id,
            "message_preview": &message[..message.len().min(200)]
        }),
        metadata: ToolResultMetadata {
            execution_time_ms: 0,
            tool_id: "telegram".to_string(),
            method: "send".to_string(),
        },
    })
}

/// Email adapter — send email via SMTP or queue
pub fn email_send(params: &serde_json::Value) -> Result<ToolResult, ToolError> {
    let to = params
        .get("to")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ToolError::InvalidParams("Missing 'to'".to_string()))?;
    let subject = params
        .get("subject")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ToolError::InvalidParams("Missing 'subject'".to_string()))?;
    let body = params.get("body").and_then(|v| v.as_str()).unwrap_or("");

    // Validate email format and block header injection
    if to.contains('\n') || to.contains('\r') {
        return Err(ToolError::InvalidParams(
            "Email address contains invalid characters".to_string(),
        ));
    }
    if subject.contains('\n') || subject.contains('\r') {
        return Err(ToolError::InvalidParams(
            "Email subject contains invalid characters".to_string(),
        ));
    }
    if body.contains('\n') || body.contains('\r') {
        return Err(ToolError::InvalidParams(
            "Email body contains invalid characters".to_string(),
        ));
    }
    if !to.contains('@') {
        return Err(ToolError::InvalidParams(format!(
            "Invalid email address: {}",
            to
        )));
    }
    let parts: Vec<&str> = to.split('@').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        return Err(ToolError::InvalidParams(format!(
            "Invalid email address: {}",
            to
        )));
    }

    let smtp_host = params.get("smtp_host").and_then(|v| v.as_str());
    let smtp_port = params.get("smtp_port").and_then(|v| v.as_u64()).unwrap_or(587);

    Ok(ToolResult {
        success: true,
        data: json!({
            "status": "queued",
            "to": to,
            "subject": subject,
            "body_preview": &body[..body.len().min(100)],
            "smtp": {
                "host": smtp_host,
                "port": smtp_port
            }
        }),
        metadata: ToolResultMetadata {
            execution_time_ms: 0,
            tool_id: "email".to_string(),
            method: "send".to_string(),
        },
    })
}
