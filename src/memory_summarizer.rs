//! Session summarizer.

use crate::web::ChatSession;

/// Returns true if the session has more than 50 messages.
pub fn should_summarize(session: &ChatSession) -> bool {
    session.messages.len() > 50
}

/// Generates a concise summary of the chat session.
///
/// Counts messages per role, extracts key topics from the first few user
/// messages, and surfaces any sentences that look like decisions.
pub fn summarize(session: &ChatSession) -> String {
    let total = session.messages.len();

    let mut user_count = 0usize;
    let mut ai_count = 0usize;
    let mut system_count = 0usize;
    for msg in &session.messages {
        match msg.role.as_str() {
            "user" => user_count += 1,
            "ai" | "assistant" => ai_count += 1,
            "system" => system_count += 1,
            _ => {}
        }
    }

    // Extract topics from first few user messages.
    let topics: Vec<String> = session
        .messages
        .iter()
        .filter(|m| m.role == "user")
        .take(5)
        .map(|m| {
            let c = m.content.trim();
            if c.chars().count() > 60 {
                format!("{}...", c.chars().take(60).collect::<String>())
            } else {
                c.to_string()
            }
        })
        .collect();

    // Look for decision-like keywords in AI replies.
    let decision_keywords = ["decided", "decision", "concluded", "agreed", "recommend", "resolved", "chosen"];
    let decisions: Vec<String> = session
        .messages
        .iter()
        .filter(|m| m.role == "ai" || m.role == "assistant")
        .filter_map(|m| {
            let lower = m.content.to_lowercase();
            if decision_keywords.iter().any(|kw| lower.contains(kw)) {
                let c = m.content.trim();
                Some(if c.chars().count() > 100 {
                    format!("{}...", c.chars().take(100).collect::<String>())
                } else {
                    c.to_string()
                })
            } else {
                None
            }
        })
        .take(3)
        .collect();

    let topics_str = if topics.is_empty() {
        "None identified".to_string()
    } else {
        topics.join("; ")
    };

    let decisions_str = if decisions.is_empty() {
        "None recorded".to_string()
    } else {
        decisions.join("; ")
    };

    format!(
        "Session '{}' ({} messages — {} user, {} AI, {} system). Topics: {}. Key decisions: {}.",
        session.title, total, user_count, ai_count, system_count, topics_str, decisions_str
    )
}
