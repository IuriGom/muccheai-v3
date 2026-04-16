//! Session compaction
//!
//! When session context exceeds a threshold, summarize old messages,
//! flush notes to episodic memory, and append a compaction marker.

use anyhow::Result;

use crate::episodic::EpisodicMemory;
use crate::transcript::{ContentBlock, Role, SessionTranscript, TranscriptEntry};

/// Threshold: compact when transcript exceeds this many entries.
const COMPACTION_THRESHOLD: usize = 20;
/// Number of recent entries to preserve after compaction.
const PRESERVE_COUNT: usize = 10;

/// Summarize old messages and append a compaction entry.
pub fn compact(
    transcript: &mut SessionTranscript,
    episodic: &EpisodicMemory,
) -> Result<bool> {
    if transcript.len() <= COMPACTION_THRESHOLD {
        return Ok(false);
    }

    let to_summarize = &transcript.entries[..transcript.len() - PRESERVE_COUNT];
    let summary_text = generate_summary(to_summarize);
    episodic.write_note(&format!(
        "Session {} compaction: {}",
        transcript.id, summary_text
    ))?;

    let preserved_ids: Vec<String> = transcript.entries[transcript.len() - PRESERVE_COUNT..]
        .iter()
        .map(|e| e.id.clone())
        .collect();

    transcript.append_compaction(&summary_text, &preserved_ids)?;

    Ok(true)
}

fn generate_summary(entries: &[TranscriptEntry]) -> String {
    let mut user_msgs = Vec::new();
    let mut assistant_msgs = Vec::new();

    for entry in entries {
        match entry.role {
            Role::User => {
                for block in &entry.content {
                    if let ContentBlock::Text { text } = block {
                        user_msgs.push(text.clone());
                    }
                }
            }
            Role::Assistant => {
                for block in &entry.content {
                    if let ContentBlock::Text { text } = block {
                        assistant_msgs.push(text.clone());
                    }
                }
            }
            _ => {}
        }
    }

    let user_summary = if user_msgs.len() > 3 {
        format!(
            "{} user messages, starting with: {}",
            user_msgs.len(),
            &user_msgs[0][..user_msgs[0].len().min(80)]
        )
    } else {
        format!("User messages: {}", user_msgs.join("; "))
    };

    let assistant_summary = if assistant_msgs.len() > 3 {
        format!("{} assistant responses", assistant_msgs.len())
    } else {
        format!("Assistant responses: {}", assistant_msgs.join("; "))
    };

    format!("{} | {}", user_summary, assistant_summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transcript::{generate_session_slug, now_secs};
    use tempfile::TempDir;

    #[test]
    fn test_no_compact_under_threshold() {
        let tmp = TempDir::new().unwrap();
        let mut tx = SessionTranscript::new(tmp.path(), &generate_session_slug()).unwrap();
        let ep = EpisodicMemory::new(tmp.path());

        for i in 0..5 {
            tx.append(TranscriptEntry {
                id: format!("msg-{}", i),
                parent_id: None,
                role: Role::User,
                content: vec![ContentBlock::Text {
                    text: format!("message {}", i),
                }],
                timestamp: now_secs(),
            })
            .unwrap();
        }

        assert!(!compact(&mut tx, &ep).unwrap());
    }

    #[test]
    fn test_compact_over_threshold() {
        let tmp = TempDir::new().unwrap();
        let mut tx = SessionTranscript::new(tmp.path(), &generate_session_slug()).unwrap();
        let ep = EpisodicMemory::new(tmp.path());

        for i in 0..25 {
            tx.append(TranscriptEntry {
                id: format!("msg-{}", i),
                parent_id: None,
                role: if i % 2 == 0 {
                    Role::User
                } else {
                    Role::Assistant
                },
                content: vec![ContentBlock::Text {
                    text: format!("message {}", i),
                }],
                timestamp: now_secs(),
            })
            .unwrap();
        }

        assert!(compact(&mut tx, &ep).unwrap());

        // Check that a compaction entry was added
        let has_compaction = tx.entries.iter().any(|e| {
            e.id.starts_with("compaction-") && matches!(e.role, Role::Assistant)
        });
        assert!(has_compaction);

        // Check that a daily note was written
        let notes = ep.read_recent(1).unwrap();
        assert_eq!(notes.len(), 1);
        assert!(notes[0].1.contains("compaction"));
    }
}
