//! MuccheAI v3.0 — Memory System
//!
//! Implements the OpenClaw filesystem architecture:
//! - Session transcripts (JSONL)
//! - Daily episodic memory (Markdown)
//! - Semantic long-term memory (MEMORY.md)
//! - Hybrid search index (SQLite + FTS5 + vector)

#![warn(unsafe_code)]
#![warn(missing_docs)]

pub mod bootstrap;
pub mod compaction;
pub mod episodic;
pub mod index;
pub mod semantic;
pub mod transcript;

use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::bootstrap::load_bootstrap_files;
use crate::compaction::compact;
use crate::episodic::EpisodicMemory;
use crate::index::{HybridIndex, MemoryHit};
use crate::semantic::SemanticMemory;
use crate::transcript::{ContentBlock, Role, SessionTranscript, TranscriptEntry, generate_session_slug, now_secs};

/// Main memory engine coordinating all subsystems.
pub struct MemoryEngine {
    root: PathBuf,
    session: SessionTranscript,
    index: HybridIndex,
    episodic: EpisodicMemory,
    semantic: SemanticMemory,
}

impl MemoryEngine {
    /// Initialize the memory engine for the given agent.
    ///
    /// Creates the `~/.muccheai/` directory tree if it does not exist.
    pub fn new(_agent_id: &str) -> Result<Self> {
        let home = dirs::home_dir().context("could not determine home directory")?;
        let root = home.join(".muccheai");

        std::fs::create_dir_all(&root)?;
        std::fs::create_dir_all(root.join("sessions"))?;
        std::fs::create_dir_all(root.join("memory"))?;
        std::fs::create_dir_all(root.join("workspace"))?;
        std::fs::create_dir_all(root.join("skills"))?;

        let session_id = generate_session_slug();
        let session = SessionTranscript::new(&root.join("sessions"), &session_id)?;

        let index = HybridIndex::new(&root.join("memory").join("index.sqlite"))?;
        let episodic = EpisodicMemory::new(&root);
        let semantic = SemanticMemory::new(&root.join("workspace"));

        // Index any existing bootstrap files
        for file in load_bootstrap_files(&root.join("workspace")) {
            if !file.content.is_empty() {
                let id = format!("bootstrap:{}", file.name);
                index.insert(&id, &file.content, "bootstrap", now_secs())?;
            }
        }

        Ok(Self {
            root,
            session,
            index,
            episodic,
            semantic,
        })
    }

    /// Append a message to the current session transcript.
    pub fn append_message(&mut self, role: Role, content: &str) -> Result<()> {
        let entry = TranscriptEntry {
            id: format!("msg-{}", uuid::Uuid::new_v4()),
            parent_id: None,
            role,
            content: vec![ContentBlock::Text {
                text: content.to_string(),
            }],
            timestamp: now_secs(),
        };
        self.session.append(entry.clone())?;

        // Also index the message
        self.index.insert(
            &format!("session:{}:{}", self.session.id, entry.id),
            content,
            "session",
            entry.timestamp,
        )?;

        Ok(())
    }

    /// Search across all indexed memories.
    pub fn search(&self, query: &str, limit: usize) -> Vec<MemoryHit> {
        self.index.search(query, limit).unwrap_or_default()
    }

    /// Write a daily episodic note.
    pub fn write_daily_note(&mut self, note: &str) -> Result<()> {
        self.episodic.write_note(note)?;
        let today = chrono::Local::now().format("%Y-%m-%d").to_string();
        self.index.insert(
            &format!("daily:{}", today),
            note,
            "daily",
            now_secs(),
        )?;
        Ok(())
    }

    /// Promote a fact to long-term semantic memory.
    pub fn promote_to_semantic(&mut self, fact: &str) -> Result<()> {
        self.semantic.promote_fact(fact)?;
        self.index.insert(
            &format!("semantic:{}", uuid::Uuid::new_v4()),
            fact,
            "semantic",
            now_secs(),
        )?;
        Ok(())
    }

    /// Compact the current session if it exceeds the threshold.
    pub fn compact_session(&mut self) -> Result<bool> {
        compact(&mut self.session, &self.episodic)
    }

    /// Load and concatenate all bootstrap files.
    pub fn bootstrap_context(&self) -> String {
        let files = load_bootstrap_files(&self.root.join("workspace"));
        let mut out = String::new();
        for file in files {
            if !file.content.is_empty() {
                out.push_str(&format!("--- {} ---\n{}\n\n", file.name, file.content));
            }
        }
        out
    }

    /// Load recent episodic notes as context.
    pub fn recent_episodic_context(&self) -> Result<String> {
        let notes = self.episodic.read_recent(2)?;
        let mut out = String::new();
        for (date, content) in notes {
            out.push_str(&format!("--- Daily Note: {} ---\n{}\n\n", date, content));
        }
        Ok(out)
    }

    /// Access the current session transcript.
    pub fn session(&self) -> &SessionTranscript {
        &self.session
    }

    /// Access the hybrid index.
    pub fn index(&self) -> &HybridIndex {
        &self.index
    }

    /// Access the semantic memory.
    pub fn semantic(&self) -> &SemanticMemory {
        &self.semantic
    }

    /// Access the episodic memory.
    pub fn episodic(&self) -> &EpisodicMemory {
        &self.episodic
    }

    /// Return the root path of the memory store.
    pub fn root(&self) -> &PathBuf {
        &self.root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn engine_in_temp() -> (MemoryEngine, TempDir) {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join(".muccheai");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(root.join("sessions")).unwrap();
        std::fs::create_dir_all(root.join("memory")).unwrap();
        std::fs::create_dir_all(root.join("workspace")).unwrap();

        let session = SessionTranscript::new(&root.join("sessions"), "test-session").unwrap();
        let index = HybridIndex::new(&root.join("memory").join("index.sqlite")).unwrap();
        let episodic = EpisodicMemory::new(&root);
        let semantic = SemanticMemory::new(&root.join("workspace"));

        let engine = MemoryEngine {
            root,
            session,
            index,
            episodic,
            semantic,
        };
        (engine, tmp)
    }

    #[test]
    fn test_append_message_and_search() {
        let (mut engine, _tmp) = engine_in_temp();
        engine.append_message(Role::User, "I love Rust programming").unwrap();
        engine.append_message(Role::Assistant, "Rust is great for systems").unwrap();

        let hits = engine.search("Rust", 5);
        assert!(!hits.is_empty());
    }

    #[test]
    fn test_daily_note_and_semantic() {
        let (mut engine, _tmp) = engine_in_temp();
        engine.write_daily_note("Learned about lifetimes today").unwrap();
        engine.promote_to_semantic("User prefers dark mode").unwrap();

        let facts = engine.semantic().read_facts().unwrap();
        assert_eq!(facts.len(), 1);
        assert!(facts[0].contains("dark mode"));
    }

    #[test]
    fn test_bootstrap_context() {
        let (engine, tmp) = engine_in_temp();
        std::fs::write(tmp.path().join(".muccheai/workspace/AGENTS.md"), "Be helpful").unwrap();

        let ctx = engine.bootstrap_context();
        assert!(ctx.contains("Be helpful"));
    }
}
