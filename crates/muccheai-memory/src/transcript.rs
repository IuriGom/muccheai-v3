//! Session transcript management (JSONL)
//!
//! Append-only JSONL files with file-level locking and atomic writes.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Role of a transcript entry participant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    /// Human user
    User,
    /// AI assistant
    Assistant,
    /// Tool invocation
    ToolUse,
    /// Tool execution result
    ToolResult,
}

/// A content block within a transcript entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlock {
    /// Plain text
    Text {
        /// Text content
        text: String,
    },
    /// Tool use request
    ToolUse {
        /// Tool use ID
        id: String,
        /// Tool name
        name: String,
        /// Input parameters
        input: serde_json::Value,
    },
    /// Tool execution result
    ToolResult {
        /// Corresponding tool use ID
        tool_use_id: String,
        /// Result content
        content: String,
        /// Whether the tool call failed
        is_error: bool,
    },
}

/// A single entry in a session transcript.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TranscriptEntry {
    /// Unique entry ID
    pub id: String,
    /// Parent entry ID (for threading)
    pub parent_id: Option<String>,
    /// Role of the participant
    pub role: Role,
    /// Content blocks
    pub content: Vec<ContentBlock>,
    /// Unix timestamp (seconds)
    pub timestamp: u64,
}

/// An append-only session transcript stored as JSONL.
#[derive(Debug, Clone)]
pub struct SessionTranscript {
    /// Readable session slug
    pub id: String,
    /// Loaded entries
    pub entries: Vec<TranscriptEntry>,
    /// Path to the JSONL file
    path: PathBuf,
}

impl SessionTranscript {
    /// Create or load a session transcript.
    pub fn new(session_dir: &Path, id: &str) -> Result<Self> {
        let path = session_dir.join(format!("{}.jsonl", id));
        let entries = match Self::read_entries(&path) {
            Ok(e) => e,
            Err(e) => {
                // Check if the root cause is a NotFound IO error
                let is_not_found = e.root_cause().downcast_ref::<std::io::Error>()
                    .map(|ioe| ioe.kind() == std::io::ErrorKind::NotFound)
                    .unwrap_or(false);
                if is_not_found {
                    Vec::new()
                } else {
                    return Err(e);
                }
            }
        };
        Ok(Self {
            id: id.to_string(),
            entries,
            path,
        })
    }

    /// Append an entry to the transcript (atomic, with file locking).
    pub fn append(&mut self, entry: TranscriptEntry) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let lock_path = self.path.with_extension("jsonl.lock");
        let _lock = FileLock::acquire(&lock_path)?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;

        let line = serde_json::to_string(&entry)?;
        writeln!(file, "{}", line)?;
        file.sync_all()?;

        self.entries.push(entry);
        Ok(())
    }

    /// Write a compaction summary entry.
    pub fn append_compaction(&mut self, summary: &str, preserved_ids: &[String]) -> Result<()> {
        let entry = TranscriptEntry {
            id: format!("compaction-{}", uuid::Uuid::new_v4()),
            parent_id: None,
            role: Role::Assistant,
            content: vec![ContentBlock::Text {
                text: format!(
                    "[COMPACTION] Summary: {}\nPreserved message IDs: {:?}",
                    summary, preserved_ids
                ),
            }],
            timestamp: now_secs(),
        };
        self.append(entry)
    }

    /// Read all entries from a JSONL file.
    fn read_entries(path: &Path) -> Result<Vec<TranscriptEntry>> {
        const MAX_JSONL_SIZE: u64 = 100 * 1024 * 1024;
        const MAX_JSONL_LINES: usize = 100_000;

        let metadata = std::fs::metadata(path).context("transcript metadata")?;
        if metadata.len() > MAX_JSONL_SIZE {
            return Err(anyhow::anyhow!("Transcript file too large"));
        }

        let file = File::open(path).context("open transcript")?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();
        for line in reader.lines() {
            if entries.len() >= MAX_JSONL_LINES {
                return Err(anyhow::anyhow!("Transcript file exceeds max line count"));
            }
            let line = line.context("read transcript line")?;
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(entry) = serde_json::from_str::<TranscriptEntry>(&line) {
                entries.push(entry);
            }
        }
        Ok(entries)
    }

    /// Archive old transcript to a compressed file.
    pub fn archive(&self, archive_dir: &Path) -> Result<PathBuf> {
        std::fs::create_dir_all(archive_dir)?;
        let archive_path = archive_dir.join(format!("{}-archive.jsonl.gz", self.id));
        let file = File::create(&archive_path)?;
        let mut encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        for entry in &self.entries {
            let line = serde_json::to_string(entry)?;
            writeln!(encoder, "{}", line)?;
        }
        encoder.finish()?;
        Ok(archive_path)
    }

    /// Total character count of all text content.
    pub fn text_len(&self) -> usize {
        self.entries.iter().map(|e| e.text_len()).sum()
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the transcript is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl TranscriptEntry {
    /// Total text length in this entry.
    pub fn text_len(&self) -> usize {
        self.content.iter().map(|c| c.text_len()).sum()
    }
}

impl ContentBlock {
    /// Text length of this block.
    pub fn text_len(&self) -> usize {
        match self {
            ContentBlock::Text { text } => text.len(),
            ContentBlock::ToolUse { input, .. } => {
                serde_json::to_string(input).unwrap_or_default().len()
            }
            ContentBlock::ToolResult { content, .. } => content.len(),
        }
    }
}

/// Generate a readable session slug.
pub fn generate_session_slug() -> String {
    use rand::Rng;
    let adj = ADJECTIVES[rand::thread_rng().gen_range(0..ADJECTIVES.len())];
    let noun = NOUNS[rand::thread_rng().gen_range(0..NOUNS.len())];
    format!("{}-{}", adj, noun)
}

const ADJECTIVES: &[&str] = &[
    "happy", "calm", "bright", "gentle", "wild", "quiet", "golden", "swift", "brave",
    "cosmic", "silver", "ancient", "hidden", "frozen", "silent", "lucky", "noble",
    "crimson", "emerald", "azure",
];

const NOUNS: &[&str] = &[
    "mountain", "river", "forest", "ocean", "meadow", "star", "eagle", "wolf", "tree",
    "cloud", "valley", "thunder", "shadow", "flame", "crystal", "drift", "peak",
    "horizon", "garden", "moon",
];

/// Current unix timestamp in seconds.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Simple cross-process file lock (Unix only).
#[cfg(unix)]
pub mod file_lock {
    use std::fs::File;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    use std::path::Path;

    /// An advisory file lock acquired via `flock`.
    pub struct FileLock {
        _file: File,
    }

    impl FileLock {
        /// Acquire an exclusive lock on the given path.
        pub fn acquire(path: &Path) -> anyhow::Result<Self> {
            // Reject symlinks to prevent TOCTOU attacks.
            if let Ok(meta) = std::fs::symlink_metadata(path) {
                if meta.file_type().is_symlink() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "lock path is a symlink",
                    )
                    .into());
                }
            }
            // Open with O_NOFOLLOW so that even if a symlink is created
            // between the metadata check and the open, the call fails safely.
            let file = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)?;
            let fd = file.as_raw_fd();
            let ret = flock_raw(fd, libc::LOCK_EX);
            if ret != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            Ok(Self { _file: file })
        }
    }

    impl Drop for FileLock {
        fn drop(&mut self) {
            let fd = self._file.as_raw_fd();
            let _ = flock_raw(fd, libc::LOCK_UN);
        }
    }

    /// SAFETY: `flock` is a valid POSIX syscall. The fd is guaranteed to be
    /// valid because it comes from an owned `File` that outlives this call.
    #[inline]
    fn flock_raw(fd: std::os::unix::io::RawFd, op: i32) -> i32 {
        unsafe { libc::flock(fd, op) }
    }
}

#[cfg(not(unix))]
pub mod file_lock {
    use std::path::Path;

    /// Stub file lock for non-Unix platforms.
    pub struct FileLock;

    impl FileLock {
        /// No-op lock acquisition.
        pub fn acquire(_path: &Path) -> anyhow::Result<Self> {
            Ok(Self)
        }
    }
}

use file_lock::FileLock;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_session_slug_format() {
        let slug = generate_session_slug();
        assert!(slug.contains('-'));
        let parts: Vec<_> = slug.split('-').collect();
        assert_eq!(parts.len(), 2);
    }

    #[test]
    fn test_transcript_append_and_read() {
        let tmp = TempDir::new().unwrap();
        let mut tx = SessionTranscript::new(tmp.path(), "test-session").unwrap();

        let entry = TranscriptEntry {
            id: "msg-1".to_string(),
            parent_id: None,
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: "Hello".to_string(),
            }],
            timestamp: now_secs(),
        };
        tx.append(entry).unwrap();
        assert_eq!(tx.len(), 1);

        // Reload and verify
        let tx2 = SessionTranscript::new(tmp.path(), "test-session").unwrap();
        assert_eq!(tx2.len(), 1);
        assert_eq!(tx2.entries[0].role, Role::User);
    }

    #[test]
    fn test_archive_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let mut tx = SessionTranscript::new(tmp.path(), "arch-test").unwrap();
        tx.append(TranscriptEntry {
            id: "a".to_string(),
            parent_id: None,
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: "archive me".to_string(),
            }],
            timestamp: now_secs(),
        })
        .unwrap();

        let archive_dir = tmp.path().join("archives");
        let path = tx.archive(&archive_dir).unwrap();
        assert!(path.exists());
        assert!(path.to_string_lossy().ends_with(".gz"));
    }
}
