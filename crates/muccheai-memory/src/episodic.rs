//! Daily episodic memory
//!
//! Append-only Markdown notes organized by date: `memory/YYYY-MM-DD.md`

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;
use chrono::Local;

/// Daily episodic memory stored as append-only Markdown.
pub struct EpisodicMemory {
    root: PathBuf,
}

impl EpisodicMemory {
    /// Create a new episodic memory store rooted at `root/memory/`.
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.join("memory"),
        }
    }

    /// Append a note to today's daily note.
    pub fn write_note(&self, note: &str) -> Result<PathBuf> {
        let today = Local::now().format("%Y-%m-%d").to_string();
        let path = self.root.join(format!("{}.md", today));
        std::fs::create_dir_all(&self.root)?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;

        let timestamp = Local::now().format("%H:%M:%S").to_string();
        writeln!(file, "- [{}] {}", timestamp, note)?;
        file.sync_all()?;
        Ok(path)
    }

    /// Read the N most recent daily notes.
    pub fn read_recent(&self, n: usize) -> Result<Vec<(String, String)>> {
        std::fs::create_dir_all(&self.root)?;
        let mut files: Vec<_> = std::fs::read_dir(&self.root)?
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "md")
                    .unwrap_or(false)
            })
            .collect();

        files.sort_by_key(|e| e.path());
        files.reverse();

        let mut results = Vec::new();
        for entry in files.iter().take(n) {
            let path = entry.path();
            let date = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string();
            let mut content = String::new();
            File::open(&path)?.read_to_string(&mut content)?;
            results.push((date, content));
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_write_and_read_recent() {
        let tmp = TempDir::new().unwrap();
        let ep = EpisodicMemory::new(tmp.path());

        let path = ep.write_note("Learned about Rust lifetimes").unwrap();
        assert!(path.exists());

        let recent = ep.read_recent(2).unwrap();
        assert_eq!(recent.len(), 1);
        assert!(recent[0].1.contains("Learned about Rust lifetimes"));
    }
}
