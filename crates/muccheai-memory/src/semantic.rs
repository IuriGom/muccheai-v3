//! Semantic long-term memory (MEMORY.md)
//!
//! Curated facts distilled from daily notes, stored in `workspace/MEMORY.md`.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;

/// Semantic long-term memory (curated facts from daily notes).
pub struct SemanticMemory {
    path: PathBuf,
}

impl SemanticMemory {
    /// Heading used to separate facts in MEMORY.md.
    const FACT_HEADER: &'static str = "## Fact";

    /// Create a new semantic memory store at `workspace/MEMORY.md`.
    pub fn new(workspace: &Path) -> Self {
        Self {
            path: workspace.join("MEMORY.md"),
        }
    }

    /// Add a curated fact to MEMORY.md.
    pub fn promote_fact(&self, fact: &str) -> Result<()> {
        std::fs::create_dir_all(self.path.parent().unwrap_or(Path::new("")))?;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;

        writeln!(file, "{}", Self::FACT_HEADER)?;
        writeln!(file, "{}", fact)?;
        writeln!(file)?;
        file.sync_all()?;
        Ok(())
    }

    /// Read all curated facts.
    pub fn read_facts(&self) -> Result<Vec<String>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let mut content = String::new();
        fs::File::open(&self.path)?.read_to_string(&mut content)?;

        let mut facts = Vec::new();
        let mut current_fact = String::new();
        let mut in_fact = false;

        for line in content.lines() {
            if line.trim() == Self::FACT_HEADER {
                if in_fact && !current_fact.trim().is_empty() {
                    facts.push(current_fact.trim().to_string());
                }
                in_fact = true;
                current_fact.clear();
            } else if in_fact {
                current_fact.push_str(line);
                current_fact.push('\n');
            }
        }

        if in_fact && !current_fact.trim().is_empty() {
            facts.push(current_fact.trim().to_string());
        }

        Ok(facts)
    }

    /// Read the full MEMORY.md content.
    pub fn read_all(&self) -> Result<String> {
        if !self.path.exists() {
            return Ok(String::new());
        }
        let mut content = String::new();
        fs::File::open(&self.path)?.read_to_string(&mut content)?;
        Ok(content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_promote_and_read() {
        let tmp = TempDir::new().unwrap();
        let sm = SemanticMemory::new(tmp.path());

        sm.promote_fact("User prefers dark mode").unwrap();
        sm.promote_fact("User works in UTC-5").unwrap();

        let facts = sm.read_facts().unwrap();
        assert_eq!(facts.len(), 2);
        assert!(facts[0].contains("dark mode"));
        assert!(facts[1].contains("UTC-5"));
    }
}
