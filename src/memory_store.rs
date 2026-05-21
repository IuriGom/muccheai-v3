//! Persistent memory storage backed by JSONL.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use anyhow::Result;
use muccheai_types::memory::MemoryEntry;

use crate::config::MuccheConfig;

/// Simple cross-process advisory file lock (Unix only).
#[cfg(unix)]
mod file_lock {
    use std::fs::File;
    use std::os::unix::io::AsRawFd;
    use std::path::Path;

    pub struct FileLock {
        _file: File,
    }

    impl FileLock {
        pub fn acquire(path: &Path) -> anyhow::Result<Self> {
            let file = File::create(path)?;
            let fd = file.as_raw_fd();
            let ret = unsafe { libc::flock(fd, libc::LOCK_EX) };
            if ret != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            Ok(Self { _file: file })
        }
    }

    impl Drop for FileLock {
        fn drop(&mut self) {
            let fd = self._file.as_raw_fd();
            unsafe {
                let _ = libc::flock(fd, libc::LOCK_UN);
            };
        }
    }
}

#[cfg(not(unix))]
mod file_lock {
    use std::path::Path;
    pub struct FileLock;
    impl FileLock {
        pub fn acquire(_path: &Path) -> anyhow::Result<Self> {
            Ok(Self)
        }
    }
}

use file_lock::FileLock;

/// Append-only JSONL memory store.
pub struct MemoryStore {
    /// Path to the memory.jsonl file.
    pub path: PathBuf,
}

impl MemoryStore {
    /// Open or create the memory store at `~/.muccheai/memory.jsonl`.
    pub fn new() -> Result<Self> {
        let path = MuccheConfig::config_path()
            .parent()
            .expect("config path has a parent directory")
            .join("memory.jsonl");

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if !path.exists() {
            let tmp = path.with_extension("tmp");
            File::create(&tmp)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(&tmp)?.permissions();
                perms.set_mode(0o600);
                std::fs::set_permissions(&tmp, perms)?;
            }
            std::fs::rename(&tmp, &path)?;
        }

        Ok(Self { path })
    }

    /// Append a single entry to the JSONL file.
    /// If the total entries exceed the cap, oldest entries are removed.
    pub fn store(&self, entry: &MemoryEntry) -> Result<()> {
        let lock_path = self.path.with_extension("lock");
        let _lock = FileLock::acquire(&lock_path)?;
        const MAX_ENTRIES: usize = 10_000;
        let mut entries = self.read_entries()?;
        entries.push(entry.clone());
        // Prune oldest entries if over cap.
        if entries.len() > MAX_ENTRIES {
            let excess = entries.len() - MAX_ENTRIES;
            entries.drain(0..excess);
        }
        let tmp_path = self.path.with_extension("tmp");
        let mut file = File::create(&tmp_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&tmp_path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&tmp_path, perms)?;
        }
        for e in &entries {
            let line = serde_json::to_string(e)?;
            writeln!(file, "{}", line)?;
        }
        drop(file);
        std::fs::rename(&tmp_path, &self.path)?;
        Ok(())
    }

    /// Find the first entry matching `key`.
    pub fn get(&self, key: &str) -> Option<MemoryEntry> {
        self.read_entries().ok()?.into_iter().find(|e| e.key == key)
    }

    /// Return all entries, newest first.
    pub fn list(&self) -> Vec<MemoryEntry> {
        let mut entries = self.read_entries().unwrap_or_default();
        entries.reverse();
        entries
    }

    /// Simple substring search over keys and JSON-serialized values.
    pub fn search(&self, query: &str) -> Vec<MemoryEntry> {
        let query = query.to_lowercase();
        let mut entries = self.read_entries().unwrap_or_default();
        entries.retain(|e| {
            e.key.to_lowercase().contains(&query)
                || serde_json::to_string(&e.value)
                    .unwrap_or_default()
                    .to_lowercase()
                    .contains(&query)
        });
        entries.reverse();
        entries
    }

    /// Remove all entries with the given key and rewrite the file atomically.
    pub fn delete(&self, key: &str) -> Result<bool> {
        let lock_path = self.path.with_extension("lock");
        let _lock = FileLock::acquire(&lock_path)?;
        let mut entries = self.read_entries()?;
        let original_len = entries.len();
        entries.retain(|e| e.key != key);

        if entries.len() == original_len {
            return Ok(false);
        }

        let tmp_path = self.path.with_extension("tmp");
        let mut file = File::create(&tmp_path)?;
        for entry in entries {
            let line = serde_json::to_string(&entry)?;
            writeln!(file, "{}", line)?;
        }
        drop(file);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&tmp_path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&tmp_path, perms)?;
        }
        std::fs::rename(&tmp_path, &self.path)?;
        Ok(true)
    }

    fn read_entries(&self) -> Result<Vec<MemoryEntry>> {
        const MAX_JSONL_SIZE: u64 = 100 * 1024 * 1024;
        const MAX_JSONL_LINES: usize = 100_000;

        let metadata = std::fs::metadata(&self.path)?;
        if metadata.len() > MAX_JSONL_SIZE {
            return Err(anyhow::anyhow!("Memory file too large"));
        }

        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();

        for line in reader.lines() {
            if entries.len() >= MAX_JSONL_LINES {
                return Err(anyhow::anyhow!("Memory file exceeds max line count"));
            }
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(entry) = serde_json::from_str::<MemoryEntry>(&line) {
                entries.push(entry);
            }
        }

        Ok(entries)
    }
}
