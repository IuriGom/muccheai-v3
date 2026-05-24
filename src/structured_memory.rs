//! Structured memory manager with approval queue.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};

use muccheai_types::memory::{MemoryEntry, MemoryType, MemoryValue};
use muccheai_types::Timestamp;

use crate::memory_store::MemoryStore;

// Cross-process advisory file lock (Unix only).
#[cfg(unix)]
mod file_lock {
    use std::fs::File;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    use std::path::Path;

    pub struct FileLock {
        _file: File,
    }

    impl FileLock {
        pub fn acquire(path: &Path) -> anyhow::Result<Self> {
            if let Ok(meta) = std::fs::symlink_metadata(path) {
                if meta.file_type().is_symlink() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "lock path is a symlink",
                    )
                    .into());
                }
            }
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

/// Status of a memory proposal in the approval queue.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ProposalStatus {
    Pending,
    Approved,
    Rejected,
}

/// A queued memory proposal awaiting approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedProposal {
    pub id: String,
    pub entry: MemoryEntry,
    pub justification: String,
    pub status: ProposalStatus,
    pub proposed_at: Timestamp,
    pub resolved_at: Option<Timestamp>,
}

/// Manages structured memory with cryptographic integrity and approval queue.
pub struct StructuredMemoryManager {
    store: MemoryStore,
    queue_path: PathBuf,
}

impl StructuredMemoryManager {
    pub fn new() -> Result<Self> {
        let store = MemoryStore::new()?;
        let queue_path = store.path.with_file_name("memory_queue.jsonl");
        Ok(Self { store, queue_path })
    }

    // ------------------------------------------------------------------
    // Approval Queue
    // ------------------------------------------------------------------

    pub fn propose(&self, entry: MemoryEntry, justification: &str) -> Result<String> {
        let lock_path = self.queue_path.with_extension("lock");
        let _lock = FileLock::acquire(&lock_path)?;
        let mut rng_bytes = [0u8; 16];
        ring::rand::SystemRandom::new()
            .fill(&mut rng_bytes)
            .expect("CSPRNG must succeed");
        let id = format!("proposal-{}", hex::encode(rng_bytes));
        let proposal = QueuedProposal {
            id: id.clone(),
            entry,
            justification: justification.to_string(),
            status: ProposalStatus::Pending,
            proposed_at: Timestamp::now(),
            resolved_at: None,
        };
        self.append_to_queue(&proposal)?;
        Ok(id)
    }

    pub fn approve(&self, id: &str) -> Result<bool> {
        let lock_path = self.queue_path.with_extension("lock");
        let _lock = FileLock::acquire(&lock_path)?;
        let mut proposals = self.read_queue()?;
        let mut found = false;
        for p in &mut proposals {
            if p.id == id && p.status == ProposalStatus::Pending {
                p.status = ProposalStatus::Approved;
                p.resolved_at = Some(Timestamp::now());
                found = true;

                // Persist with computed content hash
                let mut entry = p.entry.clone();
                entry.content_hash = entry.compute_hash();
                self.store.store(&entry)?;
                break;
            }
        }
        if found {
            self.rewrite_queue(&proposals)?;
        }
        Ok(found)
    }

    pub fn reject(&self, id: &str) -> Result<bool> {
        let lock_path = self.queue_path.with_extension("lock");
        let _lock = FileLock::acquire(&lock_path)?;
        let mut proposals = self.read_queue()?;
        let mut found = false;
        for p in &mut proposals {
            if p.id == id && p.status == ProposalStatus::Pending {
                p.status = ProposalStatus::Rejected;
                p.resolved_at = Some(Timestamp::now());
                found = true;
                break;
            }
        }
        if found {
            self.rewrite_queue(&proposals)?;
        }
        Ok(found)
    }

    pub fn list_pending(&self) -> Vec<QueuedProposal> {
        self.read_queue()
            .unwrap_or_default()
            .into_iter()
            .filter(|p| p.status == ProposalStatus::Pending)
            .collect()
    }

    pub fn list_all_proposals(&self) -> Vec<QueuedProposal> {
        self.read_queue().unwrap_or_default()
    }

    // ------------------------------------------------------------------
    // Structured Memory Access
    // ------------------------------------------------------------------

    pub fn list_by_type(&self, mem_type: MemoryType) -> Vec<MemoryEntry> {
        self.store
            .list()
            .into_iter()
            .filter(|e| e.memory_type == mem_type)
            .collect()
    }

    pub fn list_all(&self) -> Vec<MemoryEntry> {
        self.store.list()
    }

    pub fn get(&self, key: &str) -> Option<MemoryEntry> {
        self.store.get(key)
    }

    pub fn delete(&self, key: &str) -> Result<bool> {
        self.store.delete(key)
    }

    // ------------------------------------------------------------------
    // Task History (auto-logged, no approval needed)
    // ------------------------------------------------------------------

    pub fn log_task(
        &self,
        description: &str,
        mut metadata: serde_json::Map<String, serde_json::Value>,
    ) -> Result<()> {
        metadata.insert(
            "description".to_string(),
            serde_json::Value::String(description.to_string()),
        );
        let mut entry = MemoryEntry {
            memory_type: MemoryType::TaskHistory,
            key: format!("task-{}", Timestamp::now().0),
            value: MemoryValue::JsonObject(metadata),
            created_at: Timestamp::now(),
            user_signature: vec![], // Auto-logged, no per-entry signature
            content_hash: vec![],   // Computed below
        };
        entry.content_hash = entry.compute_hash();
        self.store.store(&entry)?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Convenience: Store approved facts/preferences directly
    // ------------------------------------------------------------------

    pub fn store_fact(&self, key: &str, value: &MemoryValue) -> Result<()> {
        let mut entry = MemoryEntry {
            memory_type: MemoryType::Fact,
            key: key.to_string(),
            value: value.clone(),
            created_at: Timestamp::now(),
            user_signature: vec![],
            content_hash: vec![],
        };
        entry.content_hash = entry.compute_hash();
        self.store.store(&entry)
    }

    pub fn store_preference(&self, key: &str, value: &MemoryValue) -> Result<()> {
        if !value.fits_preference_limit() {
            return Err(anyhow::anyhow!("Preference exceeds 1KB limit"));
        }
        let mut entry = MemoryEntry {
            memory_type: MemoryType::Preference,
            key: key.to_string(),
            value: value.clone(),
            created_at: Timestamp::now(),
            user_signature: vec![],
            content_hash: vec![],
        };
        entry.content_hash = entry.compute_hash();
        self.store.store(&entry)
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    fn append_to_queue(&self, proposal: &QueuedProposal) -> Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.queue_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&self.queue_path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&self.queue_path, perms)?;
        }
        let line = serde_json::to_string(proposal)?;
        writeln!(file, "{}", line)?;
        Ok(())
    }

    fn read_queue(&self) -> Result<Vec<QueuedProposal>> {
        const MAX_JSONL_SIZE: u64 = 100 * 1024 * 1024;
        const MAX_JSONL_LINES: usize = 100_000;

        if !self.queue_path.exists() {
            return Ok(Vec::new());
        }
        let metadata = std::fs::metadata(&self.queue_path)?;
        if metadata.len() > MAX_JSONL_SIZE {
            return Err(anyhow::anyhow!("Queue file too large"));
        }
        let file = File::open(&self.queue_path)?;
        let reader = BufReader::new(file);
        let mut proposals = Vec::new();
        for line in reader.lines() {
            if proposals.len() >= MAX_JSONL_LINES {
                return Err(anyhow::anyhow!("Queue file exceeds max line count"));
            }
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(p) = serde_json::from_str::<QueuedProposal>(&line) {
                proposals.push(p);
            }
        }
        Ok(proposals)
    }

    fn rewrite_queue(&self, proposals: &[QueuedProposal]) -> Result<()> {
        let tmp_path = self.queue_path.with_extension("tmp");
        let mut file = File::create(&tmp_path)?;
        for p in proposals {
            let line = serde_json::to_string(p)?;
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
        std::fs::rename(&tmp_path, &self.queue_path)?;
        Ok(())
    }
}

// ============================================================================
// Bootstrap Files
// ============================================================================

const DEFAULT_SOUL: &str = r#"# MuccheAI

Security first. Transparency. User autonomy. Minimalism.

## Memory Types

- **Fact**: Immutable personal truths. Proposed by the system, user-approved.
- **Preference**: User-configurable settings. Proposed by the system, user-approved.
- **TaskHistory**: Auto-logged tool executions. Read-only.
- **Context**: Current conversation. RAM-only, never persisted.
- **Draft**: Temporary compositions. Not yet implemented.

## Proposing Memories

1. Ask the user first: "Should I remember that you [fact/preference]?"
2. If yes, state clearly what is being proposed.
3. If no, drop it. No logging. No persistence.

Never silently save. Never auto-populate without consent.
"#;

const DEFAULT_IDENTITY: &str = r#"# Identity

Name: MuccheAI
Architecture: Secure personal AI agent with capability-based security.

## Capabilities
- Multi-turn conversation
- Tool use via Policy Engine approval
- Structured memory management
- File system access (user-approved)

## Limitations
- No direct internet access (proxied through Tool Gateway)
- Cannot modify own code or configuration
- Cannot access credentials or secrets
- Does not learn unless explicitly instructed
"#;

const DEFAULT_USER: &str = r#"# User Profile

Edit this file at `~/.muccheai/workspace/USER.md`.

## Profile
- Name:
- Timezone:
- Language:
- Occupation:

## Preferences
- Use 24-hour time format
- Prefer concise answers

## Facts
- Birthday:
- Employer:
"#;

const DEFAULT_TOOLS: &str = r#"# Tools

- `email.send` — Send email via send-only queue
- `calendar.read` — Read calendar events
- `filesystem.read` — Read files from user-approved directory
- `filesystem.write` — Write files to user-approved directory
- `search.web` — Web search

All tool calls require Policy Engine validation and user approval.
"#;

const DEFAULT_MEMORY: &str = r#"# Memory

Curated long-term facts and preferences.
Edit directly or approve through the web UI queue.
"#;

const DEFAULT_HEARTBEAT: &str = r#"# Status

- Policy Engine: OK
- Sandbox: OK
- Tool Gateway: OK
- Memory Index: OK
- Structured Memory Store: OK
- Approval Queue: 0 pending
"#;

const DEFAULT_AGENTS: &str = r#"# Agents

[Populated from agent configurations at runtime]
"#;

/// Ensure all bootstrap files exist in the workspace directory.
///
/// Creates `~/.muccheai/workspace/` and writes default templates for any
/// missing files. Never overwrites existing files.
pub fn ensure_bootstrap_files(workspace: &Path) -> Result<()> {
    std::fs::create_dir_all(workspace)?;

    let files = [
        ("AGENTS.md", DEFAULT_AGENTS),
        ("SOUL.md", DEFAULT_SOUL),
        ("IDENTITY.md", DEFAULT_IDENTITY),
        ("USER.md", DEFAULT_USER),
        ("TOOLS.md", DEFAULT_TOOLS),
        ("MEMORY.md", DEFAULT_MEMORY),
        ("HEARTBEAT.md", DEFAULT_HEARTBEAT),
    ];

    for (name, content) in &files {
        let path = workspace.join(name);
        if !path.exists() {
            let tmp = path.with_extension("tmp");
            std::fs::write(&tmp, content)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(&tmp)?.permissions();
                perms.set_mode(0o600);
                std::fs::set_permissions(&tmp, perms)?;
            }
            std::fs::rename(&tmp, &path)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use muccheai_types::memory::MemoryValue;
    use tempfile::TempDir;

    fn manager_in_temp() -> (StructuredMemoryManager, TempDir) {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join(".muccheai");
        std::fs::create_dir_all(&root).unwrap();

        // Hack: create a MemoryStore pointing to temp
        let store_path = root.join("memory.jsonl");
        std::fs::File::create(&store_path).unwrap();
        let store = MemoryStore { path: store_path };
        let queue_path = root.join("memory_queue.jsonl");

        let mgr = StructuredMemoryManager {
            store,
            queue_path,
        };
        (mgr, tmp)
    }

    #[test]
    fn test_propose_approve_reject() {
        let (mgr, _tmp) = manager_in_temp();

        let entry = MemoryEntry {
            memory_type: MemoryType::Fact,
            key: "birthday".to_string(),
            value: MemoryValue::ShortString("March 15".to_string()),
            created_at: Timestamp::now(),
            user_signature: vec![],
            content_hash: vec![],
        };

        let id = mgr.propose(entry, "User mentioned their birthday").unwrap();
        assert_eq!(mgr.list_pending().len(), 1);

        assert!(mgr.approve(&id).unwrap());
        assert!(mgr.list_pending().is_empty());
        assert_eq!(mgr.list_by_type(MemoryType::Fact).len(), 1);

        // Re-approving same ID fails
        assert!(!mgr.approve(&id).unwrap());
    }

    #[test]
    fn test_log_task() {
        let (mgr, _tmp) = manager_in_temp();

        let mut meta = serde_json::Map::new();
        meta.insert("tool".to_string(), serde_json::Value::String("email.send".to_string()));

        mgr.log_task("Sent email to john@example.com", meta).unwrap();

        let tasks = mgr.list_by_type(MemoryType::TaskHistory);
        assert_eq!(tasks.len(), 1);
    }

    #[test]
    fn test_store_preference_size_limit() {
        let (mgr, _tmp) = manager_in_temp();

        let big_value = MemoryValue::ShortString("x".repeat(2000));
        assert!(mgr.store_preference("test", &big_value).is_err());

        let small_value = MemoryValue::ShortString("dark mode".to_string());
        assert!(mgr.store_preference("theme", &small_value).is_ok());
    }

    #[test]
    fn test_bootstrap_files() {
        let tmp = TempDir::new().unwrap();
        let ws = tmp.path().join("workspace");
        ensure_bootstrap_files(&ws).unwrap();

        assert!(ws.join("SOUL.md").exists());
        assert!(ws.join("IDENTITY.md").exists());
        assert!(ws.join("USER.md").exists());
        assert!(ws.join("TOOLS.md").exists());

        let soul = std::fs::read_to_string(ws.join("SOUL.md")).unwrap();
        assert!(soul.contains("MuccheAI"));
    }
}
