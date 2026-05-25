//! Persistent memory storage backed by JSONL.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use anyhow::Result;
use muccheai_types::memory::MemoryEntry;

use crate::config::MuccheConfig;

fn load_machine_key() -> Option<[u8; 32]> {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    let path = home.join(".muccheai").join(".machine_key");
    let bytes = std::fs::read(&path).ok()?;
    if bytes.len() == 32 {
        let mut material = [0u8; 32];
        material.copy_from_slice(&bytes);
        let salt = MuccheConfig::load_or_create_salt();
        Some(MuccheConfig::derive_machine_key(&material, &salt))
    } else {
        None
    }
}

/// Encrypt a line if a machine key is available; otherwise return plaintext.
fn encrypt_line(plaintext: &str) -> String {
    match load_machine_key() {
        Some(key) => match crate::config::encrypt_aes_256_gcm(plaintext.as_bytes(), &key) {
            Ok(ciphertext) => format!("enc:{}", hex::encode(ciphertext)),
            Err(_) => plaintext.to_string(),
        },
        None => plaintext.to_string(),
    }
}

/// Decrypt a line if it has the `enc:` prefix; otherwise return plaintext.
fn decrypt_line(line: &str) -> Option<String> {
    if let Some(hex_ct) = line.strip_prefix("enc:") {
        let ciphertext = hex::decode(hex_ct).ok()?;
        let key = load_machine_key()?;
        let plaintext = crate::config::decrypt_aes_256_gcm(&ciphertext, &key).ok()?;
        String::from_utf8(plaintext).ok()
    } else {
        Some(line.to_string())
    }
}

/// Compute a file-level HMAC over all entry content hashes.
/// This detects truncation and reordering attacks on the JSONL file.
fn compute_file_hmac(entries: &[MemoryEntry]) -> String {
    use hmac::{Hmac, Mac};
    use sha3::Sha3_256;
    type HmacSha3 = Hmac<Sha3_256>;

    let key = load_machine_key().unwrap_or_default();
    let mut mac = HmacSha3::new_from_slice(&key).expect("HMAC key size valid");
    for e in entries {
        mac.update(&e.content_hash);
    }
    hex::encode(mac.finalize().into_bytes())
}

/// Simple cross-process advisory file lock (Unix only).
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

    // fd comes from an owned File, so it's valid here.
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
            let mut e = e.clone();
            if e.content_hash.is_empty() {
                e.content_hash = e.compute_hash();
            }
            let line = serde_json::to_string(&e)?;
            writeln!(file, "{}", encrypt_line(&line))?;
        }
        let hmac = compute_file_hmac(&entries);
        writeln!(file, "{}", encrypt_line(&format!("__hmac__:{}", hmac)))?;
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
        self.delete_by_owner(key, "")
    }

    /// Remove entries matching key and owner. Empty owner matches all (legacy compat).
    pub fn delete_by_owner(&self, key: &str, owner: &str) -> Result<bool> {
        let lock_path = self.path.with_extension("lock");
        let _lock = FileLock::acquire(&lock_path)?;
        let mut entries = self.read_entries()?;
        let original_len = entries.len();
        entries.retain(|e| e.key != key || e.owner_hash != owner);

        if entries.len() == original_len {
            return Ok(false);
        }

        let tmp_path = self.path.with_extension("tmp");
        let mut file = File::create(&tmp_path)?;
        let hmac = compute_file_hmac(&entries);
        for mut entry in entries {
            if entry.content_hash.is_empty() {
                entry.content_hash = entry.compute_hash();
            }
            let line = serde_json::to_string(&entry)?;
            writeln!(file, "{}", encrypt_line(&line))?;
        }
        writeln!(file, "{}", encrypt_line(&format!("__hmac__:{}", hmac)))?;
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
        let mut stored_hmac: Option<String> = None;

        for line in reader.lines() {
            if entries.len() >= MAX_JSONL_LINES {
                return Err(anyhow::anyhow!("Memory file exceeds max line count"));
            }
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let plaintext = decrypt_line(&line).unwrap_or(line);
            if plaintext.starts_with("__hmac__:") {
                stored_hmac = plaintext.strip_prefix("__hmac__:").map(|s| s.to_string());
                continue;
            }
            match serde_json::from_str::<MemoryEntry>(&plaintext) {
                Ok(entry) => {
                    if !entry.verify_integrity() {
                        return Err(anyhow::anyhow!(
                            "Memory entry integrity check failed for key '{}'",
                            entry.key
                        ));
                    }
                    entries.push(entry);
                }
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "Corrupted memory entry ({}). The memory file may have been tampered with.",
                        e
                    ));
                }
            }
        }

        // Verify file-level HMAC if present.
        if let Some(expected) = stored_hmac {
            let actual = compute_file_hmac(&entries);
            if !muccheai_crypto::constant_time::eq(actual.as_bytes(), expected.as_bytes()) {
                return Err(anyhow::anyhow!(
                    "Memory file HMAC verification failed. The file may have been truncated or reordered."
                ));
            }
        }

        Ok(entries)
    }
}
