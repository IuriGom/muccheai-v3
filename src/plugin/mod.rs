//! Plugin system — manager, runtime, manifest.

pub mod manifest;
pub mod runtime;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use serde::{Deserialize, Serialize};

use manifest::{PluginManifest, PluginRole};
use runtime::PluginRuntime;

/// Revoked plugin entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RevokedEntry {
    pub wasm_hash: String,
    pub reason: String,
    pub revoked_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginEntry {
    pub name: String,
    pub manifest: PluginManifest,
    pub wasm_hash: String,
    pub enabled: bool,
    pub installed_at: u64,
    /// Role assigned by the user at install time. Never upgraded automatically.
    pub installed_role: PluginRole,
}

pub struct PluginManager {
    plugins_dir: PathBuf,
    runtime: PluginRuntime,
    entries: HashMap<String, PluginEntry>,
}

impl PluginManager {
    pub fn new_disabled() -> Self {
        Self {
            plugins_dir: std::path::PathBuf::from("/dev/null"),
            runtime: PluginRuntime::new(),
            entries: HashMap::new(),
        }
    }

    pub fn with_counters(counters: Arc<std::sync::Mutex<HashMap<String, (u64, u64)>>>) -> anyhow::Result<Self> {
        let plugins_dir = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".muccheai")
            .join("plugins");
        std::fs::create_dir_all(&plugins_dir)?;

        let mut manager = Self {
            plugins_dir,
            runtime: PluginRuntime::with_counters(counters),
            entries: HashMap::new(),
        };
        manager.load_all()?;
        Ok(manager)
    }

    pub fn new() -> anyhow::Result<Self> {
        let plugins_dir = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".muccheai")
            .join("plugins");
        std::fs::create_dir_all(&plugins_dir)?;

        let mut manager = Self {
            plugins_dir,
            runtime: PluginRuntime::new(),
            entries: HashMap::new(),
        };
        manager.load_all()?;
        Ok(manager)
    }

    fn load_revoked_list(&self) -> std::collections::HashSet<String> {
        let path = self.plugins_dir.parent().unwrap_or(&self.plugins_dir).join("revoked-plugins.json");
        if let Ok(data) = std::fs::read_to_string(&path) {
            match serde_json::from_str::<Vec<RevokedEntry>>(&data) {
                Ok(list) => list.into_iter().map(|e| e.wasm_hash).collect(),
                Err(e) => {
                    tracing::warn!("Corrupted revoked-plugins.json: {}", e);
                    std::collections::HashSet::new()
                }
            }
        } else {
            std::collections::HashSet::new()
        }
    }

    fn load_trusted_keys(&self) -> Vec<[u8; 32]> {
        let keys_dir = self.plugins_dir.parent().unwrap_or(&self.plugins_dir).join("trusted-keys");
        let mut keys = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&keys_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                // Reject symlinks in trust anchor to prevent traversal attacks.
                if let Ok(meta) = std::fs::symlink_metadata(&path) {
                    if meta.file_type().is_symlink() {
                        tracing::warn!("Skipping symlink in trusted-keys: {:?}", path);
                        continue;
                    }
                }
                if let Ok(text) = std::fs::read_to_string(&path) {
                    let trimmed = text.trim();
                    if trimmed.len() == 64 {
                        if let Ok(bytes) = hex::decode(trimmed) {
                            if bytes.len() == 32 {
                                let mut arr = [0u8; 32];
                                arr.copy_from_slice(&bytes);
                                keys.push(arr);
                            }
                        }
                    }
                }
            }
        }
        keys
    }

    fn verify_plugin_signature(&self, manifest: &PluginManifest, trusted: &[[u8; 32]]) -> bool {
        use ed25519_dalek::Verifier;
        let Some(ref pk_hex) = manifest.plugin.author_pubkey else {
            return false; // unsigned plugins are rejected when trust anchor exists
        };
        let Some(ref sig_hex) = manifest.plugin.signature else {
            return false;
        };
        let pk_bytes = match hex::decode(pk_hex) {
            Ok(b) if b.len() == 32 => b,
            _ => return false,
        };
        // If trust anchor exists, author must be in the trusted set.
        if !trusted.is_empty() {
            let mut pk_arr = [0u8; 32];
            pk_arr.copy_from_slice(&pk_bytes);
            if !trusted.contains(&pk_arr) {
                tracing::warn!("Plugin '{}' author pubkey not in trusted-keys", manifest.plugin.name);
                return false;
            }
        }
        let sig_bytes = match hex::decode(sig_hex) {
            Ok(b) if b.len() == 64 => b,
            _ => return false,
        };
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pk_bytes);
        let vk = match ed25519_dalek::VerifyingKey::from_bytes(&pk_arr) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        let msg = manifest.canonical_signing_bytes();
        if msg.is_empty() {
            tracing::warn!("Plugin '{}' canonical signing bytes are empty — toml serialization failed", manifest.plugin.name);
            return false;
        }
        vk.verify(&msg, &sig).is_ok()
    }

    pub fn load_all(&mut self) -> anyhow::Result<()> {
        self.entries.clear();
        let revoked = self.load_revoked_list();
        let trusted = self.load_trusted_keys();
        // First pass: load all valid plugins into a temporary map.
        let mut loaded: HashMap<String, PluginEntry> = HashMap::new();
        for entry in std::fs::read_dir(&self.plugins_dir)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_dir() { continue; }
            let manifest_path = path.join("plugin.toml");
            if !manifest_path.exists() { continue; }
            let manifest = match PluginManifest::load(&manifest_path) {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!("Failed to load plugin manifest at {:?}: {}", manifest_path, e);
                    continue;
                }
            };
            if let Err(e) = manifest.validate() {
                tracing::warn!("Invalid plugin manifest at {:?}: {}", manifest_path, e);
                continue;
            }
            let wasm_path = path.join(std::path::Path::new(&manifest.plugin.wasm_path).file_name().unwrap_or(std::ffi::OsStr::new("plugin.wasm")));
            let wasm_hash = match std::fs::read(&wasm_path) {
                Ok(bytes) => {
                    use sha3::{Sha3_256, Digest};
                    let mut hasher = Sha3_256::new();
                    hasher.update(&bytes);
                    hex::encode(hasher.finalize())
                }
                Err(_) => {
                    tracing::warn!("Plugin '{}' WASM not found at {:?}", manifest.plugin.name, wasm_path);
                    continue;
                }
            };
            // Revocation check
            if revoked.contains(&wasm_hash) {
                tracing::warn!("Plugin '{}' WASM hash is revoked — skipping", manifest.plugin.name);
                continue;
            }
            // Expected hash check
            if let Some(ref expected) = manifest.plugin.expected_wasm_hash {
                if expected != &wasm_hash {
                    tracing::warn!("Plugin '{}' WASM hash mismatch: expected {} got {}", manifest.plugin.name, expected, wasm_hash);
                    continue;
                }
            }
            // Signature verification (mandatory if trusted-keys exist; advisory otherwise)
            let sig_ok = self.verify_plugin_signature(&manifest, &trusted);
            if !trusted.is_empty() && !sig_ok {
                tracing::warn!("Plugin '{}' signature verification failed — skipping", manifest.plugin.name);
                continue;
            }
            if trusted.is_empty() && manifest.plugin.signature.is_some() && !sig_ok {
                tracing::warn!("Plugin '{}' signature invalid but no trusted-keys configured — loading anyway", manifest.plugin.name);
            }
            // Load persisted role or default to the requested role.
            let role_path = path.join(".installed_role");
            let installed_role = if let Ok(role_text) = std::fs::read_to_string(&role_path) {
                match serde_json::from_str(&role_text) {
                    Ok(r) => r,
                    Err(_) => manifest.plugin.requested_role,
                }
            } else {
                manifest.plugin.requested_role
            };
            let name = manifest.plugin.name.clone();
            let plugin_entry = PluginEntry {
                name: name.clone(),
                manifest,
                wasm_hash,
                enabled: true,
                installed_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                installed_role,
            };
            loaded.insert(name, plugin_entry);
        }
        // Second pass: dependency validation + circular detection.
        let mut admitted = std::collections::HashSet::new();
        for (name, entry) in &loaded {
            let mut deps_ok = true;
            for dep in &entry.manifest.dependencies.requires {
                if !loaded.contains_key(dep) {
                    return Err(anyhow::anyhow!("Plugin '{}' requires missing dependency '{}'", name, dep));
                }
                // Circular dependency check: A depends on B, B depends on A.
                if let Some(other) = loaded.get(dep) {
                    if other.manifest.dependencies.requires.contains(name) {
                        return Err(anyhow::anyhow!("Circular dependency detected between '{}' and '{}'", name, dep));
                    }
                }
            }
            deps_ok = true;
            if deps_ok {
                admitted.insert(name.clone());
                self.entries.insert(name.clone(), entry.clone());
            }
        }
        Ok(())
    }

    pub fn list(&self) -> Vec<&PluginEntry> {
        self.entries.values().collect()
    }

    pub fn get(&self, name: &str) -> Option<&PluginEntry> {
        self.entries.get(name)
    }

    pub fn enable(&mut self, name: &str) -> bool {
        self.entries.get_mut(name).map(|e| { e.enabled = true; true }).unwrap_or(false)
    }

    pub fn disable(&mut self, name: &str) -> bool {
        self.entries.get_mut(name).map(|e| { e.enabled = false; true }).unwrap_or(false)
    }

    pub fn remove(&mut self, name: &str) -> anyhow::Result<()> {
        let path = self.plugins_dir.join(name);
        if path.exists() {
            std::fs::remove_dir_all(&path)?;
        }
        self.entries.remove(name);
        Ok(())
    }

    /// Install a plugin from a local path, assigning the given security role.
    /// If `role` is None, uses the plugin's requested_role.
    pub fn install_from_path_with_role(&mut self, source: &Path, role: Option<PluginRole>) -> anyhow::Result<String> {
        let manifest = PluginManifest::load(&source.join("plugin.toml"))?;
        manifest.validate()?;
        let chosen_role = role.unwrap_or(manifest.plugin.requested_role);
        let name = self.install_from_path_internal(source, chosen_role)?;
        self.load_all()?;
        Ok(name)
    }

    fn install_from_path_internal(&mut self, source: &Path, chosen_role: PluginRole) -> anyhow::Result<String> {
        // Reject symlink sources to prevent traversal attacks.
        if let Ok(meta) = std::fs::symlink_metadata(source) {
            if meta.file_type().is_symlink() {
                return Err(anyhow::anyhow!("plugin source cannot be a symlink"));
            }
        }
        let manifest_path = source.join("plugin.toml");
        if !manifest_path.exists() {
            return Err(anyhow::anyhow!("plugin.toml not found in source directory"));
        }
        let manifest = PluginManifest::load(&manifest_path)?;
        manifest.validate()?;

        // Prevent path traversal in wasm_path
        let wasm_name = std::path::Path::new(&manifest.plugin.wasm_path);
        if wasm_name.components().any(|c| matches!(c, std::path::Component::ParentDir | std::path::Component::RootDir | std::path::Component::Prefix(..))) {
            return Err(anyhow::anyhow!("wasm_path contains path traversal components"));
        }

        // Prevent path traversal via plugin name
        let safe_name = manifest.plugin.name
            .replace('/', "_")
            .replace("\\", "_")
            .replace("..", "_");
        let dest = self.plugins_dir.join(&safe_name);
        if dest.exists() {
            std::fs::remove_dir_all(&dest)?;
        }
        std::fs::create_dir_all(&dest)?;

        // Copy manifest
        std::fs::copy(&manifest_path, dest.join("plugin.toml"))?;

        // Persist chosen role
        let role_path = dest.join(".installed_role");
        std::fs::write(&role_path, serde_json::to_string(&chosen_role)?)?;

        // Copy WASM (into plugin dir root, ignoring any directory components in wasm_name)
        let wasm_src = source.join(wasm_name);
        if !wasm_src.exists() {
            return Err(anyhow::anyhow!("WASM file not found at {:?}", wasm_src));
        }
        let wasm_dest = dest.join(wasm_name.file_name().unwrap_or_else(|| std::ffi::OsStr::new("plugin.wasm")));
        std::fs::copy(&wasm_src, &wasm_dest)?;

        // Copy source for audit trail
        let src_dest = dest.join("src");
        let src_source = source.join("src");
        if src_source.exists() && src_source.is_dir() {
            copy_dir_all(&src_source, &src_dest)?;
        }

        self.load_all()?;
        Ok(manifest.plugin.name)
    }

    pub fn install_from_path(&mut self, source: &Path) -> anyhow::Result<String> {
        self.install_from_path_with_role(source, None)
    }

    /// Find plugins that should trigger for the given message.
    pub fn find_triggered(&self, message: &str) -> Vec<&PluginEntry> {
        let lower = message.to_lowercase();
        self.entries
            .values()
            .filter(|e| e.enabled)
            .filter(|e| {
                if e.manifest.triggers.require_mention {
                    let mention = format!("@{}", e.name.to_lowercase());
                    lower.contains(&mention)
                } else {
                    e.manifest.triggers.keywords.iter().any(|k| lower.contains(&k.to_lowercase()))
                }
            })
            .collect()
    }

    /// Execute a plugin and return its output.
    pub fn execute(&self, entry: &PluginEntry, input_json: &str) -> anyhow::Result<String> {
        // Resolve wasm_path the same way load_all does: only the file_name component.
        let wasm_name = std::path::Path::new(&entry.manifest.plugin.wasm_path)
            .file_name()
            .unwrap_or(std::ffi::OsStr::new("plugin.wasm"));
        let wasm_path = self.plugins_dir.join(&entry.name).join(wasm_name);
        self.runtime.execute(&wasm_path, &entry.manifest, &entry.wasm_hash, entry.installed_role, input_json)
    }
}

fn copy_dir_all(src: &Path, dst: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dst)?;
    let dst_canon = std::fs::canonicalize(dst).unwrap_or_else(|_| dst.to_path_buf());
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let path = entry.path();
        let file_name = entry.file_name();
        // Reject suspicious file names that could escape the target directory.
        let name = file_name.to_string_lossy();
        if name.contains("..") || name.contains('/') || name.contains('\\') {
            tracing::warn!(target: "plugin", "Skipping suspicious file name during plugin install: {}", name);
            continue;
        }
        let dest = dst.join(&file_name);
        // Reject symlinks to prevent directory traversal / data exfiltration.
        let meta = std::fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() {
            tracing::warn!(target: "plugin", "Skipping symlink during plugin install: {:?}", path);
            continue;
        }
        // Path traversal guard: canonicalize existing paths, or build expected path for new ones.
        let dest_canon = if dest.exists() {
            std::fs::canonicalize(&dest).unwrap_or_else(|_| dest.clone())
        } else {
            // For paths that don't exist yet, canonicalize the parent and append the file name.
            let parent_canon = std::fs::canonicalize(dst).unwrap_or_else(|_| dst.to_path_buf());
            parent_canon.join(&file_name)
        };
        if !dest_canon.starts_with(&dst_canon) {
            tracing::warn!(target: "plugin", "Skipping path traversal attempt during plugin install: {:?}", path);
            continue;
        }
        if path.is_dir() {
            copy_dir_all(&path, &dest)?;
        } else {
            std::fs::copy(&path, &dest)?;
        }
    }
    Ok(())
}
