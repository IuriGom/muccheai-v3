//! Plugin system — manager, runtime, manifest.

pub mod manifest;
pub mod runtime;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

use manifest::PluginManifest;
use runtime::PluginRuntime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginEntry {
    pub name: String,
    pub manifest: PluginManifest,
    pub wasm_hash: String,
    pub enabled: bool,
    pub installed_at: u64,
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

    pub fn load_all(&mut self) -> anyhow::Result<()> {
        self.entries.clear();
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
            let wasm_path = path.join(std::path::Path::new(&manifest.plugin.wasm_path).file_name().unwrap_or_else(|| std::ffi::OsStr::new("plugin.wasm")));
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
            };
            self.entries.insert(name, plugin_entry);
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

    pub fn install_from_path(&mut self, source: &Path) -> anyhow::Result<String> {
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
        let wasm_path = self.plugins_dir.join(&entry.name).join(&entry.manifest.plugin.wasm_path);
        self.runtime.execute(&wasm_path, &entry.manifest, &entry.wasm_hash, input_json)
    }
}

fn copy_dir_all(src: &Path, dst: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let path = entry.path();
        let dest = dst.join(entry.file_name());
        // Reject symlinks to prevent directory traversal / data exfiltration.
        let meta = std::fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() {
            tracing::warn!(target: "plugin", "Skipping symlink during plugin install: {:?}", path);
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
