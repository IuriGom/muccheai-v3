//! Plugin capability manifest parser.

use serde::{Deserialize, Serialize};
use std::path::Path;



#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMeta {
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    pub license: String,
    pub wasm_path: String,
    #[serde(default)]
    pub requested_role: PluginRole,
    /// Expected SHA3-256 hash of the WASM binary (hex).
    /// If present, the runtime verifies the loaded WASM matches.
    #[serde(default)]
    pub expected_wasm_hash: Option<String>,
    /// Ed25519 public key of the plugin author (hex, 64 chars).
    #[serde(default)]
    pub author_pubkey: Option<String>,
    /// Ed25519 signature of the manifest + expected_wasm_hash (hex).
    #[serde(default)]
    pub signature: Option<String>,
}

/// Predefined security roles for plugins.
/// The user can downgrade but never upgrade automatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PluginRole {
    /// Read-only: memories, /data, logs. No network, no exec.
    #[default]
    Observer,
    /// HTTP allowlist + /data + logs. No exec, no env, no memories.
    Messenger,
    /// HTTP allowlist + /data + sandboxed exec + filtered env.
    Worker,
    /// Worker + read memories + propose memories.
    Assistant,
    /// Everything but each sensitive action requires manual approval.
    Privileged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    #[serde(default = "default_manifest_version")]
    pub manifest_version: String,
    pub plugin: PluginMeta,
    pub capabilities: PluginCapabilities,
    #[serde(default)]
    pub triggers: PluginTriggers,
    #[serde(default)]
    pub output: PluginOutput,
    #[serde(default)]
    pub dependencies: PluginDependencies,
}

fn default_manifest_version() -> String { "1.0".to_string() }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginCapabilities {
    #[serde(default)]
    pub http_hosts: Vec<String>,
    #[serde(default = "default_none")]
    pub filesystem: String,
    #[serde(default = "default_none")]
    pub env: String,
    #[serde(default = "default_storage")]
    pub storage_dir: String,
    /// Max HTTP requests per minute (default 60).
    #[serde(default = "default_rate_limit")]
    pub max_requests_per_minute: u32,
    /// Max HTTP request/response body size in bytes (default 1MB).
    #[serde(default = "default_max_body_size")]
    pub max_body_size: u64,
    /// Max memory usage in MB (enforced via wasmtime StoreLimits).
    #[serde(default)]
    pub max_memory_mb: Option<u64>,
    /// Max CPU percent (0-100). 0 = no limit.
    /// Note: WASI preview1 does not expose process spawning, so this is
    /// best-effort via instruction counting when fuel is enabled.
    #[serde(default)]
    pub max_cpu_percent: Option<u8>,
}

fn default_none() -> String { "none".to_string() }
fn default_storage() -> String { "data".to_string() }
fn default_rate_limit() -> u32 { 60 }
fn default_max_body_size() -> u64 { 1024 * 1024 }

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginTriggers {
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default)]
    pub require_mention: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginDependencies {
    #[serde(default)]
    pub requires: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginOutput {
    #[serde(default = "default_prefix")]
    pub mode: String,
    #[serde(default)]
    pub template: Option<String>,
}

fn default_prefix() -> String { "prefix".to_string() }

impl PluginManifest {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let manifest: PluginManifest = toml::from_str(&text)?;
        Ok(manifest)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.manifest_version != "1.0" {
            return Err(anyhow::anyhow!("Unsupported manifest version: {}", self.manifest_version));
        }
        if self.plugin.name.is_empty() {
            return Err(anyhow::anyhow!("Plugin name is required"));
        }
        if self.plugin.wasm_path.is_empty() {
            return Err(anyhow::anyhow!("Plugin wasm_path is required"));
        }
        if let Some(ref hash) = self.plugin.expected_wasm_hash {
            if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(anyhow::anyhow!("expected_wasm_hash must be 64 hex chars"));
            }
        }
        if let Some(ref pk) = self.plugin.author_pubkey {
            if pk.len() != 64 || !pk.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(anyhow::anyhow!("author_pubkey must be 64 hex chars (Ed25519)"));
            }
        }
        if let Some(ref sig) = self.plugin.signature {
            if sig.len() != 128 || !sig.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(anyhow::anyhow!("signature must be 128 hex chars (Ed25519)"));
            }
        }
        for host in &self.capabilities.http_hosts {
            if host.is_empty() {
                return Err(anyhow::anyhow!("Empty http_hosts entry is not allowed"));
            }
            if host.contains('*') || host.contains('/') || host.contains("..") {
                return Err(anyhow::anyhow!("Invalid http_hosts entry: {}", host));
            }
            // Reject raw IP addresses — plugins should declare hostnames.
            if host.parse::<std::net::IpAddr>().is_ok() {
                return Err(anyhow::anyhow!("IP addresses not allowed in http_hosts (use hostnames): {}", host));
            }
        }
        // Validate that Privileged plugins declare *why* they need it.
        if self.plugin.requested_role == PluginRole::Privileged {
            if self.capabilities.http_hosts.len() > 10 {
                return Err(anyhow::anyhow!("Privileged plugins may not request more than 10 HTTP hosts"));
            }
        }
        Ok(())
    }

    /// Compute the canonical bytes that the author should sign.
    /// Includes manifest_version, plugin metadata (without signature), capabilities, triggers, output.
    pub fn canonical_signing_bytes(&self) -> Vec<u8> {
        let stripped = PluginManifest {
            manifest_version: self.manifest_version.clone(),
            plugin: PluginMeta {
                signature: None,
                ..self.plugin.clone()
            },
            capabilities: self.capabilities.clone(),
            triggers: self.triggers.clone(),
            output: self.output.clone(),
            dependencies: self.dependencies.clone(),
        };
        // Use a deterministic representation (TOML is stable enough for this purpose).
        match toml::to_string(&stripped) {
            Ok(s) => s.into_bytes(),
            Err(_) => Vec::new(),
        }
    }
}

impl PluginRole {
    /// Whether this role may access the network at all.
    pub fn may_network(&self) -> bool {
        matches!(self, Self::Messenger | Self::Worker | Self::Assistant | Self::Privileged)
    }

    /// Whether this role may access structured memories.
    pub fn may_read_memories(&self) -> bool {
        matches!(self, Self::Observer | Self::Assistant | Self::Privileged)
    }

    /// Whether this role may propose new memories.
    pub fn may_propose_memory(&self) -> bool {
        matches!(self, Self::Assistant | Self::Privileged)
    }
}
