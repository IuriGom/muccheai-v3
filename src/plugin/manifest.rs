//! Plugin capability manifest parser.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub plugin: PluginMeta,
    pub capabilities: PluginCapabilities,
    #[serde(default)]
    pub triggers: PluginTriggers,
    #[serde(default)]
    pub output: PluginOutput,
}

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
    /// Worker + read memories + propose memories + llm_callback.
    Assistant,
    /// Everything but each sensitive action requires manual approval.
    Privileged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginCapabilities {
    #[serde(default)]
    pub http_hosts: Vec<String>,
    #[serde(default = "default_none")]
    pub filesystem: String,
    #[serde(default = "default_none")]
    pub env: String,
    #[serde(default = "default_none")]
    pub exec: String,
    #[serde(default)]
    pub llm_callback: bool,
    #[serde(default = "default_storage")]
    pub storage_dir: String,
}

fn default_none() -> String { "none".to_string() }
fn default_storage() -> String { "data".to_string() }

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginTriggers {
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default)]
    pub require_mention: bool,
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
        if self.plugin.name.is_empty() {
            return Err(anyhow::anyhow!("Plugin name is required"));
        }
        if self.plugin.wasm_path.is_empty() {
            return Err(anyhow::anyhow!("Plugin wasm_path is required"));
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
}

impl PluginRole {
    /// Whether this role may access the network at all.
    pub fn may_network(&self) -> bool {
        matches!(self, Self::Messenger | Self::Worker | Self::Assistant | Self::Privileged)
    }

    /// Whether this role may execute commands (even sandboxed).
    pub fn may_exec(&self) -> bool {
        matches!(self, Self::Worker | Self::Assistant | Self::Privileged)
    }

    /// Whether this role may access structured memories.
    pub fn may_read_memories(&self) -> bool {
        matches!(self, Self::Observer | Self::Assistant | Self::Privileged)
    }

    /// Whether this role may propose new memories.
    pub fn may_propose_memory(&self) -> bool {
        matches!(self, Self::Assistant | Self::Privileged)
    }

    /// Whether this role may trigger LLM callbacks.
    pub fn may_llm_callback(&self) -> bool {
        matches!(self, Self::Assistant | Self::Privileged)
    }
}
