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
            if host.contains('*') || host.contains('/') {
                return Err(anyhow::anyhow!("Invalid http_hosts entry: {}", host));
            }
        }
        Ok(())
    }
}
