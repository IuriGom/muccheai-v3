//! Tool Gateway configuration
//!
//! Loads tool settings from `~/.muccheai/tools.toml`.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

/// Top-level configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolConfig {
    /// Tool-specific configurations
    #[serde(default)]
    pub tools: HashMap<String, ToolEntry>,
    /// MCP server configurations
    #[serde(default)]
    pub mcp: Option<McpConfig>,
}

/// Configuration for a single tool
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolEntry {
    /// Whether the tool is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Extra key-value settings
    #[serde(flatten)]
    pub settings: HashMap<String, toml::Value>,
}

/// MCP configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct McpConfig {
    /// MCP server definitions
    #[serde(default)]
    pub servers: HashMap<String, McpServerConfig>,
}

/// Single MCP server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerConfig {
    /// Transport type
    pub transport: String,
    /// Command (for stdio)
    #[serde(default)]
    pub command: Option<String>,
    /// Arguments (for stdio)
    #[serde(default)]
    pub args: Vec<String>,
    /// URL (for SSE/HTTP)
    #[serde(default)]
    pub url: Option<String>,
    /// API key (for HTTP)
    #[serde(default)]
    pub api_key: Option<String>,
}

fn default_true() -> bool {
    true
}

impl ToolConfig {
    /// Load configuration from `~/.muccheai/tools.toml`
    pub fn load() -> Self {
        let path = config_path();
        if !path.exists() {
            debug!("No tool config found at {:?}, using defaults", path);
            return Self::default();
        }

        let contents = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to read tool config: {}", e);
                return Self::default();
            }
        };

        match toml::from_str(&contents) {
            Ok(cfg) => cfg,
            Err(e) => {
                warn!("Failed to parse tool config: {}", e);
                Self::default()
            }
        }
    }

    /// Save configuration to `~/.muccheai/tools.toml`
    pub fn save(&self) -> std::io::Result<()> {
        let path = config_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let contents = toml::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let tmp_path = path.with_extension("tmp");
        std::fs::write(&tmp_path, contents)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&tmp_path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&tmp_path, perms)?;
        }
        std::fs::rename(&tmp_path, &path)?;
        Ok(())
    }

    /// Get a tool's settings if enabled
    pub fn get_tool(&self, name: &str) -> Option<&ToolEntry> {
        self.tools.get(name).filter(|e| e.enabled)
    }

    /// Check if a tool is enabled
    pub fn is_enabled(&self, name: &str) -> bool {
        self.tools
            .get(name)
            .map(|e| e.enabled)
            .unwrap_or(true)
    }
}

/// Return the default configuration file path
pub fn config_path() -> PathBuf {
    dirs::home_dir()
        .map(|h| h.join(".muccheai").join("tools.toml"))
        .unwrap_or_else(|| PathBuf::from(".muccheai/tools.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_parse() {
        let toml_str = r#"
[tools.email]
enabled = true
smtp_host = "smtp.gmail.com"
smtp_port = 587

[tools.github]
enabled = true
token = "ghp_..."

[mcp.servers.pieces]
transport = "stdio"
command = "mcp-remote"
args = ["http://localhost:39300/mcp"]
"#;
        let cfg: ToolConfig = toml::from_str(toml_str).unwrap();
        assert!(cfg.is_enabled("email"));
        assert!(cfg.is_enabled("github"));
        let email = cfg.get_tool("email").unwrap();
        assert_eq!(
            email.settings.get("smtp_host").unwrap().as_str(),
            Some("smtp.gmail.com")
        );
        let mcp = cfg.mcp.as_ref().unwrap();
        assert!(mcp.servers.contains_key("pieces"));
    }
}
