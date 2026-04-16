//! Bootstrap file loader
//!
//! Loads workspace markdown files into the LLM context window.

use std::path::Path;

/// A bootstrap file loaded from the workspace.
#[derive(Debug, Clone)]
pub struct BootstrapFile {
    /// File name
    pub name: String,
    /// File content
    pub content: String,
}

/// Load all bootstrap files in the specified order.
///
/// Returns files in order: AGENTS → SOUL → IDENTITY → USER → TOOLS → MEMORY → HEARTBEAT.
/// Missing files are returned with empty content.
pub fn load_bootstrap_files(workspace: &Path) -> Vec<BootstrapFile> {
    let files = [
        "AGENTS.md",
        "SOUL.md",
        "IDENTITY.md",
        "USER.md",
        "TOOLS.md",
        "MEMORY.md",
        "HEARTBEAT.md",
    ];

    let mut results = Vec::new();
    for name in &files {
        let path = workspace.join(name);
        let content = if path.exists() {
            std::fs::read_to_string(&path).unwrap_or_default()
        } else {
            String::new()
        };
        results.push(BootstrapFile {
            name: name.to_string(),
            content,
        });
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_load_bootstrap_order() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("AGENTS.md"), "agents").unwrap();
        std::fs::write(tmp.path().join("SOUL.md"), "soul").unwrap();

        let files = load_bootstrap_files(tmp.path());
        assert_eq!(files.len(), 7);
        assert_eq!(files[0].name, "AGENTS.md");
        assert_eq!(files[0].content, "agents");
        assert_eq!(files[1].name, "SOUL.md");
        assert_eq!(files[1].content, "soul");
        assert_eq!(files[2].name, "IDENTITY.md");
        assert!(files[2].content.is_empty());
    }
}
