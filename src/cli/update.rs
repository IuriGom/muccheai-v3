//! Self-update command for MuccheAI.
//!
//! Checks GitHub for the latest version and updates the binary.

use crate::style::Theme;
use std::process::Command;

const GITHUB_RAW_TOML: &str =
    "https://raw.githubusercontent.com/IuriGom/muccheai-v3/main/Cargo.toml";
const GITHUB_REPO_URL: &str = "https://github.com/IuriGom/muccheai-v3.git";
const VERSION_CHECK_CACHE_HOURS: u64 = 24;

/// Check whether a newer version is available on GitHub.
///
/// Result is cached in `~/.muccheai/.version_check` for 24 hours.
pub async fn check_for_update() -> Option<String> {
    let cache_path = crate::config::MuccheConfig::config_path()
        .with_file_name(".version_check");

    // Use cached result if recent.
    if let Ok(meta) = std::fs::metadata(&cache_path) {
        if let Ok(modified) = meta.modified() {
            if let Ok(elapsed) = modified.elapsed() {
                if elapsed.as_secs() < VERSION_CHECK_CACHE_HOURS * 3600 {
                    if let Ok(cached) = std::fs::read_to_string(&cache_path) {
                        let current = env!("CARGO_PKG_VERSION");
                        let latest = cached.trim();
                        if !latest.is_empty() && latest != current {
                            return Some(latest.to_string());
                        }
                        return None;
                    }
                }
            }
        }
    }

    // Fetch latest version from GitHub raw TOML.
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(_) => return None,
    };

    let text = match client.get(GITHUB_RAW_TOML).send().await {
        Ok(r) if r.status().is_success() => match r.text().await {
            Ok(t) => t,
            Err(_) => return None,
        },
        _ => return None,
    };

    let latest = text
        .lines()
        .find_map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with("version") {
                trimmed.split('=').nth(1).map(|s| {
                    s.trim().trim_matches('"').trim_matches('"').to_string()
                })
            } else {
                None
            }
        })
        .unwrap_or_default();

    if latest.is_empty() {
        return None;
    }

    // Write cache.
    let _ = std::fs::write(&cache_path, &latest);

    let current = env!("CARGO_PKG_VERSION");
    if latest != current {
        Some(latest)
    } else {
        None
    }
}

/// Print update banner if a newer version exists.
pub async fn print_update_banner() {
    if let Some(latest) = check_for_update().await {
        eprintln!(
            "\n  🔔 New version {} available — run 'muccheai update' to update\n",
            latest
        );
    }
}

/// Run the self-update.
pub fn run_update() -> anyhow::Result<()> {
    let theme = Theme::Cyber;
    theme.print_header("Updating MuccheAI");

    let repo_path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let is_git_repo = repo_path.join(".git").is_dir();

    if is_git_repo {
        println!("  Detected local git repo at {}", repo_path.display());
        println!("  Pulling latest changes...\n");

        let status = Command::new("git")
            .args(["-C", &repo_path.to_string_lossy(), "pull", "origin", "main"])
            .status()?;

        if !status.success() {
            anyhow::bail!("git pull failed — check for local changes and try again.");
        }

        println!("  Building and installing...\n");
        let install_status = Command::new("cargo")
            .args(["install", "--path", &repo_path.to_string_lossy(), "--force"])
            .status()?;

        if !install_status.success() {
            anyhow::bail!("cargo install failed.");
        }

        theme.print_success("Update complete!");
    } else {
        println!("  Installing from GitHub...\n");
        let status = Command::new("cargo")
            .args([
                "install",
                "--git",
                GITHUB_REPO_URL,
                "--force",
            ])
            .status()?;

        if !status.success() {
            anyhow::bail!("cargo install --git failed.");
        }

        theme.print_success("Update complete!");
    }

    Ok(())
}
