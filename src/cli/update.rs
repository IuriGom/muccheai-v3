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

/// Attempt to discover the local git repo path at runtime.
/// Walks up from the current working directory looking for a .git folder.
fn find_local_repo() -> Option<std::path::PathBuf> {
    let mut current = std::env::current_dir().ok()?;
    loop {
        if current.join(".git").is_dir() && current.join("Cargo.toml").is_file() {
            return Some(current);
        }
        if !current.pop() {
            break;
        }
    }
    None
}

/// Run the self-update.
pub fn run_update() -> anyhow::Result<()> {
    let theme = Theme::Cyber;
    theme.print_header("Updating MuccheAI");

    // Warn user about security implications of auto-updates.
    eprintln!("⚠️  SECURITY NOTICE:");
    eprintln!("   This command fetches and executes code from the internet.");
    eprintln!("   No commit signature verification is performed.");
    eprintln!("   If you need supply-chain guarantees, build from a verified git tag instead.");
    eprintln!();

    let repo_path = find_local_repo();

    if let Some(ref path) = repo_path {
        println!("  Detected local git repo at {}", path.display());
        println!("  Pulling latest changes...\n");

        // Fetch the latest commit hash so the user can verify it.
        let hash_output = Command::new("git")
            .args(["-C", &path.to_string_lossy(), "rev-parse", "HEAD"])
            .output()?;
        let before_hash = String::from_utf8_lossy(&hash_output.stdout).trim().to_string();
        if before_hash.len() == 40 {
            println!("  Current commit: {}", &before_hash[..12]);
        }

        let status = Command::new("git")
            .args(["-C", &path.to_string_lossy(), "pull", "origin", "main"])
            .status()?;

        if !status.success() {
            anyhow::bail!("git pull failed — check for local changes and try again.");
        }

        let hash_output = Command::new("git")
            .args(["-C", &path.to_string_lossy(), "rev-parse", "HEAD"])
            .output()?;
        let after_hash = String::from_utf8_lossy(&hash_output.stdout).trim().to_string();
        if after_hash.len() == 40 {
            println!("  New commit: {}\n", &after_hash[..12]);
        }

        println!("  Building and installing...\n");
        let install_status = Command::new("cargo")
            .args(["install", "--path", &path.to_string_lossy(), "--force"])
            .status()?;

        if !install_status.success() {
            anyhow::bail!("cargo install failed.");
        }

        theme.print_success("Update complete!");
    } else {
        println!("  No local git repo found — installing from GitHub...\n");
        println!("  ⚠️  Installing from remote git without commit verification.");
        println!("  ⚠️  Consider cloning the repo and running `cargo install --path .` instead.\n");
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
