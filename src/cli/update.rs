//! Self-update command for MuccheAI.
//!
//! Checks GitHub for the latest version and updates the binary.

use crate::style::Theme;
use std::process::Command;

const GITHUB_RAW_TOML: &str =
    "https://raw.githubusercontent.com/IuriGom/muccheai-v3/main/Cargo.toml";
const GITHUB_REPO_URL: &str = "https://github.com/IuriGom/muccheai-v3.git";
const VERSION_CHECK_CACHE_HOURS: u64 = 24;

/// Parse a semver string like "3.2.0" into a comparable tuple.
fn parse_semver(v: &str) -> Option<(u64, u64, u64)> {
    let parts: Vec<&str> = v.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    Some((
        parts[0].parse().ok()?,
        parts[1].parse().ok()?,
        parts[2].parse().ok()?,
    ))
}

/// Compare two semver tuples. Returns true if `remote` is strictly newer than `local`.
fn is_newer(local: (u64, u64, u64), remote: (u64, u64, u64)) -> bool {
    remote.0 > local.0
        || (remote.0 == local.0 && remote.1 > local.1)
        || (remote.0 == local.0 && remote.1 == local.1 && remote.2 > local.2)
}

/// Read the cached version check file.
/// Returns (cached_version, cached_commit_hash) if valid and recent.
fn read_version_cache(cache_path: &std::path::Path) -> Option<(String, String)> {
    let meta = std::fs::metadata(cache_path).ok()?;
    let modified = meta.modified().ok()?;
    let elapsed = modified.elapsed().ok()?;
    if elapsed.as_secs() >= VERSION_CHECK_CACHE_HOURS * 3600 {
        return None;
    }
    let content = std::fs::read_to_string(cache_path).ok()?;
    let mut parts = content.trim().splitn(2, '|');
    let version = parts.next()?.to_string();
    let commit = parts.next()?.to_string();
    Some((version, commit))
}

/// Write the version check cache.
fn write_version_cache(cache_path: &std::path::Path, version: &str, commit: &str) {
    let _ = std::fs::write(cache_path, format!("{}|{}", version, commit));
}

/// Check whether a newer version is available on GitHub.
///
/// Returns Some((latest_version, remote_commit_hash)) if an update is available.
/// Result is cached in `~/.muccheai/.version_check` for 24 hours.
/// Cache is invalidated if the local git commit changes.
pub async fn check_for_update() -> Option<(String, String)> {
    let cache_path = crate::config::MuccheConfig::config_path()
        .with_file_name(".version_check");

    let local_version = env!("CARGO_PKG_VERSION");
    let local_commit = env!("GIT_COMMIT_HASH");

    // Try cache first, but invalidate if local commit changed.
    if let Some((cached_version, cached_commit)) = read_version_cache(&cache_path) {
        if cached_commit == local_commit {
            let local_sem = parse_semver(local_version)?;
            let remote_sem = parse_semver(&cached_version)?;
            if is_newer(local_sem, remote_sem) {
                return Some((cached_version, cached_commit));
            }
            return None;
        }
        // Local commit changed — invalidate cache and re-fetch.
    }

    // Fetch latest version from GitHub raw TOML.
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("Update check: failed to build HTTP client: {}", e);
            return None;
        }
    };

    let text = match client.get(GITHUB_RAW_TOML).send().await {
        Ok(r) if r.status().is_success() => match r.text().await {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!("Update check: failed to read response body: {}", e);
                return None;
            }
        },
        Ok(r) => {
            tracing::warn!("Update check: GitHub returned status {}", r.status());
            return None;
        }
        Err(e) => {
            tracing::warn!("Update check: request failed: {}", e);
            return None;
        }
    };

    let latest = text
        .lines()
        .find_map(|line| {
            let trimmed = line.trim();
            // Match exactly `version = "..."` (not `version.workspace = true`)
            if (trimmed.starts_with("version ") || trimmed.starts_with("version="))
                && !trimmed.contains(".workspace")
            {
                trimmed.split('=').nth(1).map(|s| {
                    s.trim()
                        .trim_matches('"')
                        .trim_matches('\'')
                        .to_string()
                })
            } else {
                None
            }
        })
        .unwrap_or_default();

    if latest.is_empty() {
        tracing::warn!("Update check: could not parse version from GitHub Cargo.toml");
        return None;
    }

    // Fetch remote commit hash for cache invalidation.
    let remote_commit = fetch_latest_commit_hash().unwrap_or_default();

    write_version_cache(&cache_path, &latest, &remote_commit);

    let local_sem = parse_semver(local_version)?;
    let remote_sem = parse_semver(&latest)?;
    if is_newer(local_sem, remote_sem) {
        Some((latest, remote_commit))
    } else {
        None
    }
}

/// Print update banner if a newer version exists.
pub async fn print_update_banner() {
    if std::env::var("MUCCHEAI_SKIP_UPDATE_CHECK").is_ok() {
        return;
    }
    if let Some((latest, _remote_commit)) = check_for_update().await {
        eprintln!();
        eprintln!("  🔔 New update available: v{} → v{}", env!("CARGO_PKG_VERSION"), latest);
        eprintln!("     Run 'muccheai update' to update now.");
        eprintln!();
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

/// Fetch the latest commit hash from GitHub API for the main branch.
fn fetch_latest_commit_hash() -> Option<String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .ok()?;
    let url = "https://api.github.com/repos/IuriGom/muccheai-v3/commits/main";
    let resp = client
        .get(url)
        .header("User-Agent", "muccheai-updater")
        .send()
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let json: serde_json::Value = resp.json().ok()?;
    json.get("sha")?.as_str().map(|s| s.to_string())
}

/// Prompt the user for confirmation (stdin-based).
fn confirm(prompt: &str) -> bool {
    use std::io::Write;
    print!("{} [y/N] ", prompt);
    let _ = std::io::stdout().flush();
    let mut buf = String::new();
    if std::io::stdin().read_line(&mut buf).is_err() {
        return false;
    }
    matches!(buf.trim().to_lowercase().as_str(), "y" | "yes")
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

        // Fetch the latest commit hash so the user can verify it.
        let hash_output = Command::new("git")
            .args(["-C", &path.to_string_lossy(), "rev-parse", "HEAD"])
            .output()?;
        let before_hash = String::from_utf8_lossy(&hash_output.stdout).trim().to_string();
        if before_hash.len() == 40 {
            println!("  Current commit: {}", &before_hash[..12]);
        }

        // Fetch remote latest commit hash for verification.
        let needs_pull = if let Some(remote_hash) = fetch_latest_commit_hash() {
            println!("  Remote latest:  {}", &remote_hash[..12.min(remote_hash.len())]);
            if before_hash == remote_hash {
                println!("  Local repo is on the latest commit.");
                false
            } else {
                if !confirm("  Proceed with update?") {
                    anyhow::bail!("Update cancelled by user.");
                }
                true
            }
        } else {
            println!("  ⚠️  Could not fetch remote commit hash. Proceeding blindly.");
            if !confirm("  Proceed without verification?") {
                anyhow::bail!("Update cancelled by user.");
            }
            true
        };

        if needs_pull {
            println!("  Pulling latest changes...\n");

            // Try git pull with HTTP/2 disabled first (fixes curl 16 framing errors).
            let status = Command::new("git")
                .args(["-C", &path.to_string_lossy(), "-c", "http.version=HTTP/1.1", "pull", "origin", "main"])
                .status()?;

            if !status.success() {
                eprintln!("  ⚠️  git pull failed. Trying fetch + merge fallback...");
                let fetch_status = Command::new("git")
                    .args(["-C", &path.to_string_lossy(), "-c", "http.version=HTTP/1.1", "fetch", "origin", "main"])
                    .status()?;
                if !fetch_status.success() {
                    anyhow::bail!("git fetch failed — check your network connection and try again.");
                }
                let merge_status = Command::new("git")
                    .args(["-C", &path.to_string_lossy(), "merge", "origin/main"])
                    .status()?;
                if !merge_status.success() {
                    anyhow::bail!("git merge failed — you may have local changes that conflict with the remote.");
                }
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
            println!("  Local repo is already on the latest commit. Nothing to do.");
        }
    } else {
        println!("  No local git repo found — installing from GitHub...\n");
        println!("  ⚠️  Installing from remote git without commit verification.");
        println!("  ⚠️  Consider cloning the repo and running `cargo install --path .` instead.\n");

        if let Some(remote_hash) = fetch_latest_commit_hash() {
            println!("  Remote latest: {}", &remote_hash[..12.min(remote_hash.len())]);
            if !confirm("  Proceed with installation?") {
                anyhow::bail!("Update cancelled by user.");
            }
        } else {
            println!("  ⚠️  Could not fetch remote commit hash.");
            if !confirm("  Proceed without verification?") {
                anyhow::bail!("Update cancelled by user.");
            }
        }

        // Try cargo install --git with HTTP/1.1 fallback for libgit2.
        let status = Command::new("cargo")
            .env("CARGO_NET_GIT_FETCH_WITH_CLI", "true")
            .args(["install", "--git", GITHUB_REPO_URL, "--force"])
            .status()?;

        if !status.success() {
            eprintln!("  ⚠️  cargo install --git failed. Trying with explicit HTTP/1.1...");
            let status2 = Command::new("cargo")
                .env("CARGO_NET_GIT_FETCH_WITH_CLI", "true")
                .env("GIT_HTTP_VERSION", "HTTP/1.1")
                .args(["install", "--git", GITHUB_REPO_URL, "--force"])
                .status()?;
            if !status2.success() {
                anyhow::bail!("cargo install --git failed. Try manually: git pull && cargo install --path .");
            }
        }

        theme.print_success("Update complete!");
    }

    Ok(())
}
