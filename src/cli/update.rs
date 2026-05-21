//! Check for MuccheAI updates via GitHub API.

const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const GITHUB_API_URL: &str = "https://api.github.com/repos/muccheai/muccheai/releases/latest";

/// Query GitHub for the latest release and compare with the current version.
pub async fn run() -> anyhow::Result<()> {
    let current = env!("CARGO_PKG_VERSION");
    println!("MuccheAI v{current}");
    println!("Checking for updates...");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .connect_timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .pool_max_idle_per_host(5)
        .build()?;

    match client
        .get(GITHUB_API_URL)
        .header("User-Agent", format!("muccheai/{}", CURRENT_VERSION))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            let json: serde_json::Value = resp.json().await?;
            if let Some(latest) = json.get("tag_name").and_then(|v| v.as_str()) {
                let latest_trimmed = latest.trim_start_matches('v');
                if latest_trimmed == CURRENT_VERSION {
                    println!("✓ MuccheAI is up to date ({CURRENT_VERSION})");
                } else {
                    println!("⬆️  Update available: {CURRENT_VERSION} → {latest}");
                    if let Some(url) = json.get("html_url").and_then(|v| v.as_str()) {
                        println!("   {url}");
                    }
                }
            } else {
                println!("⚠ Could not determine latest version from GitHub API");
            }
        }
        Ok(resp) => {
            println!("⚠ GitHub API returned HTTP {}", resp.status());
        }
        Err(e) => {
            println!("⚠ Could not check for updates: {e}");
        }
    }
    Ok(())
}
