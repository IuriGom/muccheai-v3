//! Development tool adapters
//!
//! Includes: github, git, shell, docker

use muccheai_types::{ToolError, ToolResult, ToolResultMetadata};
use serde_json::json;

/// Run a std::process::Command with a timeout, killing the child if it exceeds the limit.
fn run_with_timeout(
    mut cmd: std::process::Command,
    timeout: std::time::Duration,
) -> Result<std::process::Output, String> {
    use std::sync::{Arc, Mutex};

    let child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn error: {}", e))?;

    let child_arc = Arc::new(Mutex::new(Some(child)));
    let child_clone = Arc::clone(&child_arc);

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = if let Some(mut child) = child_clone.lock().unwrap().take() {
            child.wait_with_output()
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "process already terminated",
            ))
        };
        let _ = tx.send(result);
    });

    match rx.recv_timeout(timeout) {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(e)) => Err(format!("process error: {}", e)),
        Err(_) => {
            if let Some(mut child) = child_arc.lock().unwrap().take() {
                let _ = child.kill();
            }
            Err("command timed out".to_string())
        }
    }
}

/// GitHub adapter — create issues, PRs, comments
pub fn github_create_issue(params: &serde_json::Value) -> Result<ToolResult, ToolError> {
    let token = params
        .get("token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ToolError::InvalidParams("Missing 'token'".to_string()))?;
    let owner = params
        .get("owner")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ToolError::InvalidParams("Missing 'owner'".to_string()))?;
    let repo = params
        .get("repo")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ToolError::InvalidParams("Missing 'repo'".to_string()))?;
    let title = params
        .get("title")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ToolError::InvalidParams("Missing 'title'".to_string()))?;
    let body = params.get("body").and_then(|v| v.as_str()).unwrap_or("");

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| ToolError::ExecutionFailed(e.to_string()))?;

    let url = format!("https://api.github.com/repos/{}/{}/issues", owner, repo);
    let payload = json!({
        "title": title,
        "body": body,
    });

    let resp = client
        .post(&url)
        .header("Authorization", format!("token {}", token))
        .header("User-Agent", "muccheai-tool-gateway")
        .json(&payload)
        .send()
        .map_err(|e| ToolError::ExecutionFailed(format!("GitHub HTTP error: {}", e)))?;

    if !resp.status().is_success() {
        return Err(ToolError::ExecutionFailed(format!(
            "GitHub API error: {}",
            resp.status()
        )));
    }

    let data: serde_json::Value = resp
        .json()
        .map_err(|e| ToolError::ExecutionFailed(format!("GitHub JSON error: {}", e)))?;

    Ok(ToolResult {
        success: true,
        data: json!({
            "status": "created",
            "issue_number": data["number"],
            "html_url": data["html_url"],
            "title": title
        }),
        metadata: ToolResultMetadata {
            execution_time_ms: 0,
            tool_id: "github".to_string(),
            method: "create_issue".to_string(),
        },
    })
}

/// Git adapter — run git commands
pub fn git_run(params: &serde_json::Value) -> Result<ToolResult, ToolError> {
    let command = params
        .get("command")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ToolError::InvalidParams("Missing 'command'".to_string()))?;
    let repo_path = params.get("repo_path").and_then(|v| v.as_str()).unwrap_or(".");

    // Validate repo_path to prevent traversal, absolute path abuse, and symlink escapes.
    let cwd = std::env::current_dir().map_err(|e| {
        ToolError::ExecutionFailed(format!("Failed to get current directory: {}", e))
    })?;
    let repo_canonical = std::path::Path::new(repo_path).canonicalize().map_err(|e| {
        ToolError::CapabilityDenied(format!("Invalid repo_path: {}", e))
    })?;
    if !repo_canonical.starts_with(&cwd) {
        return Err(ToolError::CapabilityDenied(
            "repo_path escapes allowed directory".to_string(),
        ));
    }

    // Allowed git subcommands
    let allowed = ["status", "log", "diff", "branch", "show", "remote"];
    let parts: Vec<&str> = command.split_whitespace().collect();
    let subcommand = parts.first().copied().unwrap_or("");

    if !allowed.contains(&subcommand) {
        return Err(ToolError::CapabilityDenied(format!(
            "Git subcommand '{}' is not allowed. Allowed: {:?}",
            subcommand, allowed
        )));
    }

    // Block dangerous flags that can write to arbitrary files or execute code.
    let dangerous_flags = [
        "--output", "--open-files-in-pager", "-p", "--paginate",
        "--exec", "--upload-pack", "--receive-pack", "--config", "-c", "--no-index",
    ];
    for part in &parts {
        let part_lower = part.to_lowercase();
        for flag in &dangerous_flags {
            let flag_lower = flag.to_lowercase();
            if part_lower == flag_lower || part_lower.starts_with(&flag_lower) {
                return Err(ToolError::CapabilityDenied(format!(
                    "Dangerous git flag '{}' is not allowed",
                    flag
                )));
            }
        }
    }

    let mut cmd = std::process::Command::new("git");
    cmd.env_clear()
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("HOME", "/dev/null")
        .arg("-c")
        .arg("alias.status=status")
        .arg("-c")
        .arg("alias.log=log")
        .arg("-c")
        .arg("alias.diff=diff")
        .arg("-c")
        .arg("alias.branch=branch")
        .arg("-c")
        .arg("alias.show=show")
        .arg("-c")
        .arg("alias.remote=remote")
        .arg("-c")
        .arg("alias.fetch=fetch")
        .arg("-C")
        .arg(&repo_canonical)
        .args(parts);
    let output = run_with_timeout(cmd, std::time::Duration::from_secs(30))
        .map_err(|e| ToolError::ExecutionFailed(format!("Git execution failed: {}", e)))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    Ok(ToolResult {
        success: output.status.success(),
        data: json!({
            "stdout": stdout.to_string(),
            "stderr": stderr.to_string(),
            "exit_code": output.status.code()
        }),
        metadata: ToolResultMetadata {
            execution_time_ms: 0,
            tool_id: "git".to_string(),
            method: "run".to_string(),
        },
    })
}

/// Shell adapter — DISABLED for security.
///
/// The previous implementation used a prefix-based allowlist that was
/// trivially bypassed (e.g. `cat /etc/shadow`, `cp /etc/passwd /tmp/`).
/// Shell execution cannot be made safe while remaining useful.
///
/// If you need file inspection, use the `csv.read`, `json.transform`,
/// or `sqlite.query` adapters instead.
#[cfg(feature = "shell")]
pub fn shell_run(_params: &serde_json::Value) -> Result<ToolResult, ToolError> {
    Err(ToolError::CapabilityDenied(
        "Shell execution is disabled for security reasons. ".to_string()
        + "Use read-only data adapters (csv, json, sqlite) instead."
    ))
}

/// Docker adapter — run containers, list images
pub fn docker_run(params: &serde_json::Value) -> Result<ToolResult, ToolError> {
    let subcommand = params
        .get("subcommand")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ToolError::InvalidParams("Missing 'subcommand'".to_string()))?;
    let image = params.get("image").and_then(|v| v.as_str()).unwrap_or("");
    let args = params.get("args").and_then(|v| v.as_array());

    // Allowed docker subcommands — `run` removed because it allows arbitrary
    // code execution inside containers with full network egress.
    let allowed = ["ps", "images", "logs", "inspect", "version"];
    if !allowed.contains(&subcommand) {
        return Err(ToolError::CapabilityDenied(format!(
            "Docker subcommand '{}' not allowed. Allowed: {:?}",
            subcommand, allowed
        )));
    }

    // Block dangerous args that escape container isolation.
    let dangerous = [
        "--privileged", "-v", "--volume", "--network", "--pid",
        "--cap-add", "--cap-drop", "--device", "--security-opt",
        "--userns", "--ipc", "--uts", "--cgroupns", "--runtime",
    ];
    if let Some(a) = args {
        for arg in a {
            if let Some(s) = arg.as_str() {
                let s_lower = s.to_lowercase();
                for d in &dangerous {
                    let d_lower = d.to_lowercase();
                    if s_lower == d_lower || s_lower.starts_with(&d_lower) {
                        return Err(ToolError::CapabilityDenied(format!(
                            "Dangerous docker argument '{}' is not allowed",
                            d
                        )));
                    }
                }
            }
        }
    }

    let mut cmd = std::process::Command::new("docker");
    cmd.arg(subcommand);
    if !image.is_empty() {
        cmd.arg(image);
    }
    if let Some(a) = args {
        for arg in a {
            if let Some(s) = arg.as_str() {
                cmd.arg(s);
            }
        }
    }

    let output = run_with_timeout(cmd, std::time::Duration::from_secs(30))
        .map_err(|e| ToolError::ExecutionFailed(format!("Docker execution failed: {}", e)))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    Ok(ToolResult {
        success: output.status.success(),
        data: json!({
            "stdout": stdout.to_string(),
            "stderr": stderr.to_string(),
            "exit_code": output.status.code()
        }),
        metadata: ToolResultMetadata {
            execution_time_ms: 0,
            tool_id: "docker".to_string(),
            method: "run".to_string(),
        },
    })
}
