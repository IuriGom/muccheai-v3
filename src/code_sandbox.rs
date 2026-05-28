//! Inline code sandbox — detect and safely execute code blocks from LLM responses.

use std::process::Stdio;
use std::time::Duration;

/// A single fenced code block extracted from markdown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeBlock {
    /// Language tag (e.g. "python", "rust", "bash").
    pub language: String,
    /// Raw code content.
    pub code: String,
}

/// Execution result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionResult {
    /// stdout
    pub stdout: String,
    /// stderr
    pub stderr: String,
    /// exit code (None if killed/timed out)
    pub exit_code: Option<i32>,
    /// Whether execution was sandboxed (firejail/docker)
    pub sandboxed: bool,
}

/// Extract ```language fenced code blocks from text.
pub fn extract_code_blocks(text: &str) -> Vec<CodeBlock> {
    let mut blocks = Vec::new();
    let mut lines = text.lines().peekable();
    while let Some(line) = lines.next() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("```") {
            let lang = trimmed[3..].trim().to_string();
            let mut code = String::new();
            for inner in lines.by_ref() {
                if inner.trim_start().starts_with("```") {
                    break;
                }
                if !code.is_empty() {
                    code.push('\n');
                }
                code.push_str(inner);
            }
            if !code.is_empty() {
                blocks.push(CodeBlock { language: lang, code });
            }
        }
    }
    blocks
}

/// Execute a code block inside a sandbox.
/// Priority: firejail → docker → bare subprocess with rlimits.
pub async fn execute_code_block(block: &CodeBlock) -> anyhow::Result<ExecutionResult> {
    let lang = block.language.to_lowercase();
    if lang == "python" || lang == "py" {
        if has_firejail() {
            return run_firejail("python3", &["-c", &block.code], &lang).await;
        }
        if has_docker() {
            return run_docker("python:3-alpine", "python3", &["-c", &block.code], &lang).await;
        }
        return run_subprocess("python3", &["-c", &block.code]).await;
    }
    if lang == "bash" || lang == "sh" || lang == "shell" {
        if has_firejail() {
            return run_firejail("bash", &["-c", &block.code], &lang).await;
        }
        if has_docker() {
            return run_docker("alpine:latest", "sh", &["-c", &block.code], &lang).await;
        }
        return run_subprocess("bash", &["-c", &block.code]).await;
    }
    if lang == "rust" || lang == "rs" {
        // For rust we need a file; use docker if possible, else bare rustc
        if has_docker() {
            return run_docker(
                "rust:slim",
                "bash",
                &["-c", &format!("echo '{}' > /tmp/main.rs && rustc /tmp/main.rs -o /tmp/main && /tmp/main", escape_single_quotes(&block.code))],
                &lang,
            )
            .await;
        }
        return Err(anyhow::anyhow!("Rust execution requires Docker sandbox"));
    }
    if lang == "javascript" || lang == "js" || lang == "node" {
        if has_docker() {
            return run_docker("node:alpine", "node", &["-e", &block.code], &lang).await;
        }
        return run_subprocess("node", &["-e", &block.code]).await;
    }

    Err(anyhow::anyhow!("Unsupported language for sandbox execution: {}", block.language))
}

fn has_firejail() -> bool {
    which::which("firejail").is_ok()
}

fn has_docker() -> bool {
    which::which("docker").is_ok()
}

async fn run_firejail(cmd: &str, args: &[&str], _lang: &str) -> anyhow::Result<ExecutionResult> {
    let mut command = tokio::process::Command::new("firejail");
    command
        .arg("--noprofile")
        .arg("--private")
        .arg("--net=none")
        .arg("--rlimit-cpu=30")
        .arg("--rlimit-fsize=10485760")
        .arg("--rlimit-nofile=64")
        .arg(cmd)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let child = command.spawn()?;
    let output = tokio::time::timeout(Duration::from_secs(30), child.wait_with_output()).await??;

    Ok(ExecutionResult {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        exit_code: output.status.code(),
        sandboxed: true,
    })
}

async fn run_docker(
    image: &str,
    cmd: &str,
    args: &[&str],
    _lang: &str,
) -> anyhow::Result<ExecutionResult> {
    let mut command = tokio::process::Command::new("docker");
    command
        .arg("run")
        .arg("--rm")
        .arg("--network=none")
        .arg("--memory=256m")
        .arg("--cpus=1.0")
        .arg("--read-only")
        .arg("-i")
        .arg(image)
        .arg(cmd)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let child = command.spawn()?;
    let output = tokio::time::timeout(Duration::from_secs(30), child.wait_with_output()).await??;

    Ok(ExecutionResult {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        exit_code: output.status.code(),
        sandboxed: true,
    })
}

async fn run_subprocess(cmd: &str, args: &[&str]) -> anyhow::Result<ExecutionResult> {
    let mut command = tokio::process::Command::new(cmd);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    // Best-effort rlimits on Unix
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            command.pre_exec(|| {
                #[cfg(target_os = "linux")]
                {
                    let mem_limit = libc::rlimit {
                        rlim_cur: 256 * 1024 * 1024,
                        rlim_max: 256 * 1024 * 1024,
                    };
                    let _ = libc::setrlimit(libc::RLIMIT_AS, &mem_limit);
                }
                let cpu_limit = libc::rlimit {
                    rlim_cur: 30,
                    rlim_max: 30,
                };
                let _ = libc::setrlimit(libc::RLIMIT_CPU, &cpu_limit);
                let core_limit = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                let _ = libc::setrlimit(libc::RLIMIT_CORE, &core_limit);
                Ok(())
            });
        }
    }

    let child = command.spawn()?;
    let output = tokio::time::timeout(Duration::from_secs(30), child.wait_with_output()).await??;

    Ok(ExecutionResult {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        exit_code: output.status.code(),
        sandboxed: false,
    })
}

fn escape_single_quotes(s: &str) -> String {
    s.replace('\'', "'\"'\"'")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_code_blocks() {
        let text = r#"Here is some code:
```python
print("hello")
```
And another:
```bash
echo world
```
"#;
        let blocks = extract_code_blocks(text);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].language, "python");
        assert_eq!(blocks[0].code, r#"print("hello")"#);
        assert_eq!(blocks[1].language, "bash");
        assert_eq!(blocks[1].code, "echo world");
    }

    #[test]
    fn test_extract_no_blocks() {
        let text = "Just plain text without code.";
        assert!(extract_code_blocks(text).is_empty());
    }

    #[test]
    fn test_extract_multiline() {
        let text = r#"```rust
fn main() {
    println!("ok");
}
```"#;
        let blocks = extract_code_blocks(text);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].language, "rust");
        assert!(blocks[0].code.contains("fn main()"));
    }
}
