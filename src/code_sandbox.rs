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
            return run_docker("python:3.12-alpine", "python3", &["-c", &block.code], &lang).await;
        }
        return Err(anyhow::anyhow!("No sandbox available for Python execution"));
    }
    if lang == "bash" || lang == "sh" || lang == "shell" {
        if has_firejail() {
            return run_firejail("bash", &["-c", &block.code], &lang).await;
        }
        if has_docker() {
            return run_docker("alpine:3.19", "sh", &["-c", &block.code], &lang).await;
        }
        return Err(anyhow::anyhow!("No sandbox available for shell execution"));
    }
    if lang == "rust" || lang == "rs" {
        if has_docker() {
            return run_docker(
                "rust:1.78-slim",
                "bash",
                &["-c", &format!("printf '%s' '{}' > /tmp/main.rs && rustc /tmp/main.rs -o /tmp/main && /tmp/main", escape_single_quotes(&block.code))],
                &lang,
            )
            .await;
        }
        return Err(anyhow::anyhow!("Rust execution requires Docker sandbox"));
    }
    if lang == "javascript" || lang == "js" || lang == "node" {
        if has_docker() {
            return run_docker("node:20-alpine", "node", &["-e", &block.code], &lang).await;
        }
        return Err(anyhow::anyhow!("No sandbox available for JavaScript execution"));
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
        .arg("--private-tmp")
        .arg("--net=none")
        .arg("--blacklist=/proc")
        .arg("--blacklist=/sys")
        .arg("--rlimit-cpu=30")
        .arg("--rlimit-fsize=10485760")
        .arg("--rlimit-nofile=64")
        .arg("--rlimit-nproc=32")
        .arg(cmd)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let child = command.spawn()?;
    let output = tokio::time::timeout(Duration::from_secs(30), capped_output(child, 1024 * 1024)).await??;

    Ok(ExecutionResult {
        stdout: output.stdout,
        stderr: output.stderr,
        exit_code: output.exit_code,
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
        .arg("--pids-limit=32")
        .arg("--read-only")
        .arg("-i")
        .arg(image)
        .arg(cmd)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let child = command.spawn()?;
    let output = tokio::time::timeout(Duration::from_secs(30), capped_output(child, 1024 * 1024)).await??;

    Ok(ExecutionResult {
        stdout: output.stdout,
        stderr: output.stderr,
        exit_code: output.exit_code,
        sandboxed: true,
    })
}

/// Capped output from a child process — reads stdout/stderr up to max_bytes each.
struct CappedOutput {
    stdout: String,
    stderr: String,
    exit_code: Option<i32>,
}

async fn capped_output(
    mut child: tokio::process::Child,
    max_bytes: usize,
) -> anyhow::Result<CappedOutput> {
    use tokio::io::AsyncReadExt;

    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();

    let mut out_buf = Vec::new();
    let mut err_buf = Vec::new();

    let stdout_fut = async {
        if let Some(ref mut s) = stdout {
            let mut buf = [0u8; 4096];
            while out_buf.len() < max_bytes {
                match s.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => out_buf.extend_from_slice(&buf[..n.min(max_bytes.saturating_sub(out_buf.len()))]),
                    Err(_) => break,
                }
            }
        }
    };

    let stderr_fut = async {
        if let Some(ref mut s) = stderr {
            let mut buf = [0u8; 4096];
            while err_buf.len() < max_bytes {
                match s.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => err_buf.extend_from_slice(&buf[..n.min(max_bytes.saturating_sub(err_buf.len()))]),
                    Err(_) => break,
                }
            }
        }
    };

    tokio::join!(stdout_fut, stderr_fut);

    let status = child.wait().await?;
    Ok(CappedOutput {
        stdout: String::from_utf8_lossy(&out_buf).to_string(),
        stderr: String::from_utf8_lossy(&err_buf).to_string(),
        exit_code: status.code(),
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
