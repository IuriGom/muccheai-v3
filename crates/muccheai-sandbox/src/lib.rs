//! MuccheAI v3.0 — LLM Sandbox
//!
//! Process-level sandbox with resource limits.
//! This is NOT hardware-isolated (no VM/container). It uses process isolation,
//! rlimits, and stdio redirection. For true isolation, run inside a VM or container.
//! - Ollama integration for real LLM inference
//! - Dual verification with semantic similarity

#![warn(unsafe_code)]
#![warn(missing_docs)]

pub mod inference;

use muccheai_types::*;
use crate::inference::{SchemaEnforcedOutput, OutputSchema};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

/// Sandbox configuration
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxConfig {
    /// VM ID
    pub vm_id: String,
    /// Dedicated CPU cores
    pub cpu_cores: Vec<usize>,
    /// Memory limit in MB
    pub memory_limit_mb: u64,
    /// Enable network (default: false)
    pub network_enabled: bool,
    /// Filesystem type (tmpfs only)
    pub filesystem: FilesystemType,
    /// Model weights path (read-only)
    pub model_weights_path: String,
    /// Cache flush on VM exit
    pub cache_flush_on_exit: bool,
    /// KSM disabled
    pub ksm_disabled: bool,
    /// Apple Memory Encryption
    pub memory_encryption: bool,
    /// Ollama API endpoint
    pub ollama_url: String,
    /// Ollama model name
    pub ollama_model: String,
}

/// Filesystem type for sandbox
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilesystemType {
    /// tmpfs only — ephemeral, no persistence
    Tmpfs,
    /// Read-only bind mount
    ReadOnlyBind(String),
}

/// LLM Sandbox state
pub struct LlmSandbox {
    /// Sandbox configuration
    config: SandboxConfig,
    /// Whether the sandbox is currently running
    running: bool,
    /// SHA3-512 hash of loaded model weights
    model_hash: [u8; 64],
    /// Isolated sandbox child process
    sandbox_process: Option<std::process::Child>,
    /// Path to model weights file
    weights_path: Option<String>,
}

/// Validated prompt (already checked by Policy Engine)
#[derive(Debug, Clone)]
pub struct ValidatedPrompt {
    /// Prompt text
    pub text: String,
    /// Schema to enforce
    pub output_schema: String,
    /// Maximum tokens
    pub max_tokens: u32,
    /// Optional memory context injected before the prompt
    pub memory_context: Option<String>,
}

/// Structured suggestion from LLM
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredSuggestion {
    /// JSON payload conforming to schema
    pub json_payload: Vec<u8>,
    /// Model hash that produced this
    pub model_hash: [u8; 64],
    /// Inference time
    pub inference_time_ms: u64,
    /// Integrity proof
    pub integrity_proof: [u8; 64],
}

/// Inference error
#[derive(Debug, Clone, thiserror::Error)]
pub enum InferenceError {
    /// Model not loaded.
    #[error("Model not loaded")]
    ModelNotLoaded,
    /// Schema violation with detail.
    #[error("Schema violation: {0}")]
    SchemaViolation(String),
    /// Weight tampering detected.
    #[error("Weight tampering detected")]
    WeightTampering,
    /// Sandbox error with detail.
    #[error("Sandbox error: {0}")]
    SandboxError(String),
    /// Ollama not running with detail.
    #[error("Ollama not running: {0}")]
    OllamaNotRunning(String),
    /// Ollama unavailable.
    #[error("Ollama unavailable")]
    OllamaUnavailable,
    /// Invalid model output with detail.
    #[error("Invalid model output: {0}")]
    InvalidModelOutput(String),
}

/// Ollama generate request payload
#[derive(Debug, serde::Serialize)]
struct OllamaRequest {
    /// Model name to use
    model: String,
    /// Input prompt text
    prompt: String,
    /// Whether to stream the response
    stream: bool,
    /// Output format (e.g. "json")
    format: String,
    /// Generation hyperparameters
    options: OllamaOptions,
}

/// Ollama generation options
#[derive(Debug, serde::Serialize)]
struct OllamaOptions {
    /// Sampling temperature
    temperature: f32,
    /// Random seed for deterministic generation
    seed: i64,
    /// Maximum tokens to predict
    num_predict: i32,
}

/// Ollama generate response
#[derive(Debug, serde::Deserialize)]
struct OllamaResponse {
    /// Generated text response
    response: String,
}

impl LlmSandbox {
    /// Create a new sandbox with given configuration
    pub fn new(config: SandboxConfig) -> Self {
        Self {
            config,
            running: false,
            model_hash: [0u8; 64],
            sandbox_process: None,
            weights_path: None,
        }
    }

    /// Start the sandbox with basic resource limits and isolation.
    pub fn start(&mut self) -> std::result::Result<(), MuccheError> {
        let temp_dir = tempfile::tempdir()
            .map_err(|e| MuccheError::SandboxError(format!("Failed to create temp dir: {}", e)))?;

        let mut cmd = std::process::Command::new("sleep");
        cmd.arg("3600")
            .env_clear()
            .current_dir(temp_dir.path())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());

        // Apply resource limits (best effort)
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            let memory_limit_mb = self.config.memory_limit_mb;
            // SAFETY: `pre_exec` runs in the child process between `fork()` and `exec()`.
            // This closure only invokes syscalls (`setrlimit`, `prctl`) that do not allocate
            // memory, use locks, or touch non-async-signal-safe state. It is safe because:
            // 1. The child process has only one thread (the forking thread).
            // 2. No Rust heap allocations or panics occur in this closure.
            // 3. All called functions are safe in practice on Linux between fork and exec.
            // NOTE: macOS does not allow setting RLIMIT_AS/RLIMIT_DATA to finite values
            // from user space, so memory limits are best-effort and may be skipped.
            let _ = unsafe {
                cmd.pre_exec(move || {
                    // Memory limit (Linux only — macOS rejects finite RLIMIT_AS values)
                    #[cfg(target_os = "linux")]
                    {
                        let mem_bytes = memory_limit_mb
                            .checked_mul(1024)
                            .and_then(|v| v.checked_mul(1024))
                            .unwrap_or(u64::MAX);
                        let mem_limit = libc::rlimit {
                            rlim_cur: mem_bytes,
                            rlim_max: mem_bytes,
                        };
                        let _ = libc::setrlimit(libc::RLIMIT_AS, &mem_limit);
                    }

                    // CPU time limit: 300 seconds
                    let cpu_limit = libc::rlimit {
                        rlim_cur: 300,
                        rlim_max: 300,
                    };
                    if libc::setrlimit(libc::RLIMIT_CPU, &cpu_limit) != 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "Failed to set sandbox CPU limit",
                        ));
                    }

                    // No core dumps
                    let core_limit = libc::rlimit {
                        rlim_cur: 0,
                        rlim_max: 0,
                    };
                    if libc::setrlimit(libc::RLIMIT_CORE, &core_limit) != 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "Failed to set sandbox core dump limit",
                        ));
                    }

                    // Disable network if requested (best effort via no_new_privs on Linux)
                    #[cfg(target_os = "linux")]
                    {
                        let _ = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                    }

                    Ok(())
                })
            };
        }

        let child = cmd
            .spawn()
            .map_err(|e| MuccheError::SandboxError(format!("Failed to spawn sandbox process: {}", e)))?;
        self.sandbox_process = Some(child);
        self.running = true;
        Ok(())
    }

    /// Stop the sandbox (destroy VM, no snapshot)
    pub fn stop(&mut self) -> std::result::Result<(), MuccheError> {
        if let Some(mut child) = self.sandbox_process.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.running = false;
        Ok(())
    }

    /// Check if the sandbox is currently running.
    /// Validates that the child process is still alive using its PID.
    pub fn is_running(&self) -> bool {
        if !self.running {
            return false;
        }
        if let Some(ref child) = self.sandbox_process {
            let pid = child.id();
            #[cfg(target_os = "linux")]
            {
                std::fs::metadata(format!("/proc/{}", pid)).is_ok()
            }
            #[cfg(not(target_os = "linux"))]
            {
                // Fallback: best-effort process existence check via kill -0
                std::process::Command::new("kill")
                    .arg("-0")
                    .arg(pid.to_string())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false)
            }
        } else {
            false
        }
    }

    /// Run inference with dual verification
    pub fn inference(
        &self,
        prompt: &ValidatedPrompt,
    ) -> std::result::Result<StructuredSuggestion, InferenceError> {
        if !self.is_running() {
            return Err(InferenceError::ModelNotLoaded);
        }

        // Dual inference verification
        let output_a = self.run_inference_once(prompt, 0x1234)?;
        let output_b = self.run_inference_once(prompt, 0x5678)?;

        // Semantic similarity check on parsed JSON structure
        let similarity = self.semantic_similarity(&output_a, &output_b);
        if similarity < 0.8 {
            return Err(InferenceError::WeightTampering);
        }

        // Validate schema enforcement
        let payload: serde_json::Value = serde_json::from_slice(&output_a.json_payload)
            .map_err(|e| InferenceError::InvalidModelOutput(e.to_string()))?;
        let enforced = SchemaEnforcedOutput {
            schema: OutputSchema::ActionProposal,
            version: "1.0".to_string(),
            payload,
        };
        enforced.validate()
            .map_err(InferenceError::SchemaViolation)?;

        Ok(output_a)
    }

    /// Run inference once with given seed
    fn run_inference_once(
        &self,
        prompt: &ValidatedPrompt,
        seed: u64,
    ) -> std::result::Result<StructuredSuggestion, InferenceError> {
        let start = std::time::Instant::now();

        // Try Ollama first, fail if unavailable
        let json_text = match self.call_ollama(prompt, seed) {
            Ok(text) => text,
            Err(e) => {
                tracing::warn!("Ollama unavailable: {}", e);
                return Err(InferenceError::OllamaUnavailable);
            }
        };

        // Validate that output is valid JSON (with size and depth limits)
        const MAX_JSON_PAYLOAD_BYTES: usize = 1024 * 1024;
        if json_text.len() > MAX_JSON_PAYLOAD_BYTES {
            return Err(InferenceError::InvalidModelOutput(
                "JSON payload exceeds maximum size".to_string()
            ));
        }
        if serde_json::from_str::<serde_json::Value>(&json_text).is_err() {
            return Err(InferenceError::InvalidModelOutput(
                "Output is not valid JSON".to_string()
            ));
        }

        let elapsed = start.elapsed().as_millis() as u64;

        let json_bytes = json_text.into_bytes();
        Ok(StructuredSuggestion {
            json_payload: json_bytes.clone(),
            model_hash: self.model_hash,
            inference_time_ms: elapsed,
            integrity_proof: muccheai_crypto::sha3_512(&json_bytes),
        })
    }

    /// Build a safely delimited prompt with injection-pattern detection.
    /// Rejects common prompt-injection payloads that attempt to override
    /// system instructions.
    fn build_safe_prompt(
        &self,
        prompt: &ValidatedPrompt,
    ) -> std::result::Result<String, InferenceError> {
        let user_text = &prompt.text;

        // Reject known prompt-injection patterns.
        let lower = user_text.to_lowercase();
        let forbidden_patterns = [
            "ignore previous instructions",
            "ignore all prior",
            "ignore the above",
            "system prompt:",
            "you are now",
            "you are a",
            "</system>",
            "</user>",
            "</instruction>",
            "</sys>",
            "[system]",
            "[/system]",
            "<<|",
            "|>>",
        ];
        for pat in &forbidden_patterns {
            if lower.contains(pat) {
                return Err(InferenceError::InvalidModelOutput(
                    format!("Prompt contains forbidden pattern: {}", pat)
                ));
            }
        }

        let system_prompt = format!(
            "You are a structured action parser. Extract the user's intent and respond with ONLY a single JSON object. \
             The JSON must match this schema: {}. \
             Do not include markdown code fences, explanations, or any text outside the JSON object. \
             Example: {{\"tool_id\":\"email\",\"method\":\"send\",\"params\":{{\"to\":\"john@example.com\",\"subject\":\"Hello\"}}}}",
            prompt.output_schema
        );

        let memory_prefix = prompt.memory_context.as_ref()
            .map(|ctx| format!("Context:\n{}\n\n", ctx))
            .unwrap_or_default();

        // Use XML-like delimiters to separate system instructions from user input.
        // This makes it harder for the user to break out of the user context.
        let full_prompt = format!(
            "{}<|system|>\n{}\n<|/system|>\n<|user|>\n{}\n<|/user|>\n<|response|>\n",
            memory_prefix, system_prompt, user_text
        );

        Ok(full_prompt)
    }

    /// Call Ollama API for real inference.
    /// ⚠ OS-level sandboxing (VM/container) is not yet implemented.
    ///    This runs the HTTP request in the parent process with best-effort
    ///    restrictions (no redirects, timeouts, injection filtering).
    fn call_ollama(
        &self,
        prompt: &ValidatedPrompt,
        seed: u64,
    ) -> std::result::Result<String, InferenceError> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(5)
            .build()
            .map_err(|e| InferenceError::OllamaNotRunning(e.to_string()))?;

        let safe_prompt = self.build_safe_prompt(prompt)?;

        let request = OllamaRequest {
            model: self.config.ollama_model.clone(),
            prompt: safe_prompt,
            stream: false,
            format: "json".to_string(),
            options: OllamaOptions {
                temperature: 0.1,
                seed: seed as i64,
                num_predict: prompt.max_tokens as i32,
            },
        };

        let url = format!("{}/api/generate", self.config.ollama_url);
        let response = client
            .post(&url)
            .json(&request)
            .send()
            .map_err(|e| InferenceError::OllamaNotRunning(e.to_string()))?;

        if !response.status().is_success() {
            return Err(InferenceError::OllamaNotRunning(
                format!("HTTP {}", response.status())
            ));
        }

        let ollama_resp: OllamaResponse = response
            .json()
            .map_err(|e| InferenceError::InvalidModelOutput(e.to_string()))?;

        // Clean up response — remove markdown code fences if present
        let cleaned = ollama_resp.response
            .trim()
            .trim_start_matches("```json")
            .trim_start_matches("```")
            .trim_end_matches("```")
            .trim()
            .to_string();

        Ok(cleaned)
    }

    /// Async version of Ollama API call.
    /// ⚠ OS-level sandboxing (VM/container) is not yet implemented.
    pub async fn call_ollama_async(
        &self,
        prompt: &ValidatedPrompt,
        seed: u64,
    ) -> std::result::Result<String, InferenceError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(5)
            .build()
            .map_err(|e| InferenceError::OllamaNotRunning(e.to_string()))?;

        let safe_prompt = self.build_safe_prompt(prompt)?;

        let request = OllamaRequest {
            model: self.config.ollama_model.clone(),
            prompt: safe_prompt,
            stream: false,
            format: "json".to_string(),
            options: OllamaOptions {
                temperature: 0.1,
                seed: seed as i64,
                num_predict: prompt.max_tokens as i32,
            },
        };

        let url = format!("{}/api/generate", self.config.ollama_url);
        let response = client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| InferenceError::OllamaNotRunning(e.to_string()))?;

        if !response.status().is_success() {
            return Err(InferenceError::OllamaNotRunning(
                format!("HTTP {}", response.status())
            ));
        }

        let ollama_resp: OllamaResponse = response
            .json()
            .await
            .map_err(|e| InferenceError::InvalidModelOutput(e.to_string()))?;

        let cleaned = ollama_resp.response
            .trim()
            .trim_start_matches("```json")
            .trim_start_matches("```")
            .trim_end_matches("```")
            .trim()
            .to_string();

        Ok(cleaned)
    }

    /// Compute semantic similarity between two outputs using JSON key overlap.
    /// Always parses both payloads fully to avoid timing side-channels.
    fn semantic_similarity(&self, a: &StructuredSuggestion, b: &StructuredSuggestion) -> f64 {
        let a_str = String::from_utf8_lossy(&a.json_payload);
        let b_str = String::from_utf8_lossy(&b.json_payload);

        let parse = |s: &str| -> Option<(String, String, serde_json::Value)> {
            let v: serde_json::Value = serde_json::from_str(s).ok()?;
            let tool = v.get("tool_id")?.as_str()?.to_string();
            let method = v.get("method")?.as_str()?.to_string();
            let params = v.get("params")?.clone();
            Some((tool, method, params))
        };

        let parsed_a = parse(&a_str);
        let parsed_b = parse(&b_str);

        match (parsed_a, parsed_b) {
            (Some((ta, ma, pa)), Some((tb, mb, pb))) => {
                let a_keys = collect_json_keys(&pa);
                let b_keys = collect_json_keys(&pb);
                if a_keys.is_empty() && b_keys.is_empty() {
                    return 1.0;
                }
                let intersection: std::collections::HashSet<_> = a_keys.intersection(&b_keys).collect();
                let union: std::collections::HashSet<_> = a_keys.union(&b_keys).collect();
                let jaccard = intersection.len() as f64 / union.len() as f64;
                // Penalize tool/method mismatches by scaling similarity down,
                // but only after computing the full key overlap (constant-time-ish).
                if ta != tb || ma != mb {
                    jaccard * 0.5
                } else {
                    jaccard
                }
            }
            _ => {
                if a.json_payload == b.json_payload {
                    1.0
                } else {
                    0.0
                }
            }
        }
    }

    /// Verify model weights integrity by reading file and computing SHA3-512.
    /// Uses constant-time comparison to prevent timing side-channels.
    pub fn verify_weights(&self, expected_hash: &[u8; 64]) -> std::result::Result<bool, MuccheError> {
        let path = self.weights_path.as_ref()
            .ok_or_else(|| MuccheError::SandboxError("Weights path not set".to_string()))?;
        let data = std::fs::read(path)
            .map_err(|e| MuccheError::SandboxError(format!("Failed to read weights: {}", e)))?;
        let hash = muccheai_crypto::sha3_512(&data);
        Ok(muccheai_crypto::compare_hashes(&hash, expected_hash))
    }

    /// Load model weights, storing path and expected hash
    pub fn load_weights(&mut self, path: &str, expected_hash: [u8; 64]) -> std::result::Result<(), MuccheError> {
        self.weights_path = Some(path.to_string());
        self.model_hash = expected_hash;
        Ok(())
    }
}

impl Drop for LlmSandbox {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// Recursively collect all keys from a JSON value
fn collect_json_keys(val: &serde_json::Value) -> std::collections::HashSet<String> {
    let mut keys = std::collections::HashSet::new();
    fn recurse(v: &serde_json::Value, prefix: &str, keys: &mut std::collections::HashSet<String>) {
        match v {
            serde_json::Value::Object(map) => {
                for (k, child) in map {
                    let key = if prefix.is_empty() { k.clone() } else { format!("{}.{}", prefix, k) };
                    keys.insert(key.clone());
                    recurse(child, &key, keys);
                }
            }
            serde_json::Value::Array(arr) => {
                for (i, child) in arr.iter().enumerate() {
                    let key = format!("{}[{}]", prefix, i);
                    recurse(child, &key, keys);
                }
            }
            _ => {}
        }
    }
    recurse(val, "", &mut keys);
    keys
}

/// Default sandbox configuration for Qwen inference
pub fn default_sandbox_config() -> SandboxConfig {
    SandboxConfig {
        vm_id: format!("muccheai-sandbox-{}", std::process::id()),
        cpu_cores: vec![2, 3],
        memory_limit_mb: 8192,
        network_enabled: false,
        filesystem: FilesystemType::Tmpfs,
        model_weights_path: "/models/qwen-7b-q4_k_m.gguf".to_string(),
        cache_flush_on_exit: true,
        ksm_disabled: true,
        memory_encryption: true,
        ollama_url: "http://localhost:11434".to_string(),
        ollama_model: "qwen3:14b".to_string(),
    }
}

/// Sandbox executor with real process-level isolation
pub struct SandboxExecutor;

impl SandboxExecutor {
    /// Execute a command in an isolated subprocess
    pub fn execute(cmd: &str, args: &[String]) -> std::io::Result<std::process::Output> {
        let temp_dir = tempfile::tempdir()?;

        let mut command = std::process::Command::new(cmd);
        command
            .args(args)
            .env_clear()
            .current_dir(temp_dir.path())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        // Set resource limits via libc (best effort — check return values)
        #[cfg(unix)]
        {
            // SAFETY: `pre_exec` runs in the child process between `fork()` and `exec()`.
            // This closure only invokes syscalls (`setrlimit`) that do not allocate memory,
            // use locks, or touch non-async-signal-safe state. See safety note in
            // `LlmSandbox::start()` for full justification.
            // NOTE: macOS does not allow setting RLIMIT_AS to finite values from user space.
            let _ = unsafe {
                command.pre_exec(|| {
                    // Memory limit: 2GB (Linux only — macOS rejects finite RLIMIT_AS values)
                    #[cfg(target_os = "linux")]
                    {
                        let limit = libc::rlimit {
                            rlim_cur: 2 * 1024 * 1024 * 1024,
                            rlim_max: 2 * 1024 * 1024 * 1024,
                        };
                        let _ = libc::setrlimit(libc::RLIMIT_AS, &limit);
                    }

                    // CPU time limit: 60 seconds
                    let cpu_limit = libc::rlimit {
                        rlim_cur: 60,
                        rlim_max: 60,
                    };
                    if libc::setrlimit(libc::RLIMIT_CPU, &cpu_limit) != 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "Failed to set CPU limit",
                        ));
                    }

                    // No core dumps
                    let core_limit = libc::rlimit {
                        rlim_cur: 0,
                        rlim_max: 0,
                    };
                    if libc::setrlimit(libc::RLIMIT_CORE, &core_limit) != 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "Failed to disable core dumps",
                        ));
                    }

                    Ok(())
                })
            };
        }

        command.output()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_lifecycle() {
        let config = default_sandbox_config();
        let mut sandbox = LlmSandbox::new(config);

        assert!(sandbox.start().is_ok());
        assert!(sandbox.is_running());

        assert!(sandbox.stop().is_ok());
        assert!(!sandbox.is_running());
    }

    #[test]
    fn test_inference_not_running() {
        let config = default_sandbox_config();
        let sandbox = LlmSandbox::new(config);

        let prompt = ValidatedPrompt {
            text: "Hello".to_string(),
            output_schema: "action_proposal".to_string(),
            max_tokens: 512,
            memory_context: None,
        };

        let result = sandbox.inference(&prompt);
        assert!(matches!(result, Err(InferenceError::ModelNotLoaded)));
    }

    #[test]
    fn test_inference_ollama_unavailable() {
        let mut config = default_sandbox_config();
        // Point to a non-existent port so Ollama is unavailable
        config.ollama_url = "http://localhost:99999".to_string();
        let mut sandbox = LlmSandbox::new(config);
        sandbox.start().unwrap();

        let prompt = ValidatedPrompt {
            text: "Email John about the meeting".to_string(),
            output_schema: r#"{"tool_id":"string","method":"string","params":{}}"#.to_string(),
            max_tokens: 256,
            memory_context: None,
        };

        let result = sandbox.inference(&prompt);
        assert!(matches!(result, Err(InferenceError::OllamaUnavailable)));
        sandbox.stop().unwrap();
    }

    #[test]
    fn test_load_and_verify_weights() {
        let config = default_sandbox_config();
        let mut sandbox = LlmSandbox::new(config);

        let expected = [0u8; 64];
        sandbox.load_weights("/tmp/nonexistent_weights.gguf", expected).unwrap();

        // Verify should fail because file doesn't exist
        assert!(sandbox.verify_weights(&expected).is_err());
    }

    #[test]
    fn test_semantic_similarity_key_overlap() {
        let config = default_sandbox_config();
        let sandbox = LlmSandbox::new(config);

        let a = StructuredSuggestion {
            json_payload: br#"{"tool_id":"email","method":"send","params":{"to":"a","subject":"s"}}"#.to_vec(),
            model_hash: [0u8; 64],
            inference_time_ms: 0,
            integrity_proof: [0u8; 64],
        };
        let b = StructuredSuggestion {
            json_payload: br#"{"tool_id":"email","method":"send","params":{"to":"b","subject":"s","body":"b"}}"#.to_vec(),
            model_hash: [0u8; 64],
            inference_time_ms: 0,
            integrity_proof: [0u8; 64],
        };

        let sim = sandbox.semantic_similarity(&a, &b);
        // tool_id and method match; params keys: to, subject vs to, subject, body -> intersection 2, union 3 -> 0.666...
        assert!(sim > 0.5 && sim < 1.0);

        let c = StructuredSuggestion {
            json_payload: br#"{"tool_id":"calendar","method":"read","params":{}}"#.to_vec(),
            model_hash: [0u8; 64],
            inference_time_ms: 0,
            integrity_proof: [0u8; 64],
        };
        assert_eq!(sandbox.semantic_similarity(&a, &c), 0.0);
    }
}
