//! MuccheAI configuration management

use muccheai_policy_engine::rules::{PolicyRule, PolicyRules, RuleAction, RuleConditions};
use muccheai_types::crypto_primitives::{HybridKeypair, HybridPrivkey, HybridPubkey};
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A serializable wrapper for the hybrid keypair.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredKeypair {
    /// Public component
    pub pubkey: HybridPubkey,
    /// Ed25519 private key
    pub classical: Vec<u8>,
    /// X25519 private key
    pub x25519: Vec<u8>,
    /// ML-KEM-768 private key
    pub pq: Vec<u8>,
    /// ML-DSA-44 private key
    pub pq_sign: Vec<u8>,
}

impl std::fmt::Debug for StoredKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredKeypair")
            .field("pubkey", &self.pubkey)
            .field("classical", &"<redacted>")
            .field("x25519", &"<redacted>")
            .field("pq", &"<redacted>")
            .field("pq_sign", &"<redacted>")
            .finish()
    }
}

impl Drop for StoredKeypair {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.classical.zeroize();
        self.x25519.zeroize();
        self.pq.zeroize();
        self.pq_sign.zeroize();
    }
}

impl Default for StoredKeypair {
    fn default() -> Self {
        Self {
            pubkey: HybridPubkey::default(),
            classical: Vec::new(),
            x25519: Vec::new(),
            pq: Vec::new(),
            pq_sign: Vec::new(),
        }
    }
}

/// Decrypt a single MCP API key if it has the `enc:` prefix.
pub fn decrypt_mcp_api_key(api_key: &str) -> Option<String> {
    if let Some(hex_ct) = api_key.strip_prefix("enc:") {
        let ciphertext = hex::decode(hex_ct).ok()?;
        let key = MuccheConfig::load_or_create_machine_key().ok()?;
        let plaintext = decrypt_aes_256_gcm(&ciphertext, &key).ok()?;
        String::from_utf8(plaintext).ok()
    } else {
        Some(api_key.to_string())
    }
}

impl From<HybridKeypair> for StoredKeypair {
    fn from(kp: HybridKeypair) -> Self {
        Self {
            pubkey: kp.pubkey.clone(),
            classical: kp.privkey.classical.clone(),
            x25519: kp.privkey.x25519.clone(),
            pq: kp.privkey.pq.clone(),
            pq_sign: kp.privkey.pq_sign.clone(),
        }
    }
}

impl From<StoredKeypair> for muccheai_types::crypto_primitives::HybridKeypair {
    fn from(stored: StoredKeypair) -> Self {
        Self {
            pubkey: stored.pubkey.clone(),
            privkey: HybridPrivkey {
                classical: stored.classical.clone(),
                x25519: stored.x25519.clone(),
                pq: stored.pq.clone(),
                pq_sign: stored.pq_sign.clone(),
            },
        }
    }
}

/// Default policy rules for a fresh installation.
fn default_policy_rules() -> PolicyRules {
    PolicyRules {
        rules: vec![
            PolicyRule {
                id: "allow-email-send".to_string(),
                tool_id: "email".to_string(),
                method: "send".to_string(),
                resource_patterns: vec!["*".to_string()],
                action: RuleAction::Allow,
                conditions: RuleConditions::Always,
            },
            PolicyRule {
                id: "allow-calendar-read".to_string(),
                tool_id: "calendar".to_string(),
                method: "read".to_string(),
                resource_patterns: vec!["*".to_string()],
                action: RuleAction::Allow,
                conditions: RuleConditions::Always,
            },
            PolicyRule {
                id: "deny-filesystem-delete".to_string(),
                tool_id: "filesystem".to_string(),
                method: "delete".to_string(),
                resource_patterns: vec!["*".to_string()],
                action: RuleAction::Deny,
                conditions: RuleConditions::Always,
            },
        ],
        default_action: RuleAction::Deny,
        ..Default::default()
    }
}

/// Generate a random alphanumeric API key using a CSPRNG.
/// Uses rejection sampling to eliminate modulo bias.
fn generate_api_key() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const CHARSET_LEN: u8 = 62;
    // Largest multiple of CHARSET_LEN that fits in u8
    const LIMIT: u8 = u8::MAX - (u8::MAX % CHARSET_LEN);
    let mut buf = [0u8; 48];
    let rng = ring::rand::SystemRandom::new();
    for i in 0..48 {
        loop {
            let mut byte = [0u8; 1];
            rng.fill(&mut byte).unwrap_or(());
            if byte[0] < LIMIT {
                buf[i] = CHARSET[byte[0] as usize % CHARSET.len()];
                break;
            }
        }
    }
    buf.iter().map(|&b| b as char).collect()
}

/// An AI agent / provider configuration.
#[derive(Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Display name for this agent.
    pub name: String,
    /// Provider type: "ollama", "openai", "anthropic".
    pub provider: String,
    /// Model name (e.g. "qwen3:14b", "gpt-4o", "claude-3-5-sonnet").
    pub model: String,
    /// API key for cloud providers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    /// Base URL (for Ollama or custom endpoints).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
}

impl std::fmt::Debug for AgentConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentConfig")
            .field("name", &self.name)
            .field("provider", &self.provider)
            .field("model", &self.model)
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl AgentConfig {
    /// Return a clone with sensitive fields redacted for API responses.
    pub fn sanitized(&self) -> Self {
        Self {
            name: self.name.clone(),
            provider: self.provider.clone(),
            model: self.model.clone(),
            api_key: None,
            base_url: self.base_url.as_ref().map(|_| "***REDACTED***".to_string()),
        }
    }
}

/// An AI persona / identity profile.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Persona {
    /// Display name of the persona.
    pub name: String,
    /// Emoji icon for the persona.
    #[serde(default)]
    pub emoji: String,
    /// Short description of the persona's personality.
    pub description: String,
    /// System prompt sent to the LLM for this persona.
    pub system_prompt: String,
}

/// Default personas for a fresh installation.
pub fn default_personas() -> Vec<Persona> {
    vec![
        Persona {
            name: "Assistant".to_string(),
            emoji: "🐄".to_string(),
            description: "A friendly, helpful general-purpose AI assistant".to_string(),
            system_prompt: "You are MuccheAI, a helpful, secure, and friendly personal AI assistant. \
                You prioritize user privacy, give concise answers, and ask for clarification when needed. \
                Use emojis sparingly — at most one per message."
                .to_string(),
        },
        Persona {
            name: "Coder".to_string(),
            emoji: "💻".to_string(),
            description: "Expert software engineer focused on clean, secure code".to_string(),
            system_prompt: "You are an expert software engineer and security researcher. \
                You write clean, well-documented, secure code. You think step by step, explain your reasoning, \
                and always consider edge cases and security implications. Prefer Rust, Python, and TypeScript."
                .to_string(),
        },
        Persona {
            name: "Security Analyst".to_string(),
            emoji: "🔒".to_string(),
            description: "Paranoid security-focused analyst with a defensive mindset".to_string(),
            system_prompt: "You are a paranoid security analyst with deep expertise in threat modeling, \
                cryptography, and defensive security. You approach every request with a defensive mindset, \
                considering attack surfaces, trust boundaries, and failure modes. You cite specific risks \
                and suggest concrete mitigations."
                .to_string(),
        },
        Persona {
            name: "Creative Writer".to_string(),
            emoji: "✍️".to_string(),
            description: "Imaginative storyteller with vivid prose and narrative flair".to_string(),
            system_prompt: "You are a creative writer with a gift for vivid prose, compelling characters, \
                and imaginative worldbuilding. You adapt your tone to the user's needs — from poetry to screenplays, \
                from flash fiction to epic fantasy. You offer constructive feedback and brainstorming assistance."
                .to_string(),
        },
    ]
}

/// MuccheAI user configuration.
#[derive(Clone, Serialize, Deserialize)]
pub struct MuccheConfig {
    /// Ollama API endpoint (legacy — kept for backward compatibility).
    pub ollama_host: String,
    /// Ollama model name (legacy — kept for backward compatibility).
    pub ollama_model: String,
    /// Tools that are allowed by policy.
    pub allowed_tools: Vec<String>,
    /// Default policy action.
    pub default_action: RuleAction,
    /// Whether to restrict actions to business hours.
    pub business_hours_restriction: bool,
    /// Default approval tier.
    pub approval_tier: String,
    /// Shamir threshold.
    pub shamir_threshold: u8,
    /// Issuer keypair for capability minting.
    /// Stored separately in an encrypted file, not in the TOML config.
    #[serde(skip)]
    pub keypair: StoredKeypair,
    /// Policy rules for the policy engine.
    #[serde(default = "default_policy_rules")]
    pub policy_rules: PolicyRules,
    /// Bearer token for API authentication.
    /// Not serialized to TOML — stored in an encrypted sidecar file instead.
    #[serde(default = "generate_api_key", skip_serializing)]
    pub api_key: String,
    /// Web server bind address.
    #[serde(default = "default_web_bind_address")]
    pub web_bind_address: String,
    /// AI persona profiles.
    #[serde(default = "default_personas")]
    pub personas: Vec<Persona>,
    /// Name of the currently active persona.
    #[serde(default)]
    pub current_persona: String,
    /// Configured AI agents / providers.
    #[serde(default)]
    pub agents: Vec<AgentConfig>,
    /// Name of the active agent.
    #[serde(default)]
    pub active_agent: String,
    /// Temperature for LLM inference (0.0 - 1.0).
    #[serde(default = "default_temperature")]
    pub temperature: f32,
    /// Maximum tokens to generate per response.
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
    /// Sandbox memory limit in MB.
    #[serde(default = "default_sandbox_memory_limit_mb")]
    pub sandbox_memory_limit_mb: u32,
    /// Enable dual verification for LLM outputs.
    #[serde(default = "default_true")]
    pub dual_verification: bool,
    /// Auto-approve low-risk actions without user confirmation.
    #[serde(default)]
    pub auto_approve_low_risk: bool,
    /// Show reasoning steps in the UI.
    #[serde(default = "default_true")]
    pub show_reasoning: bool,
    /// IP addresses or CIDR ranges of trusted reverse proxies.
    /// If empty (default), X-Forwarded-For is never trusted.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// Enable web search integration.
    #[serde(default)]
    pub web_search_enabled: bool,
    /// Web search approval mode: "disabled", "approval_required", "always_allow".
    #[serde(default = "default_web_search_approval")]
    pub web_search_approval: String,
    /// Enable the speech-to-text API endpoint.
    #[serde(default)]
    pub stt_enabled: bool,
    /// Path or name of the whisper model / binary to use for STT.
    #[serde(default = "default_stt_model")]
    pub stt_model: String,
    /// Automatically summarize chat sessions when they grow long.
    #[serde(default = "default_true")]
    pub auto_summarize_sessions: bool,
    /// Number of messages after which auto-summarization triggers.
    #[serde(default = "default_summarize_after_messages")]
    pub summarize_after_messages: usize,
    /// Enable Ollama native tool calling (OpenAI-compatible tools format).
    #[serde(default = "default_true")]
    pub native_tool_calling: bool,
    /// Enable modular processing pipelines for chat.
    #[serde(default = "default_true")]
    pub modular_pipelines: bool,
    /// Display name for the AI assistant in the web UI.
    #[serde(default)]
    pub ai_name: String,
    /// UI language code.
    #[serde(default)]
    pub language: String,
    /// Enable UI sound effects.
    #[serde(default = "default_true")]
    pub sound_enabled: bool,
    /// Auto-scroll to new messages in the chat.
    #[serde(default = "default_true")]
    pub auto_scroll: bool,
    /// Compact UI mode.
    #[serde(default)]
    pub compact_mode: bool,
}

impl std::fmt::Debug for MuccheConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MuccheConfig")
            .field("ollama_host", &self.ollama_host)
            .field("ollama_model", &self.ollama_model)
            .field("allowed_tools", &self.allowed_tools)
            .field("default_action", &self.default_action)
            .field("business_hours_restriction", &self.business_hours_restriction)
            .field("approval_tier", &self.approval_tier)
            .field("shamir_threshold", &self.shamir_threshold)
            .field("keypair", &"<redacted>")
            .field("policy_rules", &self.policy_rules)
            .field("api_key", &"<redacted>")
            .field("web_bind_address", &self.web_bind_address)
            .field("personas", &self.personas)
            .field("current_persona", &self.current_persona)
            .field("agents", &self.agents)
            .field("active_agent", &self.active_agent)
            .field("temperature", &self.temperature)
            .field("max_tokens", &self.max_tokens)
            .field("sandbox_memory_limit_mb", &self.sandbox_memory_limit_mb)
            .field("dual_verification", &self.dual_verification)
            .field("auto_approve_low_risk", &self.auto_approve_low_risk)
            .field("show_reasoning", &self.show_reasoning)
            .field("web_search_enabled", &self.web_search_enabled)
            .field("web_search_approval", &self.web_search_approval)
            .field("stt_enabled", &self.stt_enabled)
            .field("stt_model", &self.stt_model)
            .field("auto_summarize_sessions", &self.auto_summarize_sessions)
            .field("summarize_after_messages", &self.summarize_after_messages)
            .field("native_tool_calling", &self.native_tool_calling)
            .field("modular_pipelines", &self.modular_pipelines)
            .field("ai_name", &self.ai_name)
            .field("language", &self.language)
            .field("sound_enabled", &self.sound_enabled)
            .field("auto_scroll", &self.auto_scroll)
            .field("compact_mode", &self.compact_mode)
            .finish()
    }
}

fn default_temperature() -> f32 {
    0.7
}

fn default_max_tokens() -> u32 {
    1024
}

fn default_sandbox_memory_limit_mb() -> u32 {
    512
}

fn default_true() -> bool {
    true
}

fn default_web_bind_address() -> String {
    "127.0.0.1:3000".to_string()
}

fn default_summarize_after_messages() -> usize {
    50
}

fn default_stt_model() -> String {
    "whisper".to_string()
}

fn default_web_search_approval() -> String {
    "approval_required".to_string()
}

impl Default for MuccheConfig {
    fn default() -> Self {
        // Use a placeholder keypair in Default; load() will generate a real one
        // if the keypair is missing or invalid.
        let kp = StoredKeypair::default();
        Self {
            ollama_host: "http://localhost:11434".to_string(),
            ollama_model: "qwen3:14b".to_string(),
            allowed_tools: vec!["email".to_string(), "calendar".to_string()],
            default_action: RuleAction::Deny,
            business_hours_restriction: false,
            approval_tier: "standard".to_string(),
            shamir_threshold: 3,
            keypair: kp.into(),
            policy_rules: default_policy_rules(),
            api_key: generate_api_key(),
            web_bind_address: default_web_bind_address(),
            personas: default_personas(),
            current_persona: "default".to_string(),
            agents: Vec::new(),
            active_agent: String::new(),
            temperature: 0.7,
            max_tokens: 1024,
            sandbox_memory_limit_mb: 512,
            dual_verification: true,
            auto_approve_low_risk: false,
            show_reasoning: true,
            trusted_proxies: Vec::new(),
            web_search_enabled: false,
            web_search_approval: default_web_search_approval(),
            stt_enabled: true,
            stt_model: default_stt_model(),
            auto_summarize_sessions: true,
            summarize_after_messages: 50,
            native_tool_calling: true,
            modular_pipelines: true,
            ai_name: String::new(),
            language: String::new(),
            sound_enabled: true,
            auto_scroll: true,
            compact_mode: false,
        }
    }
}

impl MuccheConfig {
    /// Path to the configuration file.
    pub fn config_path() -> PathBuf {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        home.join(".muccheai").join("config.toml")
    }

    /// Path to the encrypted keypair file.
    pub fn keypair_path() -> PathBuf {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        home.join(".muccheai").join("keypair.enc")
    }

    /// Path to the MuccheAI data directory.
    pub fn data_dir() -> PathBuf {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        home.join(".muccheai")
    }

    /// Path to the persisted chat sessions file.
    pub fn chat_sessions_path() -> PathBuf {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        home.join(".muccheai").join("chat_sessions.json")
    }

    /// Create a directory and restrict its permissions to owner-only (0o700).
    fn ensure_private_dir(path: &std::path::Path) -> anyhow::Result<()> {
        std::fs::create_dir_all(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(path)?.permissions();
            if perms.mode() & 0o777 != 0o700 {
                perms.set_mode(0o700);
                std::fs::set_permissions(path, perms)?;
            }
        }
        Ok(())
    }

    /// Path to the encrypted agent API keys file.
    pub fn agent_keys_path() -> PathBuf {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        home.join(".muccheai").join("agent_keys.enc")
    }

    /// Path to the machine-bound encryption key.
    /// Path to the machine-bound encryption key.
    pub fn machine_key_path() -> PathBuf {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        home.join(".muccheai").join(".machine_key")
    }

    /// Load or create a random 32-byte machine key for encrypting local secrets.
    /// If `MUCCHEAI_KEY_PASSWORD` is set, the returned key is Argon2id-derived
    /// from the password + the raw material; otherwise the raw material is used.
    pub fn load_or_create_machine_key() -> anyhow::Result<[u8; 32]> {
        let path = Self::machine_key_path();
        let mut material = [0u8; 32];
        let salt = Self::load_or_create_salt()?;
        if let Ok(bytes) = std::fs::read(&path) {
            if bytes.len() == 32 {
                material.copy_from_slice(&bytes);
                return Ok(Self::derive_machine_key(&material, &salt));
            }
        }
        ring::rand::SystemRandom::new()
            .fill(&mut material)
            .map_err(|e| anyhow::anyhow!("CSPRNG failure: {}", e))?;
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                use std::io::Write;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(meta) = file.metadata() {
                        let mut perms = meta.permissions();
                        perms.set_mode(0o600);
                        let _ = file.set_permissions(perms);
                    }
                }
                let _ = file.write_all(&material);
                Ok(Self::derive_machine_key(&material, &salt))
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if let Ok(bytes) = std::fs::read(&path) {
                    if bytes.len() == 32 {
                        let mut existing = [0u8; 32];
                        existing.copy_from_slice(&bytes);
                        return Ok(Self::derive_machine_key(&existing, &salt));
                    }
                }
                Ok(Self::derive_machine_key(&material, &salt))
            }
            _ => Ok(Self::derive_machine_key(&material, &salt)),
        }
    }

    fn salt_path() -> PathBuf {
        Self::machine_key_path().with_extension("salt")
    }

    pub fn load_or_create_salt() -> anyhow::Result<[u8; 16]> {
        let path = Self::salt_path();
        if let Ok(bytes) = std::fs::read(&path) {
            if bytes.len() == 16 {
                let mut salt = [0u8; 16];
                salt.copy_from_slice(&bytes);
                return Ok(salt);
            }
        }
        let mut salt = [0u8; 16];
        ring::rand::SystemRandom::new()
            .fill(&mut salt)
            .map_err(|e| anyhow::anyhow!("CSPRNG failure: {}", e))?;
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let tmp = path.with_extension("tmp");
        if std::fs::write(&tmp, &salt).is_ok() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = std::fs::metadata(&tmp) {
                    let mut perms = meta.permissions();
                    perms.set_mode(0o600);
                    let _ = std::fs::set_permissions(&tmp, perms);
                }
            }
            let _ = std::fs::rename(&tmp, &path);
        }
        Ok(salt)
    }

    pub fn derive_machine_key(material: &[u8; 32], salt: &[u8; 16]) -> [u8; 32] {
        use argon2::{Argon2, Algorithm, Params, Version};

        match std::env::var("MUCCHEAI_KEY_PASSWORD") {
            Ok(password) => {
                let params = Params::new(65536, 3, 4, Some(32))
                    .expect("valid argon2 params");
                let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
                let mut key = [0u8; 32];
                argon2.hash_password_into(password.as_bytes(), salt, &mut key)
                    .expect("argon2 hash failed");
                key
            }
            Err(_) => {
                tracing::warn!(
                    "MUCCHEAI_KEY_PASSWORD is not set. The machine key file contains the raw AES-256 key."
                );
                *material
            }
        }
    }

    /// Encrypt the master API key and save to a sidecar file.
    fn save_api_key(&self) -> anyhow::Result<()> {
        let path = Self::machine_key_path().with_extension("api_key_enc");
        if let Some(parent) = path.parent() {
            Self::ensure_private_dir(parent)?;
        }
        let machine_key = Self::load_or_create_machine_key()?;
        let ciphertext = encrypt_aes_256_gcm(self.api_key.as_bytes(), &machine_key)?;
        let tmp_path = path.with_extension("tmp");
        std::fs::write(&tmp_path, &ciphertext)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&tmp_path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&tmp_path, perms)?;
        }
        std::fs::rename(&tmp_path, path)?;
        Ok(())
    }

    /// Extract the raw `api_key = "..."` value from TOML text.
    /// Used for backward-compat migration when the field is #[serde(skip)].
    /// Parses the TOML properly instead of using string splitting to avoid
    /// false positives on comments or values containing quotes.
    fn extract_api_key_from_raw_toml(content: &str) -> Option<String> {
        #[derive(serde::Deserialize)]
        struct RawConfig {
            api_key: Option<String>,
        }
        toml::from_str::<RawConfig>(content)
            .ok()
            .and_then(|raw| raw.api_key)
            .filter(|s| !s.is_empty())
    }

    /// Load and decrypt the master API key from the sidecar file.
    fn load_api_key(&mut self) -> anyhow::Result<()> {
        let path = Self::machine_key_path().with_extension("api_key_enc");
        if !path.exists() {
            // No sidecar yet — backward compat: plaintext api_key was loaded from TOML.
            // Migrate on next save.
            return Ok(());
        }
        let ciphertext = std::fs::read(&path)?;
        let machine_key = Self::load_or_create_machine_key()?;
        let plaintext = decrypt_aes_256_gcm(&ciphertext, &machine_key)?;
        self.api_key = String::from_utf8(plaintext)
            .map_err(|e| anyhow::anyhow!("invalid UTF-8 in decrypted API key: {}", e))?;
        Ok(())
    }

    /// Derive an encryption key from the API key using Argon2id (memory-hard KDF)
    /// with a unique per-encryption random salt.
    fn derive_key(api_key: &str, salt: &[u8]) -> [u8; 32] {
        use argon2::{Argon2, Params, Algorithm, Version};
        let params = Params::new(65536, 3, 4, Some(32))
            .expect("valid argon2 params");
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = [0u8; 32];
        argon2.hash_password_into(api_key.as_bytes(), salt, &mut key)
            .expect("argon2 hash must succeed");
        key
    }

    /// Encrypt the keypair and save to the keypair file atomically.
    /// Format: salt(16) || nonce(12) || ciphertext || tag(16)
    fn save_keypair(&self) -> anyhow::Result<()> {
        let path = Self::keypair_path();
        if let Some(parent) = path.parent() {
            Self::ensure_private_dir(parent)?;
        }

        // Generate a random 16-byte salt per encryption
        let mut salt = [0u8; 16];
        ring::rand::SystemRandom::new()
            .fill(&mut salt)
            .map_err(|_| anyhow::anyhow!("CSPRNG failure"))?;

        let plaintext = serde_json::to_vec(&self.keypair)?;
        let key = Self::derive_key(&self.api_key, &salt);
        let ciphertext = encrypt_aes_256_gcm(&plaintext, &key)?;

        // Prepend salt to ciphertext
        let mut output = Vec::with_capacity(salt.len() + ciphertext.len());
        output.extend_from_slice(&salt);
        output.extend_from_slice(&ciphertext);

        // Atomic write: write to temp file, then rename.
        let tmp_path = path.with_extension("tmp");
        std::fs::write(&tmp_path, &output)?;

        // Restrict permissions on Unix before rename
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

    /// Load the keypair from the encrypted keypair file.
    /// Format: salt(16) || nonce(12) || ciphertext || tag(16)
    fn load_keypair(api_key: &str) -> anyhow::Result<StoredKeypair> {
        let path = Self::keypair_path();
        if !path.exists() {
            return Err(anyhow::anyhow!("keypair file not found"));
        }

        let data = std::fs::read(&path)?;
        if data.len() < 16 + 12 + 16 {
            return Err(anyhow::anyhow!("keypair file too short"));
        }

        // Extract salt (first 16 bytes)
        let salt = &data[..16];
        let ciphertext = &data[16..];

        let key = Self::derive_key(api_key, salt);
        let plaintext = decrypt_aes_256_gcm(ciphertext, &key)?;
        let keypair: StoredKeypair = serde_json::from_slice(&plaintext)?;
        Ok(keypair)
    }

    /// Save agent API keys to an encrypted sidecar file.
    /// Each agent's api_key is extracted, serialized as a JSON map, and encrypted.
    /// Format: salt(16) || nonce(12) || ciphertext || tag(16)
    fn save_agent_keys(&self) -> anyhow::Result<()> {
        let path = Self::agent_keys_path();
        if let Some(parent) = path.parent() {
            Self::ensure_private_dir(parent)?;
        }

        // Build map of agent name -> api_key for agents that have one
        let mut keys: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        for agent in &self.agents {
            if let Some(ref key) = agent.api_key {
                if !key.is_empty() {
                    keys.insert(agent.name.clone(), key.clone());
                }
            }
        }

        if keys.is_empty() {
            // Remove the file if no keys to store
            let _ = std::fs::remove_file(&path);
            return Ok(());
        }

        let plaintext = serde_json::to_vec(&keys)?;
        let mut salt = [0u8; 16];
        ring::rand::SystemRandom::new()
            .fill(&mut salt)
            .map_err(|_| anyhow::anyhow!("CSPRNG failure"))?;
        let key = Self::derive_key(&self.api_key, &salt);
        let ciphertext = encrypt_aes_256_gcm(&plaintext, &key)?;

        let mut output = Vec::with_capacity(salt.len() + ciphertext.len());
        output.extend_from_slice(&salt);
        output.extend_from_slice(&ciphertext);

        let tmp_path = path.with_extension("tmp");
        std::fs::write(&tmp_path, &output)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&tmp_path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&tmp_path, perms)?;
        }
        std::fs::rename(&tmp_path, path)?;
        Ok(())
    }

    /// Load and decrypt agent API keys from the sidecar file.
    /// Format: salt(16) || nonce(12) || ciphertext || tag(16)
    fn load_agent_keys(&mut self) -> anyhow::Result<()> {
        let path = Self::agent_keys_path();
        if !path.exists() {
            return Ok(());
        }

        let data = std::fs::read(&path)?;
        if data.len() < 16 + 12 + 16 {
            return Err(anyhow::anyhow!("agent keys file too short"));
        }
        let salt = &data[..16];
        let ciphertext = &data[16..];

        let key = Self::derive_key(&self.api_key, salt);
        let plaintext = match decrypt_aes_256_gcm(ciphertext, &key) {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!("Failed to decrypt agent API keys (wrong master key or corrupted file). Agent keys will need to be reconfigured.");
                return Ok(());
            }
        };

        let keys: std::collections::HashMap<String, String> = serde_json::from_slice(&plaintext)?;
        for agent in &mut self.agents {
            if let Some(key) = keys.get(&agent.name) {
                agent.api_key = Some(key.clone());
            }
        }
        Ok(())
    }

    /// Load configuration from disk.
    ///
    /// If the file does not exist or cannot be parsed, a default configuration
    /// is created, persisted to disk, and returned.
    pub fn load() -> anyhow::Result<Self> {
        let path = Self::config_path();
        let mut config: MuccheConfig;
        let mut raw_content = String::new();

        match std::fs::OpenOptions::new().read(true).open(&path) {
            Ok(mut file) => {
                use std::io::Read;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let perms = file.metadata()?.permissions();
                    if perms.mode() & 0o777 != 0o600 {
                        return Err(anyhow::anyhow!(
                            "Config file permissions are {:o} (expected 0o600). Refusing to load.",
                            perms.mode() & 0o777
                        ));
                    }
                }
                const MAX_CONFIG_SIZE: usize = 1_048_576;
                file.read_to_string(&mut raw_content)?;
                if raw_content.len() > MAX_CONFIG_SIZE {
                    return Err(anyhow::anyhow!("Config file too large (max {} bytes)", MAX_CONFIG_SIZE));
                }
                config = toml::from_str(&raw_content)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                config = MuccheConfig::default();
                config.save()?;
                return Ok(config);
            }
            Err(e) => return Err(e.into()),
        }

        // Load encrypted master API key from sidecar.
        // Backward compat: if no sidecar exists, the old plaintext api_key in TOML was
        // skipped by serde; try to extract it from the raw file so the keypair decrypts.
        let sidecar_path = Self::machine_key_path().with_extension("api_key_enc");
        if !sidecar_path.exists() {
            if let Some(raw_key) = Self::extract_api_key_from_raw_toml(&raw_content) {
                config.api_key = raw_key;
            }
        }
        if let Err(e) = config.load_api_key() {
            tracing::warn!("Failed to load encrypted API key ({}). Using plaintext from TOML if present.", e);
        }

        // Load the encrypted keypair separately
        match Self::load_keypair(&config.api_key) {
            Ok(keypair) => {
                config.keypair = keypair;
            }
            Err(e) => {
                tracing::warn!("Failed to load encrypted keypair ({}). Generating new keypair.", e);
                let kp = muccheai_crypto::generate_hybrid_keypair()
                    .map_err(|e| anyhow::anyhow!("key generation failed: {}", e))?;
                config.keypair = kp.into();
                config.save_keypair()?;
            }
        }

        // Load encrypted agent API keys
        if let Err(e) = config.load_agent_keys() {
            tracing::warn!("Failed to load agent API keys: {}", e);
        }

        // Migration: if the plaintext api_key was still in config.toml, rewrite
        // the file now so the secret moves to the encrypted sidecar and is
        // stripped from the TOML.
        let sidecar_path = Self::machine_key_path().with_extension("api_key_enc");
        if !sidecar_path.exists() {
            if let Err(e) = config.save() {
                tracing::warn!("Failed to migrate plaintext API key to encrypted sidecar: {}", e);
            }
        }

        Ok(config)
    }

    /// Save configuration to disk atomically.
    /// Agent API keys are stored in a separate encrypted file, not in the TOML.
    pub fn save(&self) -> anyhow::Result<()> {
        let path = Self::config_path();
        if let Some(parent) = path.parent() {
            Self::ensure_private_dir(parent)?;
        }

        #[cfg(unix)]
        let _lock = {
            use std::os::unix::fs::OpenOptionsExt;
            use std::os::unix::io::AsRawFd;
            let lock_path = path.with_extension("lock");
            let file = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&lock_path)?;
            let fd = file.as_raw_fd();
            let ret = unsafe { libc::flock(fd, libc::LOCK_EX) };
            if ret != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            file
        };

        // Save the encrypted keypair separately
        self.save_keypair()?;

        // Save encrypted agent API keys to sidecar
        self.save_agent_keys()?;

        // Save encrypted master API key to sidecar
        self.save_api_key()?;

        // Save the config without agent API keys and without the keypair
        let mut config_for_save = self.clone();
        for agent in &mut config_for_save.agents {
            agent.api_key = None;
        }
        let content = toml::to_string_pretty(&config_for_save)?;
        let tmp_path = path.with_extension("tmp");
        std::fs::write(&tmp_path, content)?;

        // Restrict permissions on Unix before rename
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&tmp_path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&tmp_path, perms)?;
        }

        std::fs::rename(&tmp_path, path)?;
        Ok(())
    }

    /// Get the active agent configuration.
    /// Falls back to legacy Ollama fields if no active agent is set.
    pub fn active_agent_config(&self) -> AgentConfig {
        if self.active_agent.is_empty() {
            AgentConfig {
                name: "default".to_string(),
                provider: "ollama".to_string(),
                model: self.ollama_model.clone(),
                api_key: None,
                base_url: Some(self.ollama_host.clone()),
            }
        } else {
            self.agents
                .iter()
                .find(|a| a.name == self.active_agent)
                .cloned()
                .unwrap_or_else(|| AgentConfig {
                    name: "default".to_string(),
                    provider: "ollama".to_string(),
                    model: self.ollama_model.clone(),
                    api_key: None,
                    base_url: Some(self.ollama_host.clone()),
                })
        }
    }

    /// Get the system prompt for the currently active persona.
    pub fn active_persona_prompt(&self) -> String {
        let persona = self
            .personas
            .iter()
            .find(|p| p.name == self.current_persona)
            .cloned()
            .unwrap_or_else(|| default_personas().into_iter().next().unwrap_or(Persona::default()));
        persona.system_prompt
    }
}

/// Encrypt plaintext with AES-256-GCM using ring (LessSafeKey API).
pub fn encrypt_aes_256_gcm(plaintext: &[u8], key: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
    use ring::aead::{AES_256_GCM, Aad, Nonce, UnboundKey, LessSafeKey, NONCE_LEN};

    let mut nonce_bytes = [0u8; NONCE_LEN];
    ring::rand::SystemRandom::new()
        .fill(&mut nonce_bytes)
        .map_err(|_| anyhow::anyhow!("rng failure"))?;

    let unbound = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|_| anyhow::anyhow!("invalid AES key"))?;
    let sealing_key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = plaintext.to_vec();
    let tag = sealing_key
        .seal_in_place_separate_tag(nonce, Aad::from(b"muccheai-config-v1"), &mut in_out)
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;

    let mut out = Vec::with_capacity(NONCE_LEN + in_out.len() + tag.as_ref().len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&in_out);
    out.extend_from_slice(tag.as_ref());
    Ok(out)
}

/// Decrypt ciphertext (nonce || ciphertext || tag) with AES-256-GCM using ring.
pub fn decrypt_aes_256_gcm(ciphertext: &[u8], key: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
    use ring::aead::{AES_256_GCM, Aad, Nonce, UnboundKey, LessSafeKey, NONCE_LEN};

    if ciphertext.len() < NONCE_LEN + 16 {
        return Err(anyhow::anyhow!("ciphertext too short"));
    }

    let nonce_bytes = &ciphertext[..NONCE_LEN];
    let in_out_with_tag = &ciphertext[NONCE_LEN..];

    let unbound = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|_| anyhow::anyhow!("invalid AES key"))?;
    let opening_key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(
        nonce_bytes.try_into().map_err(|_| anyhow::anyhow!("invalid nonce"))?
    );

    let mut buf = in_out_with_tag.to_vec();
    let plaintext = opening_key
        .open_in_place(nonce, Aad::from(b"muccheai-config-v1"), &mut buf)
        .map_err(|_| anyhow::anyhow!("decryption failed"))?;
    Ok(plaintext.to_vec())
}

/// Encrypt plaintext MCP API keys inside a `ToolConfig` before saving.
/// Values that already start with `enc:` are left untouched.
pub fn encrypt_mcp_keys(cfg: &mut muccheai_tool_gateway::config::ToolConfig) {
    let key = match MuccheConfig::load_or_create_machine_key() {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!("Failed to load machine key for MCP encryption: {}", e);
            return;
        }
    };
    if let Some(ref mut mcp) = cfg.mcp {
        for server in mcp.servers.values_mut() {
            if let Some(ref api_key) = server.api_key {
                if api_key.starts_with("enc:") {
                    continue;
                }
                match encrypt_aes_256_gcm(api_key.as_bytes(), &key) {
                    Ok(ct) => {
                        server.api_key = Some(format!("enc:{}", hex::encode(ct)));
                    }
                    Err(_) => {
                        tracing::warn!("Failed to encrypt MCP API key");
                    }
                }
            }
        }
    }
}

/// Decrypt `enc:`-prefixed MCP API keys inside a `ToolConfig` after loading.
pub fn decrypt_mcp_keys(cfg: &mut muccheai_tool_gateway::config::ToolConfig) {
    let key = match MuccheConfig::load_or_create_machine_key() {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!("Failed to load machine key for MCP decryption: {}", e);
            return;
        }
    };
    if let Some(ref mut mcp) = cfg.mcp {
        for server in mcp.servers.values_mut() {
            if let Some(ref api_key) = server.api_key {
                if let Some(hex_ct) = api_key.strip_prefix("enc:") {
                    match hex::decode(hex_ct) {
                        Ok(ct) => match decrypt_aes_256_gcm(&ct, &key) {
                            Ok(pt) => {
                                if let Ok(s) = String::from_utf8(pt) {
                                    server.api_key = Some(s);
                                } else {
                                    tracing::error!("MCP API key decrypted to invalid UTF-8");
                                }
                            }
                            Err(_) => {
                                tracing::error!("Failed to decrypt MCP API key");
                            }
                        },
                        Err(_) => {
                            tracing::error!("Failed to decode encrypted MCP API key");
                        }
                    }
                }
            }
        }
    }
}

/// No-code custom HTTP tool configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CustomToolConfig {
    pub name: String,
    pub method: String,
    pub url_template: String,
    pub body_template: Option<String>,
}
