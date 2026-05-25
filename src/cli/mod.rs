//! CLI argument parsing and command dispatch for MuccheAI.

use clap::{Parser, Subcommand, ValueEnum};
use muccheai_crypto::hybrid_sign;

pub mod audit;
pub mod chat;
pub mod complete;
pub mod daemon;
pub mod doctor;
pub mod policy;
pub mod run;
pub mod setup;
pub mod status;
pub mod update;
pub mod vault;

/// Output format for CLI commands.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    /// Human-readable text output.
    Text,
    /// JSON output.
    Json,
    /// YAML output.
    Yaml,
}

impl OutputFormat {
    /// Resolve output format from boolean flags.
    pub fn resolve(json: bool, yaml: bool) -> Self {
        if json {
            OutputFormat::Json
        } else if yaml {
            OutputFormat::Yaml
        } else {
            OutputFormat::Text
        }
    }
}

/// Top-level CLI arguments.
#[derive(Parser)]
#[command(name = "muccheai")]
#[command(bin_name = "muccheai")]
#[command(about = "MuccheAI v3.0 — Maximum Assurance Secure AI Agent")]
#[command(version)]
pub struct Cli {
    /// Subcommand to execute.
    #[command(subcommand)]
    pub command: Commands,
    /// Active profile to use.
    #[arg(long, global = true)]
    pub profile: Option<String>,
    /// Output in JSON format.
    #[arg(long, global = true)]
    pub json: bool,
    /// Output in YAML format.
    #[arg(long, global = true)]
    pub yaml: bool,
}

/// Available CLI subcommands.
#[derive(Subcommand)]
pub enum Commands {
    /// First-run interactive setup wizard.
    Setup,
    /// Interactive chat REPL or one-shot message.
    Chat {
        /// Optional message to send (starts REPL if omitted).
        message: Option<String>,
    },
    /// Execute a single prompt.
    Run {
        /// The prompt to execute.
        prompt: String,
    },
    /// System status and health.
    Status,
    /// Query audit log.
    Audit {
        /// Filter by tool.
        #[arg(short, long)]
        tool: Option<String>,
        /// Start timestamp.
        #[arg(short, long)]
        from: Option<String>,
        /// End timestamp.
        #[arg(short = 'e', long)]
        to: Option<String>,
        /// Output in JSON.
        #[arg(long)]
        json: bool,
        /// Output in CSV.
        #[arg(long)]
        csv: bool,
    },
    /// Manage policy rules.
    Policy {
        /// Policy subcommand.
        #[command(subcommand)]
        action: PolicyCommands,
    },
    /// Vault operations.
    Vault {
        /// Vault subcommand.
        #[command(subcommand)]
        action: VaultCommands,
    },
    /// Launch web control panel.
    Web {
        /// Address to bind the web server to.
        #[arg(short, long, default_value = "127.0.0.1:3000")]
        bind: String,
    },
    /// Verify build attestation.
    Verify,
    /// Run system health check.
    Doctor,
    /// Run demo scenario.
    Demo,
    /// Manage daemon.
    Daemon {
        /// Daemon subcommand.
        #[command(subcommand)]
        action: DaemonCommands,
    },
    /// Generate shell completions.
    Complete {
        /// Shell to generate completions for.
        shell: clap_complete::Shell,
    },
    /// Configuration management.
    Config {
        /// Config subcommand.
        #[command(subcommand)]
        action: ConfigCommands,
    },
    /// Manage AI personas.
    Persona {
        /// Persona subcommand.
        #[command(subcommand)]
        action: PersonaCommands,
    },
    /// Update MuccheAI to the latest version.
    Update,
}

/// Policy subcommands.
#[derive(Subcommand)]
pub enum PolicyCommands {
    /// List active policy rules.
    List,
    /// Add a new policy rule.
    Add {
        /// Rule identifier.
        id: String,
        /// Tool ID.
        tool: String,
        /// Method name.
        method: String,
        /// Action to take.
        action: String,
    },
    /// Remove a policy rule.
    Remove {
        /// Rule identifier.
        id: String,
    },
}

/// Vault subcommands.
#[derive(Subcommand)]
pub enum VaultCommands {
    /// Show vault status.
    Status,
    /// Seal the vault.
    Seal,
    /// Unseal the vault.
    Unseal,
    /// Rotate vault keys.
    Rotate,
    /// Recover the vault from shares.
    Recover {
        /// Share inputs in the form index:value.
        share: Vec<String>,
    },
}

/// Daemon subcommands.
#[derive(Subcommand)]
pub enum DaemonCommands {
    /// Start the background daemon.
    Start,
    /// Stop the background daemon.
    Stop,
    /// Show daemon status.
    Status,
}

/// Persona subcommands.
#[derive(Subcommand)]
pub enum PersonaCommands {
    /// List all personas.
    List,
    /// Add a new persona.
    Add {
        /// Name of the persona.
        name: String,
        /// Description of the persona.
        description: String,
    },
    /// Switch to a different persona.
    Switch {
        /// Name of the persona.
        name: String,
    },
    /// Remove a persona.
    Remove {
        /// Name of the persona.
        name: String,
    },
}

/// Config subcommands.
#[derive(Subcommand)]
pub enum ConfigCommands {
    /// Print the configuration file path.
    Path,
    /// Print the API key for web panel authentication.
    Key,
    /// Get a configuration value.
    Get {
        /// Configuration key.
        key: String,
    },
    /// Set a configuration value.
    Set {
        /// Configuration key.
        key: String,
        /// Configuration value.
        value: String,
    },
}

/// Load a profile configuration.
pub fn load_profile(_profile: &str) -> Option<crate::config::MuccheConfig> {
    // Profiles are not yet implemented.
    None
}

/// Read input from stdin until EOF.
pub fn read_input(_hint: &str) -> String {
    let mut buf = String::new();
    let stdin = std::io::stdin();
    while let Ok(n) = stdin.read_line(&mut buf) {
        if n == 0 {
            break;
        }
    }
    buf.trim_end().to_string()
}

/// Initialize the LLM sandbox from configuration.
pub fn init_sandbox(
    config: &crate::config::MuccheConfig,
) -> anyhow::Result<muccheai_sandbox::LlmSandbox> {
    let mut sandbox_config = muccheai_sandbox::default_sandbox_config();
    sandbox_config.ollama_url = config.ollama_host.clone();
    sandbox_config.ollama_model = config.ollama_model.clone();
    let mut sandbox = muccheai_sandbox::LlmSandbox::new(sandbox_config);
    sandbox.start()?;
    Ok(sandbox)
}

/// Build a policy engine from configuration.
pub fn build_policy_engine(config: &crate::config::MuccheConfig) -> muccheai_policy_engine::PolicyEngine {
    let keypair: muccheai_types::crypto_primitives::HybridKeypair = config.keypair.clone().into();
    muccheai_policy_engine::PolicyEngine::new(config.policy_rules.clone(), keypair)
}

/// Register tool adapters on the gateway for allowed tools.
pub fn register_adapters(
    _gateway: &mut muccheai_tool_gateway::ToolGateway,
    _allowed_tools: &[String],
) {
    // Built-in adapters are auto-registered by ToolGateway::new().
    // This function is kept for API compatibility.
}

/// Run a single prompt through the full pipeline.
pub fn process_prompt(
    prompt_text: &str,
    sandbox: &muccheai_sandbox::LlmSandbox,
    policy_engine: &mut muccheai_policy_engine::PolicyEngine,
    trusted_ui: &mut muccheai_ui::TrustedUi,
    gateway: &muccheai_tool_gateway::ToolGateway,
    _config: &crate::config::MuccheConfig,
    keypair: &muccheai_types::crypto_primitives::HybridKeypair,
) -> anyhow::Result<()> {
    use muccheai_policy_engine::ValidationResult;
    use muccheai_sandbox::ValidatedPrompt;
    use muccheai_types::capabilities::CapabilitySet;
    use std::io::Write;

    let prompt = ValidatedPrompt {
        text: prompt_text.to_string(),
        output_schema: r#"{"tool_id":"string","method":"string","params":{}}"#.to_string(),
        max_tokens: 512,
        memory_context: None,
    };

    let proposal = match sandbox.inference(&prompt) {
        Ok(suggestion) => {
            let payload: serde_json::Value = serde_json::from_slice(&suggestion.json_payload)
                .map_err(|e| anyhow::anyhow!("Invalid JSON from sandbox: {}", e))?;
            json_to_proposal(&payload, &keypair.pubkey.classical)?
        }
        Err(e) => return Err(anyhow::anyhow!("Inference failed: {}", e)),
    };

    let risk = estimate_risk(&proposal);
    let style_risk = map_risk_to_style(risk);
    println!("🥛 Proposal: {}.{}", proposal.tool_id, proposal.method);
    println!(
        "🔒 Risk: {} ({})",
        style_risk.italian_name(),
        style_risk.english_name()
    );

    print!("⏳ Applying friction...");
    std::io::stdout().flush()?;
    let grant = trusted_ui
        .request_approval(&proposal, risk)
        .map_err(|e| anyhow::anyhow!("Approval denied: {}", e))?;
    println!(" ✓ Approved via {:?}", grant.mechanism);

    let root_cap = create_root_capability(&proposal, keypair)?;
    let caps = CapabilitySet {
        tokens: vec![root_cap],
        max_risk_level: risk,
    };

    let token = match policy_engine.validate_action(&proposal, &caps) {
        Ok(ValidationResult::Approved { token }) => token,
        Ok(ValidationResult::Rejected { reason }) => {
            return Err(anyhow::anyhow!("Policy rejected: {}", reason));
        }
        Err(e) => return Err(anyhow::anyhow!("Policy validation error: {}", e)),
    };

    let params_bytes = serde_json::to_vec(&proposal.params).unwrap_or_default();
    let result = gateway
        .execute(&proposal.tool_id, &proposal.method, &params_bytes, &token)
        .map_err(|e| anyhow::anyhow!("Execution failed: {}", e))?;

    if result.success {
        println!("✓ Executed. Queued.");
    } else {
        println!("✗ Execution failed.");
    }

    Ok(())
}

fn json_to_proposal(
    payload: &serde_json::Value,
    requester_pubkey: &[u8],
) -> anyhow::Result<muccheai_types::ActionProposal> {
    use muccheai_types::{ActionProposal, Timestamp};
    use rand::Rng;

    let tool_id = payload
        .get("tool_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let method = payload
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("execute")
        .to_string();
    let params = payload.get("params").cloned().unwrap_or(serde_json::json!({}));

    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill(&mut nonce);

    Ok(ActionProposal {
        tool_id,
        method,
        params,
        requester_pubkey: requester_pubkey.to_vec(),
        timestamp: Timestamp::now(),
        nonce: nonce.to_vec(),
    })
}

fn estimate_risk(proposal: &muccheai_types::ActionProposal) -> muccheai_types::RiskLevel {
    let base = match proposal.tool_id.as_str() {
        "email" => muccheai_types::RiskLevel::Medium,
        "calendar" => muccheai_types::RiskLevel::Low,
        "filesystem" => muccheai_types::RiskLevel::High,
        "search" => muccheai_types::RiskLevel::Low,
        _ => muccheai_types::RiskLevel::Medium,
    };

    // Parameter-aware risk escalation
    let params_str = serde_json::to_string(&proposal.params).unwrap_or_default().to_lowercase();
    let dangerous = ["delete", "rm", "remove", "drop", "exec", "eval", "shell", "sudo", "password", "secret", "key"];
    if dangerous.iter().any(|d| params_str.contains(d)) {
        return muccheai_types::RiskLevel::Critical;
    }
    base
}

fn map_risk_to_style(risk: muccheai_types::RiskLevel) -> crate::style::RiskLevel {
    match risk {
        muccheai_types::RiskLevel::Low => crate::style::RiskLevel::Sereno,
        muccheai_types::RiskLevel::Medium => crate::style::RiskLevel::Tramontana,
        muccheai_types::RiskLevel::High => crate::style::RiskLevel::Scirocco,
        muccheai_types::RiskLevel::Critical => crate::style::RiskLevel::Vesuvio,
    }
}

fn create_root_capability(
    proposal: &muccheai_types::ActionProposal,
    keypair: &muccheai_types::crypto_primitives::HybridKeypair,
) -> anyhow::Result<muccheai_types::capabilities::CapabilityToken> {
    use muccheai_types::capabilities::CapabilityToken;
    use muccheai_types::Timestamp;
    use rand::RngCore;

    let now = Timestamp::now();
    let expiry = Timestamp(now.0 + 3_600_000); // 1 hour
    let mut token_id = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut token_id);
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    // Build token first so we can sign its canonical payload
    let mut token = CapabilityToken {
        token_id: token_id.to_vec(),
        tool_id: proposal.tool_id.clone(),
        method: proposal.method.clone(),
        resource_ids: vec!["*".to_string()],
        not_before: now,
        not_after: expiry,
        issuer_pubkey: keypair.pubkey.classical.clone(),
        issuer_pq_pubkey: keypair.pubkey.pq_sign.clone(),
        classical_signature: vec![],
        pq_signature: vec![],
        nonce: nonce.to_vec(),
        bound_process: std::process::id() as u64,
        max_uses: 0,
    };

    let message = muccheai_crypto::sha3_512(&token.signing_payload());
    let sig = hybrid_sign(
        &message,
        &keypair,
    ).map_err(|e| anyhow::anyhow!("Failed to sign capability: {}", e))?;

    token.classical_signature = sig.classical;
    token.pq_signature = sig.pq;

    Ok(token)
}
