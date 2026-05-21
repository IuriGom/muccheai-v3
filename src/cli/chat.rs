//! Interactive chat REPL for MuccheAI.
//!
//! Conversational interface where every message routes through the full
//! security pipeline: LLM Sandbox → Policy Engine → User Approval → Tool Execution.

use crate::cli::{build_policy_engine, create_root_capability, estimate_risk, init_sandbox, json_to_proposal, map_risk_to_style, register_adapters};
use crate::config::MuccheConfig;
use crate::memory_store::MemoryStore;
use crate::structured_memory::StructuredMemoryManager;
use muccheai_memory::MemoryEngine;
use muccheai_policy_engine::ValidationResult;
use muccheai_sandbox::ValidatedPrompt;
use muccheai_tool_gateway::ToolGateway;
use muccheai_types::capabilities::CapabilitySet;
use muccheai_ui::TrustedUi;
use rustyline::DefaultEditor;
use std::io::Write;

/// Run chat: either a one-shot message or the interactive REPL.
pub async fn run_chat(message: Option<String>) -> anyhow::Result<()> {
    let config = MuccheConfig::load()
        .map_err(|_| anyhow::anyhow!("No config. Run `muccheai setup`."))?;

    match message {
        Some(msg) => run_single_message(&msg, &config).await,
        None => start_repl(&config).await,
    }
}

async fn run_single_message(msg: &str, config: &MuccheConfig) -> anyhow::Result<()> {
    let mut sandbox = init_sandbox(config)?;
    let mut policy_engine = build_policy_engine(config);
    let keypair: muccheai_types::crypto_primitives::HybridKeypair = config.keypair.clone().into();
    let mut gateway = ToolGateway::new(keypair.pubkey.clone());
    register_adapters(&mut gateway, &config.allowed_tools);
    let mut trusted_ui = TrustedUi::new();
    let mut memory = MemoryEngine::new("muccheai").unwrap();

    let result = process_message(msg, &sandbox, &mut policy_engine, &mut trusted_ui, &gateway, config, &mut memory, &keypair);
    sandbox.stop()?;
    result
}

async fn start_repl(config: &MuccheConfig) -> anyhow::Result<()> {
    let mut sandbox = init_sandbox(config)?;
    let mut policy_engine = build_policy_engine(config);
    let keypair: muccheai_types::crypto_primitives::HybridKeypair = config.keypair.clone().into();
    let mut gateway = ToolGateway::new(keypair.pubkey.clone());
    register_adapters(&mut gateway, &config.allowed_tools);
    let mut trusted_ui = TrustedUi::new();
    let _store = MemoryStore::new().ok();
    let mut memory = MemoryEngine::new("muccheai").unwrap();
    let structured_memory = StructuredMemoryManager::new().ok();

    let persona_name = if config.current_persona.is_empty() {
        "default"
    } else {
        &config.current_persona
    };
    let persona = config
        .personas
        .iter()
        .find(|p| p.name == persona_name)
        .cloned()
        .unwrap_or_else(|| crate::config::default_personas().into_iter().next().unwrap());

    println!(
        "🐄 MuccheAI v3.0 — Persona: {} — Type /help for commands",
        persona.name
    );

    let mut rl = DefaultEditor::new()?;
    let mut history: Vec<(String, String)> = Vec::new();

    loop {
        match rl.readline("muccheai> ") {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(line);

                match line {
                    "/quit" | "/exit" => {
                        println!("Ciao!");
                        break;
                    }
                    "/help" => {
                        println!("REPL commands:");
                        println!("  /quit    Exit the REPL");
                        println!("  /help    Show this message");
                        println!("  /memory  Show stored memories");
                        println!("  /status  Show system status");
                        println!("");
                        println!("Any other input is sent through the security pipeline:");
                        println!("  LLM Sandbox → Policy Engine → User Approval → Tool Execution");
                    }
                    "/memory" => {
                        if let Some(ref sm) = structured_memory {
                            let facts = sm.list_by_type(muccheai_types::memory::MemoryType::Fact);
                            let prefs = sm.list_by_type(muccheai_types::memory::MemoryType::Preference);
                            let tasks = sm.list_by_type(muccheai_types::memory::MemoryType::TaskHistory);
                            if facts.is_empty() && prefs.is_empty() && tasks.is_empty() {
                                println!("📭 No structured memories stored yet.");
                            } else {
                                println!("🧠 Structured Memories:");
                                if !facts.is_empty() {
                                    println!("  Facts:");
                                    for e in facts.iter().take(10) {
                                        println!("    • {} = {:?}", e.key, e.value);
                                    }
                                }
                                if !prefs.is_empty() {
                                    println!("  Preferences:");
                                    for e in prefs.iter().take(10) {
                                        println!("    • {} = {:?}", e.key, e.value);
                                    }
                                }
                                if !tasks.is_empty() {
                                    println!("  Task History:");
                                    for e in tasks.iter().take(10) {
                                        println!("    • {} = {:?}", e.key, e.value);
                                    }
                                }
                            }
                        }
                    }
                    "/status" => {
                        println!("Model:       {}", config.ollama_model);
                        println!("Host:        {}", config.ollama_host);
                        println!("Persona:     {}", config.current_persona);
                        println!("Policy:      default-deny");
                        println!("PQC:         ML-KEM + ML-DSA");
                        println!("Vault:       {}-of-5 Shamir", config.shamir_threshold);
                    }
                    _ => {
                        if let Err(e) = process_message_with_history(
                            line,
                            &sandbox,
                            &mut policy_engine,
                            &mut trusted_ui,
                            &gateway,
                            config,
                            &persona,
                            &mut history,
                            structured_memory.as_ref(),
                            &mut memory,
                            &keypair,
                        ) {
                            println!("✗ Error: {e}");
                        }
                    }
                }
            }
            Err(rustyline::error::ReadlineError::Interrupted) => {
                println!("^C");
                continue;
            }
            Err(rustyline::error::ReadlineError::Eof) => {
                println!("Ciao!");
                break;
            }
            Err(err) => {
                println!("Error: {err:?}");
                break;
            }
        }
    }

    sandbox.stop()?;
    Ok(())
}

fn process_message_with_history(
    text: &str,
    sandbox: &muccheai_sandbox::LlmSandbox,
    policy_engine: &mut muccheai_policy_engine::PolicyEngine,
    _trusted_ui: &mut TrustedUi,
    gateway: &ToolGateway,
    _config: &MuccheConfig,
    _persona: &crate::config::Persona,
    history: &mut Vec<(String, String)>,
    structured_memory: Option<&StructuredMemoryManager>,
    _memory: &mut MemoryEngine,
    keypair: &muccheai_types::crypto_primitives::HybridKeypair,
) -> anyhow::Result<()> {
    let mut context = String::new();
    if !history.is_empty() {
        context.push_str("Conversation history:\n");
        for (user_msg, assistant_msg) in history.iter().rev().take(5) {
            const MAX_HIST_LEN: usize = 2000;
            let um = &user_msg[..user_msg.len().min(MAX_HIST_LEN)];
            let am = &assistant_msg[..assistant_msg.len().min(MAX_HIST_LEN)];
            context.push_str(&format!("User: {}\nAssistant: {}\n", um, am));
        }
        context.push_str("\n");
    }
    context.push_str(&format!("Current user request: {}", text));

    let prompt = ValidatedPrompt {
        text: context,
        output_schema: r#"{"tool_id":"string","method":"string","params":{}}"#.to_string(),
        max_tokens: 512,
        memory_context: None,
    };

    let suggestion = match sandbox.inference(&prompt) {
        Ok(s) => s,
        Err(e) => return Err(anyhow::anyhow!("Inference failed: {e}")),
    };

    let payload: serde_json::Value = serde_json::from_slice(&suggestion.json_payload)
        .map_err(|e| anyhow::anyhow!("Invalid JSON from sandbox: {e}"))?;
    let proposal = json_to_proposal(&payload, &keypair.pubkey.classical)?;

    println!("📋 Structured suggestion:");
    println!("{}", serde_json::to_string_pretty(&payload).unwrap_or_default());
    println!("⏱  Inference time: {} ms", suggestion.inference_time_ms);

    ask_and_execute(&proposal, policy_engine, gateway, history, structured_memory, text, keypair)
}

fn ask_and_execute(
    proposal: &muccheai_types::ActionProposal,
    policy_engine: &mut muccheai_policy_engine::PolicyEngine,
    gateway: &ToolGateway,
    history: &mut Vec<(String, String)>,
    structured_memory: Option<&StructuredMemoryManager>,
    original_text: &str,
    keypair: &muccheai_types::crypto_primitives::HybridKeypair,
) -> anyhow::Result<()> {
    let risk = estimate_risk(proposal);
    let style_risk = map_risk_to_style(risk);
    print!(
        "🔒 Risk: {} ({}). Approve? (y/n) ",
        style_risk.italian_name(),
        style_risk.english_name()
    );
    std::io::stdout().flush()?;

    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if !answer.trim().eq_ignore_ascii_case("y") {
        println!("✗ Cancelled by user");
        history.push((original_text.to_string(), "Cancelled by user".to_string()));
        return Ok(());
    }

    let root_cap = create_root_capability(proposal, keypair)?;
    let caps = CapabilitySet {
        tokens: vec![root_cap],
        max_risk_level: risk,
    };

    let token = match policy_engine.validate_action(proposal, &caps) {
        Ok(ValidationResult::Approved { token }) => token,
        Ok(ValidationResult::Rejected { reason }) => {
            println!("✗ Policy rejected: {reason}");
            history.push((
                original_text.to_string(),
                format!("Policy rejected: {reason}"),
            ));
            return Ok(());
        }
        Err(e) => return Err(anyhow::anyhow!("Policy validation error: {e}")),
    };

    let params_bytes = serde_json::to_vec(&proposal.params).unwrap_or_default();
    let result = gateway
        .execute(&proposal.tool_id, &proposal.method, &params_bytes, &token)
        .map_err(|e| anyhow::anyhow!("Execution failed: {e}"))?;

    if result.success {
        println!("✓ Executed. Queued.");
        history.push((original_text.to_string(), "Executed and queued".to_string()));
    } else {
        println!("✗ Execution failed.");
        history.push((original_text.to_string(), "Execution failed".to_string()));
    }

    // Log the executed task to structured memory as TaskHistory
    if let Some(sm) = structured_memory {
        let mut meta = serde_json::Map::new();
        meta.insert(
            "tool_id".to_string(),
            serde_json::Value::String(proposal.tool_id.clone()),
        );
        meta.insert(
            "method".to_string(),
            serde_json::Value::String(proposal.method.clone()),
        );
        meta.insert(
            "params".to_string(),
            serde_json::to_value(&proposal.params).unwrap_or_default(),
        );
        meta.insert(
            "success".to_string(),
            serde_json::Value::Bool(result.success),
        );
        let desc = format!("{}.{} executed", proposal.tool_id, proposal.method);
        let _ = sm.log_task(&desc, meta);
    }

    Ok(())
}

fn process_message(
    text: &str,
    sandbox: &muccheai_sandbox::LlmSandbox,
    policy_engine: &mut muccheai_policy_engine::PolicyEngine,
    trusted_ui: &mut TrustedUi,
    gateway: &ToolGateway,
    config: &MuccheConfig,
    memory: &mut MemoryEngine,
    keypair: &muccheai_types::crypto_primitives::HybridKeypair,
) -> anyhow::Result<()> {
    let mut history = Vec::new();
    let persona = config
        .personas
        .iter()
        .find(|p| p.name == config.current_persona)
        .cloned()
        .unwrap_or_else(|| crate::config::default_personas().into_iter().next().unwrap());
    process_message_with_history(
        text, sandbox, policy_engine, trusted_ui, gateway, config, &persona, &mut history, None, memory, keypair,
    )
}
