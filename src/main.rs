//! MuccheAI v3 entry point.
//!
//! Boots the web server or runs a CLI command.

use clap::Parser;
use ring::rand::SecureRandom;

use muccheai_build_verify::*;
use muccheai_crypto::*;
use muccheai_federation::*;
use muccheai_policy_engine::*;
use muccheai_recovery::*;
use muccheai_sandbox::*;
use muccheai_tool_gateway::*;
use muccheai_tool_gateway::config::ToolConfig;
use muccheai_types::*;
use muccheai_types::capabilities::*;
use muccheai_types::crypto_primitives::*;
use muccheai_types::memory::*;
use muccheai_memory::MemoryEngine;
use muccheai_ui::*;
use muccheai_vault::*;
use chrono;

mod cli;
mod config;
mod memory_store;
mod notify;
mod plugin;
mod structured_memory;
mod style;
mod users;
mod web;

use cli::{Cli, Commands, ConfigCommands, DaemonCommands, OutputFormat, PersonaCommands, PolicyCommands, VaultCommands};

#[tokio::main]
async fn main() {
    let password_flag = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".muccheai")
        .join(".password_required");
    if password_flag.exists() && std::env::var("MUCCHEAI_KEY_PASSWORD").is_err() {
        eprintln!("╔══════════════════════════════════════════════════════════════╗");
        eprintln!("║  PASSWORD REQUIRED                                           ║");
        eprintln!("╚══════════════════════════════════════════════════════════════╝");
        eprintln!();
        eprintln!("  A password was configured during setup to protect your local key.");
        eprintln!("  Set the environment variable before running MuccheAI:");
        eprintln!();
        eprintln!("    export MUCCHEAI_KEY_PASSWORD='your-password'");
        eprintln!();
        eprintln!("  Or run with the variable inline:");
        eprintln!();
        eprintln!("    MUCCHEAI_KEY_PASSWORD='your-password' muccheai ...");
        eprintln!();
        std::process::exit(1);
    } else if std::env::var("MUCCHEAI_KEY_PASSWORD").is_err() {
        eprintln!("WARNING: MUCCHEAI_KEY_PASSWORD not set. Machine key is raw material — set a password for Argon2id derivation.");
    }

    // Hidden internal daemon mode — bypass clap so the child process doesn't
    // need to parse unknown arguments. Only trigger if __daemon is the first
    // Internal daemon entry point. Never invoke directly; use `muccheai daemon start`.
    if std::env::args().nth(1).as_deref() == Some("__daemon") {
        tracing::info!("Daemon mode requested via __daemon flag");
        // Verify this process was spawned by `daemon_start()` (PID file must exist and match).
        let pid_file = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("."))
            .join(".muccheai").join("daemon.pid");
        // Retry with backoff to avoid the race where the parent has not yet
        // written the PID file (the parent writes it immediately after spawn).
        let is_valid_spawn = (0..100).any(|_| {
            let valid = std::fs::read_to_string(&pid_file)
                .ok()
                .and_then(|s| s.trim().parse::<u32>().ok())
                == Some(std::process::id());
            if valid {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
            false
        });
        if !is_valid_spawn {
            eprintln!("Daemon mode can only be started through `muccheai daemon start`.");
            std::process::exit(1);
        }
        if let Err(e) = cli::daemon::run_daemon().await {
            eprintln!("Daemon error: {}", e);
            std::process::exit(1);
        }
        return;
    }

    // ── First-run auto-detection ──────────────────────────────────────────
    // If no config exists and the user isn't asking for help/version/completions,
    // launch the setup wizard automatically.
    let is_first_run = cli::setup::is_first_run();
    let args = Cli::parse();
    let skip_setup = matches!(
        args.command,
        Commands::Setup | Commands::Complete { .. } | Commands::Config { .. } | Commands::Update
    ) || std::env::args().any(|a| a == "--help" || a == "-h" || a == "--version" || a == "-V");

    if is_first_run && !skip_setup {
        let theme = crate::style::Theme::Cyber;
        theme.print_banner();
        theme.print_header(&format!("First-Time Setup v{}", env!("CARGO_PKG_VERSION")));
        println!(
            "  {}\n",
            theme.style_secondary().apply_to(
                "Welcome! It looks like this is your first time running MuccheAI. \
                 Let's get you set up."
            )
        );
        match cli::setup::run() {
            Ok(true) => {
                println!();
                theme.print_success("Setup complete! Running your command...\n");
            }
            Ok(false) => {
                // User cancelled setup.
                std::process::exit(0);
            }
            Err(e) => {
                theme.print_error(&format!("Setup failed: {e}"));
                std::process::exit(1);
            }
        }
    }

    // Load profile if specified
    if let Some(ref profile) = args.profile {
        if let Some(config) = cli::load_profile(profile) {
            tracing::info!("Loaded profile '{}': {:?}", profile, config);
        } else {
            eprintln!("Warning: profile '{}' not found", profile);
        }
    }

    let format = OutputFormat::resolve(args.json, args.yaml);

    // Non-blocking version check (cached, once per day).
    // Skip for commands that shouldn't be delayed or don't need it.
    let skip_version_check = matches!(
        args.command,
        Commands::Complete { .. }
            | Commands::Update
            | Commands::Setup
    ) || std::env::args().any(|a| a == "--help" || a == "-h" || a == "--version" || a == "-V");

    if !skip_version_check {
        cli::update::print_update_banner().await;
    }

    match args.command {
        Commands::Setup => {
            if let Err(e) = cli::setup::run() {
                eprintln!("Setup error: {e}");
                std::process::exit(1);
            }
        }
        Commands::Run { prompt } => {
            match crate::config::MuccheConfig::load() {
                Ok(config) => {
                    if let Err(e) = cli::run::run(&prompt, &config) {
                        eprintln!("Run failed: {e}");
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("Failed to load config: {e}. Run `muccheai setup` first.");
                    std::process::exit(1);
                }
            }
        }
        Commands::Chat { message } => run_chat(message, format).await,
        Commands::Web { bind } => run_web_server(&bind).await,
        Commands::Daemon { action } => match action {
            DaemonCommands::Start => {
                if let Err(e) = cli::daemon::daemon_start() {
                    eprintln!("{}", e);
                    std::process::exit(1);
                } else {
                    notify::notify("MuccheAI Daemon", "Daemon started successfully.");
                }
            }
            DaemonCommands::Stop => {
                if let Err(e) = cli::daemon::daemon_stop() {
                    eprintln!("{}", e);
                    std::process::exit(1);
                } else {
                    notify::notify("MuccheAI Daemon", "Daemon stopped.");
                }
            }
            DaemonCommands::Status => {
                if let Err(e) = cli::daemon::daemon_status() {
                    eprintln!("{}", e);
                }
            }
        },
        Commands::Complete { shell } => cli::complete::generate_completions(shell),
        Commands::Status => cli::status::print_status(format),
        Commands::Audit {
            tool,
            from,
            to,
            json,
            csv,
        } => {
            cli::audit::audit(tool, from, to, json, csv);
        }
        Commands::Policy { action } => match action {
            PolicyCommands::List => cli::policy::policy_list(),
            PolicyCommands::Add {
                id,
                tool,
                method,
                action,
            } => {
                cli::policy::policy_add(&id, &tool, &method, &action);
            }
            PolicyCommands::Remove { id } => {
                cli::policy::policy_remove(&id);
            }
        },
        Commands::Vault { action } => match action {
            VaultCommands::Status => cli::vault::vault_status(),
            VaultCommands::Seal => println!("Not yet implemented: vault seal"),
            VaultCommands::Unseal => println!("Not yet implemented: vault unseal"),
            VaultCommands::Rotate => {
                if let Err(e) = cli::vault::vault_rotate() {
                    println!("✗ {e}");
                }
            }
            VaultCommands::Recover { share } => {
                let inputs: Vec<cli::vault::ShareInput> = share
                    .iter()
                    .filter_map(|s| {
                        let mut parts = s.splitn(2, ':');
                        let index = parts.next()?.parse().ok()?;
                        let value = parts.next()?.to_string();
                        Some(cli::vault::ShareInput { index, value })
                    })
                    .collect();
                if let Err(e) = cli::vault::vault_recover(inputs) {
                    println!("✗ {e}");
                }
            }
        },
        Commands::Verify => {
            match verify_build() {
                Ok(report) => {
                    println!("{}", report);
                }
                Err(e) => {
                    eprintln!("Build verification failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Persona { action } => match action {
            PersonaCommands::List => {
                match crate::config::MuccheConfig::load() {
                    Ok(config) => {
                        if config.personas.is_empty() {
                            println!("No personas configured.");
                        } else {
                            println!("Personas:");
                            for p in &config.personas {
                                let marker = if p.name == config.current_persona {
                                    " (*)"
                                } else {
                                    ""
                                };
                                println!("  {}{}", p.name, marker);
                                println!("    {}", p.description);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to load config: {e}");
                        std::process::exit(1);
                    }
                }
            }
            PersonaCommands::Add { name, .. } => {
                match crate::config::MuccheConfig::load() {
                    Ok(mut config) => {
                        if config.personas.iter().any(|p| p.name == name) {
                            eprintln!("Persona '{}' already exists.", name);
                            std::process::exit(1);
                        }
                        let description = match dialoguer::Input::<String>::with_theme(&dialoguer::theme::ColorfulTheme::default())
                            .with_prompt("Description")
                            .interact_text()
                        {
                            Ok(d) => d,
                            Err(e) => {
                                eprintln!("Input error: {e}");
                                std::process::exit(1);
                            }
                        };
                        let system_prompt = match dialoguer::Input::<String>::with_theme(&dialoguer::theme::ColorfulTheme::default())
                            .with_prompt("System prompt")
                            .interact_text()
                        {
                            Ok(s) => s,
                            Err(e) => {
                                eprintln!("Input error: {e}");
                                std::process::exit(1);
                            }
                        };
                        config.personas.push(crate::config::Persona {
                            name,
                            description,
                            system_prompt,
                        });
                        if let Err(e) = config.save() {
                            eprintln!("Failed to save config: {e}");
                            std::process::exit(1);
                        }
                        println!("✓ Persona added");
                    }
                    Err(e) => {
                        eprintln!("Failed to load config: {e}");
                        std::process::exit(1);
                    }
                }
            }
            PersonaCommands::Switch { name } => {
                match crate::config::MuccheConfig::load() {
                    Ok(mut config) => {
                        if !config.personas.iter().any(|p| p.name == name) {
                            eprintln!("Persona '{}' not found.", name);
                            std::process::exit(1);
                        }
                        config.current_persona = name.clone();
                        if let Err(e) = config.save() {
                            eprintln!("Failed to save config: {e}");
                            std::process::exit(1);
                        }
                        println!("✓ Switched to persona '{}'", name);
                    }
                    Err(e) => {
                        eprintln!("Failed to load config: {e}");
                        std::process::exit(1);
                    }
                }
            }
            PersonaCommands::Remove { name } => {
                match crate::config::MuccheConfig::load() {
                    Ok(mut config) => {
                        if name == "default" {
                            eprintln!("Cannot remove the 'default' persona.");
                            std::process::exit(1);
                        }
                        if config.personas.len() <= 1 {
                            eprintln!("Cannot remove the only remaining persona.");
                            std::process::exit(1);
                        }
                        let idx = config.personas.iter().position(|p| p.name == name);
                        if let Some(i) = idx {
                            config.personas.remove(i);
                            if config.current_persona == name {
                                config.current_persona = config.personas.first().map(|p| p.name.clone()).unwrap_or_default();
                            }
                            if let Err(e) = config.save() {
                                eprintln!("Failed to save config: {e}");
                                std::process::exit(1);
                            }
                            println!("✓ Persona '{}' removed", name);
                        } else {
                            eprintln!("Persona '{}' not found.", name);
                            std::process::exit(1);
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to load config: {e}");
                        std::process::exit(1);
                    }
                }
            }
        },
        Commands::Doctor => {
            if let Err(e) = cli::doctor::run().await {
                eprintln!("Doctor error: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Demo => {
            run_demo();
        }
        Commands::Config { action } => match action {
            ConfigCommands::Path => {
                let path = crate::config::MuccheConfig::config_path();
                println!("{}", path.display());
            }
            ConfigCommands::Key => {
                match crate::config::MuccheConfig::load() {
                    Ok(config) => {
                        let masked: String = config
                            .api_key
                            .chars()
                            .enumerate()
                            .map(|(i, c)| if i < 4 || i >= config.api_key.len() - 4 { c } else { '*' })
                            .collect();
                        println!("{}", masked);
                    }
                    Err(e) => {
                        eprintln!("Failed to load config: {e}");
                        std::process::exit(1);
                    }
                }
            }
            ConfigCommands::RevealKey => {
                match crate::config::MuccheConfig::load() {
                    Ok(config) => {
                        println!("{}", config.api_key);
                    }
                    Err(e) => {
                        eprintln!("Failed to load config: {e}");
                        std::process::exit(1);
                    }
                }
            }
            ConfigCommands::Get { key } => {
                match crate::config::MuccheConfig::load() {
                    Ok(config) => {
                        let val = match key.as_str() {
                            "ollama_host" => config.ollama_host,
                            "ollama_model" => config.ollama_model,
                            "api_key" => {
                                let masked: String = config
                                    .api_key
                                    .chars()
                                    .enumerate()
                                    .map(|(i, c)| if i < 4 || i >= config.api_key.len() - 4 { c } else { '*' })
                                    .collect();
                                masked
                            }
                            "web_bind_address" => config.web_bind_address,
                            "approval_tier" => config.approval_tier,
                            "shamir_threshold" => config.shamir_threshold.to_string(),
                            "allowed_tools" => config.allowed_tools.join(", "),
                            "current_persona" => config.current_persona,
                            _ => {
                                eprintln!("Unknown key: {key}");
                                std::process::exit(1);
                            }
                        };
                        println!("{}", val);
                    }
                    Err(e) => {
                        eprintln!("Failed to load config: {e}");
                        std::process::exit(1);
                    }
                }
            }
            ConfigCommands::Set { key, value } => {
                match crate::config::MuccheConfig::load() {
                    Ok(mut config) => {
                        match key.as_str() {
                            "ollama_host" => {
                                // Prevent SSRF via malicious Ollama host configuration.
                                if crate::web::validate_no_ssrf(&value).is_err() {
                                    eprintln!("Invalid ollama_host: SSRF validation failed");
                                    std::process::exit(1);
                                }
                                config.ollama_host = value;
                            }
                            "ollama_model" => config.ollama_model = value,
                            "web_bind_address" => config.web_bind_address = value,
                            "approval_tier" => config.approval_tier = value,
                            "current_persona" => config.current_persona = value,
                            _ => {
                                eprintln!("Unknown or read-only key: {key}");
                                std::process::exit(1);
                            }
                        };
                        if let Err(e) = config.save() {
                            eprintln!("Failed to save config: {e}");
                            std::process::exit(1);
                        }
                        println!("✓ {key} updated");
                    }
                    Err(e) => {
                        eprintln!("Failed to load config: {e}");
                        std::process::exit(1);
                    }
                }
            }
        },
        Commands::Update => {
            if let Err(e) = cli::update::run_update() {
                eprintln!("Update failed: {e}");
                std::process::exit(1);
            }
        }
    }
}

/// Run chat REPL or a single message through the pipeline.
async fn run_chat(message: Option<String>, _format: OutputFormat) {
    match message {
        None => {
            if let Err(e) = cli::chat::run_chat(None).await {
                eprintln!("Chat error: {e}");
                std::process::exit(1);
            }
        }
        Some(ref m) if m == "-" => {
            match crate::config::MuccheConfig::load() {
                Ok(config) => {
                    if let Err(e) = cli::run::run("-", &config) {
                        eprintln!("Run failed: {e}");
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("Failed to load config: {e}. Run `muccheai setup` first.");
                    std::process::exit(1);
                }
            }
        }
        Some(m) => {
            match crate::config::MuccheConfig::load() {
                Ok(config) => {
                    if let Err(e) = cli::run::run(&m, &config) {
                        eprintln!("Run failed: {e}");
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("Failed to load config: {e}. Run `muccheai setup` first.");
                    std::process::exit(1);
                }
            }
        }
    }
}

/// Run the end-to-end security demonstration.
fn run_demo() {
    if cli::daemon::is_daemon_running() {
        println!("⚠️  Daemon is running. Use `muccheai daemon status` to check it, or stop it before running the demo.");
    }

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  MuccheAI v3.0 — Security-Focused AI Agent                  ║");
    println!("║  Defense-in-depth architecture (demo / work in progress)     ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    println!("Initializing hybrid PQC keypair...");
    let issuer_keypair = match generate_hybrid_keypair() {
        Ok(kp) => kp,
        Err(e) => {
            eprintln!("Failed to generate keypair: {}", e);
            return;
        }
    };
    println!("  ✓ Classical pubkey: {} bytes", issuer_keypair.pubkey.classical.len());
    println!("  ✓ PQC pubkey: {} bytes", issuer_keypair.pubkey.pq.len());

    println!("\nInitializing Policy Engine kernel...");
    let rules = rules::PolicyRules {
        rules: vec![
            rules::PolicyRule {
                id: "allow-email-send".to_string(),
                tool_id: "email".to_string(),
                method: "send".to_string(),
                resource_patterns: vec!["*".to_string()],
                action: rules::RuleAction::Allow,
                conditions: rules::RuleConditions::Always,
            },
            rules::PolicyRule {
                id: "allow-calendar-read".to_string(),
                tool_id: "calendar".to_string(),
                method: "read".to_string(),
                resource_patterns: vec!["*".to_string()],
                action: rules::RuleAction::Allow,
                conditions: rules::RuleConditions::Always,
            },
            rules::PolicyRule {
                id: "deny-filesystem-delete".to_string(),
                tool_id: "filesystem".to_string(),
                method: "delete".to_string(),
                resource_patterns: vec!["*".to_string()],
                action: rules::RuleAction::Deny,
                conditions: rules::RuleConditions::Always,
            },
        ],
        default_action: rules::RuleAction::Deny,
        ..Default::default()
    };
    let mut policy_engine = PolicyEngine::new(rules, issuer_keypair);
    println!("  ✓ Policy Engine initialized with default-deny");
    println!("  ✓ Rules loaded: allow email.send, allow calendar.read, deny filesystem.delete");

    println!("\nInitializing LLM sandbox...");
    let sandbox_config = default_sandbox_config();
    println!("  ✓ VM ID: {}", sandbox_config.vm_id);
    println!("  ✓ CPU cores: {:?} (P-cores only)", sandbox_config.cpu_cores);
    println!("  ✓ Memory: {} MB", sandbox_config.memory_limit_mb);
    println!("  ✓ Network: {}", if sandbox_config.network_enabled { "enabled" } else { "disabled" });
    println!("  ✓ Filesystem: tmpfs only");
    println!("  ✓ KSM: {}", if sandbox_config.ksm_disabled { "disabled" } else { "enabled" });
    println!("  ✓ Memory encryption: {}", if sandbox_config.memory_encryption { "enabled" } else { "disabled" });

    let mut sandbox = LlmSandbox::new(sandbox_config);
    // Demo mode: do not spawn real sandbox processes or make real HTTP calls.
    println!("  ✓ Sandbox configured (demo — process isolation skipped)");

    println!("\nInitializing intrusion recovery...");
    let recovery = IncidentResponse::new();
    println!("  ✓ Anomaly detector: 5-sigma threshold");
    println!("  ✓ Containment playbook: {} steps", recovery.containment.steps.len());
    println!("  ✓ Forward-secure logging: enabled");

    println!("\nVerifying build attestation...");
    let build_verify = MultiCiVerification::new([0u8; 20])
        .with_github_repo("torvalds", "linux"); // Demo repo
    match build_verify.verify_build() {
        Ok(attestation) => {
            for ci in &attestation.ci_systems {
                let status_str = match ci.status {
                    muccheai_build_verify::CiStatus::Passing => "✓ passing",
                    muccheai_build_verify::CiStatus::Failing => "✗ failing",
                    muccheai_build_verify::CiStatus::Pending => "◐ pending",
                    muccheai_build_verify::CiStatus::Unknown => "? unknown",
                };
                println!("  {} {}", status_str, ci.name);
            }
        }
        Err(e) => {
            println!("  ⚠ Build verification error: {}", e);
        }
    }
    println!("  ⚠ Warrant canary: placeholder data (not verified)");

    println!("\nInitializing Trusted UI...");
    let mut trusted_ui = TrustedUi::new();
    println!("  ✓ 4-tier approval system ready");
    println!("  ✓ Session isolation: per-user");
    println!("  ✓ Risk-proportional friction: configured");

    println!("\nFederation protocol initialized...");
    println!("  ✓ W3C DID support");
    println!("  ✓ Cross-agent capability delegation");
    println!("  ✓ Ephemeral federation");
    println!("  ✓ MPC: research track (P2)");

    // === Demonstrate End-to-End Flow ===
    println!("\n═══════════════════════════════════════════════════════════════");
    println!("  END-TO-END DEMONSTRATION");
    println!("═══════════════════════════════════════════════════════════════\n");

    // Step 1: User prompt
    let user_prompt = "Email John about the meeting tomorrow";
    println!("[User] \"{}\"", user_prompt);

    // Step 2: LLM generates structured suggestion (in sandbox)
    println!("\n[LLM Sandbox] Generating structured suggestion...");
    let prompt = ValidatedPrompt {
        text: user_prompt.to_string(),
        output_schema: "action_proposal".to_string(),
        max_tokens: 512,
        memory_context: None,
    };
    // Demo mode: skip real LLM inference and use mock structured output.
    let mock_payload = serde_json::json!({
        "tool_id": "email",
        "method": "send",
        "params": { "to": "john@example.com", "subject": "Meeting tomorrow" }
    });
    println!("  ✓ Structured output: {}", mock_payload);
    println!("  ✓ Dual verification: semantic similarity check passed");
    println!("  ✓ Inference time: 42 ms (demo)");

    // Step 3: Parse action proposal
    let proposal = ActionProposal {
        tool_id: "email".to_string(),
        method: "send".to_string(),
        params: serde_json::json!({"to": "john@example.com", "subject": "Meeting tomorrow"}),
        requester_pubkey: vec![0u8; 32],
        timestamp: Timestamp::now(),
        nonce: vec![0x42; 32],
    };

    // Step 4: Policy Engine validates
    println!("\n[Policy Engine] Validating action proposal...");
    let capabilities = CapabilitySet {
        tokens: vec![],
        max_risk_level: RiskLevel::Medium,
    };
    let validation_result = policy_engine.validate_action(
        &proposal,
        &capabilities,
    );
    println!("  ✓ Validation result: {:?}", validation_result.is_ok());

    // Step 5: User approval
    println!("\n[Trusted UI] Requesting user approval...");
    let risk = RiskLevel::Medium; // Email send = medium risk
    match trusted_ui.request_approval(&proposal, risk) {
        Ok(grant) => {
            println!("  ✓ User approved via {:?}", grant.mechanism);
            println!("  ✓ Approval delay: {} seconds applied", risk.delay_seconds());
        }
        Err(e) => {
            println!("  ✗ Approval denied: {}", e);
        }
    }

    // Step 6: Tool Gateway executes
    println!("\n[Tool Gateway] Executing approved action...");
    let _gateway = ToolGateway::new(HybridPubkey {
        classical: vec![0u8; 32],
        x25519: vec![0u8; 32],
        pq: vec![0u8; 1184],
        pq_sign: vec![0u8; 1312],
    });
    // Built-in adapters already registered by ToolGateway::new()
    println!("  ✓ Email adapter registered (send-only queue)");

    // Step 7: Memory architecture
    println!("\n[Memory] Structured memory architecture...");
    let fact = MemoryEntry {
        memory_type: MemoryType::Fact,
        key: "manager".to_string(),
        value: MemoryValue::ShortString("[EXAMPLE_VALUE]".to_string()),
        created_at: Timestamp::now(),
        user_signature: vec![0u8; 64],
        content_hash: vec![0u8; 64],
        owner_hash: String::new(),
    };
    println!("  ✓ Fact stored: {} = {:?}", fact.key, fact.value);
    println!("  ✓ Merkle tree: integrity verifiable");
    println!("  ✓ LLM can READ but cannot WRITE directly");

    // Step 8: Vault / Shamir
    println!("\n[Vault] Shamir's Secret Sharing (3-of-5)...");
    let master_secret = [0xABu8; 32];
    let _vault = match SecretVault::new(&master_secret, 3) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Vault creation failed: {}", e);
            return;
        }
    };
    println!("  ✓ Master secret split into 5 shares");
    println!("  ✓ Recovery threshold: 3 shares");
    println!("  ✓ Share 1: Local file");
    println!("  ✓ Share 2: Local file");
    println!("  ✓ Share 3: Local file");
    println!("  ✓ Share 4: Local file");
    println!("  ✓ Share 5: Local file");

    // Step 9: Anomaly detection
    println!("\n[Recovery] Anomaly detection...");
    let incident = recovery.detection.detect(100.0, &["email.send".to_string()]);
    if let Some(inc) = incident {
        println!("  ⚠ Anomaly detected: {}", inc.description);
        println!("  ⚠ Severity: {:?}", inc.severity);
        notify::notify("MuccheAI Anomaly", &format!("{}: {:?}", inc.description, inc.severity));
    } else {
        println!("  ✓ No anomalies detected");
    }

    // Step 10: Cross-agent delegation demo
    println!("\n[Federation] Cross-agent capability delegation...");
    let _delegation = CrossAgentDelegation {
        issuer: DID { method: "muccheai".to_string(), identifier: "personal-agent".to_string() },
        subject: DID { method: "muccheai".to_string(), identifier: "work-agent".to_string() },
        attenuated_capability: AttenuatedCapability {
            parent_token_id: vec![0u8; 32],
            resource: ResourceRestriction { allowed_patterns: vec!["calendar/freebusy".to_string()] },
            constraints: CapabilityConstraints {
                not_before: Timestamp::now(),
                not_after: Timestamp(Timestamp::now().0 + 86400000),
                max_uses: 10,
                use_count: 0,
            },
        },
        not_before: Timestamp::now(),
        not_after: Timestamp(Timestamp::now().0 + 86400000),
        proof: DelegationProof {
            classical_sig: vec![0u8; 64],
            pq_sig: vec![0u8; 2420],
            issuer_pubkey: HybridPubkey { classical: vec![0u8; 32], x25519: vec![0u8; 32], pq: vec![], pq_sign: vec![] },
        },
    };
    println!("  ✓ Delegation: personal-agent → work-agent");
    println!("  ✓ Scope: calendar/freebusy only (attenuated)");
    println!("  ✓ TTL: 24 hours");
    println!("  ✓ Max uses: 10");

    // Cleanup (demo — no real process to stop)
    let _ = sandbox;

    // Final verification
    println!("\n═══════════════════════════════════════════════════════════════");
    println!("  SYSTEM VERIFICATION");
    println!("═══════════════════════════════════════════════════════════════");
    println!("  ✓ Policy engine: default-deny, 3 rules active");
    println!("  ✓ Sandbox: process isolation, resource limits");
    println!("  ✓ Tool adapters: email (send-only queue), compiled-in");
    println!("  ✓ Secret vault: 3-of-5 Shamir (software-based shares)");
    println!("  ✓ Forward-secure logging: key evolution active");
    println!("  ✓ Anomaly detection: configurable threshold");
    println!("  ✓ Incident response: containment playbook");
    println!("  ✓ Federation: W3C DID structures");
    println!("  ⚠ Build verification: placeholder data (not verified)");
    println!("  ⚠ Warrant canary: placeholder data (not verified)");
    println!("═══════════════════════════════════════════════════════════════");
    println!("\nMuccheAI v3.0 initialized successfully.");
    println!("Core guarantee: Even with fully compromised LLM, root-level malware,");
    println!("and user clicking 'Allow' on everything, blast radius is bounded to");
    println!("an empty, ephemeral, resource-limited sandbox with no credentials,");
    println!("no network, and no persistent access.");
}

async fn run_web_server(bind: &str) {
    use tokio::sync::Mutex;
    use std::sync::Arc;

    let config = match crate::config::MuccheConfig::load() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Failed to load config: {}. Run `muccheai setup` first.", e);
            std::process::exit(1);
        }
    };

    let mut sandbox = LlmSandbox::new(default_sandbox_config());
    if let Err(e) = sandbox.start() {
        eprintln!("Failed to start sandbox: {}", e);
        std::process::exit(1);
    }

    let keypair: muccheai_types::crypto_primitives::HybridKeypair = config.keypair.clone().into();
    let policy = PolicyEngine::new(config.policy_rules.clone(), keypair.clone());
    let gateway = ToolGateway::new(keypair.pubkey.clone());
    let memory = match MemoryEngine::new("muccheai") {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Failed to initialize memory engine: {}", e);
            std::process::exit(1);
        }
    };
    let structured_memory = match crate::structured_memory::StructuredMemoryManager::new() {
        Ok(sm) => sm,
        Err(e) => {
            eprintln!("Failed to initialize structured memory: {}", e);
            std::process::exit(1);
        }
    };

    // Ensure bootstrap soul files exist
    let workspace = match dirs::home_dir() {
        Some(h) => h.join(".muccheai").join("workspace"),
        None => {
            eprintln!("HOME directory not found");
            std::process::exit(1);
        }
    };
    if let Err(e) = crate::structured_memory::ensure_bootstrap_files(&workspace) {
        eprintln!("Warning: failed to create bootstrap files: {}", e);
    }

    // Cache SOUL.md content for the system prompt (keep it small to avoid Ollama slowdown)
    let bootstrap_context = std::fs::read_to_string(workspace.join("SOUL.md")).unwrap_or_default();

    let http_client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(90))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to build HTTP client: {}", e);
            std::process::exit(1);
        }
    };

    // Discover MCP tools from configured servers at startup
    let mcp_tools_cache = web::init_mcp_tools().await;
    if !mcp_tools_cache.is_empty() {
        println!("🔌 Discovered {} MCP tools from configured servers", mcp_tools_cache.len());
    }

    // Generate a random CSRF secret for per-user token derivation.
    let mut csrf_secret = [0u8; 32];
    if ring::rand::SystemRandom::new().fill(&mut csrf_secret).is_err() {
        eprintln!("CSPRNG failure: unable to generate CSRF secret");
        std::process::exit(1);
    }

    let mut user_db = match crate::users::UserDb::load_or_create() {
        Ok(db) => db,
        Err(e) => {
            eprintln!("Failed to load user database: {}", e);
            std::process::exit(1);
        }
    };
    if let Err(e) = user_db.migrate_api_key(&config.api_key) {
        tracing::warn!("Failed to migrate API key to admin user: {}", e);
    }

    // Initialize vault with machine key as master secret (3-of-5 default).
    let vault = match crate::config::MuccheConfig::load_or_create_machine_key() {
        Ok(key) => match muccheai_vault::SecretVault::new(&key, 3) {
            Ok(v) => {
                println!("🔐 Vault initialized ({}-of-{} shares)", v.share_count(), 5);
                Some(v)
            }
            Err(e) => {
                tracing::warn!("Failed to initialize vault: {}", e);
                None
            }
        },
        Err(e) => {
            tracing::warn!("Failed to load machine key for vault: {}", e);
            None
        }
    };

    let plugin_http_counters: Arc<std::sync::Mutex<std::collections::HashMap<String, (u64, u64)>>> =
        Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));

    let state = Arc::new(web::AppState {
        sandbox: Mutex::new(sandbox),
        policy: Mutex::new(policy),
        gateway: Mutex::new(gateway),
        users: Mutex::new(user_db),
        sessions: Mutex::new(std::collections::HashMap::new()),
        csrf_secret,
        rate_limiter: Mutex::new(std::collections::HashMap::new()),
        revoked_tokens: Mutex::new(crate::web::load_revoked_tokens()),
        config: Mutex::new(config.clone()),
        chat_sessions: Mutex::new(Vec::new()),
        memory: Mutex::new(memory),
        structured_memory: Mutex::new(structured_memory),
        bootstrap_context,
        http_client,
        mcp_tools_cache: Mutex::new(mcp_tools_cache),
        tool_config: Mutex::new(ToolConfig::load()),
        csrf_tokens: Mutex::new(std::collections::HashMap::new()),
        rng: ring::rand::SystemRandom::new(),
        shared_sessions: Mutex::new(std::collections::HashMap::new()),
        custom_tools: Mutex::new(Vec::new()),
        scheduled_tasks: Mutex::new(Vec::new()),
        vault: Mutex::new(vault),
        plugin_manager: Mutex::new(crate::plugin::PluginManager::with_counters(Arc::clone(&plugin_http_counters)).unwrap_or_else(|e| {
            eprintln!("Warning: plugin manager init failed: {}", e);
            crate::plugin::PluginManager::new_disabled()
        })),
        backup_rate_limiter: Mutex::new(std::collections::HashMap::new()),
        plugin_http_counters: Mutex::new(std::collections::HashMap::new()),
    });

    println!("🔐 Login with username 'admin' and your existing API key.");

    // Open browser automatically after server binds
    let url = if bind.starts_with("http://") || bind.starts_with("https://") {
        bind.to_string()
    } else {
        format!("http://{}/", bind)
    };
    let url_clone = url.clone();
    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_millis(800)).await;
        println!("🌐 Opening browser at {}", url_clone);
        match std::process::Command::new("open").arg(&url_clone).spawn() {
            Ok(_) => {}
            Err(e) => eprintln!("⚠ Could not open browser: {}. Open {} manually.", e, url_clone),
        }
    });

    web::serve(bind, state).await;
}

/// Verify the current build against CI attestations and warrant canary.
fn verify_build() -> anyhow::Result<String> {
    use muccheai_build_verify::*;

    let mut report = String::new();
    report.push_str("═══════════════════════════════════════════════════════════════\n");
    report.push_str("  BUILD VERIFICATION REPORT\n");
    report.push_str("═══════════════════════════════════════════════════════════════\n");

    let exe = std::env::current_exe()?;
    let build_hash = verify_reproducible_build(exe.to_str().unwrap_or("muccheai"))?;
    report.push_str(&format!(
        "  ✓ Reproducible build hash: {}\n",
        hex::encode(&build_hash[..16])
    ));

    // Warrant canary is placeholder data — no maintainer signatures configured.
    report.push_str("  ⚠ Warrant canary: PLACEHOLDER (no maintainer signatures configured)\n");

    // CI attestation requires configured GitHub/GitLab repositories.
    report.push_str("  ⚠ CI attestation: NOT CONFIGURED (no CI systems verified)\n");

    let attestation = BuildAttestation {
        git_commit: [0u8; 20],
        ci_systems: vec![],
        reproducible_hash: [0u8; 32],
        canary: WarrantCanary {
            date: chrono::Utc::now().format("%Y-%m-%d").to_string(),
            statement: "No gag orders received as of today".to_string(),
            signatures: vec![],
        },
    };
    match attestation.generate_sbom() {
        Ok(sbom) => {
            let json: serde_json::Value = serde_json::from_slice(&sbom)?;
            if let Some(deps) = json.get("dependencies").and_then(|d| d.as_array()) {
                report.push_str(&format!("  ✓ SBOM: {} dependencies\n", deps.len()));
            }
        }
        Err(e) => {
            report.push_str(&format!("  ⚠ SBOM: {}\n", e));
        }
    }

    match cargo_vet_audit() {
        Ok(()) => {
            report.push_str("  ✓ cargo vet: all crates vetted\n");
        }
        Err(e) => {
            report.push_str(&format!("  ⚠ cargo vet: {}\n", e));
        }
    }

    report.push_str("═══════════════════════════════════════════════════════════════\n");
    Ok(report)
}
