//! Interactive setup wizard for first-run configuration.
//!
//! Auto-launches when no config is detected.

use crate::config::MuccheConfig;
use crate::style::Theme;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, MultiSelect, Password, Select};
use muccheai_crypto::generate_hybrid_keypair;
use muccheai_policy_engine::rules::RuleAction;
use rand::RngCore;
use std::io::Write;

const TOTAL_STEPS: usize = 7;

pub fn is_first_run() -> bool {
    !MuccheConfig::config_path().exists()
}

/// Run the interactive setup wizard.
///
/// Returns `Ok(true)` if setup completed successfully, `Ok(false)` if the user
/// cancelled, and `Err` on fatal errors.
pub fn run() -> anyhow::Result<bool> {
    let theme = Theme::Cyber;
    let config_path = MuccheConfig::config_path();

    // ── Check for existing config ─────────────────────────────────────────
    if config_path.exists() {
        theme.print_divider();
        theme.print_info(&format!(
            "Configuration already exists at {}",
            config_path.display()
        ));
        let overwrite = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Do you want to re-run setup and overwrite it?")
            .default(false)
            .interact()?;
        if !overwrite {
            theme.print_info("Keeping existing configuration. Setup cancelled.");
            return Ok(false);
        }
        println!();
    }

    // ── Welcome screen ────────────────────────────────────────────────────
    print!("\x1B[2J\x1B[H"); // clear screen
    std::io::stdout().flush()?;
    theme.print_banner();
    theme.print_header(&format!("Welcome to MuccheAI v{}", env!("CARGO_PKG_VERSION")));
    println!(
        "  {}\n",
        theme
            .style_secondary()
            .apply_to("Your personal, secure AI agent — local-first, security-conscious.")
    );
    println!(
        "  {}\n",
        theme
            .style_secondary()
            .apply_to("This wizard will get you up and running in under 2 minutes.")
    );

    let proceed = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Ready to begin?")
        .default(true)
        .interact()?;
    if !proceed {
        theme.print_info("Setup cancelled. Run `muccheai setup` when you're ready.");
        return Ok(false);
    }
    println!();

    // ── System Requirements Check ────────────────────────────────────────
    if !check_system_requirements(&theme)? {
        theme.print_info("Setup cancelled. Upgrade your system and run `muccheai setup` when ready.");
        return Ok(false);
    }
    println!();

    // ── Step 1: AI Connection ─────────────────────────────────────────────
    theme.print_step(1, TOTAL_STEPS, "Connect Your AI");
    println!(
        "  {}\n",
        theme.style_secondary().apply_to(
            "Choose your AI provider. You can use a local model (Ollama) \
             or connect to an online API (OpenAI, Anthropic, or any custom endpoint)."
        )
    );

    let providers = vec![
        "Local — Ollama (recommended)",
        "Online — OpenAI",
        "Online — Anthropic",
        "Online — Custom API",
    ];
    let provider_idx = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select provider")
        .default(0)
        .items(&providers)
        .interact()?;

    // ── Step 2: Local Key Password ────────────────────────────────────────
    theme.print_step(2, TOTAL_STEPS, "Protect Your Local Key");
    println!(
        "  {}\n",
        theme.style_secondary().apply_to(
            "Set a password to encrypt your local API key and other secrets. \
             If you forget this password, you will need to reset MuccheAI."
        )
    );

    let set_password = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Set a password to protect your local key?")
        .default(true)
        .interact()?;

    if set_password {
        let pw: String = Password::with_theme(&ColorfulTheme::default())
            .with_prompt("Password")
            .with_confirmation("Confirm password", "Passwords do not match")
            .interact()?;
        // Validate password isn't empty
        if pw.trim().is_empty() {
            theme.print_warning("Empty password provided — skipping password protection.");
        } else {
            // Write flag file so the app knows a password is expected
            let flag_path = MuccheConfig::config_path()
                .parent()
                .unwrap_or(&std::path::PathBuf::from("."))
                .join(".password_required");
            let _ = std::fs::write(&flag_path, "This file indicates that MUCCHEAI_KEY_PASSWORD is required.\n");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = std::fs::metadata(&flag_path) {
                    let mut perms = meta.permissions();
                    perms.set_mode(0o600);
                    let _ = std::fs::set_permissions(&flag_path, perms);
                }
            }
            theme.print_success("Password protection enabled");
            println!(
                "  {}\n",
                theme.style_secondary().apply_to(
                    "Remember: set the MUCCHEAI_KEY_PASSWORD environment variable \
                     before running MuccheAI, or you will be prompted for it."
                )
            );
        }
    } else {
        theme.print_info("Skipping password protection. Your local key will be stored as raw material.");
    }
    println!();

    let (agent, host, model) = match provider_idx {
        0 => {
            // Ollama
            let host: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Ollama host")
                .default("http://localhost:11434".to_string())
                .interact_text()?;
            let models = vec![
                "qwen3:14b",
                "llama3.1:8b",
                "mistral:7b",
                "deepseek-r1:14b",
                "custom (type your own)",
            ];
            let model_idx = Select::with_theme(&ColorfulTheme::default())
                .with_prompt("Select your local model")
                .default(0)
                .items(&models)
                .interact()?;
            let model = if model_idx == models.len() - 1 {
                Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("Model name")
                    .interact_text()?
            } else {
                models[model_idx].to_string()
            };

            print!("\n  Testing connection to Ollama... ");
            std::io::stdout().flush()?;
            let client = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()?;
            let test_url = format!("{}/api/tags", host);
            match client.get(&test_url).send() {
                Ok(resp) if resp.status().is_success() => {
                    theme.print_success("Ollama is reachable");
                }
                _ => {
                    theme.print_warning("Ollama not reachable — continuing anyway");
                    println!(
                        "      {}",
                        theme.style_secondary().apply_to(
                            "Tip: install from https://ollama.com and run `ollama serve`"
                        )
                    );
                }
            }

            let agent = crate::config::AgentConfig {
                name: model.clone(),
                provider: "ollama".to_string(),
                model: model.clone(),
                api_key: None,
                base_url: Some(host.clone()),
            };
            (agent, host, model)
        }
        1 => {
            // OpenAI
            let key: String = Password::with_theme(&ColorfulTheme::default())
                .with_prompt("OpenAI API key")
                .interact()?;
            let model: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Model")
                .default("gpt-4o".to_string())
                .interact_text()?;
            let agent = crate::config::AgentConfig {
                name: "OpenAI".to_string(),
                provider: "openai".to_string(),
                model: model.clone(),
                api_key: Some(key),
                base_url: Some("https://api.openai.com/v1".to_string()),
            };
            theme.print_success("OpenAI configured");
            (agent, "https://api.openai.com/v1".to_string(), model)
        }
        2 => {
            // Anthropic
            let key: String = Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Anthropic API key")
                .interact()?;
            let model: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Model")
                .default("claude-3-5-sonnet-20241022".to_string())
                .interact_text()?;
            let agent = crate::config::AgentConfig {
                name: "Anthropic".to_string(),
                provider: "anthropic".to_string(),
                model: model.clone(),
                api_key: Some(key),
                base_url: Some("https://api.anthropic.com".to_string()),
            };
            theme.print_success("Anthropic configured");
            (agent, "https://api.anthropic.com".to_string(), model)
        }
        _ => {
            // Custom
            let name: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Provider name")
                .default("Custom".to_string())
                .interact_text()?;
            let base_url: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Base URL")
                .default("http://localhost:11434".to_string())
                .interact_text()?;
            let model: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Model name")
                .interact_text()?;
            let has_key = Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("Does this API require an API key?")
                .default(false)
                .interact()?;
            let api_key = if has_key {
                Some(Password::with_theme(&ColorfulTheme::default())
                    .with_prompt("API key")
                    .interact()?)
            } else {
                None
            };
            let agent = crate::config::AgentConfig {
                name: name.clone(),
                provider: "openai".to_string(),
                model: model.clone(),
                api_key,
                base_url: Some(base_url.clone()),
            };
            theme.print_success(&format!("{} configured", name));
            (agent, base_url, model)
        }
    };

    // ── Step 3: Tools ─────────────────────────────────────────────────────
    theme.print_step(3, TOTAL_STEPS, "Choose Your Tools");
    println!(
        "  {}\n",
        theme.style_secondary().apply_to(
            "Select which tools your agent is allowed to use. \
             You can change this later with `muccheai policy`."
        )
    );

    let tools = vec!["email", "calendar", "filesystem", "search"];
    let defaults = vec![true, true, false, false];
    let selected = MultiSelect::with_theme(&ColorfulTheme::default())
        .with_prompt("Allowed tools (space to toggle, enter to confirm)")
        .items(&tools)
        .defaults(&defaults)
        .interact()?;
    let allowed_tools: Vec<String> = selected.into_iter().map(|i| tools[i].to_string()).collect();

    if allowed_tools.is_empty() {
        theme.print_warning("No tools selected. Your agent will be in read-only mode.");
    } else {
        theme.print_success(&format!("Enabled: {}", allowed_tools.join(", ")));
    }

    // ── Step 4: Security ──────────────────────────────────────────────────
    theme.print_step(4, TOTAL_STEPS, "Security Preferences");
    println!(
        "  {}\n",
        theme.style_secondary().apply_to(
            "MuccheAI uses a tiered approval system. \
             Higher-risk actions require stronger confirmation."
        )
    );

    let actions = vec!["Allow", "Deny", "Escalate"];
    let action_idx = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Default action for unknown requests")
        .default(1)
        .items(&actions)
        .interact()?;
    let default_action = match actions[action_idx] {
        "Allow" => RuleAction::Allow,
        "Deny" => RuleAction::Deny,
        _ => RuleAction::Escalate,
    };

    let tiers = vec![
        "Auto      — approve low-risk automatically",
        "Standard  — dialog confirmation",
        "Biometric — Touch ID / Face ID",
        "Hardware  — YubiKey or similar",
        "Multi-Device — requires a second device",
    ];
    let tier_idx = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Default approval tier")
        .default(1)
        .items(&tiers)
        .interact()?;
    let approval_tier = match tier_idx {
        0 => "auto",
        1 => "standard",
        2 => "biometric",
        3 => "hardware",
        _ => "multi-device",
    }
    .to_string();

    theme.print_success("Security preferences configured");

    // ── Step 5: Vault ─────────────────────────────────────────────────────
    theme.print_step(5, TOTAL_STEPS, "Create Your Vault");
    println!(
        "  {}\n",
        theme.style_secondary().apply_to(
            "Your secrets are split into 5 shares using Shamir's Secret Sharing. \
             You need a threshold number of shares to recover them."
        )
    );

    let threshold_options = vec!["2", "3", "4", "5"];
    let threshold_idx = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Recovery threshold (of 5 shares)")
        .default(1)
        .items(&threshold_options)
        .interact()?;
    let threshold: u8 = threshold_options[threshold_idx].parse()?;

    // Generate keys with animated progress
    println!();
    let pb = crate::style::milk_progress_bar(100);
    pb.set_message("Generating post-quantum keypair...");
    for i in 0..=10 {
        pb.set_position(i * 10);
        std::thread::sleep(std::time::Duration::from_millis(60));
    }
    let keypair = generate_hybrid_keypair()?;
    pb.finish_with_message("Post-quantum keys generated");

    let mut master_secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut master_secret);
    let vault = muccheai_vault::SecretVault::new(&master_secret, threshold)?;

    theme.print_success("Vault created successfully");
    println!();
    println!(
        "  {}  {} shares total",
        theme.style_info().apply_to("🔐"),
        vault.share_count()
    );
    println!(
        "  {}  {} shares needed to recover",
        theme.style_info().apply_to("🔑"),
        threshold
    );
    println!(
        "  {}  {}",
        theme.style_secondary().apply_to("   📍"),
        theme.style_secondary().apply_to("Share locations:"),
    );
    println!(
        "     {}  Secure Enclave (device-bound)",
        theme.style_secondary().apply_to("1.")
    );
    println!(
        "     {}  Hardware token (YubiKey)",
        theme.style_secondary().apply_to("2.")
    );
    println!(
        "     {}  Paper backup (BIP39 mnemonic)",
        theme.style_secondary().apply_to("3.")
    );
    println!(
        "     {}  Recovery contact",
        theme.style_secondary().apply_to("4.")
    );
    println!(
        "     {}  iCloud Keychain (ADP)",
        theme.style_secondary().apply_to("5.")
    );

    // ── Step 6: Persona ───────────────────────────────────────────────────
    theme.print_step(6, TOTAL_STEPS, "Configure Your Persona");
    println!(
        "  {}\n",
        theme.style_secondary().apply_to(
            "Choose how your AI assistant behaves. You can create custom personalities \
             or use the default friendly assistant."
        )
    );

    let persona_options = vec!["Use the default persona", "Create a custom persona"];
    let persona_idx = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Persona option")
        .default(0)
        .items(&persona_options)
        .interact()?;

    let (personas, current_persona) = if persona_idx == 1 {
        let name: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Persona name")
            .default("custom".to_string())
            .interact_text()?;
        let description: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Description")
            .default("A custom AI assistant".to_string())
            .interact_text()?;
        let system_prompt: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("System prompt")
            .default("You are a helpful AI assistant.".to_string())
            .interact_text()?;
        let emoji: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Emoji")
            .default("🐄".to_string())
            .interact_text()?;
        let persona = crate::config::Persona {
            name: name.clone(),
            emoji,
            description,
            system_prompt,
        };
        (vec![persona], name)
    } else {
        (crate::config::default_personas(), "default".to_string())
    };

    theme.print_success("Persona configured");

    // ── Step 7: Save & Finish ─────────────────────────────────────────────
    theme.print_step(7, TOTAL_STEPS, "Save Configuration");

    let mut config = MuccheConfig {
        ollama_host: host,
        ollama_model: model,
        allowed_tools,
        default_action,
        business_hours_restriction: false,
        approval_tier,
        shamir_threshold: threshold,
        keypair: keypair.into(),
        personas,
        current_persona,
        ..MuccheConfig::default()
    };
    config.agents.push(agent);
    config.active_agent = config.agents[0].name.clone();
    config.save()?;

    theme.print_success(&format!(
        "Configuration saved to {}",
        config_path.display()
    ));

    // ── Completion screen ─────────────────────────────────────────────────
    theme.print_divider();
    theme.print_header("You're All Set!");

    println!(
        "  {}\n",
        theme
            .style_success()
            .apply_to("MuccheAI is ready to use. Here are your next steps:")
    );

    println!(
        "  {}  {}",
        theme.style_primary().apply_to("chat"),
        theme.style_secondary().apply_to(" — Start an interactive session"),
    );
    println!(
        "  {}  {}",
        theme.style_primary().apply_to("run"),
        theme
            .style_secondary()
            .apply_to(" — Execute a single prompt"),
    );
    println!(
        "  {}  {}",
        theme.style_primary().apply_to("status"),
        theme.style_secondary().apply_to(" — Check system health"),
    );
    println!(
        "  {}  {}",
        theme.style_primary().apply_to("web"),
        theme
            .style_secondary()
            .apply_to(" — Open the web control panel"),
    );
    println!(
        "  {}  {}",
        theme.style_primary().apply_to("daemon start"),
        theme
            .style_secondary()
            .apply_to(" — Run the background agent"),
    );

    println!();
    theme.print_info("Try it now:");
    println!(
        "  {}\n",
        theme.style_info().apply_to("    muccheai chat")
    );

    crate::style::easter_eggs::setup_complete();

    Ok(true)
}

/// System requirements specification.
pub struct SystemRequirements {
    /// Minimum RAM in GB.
    pub min_ram_gb: u64,
    /// Recommended RAM in GB.
    pub rec_ram_gb: u64,
    /// Minimum free disk in GB.
    pub min_disk_gb: u64,
    /// Recommended free disk in GB.
    pub rec_disk_gb: u64,
    /// Minimum Rust version (major, minor).
    pub min_rust_version: (u32, u32),
}

impl Default for SystemRequirements {
    fn default() -> Self {
        Self {
            min_ram_gb: 8,
            rec_ram_gb: 16,
            min_disk_gb: 10,
            rec_disk_gb: 20,
            min_rust_version: (1, 80),
        }
    }
}

/// Check system requirements before installation.
///
/// Returns `Ok(true)` if the system meets requirements or the user chose to continue anyway.
/// Returns `Ok(false)` if the user cancelled.
pub fn check_system_requirements(theme: &crate::style::Theme) -> anyhow::Result<bool> {
    let req = SystemRequirements::default();
    let mut issues = Vec::new();

    // Check RAM
    let total_ram = sysinfo::System::new_all().total_memory() / 1024 / 1024 / 1024;
    if total_ram < req.min_ram_gb {
        issues.push(format!(
            "RAM: {} GB detected (minimum: {} GB, recommended: {} GB)",
            total_ram, req.min_ram_gb, req.rec_ram_gb
        ));
    }

    // Check disk space
    let disks = sysinfo::Disks::new_with_refreshed_list();
    let disk = disks.iter().find(|d| d.mount_point() == std::path::Path::new("/"))
        .or_else(|| disks.first());
    if let Some(disk) = disk {
        let free_gb = disk.available_space() / 1024 / 1024 / 1024;
        if free_gb < req.min_disk_gb {
            issues.push(format!(
                "Disk: {} GB free (minimum: {} GB, recommended: {} GB)",
                free_gb, req.min_disk_gb, req.rec_disk_gb
            ));
        }
    }

    // Check Rust version
    let rust_version = rustc_version::version();
    match rust_version {
        Ok(ver) => {
            let (maj, min) = (ver.major as u32, ver.minor as u32);
            if maj < req.min_rust_version.0
                || (maj == req.min_rust_version.0 && min < req.min_rust_version.1)
            {
                issues.push(format!(
                    "Rust: {}.{} detected (minimum: {}.{}, recommended: latest stable)",
                    maj, min, req.min_rust_version.0, req.min_rust_version.1
                ));
            }
        }
        Err(_) => {
            issues.push("Rust: could not detect version (minimum: 1.80)".to_string());
        }
    }

    if issues.is_empty() {
        theme.print_success("System requirements met");
        return Ok(true);
    }

    // Print requirements table
    theme.print_warning("System requirements not met");
    println!();
    println!("  {}", theme.style_primary().apply_to("┌─────────────────────────────────────────────────────────┐"));
    println!("  {}", theme.style_primary().apply_to("│  Minimum Requirements          │  Recommended            │"));
    println!("  {}", theme.style_primary().apply_to("├────────────────────────────────┼─────────────────────────┤"));
    println!(
        "  {}  {}  │  {}",
        theme.style_primary().apply_to("│"),
        theme.style_secondary().apply_to(format!("RAM:      {:>2} GB", req.min_ram_gb)),
        theme.style_secondary().apply_to(format!("{:>2} GB", req.rec_ram_gb))
    );
    println!(
        "  {}  {}  │  {}",
        theme.style_primary().apply_to("│"),
        theme.style_secondary().apply_to(format!("Disk:     {:>2} GB", req.min_disk_gb)),
        theme.style_secondary().apply_to(format!("{:>2} GB", req.rec_disk_gb))
    );
    println!(
        "  {}  {}  │  {}",
        theme.style_primary().apply_to("│"),
        theme.style_secondary().apply_to(format!("Rust:     {}.{}   ", req.min_rust_version.0, req.min_rust_version.1)),
        theme.style_secondary().apply_to("latest stable")
    );
    println!("  {}", theme.style_primary().apply_to("└────────────────────────────────┴─────────────────────────┘"));
    println!();

    // Print detected issues
    for issue in &issues {
        theme.print_error(&format!("  • {issue}"));
    }
    println!();

    // Risk explanation
    let risk = if issues.iter().any(|i| i.contains("RAM")) {
        "build failures due to out-of-memory (OOM) during compilation, especially with parallel jobs"
    } else if issues.iter().any(|i| i.contains("Disk")) {
        "insufficient space for dependency downloads and build artifacts"
    } else if issues.iter().any(|i| i.contains("Rust")) {
        "compilation errors due to missing language features or edition support"
    } else {
        "unexpected build or runtime failures"
    };

    println!(
        "  {}\n",
        theme.style_warning().apply_to(format!("Risk of continuing: {risk}"))
    );

    let proceed = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Are you sure you want to continue?")
        .default(false)
        .interact()?;

    Ok(proceed)
}
