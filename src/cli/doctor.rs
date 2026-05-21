//! System health check for MuccheAI.

use crate::config::MuccheConfig;

/// Run system health checks.
pub async fn run() -> anyhow::Result<()> {
    println!("🔬 MuccheAI Doctor");
    println!();

    let mut healthy = true;

    // Config
    print!("  Configuration... ");
    let config = match MuccheConfig::load() {
        Ok(c) => {
            println!("✓ loaded");
            c
        }
        Err(e) => {
            println!("✗ {e}");
            healthy = false;
            MuccheConfig::default()
        }
    };

    // Ollama
    print!("  Ollama... ");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;
    match client
        .get(format!("{}/api/tags", config.ollama_host))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            println!("✓ reachable at {}", config.ollama_host);
        }
        Ok(resp) => {
            println!("✗ HTTP {}", resp.status());
            healthy = false;
        }
        Err(e) => {
            println!("✗ {e}");
            healthy = false;
        }
    }

    // Sandbox
    print!("  Sandbox... ");
    let mut sandbox = muccheai_sandbox::LlmSandbox::new(muccheai_sandbox::default_sandbox_config());
    match sandbox.start() {
        Ok(_) => {
            println!("✓ started");
            let _ = sandbox.stop();
        }
        Err(e) => {
            println!("✗ {e}");
            healthy = false;
        }
    }

    // PQC
    print!("  Post-Quantum Crypto... ");
    match muccheai_crypto::generate_hybrid_keypair() {
        Ok(_) => println!("✓ key generation works"),
        Err(e) => {
            println!("✗ {e}");
            healthy = false;
        }
    }

    // Policy Engine
    print!("  Policy Engine... ");
    let keypair: muccheai_types::crypto_primitives::HybridKeypair = config.keypair.clone().into();
    let _policy = muccheai_policy_engine::PolicyEngine::new(config.policy_rules.clone(), keypair);
    println!("✓ loaded");

    println!();
    if healthy {
        println!("✓ All systems healthy");
    } else {
        println!("⚠ Some checks failed");
        std::process::exit(1);
    }
    Ok(())
}
