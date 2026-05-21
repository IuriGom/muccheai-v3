//! One-shot execution for MuccheAI.

use crate::cli::{build_policy_engine, init_sandbox, process_prompt, register_adapters};
use crate::config::MuccheConfig;
use muccheai_tool_gateway::ToolGateway;
use muccheai_ui::TrustedUi;

/// Run a single prompt through the full pipeline and exit.
///
/// If `prompt` is `"-"`, reads the prompt from stdin.
pub fn run(prompt: &str, config: &MuccheConfig) -> anyhow::Result<()> {
    let prompt_text = if prompt == "-" {
        let mut buf = String::new();
        let stdin = std::io::stdin();
        while let Ok(n) = stdin.read_line(&mut buf) {
            if n == 0 {
                break;
            }
        }
        buf.trim_end().to_string()
    } else {
        prompt.to_string()
    };

    let mut sandbox = init_sandbox(config)?;
    let mut policy_engine = build_policy_engine(config);
    let keypair: muccheai_types::crypto_primitives::HybridKeypair = config.keypair.clone().into();
    let mut gateway = ToolGateway::new(keypair.pubkey.clone());
    register_adapters(&mut gateway, &config.allowed_tools);
    let mut trusted_ui = TrustedUi::new();

    process_prompt(
        &prompt_text,
        &sandbox,
        &mut policy_engine,
        &mut trusted_ui,
        &gateway,
        config,
        &keypair,
    )?;

    sandbox.stop()?;
    Ok(())
}
