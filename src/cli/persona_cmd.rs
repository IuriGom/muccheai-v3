//! Persona management commands for MuccheAI.

use crate::config::MuccheConfig;

/// Run persona subcommand.
pub async fn run(action: super::PersonaCommands) -> anyhow::Result<()> {
    let mut config = MuccheConfig::load()?;

    match action {
        super::PersonaCommands::List => {
            if config.personas.is_empty() {
                println!("No personas configured.");
            } else {
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
        super::PersonaCommands::Set { name } => {
            if !config.personas.iter().any(|p| p.name == name) {
                anyhow::bail!("Persona '{}' not found.", name);
            }
            config.current_persona = name.clone();
            config.save()?;
            println!("✓ Switched to persona '{name}'");
        }
        super::PersonaCommands::Current => {
            let name = if config.current_persona.is_empty() {
                "default".to_string()
            } else {
                config.current_persona.clone()
            };
            if let Some(p) = config.personas.iter().find(|p| p.name == name) {
                println!("Current persona: {} — {}", p.name, p.description);
            } else {
                println!("Current persona: {name}");
            }
        }
    }

    Ok(())
}
