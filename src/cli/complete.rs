//! Shell completion generation.

use clap::CommandFactory;
use clap_complete::Shell;
use clap_complete::generate;

/// Generate shell completion scripts.
pub fn generate_completions(shell: Shell) {
    let mut cmd = super::Cli::command();
    generate(shell, &mut cmd, "muccheai", &mut std::io::stdout());
}
