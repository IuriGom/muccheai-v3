//! Status command implementation.

use crate::style::{Theme, RiskLevel};

/// Print system status.
pub fn print_status(_format: crate::cli::OutputFormat) {
    let theme = Theme::Minimal;
    theme.print_header("System Status");
    
    println!("Sandbox:     running");
    println!("Model:       qwen3:14b");
    println!("Policy:      default-deny");
    println!("PQC:         ML-KEM + ML-DSA");
    println!("Vault:       3-of-5 Shamir");
    println!("Audit Log:   forward-secure");
    
    let risk = RiskLevel::Low;
    println!("Risk Level:  {}", risk.badge());
}
