//! Automated containment procedures

use muccheai_sandbox::LlmSandbox;
use muccheai_types::audit::*;
use sha3::Digest;

/// Errors during containment operations
#[derive(Debug, Clone, thiserror::Error)]
pub enum ContainmentError {
    /// Firewall command failed
    #[error("Firewall command failed: {0}")]
    FirewallError(String),
    /// Sandbox termination failed
    #[error("Sandbox termination failed: {0}")]
    TerminationError(String),
    /// Audit log sealing failed
    #[error("Audit log sealing failed: {0}")]
    SealError(String),
    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Network containment using platform firewall.
pub fn block_all_egress() -> std::result::Result<(), ContainmentError> {
    #[cfg(target_os = "macos")]
    {
        let anchor_rules = "block drop out all\n";
        let home = dirs::home_dir().unwrap_or_else(|| std::env::temp_dir());
        let anchor_dir = home.join(".muccheai");
        let _ = std::fs::create_dir_all(&anchor_dir);
        let anchor_path = anchor_dir.join("block_anchor.conf");
        std::fs::write(&anchor_path, anchor_rules)
            .map_err(|_e| ContainmentError::FirewallError("Failed to write anchor".to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&anchor_path, std::fs::Permissions::from_mode(0o600));
        }
        // Load the anchor into pf
        let output = std::process::Command::new("pfctl")
            .args(["-a", "muccheai_block", "-f", anchor_path.to_str().unwrap_or("/dev/null")])
            .output()
            .map_err(|_e| ContainmentError::FirewallError("Firewall command failed".to_string()))?;
        if !output.status.success() {
            return Err(ContainmentError::FirewallError("Firewall rule load failed".to_string()));
        }
        // Enable pf if not already enabled
        let _ = std::process::Command::new("pfctl")
            .arg("-e")
            .output();
    }
    #[cfg(target_os = "linux")]
    {
        // Drop all outgoing traffic via iptables
        let output = std::process::Command::new("iptables")
            .args(["-P", "OUTPUT", "DROP"])
            .output()
            .map_err(|_e| ContainmentError::FirewallError("Firewall command failed".to_string()))?;
        if !output.status.success() {
            return Err(ContainmentError::FirewallError("Firewall rule load failed".to_string()));
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        return Err(ContainmentError::FirewallError(
            "Unsupported platform for egress blocking".to_string()
        ));
    }
    Ok(())
}

/// Sandbox termination
pub fn terminate_sandbox(sandbox: &mut LlmSandbox) -> std::result::Result<(), ContainmentError> {
    sandbox
        .stop()
        .map_err(|e| ContainmentError::TerminationError(e.to_string()))
}

/// Seal audit log with final Merkle root and signature.
/// Destroys the current signing key to prevent further appends.
pub fn seal_audit_log(logger: &mut crate::ForwardSecureLogger) -> std::result::Result<LogEntry, ContainmentError> {
    let entries = logger.entries();
    if entries.is_empty() {
        return Err(ContainmentError::SealError("No entries to seal".to_string()));
    }

    // Compute Merkle root by hashing all entry signatures sequentially
    let mut hasher = sha3::Sha3_512::new();
    for entry in entries {
        hasher.update(&entry.signature);
    }
    let merkle_root = hasher.finalize();
    logger.set_merkle_root(merkle_root.to_vec());

    // Seal the log: append seal event and destroy signing key
    let entry = logger
        .seal()
        .map_err(|e| ContainmentError::SealError(e.to_string()))?;

    Ok(entry)
}
