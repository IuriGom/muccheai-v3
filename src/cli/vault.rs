//! Vault operations command implementation.

/// Show vault status.
pub fn vault_status() {
    println!("Vault status:");
    println!("  State: sealed");
    println!("  Shamir: 3-of-5");
    println!("  Key shares: 0/5 loaded");
}

/// Rotate vault keys.
///
/// ⚠ NOT YET IMPLEMENTED. This is a placeholder for future Shamir re-sharing.
/// Calling this function will return an error.
pub fn vault_rotate() -> anyhow::Result<()> {
    anyhow::bail!(
        "Vault key rotation is not yet implemented. Create a new vault and migrate secrets manually."
    )
}

/// Recover vault from shares.
///
/// ⚠ NOT YET IMPLEMENTED. This is a placeholder for future Shamir recovery.
pub fn vault_recover(_shares: Vec<ShareInput>) -> anyhow::Result<()> {
    anyhow::bail!(
        "Vault recovery from shares is not yet implemented."
    )
}

/// A single share input for recovery.
pub struct ShareInput {
    /// Share index.
    pub index: u8,
    /// Share value.
    pub value: String,
}
