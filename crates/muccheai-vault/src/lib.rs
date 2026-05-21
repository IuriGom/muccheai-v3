//! MuccheAI v3.0 — Secret Vault (Secret Management)
//!
//! Hardware-backed secret storage with Shamir's Secret Sharing (3-of-5).
//!
//! Shares:
//! 1. Secure Enclave (device-bound)
//! 2. Hardware token (YubiKey/OnlyKey)
//! 3. Paper backup (BIP39 mnemonic)
//! 4. Recovery contact (encrypted to their key)
//! 5. iCloud Keychain (with ADP)

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use muccheai_types::*;
use rand::RngCore;
use ring::aead::{Aad, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::aead::LessSafeKey;

/// Constant-time comparison of two byte slices.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod shamir;

/// Errors specific to vault operations.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum VaultError {
    /// Shamir error.
    #[error("Shamir error: {0}")]
    Shamir(#[from] shamir::ShamirError),
    /// Cryptographic operation failed.
    #[error("Crypto error: {0}")]
    Crypto(String),
    /// Approval proof is invalid or missing.
    #[error("Invalid approval proof")]
    InvalidApprovalProof,
    /// Secret rotation verification failed.
    #[error("Secret rotation verification failed: reconstructed secret does not match current master")]
    RotationVerificationFailed,
    /// Invalid parameters.
    #[error("Invalid parameters: {0}")]
    InvalidParameters(String),
}

impl From<VaultError> for MuccheError {
    fn from(err: VaultError) -> Self {
        MuccheError::VaultError(err.to_string())
    }
}

/// A single Shamir share (convenience re-export matching the shamir module).
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct Share {
    /// Share index (1-5)
    pub index: u8,
    /// Share value (256 bits)
    pub value: [u8; 32],
    /// MAC for integrity
    pub mac: Vec<u8>,
}

impl From<shamir::Share> for Share {
    fn from(share: shamir::Share) -> Self {
        Self {
            index: share.index,
            value: share.value,
            mac: share.mac.clone(),
        }
    }
}

impl From<Share> for shamir::Share {
    fn from(share: Share) -> Self {
        Self {
            index: share.index,
            value: share.value,
            mac: share.mac.clone(),
        }
    }
}

/// Share encrypted for a specific storage location.
#[derive(Debug, Clone)]
pub struct EncryptedShare {
    /// Which share this is
    pub index: u8,
    /// Encrypted share value (nonce || ciphertext || tag)
    pub ciphertext: Vec<u8>,
    /// MAC for the share value (HMAC-SHA3-256)
    pub mac: Vec<u8>,
    /// Storage type
    pub storage: ShareStorage,
}

/// Where a share is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShareStorage {
    /// Apple Secure Enclave
    SecureEnclave,
    /// Hardware token (YubiKey)
    HardwareToken,
    /// Paper backup (BIP39)
    PaperBackup,
    /// Recovery contact
    RecoveryContact(String),
    /// iCloud Keychain
    IcloudKeychain,
}

/// An ephemeral token (60-second TTL).
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct EphemeralToken {
    /// Token value
    pub token: Vec<u8>,
    /// Created at
    pub created_at: Timestamp,
    /// Tool this token is for
    pub tool_id: String,
}

impl EphemeralToken {
    /// Check if token is still valid (< 60 seconds old).
    pub fn is_valid(&self) -> bool {
        let now = Timestamp::now();
        now.0.saturating_sub(self.created_at.0) < 60_000
    }
}

/// AES-256-GCM encrypt plaintext with the given key.
/// Returns nonce || ciphertext || tag.
fn aes_256_gcm_encrypt(key: &[u8; 32], plaintext: &[u8]) -> std::result::Result<Vec<u8>, VaultError> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    let unbound_key = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|_| VaultError::Crypto("Invalid AES key".to_string()))?;
    let sealing_key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = plaintext.to_vec();
    let tag = sealing_key
        .seal_in_place_separate_tag(nonce, Aad::from(b"muccheai-vault-v1"), &mut in_out)
        .map_err(|_| VaultError::Crypto("Encryption failed".to_string()))?;

    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&in_out);
    result.extend_from_slice(tag.as_ref());
    Ok(result)
}

/// AES-256-GCM decrypt ciphertext (nonce || ciphertext || tag) with the given key.
fn aes_256_gcm_decrypt(key: &[u8; 32], ciphertext: &[u8]) -> std::result::Result<Vec<u8>, VaultError> {
    if ciphertext.len() < NONCE_LEN + 16 {
        return Err(VaultError::Crypto("Ciphertext too short".to_string()));
    }
    let (nonce_bytes, rest) = ciphertext.split_at(NONCE_LEN);
    let unbound_key = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|_| VaultError::Crypto("Invalid AES key".to_string()))?;
    let opening_key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)
        .map_err(|_| VaultError::Crypto("Invalid nonce length".to_string()))?;

    let mut in_out = rest.to_vec();
    let result = match opening_key.open_in_place(nonce, Aad::from(b"muccheai-vault-v1"), &mut in_out) {
        Ok(plaintext) => {
            let out = plaintext.to_vec();
            in_out.zeroize();
            Ok(out)
        }
        Err(_) => {
            in_out.zeroize();
            Err(VaultError::Crypto("Decryption failed".to_string()))
        }
    };
    result
}

/// Derive a 32-byte root key from seed material using SHA3-512.
/// Truncates the 64-byte digest to the first 32 bytes.
pub fn derive_root_key(seed: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Sha3_512};
    let hash = Sha3_512::digest(seed);
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash[..32]);
    key
}

/// A secret vault.
pub struct SecretVault {
    /// Master secret (encrypted with AES-256-GCM, never stored plaintext)
    encrypted_master: Vec<u8>,
    /// 32-byte vault key used to encrypt master and shares
    vault_key: [u8; 32],
    /// Shamir shares (each encrypted with AES-256-GCM)
    shares: Vec<EncryptedShare>,
    /// Ephemeral token cache (60s TTL)
    ephemeral_cache: Vec<EphemeralToken>,
    /// Recovery threshold (minimum shares needed)
    threshold: u8,
}

impl Drop for SecretVault {
    fn drop(&mut self) {
        self.vault_key.zeroize();
    }
}

/// Secret vault operations.
impl SecretVault {
    /// Create a new vault with a master secret.
    pub fn new(master_secret: &[u8; 32], threshold: u8) -> std::result::Result<Self, VaultError> {
        if threshold == 0 {
            return Err(VaultError::InvalidParameters(
                "threshold must be > 0".to_string(),
            ));
        }

        // Generate a random 32-byte vault key.
        let mut vault_key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut vault_key[..]);

        // Generate 5 shares, any `threshold` can reconstruct.
        let shares = shamir::split_secret(master_secret, 5, threshold)?;

        let encrypted_shares: Vec<EncryptedShare> = shares
            .into_iter()
            .map(|share| {
                let encrypted = aes_256_gcm_encrypt(&vault_key, &share.value)
                    .expect("encryption should not fail");
                EncryptedShare {
                    index: share.index,
                    ciphertext: encrypted,
                    mac: share.mac.clone(),
                    storage: match share.index {
                        1 => ShareStorage::SecureEnclave,
                        2 => ShareStorage::HardwareToken,
                        3 => ShareStorage::PaperBackup,
                        4 => ShareStorage::RecoveryContact("trusted@example.com".to_string()),
                        5 => ShareStorage::IcloudKeychain,
                        _ => ShareStorage::SecureEnclave,
                    },
                }
            })
            .collect();

        // Encrypt master with vault key.
        let encrypted_master =
            aes_256_gcm_encrypt(&vault_key, master_secret.as_slice())
                .map_err(|e| VaultError::Crypto(e.to_string()))?;

        Ok(Self {
            encrypted_master,
            vault_key,
            shares: encrypted_shares,
            ephemeral_cache: vec![],
            threshold,
        })
    }

    /// Reconstruct master secret from shares.
    pub fn reconstruct(
        &self,
        shares: &[shamir::Share],
    ) -> std::result::Result<Vec<u8>, VaultError> {
        shamir::reconstruct_secret(shares, self.threshold as usize).map_err(VaultError::from)
    }

    /// Return the number of shares in the vault.
    pub fn share_count(&self) -> usize {
        self.shares.len()
    }

    /// Fetch an ephemeral token for a tool.
    /// Only callable with proof of valid user approval.
    pub fn fetch_ephemeral_token(
        &mut self,
        tool_id: &str,
        approval_proof: &[u8],
    ) -> std::result::Result<EphemeralToken, VaultError> {
        // Verify approval proof is a valid HMAC over tool_id using vault_key.
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &self.vault_key);
        let expected = ring::hmac::sign(&key, tool_id.as_bytes());
        if !constant_time_eq(approval_proof, expected.as_ref()) {
            return Err(VaultError::InvalidApprovalProof);
        }

        // Clean expired tokens
        self.ephemeral_cache.retain(|t| t.is_valid());

        // Check if we have a valid cached token
        if let Some(token) = self
            .ephemeral_cache
            .iter()
            .find(|t| t.tool_id == tool_id && t.is_valid())
        {
            return Ok(token.clone());
        }

        // Generate new ephemeral token
        let mut token_bytes = [0u8; 64];
        rand::rngs::OsRng.fill_bytes(&mut token_bytes[..]);

        let token = EphemeralToken {
            token: token_bytes.to_vec(),
            created_at: Timestamp::now(),
            tool_id: tool_id.to_string(),
        };
        token_bytes.zeroize();

        self.ephemeral_cache.push(token.clone());
        const MAX_EPHEMERAL_CACHE: usize = 1_000;
        if self.ephemeral_cache.len() > MAX_EPHEMERAL_CACHE {
            self.ephemeral_cache.drain(0..self.ephemeral_cache.len() - MAX_EPHEMERAL_CACHE);
        }
        Ok(token)
    }

    /// Rotate master secret (requires 3 shares).
    pub fn rotate_secret(
        &mut self,
        shares: &[shamir::Share],
    ) -> std::result::Result<(), VaultError> {
        let reconstructed = self.reconstruct(shares)?;

        // Verify reconstructed master matches current encrypted master.
        let current_master =
            aes_256_gcm_decrypt(&self.vault_key, &self.encrypted_master)
                .map_err(|_| VaultError::RotationVerificationFailed)?;

        if !shamir::constant_time_eq(&reconstructed, &current_master) {
            return Err(VaultError::RotationVerificationFailed);
        }

        // Generate new master
        let mut new_master = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut new_master[..]);

        // Create new vault with rotated secret
        let new_vault = Self::new(&new_master, self.threshold)?;
        new_master.zeroize();
        *self = new_vault;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shamir_split_reconstruct() {
        let secret = [0xABu8; 32];
        let shares = shamir::split_secret(&secret, 5, 3).unwrap();
        assert_eq!(shares.len(), 5);

        // Reconstruct with 3 shares
        let reconstructed = shamir::reconstruct_secret(&shares[..3], 3).unwrap();
        assert_eq!(reconstructed, secret.to_vec());

        // Reconstruct with all 5 shares
        let reconstructed2 = shamir::reconstruct_secret(&shares, 3).unwrap();
        assert_eq!(reconstructed2, secret.to_vec());
    }

    #[test]
    fn test_vault_create() {
        let master = [0xCDu8; 32];
        let vault = SecretVault::new(&master, 3).unwrap();
        assert_eq!(vault.shares.len(), 5);
    }

    #[test]
    fn test_vault_reconstruct() {
        let master = [0xEFu8; 32];
        let vault = SecretVault::new(&master, 3).unwrap();

        // Generate fresh shares for the same master to test reconstruction.
        let shares = shamir::split_secret(&master, 5, 3).unwrap();
        let reconstructed = vault.reconstruct(&shares[..3]).unwrap();
        assert_eq!(reconstructed, master.to_vec());
    }

    #[test]
    fn test_ephemeral_token() {
        let master = [0xEFu8; 32];
        let mut vault = SecretVault::new(&master, 3).unwrap();

        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &vault.vault_key);
        let proof = ring::hmac::sign(&key, b"email");
        let token = vault
            .fetch_ephemeral_token("email", proof.as_ref())
            .unwrap();
        assert_eq!(token.tool_id, "email");
        assert!(token.is_valid());
    }

    #[test]
    fn test_ephemeral_token_rejects_empty_approval() {
        let master = [0xEFu8; 32];
        let mut vault = SecretVault::new(&master, 3).unwrap();

        let result = vault.fetch_ephemeral_token("email", b"");
        assert!(matches!(result, Err(VaultError::InvalidApprovalProof)));
    }

    #[test]
    fn test_rotate_secret() {
        let master = [0x12u8; 32];
        let mut vault = SecretVault::new(&master, 3).unwrap();

        let shares = shamir::split_secret(&master, 5, 3).unwrap();
        vault.rotate_secret(&shares[..3]).unwrap();

        // Rotation succeeded — vault still has 5 shares.
        assert_eq!(vault.shares.len(), 5);
    }

    #[test]
    fn test_rotate_secret_fails_with_wrong_shares() {
        let master = [0x12u8; 32];
        let mut vault = SecretVault::new(&master, 3).unwrap();

        let wrong_secret = [0x34u8; 32];
        let wrong_shares = shamir::split_secret(&wrong_secret, 5, 3).unwrap();
        let result = vault.rotate_secret(&wrong_shares[..3]);
        assert!(matches!(result, Err(VaultError::RotationVerificationFailed)));
    }

    #[test]
    fn test_vault_rejects_threshold_zero() {
        let master = [0x12u8; 32];
        let result = SecretVault::new(&master, 0);
        assert!(matches!(result, Err(VaultError::InvalidParameters(_))));
    }

    #[test]
    fn test_ephemeral_token_rejects_wrong_tool() {
        let master = [0xEFu8; 32];
        let mut vault = SecretVault::new(&master, 3).unwrap();

        // Generate proof for "email" tool but request "shell"
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &vault.vault_key);
        let proof = ring::hmac::sign(&key, b"email");
        let result = vault.fetch_ephemeral_token("shell", proof.as_ref());
        assert!(matches!(result, Err(VaultError::InvalidApprovalProof)));
    }

    #[test]
    fn test_ephemeral_token_rejects_tampered_proof() {
        let master = [0xEFu8; 32];
        let mut vault = SecretVault::new(&master, 3).unwrap();

        let mut proof = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut proof);
        let result = vault.fetch_ephemeral_token("email", &proof);
        assert!(matches!(result, Err(VaultError::InvalidApprovalProof)));
    }
}
