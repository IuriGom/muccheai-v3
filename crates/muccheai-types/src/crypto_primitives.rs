//! Cryptographic primitive types for MuccheAI
//!
//! Hybrid classical/post-quantum cryptography.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Classical + PQC hybrid public key
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct HybridPubkey {
    /// Ed25519 public key (32 bytes)
    pub classical: Vec<u8>,
    /// X25519 public key (32 bytes)
    pub x25519: Vec<u8>,
    /// ML-KEM-768 public key (1,184 bytes)
    pub pq: Vec<u8>,
    /// ML-DSA-44 public key (1,312 bytes)
    pub pq_sign: Vec<u8>,
}

/// Hybrid private key (sensitive — zeroized on drop)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridPrivkey {
    /// Ed25519 private key (32 bytes)
    pub classical: Vec<u8>,
    /// X25519 private key (32 bytes)
    pub x25519: Vec<u8>,
    /// ML-KEM-768 private key (2,400 bytes)
    pub pq: Vec<u8>,
    /// ML-DSA-44 private key (2,528 bytes)
    pub pq_sign: Vec<u8>,
}

/// Hybrid keypair
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridKeypair {
    /// Public component
    pub pubkey: HybridPubkey,
    /// Private component
    pub privkey: HybridPrivkey,
}

/// Hybrid ciphertext
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HybridCiphertext {
    /// X25519 ciphertext
    pub classical: Vec<u8>,
    /// ML-KEM-768 ciphertext (1,088 bytes)
    pub pq: Vec<u8>,
}

/// Hybrid digital signature
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HybridSignature {
    /// Ed25519 signature (64 bytes)
    pub classical: Vec<u8>,
    /// ML-DSA-44 signature (~2,420 bytes)
    pub pq: Vec<u8>,
}

/// Shared secret from key encapsulation
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret {
    /// The derived shared secret (32 bytes, XOR of classical and PQC)
    pub secret: Vec<u8>,
}

/// Cryptographic suite version for agility
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum CryptoSuite {
    /// v1.0: Classical only (Ed25519 + X25519)
    V1Classical,
    /// v2.0: Hybrid classical + PQC
    V2Hybrid,
    /// v3.0: Pure PQC (future)
    V3PurePq,
}

impl CryptoSuite {
    /// Is this suite quantum-resistant?
    pub fn is_quantum_resistant(&self) -> bool {
        matches!(self, CryptoSuite::V2Hybrid | CryptoSuite::V3PurePq)
    }
}

/// Algorithm identifier for agility
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlgorithmId {
    /// Suite version
    pub suite: CryptoSuite,
    /// Classical algorithm
    pub classical: String,
    /// Post-quantum algorithm
    pub pq: Option<String>,
}

/// A quantum-safe capability token
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuantumSafeToken {
    /// Classical Ed25519 signature
    pub classical_signature: Vec<u8>,
    /// Post-quantum ML-DSA signature
    pub pq_signature: Vec<u8>,
    /// Hybrid public key of issuer
    pub hybrid_pubkey: HybridPubkey,
    /// Token payload
    pub payload: TokenPayload,
}

/// Payload of a capability token
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TokenPayload {
    /// Token ID
    pub token_id: Vec<u8>,
    /// Tool ID
    pub tool_id: String,
    /// Method
    pub method: String,
    /// Resources
    pub resource_ids: Vec<String>,
    /// Not before (unix millis)
    pub not_before: u64,
    /// Not after (unix millis)
    pub not_after: u64,
    /// Nonce
    pub nonce: Vec<u8>,
    /// Crypto suite version
    pub suite: CryptoSuite,
}

/// Errors in cryptographic operations
#[derive(Debug, Clone, thiserror::Error, Serialize, Deserialize)]
pub enum CryptoError {
    /// Invalid key length provided
    #[error("Invalid key length")]
    InvalidKeyLength,
    /// Signature verification failed
    #[error("Invalid signature")]
    InvalidSignature,
    /// Key decapsulation operation failed
    #[error("Decapsulation failed")]
    DecapsulationFailed,
    /// Unsupported cryptographic suite requested
    #[error("Unsupported crypto suite")]
    UnsupportedSuite,
    /// Constant-time comparison failed (potential tampering)
    #[error("Constant time comparison failed")]
    ComparisonFailed,
}

/// Model provenance for integrity verification
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelProvenance {
    /// Publisher hash (from Meta/whoever)
    pub publisher_hash: Vec<u8>,
    /// Independent auditor attestations
    pub auditor_attestations: Vec<Attestation>,
    /// Transparency log Merkle proof
    pub transparency_log_proof: MerkleProof,
    /// User's LoRA fine-tune hash (if any)
    pub adapter_hash: Option<Vec<u8>>,
}

/// Third-party attestation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Attestation {
    /// Auditor identifier
    pub auditor: String,
    /// Attested hash
    pub hash: Vec<u8>,
    /// Ed25519 signature from auditor
    pub signature: Vec<u8>,
    /// Timestamp
    pub timestamp: u64,
}

/// Merkle proof (simplified)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Leaf hash
    pub leaf: Vec<u8>,
    /// Path to root
    pub path: Vec<[u8; 32]>,
}

/// TPM PCR value
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PcrValue {
    /// PCR index
    pub index: u32,
    /// PCR value (SHA-256 hash)
    pub value: Vec<u8>,
}

/// TPM measured boot state
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeasuredBoot {
    /// PCR values
    pub pcrs: Vec<PcrValue>,
    /// Golden measurements
    pub golden: Vec<PcrValue>,
}
