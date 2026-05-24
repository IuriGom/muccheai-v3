//! Capability-based security types.

use serde::{Deserialize, Serialize};

use crate::Timestamp;

/// A capability token — unforgeable, scoped, time-bounded permission
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityToken {
    /// Unique token identifier (32 bytes random)
    pub token_id: Vec<u8>,
    /// Which tool this token grants access to
    pub tool_id: String,
    /// Which method on the tool
    pub method: String,
    /// Specific resource identifiers this token covers
    pub resource_ids: Vec<String>,
    /// Not valid before this time
    pub not_before: Timestamp,
    /// Expires at this time
    pub not_after: Timestamp,
    /// Public key of the issuer (Policy Engine) — classical Ed25519
    pub issuer_pubkey: Vec<u8>,
    /// Post-quantum public key of the issuer (ML-DSA-44)
    #[serde(default)]
    pub issuer_pq_pubkey: Vec<u8>,
    /// Ed25519 signature (classical)
    pub classical_signature: Vec<u8>,
    /// ML-DSA-44 signature (post-quantum)
    pub pq_signature: Vec<u8>,
    /// Unique nonce preventing replay
    pub nonce: Vec<u8>,
    /// Process ID this token is bound to
    pub bound_process: u64,
    /// Maximum number of uses (0 = unlimited)
    #[serde(default)]
    pub max_uses: u64,
}

impl CapabilityToken {
    /// Check if the token is currently valid (time bounds)
    pub fn is_temporally_valid(&self) -> bool {
        let now = Timestamp::now();
        now >= self.not_before && now < self.not_after
    }

    /// Check if token covers a specific resource.
    /// Supports exact match, prefix wildcard (`*`), single-char wildcard (`?`),
    /// and recursive wildcard (`**`).
    pub fn covers_resource(&self, resource: &str) -> bool {
        self.resource_ids.iter().any(|pattern| match_pattern(pattern, resource))
    }

    /// Get the canonical payload bytes that were signed.
    /// Uses length-prefixed encoding to prevent canonicalization attacks.
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&(self.token_id.len() as u16).to_le_bytes());
        payload.extend_from_slice(&self.token_id);
        payload.extend_from_slice(&(self.tool_id.len() as u16).to_le_bytes());
        payload.extend_from_slice(self.tool_id.as_bytes());
        payload.extend_from_slice(&(self.method.len() as u16).to_le_bytes());
        payload.extend_from_slice(self.method.as_bytes());
        payload.extend_from_slice(&(self.resource_ids.len() as u16).to_le_bytes());
        for res in &self.resource_ids {
            payload.extend_from_slice(&(res.len() as u16).to_le_bytes());
            payload.extend_from_slice(res.as_bytes());
        }
        payload.extend_from_slice(&self.not_before.0.to_le_bytes());
        payload.extend_from_slice(&self.not_after.0.to_le_bytes());
        payload.extend_from_slice(&(self.issuer_pubkey.len() as u16).to_le_bytes());
        payload.extend_from_slice(&self.issuer_pubkey);
        payload.extend_from_slice(&(self.nonce.len() as u16).to_le_bytes());
        payload.extend_from_slice(&self.nonce);
        payload.extend_from_slice(&self.bound_process.to_le_bytes());
        payload.extend_from_slice(&self.max_uses.to_le_bytes());
        payload
    }
}

/// A set of capabilities held by an agent
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilitySet {
    /// Owned capabilities
    pub tokens: Vec<CapabilityToken>,
    /// Maximum risk level this set can approve
    pub max_risk_level: crate::RiskLevel,
}

/// A request to mint a new (attenuated) capability
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityRequest {
    /// Parent token ID (must be held by requester)
    pub parent_token_id: Vec<u8>,
    /// Desired tool
    pub tool_id: String,
    /// Desired method
    pub method: String,
    /// Desired resources (must be subset of parent)
    pub resource_ids: Vec<String>,
    /// Requested time-to-live in seconds
    pub ttl_seconds: u64,
}

/// Errors during capability operations
#[derive(Debug, Clone, thiserror::Error, Serialize, Deserialize)]
pub enum CapabilityError {
    /// Token has expired
    #[error("Token expired")]
    Expired,
    /// Token has been revoked
    #[error("Token revoked")]
    Revoked,
    /// Resource is not covered by this capability
    #[error("Resource not covered: {0}")]
    ResourceNotCovered(String),
    /// Method is not allowed by this capability
    #[error("Method not allowed: {0}")]
    MethodNotAllowed(String),
    /// Signature verification failed
    #[error("Invalid signature")]
    InvalidSignature,
    /// Child capability exceeds parent scope
    #[error("Attenuation violation: child exceeds parent scope")]
    AttenuationViolation,
    /// Nonce has already been used (replay detected)
    #[error("Nonce replay detected")]
    ReplayDetected,
    /// Token is bound to a different process
    #[error("Process binding mismatch")]
    ProcessBindingMismatch,
}

/// Match a glob pattern against a resource string.
/// Supports `*` (any suffix), `?` (single char), and `**` (recursive).
fn match_pattern(pattern: &str, resource: &str) -> bool {
    if pattern == "**" || pattern == resource {
        return true;
    }
    if pattern.ends_with("**") {
        let prefix = &pattern[..pattern.len() - 2];
        return resource.starts_with(prefix);
    }
    if pattern.ends_with('*') && !pattern.ends_with("**") {
        let prefix = &pattern[..pattern.len() - 1];
        return resource.starts_with(prefix);
    }
    // Simple ? wildcard support
    if pattern.len() == resource.len() {
        return pattern.chars().zip(resource.chars()).all(|(p, r)| p == '?' || p == r);
    }
    false
}

/// Attenuated capability for cross-agent delegation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttenuatedCapability {
    /// Parent capability this was derived from
    pub parent_token_id: Vec<u8>,
    /// Narrower scope
    pub resource: ResourceRestriction,
    /// Narrower constraints
    pub constraints: CapabilityConstraints,
}

/// Resource restriction for attenuation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceRestriction {
    /// Allowed resource patterns (intersection of parent)
    pub allowed_patterns: Vec<String>,
}

/// Time and usage constraints on a capability
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityConstraints {
    /// Not valid before
    pub not_before: Timestamp,
    /// Not valid after
    pub not_after: Timestamp,
    /// Maximum number of uses (0 = unlimited)
    pub max_uses: u64,
    /// Current use count
    pub use_count: u64,
}

/// Rights mask for capability minting
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct RightsMask {
    /// Can read
    pub read: bool,
    /// Can write
    pub write: bool,
    /// Can execute
    pub execute: bool,
    /// Can delegate (mint child capabilities)
    pub delegate: bool,
}

/// A handle to a resource in the capability system
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceHandle {
    /// Resource type
    pub resource_type: String,
    /// Resource identifier
    pub identifier: String,
}
