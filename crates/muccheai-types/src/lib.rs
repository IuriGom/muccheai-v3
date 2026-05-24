//! Shared core types.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod capabilities;
pub mod memory;
pub mod audit;
pub mod crypto_primitives;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Unique identifier for an agent instance (W3C DID compatible)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId(pub String);

/// A validated timestamp with millisecond precision
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Zeroize)]
pub struct Timestamp(pub u64);

impl Timestamp {
    /// Current time as Timestamp
    pub fn now() -> Self {
        let dt: DateTime<Utc> = Utc::now();
        Self(dt.timestamp_millis() as u64)
    }

    /// Check if this timestamp is before now
    pub fn is_expired(&self) -> bool {
        Self::now().0 > self.0
    }
}

/// Risk level for an action — drives approval friction
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum RiskLevel {
    /// Low risk: no approval required
    Low,
    /// Medium risk: standard dialog, 3s delay
    Medium,
    /// High risk: re-type summary, 5s delay
    High,
    /// Critical risk: hardware token, 10s delay, multi-device
    Critical,
}

impl RiskLevel {
    /// Approval delay in seconds for this risk level
    pub fn delay_seconds(&self) -> u64 {
        match self {
            RiskLevel::Low => 0,
            RiskLevel::Medium => 3,
            RiskLevel::High => 5,
            RiskLevel::Critical => 10,
        }
    }

    /// Whether this risk level requires biometric confirmation
    pub fn requires_biometric(&self) -> bool {
        matches!(self, RiskLevel::Medium | RiskLevel::High | RiskLevel::Critical)
    }

    /// Whether this risk level requires hardware token
    pub fn requires_hardware_token(&self) -> bool {
        matches!(self, RiskLevel::Critical)
    }
}

/// A concrete action proposed by the LLM sandbox
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionProposal {
    /// Which tool to invoke
    pub tool_id: String,
    /// Which method on the tool
    pub method: String,
    /// JSON-encoded parameters
    pub params: serde_json::Value,
    /// Public key of the requester (LLM sandbox)
    pub requester_pubkey: Vec<u8>,
    /// When the proposal was created
    pub timestamp: Timestamp,
    /// Unique nonce to prevent replay
    pub nonce: Vec<u8>,
}

/// A capability grant from user to agent
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityGrant {
    /// The action being approved
    pub action: ActionProposal,
    /// Aggregated signature from approval mechanism
    pub signature: AggregatedSignature,
    /// How this approval was obtained
    pub mechanism: ApprovalMechanism,
}

/// Approval mechanism used
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ApprovalMechanism {
    /// Low-risk standard dialog
    Standard,
    /// Face ID / Touch ID with attention detection
    SecureEnclave,
    /// YubiKey / OnlyKey hardware token
    HardwareToken,
    /// Multiple devices co-signed
    MultiDevice,
    /// Duress mode triggered — all capabilities revoked
    Duress,
}

/// Aggregated signature from multi-device or single-device approval
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct AggregatedSignature {
    /// Ed25519 signatures
    pub classical_sigs: Vec<Vec<u8>>,
    /// ML-DSA signatures (PQC)
    pub pq_sigs: Vec<Vec<u8>>,
}

/// A tool adapter declaration (compiled-in, not dynamic)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolAdapter {
    /// Unique tool identifier
    pub tool_id: String,
    /// Version
    pub version: String,
    /// Declared scope
    pub scope: ToolScope,
    /// SHA-3-512 hash of the adapter binary
    pub adapter_hash: Vec<u8>,
}

/// Result of a tool method execution
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolResult {
    /// Whether execution succeeded
    pub success: bool,
    /// Result data
    pub data: serde_json::Value,
    /// Execution metadata
    pub metadata: ToolResultMetadata,
}

/// Metadata about a tool execution
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolResultMetadata {
    /// Execution time in milliseconds
    pub execution_time_ms: u64,
    /// Tool identifier
    pub tool_id: String,
    /// Method name
    pub method: String,
}

/// Error type for tool execution
#[derive(Debug, Clone, thiserror::Error, Serialize, Deserialize)]
pub enum ToolError {
    /// Invalid parameters
    #[error("Invalid parameters: {0}")]
    InvalidParams(String),
    /// Execution failed
    #[error("Execution failed: {0}")]
    ExecutionFailed(String),
    /// Capability denied
    #[error("Capability denied: {0}")]
    CapabilityDenied(String),
    /// Tool not found
    #[error("Tool not found: {0}")]
    ToolNotFound(String),
    /// Method not found
    #[error("Method not found: {0}")]
    MethodNotFound(String),
    /// Result too large for context window
    #[error("Result too large: {0}")]
    ResultTooLarge(String),
    /// Schema validation failed
    #[error("Schema validation failed: {0}")]
    SchemaValidationFailed(String),
    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

/// Scope declaration for a tool adapter
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolScope {
    /// Allowed methods
    pub methods: Vec<String>,
    /// Allowed memory access patterns
    pub memory: Vec<String>,
    /// Sandbox restrictions
    pub sandbox: SandboxRestrictions,
}

/// Sandbox restrictions for a tool
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SandboxRestrictions {
    /// Network access allowed
    pub network: bool,
    /// Filesystem access allowed
    pub filesystem: bool,
    /// Max execution time in milliseconds
    pub max_execution_ms: u64,
}

/// Error type for all MuccheAI operations
#[derive(Debug, Clone, thiserror::Error, Serialize, Deserialize)]
pub enum MuccheError {
    /// Policy denied the action
    #[error("Policy denied: {0}")]
    PolicyDenied(String),
    /// Invalid capability token
    #[error("Invalid capability: {0}")]
    InvalidCapability(String),
    /// Cryptographic verification failed
    #[error("Crypto error: {0}")]
    CryptoError(String),
    /// Sandbox violation
    #[error("Sandbox error: {0}")]
    SandboxError(String),
    /// Audit log failure
    #[error("Audit error: {0}")]
    AuditError(String),
    /// UI/approval error
    #[error("Approval error: {0}")]
    ApprovalError(String),
    /// Vault/secret error
    #[error("Vault error: {0}")]
    VaultError(String),
    /// Generic internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Result type alias
pub type Result<T> = std::result::Result<T, MuccheError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_ordering() {
        let t1 = Timestamp(100);
        let t2 = Timestamp(200);
        assert!(t1 < t2);
        assert!(t2 > t1);
        assert_eq!(t1, Timestamp(100));
    }

    #[test]
    fn test_timestamp_serialization_roundtrip() {
        let ts = Timestamp(123456789);
        let json = serde_json::to_string(&ts).unwrap();
        let de: Timestamp = serde_json::from_str(&json).unwrap();
        assert_eq!(ts, de);
    }

    #[test]
    fn test_timestamp_is_expired() {
        let past = Timestamp(0);
        assert!(past.is_expired());
        let future = Timestamp(u64::MAX);
        assert!(!future.is_expired());
    }

    #[test]
    fn test_risk_level_delay_seconds() {
        assert_eq!(RiskLevel::Low.delay_seconds(), 0);
        assert_eq!(RiskLevel::Medium.delay_seconds(), 3);
        assert_eq!(RiskLevel::High.delay_seconds(), 5);
        assert_eq!(RiskLevel::Critical.delay_seconds(), 10);
    }

    #[test]
    fn test_risk_level_requires_biometric() {
        assert!(!RiskLevel::Low.requires_biometric());
        assert!(RiskLevel::Medium.requires_biometric());
        assert!(RiskLevel::High.requires_biometric());
        assert!(RiskLevel::Critical.requires_biometric());
    }

    #[test]
    fn test_risk_level_requires_hardware_token() {
        assert!(!RiskLevel::Low.requires_hardware_token());
        assert!(!RiskLevel::Medium.requires_hardware_token());
        assert!(!RiskLevel::High.requires_hardware_token());
        assert!(RiskLevel::Critical.requires_hardware_token());
    }

    #[test]
    fn test_aggregated_signature_serialization() {
        let sig = AggregatedSignature {
            classical_sigs: vec![vec![1u8; 64]],
            pq_sigs: vec![vec![2u8; 2420]],
        };
        let json = serde_json::to_string(&sig).unwrap();
        let de: AggregatedSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(sig, de);
    }

    #[test]
    fn test_aggregated_signature_zeroize() {
        let mut sig = AggregatedSignature {
            classical_sigs: vec![vec![1u8; 64]],
            pq_sigs: vec![vec![2u8; 2420]],
        };
        sig.zeroize();
        assert!(sig.classical_sigs.iter().all(|s| s.iter().all(|b| *b == 0)));
        assert!(sig.pq_sigs.iter().all(|s| s.iter().all(|b| *b == 0)));
    }

    #[test]
    fn test_mucche_error_display() {
        let e = MuccheError::PolicyDenied("test".to_string());
        assert_eq!(e.to_string(), "Policy denied: test");
    }

    #[test]
    fn test_action_proposal_serialization() {
        let proposal = ActionProposal {
            tool_id: "email".to_string(),
            method: "send".to_string(),
            params: serde_json::json!({"to": "test@example.com"}),
            requester_pubkey: vec![0u8; 32],
            timestamp: Timestamp::now(),
            nonce: vec![0u8; 32],
        };
        let json = serde_json::to_string(&proposal).unwrap();
        let de: ActionProposal = serde_json::from_str(&json).unwrap();
        assert_eq!(proposal.tool_id, de.tool_id);
        assert_eq!(proposal.method, de.method);
    }
}
