//! Forward-secure audit logging types
//!
//! Each log entry derives the next signing key and destroys the previous.
//! Compromise of current key does not expose past entries.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Timestamp;

/// A single audit log entry
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LogEntry {
    /// Sequence number (monotonically increasing)
    pub sequence: u64,
    /// Hash of previous entry (None for first)
    pub previous_hash: Option<Vec<u8>>,
    /// When this entry was created
    pub timestamp: Timestamp,
    /// The event being logged
    pub event: SecurityEvent,
    /// Ed25519 verifying key for this entry's signature (stored for forward-secure verification)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub verifying_key: Option<Vec<u8>>,
    /// Signature with the forward-secure key
    pub signature: Vec<u8>,
}

/// Types of security events
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SecurityEvent {
/// Action was proposed by LLM
    ActionProposed {
        /// Tool being requested
        tool_id: String,
        /// Method on the tool
        method: String,
        /// Public key of the requester
        requester: Vec<u8>,
    },
    /// Action was validated by Policy Engine
    ActionValidated {
        /// Capability token ID
        token_id: Vec<u8>,
        /// Tool being validated
        tool_id: String,
        /// Method on the tool
        method: String,
    },
    /// Action was rejected
    ActionRejected {
        /// Hash of the rejected proposal
        proposal_hash: Vec<u8>,
        /// Rejection reason
        reason: String,
    },
    /// Capability was minted
    CapabilityMinted {
        /// Token ID
        token_id: Vec<u8>,
        /// Parent token ID (None for root)
        parent_id: Option<Vec<u8>>,
        /// Tool this capability is for
        tool_id: String,
    },
    /// Capability was revoked
    CapabilityRevoked {
        /// Token ID revoked
        token_id: Vec<u8>,
        /// Number of child tokens also revoked
        revoked_count: u32,
    },
    /// User approved an action
    UserApproved {
        /// Hash of the approved action
        action_hash: Vec<u8>,
        /// Approval mechanism (e.g. "password", "biometric")
        mechanism: String,
    },
    /// User denied an action
    UserDenied {
        /// Hash of the denied action
        action_hash: Vec<u8>,
        /// Denial reason
        reason: String,
    },
    /// Memory entry added
    MemoryAdded {
        /// Memory key
        key: String,
        /// Type of memory (Fact, Preference, TaskHistory, etc.)
        memory_type: String,
    },
    /// Sandbox started
    SandboxStarted {
        /// VM identifier
        vm_id: String,
        /// Hash of the sandbox configuration
        config_hash: Vec<u8>,
    },
    /// Sandbox terminated
    SandboxTerminated {
        /// VM identifier
        vm_id: String,
        /// Termination reason
        reason: String,
    },
    /// Anomaly detected
    AnomalyDetected {
        /// Severity level
        severity: AnomalySeverity,
        /// Human-readable description
        description: String,
        /// Indicators that triggered the anomaly
        indicators: Vec<String>,
    },
    /// Incident response triggered
    IncidentResponse {
        /// Incident identifier
        incident_id: String,
        /// Response phase (detect, contain, eradicate, recover)
        phase: String,
    },
    /// System boot verified
    BootVerified {
        /// TPM / secure boot measurements
        measurements: Vec<Vec<u8>>,
    },
    /// Build attestation verified
    BuildAttestationVerified {
        /// Git commit hash (20 bytes)
        git_commit: [u8; 20],
        /// Number of CI systems that attested
        ci_count: usize,
    },
    /// MCP tool was invoked by the LLM
    McpToolInvoked {
        /// MCP server name
        server: String,
        /// Tool name
        tool_id: String,
        /// Whether the tool call succeeded
        success: bool,
    },
    /// MCP tool invocation was rejected by policy or schema validation
    McpToolRejected {
        /// MCP server name
        server: String,
        /// Tool name
        tool_id: String,
        /// Rejection reason
        reason: String,
    },
}

/// Severity of an anomaly
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum AnomalySeverity {
    /// Informational severity level
    Info,
    /// Low severity level
    Low,
    /// Medium severity level
    Medium,
    /// High severity level
    High,
    /// Critical severity level
    Critical,
}

/// Forward-secure key for signing log entries
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ForwardSecureKey {
    /// Current signing key (32 bytes Ed25519 seed)
    pub key: [u8; 32],
    /// Key identifier (sequence number)
    pub key_id: u64,
}

impl std::fmt::Debug for ForwardSecureKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForwardSecureKey")
            .field("key", &"<redacted>")
            .field("key_id", &self.key_id)
            .finish()
    }
}

/// Forward-secure audit log
#[derive(Debug, Clone)]
pub struct ForwardSecureLog {
    /// Current signing key
    pub current_key: ForwardSecureKey,
    /// IDs of keys that have been destroyed
    pub destroyed_keys: Vec<u64>,
    /// Log entries
    pub entries: Vec<LogEntry>,
    /// Merkle tree root hash
    pub merkle_root: Option<Vec<u8>>,
    /// Whether the log has been sealed (no further appends allowed)
    pub sealed: bool,
}

/// Compacted log for long-term storage
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompactedLog {
    /// Full Merkle tree for recent entries (last 24 hours)
    pub recent_tree: Vec<LogEntry>,
    /// Daily summaries for older entries
    pub historical_summaries: Vec<CompactedDay>,
    /// Forward-secure key chain info
    pub key_chain_info: KeyChainInfo,
}

/// Daily summary of audit entries
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompactedDay {
    /// Date (YYYY-MM-DD)
    pub date: String,
    /// Number of entries this day
    pub entry_count: u64,
    /// Merkle root for this day
    pub merkle_root: Vec<u8>,
}

/// Info about the forward-secure key chain
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyChainInfo {
    /// Current key ID
    pub current_key_id: u64,
    /// Total entries signed
    pub total_entries: u64,
}

/// Query parameters for audit log retrieval
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditQuery {
    /// Start time (inclusive)
    pub from: Timestamp,
    /// End time (inclusive)
    pub to: Timestamp,
    /// Filter by tool ID (optional)
    pub tool_id: Option<String>,
    /// Filter by requester pubkey (optional)
    pub requester: Option<Vec<u8>>,
    /// Filter by event type (optional)
    pub event_type: Option<String>,
}

/// Result of audit log query
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditResult {
    /// Matching entries
    pub entries: Vec<LogEntry>,
    /// Merkle root at query time
    pub merkle_root: Vec<u8>,
    /// Total entries in log
    pub total_entries: u64,
}
