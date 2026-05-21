//! Structured memory architecture for MuccheAI
//!
//! Critical design: LLM can READ structured memory via queries.
//! LLM CANNOT write directly. All writes go through approval queue.

use serde::{Deserialize, Serialize};

use crate::Timestamp;

/// Types of structured memory
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MemoryType {
    /// Immutable facts — user approves every addition
    Fact,
    /// User preferences — key-value, typed, max 1KB
    Preference,
    /// Task history — append-only system logs
    TaskHistory,
    /// Drafts — encrypted, 24h TTL
    Draft,
    /// Session-only context — RAM only, never disk
    Context,
}

/// A memory entry with cryptographic integrity
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryEntry {
    /// Entry type
    pub memory_type: MemoryType,
    /// Unique key
    pub key: String,
    /// Typed value
    pub value: MemoryValue,
    /// When created
    pub created_at: Timestamp,
    /// User signature approving this entry
    pub user_signature: Vec<u8>,
    /// SHA-3-512 hash of entry content
    pub content_hash: Vec<u8>,
}

impl MemoryEntry {
    /// Compute content hash for integrity verification
    pub fn compute_hash(&self) -> Vec<u8> {
        use sha3::{Digest, Sha3_512};
        let mut hasher = Sha3_512::new();
        hasher.update(self.memory_type.as_bytes());
        hasher.update(self.key.as_bytes());
        hasher.update(&self.value.as_bytes());
        hasher.update(&self.created_at.0.to_le_bytes());
        hasher.update(&self.user_signature);
        hasher.finalize().to_vec()
    }

    /// Verify integrity of this entry
    pub fn verify_integrity(&self) -> bool {
        self.compute_hash() == self.content_hash
    }
}

/// Typed memory values — never freeform text
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MemoryValue {
    /// Boolean value
    Bool(bool),
    /// 64-bit integer
    I64(i64),
    /// 64-bit unsigned
    U64(u64),
    /// Floating point
    F64(f64),
    /// Short string (max 256 bytes)
    ShortString(String),
    /// JSON object (structured, validated against schema)
    JsonObject(serde_json::Map<String, serde_json::Value>),
    /// Timestamp
    Timestamp(Timestamp),
    /// Binary data (max 1KB for preferences)
    Bytes(Vec<u8>),
}

impl MemoryValue {
    /// Serialize to bytes for hashing
    pub fn as_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Size in bytes
    pub fn size_bytes(&self) -> usize {
        self.as_bytes().len()
    }

    /// Check if value fits within preference size limit (1KB)
    pub fn fits_preference_limit(&self) -> bool {
        self.size_bytes() <= 1024
    }
}

impl MemoryType {
    /// Human-readable bytes for hashing
    fn as_bytes(&self) -> Vec<u8> {
        match self {
            MemoryType::Fact => b"FACT".to_vec(),
            MemoryType::Preference => b"PREF".to_vec(),
            MemoryType::TaskHistory => b"HIST".to_vec(),
            MemoryType::Draft => b"DRAFT".to_vec(),
            MemoryType::Context => b"CTX".to_vec(),
        }
    }
}

/// Merkle tree node for memory integrity
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MerkleNode {
    /// SHA-3-512 hash of this node
    pub hash: Vec<u8>,
    /// Left child index (if internal node)
    pub left: Option<usize>,
    /// Right child index (if internal node)
    pub right: Option<usize>,
    /// Leaf data index (if leaf node)
    pub leaf: Option<usize>,
}

/// Merkle tree over memory entries
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryMerkleTree {
    /// All nodes, root is at index 0
    pub nodes: Vec<MerkleNode>,
    /// Leaf entries
    pub leaves: Vec<MemoryEntry>,
    /// Root hash signed by user
    pub signed_root: Option<SignedRoot>,
}

/// Signed Merkle root for transparency
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedRoot {
    /// The root hash
    pub root_hash: Vec<u8>,
    /// Ed25519 signature
    pub signature: Vec<u8>,
    /// Timestamp of signing
    pub timestamp: Timestamp,
}

impl MemoryMerkleTree {
    /// Build a Merkle tree from leaf entries
    pub fn build(leaves: Vec<MemoryEntry>) -> Self {
        use sha3::{Digest, Sha3_512};
        
        if leaves.is_empty() {
            return Self {
                nodes: vec![MerkleNode {
                    hash: vec![0u8; 64],
                    left: None,
                    right: None,
                    leaf: None,
                }],
                leaves: vec![],
                signed_root: None,
            };
        }

        let mut nodes = Vec::new();
        let leaf_start = nodes.len();
        
        // Create leaf nodes
        for (i, leaf) in leaves.iter().enumerate() {
            nodes.push(MerkleNode {
                hash: leaf.content_hash.clone(),
                left: None,
                right: None,
                leaf: Some(i),
            });
        }

        // Build internal nodes bottom-up
        let mut level_start = leaf_start;
        let mut level_len = leaves.len();
        
        while level_len > 1 {
            let mut next_level = Vec::new();
            for i in (0..level_len).step_by(2) {
                let left_idx = level_start + i;
                let right_idx = if i + 1 < level_len {
                    level_start + i + 1
                } else {
                    left_idx // Duplicate last node if odd
                };

                let mut hasher = Sha3_512::new();
                hasher.update(&nodes[left_idx].hash);
                hasher.update(&nodes[right_idx].hash);
                let hash = hasher.finalize().to_vec();

                next_level.push(MerkleNode {
                    hash: hash,
                    left: Some(left_idx),
                    right: Some(right_idx),
                    leaf: None,
                });
            }
            
            level_start = nodes.len();
            level_len = next_level.len();
            nodes.extend(next_level);
        }

        // Reorder so root is at index 0
        // For simplicity in this implementation, we just note the root index
        let _root_idx = nodes.len() - 1;
        
        // A full reindexing would happen here in production
        // For the MVP we keep the original order and access root directly
        
        Self {
            nodes,
            leaves,
            signed_root: None,
        }
    }

    /// Get the root hash
    pub fn root_hash(&self) -> Option<Vec<u8>> {
        self.nodes.last().map(|n| n.hash.clone())
    }

    /// Generate a Merkle proof for a leaf
    pub fn proof(&self, leaf_index: usize) -> Option<MerkleProof> {
        // Simplified: would build actual proof path
        if leaf_index >= self.leaves.len() {
            return None;
        }
        Some(MerkleProof {
            leaf_hash: self.leaves[leaf_index].content_hash.clone(),
            path: vec![], // Would contain sibling hashes
        })
    }
}

/// Merkle proof for a single leaf
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Hash of the leaf
    pub leaf_hash: Vec<u8>,
    /// Sibling hashes along path to root
    pub path: Vec<Vec<u8>>,
}

/// Request to add a new memory entry (goes to approval queue)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryAdditionRequest {
    /// Proposed entry
    pub entry: MemoryEntry,
    /// LLM's justification
    pub justification: String,
    /// Risk level of this addition
    pub risk_level: crate::RiskLevel,
}
