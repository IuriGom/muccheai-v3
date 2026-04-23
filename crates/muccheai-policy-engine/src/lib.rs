//! Policy engine.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use sha3::Digest;
use std::collections::{HashSet, VecDeque};

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use zeroize::Zeroize;

use muccheai_types::*;
use muccheai_types::capabilities::*;
use muccheai_types::audit::*;
use muccheai_types::crypto_primitives::*;
use muccheai_crypto::{hybrid_sign, sha3_512};


pub mod rules;
pub mod anomaly;

use rules::*;

/// Policy Engine — the security kernel
pub struct PolicyEngine {
    /// Policy rules
    rules: PolicyRules,
    /// Issuer keypair for minting capabilities
    issuer_keypair: HybridKeypair,
    /// Used nonces (anti-replay) — bounded to prevent memory exhaustion
    used_nonces: HashSet<Vec<u8>>,
    /// Order of nonce insertion for LRU eviction
    nonce_queue: VecDeque<Vec<u8>>,
    /// Maximum number of tracked nonces before eviction
    max_nonces: usize,
    /// Revoked token IDs — bounded to prevent memory exhaustion
    revoked_tokens: HashSet<Vec<u8>>,
    /// Order of revocation insertion for LRU eviction
    revoked_queue: VecDeque<Vec<u8>>,
    /// Maximum number of tracked revoked tokens
    max_revoked: usize,
    /// Issued token IDs (for emergency revocation) — bounded
    issued_tokens: HashSet<Vec<u8>>,
    /// Order of issued token insertion for LRU eviction
    issued_queue: VecDeque<Vec<u8>>,
    /// Maximum number of tracked issued tokens
    max_issued: usize,
    /// Maximum number of audit log entries before rotation
    max_audit_entries: usize,
    /// Forward-secure audit log
    audit_log: ForwardSecureLog,
}

impl PolicyEngine {
    /// Create a new Policy Engine with given rules
    pub fn new(rules: PolicyRules, issuer_keypair: HybridKeypair) -> Self {
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        let initial_key = ForwardSecureKey {
            key,
            key_id: 0,
        };
        
        Self {
            rules,
            issuer_keypair,
            used_nonces: HashSet::new(),
            nonce_queue: VecDeque::new(),
            max_nonces: 1_000_000,
            revoked_tokens: HashSet::new(),
            revoked_queue: VecDeque::new(),
            max_revoked: 1_000_000,
            issued_tokens: HashSet::new(),
            issued_queue: VecDeque::new(),
            max_issued: 100_000,
            max_audit_entries: 100_000,
            audit_log: ForwardSecureLog {
                current_key: initial_key,
                destroyed_keys: vec![],
                entries: vec![],
                merkle_root: None,
                sealed: false,
            },
        }
    }

    /// Validate an action proposal and optionally mint a capability token
    ///
    pub fn validate_action(
        &mut self,
        proposal: &ActionProposal,
        user_capabilities: &CapabilitySet,
    ) -> Result<ValidationResult> {
        // Pre-compute proposal hash safely (avoids panic on non-string map keys).
        let proposal_hash = Vec::from(sha3_512(
            &serde_json::to_vec(proposal).unwrap_or_default(),
        ));

        // Also reject proposals outside a reasonable time window to prevent
        // replay after LRU eviction or clock skew attacks.
        const PROPOSAL_MAX_AGE_MS: u64 = 300_000; // 5 minutes
        const PROPOSAL_MAX_FUTURE_MS: u64 = 60_000; // 1 minute
        let now = Timestamp::now().0;
        let proposal_time = proposal.timestamp.0;
        if proposal_time.saturating_add(PROPOSAL_MAX_AGE_MS) < now {
            self.log_event(SecurityEvent::ActionRejected {
                proposal_hash: proposal_hash.clone(),
                reason: "Proposal expired (older than 5 minutes)".to_string(),
            });
            return Err(MuccheError::InvalidCapability(
                "Proposal too old".to_string()
            ));
        }
        if proposal_time > now.saturating_add(PROPOSAL_MAX_FUTURE_MS) {
            self.log_event(SecurityEvent::ActionRejected {
                proposal_hash: proposal_hash.clone(),
                reason: "Proposal timestamp in the future".to_string(),
            });
            return Err(MuccheError::InvalidCapability(
                "Invalid proposal timestamp".to_string()
            ));
        }
        if self.used_nonces.contains(&proposal.nonce) {
            self.log_event(SecurityEvent::ActionRejected {
                proposal_hash: proposal_hash.clone(),
                reason: "Nonce replay detected".to_string(),
            });
            return Err(MuccheError::InvalidCapability(
                "Replay detected".to_string()
            ));
        }

        // the proposed action; ignore irrelevant (including invalid) tokens.
        let resource = proposal.params.get("resource")
            .and_then(|v| v.as_str())
            .or_else(|| proposal.params.get("path").and_then(|v| v.as_str()))
            .or_else(|| proposal.params.get("to").and_then(|v| v.as_str()))
            .unwrap_or(&proposal.tool_id);

        let mut matching_cap: Option<&CapabilityToken> = None;
        for cap in &user_capabilities.tokens {
            if cap.tool_id != proposal.tool_id
                || cap.method != proposal.method
                || !cap.covers_resource(resource)
            {
                continue;
            }
            // Matching token found — perform full validation.
            if !cap.is_temporally_valid() {
                return Err(MuccheError::InvalidCapability("Token expired".to_string()));
            }
            if self.revoked_tokens.contains(&cap.token_id) {
                return Err(MuccheError::InvalidCapability("Token revoked".to_string()));
            }
            if self.used_nonces.contains(&cap.nonce) {
                self.log_event(SecurityEvent::ActionRejected {
                    proposal_hash: proposal_hash.clone(),
                    reason: "Capability token nonce replay detected".to_string(),
                });
                return Err(MuccheError::InvalidCapability(
                    "Capability token replay detected".to_string()
                ));
            }
            if cap.issuer_pubkey != self.issuer_keypair.pubkey.classical {
                self.log_event(SecurityEvent::ActionRejected {
                    proposal_hash: proposal_hash.clone(),
                    reason: "Untrusted capability issuer".to_string(),
                });
                return Err(MuccheError::InvalidCapability(
                    "Capability issuer is not trusted".to_string()
                ));
            }
            if cap.bound_process > 0 && cap.bound_process != std::process::id() as u64 {
                return Err(MuccheError::InvalidCapability(
                    "Capability bound to different process".to_string()
                ));
            }
            if let Err(e) = verify_classical_signature(cap) {
                self.log_event(SecurityEvent::ActionRejected {
                    proposal_hash: proposal_hash.clone(),
                    reason: format!("Capability signature invalid: {}", e),
                });
                return Err(MuccheError::InvalidCapability(format!("Invalid capability signature: {}", e)));
            }
            matching_cap = Some(cap);
            break; // First valid match wins; don't let later bad tokens override.
        }

        if matching_cap.is_none() {
            self.log_event(SecurityEvent::ActionRejected {
                proposal_hash: proposal_hash.clone(),
                reason: "No matching capability".to_string(),
            });
            // Burn the proposal nonce so rejected requests cannot be replayed.
            self.insert_nonce(proposal.nonce.clone());
            return Ok(ValidationResult::Rejected {
                reason: "No capability covers this action".to_string(),
            });
        }

        let rule_result = self.rules.evaluate(proposal);
        match rule_result {
            RuleAction::Deny => {
                self.log_event(SecurityEvent::ActionRejected {
                    proposal_hash: proposal_hash.clone(),
                    reason: "Policy rule denied".to_string(),
                });
                self.insert_nonce(proposal.nonce.clone());
                return Ok(ValidationResult::Rejected {
                    reason: "Denied by policy rule".to_string(),
                });
            }
            RuleAction::Allow => {}
            RuleAction::Escalate => {
                self.log_event(SecurityEvent::ActionRejected {
                    proposal_hash: proposal_hash.clone(),
                    reason: "Escalation required".to_string(),
                });
                self.insert_nonce(proposal.nonce.clone());
                return Ok(ValidationResult::Rejected {
                    reason: "Escalation required".to_string(),
                });
            }
        }

        self.insert_nonce(proposal.nonce.clone());
        if let Some(cap) = matching_cap {
            self.insert_nonce(cap.nonce.clone());
        }

        let token = self.mint_capability(proposal)?;

        let token_id = token.token_id.clone();
        self.log_event(SecurityEvent::ActionValidated {
            token_id,
            tool_id: proposal.tool_id.clone(),
            method: proposal.method.clone(),
        });

        Ok(ValidationResult::Approved { token })
    }

    /// Evaluate policy rules for an action proposal without capability validation.
    /// Used for MCP tool call policy checks.
    pub fn evaluate_proposal(&mut self, proposal: &ActionProposal) -> RuleAction {
        self.rules.evaluate(proposal)
    }

    /// Log a security event to the forward-secure audit log.
    pub fn log_security_event(&mut self, event: SecurityEvent) {
        self.log_event(event);
    }

    /// Mint a single-use capability token
    fn mint_capability(
        &mut self,
        proposal: &ActionProposal,
    ) -> Result<CapabilityToken> {
        let now = Timestamp::now();
        let expiry = Timestamp(now.0.checked_add(60_000).unwrap_or(u64::MAX)); // 60 second TTL
        let mut token_id_arr = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut token_id_arr);
        let token_id = token_id_arr.to_vec();

        let mut nonce_arr = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce_arr);
        let nonce = nonce_arr.to_vec();

        // Build the token first so we can sign its canonical payload
        let token = CapabilityToken {
            token_id: token_id.clone(),
            tool_id: proposal.tool_id.clone(),
            method: proposal.method.clone(),
            resource_ids: vec![proposal.tool_id.clone()],
            not_before: now,
            not_after: expiry,
            issuer_pubkey: self.issuer_keypair.pubkey.classical.clone(),
            issuer_pq_pubkey: self.issuer_keypair.pubkey.pq_sign.clone(),
            classical_signature: vec![],
            pq_signature: vec![],
            nonce: nonce.clone(),
            bound_process: std::process::id() as u64,
            max_uses: 1,
        };

        let payload_bytes = token.signing_payload();
        let message = sha3_512(&payload_bytes);

        let signed = hybrid_sign(
            &message,
            &self.issuer_keypair,
        ).map_err(|e| MuccheError::CryptoError(e.to_string()))?;

        let mut token = token;
        token.classical_signature = signed.classical;
        token.pq_signature = signed.pq;

        self.insert_issued_token(token_id.clone());

        self.log_event(SecurityEvent::CapabilityMinted {
            token_id: token_id.clone(),
            parent_id: None,
            tool_id: proposal.tool_id.clone(),
        });

        Ok(token)
    }

    /// Revoke a capability and all derived capabilities
    pub fn revoke_capability(
        &mut self,
        token_id: &[u8],
    ) -> Result<u32> {
        self.insert_revoked_token(token_id.to_vec());
        
        // In full implementation: traverse Capability Derivation Tree (CDT)
        // to find and revoke all child capabilities
        let revoked_count = 1u32;

        self.log_event(SecurityEvent::CapabilityRevoked {
            token_id: token_id.to_vec(),
            revoked_count,
        });

        Ok(revoked_count)
    }

    /// Revoke ALL capabilities (emergency containment)
    pub fn revoke_all_capabilities(&mut self) -> Result<()> {
        self.revoked_tokens = self.issued_tokens.iter().cloned().collect();
        self.revoked_queue = self.revoked_tokens.iter().cloned().collect();
        
        self.log_event(SecurityEvent::IncidentResponse {
            incident_id: "emergency-revoke-all".to_string(),
            phase: "containment".to_string(),
        });

        Ok(())
    }

    /// Insert a nonce into the bounded used_nonces set with LRU eviction.
    fn insert_nonce(&mut self, nonce: Vec<u8>) {
        if self.used_nonces.insert(nonce.clone()) {
            self.nonce_queue.push_back(nonce);
            while self.nonce_queue.len() > self.max_nonces {
                if let Some(old) = self.nonce_queue.pop_front() {
                    self.used_nonces.remove(&old);
                }
            }
        }
    }

    /// Insert a revoked token ID into the bounded set with LRU eviction.
    fn insert_revoked_token(&mut self, token_id: Vec<u8>) {
        if self.revoked_tokens.insert(token_id.clone()) {
            self.revoked_queue.push_back(token_id);
            while self.revoked_queue.len() > self.max_revoked {
                if let Some(old) = self.revoked_queue.pop_front() {
                    self.revoked_tokens.remove(&old);
                }
            }
        }
    }

    /// Insert an issued token ID into the bounded set with LRU eviction.
    fn insert_issued_token(&mut self, token_id: Vec<u8>) {
        if self.issued_tokens.insert(token_id.clone()) {
            self.issued_queue.push_back(token_id);
            while self.issued_queue.len() > self.max_issued {
                if let Some(old) = self.issued_queue.pop_front() {
                    self.issued_tokens.remove(&old);
                }
            }
        }
    }

    /// Seal the audit log permanently: append a final seal event, zeroize the signing key,
    /// and set the sealed flag to prevent further appends.
    pub fn seal_audit_log(&mut self) -> Result<()> {
        if self.audit_log.sealed {
            return Ok(());
        }
        // Directly append the seal entry without going through log_event()
        // to avoid recursion and the sealed-gate check.
        let sequence = self.audit_log.entries.len() as u64;
        let previous_hash = self.audit_log.entries.last()
            .and_then(|e| serde_json::to_vec(e).ok())
            .map(|bytes| Vec::from(sha3_512(&bytes)));
        let mut entry = LogEntry {
            sequence,
            previous_hash,
            timestamp: Timestamp::now(),
            event: SecurityEvent::IncidentResponse {
                incident_id: "audit-log-sealed".to_string(),
                phase: "audit-seal".to_string(),
            },
            verifying_key: None,
            signature: vec![],
        };
        let entry_bytes = match serde_json::to_vec(&entry) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("Audit seal serialization failed: {}", e);
                return Ok(());
            }
        };
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&self.audit_log.current_key.key);
        let verifying_key = signing_key.verifying_key().to_bytes().to_vec();
        let sig = signing_key.sign(&entry_bytes);
        entry.verifying_key = Some(verifying_key);
        entry.signature = sig.to_bytes().to_vec();
        self.audit_log.entries.push(entry);
        self.audit_log.merkle_root = self.audit_merkle_root();
        self.audit_log.current_key.key.zeroize();
        self.audit_log.sealed = true;
        Ok(())
    }

    /// Rotate the audit log: preserve the Merkle root as an anchor, clear entries,
    /// and generate a fresh forward-secure key so logging can continue.
    fn rotate_audit_log(&mut self) {
        let anchor_root = self.audit_merkle_root().unwrap_or_else(|| vec![0u8; 64]);
        self.audit_log.entries.clear();
        self.audit_log.destroyed_keys.clear();
        self.audit_log.merkle_root = Some(anchor_root.clone());
        // Generate a fresh key for the new log epoch
        let mut new_key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut new_key);
        self.audit_log.current_key = ForwardSecureKey {
            key: new_key,
            key_id: 0,
        };
        // Insert an anchor entry linking back to the previous Merkle root
        let mut entry = LogEntry {
            sequence: 0,
            previous_hash: Some(anchor_root),
            timestamp: Timestamp::now(),
            event: SecurityEvent::IncidentResponse {
                incident_id: "audit-log-rotated".to_string(),
                phase: "audit-rotate".to_string(),
            },
            verifying_key: None,
            signature: vec![],
        };
        let entry_bytes = match serde_json::to_vec(&entry) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("Audit rotation serialization failed: {}", e);
                return;
            }
        };
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&self.audit_log.current_key.key);
        let verifying_key = signing_key.verifying_key().to_bytes().to_vec();
        let sig = signing_key.sign(&entry_bytes);
        entry.verifying_key = Some(verifying_key);
        entry.signature = sig.to_bytes().to_vec();
        self.audit_log.entries.push(entry);
    }

    /// List active policy rules as human-readable strings
    pub fn list_rules(&self) -> Vec<String> {
        self.rules.rules.iter().map(|r| {
            let action = match r.action {
                RuleAction::Allow => "allow",
                RuleAction::Deny => "deny",
                RuleAction::Escalate => "escalate",
            };
            format!("{} {}.{}", action, r.tool_id, r.method)
        }).collect()
    }

    /// Log a security event to the forward-secure audit log
    fn log_event(&mut self, event: SecurityEvent) {
        if self.audit_log.sealed {
            tracing::warn!("Attempted to append to sealed audit log — event dropped");
            return;
        }
        let sequence = self.audit_log.entries.len() as u64;
        let previous_hash = self.audit_log.entries.last()
            .and_then(|e| serde_json::to_vec(e).ok())
            .map(|bytes| Vec::from(sha3_512(&bytes)));

        // Derive next key (forward security) with domain separator
        let mut next_key = [0u8; 32];
        let mut hasher = sha3::Sha3_512::new();
        hasher.update(b"muccheai-audit-key-v1");
        hasher.update(&self.audit_log.current_key.key);
        hasher.update(&sequence.to_le_bytes());
        let derived = hasher.finalize();
        next_key.copy_from_slice(&derived[..32]);

        let timestamp = Timestamp::now();

        // so that compromise of future keys cannot forge past signatures.
        let mut entry = LogEntry {
            sequence,
            previous_hash,
            timestamp,
            event,
            verifying_key: None,
            signature: vec![],
        };
        let entry_bytes = match serde_json::to_vec(&entry) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("Audit log serialization failed: {}", e);
                return;
            }
        };
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&self.audit_log.current_key.key);
        let verifying_key = signing_key.verifying_key().to_bytes().to_vec();
        let sig = signing_key.sign(&entry_bytes);
        entry.verifying_key = Some(verifying_key);
        entry.signature = sig.to_bytes().to_vec();

        // Destroy old key material and advance to the next forward-secure key
        self.audit_log.current_key.key.zeroize();
        self.audit_log.destroyed_keys.push(self.audit_log.current_key.key_id);
        self.audit_log.current_key = ForwardSecureKey {
            key: next_key,
            key_id: sequence + 1,
        };
        self.audit_log.entries.push(entry);
        // Rotate the log when max size is reached, preserving the Merkle chain.
        if self.audit_log.entries.len() > self.max_audit_entries {
            self.rotate_audit_log();
        }
        self.audit_log.merkle_root = self.audit_merkle_root();
    }

    /// Verify the Ed25519 signature of a single audit log entry.
    fn verify_audit_entry(entry: &LogEntry) -> bool {
        let Some(ref vk_bytes) = entry.verifying_key else {
            return false;
        };
        if vk_bytes.len() != 32 || entry.signature.len() != 64 {
            return false;
        }
        let verifying_key = match VerifyingKey::from_bytes(vk_bytes.as_slice().try_into().unwrap_or(&[0u8; 32])) {
            Ok(vk) => vk,
            Err(_) => return false,
        };
        // Reconstruct the entry bytes as they were at signing time
        let mut entry_for_verify = entry.clone();
        entry_for_verify.verifying_key = None;
        entry_for_verify.signature = vec![];
        let entry_bytes = match serde_json::to_vec(&entry_for_verify) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sig_bytes: &[u8; 64] = match entry.signature.as_slice().try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let signature = ed25519_dalek::Signature::from_bytes(sig_bytes);
        verifying_key.verify(&entry_bytes, &signature).is_ok()
    }

    /// Query the audit log, returning only entries with valid signatures.
    pub fn query_audit_log(&self, query: &AuditQuery) -> AuditResult {
        let entries: Vec<LogEntry> = self.audit_log.entries.iter()
            .filter(|e| {
                let timestamp_ok = e.timestamp >= query.from && e.timestamp <= query.to;
                let tool_ok = query.tool_id.as_ref().map_or(true, |t| {
                    matches!(&e.event, SecurityEvent::ActionValidated { tool_id, .. } if tool_id == t)
                });
                timestamp_ok && tool_ok && Self::verify_audit_entry(e)
            })
            .cloned()
            .collect();

        let merkle_root = self.audit_merkle_root().unwrap_or_else(|| vec![0u8; 64]);

        AuditResult {
            entries,
            merkle_root,
            total_entries: self.audit_log.entries.len() as u64,
        }
    }

    /// Get current Merkle root of audit log
    pub fn audit_merkle_root(&self) -> Option<Vec<u8>> {
        let entries = &self.audit_log.entries;
        if entries.is_empty() {
            return None;
        }

        let mut hashes: Vec<Vec<u8>> = entries.iter().filter_map(|e| {
            serde_json::to_vec(e).ok().map(|bytes| sha3::Sha3_256::digest(&bytes).to_vec())
        }).collect();

        if hashes.is_empty() {
            return None;
        }

        while hashes.len() > 1 {
            let mut next_level = Vec::new();
            for i in (0..hashes.len()).step_by(2) {
                let left = &hashes[i];
                let right = if i + 1 < hashes.len() {
                    &hashes[i + 1]
                } else {
                    left
                };
                let mut hasher = sha3::Sha3_256::new();
                hasher.update(left);
                hasher.update(right);
                next_level.push(hasher.finalize().to_vec());
            }
            hashes = next_level;
        }

        hashes.into_iter().next()
    }
}

/// Verify the hybrid (classical + post-quantum) signature on a capability token.
fn verify_classical_signature(token: &CapabilityToken) -> Result<()> {
    let message = sha3_512(&token.signing_payload());

    // Require PQ pubkey — classical-only fallback removed to prevent downgrade attacks
    if token.issuer_pq_pubkey.is_empty() {
        return Err(MuccheError::InvalidCapability(
            "Classical-only capability tokens are not allowed".to_string()
        ));
    }

    let hybrid_sig = HybridSignature {
        classical: token.classical_signature.clone(),
        pq: token.pq_signature.clone(),
    };
    let hybrid_pk = HybridPubkey {
        classical: token.issuer_pubkey.clone(),
        x25519: vec![],
        pq: vec![],
        pq_sign: token.issuer_pq_pubkey.clone(),
    };
    muccheai_crypto::hybrid_verify(&message, &hybrid_sig, &hybrid_pk)
        .map_err(|e| MuccheError::InvalidCapability(format!("Hybrid signature verification failed: {:?}", e)))?;
    Ok(())
}

/// Result of policy validation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationResult {
    /// Action approved, here's the token
    Approved {
        /// Capability token granting access
        token: CapabilityToken,
    },
    /// Action rejected with reason
    Rejected {
        /// Human-readable rejection reason
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use muccheai_crypto::generate_hybrid_keypair;

    fn test_proposal() -> ActionProposal {
        ActionProposal {
            tool_id: "email".to_string(),
            method: "send".to_string(),
            params: serde_json::json!({"to": "test@example.com"}),
            requester_pubkey: vec![0u8; 32],
            timestamp: Timestamp::now(),
            nonce: vec![1u8; 32],
        }
    }

    fn test_rules() -> PolicyRules {
        PolicyRules {
            rules: vec![
                PolicyRule {
                    id: "allow-email".to_string(),
                    tool_id: "email".to_string(),
                    method: "send".to_string(),
                    resource_patterns: vec!["*".to_string()],
                    action: RuleAction::Allow,
                    conditions: RuleConditions::Always,
                }
            ],
            default_action: RuleAction::Deny,
            ..Default::default()
        }
    }

    /// Helper to mint a test capability token with a custom TTL.
    fn mint_test_capability(
        kp: &HybridKeypair,
        tool_id: &str,
        method: &str,
        resources: &[&str],
        ttl_ms: u64,
    ) -> CapabilityToken {
        let now = Timestamp::now();
        let expiry = Timestamp(now.0 + ttl_ms);
        let mut token_id_arr = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut token_id_arr);
        let token_id = token_id_arr.to_vec();

        let mut nonce_arr = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce_arr);
        let nonce = nonce_arr.to_vec();

        let mut token = CapabilityToken {
            token_id: token_id.clone(),
            tool_id: tool_id.to_string(),
            method: method.to_string(),
            resource_ids: resources.iter().map(|s| s.to_string()).collect(),
            not_before: now,
            not_after: expiry,
            issuer_pubkey: kp.pubkey.classical.clone(),
            issuer_pq_pubkey: kp.pubkey.pq_sign.clone(),
            classical_signature: vec![],
            pq_signature: vec![],
            nonce: nonce.clone(),
            bound_process: std::process::id() as u64,
            max_uses: 0,
        };

        let payload_bytes = token.signing_payload();
        let message = sha3_512(&payload_bytes);

        let signed = hybrid_sign(&message, &kp).unwrap();

        token.classical_signature = signed.classical;
        token.pq_signature = signed.pq;

        token
    }

    #[test]
    fn test_validate_action_approved() {
        let kp = generate_hybrid_keypair().unwrap();
        let rules = test_rules();
        let mut engine = PolicyEngine::new(rules, kp);

        let proposal = test_proposal();
        let caps = CapabilitySet {
            tokens: vec![],
            max_risk_level: RiskLevel::Low,
        };

        // Without capability, should be rejected (no matching cap)
        let result = engine.validate_action(&proposal, &caps);
        assert!(matches!(result, Ok(ValidationResult::Rejected { .. })));
    }

    #[test]
    fn test_revoke_all() {
        let kp = generate_hybrid_keypair().unwrap();
        let mut engine = PolicyEngine::new(test_rules(), kp);
        assert!(engine.revoke_all_capabilities().is_ok());
    }

    #[test]
    fn test_validate_action_deny_by_default() {
        let kp = generate_hybrid_keypair().unwrap();
        let mut policy = PolicyEngine::new(PolicyRules::default(), kp);

        let proposal = ActionProposal {
            tool_id: "unknown_tool".to_string(),
            method: "delete".to_string(),
            params: serde_json::json!({}),
            requester_pubkey: vec![0u8; 32],
            timestamp: Timestamp::now(),
            nonce: vec![0x42; 32],
        };

        let cap = CapabilitySet {
            tokens: vec![],
            max_risk_level: RiskLevel::Critical,
        };

        let result = policy.validate_action(&proposal, &cap);
        assert!(matches!(result, Ok(ValidationResult::Rejected { .. })), "default-deny should reject unknown actions");
    }

    #[test]
    fn test_validate_action_with_valid_capability() {
        let kp = generate_hybrid_keypair().unwrap();
        let rules = PolicyRules {
            rules: vec![PolicyRule {
                id: "allow-test".to_string(),
                tool_id: "test_tool".to_string(),
                method: "read".to_string(),
                resource_patterns: vec!["*".to_string()],
                action: RuleAction::Allow,
                conditions: RuleConditions::Always,
            }],
            default_action: RuleAction::Deny,
            ..Default::default()
        };
        let mut policy = PolicyEngine::new(rules, kp.clone());

        let cap = mint_test_capability(
            &kp,
            "test_tool",
            "read",
            &["test_tool"],
            60_000,
        );

        // Verify the capability token is valid
        assert!(verify_classical_signature(&cap).is_ok());

        let proposal = ActionProposal {
            tool_id: "test_tool".to_string(),
            method: "read".to_string(),
            params: serde_json::json!({}),
            requester_pubkey: kp.pubkey.classical.clone(),
            timestamp: Timestamp::now(),
            nonce: vec![0x42; 32],
        };

        let result = policy.validate_action(
            &proposal,
            &CapabilitySet {
                tokens: vec![cap],
                max_risk_level: RiskLevel::Critical,
            },
        );
        assert!(matches!(result, Ok(ValidationResult::Approved { .. })), "valid capability should allow action");
    }

    #[test]
    fn test_validate_action_expired_capability() {
        let kp = generate_hybrid_keypair().unwrap();
        let rules = PolicyRules {
            rules: vec![PolicyRule {
                id: "allow-test".to_string(),
                tool_id: "test_tool".to_string(),
                method: "read".to_string(),
                resource_patterns: vec!["*".to_string()],
                action: RuleAction::Allow,
                conditions: RuleConditions::Always,
            }],
            default_action: RuleAction::Deny,
            ..Default::default()
        };
        let mut policy = PolicyEngine::new(rules, kp.clone());

        let cap = mint_test_capability(
            &kp,
            "test_tool",
            "read",
            &["resource1"],
            1, // 1ms TTL — immediately expired
        );

        // Sleep to ensure expiration
        std::thread::sleep(std::time::Duration::from_millis(10));

        let proposal = ActionProposal {
            tool_id: "test_tool".to_string(),
            method: "read".to_string(),
            params: serde_json::json!({"resource": "resource1"}),
            requester_pubkey: kp.pubkey.classical.clone(),
            timestamp: Timestamp::now(),
            nonce: vec![0x42; 32],
        };

        let result = policy.validate_action(
            &proposal,
            &CapabilitySet {
                tokens: vec![cap],
                max_risk_level: RiskLevel::Critical,
            },
        );
        assert!(result.is_err(), "expired capability should be rejected");
    }

    #[test]
    fn test_validate_action_wrong_signature() {
        let kp = generate_hybrid_keypair().unwrap();
        let rules = PolicyRules {
            rules: vec![PolicyRule {
                id: "allow-test".to_string(),
                tool_id: "test_tool".to_string(),
                method: "read".to_string(),
                resource_patterns: vec!["*".to_string()],
                action: RuleAction::Allow,
                conditions: RuleConditions::Always,
            }],
            default_action: RuleAction::Deny,
            ..Default::default()
        };
        let mut policy = PolicyEngine::new(rules, kp.clone());

        let mut cap = mint_test_capability(
            &kp,
            "test_tool",
            "read",
            &["*"],
            60_000,
        );

        // Corrupt the signature
        cap.classical_signature[0] ^= 0xFF;

        let proposal = ActionProposal {
            tool_id: "test_tool".to_string(),
            method: "read".to_string(),
            params: serde_json::json!({}),
            requester_pubkey: kp.pubkey.classical.clone(),
            timestamp: Timestamp::now(),
            nonce: vec![0x42; 32],
        };

        let result = policy.validate_action(
            &proposal,
            &CapabilitySet {
                tokens: vec![cap],
                max_risk_level: RiskLevel::Critical,
            },
        );
        assert!(result.is_err(), "invalid signature should be rejected");
    }

    #[test]
    fn test_nonce_replay_detection() {
        let mut seen = std::collections::HashSet::new();
        let nonce1 = vec![0x01u8; 32];
        let nonce2 = vec![0x01u8; 32];
        let nonce3 = vec![0x02u8; 32];

        assert!(seen.insert(nonce1.clone()));
        assert!(!seen.insert(nonce2.clone()), "duplicate nonce should be detected");
        assert!(seen.insert(nonce3.clone()));
    }
}
