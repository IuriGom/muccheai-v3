//! Inter-agent federation.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use muccheai_types::*;
use muccheai_types::capabilities::*;
use muccheai_types::crypto_primitives::*;

/// W3C DID for agent identification
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DID {
    /// DID method
    pub method: String,
    /// DID identifier
    pub identifier: String,
}

impl std::fmt::Display for DID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "did:{}:{}", self.method, self.identifier)
    }
}

/// Cross-agent capability delegation
#[derive(Debug, Clone)]
pub struct CrossAgentDelegation {
    /// Issuer agent DID
    pub issuer: DID,
    /// Subject agent DID
    pub subject: DID,
    /// Attenuated capability
    pub attenuated_capability: AttenuatedCapability,
    /// Valid from
    pub not_before: Timestamp,
    /// Valid until
    pub not_after: Timestamp,
    /// Delegation proof (signed by issuer)
    pub proof: DelegationProof,
}

/// Proof of delegation
#[derive(Debug, Clone)]
pub struct DelegationProof {
    /// Ed25519 signature
    pub classical_sig: Vec<u8>,
    /// ML-DSA signature
    pub pq_sig: Vec<u8>,
    /// Issuer public key
    pub issuer_pubkey: HybridPubkey,
}

/// Ephemeral federation for temporary task coalitions
#[derive(Debug, Clone)]
pub struct EphemeralFederation {
    /// Task ID
    pub task_id: String,
    /// Federation members
    pub members: Vec<FederationMember>,
    /// Shared capabilities
    pub shared_capabilities: Vec<CapabilityToken>,
    /// Auto-revoke timestamp
    pub auto_revoke: Timestamp,
}

/// Federation member
#[derive(Debug, Clone)]
pub struct FederationMember {
    /// Member DID
    pub did: DID,
    /// Member public key
    pub pubkey: HybridPubkey,
    /// Role in federation
    pub role: FederationRole,
}

/// Role in federation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FederationRole {
    /// Task coordinator
    Coordinator,
    /// Task participant
    Participant,
    /// Observer
    Observer,
}

/// Cross-agent delegation operations
impl CrossAgentDelegation {
    /// Create attenuated delegation from parent capability
    pub fn attenuate(
        parent: &CapabilityToken,
        restrictions: &RestrictionSet,
        issuer_keypair: &HybridKeypair,
    ) -> Result<Self> {
        // Verify child resources are a subset of parent resources
        for child_res in &restrictions.resource_ids {
            if !parent.covers_resource(child_res) {
                return Err(MuccheError::InvalidCapability(
                    format!(
                        "Attenuation violation: child resource '{}' exceeds parent scope",
                        child_res
                    )
                ));
            }
        }

        // Verify child temporal bounds do not exceed parent bounds
        if restrictions.not_before < parent.not_before {
            return Err(MuccheError::InvalidCapability(
                "Attenuation violation: child not_before exceeds parent".to_string()
            ));
        }
        if restrictions.not_after > parent.not_after {
            return Err(MuccheError::InvalidCapability(
                "Attenuation violation: child not_after exceeds parent".to_string()
            ));
        }
        if restrictions.max_uses > parent.max_uses && parent.max_uses > 0 {
            return Err(MuccheError::InvalidCapability(
                "Attenuation violation: child max_uses exceeds parent".to_string()
            ));
        }

        let child = AttenuatedCapability {
            parent_token_id: parent.token_id.clone(),
            resource: ResourceRestriction {
                allowed_patterns: restrictions.resource_ids.clone(),
            },
            constraints: CapabilityConstraints {
                not_before: restrictions.not_before,
                not_after: restrictions.not_after,
                max_uses: restrictions.max_uses,
                use_count: 0,
            },
        };

        // Sign delegation using canonical serialization
        let payload = serde_json::to_vec(&child)
            .map_err(|e| MuccheError::Internal(format!("Serialization error: {}", e)))?;
        let sig = muccheai_crypto::hybrid_sign(&payload, &issuer_keypair)
            .map_err(|e| MuccheError::CryptoError(e.to_string()))?;

        Ok(CrossAgentDelegation {
            issuer: restrictions.issuer_did.clone(),
            subject: restrictions.subject_did.clone(),
            attenuated_capability: child,
            not_before: restrictions.not_before,
            not_after: restrictions.not_after,
            proof: DelegationProof {
                classical_sig: sig.classical.clone(),
                pq_sig: sig.pq,
                issuer_pubkey: issuer_keypair.pubkey.clone(),
            },
        })
    }

    /// Verify delegation proof using hybrid signature verification
    pub fn verify(&self) -> Result<()> {
        // Check temporal validity
        let now = Timestamp::now();
        if now < self.not_before || now >= self.not_after {
            return Err(MuccheError::InvalidCapability("Delegation expired".to_string()));
        }

        // Verify hybrid signature over the attenuated capability
        let payload = serde_json::to_vec(&self.attenuated_capability)
            .map_err(|e| MuccheError::Internal(format!("Serialization error: {}", e)))?;
        let sig = HybridSignature {
            classical: self.proof.classical_sig.clone(),
            pq: self.proof.pq_sig.clone(),
        };
        muccheai_crypto::hybrid_verify(&payload, &sig, &self.proof.issuer_pubkey)
            .map_err(|e| MuccheError::CryptoError(format!("Delegation signature invalid: {}", e)))?;

        Ok(())
    }
}

/// Restrictions for capability attenuation
#[derive(Debug, Clone)]
pub struct RestrictionSet {
    /// Issuer DID
    pub issuer_did: DID,
    /// Subject DID
    pub subject_did: DID,
    /// Resource restrictions
    pub resource_ids: Vec<String>,
    /// Not valid before this timestamp
    pub not_before: Timestamp,
    /// Not valid after this timestamp
    pub not_after: Timestamp,
    /// Maximum number of uses
    pub max_uses: u64,
}

/// Ephemeral federation operations
impl EphemeralFederation {
    /// Create new federation for a task
    pub fn new(task_id: String, members: Vec<FederationMember>, ttl_seconds: u64) -> Self {
        let now = Timestamp::now();
        Self {
            task_id,
            members,
            shared_capabilities: vec![],
            auto_revoke: Timestamp(now.0 + ttl_seconds * 1000),
        }
    }

    /// Check if federation is still valid
    pub fn is_valid(&self) -> bool {
        Timestamp::now() < self.auto_revoke
    }

    /// Revoke all shared capabilities
    pub fn revoke_all(&mut self) {
        self.shared_capabilities.clear();
        self.auto_revoke = Timestamp::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_formatting() {
        let did = DID {
            method: "muccheai".to_string(),
            identifier: "abc123".to_string(),
        };
        assert_eq!(did.to_string(), "did:muccheai:abc123");
    }

    #[test]
    fn test_did_display() {
        let did = DID {
            method: "muccheai".to_string(),
            identifier: "agent-1".to_string(),
        };
        let formatted = format!("{}", did);
        assert_eq!(formatted, "did:muccheai:agent-1");
    }

    #[test]
    fn test_federation_lifecycle() {
        let member = FederationMember {
            did: DID { method: "muccheai".to_string(), identifier: "agent1".to_string() },
            pubkey: HybridPubkey { classical: vec![0u8; 32], x25519: vec![0u8; 32], pq: vec![], pq_sign: vec![] },
            role: FederationRole::Coordinator,
        };

        let mut federation = EphemeralFederation::new(
            "task-123".to_string(),
            vec![member],
            3600,
        );

        assert!(federation.is_valid());
        federation.revoke_all();
        assert!(!federation.is_valid());
    }

    #[test]
    fn test_attenuate_subset_verification() {
        let parent = CapabilityToken {
            token_id: vec![1u8; 32],
            tool_id: "email".to_string(),
            method: "send".to_string(),
            resource_ids: vec!["inbox/*".to_string(), "drafts/*".to_string()],
            not_before: Timestamp::now(),
            not_after: Timestamp(Timestamp::now().0 + 3600000),
            issuer_pubkey: vec![0u8; 32],
            issuer_pq_pubkey: vec![0u8; 1312],
            classical_signature: vec![0u8; 64],
            pq_signature: vec![0u8; 2420],
            nonce: vec![0u8; 32],
            bound_process: 0,
            max_uses: 0,
        };

        let issuer_kp = muccheai_crypto::generate_hybrid_keypair().unwrap();

        // Valid attenuation: child resources are subset of parent
        let valid_restrictions = RestrictionSet {
            issuer_did: DID { method: "muccheai".to_string(), identifier: "a".to_string() },
            subject_did: DID { method: "muccheai".to_string(), identifier: "b".to_string() },
            resource_ids: vec!["inbox/work".to_string()],
            not_before: Timestamp::now(),
            not_after: Timestamp(Timestamp::now().0 + 1800000),
            max_uses: 5,
        };

        let delegation = CrossAgentDelegation::attenuate(&parent, &valid_restrictions, &issuer_kp);
        assert!(delegation.is_ok());

        // Invalid attenuation: child resource exceeds parent scope
        let invalid_restrictions = RestrictionSet {
            issuer_did: DID { method: "muccheai".to_string(), identifier: "a".to_string() },
            subject_did: DID { method: "muccheai".to_string(), identifier: "b".to_string() },
            resource_ids: vec!["sent/*".to_string()],
            not_before: Timestamp::now(),
            not_after: Timestamp(Timestamp::now().0 + 1800000),
            max_uses: 5,
        };

        let bad = CrossAgentDelegation::attenuate(&parent, &invalid_restrictions, &issuer_kp);
        assert!(bad.is_err());
    }

    #[test]
    fn test_delegation_verify() {
        let parent = CapabilityToken {
            token_id: vec![1u8; 32],
            tool_id: "calendar".to_string(),
            method: "read".to_string(),
            resource_ids: vec!["*".to_string()],
            not_before: Timestamp::now(),
            not_after: Timestamp(Timestamp::now().0 + 3600000),
            issuer_pubkey: vec![0u8; 32],
            issuer_pq_pubkey: vec![0u8; 1312],
            classical_signature: vec![0u8; 64],
            pq_signature: vec![0u8; 2420],
            nonce: vec![0u8; 32],
            bound_process: 0,
            max_uses: 0,
        };

        let issuer_kp = muccheai_crypto::generate_hybrid_keypair().unwrap();
        let restrictions = RestrictionSet {
            issuer_did: DID { method: "muccheai".to_string(), identifier: "a".to_string() },
            subject_did: DID { method: "muccheai".to_string(), identifier: "b".to_string() },
            resource_ids: vec!["freebusy".to_string()],
            not_before: Timestamp::now(),
            not_after: Timestamp(Timestamp::now().0 + 1800000),
            max_uses: 10,
        };

        let delegation = CrossAgentDelegation::attenuate(&parent, &restrictions, &issuer_kp).unwrap();
        assert!(delegation.verify().is_ok());
    }
}
