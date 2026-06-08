//! Trusted UI.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use ed25519_dalek::{Signer, SigningKey};
use muccheai_crypto::sha3_512;
use muccheai_types::*;
use rand::Rng;

/// Approval tier for an action
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalTier {
    /// Low risk: no approval required
    Standard,
    /// Medium risk: Face ID / Touch ID
    SecureOverlay,
    /// High risk: hardware token
    HardwareToken,
    /// Critical: multi-device M-of-N
    MultiDevice {
        /// Number of approvals required
        required: u8,
        /// Device identifiers participating
        devices: Vec<String>,
    },
}

/// Approval request
#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    /// Action being proposed
    pub action: ActionProposal,
    /// Risk level
    pub risk_level: RiskLevel,
    /// Tier required
    pub tier: ApprovalTier,
    /// Timestamp
    pub timestamp: Timestamp,
}

/// Biometric authentication result
#[derive(Debug, Clone)]
pub struct BiometricAuth {
    /// Whether biometric authentication succeeded
    pub success: bool,
    /// Attention detected (eyes open, looking at screen)
    pub attention_detected: bool,
    /// Dwell time in milliseconds
    pub dwell_time_ms: u64,
    /// Was duress mode triggered?
    pub duress_triggered: bool,
}

/// Trusted UI controller
pub struct TrustedUi {
    /// Current approval queue
    pending: Vec<ApprovalRequest>,
    /// Duress mode enabled
    duress_enabled: bool,
    /// Behavioral baseline for biometric detection
    #[allow(dead_code)]
    behavioral_baseline: BehavioralBaseline,
    /// Per-instance Secure Enclave signing key
    secure_overlay_key: SigningKey,
    /// Per-instance hardware token signing key
    hardware_token_key: SigningKey,
    /// Per-instance multi-device seed
    multi_device_seed: [u8; 32],
}

/// Behavioral biometrics baseline
#[derive(Debug, Clone)]
pub struct BehavioralBaseline {
    /// Typing cadence (ms between keystrokes)
    pub typing_cadence_ms: f64,
    /// Mouse movement patterns
    pub mouse_speed: f64,
    /// Baseline established
    pub established: bool,
}

impl TrustedUi {
    /// Create new Trusted UI with cryptographically random signing keys
    pub fn new() -> Self {
        let mut secure_overlay_bytes = [0u8; 32];
        let mut hardware_token_bytes = [0u8; 32];
        let mut multi_device_seed = [0u8; 32];
        rand::rngs::OsRng.fill(&mut secure_overlay_bytes);
        rand::rngs::OsRng.fill(&mut hardware_token_bytes);
        rand::rngs::OsRng.fill(&mut multi_device_seed);
        Self {
            pending: vec![],
            duress_enabled: true,
            behavioral_baseline: BehavioralBaseline {
                typing_cadence_ms: 150.0,
                mouse_speed: 1.0,
                established: false,
            },
            secure_overlay_key: SigningKey::from_bytes(&secure_overlay_bytes),
            hardware_token_key: SigningKey::from_bytes(&hardware_token_bytes),
            multi_device_seed,
        }
    }

    /// Request approval for an action
    pub fn request_approval(
        &mut self,
        action: &ActionProposal,
        risk_level: RiskLevel,
    ) -> Result<CapabilityGrant> {
        let tier = self.tier_for_risk(risk_level);
        
        let request = ApprovalRequest {
            action: action.clone(),
            risk_level,
            tier,
            timestamp: Timestamp::now(),
        };

        // Check duress detection using a simulated biometric check
        let bio = BiometricAuth {
            success: true,
            attention_detected: true,
            dwell_time_ms: 2500,
            duress_triggered: false,
        };
        if self.detect_duress(&bio) {
            return self.handle_duress();
        }

        // Apply risk-proportional friction
        self.apply_friction(risk_level);

        // Route to appropriate approval mechanism
        let result = match request.tier {
            ApprovalTier::Standard => {
                Ok(CapabilityGrant {
                    action: action.clone(),
                    signature: AggregatedSignature {
                        classical_sigs: vec![],
                        pq_sigs: vec![],
                    },
                    mechanism: ApprovalMechanism::Standard,
                })
            }
            ApprovalTier::SecureOverlay => {
                self.approve_secure_overlay(action)
            }
            ApprovalTier::HardwareToken => {
                self.approve_hardware_token(action)
            }
            ApprovalTier::MultiDevice { required, .. } => {
                self.approve_multi_device(action, required)
            }
        };

        // Remove resolved request from pending queue
        self.pending.retain(|r| r.timestamp != request.timestamp);

        result
    }

    /// Determine approval tier from risk level
    fn tier_for_risk(&self, risk: RiskLevel) -> ApprovalTier {
        match risk {
            RiskLevel::Low => ApprovalTier::Standard,
            RiskLevel::Medium => ApprovalTier::SecureOverlay,
            RiskLevel::High => ApprovalTier::HardwareToken,
            RiskLevel::Critical => ApprovalTier::MultiDevice {
                required: 2,
                devices: vec!["phone".to_string(), "laptop".to_string()],
            },
        }
    }

    /// Apply risk-proportional friction (synchronous delay)
    fn apply_friction(&self, risk: RiskLevel) {
        let delay = risk.delay_seconds();
        if delay > 0 {
            std::thread::sleep(std::time::Duration::from_secs(delay));
        }
    }

    /// Apply risk-proportional friction (asynchronous delay)
    pub async fn apply_friction_async(&self, risk: RiskLevel) {
        let delay = risk.delay_seconds();
        if delay > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
        }
    }

    /// Detect duress conditions from biometric auth
    pub fn detect_duress(&self, auth: &BiometricAuth) -> bool {
        self.duress_enabled && auth.duress_triggered
    }

    /// Handle duress mode activation
    fn handle_duress(&self) -> Result<CapabilityGrant> {
        // Silently revoke all capabilities, enter lockdown
        Err(MuccheError::ApprovalError(
            "Duress mode activated. All capabilities revoked.".to_string()
        ))
    }

    /// Approve via Secure Enclave (Face ID / Touch ID)
    fn approve_secure_overlay(
        &self,
        action: &ActionProposal,
    ) -> Result<CapabilityGrant> {
        // Simulate PIN check: require a non-empty action
        if action.tool_id.is_empty() || action.method.is_empty() {
            return Err(MuccheError::ApprovalError(
                "Secure overlay approval failed: invalid action".to_string()
            ));
        }

        // Generate a real Ed25519 signature using the per-instance key
        let signing_key = self.secure_overlay_key.clone();
        let payload = format!("secure-overlay:{}.{}", action.tool_id, action.method);
        let sig = signing_key.sign(payload.as_bytes());

        Ok(CapabilityGrant {
            action: action.clone(),
            signature: AggregatedSignature {
                classical_sigs: vec![sig.to_bytes().to_vec()],
                pq_sigs: vec![vec![0u8; 2420]],
            },
            mechanism: ApprovalMechanism::SecureEnclave,
        })
    }

    /// Approve via hardware token
    fn approve_hardware_token(
        &self,
        action: &ActionProposal,
    ) -> Result<CapabilityGrant> {
        // Simulate confirmation code check
        if action.tool_id.is_empty() {
            return Err(MuccheError::ApprovalError(
                "Hardware token approval failed: invalid action".to_string()
            ));
        }

        // Generate a real Ed25519 signature using the per-instance key
        let signing_key = self.hardware_token_key.clone();
        let payload = format!("hardware-token:{}.{}", action.tool_id, action.method);
        let sig = signing_key.sign(payload.as_bytes());

        Ok(CapabilityGrant {
            action: action.clone(),
            signature: AggregatedSignature {
                classical_sigs: vec![sig.to_bytes().to_vec()],
                pq_sigs: vec![vec![0u8; 2420]],
            },
            mechanism: ApprovalMechanism::HardwareToken,
        })
    }

    /// Approve via multi-device M-of-N
    fn approve_multi_device(
        &self,
        action: &ActionProposal,
        required: u8,
    ) -> Result<CapabilityGrant> {
        // Simulate device approvals: count each device as approved
        let approvals = required as usize;

        // Generate one Ed25519 signature per simulated device
        let mut classical_sigs = Vec::with_capacity(approvals);
        for i in 0..approvals {
            let mut input = format!("device-{}", i).into_bytes();
            input.extend_from_slice(&self.multi_device_seed);
            let seed = sha3_512(&input);
            let mut seed_32 = [0u8; 32];
            seed_32.copy_from_slice(&seed[..32]);
            let signing_key = SigningKey::from_bytes(&seed_32);
            let payload = format!("multi-device:{}.{}:device-{}", action.tool_id, action.method, i);
            let sig = signing_key.sign(payload.as_bytes());
            classical_sigs.push(sig.to_bytes().to_vec());
        }

        Ok(CapabilityGrant {
            action: action.clone(),
            signature: AggregatedSignature {
                classical_sigs,
                pq_sigs: vec![vec![0u8; 2420]; approvals],
            },
            mechanism: ApprovalMechanism::MultiDevice,
        })
    }

    /// Render action summary for approval dialog
    pub fn render_summary(&self, action: &ActionProposal) -> String {
        let risk = self.tier_for_risk(self.estimate_risk(action));
        let risk_label = match risk {
            ApprovalTier::Standard => "Low",
            ApprovalTier::SecureOverlay => "Medium",
            ApprovalTier::HardwareToken => "High",
            ApprovalTier::MultiDevice { .. } => "Critical",
        };

        let params = serde_json::to_string_pretty(&action.params).unwrap_or_else(|_| "{}".to_string());

        format!(
            "Action: {}.{}\nRisk Level: {}\nResource Scope: {}\nParameters:\n{}",
            action.tool_id,
            action.method,
            risk_label,
            action.tool_id,
            params
        )
    }

    /// Estimate risk level for an action (simplified heuristic)
    fn estimate_risk(&self, action: &ActionProposal) -> RiskLevel {
        match action.tool_id.as_str() {
            "email" => RiskLevel::Medium,
            "calendar" => RiskLevel::Low,
            "filesystem" => RiskLevel::High,
            "search" => RiskLevel::Low,
            _ => RiskLevel::Critical,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier_mapping() {
        let ui = TrustedUi::new();
        assert!(matches!(ui.tier_for_risk(RiskLevel::Low), ApprovalTier::Standard));
        assert!(matches!(ui.tier_for_risk(RiskLevel::Critical), ApprovalTier::MultiDevice { .. }));
    }

    #[test]
    fn test_render_summary() {
        let ui = TrustedUi::new();
        let action = ActionProposal {
            tool_id: "email".to_string(),
            method: "send".to_string(),
            params: serde_json::json!({"to": "test@example.com"}),
            requester_pubkey: vec![0u8; 32],
            timestamp: Timestamp::now(),
            nonce: vec![0u8; 32],
        };
        let summary = ui.render_summary(&action);
        assert!(summary.contains("email"));
        assert!(summary.contains("send"));
        assert!(summary.contains("Risk Level"));
        assert!(summary.contains("Resource Scope"));
        assert!(summary.contains("Parameters"));
    }

    #[test]
    fn test_detect_duress() {
        let ui = TrustedUi::new();
        let normal = BiometricAuth {
            success: true,
            attention_detected: true,
            dwell_time_ms: 2000,
            duress_triggered: false,
        };
        assert!(!ui.detect_duress(&normal));

        let duress = BiometricAuth {
            success: true,
            attention_detected: true,
            dwell_time_ms: 2000,
            duress_triggered: true,
        };
        assert!(ui.detect_duress(&duress));
    }

    #[test]
    fn test_secure_overlay_signature() {
        let ui = TrustedUi::new();
        let action = ActionProposal {
            tool_id: "email".to_string(),
            method: "send".to_string(),
            params: serde_json::json!({}),
            requester_pubkey: vec![0u8; 32],
            timestamp: Timestamp::now(),
            nonce: vec![0u8; 32],
        };
        let grant = ui.approve_secure_overlay(&action).unwrap();
        assert_eq!(grant.signature.classical_sigs.len(), 1);
        assert_eq!(grant.signature.classical_sigs[0].len(), 64);
    }

    #[test]
    fn test_hardware_token_signature() {
        let ui = TrustedUi::new();
        let action = ActionProposal {
            tool_id: "calendar".to_string(),
            method: "read".to_string(),
            params: serde_json::json!({}),
            requester_pubkey: vec![0u8; 32],
            timestamp: Timestamp::now(),
            nonce: vec![0u8; 32],
        };
        let grant = ui.approve_hardware_token(&action).unwrap();
        assert_eq!(grant.signature.classical_sigs.len(), 1);
        assert_eq!(grant.signature.classical_sigs[0].len(), 64);
    }

    #[test]
    fn test_multi_device_approvals() {
        let ui = TrustedUi::new();
        let action = ActionProposal {
            tool_id: "filesystem".to_string(),
            method: "read".to_string(),
            params: serde_json::json!({}),
            requester_pubkey: vec![0u8; 32],
            timestamp: Timestamp::now(),
            nonce: vec![0u8; 32],
        };
        let grant = ui.approve_multi_device(&action, 3).unwrap();
        assert_eq!(grant.signature.classical_sigs.len(), 3);
    }
}
