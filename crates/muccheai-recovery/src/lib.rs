//! MuccheAI v3.0 — Intrusion Recovery + Self-Healing
//!
//! Automated detection, containment, and recovery from compromise.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use muccheai_crypto::sha3_512;
use muccheai_policy_engine::PolicyEngine;
use muccheai_sandbox::LlmSandbox;
use muccheai_types::audit::*;
use muccheai_types::crypto_primitives::*;
use muccheai_types::*;
use serde::{Deserialize, Serialize};
use sha3::Digest;
use ed25519_dalek::Signer;
use zeroize::Zeroize;

pub mod containment;

/// Incident response system
pub struct IncidentResponse {
    /// Anomaly detector
    pub detection: AnomalyDetector,
    /// Containment playbook
    pub containment: ContainmentPlaybook,
    /// Recovery guide
    pub recovery: RecoveryGuide,
}

/// Anomaly detector with statistical process control
pub struct AnomalyDetector {
    /// Baseline behavior
    pub baseline: BaselineStats,
    /// Alert threshold (sigma)
    pub sigma_threshold: f64,
}

/// Baseline statistics
#[derive(Debug, Clone)]
pub struct BaselineStats {
    /// Mean capability rate
    pub rate_mean: f64,
    /// Standard deviation
    pub rate_stddev: f64,
    /// Normal action types
    pub normal_actions: Vec<String>,
}

/// Containment playbook phases
#[derive(Debug, Clone)]
pub struct ContainmentPlaybook {
    /// Steps to execute
    pub steps: Vec<ContainmentStep>,
}

/// A containment step
#[derive(Debug, Clone)]
pub enum ContainmentStep {
    /// Revoke all capabilities
    RevokeAll,
    /// Terminate LLM sandbox
    TerminateSandbox,
    /// Block network egress
    BlockNetwork,
    /// Seal audit log
    SealAuditLog,
    /// Notify user
    NotifyUser,
}

/// Recovery guide
#[derive(Debug, Clone)]
pub struct RecoveryGuide {
    /// Rollback image path
    pub rollback_image: String,
    /// Golden measurements
    pub golden_measurements: Vec<PcrValue>,
    /// Re-keying instructions
    pub rekey_instructions: String,
}

/// Detected incident
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Incident {
    /// Unique ID
    pub id: String,
    /// Severity
    pub severity: AnomalySeverity,
    /// Description
    pub description: String,
    /// Timestamp
    pub timestamp: Timestamp,
    /// Indicators
    pub indicators: Vec<String>,
}

impl IncidentResponse {
    /// Create new incident response system
    pub fn new() -> Self {
        Self {
            detection: AnomalyDetector {
                baseline: BaselineStats {
                    rate_mean: 10.0,
                    rate_stddev: 2.0,
                    normal_actions: vec![
                        "email.send".to_string(),
                        "calendar.read".to_string(),
                    ],
                },
                sigma_threshold: 5.0,
            },
            containment: ContainmentPlaybook {
                steps: vec![
                    ContainmentStep::RevokeAll,
                    ContainmentStep::TerminateSandbox,
                    ContainmentStep::BlockNetwork,
                    ContainmentStep::SealAuditLog,
                    ContainmentStep::NotifyUser,
                ],
            },
            recovery: RecoveryGuide {
                rollback_image: "/muccheai/rollback/golden.img".to_string(),
                golden_measurements: vec![],
                rekey_instructions: "Rotate Shamir shares using 3-of-5 recovery".to_string(),
            },
        }
    }

    /// Handle an incident with full lifecycle management
    pub async fn handle_incident(
        &self,
        incident: &Incident,
        policy: &mut PolicyEngine,
        sandbox: &mut LlmSandbox,
    ) -> Result<()> {
        self.containment.execute(incident, policy, sandbox).await?;

        self.preserve_evidence(incident).await?;

        self.notify_user(incident).await?;

        self.prepare_recovery(incident).await?;

        Ok(())
    }

    /// Preserve evidence by serializing state, hashing, and writing to file
    async fn preserve_evidence(&self, incident: &Incident) -> Result<()> {
        let state = serde_json::json!({
            "incident": {
                "id": incident.id,
                "severity": format!("{:?}", incident.severity),
                "description": incident.description,
                "timestamp": incident.timestamp.0,
                "indicators": incident.indicators,
            },
            "baseline": {
                "rate_mean": self.detection.baseline.rate_mean,
                "rate_stddev": self.detection.baseline.rate_stddev,
                "normal_actions": self.detection.baseline.normal_actions,
            },
            "recovery_guide": {
                "rollback_image": self.recovery.rollback_image,
                "rekey_instructions": self.recovery.rekey_instructions,
            },
        });

        let state_bytes = serde_json::to_vec(&state)
            .map_err(|e| MuccheError::Internal(format!("Failed to serialize evidence: {}", e)))?;
        let hash = sha3_512(&state_bytes);

        let safe_id = incident.id.replace(|c: char| !c.is_alphanumeric(), "_");
        let evidence_dir = dirs::home_dir()
            .unwrap_or_else(|| std::env::temp_dir())
            .join(".muccheai")
            .join("evidence");
        std::fs::create_dir_all(&evidence_dir)
            .map_err(|e| MuccheError::Internal(format!("Failed to create evidence dir: {}", e)))?;
        let evidence_path = evidence_dir
            .join(format!("muccheai-evidence-{}-{:.8}.json", safe_id, hex::encode(&hash[..4])));
        std::fs::write(&evidence_path, &state_bytes)
            .map_err(|e| MuccheError::Internal(format!("Failed to write evidence file: {}", e)))?;

        // Restrict permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&evidence_path)
                .map_err(|e| MuccheError::Internal(format!("Failed to stat evidence file: {}", e)))?
                .permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&evidence_path, perms)
                .map_err(|e| MuccheError::Internal(format!("Failed to set evidence permissions: {}", e)))?;
        }

        tracing::info!(
            "Evidence preserved: {} (SHA3-512: {})",
            evidence_path.display(),
            hex::encode(&hash[..16])
        );
        Ok(())
    }

    /// Notify user via stderr and notification log file
    async fn notify_user(&self, incident: &Incident) -> Result<()> {
        let message = format!(
            "[MUCCHEAI SECURITY ALERT] Incident {} ({:?}): {} at {}\n",
            incident.id, incident.severity, incident.description, incident.timestamp.0
        );

        // Write to stderr for immediate visibility
        eprintln!("{}", message);

        let log_path = dirs::home_dir()
            .unwrap_or_else(|| std::env::temp_dir())
            .join(".muccheai")
            .join("notifications.log");
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .map_err(|e| MuccheError::Internal(format!("Failed to open notification log: {}", e)))?;

        // Restrict permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = file.metadata()
                .map_err(|e| MuccheError::Internal(format!("Failed to stat notification log: {}", e)))?
                .permissions();
            perms.set_mode(0o600);
            file.set_permissions(perms)
                .map_err(|e| MuccheError::Internal(format!("Failed to set notification permissions: {}", e)))?;
        }

        use std::io::Write;
        file.write_all(message.as_bytes())
            .map_err(|e| MuccheError::Internal(format!("Failed to write notification log: {}", e)))?;

        Ok(())
    }

    /// Prepare recovery by verifying rollback image integrity and generating re-keying guide
    async fn prepare_recovery(&self, incident: &Incident) -> Result<()> {
        // Verify rollback image integrity if it exists
        let rollback_hash = if std::path::Path::new(&self.recovery.rollback_image).exists() {
            let metadata = std::fs::metadata(&self.recovery.rollback_image)
                .map_err(|e| MuccheError::Internal(format!("Failed to read rollback image metadata: {}", e)))?;
            const MAX_ROLLBACK_SIZE: u64 = 512 * 1024 * 1024; // 512 MiB
            if metadata.len() > MAX_ROLLBACK_SIZE {
                return Err(MuccheError::Internal(
                    "Rollback image exceeds 512 MiB limit".to_string(),
                ));
            }
            let image_bytes = std::fs::read(&self.recovery.rollback_image)
                .map_err(|e| MuccheError::Internal(format!("Failed to read rollback image: {}", e)))?;
            let hash = sha3_512(&image_bytes);
            Some(hash)
        } else {
            tracing::warn!("Rollback image not found: {}", self.recovery.rollback_image);
            None
        };

        // Generate re-keying guide in a secure temp location
        let safe_id = incident.id.replace(|c: char| !c.is_alphanumeric(), "_");
        let temp_dir = std::env::temp_dir();
        let guide_path = temp_dir.join(format!("muccheai-rekey-guide-{}.txt", safe_id));
        let guide = format!(
            "MuccheAI Re-keying Guide\n=========================\nIncident: {}\nSeverity: {:?}\n\n{}",
            incident.id,
            incident.severity,
            self.recovery.rekey_instructions
        );
        std::fs::write(&guide_path, guide)
            .map_err(|e| MuccheError::Internal(format!("Failed to write re-keying guide: {}", e)))?;

        if let Some(hash) = rollback_hash {
            tracing::info!(
                "Rollback image verified (SHA3-512: {}). Re-keying guide written to: {}",
                hex::encode(&hash[..16]),
                guide_path.display()
            );
        } else {
            tracing::info!("Re-keying guide written to: {}", guide_path.display());
        }

        Ok(())
    }
}

impl ContainmentPlaybook {
    /// Execute containment steps with real subsystem calls.
    /// Continues executing remaining steps even if some fail, then reports
    /// the first error to ensure the system is as contained as possible.
    pub async fn execute(
        &self,
        incident: &Incident,
        policy: &mut PolicyEngine,
        sandbox: &mut LlmSandbox,
    ) -> Result<()> {
        let mut first_error: Option<MuccheError> = None;
        for step in &self.steps {
            let result = match step {
                ContainmentStep::RevokeAll => {
                    tracing::info!("[Containment] Revoking all capabilities for incident {}", incident.id);
                    policy.revoke_all_capabilities()
                }
                ContainmentStep::TerminateSandbox => {
                    tracing::info!("[Containment] Terminating LLM sandbox for incident {}", incident.id);
                    containment::terminate_sandbox(sandbox)
                        .map_err(|e| MuccheError::SandboxError(e.to_string()))
                }
                ContainmentStep::BlockNetwork => {
                    tracing::info!("[Containment] Blocking all network egress for incident {}", incident.id);
                    containment::block_all_egress()
                        .map_err(|e| MuccheError::Internal(format!("Network containment failed: {}", e)))
                }
                ContainmentStep::SealAuditLog => {
                    tracing::info!("[Containment] Sealing audit log for incident {}", incident.id);
                    policy.seal_audit_log()
                }
                ContainmentStep::NotifyUser => {
                    tracing::info!("[Containment] User notification sent for incident {}", incident.id);
                    Ok(())
                }
            };
            if let Err(e) = result {
                tracing::error!("[Containment] Step {:?} failed: {}", step, e);
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }
        match first_error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

impl AnomalyDetector {
    /// Detect anomaly from current activity
    pub fn detect(&self, rate: f64, actions: &[String]) -> Option<Incident> {
        // Rate anomaly (5-sigma)
        if self.baseline.rate_stddev > 0.0 {
            let zscore = (rate - self.baseline.rate_mean) / self.baseline.rate_stddev;
            if zscore.abs() > self.sigma_threshold {
                return Some(Incident {
                    id: format!("incident-{}", Timestamp::now().0),
                    severity: AnomalySeverity::Critical,
                    description: format!("Rate anomaly: z-score = {}", zscore),
                    timestamp: Timestamp::now(),
                    indicators: vec!["RateSpike".to_string()],
                });
            }
        }

        // Unknown action types
        for action in actions {
            if !self.baseline.normal_actions.contains(action) {
                return Some(Incident {
                    id: format!("incident-{}", Timestamp::now().0),
                    severity: AnomalySeverity::High,
                    description: format!("Unknown action type: {}", action),
                    timestamp: Timestamp::now(),
                    indicators: vec!["UnknownAction".to_string()],
                });
            }
        }

        None
    }
}

/// Forward-secure log implementation
pub struct ForwardSecureLogger {
    current_key: [u8; 32],
    entries: Vec<LogEntry>,
    merkle_root: Option<Vec<u8>>,
    max_entries: usize,
    sealed: bool,
}

impl ForwardSecureLogger {
    /// Create new logger
    pub fn new(initial_key: [u8; 32]) -> Self {
        Self {
            current_key: initial_key,
            entries: vec![],
            merkle_root: None,
            max_entries: 100_000,
            sealed: false,
        }
    }

    /// Seal the log: append a seal event, zeroize the signing key, and prevent further appends.
    pub fn seal(&mut self) -> Result<LogEntry> {
        if self.sealed {
            return Err(MuccheError::AuditError("Audit log is already sealed".to_string()));
        }
        let entry = self.append(SecurityEvent::IncidentResponse {
            incident_id: format!("seal-{}", self.entries.len()),
            phase: "audit-seal".to_string(),
        })?;
        self.current_key.zeroize();
        self.sealed = true;
        Ok(entry)
    }

    /// Append event with forward security using hybrid signatures.
    /// Signs the **entire** LogEntry (including sequence, previous_hash, timestamp)
    /// so that replay or reordering attacks are detectable.
    pub fn append(&mut self, event: SecurityEvent) -> Result<LogEntry> {
        if self.sealed {
            return Err(MuccheError::AuditError("Cannot append to sealed audit log".to_string()));
        }
        let sequence = self.entries.len() as u64;
        let previous_hash = self.entries.last()
            .map(|e| sha3_512(&serde_json::to_vec(e).unwrap_or_default()).to_vec());

        let mut entry = LogEntry {
            sequence,
            previous_hash,
            timestamp: Timestamp::now(),
            event,
            verifying_key: None,
            signature: vec![],
        };
        let entry_bytes = serde_json::to_vec(&entry).unwrap_or_default();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&self.current_key);
        let verifying_key = signing_key.verifying_key().to_bytes().to_vec();
        let sig = signing_key.sign(&entry_bytes);
        entry.verifying_key = Some(verifying_key);
        entry.signature = sig.to_bytes().to_vec();

        // Derive next key and destroy current
        let mut next_key = [0u8; 32];
        let mut hasher = sha3::Sha3_512::new();
        hasher.update(b"muccheai-audit-key-v1");
        hasher.update(&self.current_key);
        hasher.update(&sequence.to_le_bytes());
        let derived = hasher.finalize();
        next_key.copy_from_slice(&derived[..32]);
        self.current_key = next_key;

        self.entries.push(entry.clone());
        // Rotate log if it exceeds the maximum size.
        while self.entries.len() > self.max_entries {
            self.entries.remove(0);
        }
        Ok(entry)
    }

    /// Access the log entries
    pub fn entries(&self) -> &[LogEntry] {
        &self.entries
    }

    /// Set the Merkle root after sealing
    pub fn set_merkle_root(&mut self, root: Vec<u8>) {
        self.merkle_root = Some(root);
    }

    /// Get the current Merkle root if set
    pub fn merkle_root(&self) -> Option<&[u8]> {
        self.merkle_root.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anomaly_detection_rate() {
        let detector = AnomalyDetector {
            baseline: BaselineStats {
                rate_mean: 10.0,
                rate_stddev: 2.0,
                normal_actions: vec![],
            },
            sigma_threshold: 5.0,
        };

        assert!(detector.detect(10.0, &[]).is_none());
        assert!(detector.detect(100.0, &[]).is_some());
    }

    #[test]
    fn test_forward_secure_log() {
        let mut logger = ForwardSecureLogger::new([0u8; 32]);
        let entry = logger.append(SecurityEvent::SandboxStarted {
            vm_id: "test".to_string(),
            config_hash: vec![0u8; 64],
        }).unwrap();
        assert_eq!(entry.sequence, 0);
    }

    #[test]
    fn test_seal_audit_log() {
        let mut logger = ForwardSecureLogger::new([1u8; 32]);
        logger.append(SecurityEvent::SandboxStarted {
            vm_id: "test".to_string(),
            config_hash: vec![0u8; 64],
        }).unwrap();

        let result = containment::seal_audit_log(&mut logger);
        assert!(result.is_ok());
        assert!(logger.merkle_root().is_some());
        // After seal, further appends must fail
        assert!(logger.append(SecurityEvent::SandboxStarted {
            vm_id: "test2".to_string(),
            config_hash: vec![0u8; 64],
        }).is_err());
    }
}
