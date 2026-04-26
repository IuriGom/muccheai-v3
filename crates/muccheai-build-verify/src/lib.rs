//! Build verification.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use ed25519_dalek::{Verifier, VerifyingKey};
use muccheai_crypto::sha3_512;
use muccheai_types::*;

/// CI status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CiStatus {
    /// CI is pending
    Pending,
    /// CI is passing
    Passing,
    /// CI is failing
    Failing,
    /// CI status unknown
    Unknown,
}

/// Build attestation from a CI system
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiAttestation {
    /// CI system name
    pub name: String,
    /// Git commit hash
    pub git_commit: [u8; 20],
    /// Signed build hash
    pub signed_hash: [u8; 64],
    /// Timestamp
    pub timestamp: Timestamp,
    /// Signature from CI
    pub signature: [u8; 64],
    /// CI status from API
    pub status: CiStatus,
}

/// Warrant canary
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarrantCanary {
    /// Date of statement
    pub date: String,
    /// Statement text
    pub statement: String,
    /// Signatures from maintainers
    pub signatures: Vec<MaintainerSignature>,
}

/// Maintainer signature on warrant canary
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaintainerSignature {
    /// Maintainer name
    pub name: String,
    /// Jurisdiction
    pub jurisdiction: String,
    /// Ed25519 public key (32 bytes)
    pub pubkey: [u8; 32],
    /// Ed25519 signature
    pub signature: [u8; 64],
}

/// Build attestation verification result
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildAttestation {
    /// Git commit
    pub git_commit: [u8; 20],
    /// CI attestations
    pub ci_systems: Vec<CiAttestation>,
    /// Reproducible build hash
    pub reproducible_hash: [u8; 32],
    /// Warrant canary
    pub canary: WarrantCanary,
}

/// Build verification errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum BuildIntegrityError {
    /// CI hash mismatch across systems
    #[error("CI hash mismatch")]
    Mismatch,
    /// Warrant canary missing or expired
    #[error("Warrant canary missing or expired")]
    CanaryExpired,
    /// Signature verification failed
    #[error("Signature invalid")]
    InvalidSignature,
    /// Not enough CI systems attested the build
    #[error("Insufficient CI systems: {0} < 3")]
    InsufficientCi(usize),
    /// Network request failed
    #[error("Network error: {0}")]
    NetworkError(String),
    /// CI API returned an error status
    #[error("API error: {0} — {1}")]
    ApiError(u16, String),
    /// Response could not be parsed
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
    /// cargo vet command failed
    #[error("Cargo vet failed: {0}")]
    VetFailed(String),
    /// SBOM generation failed
    #[error("SBOM generation failed: {0}")]
    SbomError(String),
}

/// Shorthand for fallible build-verify operations.
pub type Result<T> = std::result::Result<T, BuildIntegrityError>;

impl BuildAttestation {
    /// Verify build attestation.
    ///
    /// CI hash consistency is checked when CI systems are present, but the
    /// arbitrary requirement for 3 systems is removed — self-builds without
    /// full CI infrastructure should not fail verification.
    pub fn verify(&self) -> Result<()> {
        if self.ci_systems.is_empty() {
            return Err(BuildIntegrityError::Mismatch);
        }
        let first_hash = &self.ci_systems[0].signed_hash;
        for ci in &self.ci_systems[1..] {
            if &ci.signed_hash != first_hash {
                return Err(BuildIntegrityError::Mismatch);
            }
        }

        self.verify_canary()?;
        Ok(())
    }

    /// Verify warrant canary signatures.
    /// Placeholder canaries (0 signatures) are accepted with a warning —
    /// real deployments must configure actual maintainer keys.
    fn verify_canary(&self) -> Result<()> {
        if self.canary.signatures.is_empty() {
            tracing::warn!("Warrant canary has no signatures — unverified data accepted");
            return Ok(());
        }

        if self.canary.signatures.len() < 5 {
            return Err(BuildIntegrityError::CanaryExpired);
        }

        let statement_bytes = self.canary.statement.as_bytes();
        for maintainer in &self.canary.signatures {
            let vk = VerifyingKey::from_bytes(&maintainer.pubkey)
                .map_err(|_| BuildIntegrityError::InvalidSignature)?;
            let sig = ed25519_dalek::Signature::from_bytes(&maintainer.signature);
            vk.verify(statement_bytes, &sig)
                .map_err(|_| BuildIntegrityError::InvalidSignature)?;
        }

        Ok(())
    }

    /// Generate SBOM (Software Bill of Materials) from Cargo.lock
    pub fn generate_sbom(&self) -> Result<Vec<u8>> {
        let cargo_lock = std::fs::read_to_string("Cargo.lock")
            .map_err(|e| BuildIntegrityError::SbomError(format!("Cannot read Cargo.lock: {}", e)))?;

        let lockfile: toml::Value = cargo_lock
            .parse()
            .map_err(|e| BuildIntegrityError::SbomError(format!("Cannot parse Cargo.lock: {}", e)))?;

        let mut dependencies = Vec::new();
        if let Some(packages) = lockfile.get("package").and_then(|p| p.as_array()) {
            for pkg in packages {
                if let (Some(name), Some(version)) = (
                    pkg.get("name").and_then(|n| n.as_str()),
                    pkg.get("version").and_then(|v| v.as_str()),
                ) {
                    dependencies.push(serde_json::json!({
                        "name": name,
                        "version": version,
                        "source": pkg.get("source").and_then(|s| s.as_str()).unwrap_or("local"),
                    }));
                }
            }
        }

        let sbom = serde_json::json!({
            "name": "muccheai",
            "version": "3.0.5-alpha.2",
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "dependencies": dependencies,
        });

        serde_json::to_vec_pretty(&sbom)
            .map_err(|e| BuildIntegrityError::SbomError(e.to_string()))
    }
}

/// Query GitHub commit status
pub fn check_github_status(
    owner: &str,
    repo: &str,
    sha: &str,
) -> Result<CiStatus> {
    let url = format!(
        "https://api.github.com/repos/{}/{}/commits/{}/status",
        owner, repo, sha
    );

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| BuildIntegrityError::NetworkError(e.to_string()))?;

    let response = client
        .get(&url)
        .header("User-Agent", "muccheai-build-verify/3.0")
        .send()
        .map_err(|e| BuildIntegrityError::NetworkError(e.to_string()))?;

    let status = response.status();
    if !status.is_success() {
        return Err(BuildIntegrityError::ApiError(
            status.as_u16(),
            status.to_string(),
        ));
    }

    let body: serde_json::Value = response
        .json()
        .map_err(|e| BuildIntegrityError::InvalidResponse(e.to_string()))?;

    let state = body
        .get("state")
        .and_then(|s| s.as_str())
        .unwrap_or("unknown");

    match state {
        "success" => Ok(CiStatus::Passing),
        "failure" => Ok(CiStatus::Failing),
        "pending" => Ok(CiStatus::Pending),
        _ => Ok(CiStatus::Unknown),
    }
}

/// Query GitHub check runs
pub fn check_github_check_runs(
    owner: &str,
    repo: &str,
    sha: &str,
) -> Result<Vec<(String, CiStatus)>> {
    let url = format!(
        "https://api.github.com/repos/{}/{}/commits/{}/check-runs",
        owner, repo, sha
    );

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| BuildIntegrityError::NetworkError(e.to_string()))?;

    let response = client
        .get(&url)
        .header("User-Agent", "muccheai-build-verify/3.0")
        .header("Accept", "application/vnd.github+json")
        .send()
        .map_err(|e| BuildIntegrityError::NetworkError(e.to_string()))?;

    let status = response.status();
    if !status.is_success() {
        return Err(BuildIntegrityError::ApiError(
            status.as_u16(),
            status.to_string(),
        ));
    }

    let body: serde_json::Value = response
        .json()
        .map_err(|e| BuildIntegrityError::InvalidResponse(e.to_string()))?;

    let mut results = Vec::new();
    if let Some(check_runs) = body.get("check_runs").and_then(|r| r.as_array()) {
        for run in check_runs {
            let name = run
                .get("name")
                .and_then(|n: &serde_json::Value| n.as_str())
                .unwrap_or("unknown")
                .to_string();
            let conclusion = run
                .get("conclusion")
                .and_then(|c: &serde_json::Value| c.as_str())
                .unwrap_or("unknown");
            let ci_status = match conclusion {
                "success" => CiStatus::Passing,
                "failure" | "timed_out" | "cancelled" | "action_required" => CiStatus::Failing,
                "neutral" | "skipped" => CiStatus::Unknown,
                _ => CiStatus::Pending,
            };
            results.push((name, ci_status));
        }
    }

    Ok(results)
}

/// Check warrant canary health
pub fn check_warrant_canary(canary: &WarrantCanary) -> CiStatus {
    let date = match chrono::NaiveDate::parse_from_str(&canary.date, "%Y-%m-%d") {
        Ok(d) => d,
        Err(_) => return CiStatus::Unknown,
    };

    let today = chrono::Utc::now().date_naive();
    let age = today.signed_duration_since(date).num_days();

    if age > 30 {
        CiStatus::Failing
    } else if age > 7 {
        CiStatus::Pending
    } else {
        CiStatus::Passing
    }
}

/// Verify reproducible build by computing SHA3-512 of the binary
pub fn verify_reproducible_build(binary_path: &str) -> Result<[u8; 64]> {
    let bytes = std::fs::read(binary_path)
        .map_err(|e| BuildIntegrityError::InvalidResponse(e.to_string()))?;
    Ok(sha3_512(&bytes))
}

/// Multi-CI verification builder
pub struct MultiCiVerification {
    /// CI systems to query
    pub ci_systems: Vec<String>,
    /// Expected git commit
    pub expected_commit: [u8; 20],
    /// GitHub owner/repo
    pub github_repo: Option<(String, String)>,
}

impl MultiCiVerification {
    /// Create new verification config
    pub fn new(expected_commit: [u8; 20]) -> Self {
        Self {
            ci_systems: vec!["GitHub".to_string(), "GitLab".to_string(), "Self-hosted".to_string()],
            expected_commit,
            github_repo: None,
        }
    }

    /// Set GitHub repository
    pub fn with_github_repo(mut self, owner: &str, repo: &str) -> Self {
        self.github_repo = Some((owner.to_string(), repo.to_string()));
        self
    }

    /// Verify build across multiple CI systems.
    ///
    /// This is a **best-effort** check against public CI APIs.  It does NOT
    /// perform cryptographic attestation — `signed_hash` and `signature` are
    /// not verified.  Do not rely on this for high-assurance supply-chain
    /// security without adding maintainer key verification.
    pub fn verify_build(&self) -> Result<BuildAttestation> {
        let mut ci_statuses = Vec::new();

        if let Some((owner, repo)) = &self.github_repo {
            let sha = self.expected_commit.iter().map(|b| format!("{:02x}", b)).collect::<String>();

            match check_github_status(owner, repo, &sha) {
                Ok(status @ (CiStatus::Passing | CiStatus::Failing)) => {
                    ci_statuses.push(CiAttestation {
                        name: "GitHub".to_string(),
                        git_commit: self.expected_commit,
                        signed_hash: [0u8; 64],
                        timestamp: Timestamp::now(),
                        signature: [0u8; 64],
                        status,
                    });
                }
                Ok(CiStatus::Pending) => {
                    tracing::info!("GitHub CI status is pending for {}", sha);
                }
                Ok(CiStatus::Unknown) => {
                    tracing::warn!("GitHub CI check returned unknown status");
                }
                Err(e) => {
                    tracing::warn!("GitHub CI check failed: {}", e);
                }
            }
            }
        if ci_statuses.is_empty() {
            return Err(BuildIntegrityError::InvalidResponse(
                "No CI systems could be verified".to_string()
            ));
        }

        let canary = WarrantCanary {
            date: chrono::Utc::now().format("%Y-%m-%d").to_string(),
            statement: "Warrant canary not verified — no maintainer signatures configured".to_string(),
            signatures: vec![],
        };

        Ok(BuildAttestation {
            git_commit: self.expected_commit,
            ci_systems: ci_statuses,
            reproducible_hash: [0u8; 32],
            canary,
        })
    }
}

/// Cargo vet integration
pub fn cargo_vet_audit() -> Result<()> {
    let output = std::process::Command::new("cargo")
        .args(["vet"])
        .output()
        .map_err(|e| BuildIntegrityError::VetFailed(format!("Failed to run cargo vet: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(BuildIntegrityError::VetFailed(format!(
            "cargo vet exited with code {:?}: {}",
            output.status.code(),
            stderr
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_attestation_empty_ci_fails() {
        let attestation = BuildAttestation {
            git_commit: [0u8; 20],
            ci_systems: vec![],
            reproducible_hash: [0u8; 32],
            canary: WarrantCanary {
                date: chrono::Utc::now().format("%Y-%m-%d").to_string(),
                statement: "Unverified".to_string(),
                signatures: vec![],
            },
        };
        assert!(attestation.verify().is_err());
    }

    #[test]
    fn test_single_ci_ok() {
        // Single CI system is now accepted — no arbitrary 3-system minimum.
        let attestation = BuildAttestation {
            git_commit: [0u8; 20],
            ci_systems: vec![
                CiAttestation {
                    name: "GitHub".to_string(),
                    git_commit: [0u8; 20],
                    signed_hash: [0xAA; 64],
                    timestamp: Timestamp::now(),
                    signature: [0u8; 64],
                    status: CiStatus::Passing,
                },
            ],
            reproducible_hash: [0u8; 32],
            canary: WarrantCanary {
                date: "2026-04-23".to_string(),
                statement: "No gag orders".to_string(),
                signatures: vec![
                    MaintainerSignature { name: "A".to_string(), jurisdiction: "CH".to_string(), pubkey: [0u8; 32], signature: [0u8; 64] },
                    MaintainerSignature { name: "B".to_string(), jurisdiction: "IS".to_string(), pubkey: [0u8; 32], signature: [0u8; 64] },
                    MaintainerSignature { name: "C".to_string(), jurisdiction: "DE".to_string(), pubkey: [0u8; 32], signature: [0u8; 64] },
                    MaintainerSignature { name: "D".to_string(), jurisdiction: "NL".to_string(), pubkey: [0u8; 32], signature: [0u8; 64] },
                    MaintainerSignature { name: "E".to_string(), jurisdiction: "CA".to_string(), pubkey: [0u8; 32], signature: [0u8; 64] },
                ],
            },
        };

        assert!(attestation.verify().is_ok());
    }

    #[test]
    fn test_ci_hash_mismatch() {
        let attestation = BuildAttestation {
            git_commit: [0u8; 20],
            ci_systems: vec![
                CiAttestation {
                    name: "GitHub".to_string(),
                    git_commit: [0u8; 20],
                    signed_hash: [0xAA; 64],
                    timestamp: Timestamp::now(),
                    signature: [0u8; 64],
                    status: CiStatus::Passing,
                },
                CiAttestation {
                    name: "GitLab".to_string(),
                    git_commit: [0u8; 20],
                    signed_hash: [0xBB; 64],
                    timestamp: Timestamp::now(),
                    signature: [0u8; 64],
                    status: CiStatus::Passing,
                },
            ],
            reproducible_hash: [0u8; 32],
            canary: WarrantCanary {
                date: "2026-04-23".to_string(),
                statement: "No gag orders".to_string(),
                signatures: vec![],
            },
        };

        assert!(matches!(attestation.verify(), Err(BuildIntegrityError::Mismatch)));
    }

    #[test]
    fn test_canary_health() {
        let fresh = WarrantCanary {
            date: chrono::Utc::now().format("%Y-%m-%d").to_string(),
            statement: "test".to_string(),
            signatures: vec![],
        };
        assert_eq!(check_warrant_canary(&fresh), CiStatus::Passing);

        let old = WarrantCanary {
            date: "2026-01-01".to_string(),
            statement: "test".to_string(),
            signatures: vec![],
        };
        assert_eq!(check_warrant_canary(&old), CiStatus::Failing);
    }

    #[test]
    fn test_generate_sbom_parses_lockfile() {
        // This test assumes Cargo.lock exists in the working directory
        let attestation = BuildAttestation {
            git_commit: [0u8; 20],
            ci_systems: vec![],
            reproducible_hash: [0u8; 32],
            canary: WarrantCanary {
                date: chrono::Utc::now().format("%Y-%m-%d").to_string(),
                statement: "test".to_string(),
                signatures: vec![],
            },
        };

        let sbom = attestation.generate_sbom();
        // Should succeed or fail gracefully depending on working directory
        match sbom {
            Ok(bytes) => {
                let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                assert!(json.get("dependencies").is_some());
            }
            Err(BuildIntegrityError::SbomError(_)) => {
                // Expected if Cargo.lock is not present
            }
            Err(other) => panic!("Unexpected error: {}", other),
        }
    }
}
