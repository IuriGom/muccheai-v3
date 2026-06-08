//! Audit log command implementation.

use muccheai_types::audit::*;
use muccheai_types::Timestamp;
use ed25519_dalek::Signer;
use ring::rand::SecureRandom;
use sha3::Digest;
use std::path::PathBuf;
use zeroize::Zeroize;

/// Path to the audit log file.
fn audit_log_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".muccheai").join("audit.jsonl")
}

/// Path to the forward-secure key file.
fn audit_key_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".muccheai").join("audit.key")
}

/// Load or initialize the forward-secure audit log.
fn load_audit_log() -> anyhow::Result<ForwardSecureLog> {
    let key_path = audit_key_path();
    let log_path = audit_log_path();

    let current_key = if key_path.exists() {
        let bytes = std::fs::read(&key_path)?;
        if bytes.len() != 40 {
            return Err(anyhow::anyhow!("corrupt audit key"));
        }
        let mut key = [0u8; 32];
        let mut key_id_bytes = [0u8; 8];
        key.copy_from_slice(&bytes[..32]);
        key_id_bytes.copy_from_slice(&bytes[32..40]);
        let key_id = u64::from_le_bytes(key_id_bytes);
        ForwardSecureKey { key, key_id }
    } else {
        let mut key = [0u8; 32];
        ring::rand::SystemRandom::new()
            .fill(&mut key)
            .map_err(|_| anyhow::anyhow!("rng failure"))?;
        ForwardSecureKey { key, key_id: 0 }
    };

    let entries = if log_path.exists() {
        let content = std::fs::read_to_string(&log_path)?;
        let mut parsed = Vec::new();
        for line in content.lines().filter(|l| !l.is_empty()) {
            let entry: LogEntry = serde_json::from_str(line)
                .map_err(|e| anyhow::anyhow!("corrupt audit log line: {}", e))?;
            // Verify previous_hash chain
            if let Some(prev) = parsed.last() {
                let expected = muccheai_crypto::sha3_512(
                    &serde_json::to_vec(prev).unwrap_or_default()
                ).to_vec();
                if entry.previous_hash.as_ref() != Some(&expected) {
                    return Err(anyhow::anyhow!("audit log chain broken at sequence {}", entry.sequence));
                }
            }
            parsed.push(entry);
        }
        parsed
    } else {
        Vec::new()
    };

    Ok(ForwardSecureLog {
        current_key,
        destroyed_keys: Vec::new(),
        entries,
        merkle_root: None,
        sealed: false,
    })
}

/// Save the audit key to disk.
fn save_audit_key(key: &ForwardSecureKey) -> anyhow::Result<()> {
    let path = audit_key_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut buf = Vec::with_capacity(40);
    buf.extend_from_slice(&key.key);
    buf.extend_from_slice(&key.key_id.to_le_bytes());
    std::fs::write(&path, &buf)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&path, perms)?;
    }

    Ok(())
}

/// Derive the next forward-secure key and destroy the current one.
/// Uses a random 32-byte nonce so that the chain is non-deterministic
/// even if an attacker learns one key.
fn evolve_key(current: &mut ForwardSecureKey) -> anyhow::Result<ForwardSecureKey> {
    let mut nonce = [0u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|e| anyhow::anyhow!("CSPRNG failure: {}", e))?;
    let mut hasher = sha3::Sha3_512::new();
    hasher.update(b"muccheai-audit-key-v1");
    hasher.update(&current.key);
    hasher.update(&nonce);
    hasher.update(&current.key_id.to_le_bytes());
    let hash = hasher.finalize();
    let mut next_key = [0u8; 32];
    next_key.copy_from_slice(&hash[..32]);
    // Destroy old key material
    current.key.zeroize();
    Ok(ForwardSecureKey {
        key: next_key,
        key_id: current.key_id + 1,
    })
}

/// Append a security event to the audit log.
pub fn append_audit_event(event: SecurityEvent) -> anyhow::Result<()> {
    let mut log = load_audit_log()?;

    let sequence = log.entries.len() as u64;
    let previous_hash = log.entries.last().map(|e| {
        let bytes = serde_json::to_vec(e).unwrap_or_default();
        muccheai_crypto::sha3_512(&bytes).to_vec()
    });

    let timestamp = Timestamp::now();

    // Sign the entry with Ed25519 using the current forward-secure key
    let entry_bytes = serde_json::to_vec(&(sequence, &event, timestamp.0)).unwrap_or_default();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&log.current_key.key);
    let verifying_key = signing_key.verifying_key().to_bytes().to_vec();
    let sig = signing_key.sign(&entry_bytes).to_bytes().to_vec();
    signing_key.to_bytes().zeroize();

    let entry = LogEntry {
        sequence,
        previous_hash,
        timestamp,
        event,
        verifying_key: Some(verifying_key),
        signature: sig,
    };

    // Write to JSONL file
    let log_path = audit_log_path();
    let line = serde_json::to_string(&entry)?;
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;
    writeln!(file, "{}", line)?;
    drop(file);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&log_path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&log_path, perms)?;
    }

    // Evolve the forward-secure key (destroys the old key)
    let next_key = evolve_key(&mut log.current_key)?;
    save_audit_key(&next_key)?;

    Ok(())
}

/// Query and display audit log entries.
pub fn audit(tool: Option<String>, from: Option<String>, to: Option<String>, json: bool, csv: bool) {
    let log = match load_audit_log() {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to load audit log: {}", e);
            std::process::exit(1);
        }
    };

    let from_ts = from.as_ref().and_then(|f| {
        f.parse::<u64>().ok().map(Timestamp)
    });
    let to_ts = to.as_ref().and_then(|t| {
        t.parse::<u64>().ok().map(Timestamp)
    });

    let filtered: Vec<&LogEntry> = log.entries.iter().filter(|e| {
        let mut include = true;
        if let Some(ref t) = tool {
            let event_tool = match &e.event {
                SecurityEvent::ActionProposed { tool_id, .. } => Some(tool_id.as_str()),
                SecurityEvent::ActionValidated { tool_id, .. } => Some(tool_id.as_str()),
                SecurityEvent::CapabilityMinted { tool_id, .. } => Some(tool_id.as_str()),
                _ => None,
            };
            include &= event_tool == Some(t.as_str());
        }
        if let Some(ref f) = from_ts {
            include &= e.timestamp >= *f;
        }
        if let Some(ref t) = to_ts {
            include &= e.timestamp <= *t;
        }
        include
    }).collect();

    if json {
        let entries: Vec<_> = filtered.iter().map(|e| *e).cloned().collect();
        match serde_json::to_string_pretty(&entries) {
            Ok(s) => println!("{}", s),
            Err(e) => eprintln!("JSON error: {}", e),
        }
    } else if csv {
        println!("sequence,timestamp,event_type");
        for e in &filtered {
            let event_type = match &e.event {
                SecurityEvent::ActionProposed { .. } => "ActionProposed",
                SecurityEvent::ActionValidated { .. } => "ActionValidated",
                SecurityEvent::ActionRejected { .. } => "ActionRejected",
                SecurityEvent::CapabilityMinted { .. } => "CapabilityMinted",
                SecurityEvent::CapabilityRevoked { .. } => "CapabilityRevoked",
                SecurityEvent::UserApproved { .. } => "UserApproved",
                SecurityEvent::UserDenied { .. } => "UserDenied",
                SecurityEvent::MemoryAdded { .. } => "MemoryAdded",
                SecurityEvent::SandboxStarted { .. } => "SandboxStarted",
                SecurityEvent::SandboxTerminated { .. } => "SandboxTerminated",
                SecurityEvent::AnomalyDetected { .. } => "AnomalyDetected",
                SecurityEvent::IncidentResponse { .. } => "IncidentResponse",
                SecurityEvent::BootVerified { .. } => "BootVerified",
                SecurityEvent::BuildAttestationVerified { .. } => "BuildAttestationVerified",
                SecurityEvent::McpToolInvoked { .. } => "McpToolInvoked",
                SecurityEvent::McpToolRejected { .. } => "McpToolRejected",
            };
            println!("{},{},{}", e.sequence, e.timestamp.0, event_type);
        }
    } else {
        println!("Audit log — {} entries ({} matching)", log.entries.len(), filtered.len());
        println!("Forward-secure key ID: {}", log.current_key.key_id);
        for e in &filtered {
            println!("  [{}] seq={} {:?}", e.timestamp.0, e.sequence, e.event);
        }
    }
}
