use std::collections::HashMap;
use std::path::PathBuf;

use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};

/// A user account with Argon2id-hashed password.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub salt: [u8; 16],
    pub password_hash: String,
    pub owner_hash: String,
    /// Optional duress PIN — if entered at login, the app silently wipes
    /// all user data and returns a sanitized session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duress_pin_hash: Option<String>,
    /// Independent salt for the duress PIN (so it can't be precomputed
    /// from the known password salt). For legacy users this may be all-zeros,
    /// in which case we fall back to `salt`.
    #[serde(default = "zero_salt")]
    pub duress_salt: [u8; 16],
}

fn zero_salt() -> [u8; 16] {
    [0u8; 16]
}

/// In-memory user database backed by JSON.
pub struct UserDb {
    path: PathBuf,
    users: HashMap<String, User>,
}

impl UserDb {
    pub fn load_or_create() -> anyhow::Result<Self> {
        let path = dirs::home_dir()
            .unwrap_or_else(|| std::env::temp_dir())
            .join(".muccheai")
            .join("users.json");

        if path.exists() {
            let text = std::fs::read_to_string(&path)?;
            // Decrypt if the file has the enc: prefix; otherwise read plaintext (legacy compat).
            let plaintext = if let Some(hex_ct) = text.strip_prefix("enc:") {
                let ciphertext = hex::decode(hex_ct).map_err(|e| anyhow::anyhow!("invalid hex: {}", e))?;
                let key = crate::config::MuccheConfig::load_or_create_machine_key();
                crate::config::decrypt_aes_256_gcm(&ciphertext, &key)
                    .map_err(|e| anyhow::anyhow!("decrypt failed: {}", e))
                    .and_then(|v| String::from_utf8(v).map_err(|e| anyhow::anyhow!("utf8: {}", e)))?
            } else {
                text
            };
            let users: Vec<User> = serde_json::from_str(&plaintext)?;
            let map: HashMap<String, User> = users
                .into_iter()
                .map(|u| (u.username.clone(), u))
                .collect();
            Ok(Self { path, users: map })
        } else {
            Ok(Self {
                path,
                users: HashMap::new(),
            })
        }
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let users: Vec<&User> = self.users.values().collect();
        let json = serde_json::to_string_pretty(&users)?;
        let key = crate::config::MuccheConfig::load_or_create_machine_key();
        let ciphertext = crate::config::encrypt_aes_256_gcm(json.as_bytes(), &key)?;
        let payload = format!("enc:{}", hex::encode(ciphertext));
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, payload)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&tmp)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&tmp, perms)?;
        }
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    pub fn get(&self, username: &str) -> Option<&User> {
        self.users.get(username)
    }

    pub fn create_user(&mut self, username: &str, password: &str, salt: &[u8; 16], duress_pin: Option<&str>) -> anyhow::Result<()> {
        if self.users.contains_key(username) {
            return Err(anyhow::anyhow!("user already exists"));
        }
        let password_hash = hash_password(password, salt)?;
        let owner_hash = hex::encode(muccheai_crypto::sha3_512(password_hash.as_bytes()));

        let (duress_pin_hash, duress_salt) = if let Some(pin) = duress_pin {
            let mut d_salt = [0u8; 16];
            ring::rand::SystemRandom::new()
                .fill(&mut d_salt)
                .expect("CSPRNG failure");
            let d_hash = hash_password(pin, &d_salt)?;
            (Some(d_hash), d_salt)
        } else {
            (None, [0u8; 16])
        };

        self.users.insert(
            username.to_string(),
            User {
                username: username.to_string(),
                salt: *salt,
                password_hash,
                owner_hash,
                duress_pin_hash,
                duress_salt,
            },
        );
        self.save()
    }

    /// Verify normal password.
    pub fn verify(&self, username: &str, password: &str) -> Option<&User> {
        let user = self.users.get(username)?;
        let computed = hash_password(password, &user.salt).ok()?;
        if muccheai_crypto::constant_time::eq(computed.as_bytes(), user.password_hash.as_bytes()) {
            Some(user)
        } else {
            None
        }
    }

    /// Check whether the provided PIN matches the user's duress PIN.
    /// Uses an independent salt so the duress PIN cannot be brute-forced
    /// from the known password salt.
    pub fn verify_duress(&self, username: &str, pin: &str) -> bool {
        let Some(user) = self.users.get(username) else { return false };
        let Some(ref duress_hash) = user.duress_pin_hash else { return false };
        // Legacy users may have an all-zero duress_salt; fall back to the main salt.
        let salt = if user.duress_salt == [0u8; 16] {
            &user.salt
        } else {
            &user.duress_salt
        };
        let computed = match hash_password(pin, salt) {
            Ok(h) => h,
            Err(_) => return false,
        };
        muccheai_crypto::constant_time::eq(computed.as_bytes(), duress_hash.as_bytes())
    }

    pub fn migrate_api_key(&mut self, api_key: &str) -> anyhow::Result<()> {
        if !self.users.is_empty() {
            return Ok(());
        }
        let mut salt = [0u8; 16];
        ring::rand::SystemRandom::new()
            .fill(&mut salt)
            .expect("CSPRNG failure");
        self.create_user("admin", api_key, &salt, None)
    }
}

pub(crate) fn hash_password(password: &str, salt: &[u8; 16]) -> anyhow::Result<String> {
    use argon2::{Argon2, Algorithm, Params, Version};
    let params = Params::new(65536, 3, 4, Some(32)).expect("valid argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|e| anyhow::anyhow!("argon2 failed: {}", e))?;
    Ok(hex::encode(out))
}
