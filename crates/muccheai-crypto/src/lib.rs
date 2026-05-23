//! Cryptography module.
//!
//! Provides:
//! - Ed25519 signatures (production-ready, actively used)
//! - X25519 key agreement (for ephemeral key exchange)
//! - SHA-3-512 hashing
//! - Constant-time comparison utilities
//!
//! TODO: ML-KEM-768 and ML-DSA-44 are included as dependencies but not yet
//! wired into the active signing / KEM paths.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use pqcrypto_dilithium::dilithium2;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext, PublicKey as KemPublicKey, SecretKey as KemSecretKey, SharedSecret as KemSharedSecret};
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as SignPublicKey, SecretKey as SignSecretKey};
use rand::rngs::OsRng;
use sha3::{Digest, Sha3_512};
use zeroize::Zeroize;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use muccheai_types::crypto_primitives::*;

pub mod constant_time;

/// Generate a new hybrid keypair (Ed25519 + X25519 + Kyber768 + Dilithium2)
pub fn generate_hybrid_keypair() -> Result<HybridKeypair, CryptoError> {
    // Classical: Ed25519
    let classical_signing = SigningKey::generate(&mut OsRng);
    let classical_pubkey = classical_signing.verifying_key().to_bytes();

    // Classical: X25519 (for key encapsulation)
    let x25519_secret = X25519StaticSecret::random_from_rng(&mut OsRng);
    let x25519_pubkey = X25519PublicKey::from(&x25519_secret);

    // PQC KEM: ML-KEM-768 (Kyber768)
    let (kem_pk, kem_sk) = kyber768::keypair();

    // PQC Sign: ML-DSA-44 (Dilithium2)
    let (sign_pk, sign_sk) = dilithium2::keypair();

    Ok(HybridKeypair {
        pubkey: HybridPubkey {
            classical: classical_pubkey.to_vec(),
            x25519: x25519_pubkey.as_bytes().to_vec(),
            pq: kem_pk.as_bytes().to_vec(),
            pq_sign: sign_pk.as_bytes().to_vec(),
        },
        privkey: HybridPrivkey {
            classical: classical_signing.to_bytes().to_vec(),
            x25519: x25519_secret.to_bytes().to_vec(),
            pq: kem_sk.as_bytes().to_vec(),
            pq_sign: sign_sk.as_bytes().to_vec(),
        },
    })
}

/// Hybrid key encapsulation using X25519 + ML-KEM-768
pub fn hybrid_encapsulate(
    pubkey: &HybridPubkey,
) -> Result<(HybridCiphertext, SharedSecret), CryptoError> {
    // Parse Kyber768 public key
    let kem_pk = kyber768::PublicKey::from_bytes(&pubkey.pq)
        .map_err(|_| CryptoError::InvalidKeyLength)?;

    // PQC: ML-KEM-768 encapsulate
    let (ss_pq, ct) = kyber768::encapsulate(&kem_pk);

    // Classical: ephemeral X25519 key exchange
    let ephemeral_secret = X25519StaticSecret::random_from_rng(&mut OsRng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

    // The recipient's X25519 public key
    let recipient_x25519_bytes: [u8; 32] = pubkey.x25519.as_slice().try_into()
        .map_err(|_| CryptoError::InvalidKeyLength)?;
    let recipient_x25519 = X25519PublicKey::from(recipient_x25519_bytes);

    let ss_classical = ephemeral_secret.diffie_hellman(&recipient_x25519);

    // Combine secrets via KDF (SHA3-512) for proper hybrid security
    let mut hasher = Sha3_512::new();
    hasher.update(ss_classical.as_bytes());
    hasher.update(ss_pq.as_bytes());
    hasher.update(ephemeral_public.as_bytes());
    hasher.update(b"muccheai-v3-hybrid-kem");
    let mut hybrid = [0u8; 32];
    hybrid.copy_from_slice(&hasher.finalize()[..32]);

    let ciphertext = HybridCiphertext {
        classical: ephemeral_public.as_bytes().to_vec(),
        pq: ct.as_bytes().to_vec(),
    };

    let secret = SharedSecret { secret: hybrid.to_vec() };
    hybrid.zeroize();
    Ok((ciphertext, secret))
}

/// Hybrid decapsulation using X25519 + ML-KEM-768
pub fn hybrid_decapsulate(
    privkey: &HybridPrivkey,
    ciphertext: &HybridCiphertext,
) -> Result<SharedSecret, CryptoError> {
    // Parse Kyber768 secret key
    let kem_sk = kyber768::SecretKey::from_bytes(&privkey.pq)
        .map_err(|_| CryptoError::InvalidKeyLength)?;

    // Parse Kyber768 ciphertext
    let ct = kyber768::Ciphertext::from_bytes(&ciphertext.pq)
        .map_err(|_| CryptoError::InvalidKeyLength)?;

    // PQC: ML-KEM-768 decapsulate
    let ss_pq = kyber768::decapsulate(&ct, &kem_sk);

    // Classical: X25519 key exchange
    let mut x25519_bytes: [u8; 32] = privkey.x25519.as_slice().try_into()
        .map_err(|_| CryptoError::InvalidKeyLength)?;
    let x25519_secret = X25519StaticSecret::from(x25519_bytes);
    x25519_bytes.zeroize();

    let ephemeral_public_bytes: [u8; 32] = ciphertext.classical.as_slice().try_into()
        .map_err(|_| CryptoError::InvalidKeyLength)?;
    let ephemeral_public = X25519PublicKey::from(ephemeral_public_bytes);

    let ss_classical = x25519_secret.diffie_hellman(&ephemeral_public);

    // Reconstruct hybrid shared secret via KDF (must match encapsulate)
    let mut hasher = Sha3_512::new();
    hasher.update(ss_classical.as_bytes());
    hasher.update(ss_pq.as_bytes());
    hasher.update(ephemeral_public.as_bytes());
    hasher.update(b"muccheai-v3-hybrid-kem");
    let mut hybrid = [0u8; 32];
    hybrid.copy_from_slice(&hasher.finalize()[..32]);

    let secret = SharedSecret { secret: hybrid.to_vec() };
    hybrid.zeroize();
    Ok(secret)
}

/// Hybrid sign a message (Ed25519 + ML-DSA-44).
/// Binds the signature to the specific hybrid pubkey to prevent cross-token
/// signature mix-and-match attacks.
pub fn hybrid_sign(
    message: &[u8],
    keypair: &HybridKeypair,
) -> Result<HybridSignature, CryptoError> {
    // Bind message to pubkey so signatures cannot be reused with a different keypair
    let bound = [message, &keypair.pubkey.classical, &keypair.pubkey.pq_sign].concat();
    let message = sha3_512(&bound);

    // Classical: Ed25519
    let mut classical_bytes: [u8; 32] = keypair.privkey.classical.as_slice().try_into()
        .map_err(|_| CryptoError::InvalidKeyLength)?;
    let classical_key = SigningKey::from_bytes(&classical_bytes);
    let classical_sig = classical_key.sign(&message).to_bytes();
    classical_bytes.zeroize();

    // PQC: ML-DSA-44 (Dilithium2) detached signature
    let sign_sk = dilithium2::SecretKey::from_bytes(&keypair.privkey.pq_sign)
        .map_err(|_| CryptoError::InvalidKeyLength)?;
    let pq_sig = dilithium2::detached_sign(&message, &sign_sk);

    Ok(HybridSignature {
        classical: classical_sig.to_vec(),
        pq: pq_sig.as_bytes().to_vec(),
    })
}

/// Hybrid verify a signature.
/// Reconstructs the keypair-bound message to prevent cross-token mix-and-match.
pub fn hybrid_verify(
    message: &[u8],
    sig: &HybridSignature,
    pubkey: &HybridPubkey,
) -> Result<(), CryptoError> {
    let bound_message = [
        message,
        &pubkey.classical,
        &pubkey.pq_sign,
    ].concat();
    let message = sha3_512(&bound_message);

    // Classical verification
    let vk = VerifyingKey::from_bytes(
        &pubkey.classical.as_slice().try_into().map_err(|_| CryptoError::InvalidKeyLength)?
    ).map_err(|_| CryptoError::InvalidKeyLength)?;
    let ed_sig: ed25519_dalek::Signature = sig.classical.as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidSignature)?;
    vk.verify(&message, &ed_sig)
        .map_err(|_| CryptoError::InvalidSignature)?;

    // PQC verification: Dilithium2
    let sign_pk = dilithium2::PublicKey::from_bytes(&pubkey.pq_sign)
        .map_err(|_| CryptoError::InvalidKeyLength)?;
    let pq_sig = dilithium2::DetachedSignature::from_bytes(&sig.pq)
        .map_err(|_| CryptoError::InvalidSignature)?;
    dilithium2::verify_detached_signature(&pq_sig, &message, &sign_pk)
        .map_err(|_| CryptoError::InvalidSignature)?;

    Ok(())
}

/// Sign a capability token payload using canonical encoding
pub fn sign_capability(
    payload: &TokenPayload,
    keypair: &HybridKeypair,
) -> Result<QuantumSafeToken, CryptoError> {
    let payload_bytes = canonical_token_payload_bytes(payload);

    let sig = hybrid_sign(&payload_bytes, &keypair)?;

    Ok(QuantumSafeToken {
        classical_signature: sig.classical,
        pq_signature: sig.pq,
        hybrid_pubkey: keypair.pubkey.clone(),
        payload: payload.clone(),
    })
}

/// Verify a capability token using canonical encoding.
/// Rejects V1Classical suite tokens to prevent downgrade attacks.
pub fn verify_capability(
    token: &QuantumSafeToken,
) -> Result<(), CryptoError> {
    if token.payload.suite == CryptoSuite::V1Classical {
        return Err(CryptoError::InvalidSignature);
    }
    let payload_bytes = canonical_token_payload_bytes(&token.payload);

    hybrid_verify(&payload_bytes, &HybridSignature {
        classical: token.classical_signature.clone(),
        pq: token.pq_signature.clone(),
    }, &token.hybrid_pubkey)
}

/// Canonical encoding for TokenPayload to prevent canonicalization attacks.
/// Panics if any field exceeds `u16::MAX` bytes — these limits are generous
/// enough that reaching them indicates an implementation bug or attack.
fn canonical_token_payload_bytes(payload: &TokenPayload) -> Vec<u8> {
    fn push_len_prefixed(out: &mut Vec<u8>, data: &[u8]) {
        let len = data.len();
        assert!(
            len <= u16::MAX as usize,
            "canonical_token_payload_bytes: field length {} exceeds u16::MAX",
            len
        );
        out.extend_from_slice(&(len as u16).to_le_bytes());
        out.extend_from_slice(data);
    }

    let mut out = Vec::new();
    push_len_prefixed(&mut out, &payload.token_id);
    push_len_prefixed(&mut out, payload.tool_id.as_bytes());
    push_len_prefixed(&mut out, payload.method.as_bytes());
    let res_count = payload.resource_ids.len();
    assert!(
        res_count <= u16::MAX as usize,
        "canonical_token_payload_bytes: resource_ids count {} exceeds u16::MAX",
        res_count
    );
    out.extend_from_slice(&(res_count as u16).to_le_bytes());
    for res in &payload.resource_ids {
        push_len_prefixed(&mut out, res.as_bytes());
    }
    out.extend_from_slice(&payload.not_before.to_le_bytes());
    out.extend_from_slice(&payload.not_after.to_le_bytes());
    push_len_prefixed(&mut out, &payload.nonce);
    out.extend_from_slice(&(payload.suite as u16).to_le_bytes());
    out
}

/// SHA-3-512 hash
pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 64];
    hash.copy_from_slice(&result);
    hash
}

/// Constant-time comparison of two hashes
pub fn compare_hashes(a: &[u8], b: &[u8]) -> bool {
    constant_time::eq(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_keygen() {
        let kp = generate_hybrid_keypair().unwrap();
        assert_eq!(kp.pubkey.classical.len(), 32);
        assert_eq!(kp.pubkey.x25519.len(), 32);
        assert_eq!(kp.pubkey.pq.len(), 1184);
        assert_eq!(kp.pubkey.pq_sign.len(), 1312);
    }

    #[test]
    fn test_hybrid_encapsulate_roundtrip() {
        let kp = generate_hybrid_keypair().unwrap();
        let (ct, ss1) = hybrid_encapsulate(&kp.pubkey).unwrap();
        assert_eq!(ct.pq.len(), 1088);
        assert_eq!(ss1.secret.len(), 32);

        let ss2 = hybrid_decapsulate(&kp.privkey, &ct).unwrap();
        assert_eq!(ss1.secret, ss2.secret);
    }

    #[test]
    fn test_hybrid_sign_verify() {
        let kp = generate_hybrid_keypair().unwrap();
        let msg = b"test message for hybrid signing";
        let sig = hybrid_sign(msg, &kp).unwrap();
        assert_eq!(sig.classical.len(), 64);
        assert_eq!(sig.pq.len(), 2420);
        assert!(hybrid_verify(msg, &sig, &kp.pubkey).is_ok());
    }

    #[test]
    fn test_hybrid_verify_fails_wrong_message() {
        let kp = generate_hybrid_keypair().unwrap();
        let msg = b"test message";
        let sig = hybrid_sign(msg, &kp).unwrap();
        assert!(hybrid_verify(b"wrong message", &sig, &kp.pubkey).is_err());
    }

    #[test]
    fn test_hybrid_verify_fails_wrong_key() {
        let kp1 = generate_hybrid_keypair().unwrap();
        let kp2 = generate_hybrid_keypair().unwrap();
        let msg = b"test message";
        let sig = hybrid_sign(msg, &kp1).unwrap();
        assert!(hybrid_verify(msg, &sig, &kp2.pubkey).is_err());
    }

    #[test]
    fn test_capability_sign_verify() {
        let kp = generate_hybrid_keypair().unwrap();
        let payload = TokenPayload {
            token_id: vec![1, 2, 3],
            tool_id: "email".to_string(),
            method: "send".to_string(),
            resource_ids: vec!["inbox".to_string()],
            not_before: 0,
            not_after: u64::MAX,
            nonce: vec![4, 5, 6],
            suite: CryptoSuite::V2Hybrid,
        };
        let token = sign_capability(&payload, &kp).unwrap();
        assert!(verify_capability(&token).is_ok());
    }

    #[test]
    fn test_sha3_512() {
        let hash = sha3_512(b"hello");
        assert_eq!(hash.len(), 64);
    }
}
