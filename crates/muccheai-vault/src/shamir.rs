//! Shamir's Secret Sharing implementation
//!
//! Splits a secret into n shares, any k of which can reconstruct it.
//! Uses finite field arithmetic on GF(2^8) with reduction polynomial 0x11D.

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha3::{Digest, Sha3_256};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Errors that can occur during Shamir secret sharing operations.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ShamirError {
    /// Not enough shares provided.
    #[error("Need at least {threshold} shares, got {got}")]
    InsufficientShares {
        /// Minimum shares required
        threshold: usize,
        /// Number of shares provided
        got: usize,
    },
    /// Duplicate share indices detected.
    #[error("Duplicate share index: {0}")]
    DuplicateIndex(u8),
    /// MAC verification failed for a share.
    #[error("MAC verification failed for share {index}")]
    MacVerificationFailed {
        /// Index of the share with invalid MAC
        index: u8,
    },
    /// Mathematical error (e.g. division by zero in GF).
    #[error("Galois field inversion failed")]
    InversionFailed,
    /// Invalid parameters.
    #[error("Invalid parameters: {0}")]
    InvalidParameters(String),
}

/// A single share.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct Share {
    /// Share index (1-based, non-zero)
    pub index: u8,
    /// Share value
    pub value: [u8; 32],
    /// MAC for integrity (HMAC-SHA3-256)
    pub mac: Vec<u8>,
}

/// Derive a per-share MAC key: SHA3-256([b"muccheai-shamir-mac", index]).
fn derive_mac_key(index: u8) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"muccheai-shamir-mac");
    hasher.update([index]);
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// Compute HMAC-SHA3-256 over data with the given key.
fn hmac_sha3_256(key: &[u8], data: &[u8]) -> [u8; 32] {
    type HmacSha3_256 = Hmac<Sha3_256>;
    let mut mac = HmacSha3_256::new_from_slice(key).expect("HMAC accepts keys of any size");
    mac.update(data);
    let result = mac.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result.into_bytes());
    out
}

/// Compute the MAC for a share value.
pub fn compute_share_mac(index: u8, value: &[u8; 32]) -> Vec<u8> {
    let key = derive_mac_key(index);
    hmac_sha3_256(&key, value.as_slice()).to_vec()
}

/// Split a 32-byte secret into n shares, requiring k to reconstruct.
pub fn split_secret(secret: &[u8; 32], n: u8, k: u8) -> Result<Vec<Share>, ShamirError> {
    if k == 0 {
        return Err(ShamirError::InvalidParameters(
            "threshold k must be > 0".to_string(),
        ));
    }
    if n < k {
        return Err(ShamirError::InvalidParameters(format!(
            "n ({n}) must be >= k ({k})"
        )));
    }

    // Generate k-1 random coefficients for the polynomial.
    let mut coefficients: Vec<[u8; 32]> = Vec::with_capacity(k as usize);
    coefficients.push(*secret); // a0 = secret

    for _ in 1..k {
        let mut coeff = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut coeff[..]);
        coefficients.push(coeff);
    }

    // Evaluate polynomial at points 1..n.
    let mut shares = Vec::with_capacity(n as usize);
    for i in 1..=n {
        let mut value = [0u8; 32];
        for byte_idx in 0..32 {
            // Evaluate polynomial: f(x) = a0 + a1*x + a2*x^2 + ... + a(k-1)*x^(k-1)
            let mut result = 0u8;
            for (power, coeff) in coefficients.iter().enumerate() {
                let term = gf_mul(coeff[byte_idx], gf_pow(i, power as u8));
                result ^= term;
            }
            value[byte_idx] = result;
        }

        let mac = compute_share_mac(i, &value);
        shares.push(Share { index: i, value, mac });
    }

    // Zeroize coefficients to prevent secret leakage in freed heap memory.
    for coeff in &mut coefficients {
        coeff.zeroize();
    }

    Ok(shares)
}

/// Reconstruct secret from shares using Lagrange interpolation.
pub fn reconstruct_secret(
    shares: &[Share],
    threshold: usize,
) -> Result<Vec<u8>, ShamirError> {
    if threshold == 0 {
        return Err(ShamirError::InvalidParameters(
            "threshold must be greater than 0".to_string(),
        ));
    }
    if shares.len() < threshold {
        return Err(ShamirError::InsufficientShares {
            threshold,
            got: shares.len(),
        });
    }

    // Check for duplicate indices and reject index 0 (which would bypass threshold).
    let mut seen = std::collections::HashSet::new();
    for share in shares {
        if share.index == 0 {
            return Err(ShamirError::InvalidParameters(
                "share index cannot be 0".to_string(),
            ));
        }
        if !seen.insert(share.index) {
            return Err(ShamirError::DuplicateIndex(share.index));
        }
    }

    // Verify MACs.
    for share in shares {
        let expected_mac = compute_share_mac(share.index, &share.value);
        if !muccheai_crypto::constant_time::eq(&share.mac, &expected_mac) {
            return Err(ShamirError::MacVerificationFailed {
                index: share.index,
            });
        }
    }

    let mut secret = vec![0u8; 32];

    for byte_idx in 0..32 {
        // Lagrange interpolation at x=0.
        let mut result = 0u8;
        for (i, share_i) in shares.iter().enumerate() {
            let mut numerator = 1u8;
            let mut denominator = 1u8;

            for (j, share_j) in shares.iter().enumerate() {
                if i != j {
                    numerator = gf_mul(numerator, share_j.index);
                    denominator = gf_mul(denominator, share_i.index ^ share_j.index);
                }
            }

            let inv_denominator = gf_inv(denominator).ok_or(ShamirError::InversionFailed)?;
            let lagrange_coeff = gf_mul(numerator, inv_denominator);
            result ^= gf_mul(share_i.value[byte_idx], lagrange_coeff);
        }
        secret[byte_idx] = result;
    }

    Ok(secret)
}

/// Galois field multiplication (GF(2^8)) — constant-time.
/// Uses bitwise masking to eliminate branches on secret data.
#[inline]
fn gf_mul(a: u8, b: u8) -> u8 {
    let mut result = 0u8;
    let mut a = a;
    let mut b = b;

    for _ in 0..8 {
        let mask = (b & 1).wrapping_neg(); // 0xFF if LSB set, else 0x00
        result ^= a & mask;
        let high_bit = a & 0x80;
        a <<= 1;
        let reduce_mask = (high_bit >> 7).wrapping_neg(); // 0xFF if high_bit set, else 0x00
        a ^= 0x1D & reduce_mask;
        b >>= 1;
    }

    result
}

/// Galois field exponentiation.
fn gf_pow(base: u8, exp: u8) -> u8 {
    let mut result = 1u8;
    let mut base = base;
    let mut exp = exp;

    while exp > 0 {
        if exp & 1 != 0 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exp >>= 1;
    }

    result
}

/// Galois field multiplicative inverse.
fn gf_inv(a: u8) -> Option<u8> {
    if a == 0 {
        return None;
    }
    // a^254 = a^-1 in GF(2^8)
    Some(gf_pow(a, 254))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gf_mul() {
        assert_eq!(gf_mul(0, 5), 0);
        assert_eq!(gf_mul(1, 5), 5);
        // Test associativity
        let a = gf_mul(3, gf_mul(5, 7));
        let b = gf_mul(gf_mul(3, 5), 7);
        assert_eq!(a, b);
    }

    #[test]
    fn test_gf_inv() {
        assert_eq!(gf_inv(0), None);
        for i in 1..=255 {
            let inv = gf_inv(i).unwrap();
            assert_eq!(gf_mul(i, inv), 1, "inverse failed for {}", i);
        }
    }

    #[test]
    fn test_split_reconstruct_3_of_5() {
        let secret = [0x42u8; 32];
        let shares = split_secret(&secret, 5, 3).unwrap();

        // Any 3 should work
        let reconstructed = reconstruct_secret(&shares[0..3], 3).unwrap();
        assert_eq!(reconstructed, secret.to_vec());

        let reconstructed2 = reconstruct_secret(&shares[1..4], 3).unwrap();
        assert_eq!(reconstructed2, secret.to_vec());

        let reconstructed3 = reconstruct_secret(&shares[2..5], 3).unwrap();
        assert_eq!(reconstructed3, secret.to_vec());
    }

    #[test]
    fn test_split_reconstruct_2_of_3() {
        let secret = [0xABu8; 32];
        let shares = split_secret(&secret, 3, 2).unwrap();

        let reconstructed = reconstruct_secret(&shares[0..2], 2).unwrap();
        assert_eq!(reconstructed, secret.to_vec());
    }

    #[test]
    fn test_insufficient_shares() {
        let secret = [0x42u8; 32];
        let shares = split_secret(&secret, 5, 3).unwrap();
        let result = reconstruct_secret(&shares[0..2], 3);
        assert!(
            matches!(result, Err(ShamirError::InsufficientShares { threshold: 3, got: 2 }))
        );
    }

    #[test]
    fn test_duplicate_index() {
        let secret = [0x42u8; 32];
        let mut shares = split_secret(&secret, 5, 3).unwrap();
        shares[0].index = shares[1].index;
        let result = reconstruct_secret(&shares[0..3], 3);
        assert!(matches!(result, Err(ShamirError::DuplicateIndex(_))));
    }

    #[test]
    fn test_mac_verification_fails_value_tampered() {
        let secret = [0x42u8; 32];
        let mut shares = split_secret(&secret, 5, 3).unwrap();
        shares[0].value[0] ^= 0xFF; // Corrupt a share value
        let result = reconstruct_secret(&shares[0..3], 3);
        assert!(matches!(
            result,
            Err(ShamirError::MacVerificationFailed { .. })
        ));
    }

    #[test]
    fn test_mac_verification_fails_mac_tampered() {
        let secret = [0x42u8; 32];
        let mut shares = split_secret(&secret, 5, 3).unwrap();
        shares[0].mac[0] ^= 0xFF; // Corrupt MAC
        let result = reconstruct_secret(&shares[0..3], 3);
        assert!(matches!(
            result,
            Err(ShamirError::MacVerificationFailed { .. })
        ));
    }

    #[test]
    fn test_gf_mul_commutativity() {
        // GF multiplication should be commutative for all values
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(
                    gf_mul(a, b),
                    gf_mul(b, a),
                    "gf_mul not commutative for {} * {}",
                    a,
                    b
                );
            }
        }
    }

    #[test]
    fn test_gf_mul_identity() {
        // Multiplication by 1 is identity
        for a in 0..=255u8 {
            assert_eq!(gf_mul(a, 1), a, "gf_mul identity failed for {}", a);
        }
    }

    #[test]
    fn test_gf_mul_zero() {
        // Multiplication by 0 is 0
        for a in 0..=255u8 {
            assert_eq!(gf_mul(a, 0), 0, "gf_mul zero failed for {}", a);
        }
    }

    #[test]
    fn test_gf_mul_associativity() {
        // Spot-check associativity
        assert_eq!(gf_mul(gf_mul(2, 3), 5), gf_mul(2, gf_mul(3, 5)));
        assert_eq!(gf_mul(gf_mul(7, 11), 13), gf_mul(7, gf_mul(11, 13)));
    }

    #[test]
    #[test]
    fn test_shamir_threshold_3_of_5() {
        let secret = [0x42u8; 32];
        let shares = split_secret(&secret, 5, 3).unwrap();

        // Any 3 shares should reconstruct
        let reconstructed = reconstruct_secret(&shares[0..3], 3).unwrap();
        assert_eq!(reconstructed, secret);

        let reconstructed = reconstruct_secret(&shares[2..5], 3).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_shamir_insufficient_shares_fails() {
        let secret = [0x42u8; 32];
        let shares = split_secret(&secret, 5, 3).unwrap();

        let result = reconstruct_secret(&shares[0..2], 3);
        assert!(result.is_err());
    }

    #[test]
    fn test_shamir_threshold_2_of_3() {
        let secret = [0xABu8; 32];
        let shares = split_secret(&secret, 3, 2).unwrap();

        let reconstructed = reconstruct_secret(&shares[0..2], 2).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_reject_index_zero() {
        let secret = [0x42u8; 32];
        let mut shares = split_secret(&secret, 5, 3).unwrap();
        shares[0].index = 0;
        let result = reconstruct_secret(&shares[0..3], 3);
        assert!(matches!(
            result,
            Err(ShamirError::InvalidParameters(msg)) if msg.contains("share index cannot be 0")
        ));
    }

    #[test]
    fn test_split_threshold_zero() {
        let secret = [0x42u8; 32];
        let result = split_secret(&secret, 5, 0);
        assert!(matches!(
            result,
            Err(ShamirError::InvalidParameters(msg)) if msg.contains("threshold k must be > 0")
        ));
    }
}
