//! Constant-time operations to prevent timing side-channels.

/// Constant-time equality comparison.
///
/// Returns true if `a` and `b` have the same length and identical content.
/// Execution time is **always** proportional to `MAX_LEN` (256 bytes);
/// it does not depend on the content or lengths of the inputs.
///
/// Inputs longer than `MAX_LEN` are silently truncated; callers comparing
/// secrets longer than 256 bytes should hash them first.
pub fn eq(a: &[u8], b: &[u8]) -> bool {
    const MAX_LEN: usize = 256;
    let mut result = 0u8;
    for i in 0..MAX_LEN {
        let av = a.get(i).copied().unwrap_or(0);
        let bv = b.get(i).copied().unwrap_or(0);
        result |= av ^ bv;
    }
    result |= (a.len() != b.len()) as u8;
    result == 0
}

/// Constant-time conditional copy.
/// If condition is true, copies src to dst.
/// Always performs the copy operations to avoid branch prediction leaks.
pub fn conditional_copy(condition: bool, src: &[u8], dst: &mut [u8]) {
    debug_assert_eq!(src.len(), dst.len());
    let mask = 0u8.wrapping_sub(condition as u8);
    for (s, d) in src.iter().zip(dst.iter_mut()) {
        *d = (*d & !mask) | (s & mask);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eq_equal() {
        assert!(eq(b"hello", b"hello"));
    }

    #[test]
    fn test_eq_different() {
        assert!(!eq(b"hello", b"world"));
    }

    #[test]
    fn test_eq_length_leak() {
        // Length mismatch must also return false.
        assert!(!eq(b"hi", b"hello"));
        assert!(!eq(b"hello", b"hi"));
    }

    #[test]
    fn test_eq_empty() {
        assert!(eq(b"", b""));
        assert!(!eq(b"", b"x"));
    }
}
