//! Constant-time operations to prevent timing side-channels

/// Constant-time equality comparison.
/// Returns true if a and b have the same content.
/// Execution time is independent of the content of the slices.
pub fn eq(a: &[u8], b: &[u8]) -> bool {
    // Do NOT early-return on length mismatch — that leaks the length difference via timing.
    let min_len = a.len().min(b.len());
    let max_len = a.len().max(b.len());
    let mut result: u8 = 0;

    // Compare overlapping region
    for (x, y) in a.iter().take(min_len).zip(b.iter().take(min_len)) {
        result |= x ^ y;
    }

    // If lengths differ, the extra bytes make the result non-zero
    result |= (max_len != min_len) as u8;

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

/// Constant-time selection.
/// Returns a if condition is true, b otherwise.
pub fn select(condition: bool, a: u8, b: u8) -> u8 {
    let mask = 0u8.wrapping_sub(condition as u8);
    (a & mask) | (b & !mask)
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
    fn test_eq_different_length() {
        assert!(!eq(b"hi", b"hello"));
        assert!(!eq(b"hello", b"hi"));
    }

    #[test]
    fn test_eq_empty() {
        assert!(eq(b"", b""));
        assert!(!eq(b"", b"x"));
    }

    #[test]
    fn test_conditional_copy() {
        let src = [1, 2, 3];
        let mut dst = [0, 0, 0];
        conditional_copy(true, &src, &mut dst);
        assert_eq!(dst, [1, 2, 3]);

        let mut dst2 = [9, 9, 9];
        conditional_copy(false, &src, &mut dst2);
        assert_eq!(dst2, [9, 9, 9]);
    }
}
