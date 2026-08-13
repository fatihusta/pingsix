//! Constant-time secret comparison helpers used by authentication plugins.

/// Hashes a secret for comparison against precomputed configuration digests.
pub fn secret_digest(value: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    Sha256::digest(value.as_bytes()).into()
}

/// Compares fixed-length secret digests in constant time.
pub fn constant_time_digest_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;

    a.ct_eq(b).into()
}

/// Constant-time string comparison for legacy callers.
///
/// New authentication plugins should precompute their expected digest during
/// configuration loading and call `constant_time_digest_eq` instead.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    constant_time_digest_eq(&secret_digest(a), &secret_digest(b))
}
