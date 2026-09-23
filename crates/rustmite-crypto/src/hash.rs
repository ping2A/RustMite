//! SHA-256 helper.

use sha2::{Digest, Sha256};

/// Compute SHA-256 digest of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// Compute SHA-256 and return lowercase hex.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256(data))
}
