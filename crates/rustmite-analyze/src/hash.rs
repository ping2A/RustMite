//! Streaming hash helpers over `&[u8]`.

use sha2::{Digest, Sha256};

/// SHA-256 hex digest of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// MD5 hex digest (IOC compatibility only — never for integrity).
pub fn md5_hex(data: &[u8]) -> String {
    let mut hasher = md5::Md5::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// BLAKE3 hex digest of `data`.
pub fn blake3_hex(data: &[u8]) -> String {
    let hash = blake3::hash(data);
    hex::encode(hash.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_empty() {
        // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn md5_known() {
        assert_eq!(md5_hex(b"hello"), "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn blake3_len() {
        assert_eq!(blake3_hex(b"x").len(), 64);
    }
}
