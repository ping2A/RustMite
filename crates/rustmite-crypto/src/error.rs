//! Crypto errors.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("signature verification failed")]
    Verify,

    #[error("invalid signature bytes")]
    InvalidSignature,

    #[error("invalid verifying key bytes")]
    InvalidVerifyingKey,

    #[error("vault: sealed blob too short")]
    SealedTooShort,

    #[error("vault: decryption failed")]
    Decrypt,

    #[error("vault: HKDF expand failed")]
    Hkdf,

    #[error("aead error")]
    Aead,

    #[error("vault: invalid master key (need 32-byte hex)")]
    InvalidMasterKey,

    #[error("vault io: {0}")]
    Io(#[from] std::io::Error),
}
