//! Credential vault seal/unseal: HKDF + ChaCha20-Poly1305.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::error::CryptoError;

/// HKDF info string for vault key derivation.
pub const VAULT_INFO: &[u8] = b"rustmite-vault-v1";

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

/// Seal plaintext under a master key.
///
/// Wire format: `salt(16) || nonce(12) || ciphertext+tag`.
pub fn seal(master_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    let mut key = derive_key(master_key, &salt)?;
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| CryptoError::Aead)?;
    key.zeroize();

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::Aead)?;

    let mut out = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Unseal a blob produced by [`seal`]. Returns zeroizing plaintext.
pub fn unseal(master_key: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if sealed.len() < SALT_LEN + NONCE_LEN + 16 {
        return Err(CryptoError::SealedTooShort);
    }
    let salt = &sealed[..SALT_LEN];
    let nonce_bytes = &sealed[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ciphertext = &sealed[SALT_LEN + NONCE_LEN..];

    let mut key = derive_key(master_key, salt)?;
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| CryptoError::Aead)?;
    key.zeroize();

    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::Decrypt)?;
    Ok(Zeroizing::new(plaintext))
}

fn derive_key(master_key: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), master_key);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(VAULT_INFO, &mut okm[..])
        .map_err(|_| CryptoError::Hkdf)?;
    Ok(okm)
}
