//! Ed25519 keygen, sign, verify.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use zeroize::Zeroizing;

use crate::error::CryptoError;

pub type SignatureBytes = [u8; 64];
pub type VerifyingKeyBytes = [u8; 32];

/// Ed25519 key pair (signing key is zeroized on drop via dalek).
pub struct KeyPair {
    signing: SigningKey,
}

impl KeyPair {
    pub fn from_signing_key(signing: SigningKey) -> Self {
        Self { signing }
    }

    pub fn verifying_key_bytes(&self) -> VerifyingKeyBytes {
        self.signing.verifying_key().to_bytes()
    }

    pub fn signing_key_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing.to_bytes())
    }
}

/// Generate a fresh Ed25519 key pair.
pub fn generate_keypair() -> KeyPair {
    let signing = SigningKey::generate(&mut OsRng);
    KeyPair { signing }
}

/// Sign a message; returns the 64-byte signature.
pub fn sign(keypair: &KeyPair, message: &[u8]) -> SignatureBytes {
    keypair.signing.sign(message).to_bytes()
}

/// Verify an Ed25519 signature.
pub fn verify(
    verifying_key: &VerifyingKeyBytes,
    message: &[u8],
    signature: &SignatureBytes,
) -> Result<(), CryptoError> {
    let vk = VerifyingKey::from_bytes(verifying_key).map_err(|_| CryptoError::InvalidVerifyingKey)?;
    let sig = Signature::from_bytes(signature);
    vk.verify(message, &sig).map_err(|_| CryptoError::Verify)
}
