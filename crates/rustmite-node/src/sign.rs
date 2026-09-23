//! Optional result signing via rustmite-crypto.

use rustmite_crypto::{generate_keypair, sign};

/// Sign payload with a fresh ephemeral key (MVP). Returns hex signature.
pub fn sign_payload(payload: &[u8]) -> Option<String> {
    let kp = generate_keypair();
    let sig = sign(&kp, payload);
    Some(hex::encode(sig))
}
