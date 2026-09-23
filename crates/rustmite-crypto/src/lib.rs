//! Cryptographic helpers: Ed25519, vault seal/unseal, credential boxes, SHA-256.
#![forbid(unsafe_code)]

mod cred_box;
mod error;
mod hash;
mod master;
mod sign;
mod vault;

pub use cred_box::{
    default_cred_priv_path, default_cred_pub_path, is_cred_box, open_for_node, seal_for_node,
    write_cred_box_file, CredPrivateKey, CredPublicKey, CRED_BOX_MAGIC, DEFAULT_CRED_PRIV_PATH,
    DEFAULT_CRED_PUB_PATH,
};
pub use error::CryptoError;
pub use hash::{sha256, sha256_hex};
pub use master::{
    default_master_key_path, open_secret_bytes, read_secret_file, seal_bytes, write_sealed_file,
    MasterKey, DEFAULT_MASTER_KEY_PATH, SEALED_MAGIC,
};
pub use sign::{generate_keypair, sign, verify, KeyPair, SignatureBytes, VerifyingKeyBytes};
pub use vault::{seal, unseal, VAULT_INFO};

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    #[test]
    fn ed25519_sign_verify_roundtrip() {
        let kp = generate_keypair();
        let msg = b"rustmite scan meta";
        let sig = sign(&kp, msg);
        assert!(verify(&kp.verifying_key_bytes(), msg, &sig).is_ok());
        assert!(verify(&kp.verifying_key_bytes(), b"tampered", &sig).is_err());
    }

    #[test]
    fn vault_seal_unseal_roundtrip() {
        let master = [0x42u8; 32];
        let pt = b"ssh-private-key-material";
        let sealed = seal(&master, pt).expect("seal");
        assert_ne!(&sealed[16..], pt); // ciphertext differs from plaintext
        let opened: Zeroizing<Vec<u8>> = unseal(&master, &sealed).expect("unseal");
        assert_eq!(&opened[..], pt);

        let bad_master = [0x41u8; 32];
        assert!(unseal(&bad_master, &sealed).is_err());
    }

    #[test]
    fn sha256_known_vector() {
        let dig = sha256(b"");
        assert_eq!(
            hex::encode(dig),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
