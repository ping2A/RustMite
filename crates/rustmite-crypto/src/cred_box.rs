//! Node-only credential boxes (Sandfly-style).
//!
//! Server encrypts SSH secrets to an X25519 public key held by scanner nodes.
//! The control plane never holds the private key, so a server/DB compromise
//! cannot recover usable SSH credentials.

use std::fs;
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::error::CryptoError;

/// On-disk / wire magic for node-sealed credential boxes.
pub const CRED_BOX_MAGIC: &[u8] = b"RMBOX1\0";

const HKDF_INFO: &[u8] = b"rustmite-cred-box-v1";
const NONCE_LEN: usize = 12;
const PUB_LEN: usize = 32;

/// Default paths for the fleet credential keypair (dev / single-node).
pub const DEFAULT_CRED_PRIV_PATH: &str = ".dev/vault/cred.priv";
pub const DEFAULT_CRED_PUB_PATH: &str = ".dev/vault/cred.pub";

/// X25519 public key used by the server to seal credentials for nodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CredPublicKey(pub [u8; 32]);

impl CredPublicKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_hex(hex_key: &str) -> Result<Self, CryptoError> {
        let raw = hex::decode(hex_key.trim()).map_err(|_| CryptoError::InvalidMasterKey)?;
        if raw.len() != 32 {
            return Err(CryptoError::InvalidMasterKey);
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&raw);
        Ok(Self(bytes))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn load_file(path: impl AsRef<Path>) -> Result<Self, CryptoError> {
        let text = fs::read_to_string(path.as_ref()).map_err(CryptoError::Io)?;
        let hex_key = text
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with('#'))
            .ok_or(CryptoError::InvalidMasterKey)?;
        Self::from_hex(hex_key)
    }

    pub fn write_file(&self, path: impl AsRef<Path>) -> Result<(), CryptoError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(CryptoError::Io)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
        }
        fs::write(path, format!("{}\n", self.to_hex())).map_err(CryptoError::Io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o644));
        }
        Ok(())
    }
}

/// X25519 private key — lives only on scanner nodes.
pub struct CredPrivateKey {
    secret: StaticSecret,
}

impl CredPrivateKey {
    pub fn generate() -> Self {
        Self {
            secret: StaticSecret::random_from_rng(OsRng),
        }
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            secret: StaticSecret::from(bytes),
        }
    }

    pub fn from_hex(hex_key: &str) -> Result<Self, CryptoError> {
        let raw = hex::decode(hex_key.trim()).map_err(|_| CryptoError::InvalidMasterKey)?;
        if raw.len() != 32 {
            return Err(CryptoError::InvalidMasterKey);
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&raw);
        Ok(Self::from_bytes(bytes))
    }

    pub fn public_key(&self) -> CredPublicKey {
        CredPublicKey(PublicKey::from(&self.secret).to_bytes())
    }

    pub fn to_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(self.secret.to_bytes()))
    }

    pub fn load_file(path: impl AsRef<Path>) -> Result<Self, CryptoError> {
        let text = fs::read_to_string(path.as_ref()).map_err(CryptoError::Io)?;
        let hex_key = text
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with('#'))
            .ok_or(CryptoError::InvalidMasterKey)?;
        Self::from_hex(hex_key)
    }

    pub fn write_file(&self, path: impl AsRef<Path>) -> Result<(), CryptoError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(CryptoError::Io)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
        }
        let hex = self.to_hex();
        fs::write(path, format!("{}\n", hex.as_str())).map_err(CryptoError::Io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    /// Load private key or generate and persist priv+pub beside each other.
    pub fn load_or_generate(
        priv_path: impl AsRef<Path>,
        pub_path: impl AsRef<Path>,
    ) -> Result<Self, CryptoError> {
        let priv_path = priv_path.as_ref();
        if priv_path.is_file() {
            let kp = Self::load_file(priv_path)?;
            // Keep the public file in sync for the server.
            let _ = kp.public_key().write_file(pub_path);
            return Ok(kp);
        }
        let kp = Self::generate();
        kp.write_file(priv_path)?;
        kp.public_key().write_file(pub_path)?;
        Ok(kp)
    }
}

impl Drop for CredPrivateKey {
    fn drop(&mut self) {
        let mut bytes = self.secret.to_bytes();
        bytes.zeroize();
    }
}

/// Seal plaintext to a node credential public key.
///
/// Wire: `RMBOX1\\0 || eph_pub(32) || nonce(12) || ciphertext+tag`.
pub fn seal_for_node(recipient: &CredPublicKey, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let eph = StaticSecret::random_from_rng(OsRng);
    let eph_pub = PublicKey::from(&eph);
    let shared = eph.diffie_hellman(&PublicKey::from(recipient.0));
    let mut key = derive_box_key(shared.as_bytes())?;
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| CryptoError::Aead)?;
    key.zeroize();

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::Aead)?;

    let mut out = Vec::with_capacity(CRED_BOX_MAGIC.len() + PUB_LEN + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(CRED_BOX_MAGIC);
    out.extend_from_slice(eph_pub.as_bytes());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open a credential box with the node private key.
pub fn open_for_node(
    private: &CredPrivateKey,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if sealed.len() < CRED_BOX_MAGIC.len() + PUB_LEN + NONCE_LEN + 16 {
        return Err(CryptoError::SealedTooShort);
    }
    if !sealed.starts_with(CRED_BOX_MAGIC) {
        return Err(CryptoError::Decrypt);
    }
    let body = &sealed[CRED_BOX_MAGIC.len()..];
    let mut eph_bytes = [0u8; PUB_LEN];
    eph_bytes.copy_from_slice(&body[..PUB_LEN]);
    let nonce_bytes = &body[PUB_LEN..PUB_LEN + NONCE_LEN];
    let ciphertext = &body[PUB_LEN + NONCE_LEN..];

    let shared = private
        .secret
        .diffie_hellman(&PublicKey::from(eph_bytes));
    let mut key = derive_box_key(shared.as_bytes())?;
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| CryptoError::Aead)?;
    key.zeroize();

    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::Decrypt)?;
    Ok(Zeroizing::new(plaintext))
}

pub fn is_cred_box(raw: &[u8]) -> bool {
    raw.starts_with(CRED_BOX_MAGIC)
}

pub fn write_cred_box_file(
    recipient: &CredPublicKey,
    path: impl AsRef<Path>,
    plaintext: &[u8],
) -> Result<(), CryptoError> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(CryptoError::Io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }
    }
    let blob = seal_for_node(recipient, plaintext)?;
    fs::write(path, &blob).map_err(CryptoError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn default_cred_priv_path() -> PathBuf {
    PathBuf::from(DEFAULT_CRED_PRIV_PATH)
}

pub fn default_cred_pub_path() -> PathBuf {
    PathBuf::from(DEFAULT_CRED_PUB_PATH)
}

fn derive_box_key(shared: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_INFO, &mut okm[..])
        .map_err(|_| CryptoError::Hkdf)?;
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let privk = CredPrivateKey::generate();
        let pubk = privk.public_key();
        let sealed = seal_for_node(&pubk, b"ssh-secret-material").unwrap();
        assert!(is_cred_box(&sealed));
        assert!(!sealed.windows(10).any(|w| w == b"ssh-secret"));
        let opened = open_for_node(&privk, &sealed).unwrap();
        assert_eq!(&opened[..], b"ssh-secret-material");
        let other = CredPrivateKey::generate();
        assert!(open_for_node(&other, &sealed).is_err());
    }

    #[test]
    fn keypair_files_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "rustmite-cred-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::create_dir_all(&dir);
        let priv_path = dir.join("cred.priv");
        let pub_path = dir.join("cred.pub");
        let a = CredPrivateKey::load_or_generate(&priv_path, &pub_path).unwrap();
        let b = CredPrivateKey::load_file(&priv_path).unwrap();
        let pub_loaded = CredPublicKey::load_file(&pub_path).unwrap();
        assert_eq!(a.public_key(), b.public_key());
        assert_eq!(a.public_key(), pub_loaded);
        let _ = fs::remove_dir_all(&dir);
    }
}
