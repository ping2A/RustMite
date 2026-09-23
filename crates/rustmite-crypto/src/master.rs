//! Vault master key: load from file / env, generate once, never log.

use std::fs;
use std::path::{Path, PathBuf};

use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::vault::{seal, unseal};

/// On-disk sealed-file magic (`RMSEAL1` + NUL).
pub const SEALED_MAGIC: &[u8] = b"RMSEAL1\0";

/// Default relative path for the auto-generated master key (dev / single-node).
pub const DEFAULT_MASTER_KEY_PATH: &str = ".dev/vault/master.key";

/// 32-byte vault master key (zeroized on drop).
#[derive(Clone)]
pub struct MasterKey {
    bytes: Zeroizing<[u8; 32]>,
}

impl MasterKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Load from `RUSTMITE_VAULT_MASTER_KEY` (64 hex chars) or `path`, generating if missing.
    pub fn load_or_generate(path: impl AsRef<Path>) -> Result<Self, CryptoError> {
        if let Ok(hex_key) = std::env::var("RUSTMITE_VAULT_MASTER_KEY") {
            let hex_key = hex_key.trim();
            if !hex_key.is_empty() {
                return Self::from_hex(hex_key);
            }
        }
        Self::load_or_generate_file(path)
    }

    pub fn from_hex(hex_key: &str) -> Result<Self, CryptoError> {
        let raw = hex::decode(hex_key).map_err(|_| CryptoError::InvalidMasterKey)?;
        if raw.len() != 32 {
            return Err(CryptoError::InvalidMasterKey);
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&raw);
        Ok(Self::from_bytes(bytes))
    }

    pub fn load_or_generate_file(path: impl AsRef<Path>) -> Result<Self, CryptoError> {
        let path = path.as_ref();
        if path.is_file() {
            return Self::load_file(path);
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(CryptoError::Io)?;
        }
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let hex = hex::encode(bytes);
        fs::write(path, format!("{hex}\n")).map_err(CryptoError::Io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
            if let Some(parent) = path.parent() {
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
        }
        Ok(Self::from_bytes(bytes))
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
}

/// Seal `plaintext` into the on-disk vault format (`RMSEAL1\\0` + AEAD blob).
pub fn seal_bytes(master: &MasterKey, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let sealed = seal(master.as_bytes(), plaintext)?;
    let mut out = Vec::with_capacity(SEALED_MAGIC.len() + sealed.len());
    out.extend_from_slice(SEALED_MAGIC);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Open a vault file: sealed format preferred; legacy plaintext accepted once.
pub fn open_secret_bytes(
    master: &MasterKey,
    raw: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if raw.starts_with(SEALED_MAGIC) {
        return unseal(master.as_bytes(), &raw[SEALED_MAGIC.len()..]);
    }
    // Legacy cleartext (pre-vault) — still returned in Zeroizing so callers wipe it.
    Ok(Zeroizing::new(raw.to_vec()))
}

pub fn write_sealed_file(
    master: &MasterKey,
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
    let blob = seal_bytes(master, plaintext)?;
    fs::write(path, &blob).map_err(CryptoError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn read_secret_file(
    master: &MasterKey,
    path: impl AsRef<Path>,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let raw = fs::read(path.as_ref()).map_err(CryptoError::Io)?;
    open_secret_bytes(master, &raw)
}

pub fn default_master_key_path() -> PathBuf {
    PathBuf::from(DEFAULT_MASTER_KEY_PATH)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_file_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "rustmite-vault-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::create_dir_all(&dir);
        let key_path = dir.join("master.key");
        let master = MasterKey::load_or_generate_file(&key_path).unwrap();
        let secret_path = dir.join("secret.bin");
        write_sealed_file(&master, &secret_path, b"ssh-secret").unwrap();
        let raw = fs::read(&secret_path).unwrap();
        assert!(raw.starts_with(SEALED_MAGIC));
        assert!(!raw.windows(10).any(|w| w == b"ssh-secret"));
        let opened = read_secret_file(&master, &secret_path).unwrap();
        assert_eq!(&opened[..], b"ssh-secret");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_plaintext_still_opens() {
        let master = MasterKey::from_bytes([7u8; 32]);
        let opened = open_secret_bytes(&master, b"plain-password\n").unwrap();
        assert_eq!(&opened[..], b"plain-password\n");
    }
}
