//! SSH `authorized_keys` line parsing + SHA-256 fingerprint of key material.

use base64::Engine;
use thiserror::Error;

use crate::hash::sha256_hex;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedKeyParsed {
    pub key_type: String,
    pub fingerprint: String,
    pub comment: Option<String>,
    pub options: Vec<String>,
    /// Public key strength in bits when known (RSA/DSA modulus; ECDSA/Ed25519 curve size).
    pub bits: Option<u32>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthorizedKeyError {
    #[error("empty line")]
    Empty,
    #[error("missing key material")]
    MissingKey,
    #[error("invalid base64 key material")]
    InvalidBase64,
}

/// Parse one authorized_keys line (simplified: options are comma-separated tokens before key type).
pub fn parse_authorized_key_line(line: &str) -> Result<AuthorizedKeyParsed, AuthorizedKeyError> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Err(AuthorizedKeyError::Empty);
    }

    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.is_empty() {
        return Err(AuthorizedKeyError::Empty);
    }

    // Find the key-type token (ssh-*, ecdsa-*, sk-*).
    let mut key_idx = None;
    for (i, t) in tokens.iter().enumerate() {
        if is_key_type(t) {
            key_idx = Some(i);
            break;
        }
    }
    let key_idx = key_idx.ok_or(AuthorizedKeyError::MissingKey)?;
    let key_type = tokens
        .get(key_idx)
        .copied()
        .ok_or(AuthorizedKeyError::MissingKey)?;
    let material = tokens
        .get(key_idx.saturating_add(1))
        .copied()
        .ok_or(AuthorizedKeyError::MissingKey)?;
    let comment = tokens
        .get(key_idx.saturating_add(2)..)
        .filter(|s| !s.is_empty())
        .map(|s| s.join(" "));

    let options: Vec<String> = tokens
        .get(..key_idx)
        .unwrap_or(&[])
        .iter()
        .flat_map(|t| t.split(','))
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();

    let raw = base64::engine::general_purpose::STANDARD
        .decode(material.as_bytes())
        .map_err(|_| AuthorizedKeyError::InvalidBase64)?;
    let fingerprint = format!("SHA256:{}", sha256_hex(&raw));
    let bits = key_bits(key_type, &raw);

    Ok(AuthorizedKeyParsed {
        key_type: key_type.to_string(),
        fingerprint,
        comment,
        options,
        bits,
    })
}

fn key_bits(key_type: &str, blob: &[u8]) -> Option<u32> {
    match key_type {
        "ssh-rsa" | "ssh-dss" => rsa_or_dsa_modulus_bits(blob),
        "ssh-ed25519" | "sk-ssh-ed25519@openssh.com" => Some(256),
        "ecdsa-sha2-nistp256" | "sk-ecdsa-sha2-nistp256@openssh.com" => Some(256),
        "ecdsa-sha2-nistp384" => Some(384),
        "ecdsa-sha2-nistp521" => Some(521),
        _ => None,
    }
}

/// OpenSSH wire: string type, mpint e, mpint n (RSA) — bit length from modulus.
fn rsa_or_dsa_modulus_bits(blob: &[u8]) -> Option<u32> {
    let mut i = 0usize;
    // skip type string
    let typ = read_ssh_string(blob, &mut i)?;
    if typ != b"ssh-rsa" && typ != b"ssh-dss" {
        return None;
    }
    if typ == b"ssh-rsa" {
        let _e = read_ssh_string(blob, &mut i)?;
        let n = read_ssh_string(blob, &mut i)?;
        return Some(mpint_bits(n));
    }
    // ssh-dss: p, q, g, y — use p
    let p = read_ssh_string(blob, &mut i)?;
    Some(mpint_bits(p))
}

fn read_ssh_string<'a>(blob: &'a [u8], i: &mut usize) -> Option<&'a [u8]> {
    if *i + 4 > blob.len() {
        return None;
    }
    let len = u32::from_be_bytes(blob[*i..*i + 4].try_into().ok()?) as usize;
    *i += 4;
    if *i + len > blob.len() {
        return None;
    }
    let out = &blob[*i..*i + len];
    *i += len;
    Some(out)
}

fn mpint_bits(n: &[u8]) -> u32 {
    let mut bytes = n;
    while bytes.first() == Some(&0) {
        bytes = &bytes[1..];
    }
    if bytes.is_empty() {
        return 0;
    }
    let bits = (bytes.len() as u32) * 8;
    let leading = bytes[0].leading_zeros();
    bits.saturating_sub(leading)
}

fn is_key_type(t: &str) -> bool {
    t.starts_with("ssh-") || t.starts_with("ecdsa-") || t.starts_with("sk-ssh-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple() {
        // base64("hello") = aGVsbG8=
        let line = "ssh-ed25519 aGVsbG8= user@host";
        let p = parse_authorized_key_line(line).expect("parse");
        assert_eq!(p.key_type, "ssh-ed25519");
        assert_eq!(p.comment.as_deref(), Some("user@host"));
        assert!(p.fingerprint.starts_with("SHA256:"));
        assert!(p.options.is_empty());
    }

    #[test]
    fn parse_with_options() {
        let line = "no-port-forwarding,command=\"/bin/false\" ssh-rsa aGVsbG8= bob";
        let p = parse_authorized_key_line(line).expect("parse");
        assert_eq!(p.key_type, "ssh-rsa");
        assert!(!p.options.is_empty());
    }

    #[test]
    fn rsa_bits_from_realish_blob() {
        // Minimal valid-looking RSA blob: type + e=65537 + 256-byte modulus → 2048 bits.
        fn enc(s: &[u8]) -> Vec<u8> {
            let mut v = (s.len() as u32).to_be_bytes().to_vec();
            v.extend_from_slice(s);
            v
        }
        let mut blob = Vec::new();
        blob.extend(enc(b"ssh-rsa"));
        blob.extend(enc(&[0x01, 0x00, 0x01])); // e = 65537
        let mut n = vec![0x80u8]; // MSB set → exactly 2048 bits
        n.extend(std::iter::repeat(0u8).take(255));
        blob.extend(enc(&n));
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &blob);
        let line = format!("ssh-rsa {b64} test");
        let p = parse_authorized_key_line(&line).expect("parse");
        assert_eq!(p.bits, Some(2048));
    }
}
