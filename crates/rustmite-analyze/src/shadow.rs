//! `/etc/shadow` line parsing (algorithm tag only — never retain raw hash longer than needed).

use crate::hash::sha256_hex;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShadowParsed {
    pub username: String,
    /// Algorithm tag (e.g. `yescrypt`, `sha512crypt`, `empty`, `locked`, `unknown`).
    pub algorithm: String,
    pub empty: bool,
    pub locked: bool,
    /// SHA-256 of the password field for duplicate detection — never the raw hash.
    pub hash_fingerprint: Option<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ShadowParseError {
    #[error("empty line")]
    Empty,
    #[error("missing fields")]
    MissingFields,
}

/// Parse a single `/etc/shadow` line.
pub fn parse_shadow_line(line: &str) -> Result<ShadowParsed, ShadowParseError> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Err(ShadowParseError::Empty);
    }
    let mut parts = line.split(':');
    let username = parts.next().ok_or(ShadowParseError::MissingFields)?;
    let hash = parts.next().ok_or(ShadowParseError::MissingFields)?;
    if username.is_empty() {
        return Err(ShadowParseError::MissingFields);
    }

    let empty = hash.is_empty();
    let locked = hash.starts_with('!') || hash.starts_with('*');
    let algorithm = if empty {
        String::from("empty")
    } else if locked && (hash == "!" || hash == "*" || hash == "!!" || hash == "!*") {
        String::from("locked")
    } else {
        algorithm_from_hash(hash)
    };

    // Fingerprint only for comparable password material (not empty/locked markers).
    let hash_fingerprint = if empty || algorithm == "locked" {
        None
    } else {
        Some(sha256_hex(hash.as_bytes()))
    };

    Ok(ShadowParsed {
        username: username.to_string(),
        algorithm,
        empty,
        locked,
        hash_fingerprint,
    })
}

fn algorithm_from_hash(hash: &str) -> String {
    // Strip lock prefix for algorithm detection.
    let h = hash.trim_start_matches(['!', '*']);
    if h.is_empty() {
        return String::from("locked");
    }
    if !h.starts_with('$') {
        return String::from("descrypt");
    }
    // $id$... or $id$param$...
    let rest = h.get(1..).unwrap_or("");
    let id = rest.split('$').next().unwrap_or("");
    let name = match id {
        "1" => "md5crypt",
        "2" | "2a" | "2b" | "2y" => "bcrypt",
        "5" => "sha256crypt",
        "6" => "sha512crypt",
        "y" => "yescrypt",
        "gy" => "gost-yescrypt",
        "7" => "scrypt",
        "sha1" => "sha1crypt",
        other if !other.is_empty() => other,
        _ => "unknown",
    };
    String::from(name)
}

/// Parse all lines from a shadow file body.
pub fn parse_shadow(data: &str) -> Vec<ShadowParsed> {
    data.lines()
        .filter_map(|l| parse_shadow_line(l).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sha512() {
        let p = parse_shadow_line(
            "root:$6$rounds=5000$salt$hashrest:19000:0:99999:7:::",
        )
        .expect("parse");
        assert_eq!(p.username, "root");
        assert_eq!(p.algorithm, "sha512crypt");
        assert!(!p.empty);
        assert!(!p.locked);
        assert!(p.hash_fingerprint.is_some());
    }

    #[test]
    fn parse_locked() {
        let p = parse_shadow_line("nobody:*:19000:0:99999:7:::").expect("parse");
        assert!(p.locked);
        assert_eq!(p.algorithm, "locked");
        assert!(p.hash_fingerprint.is_none());
    }

    #[test]
    fn parse_empty_password() {
        let p = parse_shadow_line("guest::19000:0:99999:7:::").expect("parse");
        assert!(p.empty);
        assert_eq!(p.algorithm, "empty");
        assert!(p.hash_fingerprint.is_none());
    }

    #[test]
    fn parse_yescrypt() {
        let p = parse_shadow_line("alice:$y$j9T$salt$hash:1:0:99999:7:::").expect("parse");
        assert_eq!(p.algorithm, "yescrypt");
        assert!(p.hash_fingerprint.is_some());
    }

    #[test]
    fn duplicate_accounts_share_fingerprint() {
        let a = parse_shadow_line("a:$6$s$h:1:0:99999:7:::").expect("parse");
        let b = parse_shadow_line("b:$6$s$h:1:0:99999:7:::").expect("parse");
        assert_eq!(a.hash_fingerprint, b.hash_fingerprint);
    }
}
