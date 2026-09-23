//! Debian `*.md5sums` parsing for package integrity checks.

use thiserror::Error;

/// One expected digest from a dpkg md5sums file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DpkgMd5Entry {
    pub md5_hex: String,
    /// Absolute-style path as stored (may lack leading `/`).
    pub path: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DpkgParseError {
    #[error("empty line")]
    Empty,
    #[error("malformed md5sums line")]
    Malformed,
}

/// Parse a single `md5  path` line from a dpkg `*.md5sums` file.
pub fn parse_md5sums_line(line: &str) -> Result<DpkgMd5Entry, DpkgParseError> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Err(DpkgParseError::Empty);
    }
    let (hash, path) = split_hash_path(line).ok_or(DpkgParseError::Malformed)?;
    if hash.len() != 32 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(DpkgParseError::Malformed);
    }
    if path.is_empty() {
        return Err(DpkgParseError::Malformed);
    }
    Ok(DpkgMd5Entry {
        md5_hex: hash.to_ascii_lowercase(),
        path: path.to_string(),
    })
}

fn split_hash_path(line: &str) -> Option<(&str, &str)> {
    // Canonical format: "<32 hex><two spaces><path>"
    if let Some(idx) = line.find("  ") {
        let hash = line.get(..idx)?;
        let path = line.get(idx.saturating_add(2)..)?.trim();
        return Some((hash, path));
    }
    // Fallback: first whitespace-separated field is the hash.
    let mut parts = line.split_whitespace();
    let hash = parts.next()?;
    let path = parts.next()?;
    Some((hash, path))
}

/// Parse an entire md5sums body.
pub fn parse_md5sums(data: &str) -> Vec<DpkgMd5Entry> {
    data.lines()
        .filter_map(|l| parse_md5sums_line(l).ok())
        .collect()
}

/// Package name from an md5sums filename (`coreutils.md5sums` / `openssh-client:amd64.md5sums`).
pub fn package_name_from_md5sums_filename(name: &str) -> Option<String> {
    let stem = name.strip_suffix(".md5sums")?;
    let pkg = stem.split(':').next().unwrap_or(stem);
    if pkg.is_empty() {
        None
    } else {
        Some(pkg.to_string())
    }
}

/// Whether `path` is under a critical system prefix we re-verify.
pub fn is_critical_package_path(path: &str) -> bool {
    let p = path.trim_start_matches('/');
    const PREFIXES: &[&str] = &[
        "bin/",
        "sbin/",
        "usr/bin/",
        "usr/sbin/",
        "lib/",
        "lib64/",
        "usr/lib/",
        "usr/lib64/",
    ];
    PREFIXES.iter().any(|pre| p.starts_with(pre))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_two_space_line() {
        let e = parse_md5sums_line("5d41402abc4b2a76b9719d911017c592  bin/ls").expect("parse");
        assert_eq!(e.md5_hex, "5d41402abc4b2a76b9719d911017c592");
        assert_eq!(e.path, "bin/ls");
    }

    #[test]
    fn package_from_filename() {
        assert_eq!(
            package_name_from_md5sums_filename("coreutils.md5sums").as_deref(),
            Some("coreutils")
        );
        assert_eq!(
            package_name_from_md5sums_filename("openssh-client:amd64.md5sums").as_deref(),
            Some("openssh-client")
        );
    }

    #[test]
    fn critical_paths() {
        assert!(is_critical_package_path("/usr/bin/ls"));
        assert!(is_critical_package_path("bin/ls"));
        assert!(!is_critical_package_path("usr/share/doc/x"));
    }
}
