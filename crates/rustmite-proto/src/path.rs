//! Bytes-honest paths. Linux paths are not UTF-8.

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// Path or name as raw bytes. Serialises as `{"s":"..."}` when valid UTF-8, else `{"b":"<base64>"}`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PathBytes(pub Vec<u8>);

impl PathBytes {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    pub fn from_str(s: &str) -> Self {
        Self(s.as_bytes().to_vec())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_string_lossy(&self) -> String {
        String::from_utf8_lossy(&self.0).into_owned()
    }

    pub fn is_utf8(&self) -> bool {
        core::str::from_utf8(&self.0).is_ok()
    }

    pub fn ends_with_deleted(&self) -> bool {
        self.0.windows(9).any(|w| w == b" (deleted)" || w == b"(deleted)")
            || self.to_string_lossy().contains("(deleted)")
    }

    pub fn is_memfd(&self) -> bool {
        let s = self.to_string_lossy();
        s.contains("/memfd:") || s.contains("anon_inode")
    }

    pub fn path_under(&self, prefix: &str) -> bool {
        let s = self.to_string_lossy();
        s == prefix
            || s.starts_with(&alloc::format!("{prefix}/"))
            || s.starts_with(prefix)
    }
}

impl From<&str> for PathBytes {
    fn from(s: &str) -> Self {
        Self::from_str(s)
    }
}

impl From<String> for PathBytes {
    fn from(s: String) -> Self {
        Self(s.into_bytes())
    }
}

impl From<Vec<u8>> for PathBytes {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum PathBytesSerde {
    Utf8 { s: String },
    Bytes { b: String },
}

impl Serialize for PathBytes {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match core::str::from_utf8(&self.0) {
            Ok(s) => PathBytesSerde::Utf8 { s: s.into() }.serialize(serializer),
            Err(_) => {
                use base64::Engine;
                let b = base64::engine::general_purpose::STANDARD.encode(&self.0);
                PathBytesSerde::Bytes { b }.serialize(serializer)
            }
        }
    }
}

impl<'de> Deserialize<'de> for PathBytes {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match PathBytesSerde::deserialize(deserializer)? {
            PathBytesSerde::Utf8 { s } => Ok(Self(s.into_bytes())),
            PathBytesSerde::Bytes { b } => {
                use base64::Engine;
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(b.as_bytes())
                    .map_err(serde::de::Error::custom)?;
                Ok(Self(bytes))
            }
        }
    }
}

/// JSON-safe large integer (values that may exceed 2^53).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BigInt(pub String);

impl BigInt {
    pub fn from_u64(v: u64) -> Self {
        Self(alloc::format!("{v}"))
    }

    pub fn as_u64(&self) -> Option<u64> {
        self.0.parse().ok()
    }
}

impl From<u64> for BigInt {
    fn from(v: u64) -> Self {
        Self::from_u64(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_utf8_roundtrip() {
        let p = PathBytes::from_str("/etc/passwd");
        let j = serde_json::to_string(&p).unwrap();
        assert!(j.contains("\"s\""));
        let back: PathBytes = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn path_non_utf8_roundtrip() {
        let p = PathBytes::new(vec![0xff, 0xfe, b'/', b'x']);
        let j = serde_json::to_string(&p).unwrap();
        assert!(j.contains("\"b\""));
        let back: PathBytes = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
