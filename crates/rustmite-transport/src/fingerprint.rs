use std::collections::BTreeMap;

use rustmite_proto::Arch;

#[derive(Clone, Debug)]
pub struct HostFingerprint {
    pub arch: Arch,
    pub kernel: String,
    /// `uname -s` (e.g. Linux).
    pub os_hint: Option<String>,
    /// `/etc/os-release` PRETTY_NAME when available.
    pub os: Option<String>,
    pub os_id: Option<String>,
    pub os_version: Option<String>,
    pub euid: Option<u32>,
}

/// Parsed `/etc/os-release` (or similar) KEY=VALUE pairs.
pub fn parse_os_release(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim();
        if key.is_empty() {
            continue;
        }
        let mut val = v.trim().to_string();
        if (val.starts_with('"') && val.ends_with('"'))
            || (val.starts_with('\'') && val.ends_with('\''))
        {
            val = val[1..val.len() - 1].to_string();
        }
        out.insert(key.to_string(), val);
    }
    out
}

fn looks_like_arch(s: &str) -> bool {
    !matches!(Arch::from_uname(s), Arch::Unknown)
}

fn looks_like_kernel(s: &str) -> bool {
    // 6.1.0-… / 5.15.0-… / 4.19.0
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_digit())
        && s.contains('.')
        && !looks_like_arch(s)
}

/// Parse sanctioned fingerprint output (`uname -srm` + optional sections).
///
/// Accepted shapes:
/// - `Linux 6.1.0-x86_64 x86_64` (`uname -srm`)
/// - `Linux x86_64 6.1.0-x86_64` (`uname -s -m -r`)
/// - Multi-section with `---` separators (euid / os-release after `---OS---`)
pub fn parse_uname_hint(output: &str) -> HostFingerprint {
    let mut arch = Arch::Unknown;
    let mut kernel = String::new();
    let mut os_hint = None;
    let mut os = None;
    let mut os_id = None;
    let mut os_version = None;
    let mut euid = None;

    let (uname_part, rest) = match output.split_once("---OS---") {
        Some((a, b)) => (a, Some(b)),
        None => (output, None),
    };

    let parts: Vec<&str> = uname_part.split("---").collect();
    if let Some(first) = parts.first() {
        let fields: Vec<&str> = first.split_whitespace().collect();
        if let Some(sys) = fields.first() {
            os_hint = Some((*sys).to_string());
        }
        match fields.as_slice() {
            [_, mid, last, ..] if looks_like_arch(mid) && looks_like_kernel(last) => {
                // uname -s -m -r → Linux x86_64 6.1.0
                arch = Arch::from_uname(mid);
                kernel = (*last).to_string();
            }
            [_, mid, last, ..] => {
                // uname -srm → Linux 6.1.0 x86_64
                kernel = (*mid).to_string();
                arch = Arch::from_uname(last);
                if matches!(arch, Arch::Unknown) && looks_like_arch(mid) {
                    arch = Arch::from_uname(mid);
                    kernel = (*last).to_string();
                }
            }
            [_, only] => {
                if looks_like_arch(only) {
                    arch = Arch::from_uname(only);
                } else {
                    kernel = (*only).to_string();
                }
            }
            _ => {}
        }
    }
    if let Some(rest) = parts.get(1) {
        for line in rest.lines() {
            let line = line.trim();
            if line.is_empty() || line == "---" {
                continue;
            }
            if line.chars().all(|c| c.is_ascii_digit()) {
                euid = line.parse().ok();
            } else if kernel.is_empty() {
                kernel = line.to_string();
            }
        }
    }

    if let Some(os_text) = rest {
        let map = parse_os_release(os_text);
        os = map
            .get("PRETTY_NAME")
            .cloned()
            .or_else(|| map.get("NAME").cloned());
        os_id = map.get("ID").cloned();
        os_version = map
            .get("VERSION_ID")
            .cloned()
            .or_else(|| map.get("VERSION").cloned());
        if os.is_none() {
            os = os_hint.clone();
        }
    } else if os.is_none() {
        os = os_hint.clone();
    }

    HostFingerprint {
        arch,
        kernel,
        os_hint,
        os,
        os_id,
        os_version,
        euid,
    }
}

/// Compact system identity for host records / connectivity reports.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostSystemInfo {
    pub uname: Option<String>,
    pub arch: Option<String>,
    pub kernel: Option<String>,
    pub os: Option<String>,
    pub os_id: Option<String>,
    pub os_version: Option<String>,
}

impl HostSystemInfo {
    pub fn from_fingerprint(fp: &HostFingerprint, uname_line: Option<String>) -> Self {
        Self {
            uname: uname_line.filter(|s| !s.trim().is_empty()),
            arch: match fp.arch {
                Arch::Unknown => None,
                a => Some(a.as_str().to_string()),
            },
            kernel: if fp.kernel.trim().is_empty() {
                None
            } else {
                Some(fp.kernel.clone())
            },
            os: fp.os.clone().filter(|s| !s.trim().is_empty()),
            os_id: fp.os_id.clone().filter(|s| !s.trim().is_empty()),
            os_version: fp.os_version.clone().filter(|s| !s.trim().is_empty()),
        }
    }

    pub fn from_probe_output(output: &str) -> Self {
        let fp = parse_uname_hint(output);
        let uname_line = output
            .lines()
            .next()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        Self::from_fingerprint(&fp, uname_line)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_uname_srm() {
        let fp = parse_uname_hint("Linux 6.1.0-x86_64 x86_64\n---\n0\n");
        assert!(matches!(fp.arch, Arch::X86_64));
        assert_eq!(fp.kernel, "6.1.0-x86_64");
        assert_eq!(fp.euid, Some(0));
        assert_eq!(fp.os_hint.as_deref(), Some("Linux"));
    }

    #[test]
    fn parses_uname_s_m_r() {
        let fp = parse_uname_hint("Linux x86_64 6.1.0-generic\n");
        assert!(matches!(fp.arch, Arch::X86_64));
        assert_eq!(fp.kernel, "6.1.0-generic");
    }

    #[test]
    fn parses_os_release_section() {
        let raw = r#"Linux 6.8.0-40-generic x86_64
---OS---
PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
ID=ubuntu
"#;
        let fp = parse_uname_hint(raw);
        assert!(matches!(fp.arch, Arch::X86_64));
        assert_eq!(fp.kernel, "6.8.0-40-generic");
        assert_eq!(fp.os.as_deref(), Some("Ubuntu 24.04.1 LTS"));
        assert_eq!(fp.os_id.as_deref(), Some("ubuntu"));
        assert_eq!(fp.os_version.as_deref(), Some("24.04"));
    }
}
