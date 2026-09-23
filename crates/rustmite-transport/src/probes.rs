//! On-disk agentless probe/loader catalog and arch selection.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rustmite_proto::Arch;

use crate::error::TransportError;

/// Default Linux musl targets shipped / expected for agentless delivery.
pub const DEFAULT_LINUX_TARGETS: &[AgentlessTarget] = &[
    AgentlessTarget {
        arch: Arch::X86_64,
        triple: "x86_64-unknown-linux-musl",
        label: "Linux x86_64 (musl)",
        bits: 64,
    },
    AgentlessTarget {
        arch: Arch::I686,
        triple: "i686-unknown-linux-musl",
        label: "Linux i686 (musl)",
        bits: 32,
    },
    AgentlessTarget {
        arch: Arch::Aarch64,
        triple: "aarch64-unknown-linux-musl",
        label: "Linux aarch64 (musl)",
        bits: 64,
    },
    AgentlessTarget {
        arch: Arch::Armv7,
        triple: "armv7-unknown-linux-musleabihf",
        label: "Linux armv7 (musleabihf)",
        bits: 32,
    },
];

#[derive(Clone, Copy, Debug)]
pub struct AgentlessTarget {
    pub arch: Arch,
    pub triple: &'static str,
    pub label: &'static str,
    pub bits: u8,
}

#[derive(Clone, Debug)]
pub struct ProbeArtifact {
    pub arch: Arch,
    pub triple: String,
    pub label: String,
    pub bits: u8,
    pub probe_path: PathBuf,
    pub loader_path: Option<PathBuf>,
    pub probe: Vec<u8>,
    pub loader: Option<Vec<u8>>,
}

/// Discovers built probe/loader pairs and selects by host `Arch`.
#[derive(Clone, Debug, Default)]
pub struct ProbeCatalog {
    by_arch: BTreeMap<&'static str, ProbeArtifact>,
}

impl ProbeCatalog {
    pub fn is_empty(&self) -> bool {
        self.by_arch.is_empty()
    }

    pub fn len(&self) -> usize {
        self.by_arch.len()
    }

    pub fn artifacts(&self) -> impl Iterator<Item = &ProbeArtifact> {
        self.by_arch.values()
    }

    /// Load every default Linux target found under the usual search roots.
    pub fn discover_default() -> Self {
        Self::discover(DEFAULT_LINUX_TARGETS, &default_search_roots())
    }

    pub fn discover(targets: &[AgentlessTarget], roots: &[PathBuf]) -> Self {
        let mut by_arch = BTreeMap::new();
        for target in targets {
            if let Some(art) = load_target(target, roots) {
                by_arch.insert(target.arch.as_str(), art);
            }
        }
        Self { by_arch }
    }

    /// Pick the best probe for a fingerprinted host architecture.
    pub fn select(&self, arch: Arch) -> Result<&ProbeArtifact, TransportError> {
        if let Some(art) = self.by_arch.get(arch.as_str()) {
            return Ok(art);
        }
        // Soft fallbacks for close relatives.
        let fallbacks: &[&str] = match arch {
            Arch::Armv5te => &["armv7"],
            Arch::Unknown => &["x86_64", "aarch64", "i686", "armv7"],
            _ => &[],
        };
        for key in fallbacks {
            if let Some(art) = self.by_arch.get(key) {
                return Ok(art);
            }
        }
        let available: Vec<&str> = self.by_arch.keys().copied().collect();
        Err(TransportError::Delivery(format!(
            "no agentless probe for arch {} (have: {})",
            arch.as_str(),
            if available.is_empty() {
                "none — run `cargo xtask build-probes --all`".into()
            } else {
                available.join(", ")
            }
        )))
    }
}

pub fn default_search_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(dir) = std::env::var_os("RUSTMITE_PROBE_DIR") {
        roots.push(PathBuf::from(dir));
    }
    roots.push(PathBuf::from(".dev/probes"));
    roots.push(PathBuf::from("artifacts/probes"));
    roots.push(PathBuf::from("target"));
    roots
}

fn load_target(target: &AgentlessTarget, roots: &[PathBuf]) -> Option<ProbeArtifact> {
    let probe_path = find_component(roots, target, "rustmite-probe")?;
    let probe = std::fs::read(&probe_path).ok()?;
    if probe.is_empty() {
        return None;
    }
    let loader_path = find_component(roots, target, "rustmite-loader");
    let loader = loader_path
        .as_ref()
        .and_then(|p| std::fs::read(p).ok())
        .filter(|b| !b.is_empty());
    Some(ProbeArtifact {
        arch: target.arch,
        triple: target.triple.into(),
        label: target.label.into(),
        bits: target.bits,
        probe_path,
        loader_path,
        probe,
        loader,
    })
}

fn find_component(
    roots: &[PathBuf],
    target: &AgentlessTarget,
    component: &str,
) -> Option<PathBuf> {
    for root in roots {
        let candidates = [
            root.join(target.arch.as_str()).join(component),
            root.join(target.triple).join(component),
            root.join(target.arch.as_str()).join("probe").join(component),
            root.join(target.triple).join("probe").join(component),
            root.join(format!("{component}-{}", target.arch.as_str())),
        ];
        for c in &candidates {
            if c.is_file() {
                return Some(c.clone());
            }
        }
    }
    // Single-file env overrides only apply when they match a known path hint.
    if component == "rustmite-probe" {
        if let Some(p) = std::env::var_os("RUSTMITE_PROBE") {
            let p = PathBuf::from(p);
            if p.is_file() && path_looks_like_arch(&p, target) {
                return Some(p);
            }
        }
    }
    if component == "rustmite-loader" {
        if let Some(p) = std::env::var_os("RUSTMITE_LOADER") {
            let p = PathBuf::from(p);
            if p.is_file() && path_looks_like_arch(&p, target) {
                return Some(p);
            }
        }
    }
    None
}

fn path_looks_like_arch(path: &Path, target: &AgentlessTarget) -> bool {
    let s = path.to_string_lossy();
    s.contains(target.triple) || s.contains(target.arch.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_matrix_covers_linux_64_and_32() {
        let bits: Vec<u8> = DEFAULT_LINUX_TARGETS.iter().map(|t| t.bits).collect();
        assert!(bits.contains(&64));
        assert!(bits.contains(&32));
        assert!(DEFAULT_LINUX_TARGETS
            .iter()
            .any(|t| matches!(t.arch, Arch::X86_64)));
        assert!(DEFAULT_LINUX_TARGETS
            .iter()
            .any(|t| matches!(t.arch, Arch::I686)));
    }
}
