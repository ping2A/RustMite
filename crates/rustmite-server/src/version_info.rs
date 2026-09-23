//! Control-plane and agentless binary version / integrity inventory.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};

use rustmite_transport::{default_search_roots, DEFAULT_LINUX_TARGETS};

#[derive(Clone, Debug, Serialize)]
pub struct BinaryDigest {
    pub name: String,
    pub path: Option<String>,
    pub present: bool,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AgentlessPlatformInfo {
    pub arch: String,
    pub triple: String,
    pub label: String,
    pub bits: u8,
    pub probe: BinaryDigest,
    pub loader: BinaryDigest,
}

#[derive(Clone, Debug, Serialize)]
pub struct VersionInventory {
    pub server: BinaryDigest,
    pub agentless_version: String,
    pub agentless: Vec<AgentlessPlatformInfo>,
    pub probe_search_roots: Vec<String>,
}

fn sha256_file(path: &Path) -> Result<(String, u64), String> {
    let data = fs::read(path).map_err(|e| e.to_string())?;
    let size = data.len() as u64;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Ok((hex::encode(hasher.finalize()), size))
}

fn digest_for(name: &str, version: &str, path: Option<PathBuf>) -> BinaryDigest {
    match path {
        None => BinaryDigest {
            name: name.into(),
            path: None,
            present: false,
            version: version.into(),
            sha256: None,
            size_bytes: None,
            error: Some("not found in probe search paths".into()),
        },
        Some(p) => match sha256_file(&p) {
            Ok((sha, size)) => BinaryDigest {
                name: name.into(),
                path: Some(p.display().to_string()),
                present: true,
                version: version.into(),
                sha256: Some(sha),
                size_bytes: Some(size),
                error: None,
            },
            Err(e) => BinaryDigest {
                name: name.into(),
                path: Some(p.display().to_string()),
                present: false,
                version: version.into(),
                sha256: None,
                size_bytes: None,
                error: Some(e),
            },
        },
    }
}

fn server_digest() -> BinaryDigest {
    let version = env!("CARGO_PKG_VERSION").to_string();
    match std::env::current_exe() {
        Ok(exe) => digest_for("rustmite-server", &version, Some(exe)),
        Err(e) => BinaryDigest {
            name: "rustmite-server".into(),
            path: None,
            present: false,
            version,
            sha256: None,
            size_bytes: None,
            error: Some(format!("current_exe: {e}")),
        },
    }
}

fn find_component(roots: &[PathBuf], arch: &str, triple: &str, component: &str) -> Option<PathBuf> {
    for root in roots {
        let candidates = [
            root.join(arch).join(component),
            root.join(triple).join(component),
            root.join(arch).join("probe").join(component),
            root.join(triple).join("probe").join(component),
            root.join(format!("{component}-{arch}")),
        ];
        for c in candidates {
            if c.is_file() {
                return Some(c);
            }
        }
    }
    None
}

/// Snapshot of control-plane + agentless binary versions and SHA-256 digests.
pub fn collect_version_inventory() -> VersionInventory {
    let agentless_version = env!("CARGO_PKG_VERSION").to_string();
    let roots = default_search_roots();
    let root_display: Vec<String> = roots.iter().map(|p| p.display().to_string()).collect();

    let agentless = DEFAULT_LINUX_TARGETS
        .iter()
        .map(|platform| {
            let probe_path = find_component(
                &roots,
                platform.arch.as_str(),
                platform.triple,
                "rustmite-probe",
            );
            let loader_path = find_component(
                &roots,
                platform.arch.as_str(),
                platform.triple,
                "rustmite-loader",
            );
            AgentlessPlatformInfo {
                arch: platform.arch.as_str().into(),
                triple: platform.triple.into(),
                label: platform.label.into(),
                bits: platform.bits,
                probe: digest_for("rustmite-probe", &agentless_version, probe_path),
                loader: digest_for("rustmite-loader", &agentless_version, loader_path),
            }
        })
        .collect();

    VersionInventory {
        server: server_digest(),
        agentless_version,
        agentless,
        probe_search_roots: root_display,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventory_lists_linux_64_and_32() {
        let inv = collect_version_inventory();
        assert_eq!(inv.server.name, "rustmite-server");
        assert!(inv.agentless.iter().any(|p| p.arch == "x86_64" && p.bits == 64));
        assert!(inv.agentless.iter().any(|p| p.arch == "i686" && p.bits == 32));
        assert!(inv.agentless.iter().any(|p| p.arch == "aarch64" && p.bits == 64));
        assert!(inv.agentless.iter().any(|p| p.arch == "armv7" && p.bits == 32));
        assert!(inv.server.present);
        assert!(inv
            .server
            .sha256
            .as_ref()
            .map(|s| s.len() == 64)
            .unwrap_or(false));
    }
}
