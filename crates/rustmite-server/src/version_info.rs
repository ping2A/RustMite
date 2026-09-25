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
    /// Summary of the ephemeral probe agent (Method A/B/C).
    pub agentless_info: AgentlessInfo,
    /// Built-in SSH-commands-only agent (no probe binary on the host).
    pub agentlite: AgentLiteInfo,
    pub probe_search_roots: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AgentLiteInfo {
    pub name: String,
    pub version: String,
    /// Delivery label shown in the UI (`ssh_commands` / Method D).
    pub delivery: String,
    pub description: String,
    /// Always true — AgentLite is compiled into the transport crate.
    pub present: bool,
    /// Curated remote sources collected over SSH.
    pub collectors: Vec<String>,
    /// Footprint on the remote host.
    pub host_footprint: String,
    /// Privilege model.
    pub privilege: String,
    /// Coverage note vs full probe.
    pub coverage: String,
    /// Policy finding raised on every AgentLite scan.
    pub policy_finding: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct AgentlessInfo {
    pub name: String,
    pub version: String,
    pub description: String,
    /// Preferred delivery order.
    pub delivery_methods: Vec<String>,
    pub host_footprint: String,
    pub privilege: String,
    pub coverage: String,
    pub binaries: Vec<String>,
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
        agentless_version: agentless_version.clone(),
        agentless,
        agentless_info: AgentlessInfo {
            name: "rustmite-probe".into(),
            version: agentless_version.clone(),
            description: "Ephemeral Linux probe delivered over SSH (preferred agent). Highest fidelity collectors including differential /proc and syscall-sensitive checks.".into(),
            delivery_methods: vec![
                "A memfd two-stage (kernel ≥ 3.17, anonymous exec)".into(),
                "B tmpfs ephemeral file (unlink-on-exec)".into(),
                "C SFTP + exec (when shell is restricted)".into(),
                "D pure-command degrade → AgentLite path + RM-POL-0021".into(),
            ],
            host_footprint: "No persistent install. Method A leaves no named file; Method B/C creates a short-lived file that is unlinked immediately. Process argv0 = rustmite-probe for its lifetime.".into(),
            privilege: "SSH user; optional sudo (nopasswd / ssh_password / separate sudo password) for root-level /proc and credential sources.".into(),
            coverage: "Full check catalog when collectors succeed — process decloak, sockets, modules, entropy, ELF, preload, accounts, SSH keys, etc.".into(),
            binaries: vec![
                "rustmite-probe (stage-1 musl static ELF per arch)".into(),
                "rustmite-loader (stage-0 memfd bootstrap, ~10–20 KB)".into(),
            ],
        },
        agentlite: AgentLiteInfo {
            name: "rustmite-agentlite".into(),
            version: agentless_version,
            delivery: "ssh_commands".into(),
            description: "SSH commands-only agent — curated read-only shell/cat over the existing SSH session. No probe ELF is transferred or executed on the host.".into(),
            present: true,
            collectors: vec![
                "persistence.accounts (/etc/passwd)".into(),
                "cred.audit (/etc/shadow when readable)".into(),
                "process.inventory (/proc/[pid] via shell)".into(),
                "net.sockets (/proc/net/tcp{,6} udp{,6} + best-effort inode→pid)".into(),
                "file.ioc (stat/find under defaults + host collect_paths)".into(),
                "modules.lkm (/proc/modules)".into(),
                "persistence.preload (/etc/ld.so.preload)".into(),
                "ssh.keys (authorized_keys + host *.pub)".into(),
                "policy RM-POL-0021 (always)".into(),
            ],
            host_footprint: "None — only SSH session + remote shell commands. No binary upload, no staging write during fingerprint when forced.".into(),
            privilege: "SSH user; optional sudo wraps the collection script so shadow and other users' keys are readable. Honours Settings → Agent limits (nice/ionice/ulimit, observation/file caps, transfer pacing).".into(),
            coverage: "Degraded vs full probe — no memfd/tmpfs differential syscall checks, limited socket/ELF/entropy coverage. Every scan raises RM-POL-0021.".into(),
            policy_finding: "RM-POL-0021".into(),
        },
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
        assert_eq!(inv.agentlite.name, "rustmite-agentlite");
        assert!(inv.agentlite.present);
        assert_eq!(inv.agentlite.delivery, "ssh_commands");
        assert!(!inv.agentlite.collectors.is_empty());
        assert_eq!(inv.agentless_info.name, "rustmite-probe");
        assert!(!inv.agentless_info.delivery_methods.is_empty());
        assert!(inv.server.present);
        assert!(inv
            .server
            .sha256
            .as_ref()
            .map(|s| s.len() == 64)
            .unwrap_or(false));
    }
}
