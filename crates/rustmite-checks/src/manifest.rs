//! Check manifest schema and loaders.

use std::fs;
use std::path::Path;

use rustmite_proto::{CheckId, CheckType, CollectorId, Confidence, Observation, Severity};
use serde::Deserialize;

use crate::error::CheckError;

/// Data-defined check rule (TOML/JSON).
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct CheckManifest {
    #[serde(deserialize_with = "deserialize_check_id")]
    pub id: CheckId,
    pub version: u32,
    pub name: String,
    #[serde(rename = "type")]
    pub check_type: CheckType,
    pub severity: Severity,
    pub confidence: Confidence,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_cost")]
    pub cost: String,
    /// Observation stream this check consumes (e.g. `"process"`, `"hidden_process"`).
    #[serde(rename = "match")]
    pub match_on: String,
    #[serde(rename = "where")]
    pub where_expr: String,
    pub title: String,
    #[serde(default)]
    pub evidence_fields: Vec<String>,
    #[serde(default)]
    pub attack: Vec<String>,
    #[serde(default)]
    pub requires_caps: Vec<String>,
    #[serde(default)]
    pub platforms: Vec<String>,
    #[serde(default)]
    pub kill_chain: Option<String>,
    #[serde(default)]
    pub rationale: Option<String>,
    #[serde(default)]
    pub false_positives: Option<String>,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub allowlist_key: Option<String>,
    /// Collector IDs required to feed this check (unioned into scan plans).
    #[serde(default)]
    pub collectors: Vec<String>,
}

impl CheckManifest {
    /// Resolved collector IDs: explicit manifest list, or defaults from `match`.
    pub fn required_collectors(&self) -> Vec<String> {
        if !self.collectors.is_empty() {
            return self.collectors.clone();
        }
        default_collectors_for_match(&self.match_on)
            .into_iter()
            .map(|c| c.as_str().to_string())
            .collect()
    }
}

fn default_true() -> bool {
    true
}

fn default_cost() -> String {
    "trivial".into()
}

fn deserialize_check_id<'de, D>(deserializer: D) -> Result<CheckId, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(CheckId::new(s))
}

/// Parse a check manifest from TOML text.
pub fn load_manifest(toml_text: &str) -> Result<CheckManifest, CheckError> {
    let m: CheckManifest = toml::from_str(toml_text)?;
    if m.id.as_str().is_empty() {
        return Err(CheckError::Invalid("empty check id".into()));
    }
    if m.match_on.is_empty() {
        return Err(CheckError::Invalid("empty match field".into()));
    }
    if observation_kind_for_match(&m.match_on).is_none() {
        return Err(CheckError::UnknownMatch(m.match_on.clone()));
    }
    Ok(m)
}

/// Load all `*.toml` check manifests from a directory (non-recursive).
pub fn load_dir(dir: impl AsRef<Path>) -> Result<Vec<CheckManifest>, CheckError> {
    let mut out = Vec::new();
    let mut entries: Vec<_> = fs::read_dir(dir.as_ref())?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .and_then(|x| x.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("toml"))
        })
        .collect();
    entries.sort_by_key(|e| e.path());
    for entry in entries {
        let text = fs::read_to_string(entry.path())?;
        out.push(load_manifest(&text)?);
    }
    Ok(out)
}

/// Map `match` field string → observation kind tag used for filtering.
pub fn observation_kind_for_match(match_on: &str) -> Option<&'static str> {
    Some(match match_on {
        "process" => "process",
        "hidden_process" => "hidden_process",
        "file_entropy" => "file_entropy",
        "elf_info" => "elf_info",
        "preload" => "preload",
        "account" => "account",
        "module" => "module",
        "socket" => "socket",
        "hidden_socket" => "hidden_socket",
        "ssh_host_key" => "ssh_host_key",
        "policy" => "policy",
        "recon" => "recon",
        "scheduled_task" => "scheduled_task",
        "service" => "service",
        "authorized_key" => "authorized_key",
        "dir_anomaly" => "dir_anomaly",
        "mount" => "mount",
        "log_integrity" => "log_integrity",
        "utmp_session" => "utmp_session",
        "container_info" => "container_info",
        "integrity_mismatch" => "integrity_mismatch",
        "shadow_entry" => "shadow_entry",
        "sudo_rule" => "sudo_rule",
        "bpf_prog" => "bpf_prog",
        "file_meta" => "file_meta",
        "timestomp" => "timestomp",
        "ioc_hit" => "ioc_hit",
        "container" => "container",
        _ => return None,
    })
}

/// Default collectors for a `match` stream when `collectors` is omitted.
pub fn default_collectors_for_match(match_on: &str) -> Vec<CollectorId> {
    match match_on {
        "hidden_process" => vec![CollectorId::DECLOAK_PROCESS],
        "process" => vec![CollectorId::PROCESS_INVENTORY],
        "hidden_socket" => vec![CollectorId::DECLOAK_SOCKET],
        "socket" => vec![CollectorId::NET_SOCKETS],
        "file_entropy" => vec![CollectorId::ENTROPY],
        "elf_info" => vec![CollectorId::FILE_ELF],
        "preload" => vec![CollectorId::PERSISTENCE_PRELOAD],
        "account" => vec![CollectorId::PERSISTENCE_ACCOUNTS],
        "shadow_entry" => vec![CollectorId::CRED_AUDIT],
        "sudo_rule" => vec![CollectorId::PERSISTENCE_SERVICES],
        "authorized_key" => vec![CollectorId::SSH_KEYS],
        "module" => vec![CollectorId::MODULES_LKM],
        "bpf_prog" => vec![CollectorId::EBPF],
        "file_meta" | "timestomp" => vec![CollectorId::FILE_IOC, CollectorId::FS_ANOMALY],
        "ioc_hit" => vec![CollectorId::FILE_IOC],
        "integrity_mismatch" => vec![CollectorId::FILE_INTEGRITY],
        "dir_anomaly" => vec![CollectorId::DIR_HIDDEN],
        "log_integrity" | "utmp_session" => vec![CollectorId::LOG_INTEGRITY],
        "scheduled_task" => vec![CollectorId::PERSISTENCE_SCHEDULED],
        "service" => vec![CollectorId::PERSISTENCE_SERVICES],
        "mount" => vec![CollectorId::MOUNT_ANOMALY],
        "container" | "container_info" => vec![CollectorId::CONTAINER_ESCAPE],
        "ssh_host_key" | "policy" | "recon" => vec![],
        _ => vec![],
    }
}

/// Union collector IDs from a set of manifests (stable sorted order).
pub fn union_collectors(manifests: &[CheckManifest]) -> Vec<String> {
    let mut ids: Vec<String> = manifests
        .iter()
        .flat_map(|m| m.required_collectors())
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

/// Whether an observation belongs to the check's `match` stream.
pub fn match_observation(match_on: &str, obs: &Observation) -> bool {
    match (match_on, obs) {
        ("process", Observation::Process(_)) => true,
        ("hidden_process", Observation::HiddenProcess(_)) => true,
        ("file_entropy", Observation::FileEntropy(_)) => true,
        ("elf_info", Observation::ElfInfo(_)) => true,
        ("preload", Observation::Preload(_)) => true,
        ("account", Observation::Account(_)) => true,
        ("module", Observation::Module(_) | Observation::HiddenModule(_)) => true,
        ("socket", Observation::Socket(_)) => true,
        ("hidden_socket", Observation::HiddenSocket(_)) => true,
        ("ssh_host_key", Observation::SshHostKey(_)) => true,
        ("policy", Observation::Policy(_)) => true,
        ("recon", Observation::Recon(_)) => true,
        ("scheduled_task", Observation::ScheduledTask(_)) => true,
        ("service", Observation::Service(_)) => true,
        ("authorized_key", Observation::AuthorizedKey(_)) => true,
        ("dir_anomaly", Observation::DirAnomaly(_)) => true,
        ("mount", Observation::Mount(_)) => true,
        ("log_integrity", Observation::LogIntegrity(_)) => true,
        ("utmp_session", Observation::UtmpSession(_)) => true,
        ("container" | "container_info", Observation::ContainerInfo(_)) => true,
        ("integrity_mismatch", Observation::IntegrityMismatch(_)) => true,
        ("shadow_entry", Observation::ShadowEntry(_)) => true,
        ("sudo_rule", Observation::SudoRule(_)) => true,
        ("bpf_prog", Observation::BpfProg(_)) => true,
        ("file_meta", Observation::FileMeta(_)) => true,
        ("timestomp", Observation::Timestomp(_)) => true,
        ("ioc_hit", Observation::IocHit(_)) => true,
        _ => false,
    }
}
