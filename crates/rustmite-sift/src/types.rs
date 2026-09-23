//! Core data structures: raw entries, signatures, and machine profiles.

use std::collections::HashMap;
use std::sync::Arc;
use chrono::{DateTime, Utc};
use log;
use serde::{Deserialize, Serialize};

use crate::config::DetectionConfig;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RawLogEntry {
    pub machine_id: String,
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub uid: u32,
    pub path: String,
    pub args: String,
    /// RFC3339 / epoch text; osquery `processes.start_time` accepted as alias.
    #[serde(default, alias = "start_time")]
    pub timestamp: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct RawFileEntry {
    /// Host identifier; optional in JSONL lines — filled from the input file stem by the loader when absent.
    #[serde(default)]
    pub machine_id: String,
    /// File path (JSON may use `file_path` instead of `path`).
    #[serde(alias = "file_path")]
    pub path: String,
    #[serde(default)]
    pub uid: u32,
    #[serde(default)]
    pub timestamp: Option<String>,
    /// Last modification time (IronSift `mtime` column; JSON may use `date` as alias).
    #[serde(default, alias = "date")]
    pub mtime: Option<String>,
    /// Permission bits as text; osquery `file.mode`.
    #[serde(default, alias = "mode")]
    pub permissions: Option<String>,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub size: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RawConnectionEntry {
    pub machine_id: String,
    pub remote_ip: String,
    #[serde(default)]
    pub local_ip: Option<String>,
    #[serde(default)]
    pub remote_port: Option<u16>,
    #[serde(default)]
    pub process_name: Option<String>,
    #[serde(default)]
    pub timestamp: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ProcessEntry {
    pub machine_id: String,
    pub name: String,
    pub parent_name: Option<String>,
    pub ppid: Option<u32>,
    pub uid: u32,
    pub path: String,
    pub args: String,
    pub timestamp: Option<String>,
}

impl ProcessEntry {
    pub fn new(machine_id: String, name: String) -> Self {
        log::debug!("Creating ProcessEntry: machine={}, name={}", machine_id, name);
        Self {
            machine_id,
            name,
            parent_name: None,
            ppid: None,
            uid: 1000,
            path: String::new(),
            args: String::new(),
            timestamp: None,
        }
    }

    pub fn from_command_line(machine_id: String, command: &str, parent: Option<&str>) -> Self {
        let (name, path, args) = crate::utils::parse_command_line(command);
        log::debug!("Creating ProcessEntry from command: machine={}, command={}", machine_id, command);
        Self {
            machine_id,
            name,
            parent_name: parent.map(|p| p.to_string()),
            ppid: None,
            uid: 1000,
            path,
            args,
            timestamp: None,
        }
    }

    pub fn parent(mut self, parent: &str) -> Self {
        log::debug!("  Setting parent: {}", parent);
        self.parent_name = Some(parent.to_string());
        self
    }

    pub fn ppid(mut self, ppid: u32) -> Self {
        log::debug!("  Setting PPID: {}", ppid);
        self.ppid = Some(ppid);
        self
    }

    pub fn uid(mut self, uid: u32) -> Self {
        log::debug!("  Setting UID: {}", uid);
        self.uid = uid;
        self
    }

    pub fn path(mut self, path: &str) -> Self {
        if !path.is_empty() {
            log::debug!("  Setting path: {}", path);
        }
        self.path = path.to_string();
        self
    }

    pub fn args(mut self, args: &str) -> Self {
        if !args.is_empty() {
            let display = if args.len() > 50 {
                format!("{}...", &args[..50])
            } else {
                args.to_string()
            };
            log::debug!("  Setting args: {}", display);
        }
        self.args = args.to_string();
        self
    }

    pub fn timestamp(mut self, timestamp: String) -> Self {
        log::debug!("  Setting timestamp: {}", timestamp);
        self.timestamp = Some(timestamp);
        self
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub struct ProcessSignature {
    pub name: Arc<str>,
    pub parent_name: Arc<str>,
    pub uid: u32,
    pub path: Arc<str>,
    pub is_high_entropy: bool,
    pub is_suspicious_path: bool,
}

impl ProcessSignature {
    pub fn is_unexpected_root(&self, common_root_processes: &[String]) -> bool {
        if self.uid != 0 {
            return false;
        }
        !common_root_processes.iter().any(|common| {
            self.name.as_ref() == common.as_str() || self.name.starts_with(common)
        })
    }

    pub fn risk_factors(&self, config: &DetectionConfig) -> Vec<String> {
        let mut factors = Vec::new();
        if self.is_high_entropy {
            factors.push("High entropy arguments (possible obfuscation)".to_string());
        }
        if self.is_suspicious_path {
            factors.push(format!("Suspicious execution path: {}", self.path.as_ref()));
        }
        if config.flag_unexpected_root && self.is_unexpected_root(&config.common_root_processes) {
            factors.push(format!(
                "Unexpected process running as root (UID 0): {}",
                self.name.as_ref()
            ));
        }
        if self.path.contains("/tmp") {
            factors.push("Executing from temporary directory".to_string());
        }
        factors
    }

    #[deprecated(since = "2.0.0", note = "Use risk_factors(&config) instead")]
    pub fn risk_factors_legacy(&self) -> Vec<String> {
        self.risk_factors(&DetectionConfig::default())
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub struct FileSignature {
    pub path: Arc<str>,
    pub uid: u32,
    pub is_suspicious_path: bool,
    #[serde(default)]
    pub has_mtime_anomaly: bool,
    #[serde(default)]
    pub recently_modified: bool,
    #[serde(default)]
    pub permissions: Option<Arc<str>>,
    #[serde(default)]
    pub owner: Option<Arc<str>>,
    #[serde(default)]
    pub group: Option<Arc<str>>,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub is_world_writable: bool,
    #[serde(default)]
    pub is_group_writable: bool,
}

impl FileSignature {
    pub fn risk_factors(&self, _config: &DetectionConfig) -> Vec<String> {
        let mut factors = Vec::new();
        if self.is_suspicious_path {
            factors.push(format!("Suspicious file path: {}", self.path.as_ref()));
        }
        if self.path.contains("/etc") || self.path.contains("/bin") || self.path.contains("/sbin") {
            factors.push(format!("System directory access: {}", self.path.as_ref()));
        }
        if self.path.contains("/tmp") {
            factors.push("Temporary directory access".to_string());
        }
        if self.uid == 0 && !self.path.starts_with("/proc") && !self.path.starts_with("/sys") {
            factors.push(format!("Root user accessed: {}", self.path.as_ref()));
        }
        if self.is_world_writable {
            factors.push("World-writable file permissions".to_string());
        }
        if self.is_group_writable && !self.is_world_writable {
            factors.push("Group-writable file permissions".to_string());
        }
        if let Some(ref p) = self.permissions {
            if !p.is_empty() {
                factors.push(format!("Permissions: {}", p.as_ref()));
            }
        }
        if let Some(ref o) = self.owner {
            if !o.is_empty() {
                factors.push(format!("Owner: {}", o.as_ref()));
            }
        }
        if let Some(ref g) = self.group {
            if !g.is_empty() {
                factors.push(format!("Group: {}", g.as_ref()));
            }
        }
        if let Some(sz) = self.size {
            factors.push(format!("Size: {} bytes", sz));
        }
        if self.has_mtime_anomaly {
            factors.push("MTIME ANOMALY: file modification time differs from fleet baseline".to_string());
        }
        if self.recently_modified {
            factors.push(
                "RECENTLY MODIFIED: mtime close to access (sensitive path or elevated/suspicious context)"
                    .to_string(),
            );
        }
        factors
    }
}

#[derive(Debug, Clone)]
pub struct MachineProfile {
    pub id: String,
    pub counts: HashMap<ProcessSignature, u32>,
    pub total_logs: u32,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
}

impl MachineProfile {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            counts: HashMap::new(),
            total_logs: 0,
            first_seen: None,
            last_seen: None,
        }
    }

    pub fn add_process(&mut self, sig: ProcessSignature, timestamp: Option<DateTime<Utc>>) {
        *self.counts.entry(sig).or_insert(0) += 1;
        self.total_logs += 1;
        if let Some(ts) = timestamp {
            if self.first_seen.is_none() || ts < self.first_seen.unwrap() {
                self.first_seen = Some(ts);
            }
            if self.last_seen.is_none() || ts > self.last_seen.unwrap() {
                self.last_seen = Some(ts);
            }
        }
    }

    pub fn find_new_processes(&self, baseline: &MachineProfile) -> Vec<&ProcessSignature> {
        self.counts
            .keys()
            .filter(|sig| !baseline.counts.contains_key(sig))
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct MachineFileProfile {
    pub id: String,
    pub counts: HashMap<FileSignature, u32>,
    pub total_logs: u32,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub file_mtimes: HashMap<Arc<str>, DateTime<Utc>>,
    /// Latest observed owner string per path (for fleet-wide metadata comparison).
    pub file_path_owner: HashMap<Arc<str>, Arc<str>>,
    pub file_path_group: HashMap<Arc<str>, Arc<str>>,
    pub file_path_size: HashMap<Arc<str>, u64>,
}

impl MachineFileProfile {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            counts: HashMap::new(),
            total_logs: 0,
            first_seen: None,
            last_seen: None,
            file_mtimes: HashMap::new(),
            file_path_owner: HashMap::new(),
            file_path_group: HashMap::new(),
            file_path_size: HashMap::new(),
        }
    }

    pub fn add_file(&mut self, sig: FileSignature, timestamp: Option<DateTime<Utc>>, mtime: Option<DateTime<Utc>>) {
        *self.counts.entry(sig.clone()).or_insert(0) += 1;
        self.total_logs += 1;
        if let Some(mt) = mtime {
            self.file_mtimes.insert(sig.path.clone(), mt);
        }
        if let Some(ref o) = sig.owner {
            if !o.is_empty() {
                self.file_path_owner.insert(sig.path.clone(), o.clone());
            }
        }
        if let Some(ref g) = sig.group {
            if !g.is_empty() {
                self.file_path_group.insert(sig.path.clone(), g.clone());
            }
        }
        if let Some(sz) = sig.size {
            self.file_path_size.insert(sig.path.clone(), sz);
        }
        if let Some(ts) = timestamp {
            if self.first_seen.is_none() || ts < self.first_seen.unwrap() {
                self.first_seen = Some(ts);
            }
            if self.last_seen.is_none() || ts > self.last_seen.unwrap() {
                self.last_seen = Some(ts);
            }
        }
    }

    pub fn file_paths_with_mtimes(&self) -> impl Iterator<Item = (Arc<str>, Option<DateTime<Utc>>)> + '_ {
        self.counts.keys().map(move |sig| {
            let mtime = self.file_mtimes.get(&sig.path).copied();
            (sig.path.clone(), mtime)
        })
    }
}
