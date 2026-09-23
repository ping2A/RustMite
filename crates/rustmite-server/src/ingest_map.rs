//! Per-host JSONL field mapping for virtual ingest (defaults + user overrides).

use std::collections::BTreeMap;

use rustmite_sift::RawLogEntry;
use rustmite_store::HostRecord;
use serde::{Deserialize, Serialize};

pub const LABEL_KEY: &str = "ingest_map";

/// How to build the scored / displayed command line from mapped fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum CommandCompose {
    /// Prefer a single `command`/`cmdline` field when present.
    #[default]
    CommandField,
    /// `path` + `args` (IronSift / osquery style).
    PathThenArgs,
    /// `name` + `args`.
    NameThenArgs,
}

/// Ordered alias lists for each logical field (first hit wins).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessFieldMap {
    #[serde(default = "default_pid")]
    pub pid: Vec<String>,
    #[serde(default = "default_ppid")]
    pub ppid: Vec<String>,
    #[serde(default = "default_name")]
    pub name: Vec<String>,
    #[serde(default = "default_path")]
    pub path: Vec<String>,
    #[serde(default = "default_args")]
    pub args: Vec<String>,
    /// Full command line (PulseSecure `command`, osquery `cmdline`, …).
    #[serde(default = "default_command")]
    pub command: Vec<String>,
    #[serde(default = "default_uid")]
    pub uid: Vec<String>,
    #[serde(default = "default_machine")]
    pub machine_id: Vec<String>,
    #[serde(default = "default_timestamp")]
    pub timestamp: Vec<String>,
    #[serde(default)]
    pub compose: CommandCompose,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileFieldMap {
    #[serde(default = "default_file_path")]
    pub path: Vec<String>,
    #[serde(default = "default_machine")]
    pub machine_id: Vec<String>,
    #[serde(default = "default_timestamp")]
    pub timestamp: Vec<String>,
    #[serde(default = "default_mtime")]
    pub mtime: Vec<String>,
    #[serde(default = "default_perms")]
    pub permissions: Vec<String>,
    #[serde(default = "default_owner")]
    pub owner: Vec<String>,
    #[serde(default = "default_group")]
    pub group: Vec<String>,
    #[serde(default = "default_size")]
    pub size: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualIngestMap {
    /// Preset id used as the starting point (`pulsesecure`, `osquery`, `custom`).
    #[serde(default = "default_preset")]
    pub preset: String,
    #[serde(default)]
    pub process: ProcessFieldMap,
    #[serde(default)]
    pub file: FileFieldMap,
}

fn default_preset() -> String {
    "pulsesecure".into()
}
fn default_pid() -> Vec<String> {
    vec!["pid".into(), "process_id".into(), "ProcessId".into()]
}
fn default_ppid() -> Vec<String> {
    vec![
        "ppid".into(),
        "parent_pid".into(),
        "parent".into(),
        "ParentProcessId".into(),
    ]
}
fn default_name() -> Vec<String> {
    vec![
        "name".into(),
        "comm".into(),
        "process".into(),
        "process_name".into(),
        "ProcessName".into(),
    ]
}
fn default_path() -> Vec<String> {
    vec![
        "path".into(),
        "exe".into(),
        "executable".into(),
        "Image".into(),
        "image".into(),
        "ImagePath".into(),
    ]
}
fn default_args() -> Vec<String> {
    vec!["args".into(), "arguments".into(), "params".into()]
}
fn default_command() -> Vec<String> {
    vec![
        "command".into(),
        "cmd".into(),
        "cmdline".into(),
        "commandline".into(),
        "CommandLine".into(),
        "command_line".into(),
        "ProcessCommandLine".into(),
    ]
}
fn default_uid() -> Vec<String> {
    vec!["uid".into(), "user".into(), "user_id".into(), "userid".into()]
}
fn default_machine() -> Vec<String> {
    vec![
        "machine_id".into(),
        "hostname".into(),
        "host".into(),
        "server".into(),
        "node".into(),
    ]
}
fn default_timestamp() -> Vec<String> {
    vec![
        "timestamp".into(),
        "time".into(),
        "datetime".into(),
        "start_time".into(),
    ]
}
fn default_file_path() -> Vec<String> {
    vec!["file_path".into(), "path".into(), "TargetFilename".into()]
}
fn default_mtime() -> Vec<String> {
    vec!["date".into(), "mtime".into(), "modified".into()]
}
fn default_perms() -> Vec<String> {
    vec!["permissions".into(), "mode".into()]
}
fn default_owner() -> Vec<String> {
    vec!["owner".into(), "user".into()]
}
fn default_group() -> Vec<String> {
    vec!["group".into()]
}
fn default_size() -> Vec<String> {
    vec!["size".into()]
}

impl Default for ProcessFieldMap {
    fn default() -> Self {
        Self {
            pid: default_pid(),
            ppid: default_ppid(),
            name: default_name(),
            path: default_path(),
            args: default_args(),
            command: default_command(),
            uid: default_uid(),
            machine_id: default_machine(),
            timestamp: default_timestamp(),
            compose: CommandCompose::CommandField,
        }
    }
}

impl Default for FileFieldMap {
    fn default() -> Self {
        Self {
            path: default_file_path(),
            machine_id: default_machine(),
            timestamp: default_timestamp(),
            mtime: default_mtime(),
            permissions: default_perms(),
            owner: default_owner(),
            group: default_group(),
            size: default_size(),
        }
    }
}

impl Default for VirtualIngestMap {
    fn default() -> Self {
        Self::preset_pulsesecure()
    }
}

impl VirtualIngestMap {
    pub fn preset_pulsesecure() -> Self {
        Self {
            preset: "pulsesecure".into(),
            process: ProcessFieldMap {
                compose: CommandCompose::CommandField,
                ..Default::default()
            },
            file: FileFieldMap::default(),
        }
    }

    pub fn preset_osquery() -> Self {
        Self {
            preset: "osquery".into(),
            process: ProcessFieldMap {
                command: vec!["cmdline".into()],
                path: vec!["path".into(), "cwd".into()],
                name: vec!["name".into(), "comm".into()],
                compose: CommandCompose::PathThenArgs,
                ..Default::default()
            },
            file: FileFieldMap {
                path: vec!["path".into()],
                ..Default::default()
            },
        }
    }

    pub fn preset_sysmon() -> Self {
        Self {
            preset: "sysmon".into(),
            process: ProcessFieldMap {
                command: vec!["CommandLine".into(), "ParentCommandLine".into()],
                path: vec!["Image".into(), "ImagePath".into()],
                name: vec!["ProcessName".into(), "Image".into()],
                pid: vec!["ProcessId".into(), "pid".into()],
                ppid: vec!["ParentProcessId".into(), "ppid".into()],
                compose: CommandCompose::CommandField,
                ..Default::default()
            },
            file: FileFieldMap {
                path: vec!["TargetFilename".into(), "path".into()],
                ..Default::default()
            },
        }
    }

    pub fn from_preset(name: &str) -> Self {
        match name.trim().to_ascii_lowercase().as_str() {
            "osquery" | "ironsift" => Self::preset_osquery(),
            "sysmon" | "windows" => Self::preset_sysmon(),
            _ => Self::preset_pulsesecure(),
        }
    }

    pub fn presets() -> BTreeMap<&'static str, &'static str> {
        BTreeMap::from([
            ("pulsesecure", "PulseSecure snapshots (event_type + command)"),
            ("osquery", "osquery / IronSift (cmdline, path, name)"),
            ("sysmon", "Sysmon / Windows (CommandLine, Image)"),
            ("custom", "User-edited mapping"),
        ])
    }
}

pub fn map_for_host(host: &HostRecord) -> VirtualIngestMap {
    if let Some(raw) = host.labels.get(LABEL_KEY) {
        if let Ok(m) = serde_json::from_str::<VirtualIngestMap>(raw) {
            return m;
        }
    }
    VirtualIngestMap::default()
}

pub fn map_to_label_value(map: &VirtualIngestMap) -> Result<String, String> {
    serde_json::to_string(map).map_err(|e| e.to_string())
}

fn first_str(v: &serde_json::Value, keys: &[String]) -> Option<String> {
    for k in keys {
        if let Some(x) = v.get(k) {
            if let Some(s) = x.as_str() {
                if !s.is_empty() {
                    return Some(s.to_string());
                }
            }
            if let Some(n) = x.as_u64() {
                return Some(n.to_string());
            }
            if let Some(n) = x.as_i64() {
                return Some(n.to_string());
            }
        }
    }
    None
}

fn first_u32(v: &serde_json::Value, keys: &[String]) -> Option<u32> {
    for k in keys {
        if let Some(x) = v.get(k) {
            if let Some(n) = x.as_u64() {
                return Some(n as u32);
            }
            if let Some(s) = x.as_str() {
                if let Ok(n) = s.parse::<u32>() {
                    return Some(n);
                }
            }
        }
    }
    None
}

/// Map one JSON object into a process [`RawLogEntry`] using the host field map.
pub fn process_from_value(
    v: &serde_json::Value,
    map: &VirtualIngestMap,
    default_machine: &str,
) -> Option<RawLogEntry> {
    let pm = &map.process;
    let machine_id = first_str(v, &pm.machine_id).unwrap_or_else(|| default_machine.to_string());
    let pid = first_u32(v, &pm.pid).unwrap_or(0);
    let ppid = first_u32(v, &pm.ppid).unwrap_or(0);
    let uid = first_u32(v, &pm.uid).unwrap_or(0);
    let timestamp = first_str(v, &pm.timestamp);

    let command = first_str(v, &pm.command);
    let path = first_str(v, &pm.path).unwrap_or_default();
    let args = first_str(v, &pm.args).unwrap_or_default();
    let name = first_str(v, &pm.name).unwrap_or_default();

    let (name, path, args) = match pm.compose {
        CommandCompose::CommandField => {
            if let Some(cmd) = command {
                let parts: Vec<&str> = cmd.split_whitespace().collect();
                if parts.is_empty() {
                    return None;
                }
                let n = if name.is_empty() {
                    std::path::Path::new(parts[0])
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or(parts[0])
                        .to_string()
                } else {
                    name
                };
                let p = if path.is_empty() {
                    parts[0].to_string()
                } else {
                    path
                };
                let a = if args.is_empty() && parts.len() > 1 {
                    parts[1..].join(" ")
                } else {
                    args
                };
                (n, p, a)
            } else if !path.is_empty() || !name.is_empty() {
                let n = if name.is_empty() {
                    std::path::Path::new(&path)
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or(path.as_str())
                        .to_string()
                } else {
                    name
                };
                (n, path, args)
            } else {
                return None;
            }
        }
        CommandCompose::PathThenArgs => {
            if path.is_empty() && name.is_empty() && command.is_none() {
                return None;
            }
            if let Some(cmd) = command.filter(|_| path.is_empty()) {
                let parts: Vec<&str> = cmd.split_whitespace().collect();
                let p = parts.first().copied().unwrap_or("").to_string();
                let a = if parts.len() > 1 {
                    parts[1..].join(" ")
                } else {
                    args
                };
                let n = if name.is_empty() {
                    std::path::Path::new(&p)
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or(&p)
                        .to_string()
                } else {
                    name
                };
                (n, p, a)
            } else {
                let n = if name.is_empty() {
                    std::path::Path::new(&path)
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or(path.as_str())
                        .to_string()
                } else {
                    name
                };
                (n, path, args)
            }
        }
        CommandCompose::NameThenArgs => {
            if name.is_empty() && command.is_none() {
                return None;
            }
            if let Some(cmd) = command.filter(|_| name.is_empty()) {
                let parts: Vec<&str> = cmd.split_whitespace().collect();
                let n = parts.first().copied().unwrap_or("").to_string();
                let a = if parts.len() > 1 {
                    parts[1..].join(" ")
                } else {
                    args
                };
                (n, path, a)
            } else {
                (name, path, args)
            }
        }
    };

    if name.is_empty() && path.is_empty() {
        return None;
    }
    Some(RawLogEntry {
        machine_id,
        pid,
        ppid,
        name,
        uid,
        path,
        args,
        timestamp,
    })
}

/// Map one JSON object into a file [`RawFileEntry`] using the host field map.
pub fn file_from_value(
    v: &serde_json::Value,
    map: &VirtualIngestMap,
    default_machine: &str,
) -> Option<rustmite_sift::RawFileEntry> {
    let fm = &map.file;
    let path = first_str(v, &fm.path)?.trim().to_string();
    if path.is_empty() {
        return None;
    }
    Some(rustmite_sift::RawFileEntry {
        machine_id: first_str(v, &fm.machine_id).unwrap_or_else(|| default_machine.to_string()),
        path,
        uid: 0,
        timestamp: first_str(v, &fm.timestamp),
        mtime: first_str(v, &fm.mtime),
        permissions: first_str(v, &fm.permissions),
        owner: first_str(v, &fm.owner),
        group: first_str(v, &fm.group),
        size: first_str(v, &fm.size)
            .and_then(|s| s.parse().ok())
            .or_else(|| first_u32(v, &fm.size).map(|n| n as u64)),
    })
}

/// Preview mapping against raw JSON lines (for the UI).
pub fn preview_process_lines(
    content: &str,
    map: &VirtualIngestMap,
    default_machine: &str,
    limit: usize,
) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for line in content.lines() {
        if out.len() >= limit {
            break;
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        // Skip non-process event_type when present.
        if let Some(et) = v.get("event_type").and_then(|x| x.as_str()) {
            let et = et.to_ascii_lowercase();
            if !et.is_empty()
                && et != "process"
                && !et.contains("process")
            {
                continue;
            }
        }
        let mapped = process_from_value(&v, map, default_machine);
        out.push(serde_json::json!({
            "raw_keys": v.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>()).unwrap_or_default(),
            "mapped": mapped,
        }));
    }
    out
}

/// Collect distinct keys seen in sample JSONL (helps users edit the map).
pub fn sniff_keys(content: &str, limit_lines: usize) -> Vec<String> {
    let mut keys = BTreeMap::new();
    for (i, line) in content.lines().enumerate() {
        if i >= limit_lines {
            break;
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(serde_json::Value::Object(o)) = serde_json::from_str::<serde_json::Value>(line) {
            for k in o.keys() {
                *keys.entry(k.clone()).or_insert(0u32) += 1;
            }
        }
    }
    keys.into_iter().map(|(k, _)| k).collect()
}
