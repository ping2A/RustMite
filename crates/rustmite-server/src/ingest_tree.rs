//! Fleet tree import: each subdirectory → one virtual host + optional scan snapshot.
//!
//! Designed for PulseSecure periodic snapshots laid out as:
//! ```text
//! /…/2026-05-10/
//!   PulseSecure-Periodicsnapshot-standalone-HOSTEXAMPLE01-20260511-0012/
//!     *.jsonl   (mixed: file_information, process, network_connection, …)
//!   PulseSecure-Periodicsnapshot-standalone-EDGEVPN01…/
//!     *.jsonl
//! ```
//!
//! Or a campaign parent that contains several day folders:
//! ```text
//! /…/vpn/
//!   2026-05-03/
//!     PulseSecure-Periodicsnapshot-standalone-HOST…/
//!   2026-05-10/
//!     …
//! ```
//! Pass the parent path (and optional `days`) to import every selected day with the
//! same naming / virtual-agent options.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use rustmite_proto::{
    Arch, BigInt, DeliveryReport, FileMetaObs, Observation, PathBytes, ProcessObs,
    ScanInventorySummary, ScanMeta, ScanOutcome, SocketObs,
};
use rustmite_sift::{parse_jsonl_process_line, RawFileEntry, RawLogEntry};
use rustmite_store::{
    CompleteScan, EnqueueScan, HostRecord, Store, UpdateHost, UpsertHost,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::routes::{ApiError, AppState};
use crate::sift_api::{
    collect_jsonl_files_under, replace_virtual_file_logs, replace_virtual_process_logs,
    VirtualIngestKind,
};

#[derive(Debug, Deserialize)]
pub struct ImportTreeBody {
    /// Root directory; each immediate subdirectory is one host snapshot.
    pub path: String,
    /// How to derive the host display name from the subdirectory name.
    /// - `dirname` / `dir` / `full`: use the full subdirectory name (IronSift-style default for plain folders)
    /// - `pulsesecure`: extract hostname from PulseSecure snapshot folder names
    /// - `segment`: take the N-th segment (see `parent_dir_field` + `delimiter`) — same as IronSift zip device rule
    #[serde(default = "default_host_from")]
    pub host_from: String,
    /// 1-based segment index when `host_from` is `segment` (IronSift `parent_dir_field`).
    /// Also used when set with `host_from=pulsesecure` as an override of the heuristic.
    #[serde(default)]
    pub parent_dir_field: Option<usize>,
    /// Delimiter when splitting the subdirectory name (default `-`).
    #[serde(default = "default_delimiter")]
    pub delimiter: String,
    /// Replace current virtual JSONL (new current snapshot). Default true.
    #[serde(default = "default_true")]
    pub replace: bool,
    /// Create a Store scan + observations (shows up as a real scan). Default true.
    #[serde(default = "default_true")]
    pub create_scan: bool,
    /// `auto` | `processes` | `files` — for non-event_type JSONL. Default auto.
    #[serde(default)]
    pub kind: Option<String>,
    /// Optional label applied to every imported host (`source=…`).
    #[serde(default)]
    pub source_label: Option<String>,
    /// Named virtual-agent profile (Settings → Virtual agents) applied to every host.
    #[serde(default)]
    pub virtual_agent_id: Option<String>,
    /// Optional platform identity applied to every imported host.
    #[serde(default)]
    pub arch: Option<String>,
    #[serde(default)]
    pub kernel: Option<String>,
    #[serde(default)]
    pub os: Option<String>,
    /// Host labels (env / profile / region / tags / …) applied to every imported host.
    #[serde(default)]
    pub labels: Option<BTreeMap<String, String>>,
    /// Tags applied to each scan created by this tree import.
    #[serde(default)]
    pub scan_tags: Option<Vec<String>>,
    /// Comma-separated convenience (merged into `scan_tags`).
    #[serde(default)]
    pub scan_tag: Option<String>,
    /// When the root is a campaign folder of `YYYY-MM-DD` day dirs, only import these
    /// day names. Empty / omitted = all day folders under the root (auto-detected).
    #[serde(default)]
    pub days: Option<Vec<String>>,
    /// Force campaign (day-folder) expansion even if the root is mixed.
    #[serde(default)]
    pub campaign: Option<bool>,
    /// Optional filter: only import these host subdirectory names (exact match).
    /// Used by the UI to import one host at a time for live progress.
    #[serde(default)]
    pub host_dirs: Option<Vec<String>>,
}

/// Browser folder upload: same as [`ImportTreeBody`] but files arrive inline with
/// relative paths (`webkitRelativePath`). Each top-level directory becomes one host.
#[derive(Debug, Deserialize)]
pub struct ImportTreeUploadBody {
    #[serde(default = "default_host_from")]
    pub host_from: String,
    #[serde(default)]
    pub parent_dir_field: Option<usize>,
    #[serde(default = "default_delimiter")]
    pub delimiter: String,
    #[serde(default = "default_true")]
    pub replace: bool,
    #[serde(default = "default_true")]
    pub create_scan: bool,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub source_label: Option<String>,
    #[serde(default)]
    pub virtual_agent_id: Option<String>,
    #[serde(default)]
    pub arch: Option<String>,
    #[serde(default)]
    pub kernel: Option<String>,
    #[serde(default)]
    pub os: Option<String>,
    /// Host labels (env / profile / region / tags / …) applied to every imported host.
    #[serde(default)]
    pub labels: Option<BTreeMap<String, String>>,
    /// Tags applied to each scan created by this tree import.
    #[serde(default)]
    pub scan_tags: Option<Vec<String>>,
    /// Comma-separated convenience (merged into `scan_tags`).
    #[serde(default)]
    pub scan_tag: Option<String>,
    /// Relative path + contents (e.g. `HOSTDIR/snapshot.jsonl`).
    pub files: Vec<crate::ingest_virtual::InlineIngestFile>,
}

fn default_host_from() -> String {
    "dirname".into()
}
fn default_delimiter() -> String {
    "-".into()
}
fn default_true() -> bool {
    true
}

pub(crate) fn coalesce_scan_tags(
    tags: Option<Vec<String>>,
    tag: Option<String>,
) -> Vec<String> {
    let mut v = tags.unwrap_or_default();
    if let Some(t) = tag {
        if !t.trim().is_empty() {
            v.push(t);
        }
    }
    rustmite_store::normalize_scan_tags(v)
}

/// Parent folder name used as a scan tag so multi-day imports of the same host
/// stay distinguishable (day folder `YYYY-MM-DD`, or the immediate parent dir).
fn parent_dir_scan_tag(host_dir: &Path, day: Option<&str>) -> Option<String> {
    if let Some(d) = day.map(str::trim).filter(|s| !s.is_empty()) {
        return Some(d.to_string());
    }
    host_dir
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn with_parent_scan_tag(base: &[String], parent: Option<&str>) -> Vec<String> {
    let mut v = base.to_vec();
    if let Some(p) = parent.map(str::trim).filter(|s| !s.is_empty()) {
        v.push(p.to_string());
    }
    rustmite_store::normalize_scan_tags(v)
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportTreeHostResult {
    pub dir: String,
    pub host_id: Uuid,
    pub display_name: String,
    pub created: bool,
    pub scan_id: Option<Uuid>,
    pub processes: usize,
    pub files: usize,
    pub sockets: usize,
    pub skipped: usize,
    pub error: Option<String>,
    /// Day folder name when importing a campaign parent (`YYYY-MM-DD`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub day: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportTreeSummary {
    pub root: String,
    pub hosts_ok: usize,
    pub hosts_failed: usize,
    #[serde(default)]
    pub hosts_skipped: usize,
    /// True when root was treated as a parent of day folders.
    #[serde(default)]
    pub campaign: bool,
    /// Day folders that were imported (campaign mode).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub days: Vec<String>,
    pub results: Vec<ImportTreeHostResult>,
}

/// `YYYY-MM-DD` day-folder name (campaign layout).
pub fn looks_like_iso_day_folder(name: &str) -> bool {
    let b = name.as_bytes();
    if b.len() != 10 {
        return false;
    }
    b[4] == b'-'
        && b[7] == b'-'
        && b[0..4].iter().all(u8::is_ascii_digit)
        && b[5..7].iter().all(u8::is_ascii_digit)
        && b[8..10].iter().all(u8::is_ascii_digit)
}

/// Extract hostname from PulseSecure snapshot directory names.
///
/// Examples:
/// - `PulseSecure-Periodicsnapshot-standalone-HOSTEXAMPLE01-20260511-0012` → `HOSTEXAMPLE01`
/// - `PulseSecure-Periodicsnapshot-CLUSTER_LIC-LIC_EXAMPLE-20260513-2130` → `LIC_EXAMPLE`
pub fn host_name_from_pulsesecure_dir(dirname: &str) -> String {
    let name = dirname.trim().trim_end_matches('/');
    let Some(rest) = name.strip_prefix("PulseSecure-Periodicsnapshot-") else {
        return name.to_string();
    };
    // Strip mode prefix: standalone- or CLUSTER_* -
    let rest = if let Some(r) = rest.strip_prefix("standalone-") {
        r
    } else if let Some(idx) = rest.find('-') {
        // CLUSTER_LIC-LIC_EXAMPLE-20260513-2130 → after first segment
        &rest[idx + 1..]
    } else {
        rest
    };
    // Strip trailing -YYYYMMDD-HHMM (or -HHMMSS)
    let parts: Vec<&str> = rest.split('-').collect();
    if parts.len() >= 3 {
        let last = parts[parts.len() - 1];
        let prev = parts[parts.len() - 2];
        if prev.len() == 8 && prev.chars().all(|c| c.is_ascii_digit())
            && (last.len() == 4 || last.len() == 6)
            && last.chars().all(|c| c.is_ascii_digit())
        {
            return parts[..parts.len() - 2].join("-");
        }
    }
    rest.to_string()
}

pub fn resolve_host_name(dirname: &str, host_from: &str) -> String {
    resolve_host_name_ex(dirname, host_from, None, '-')
}

/// Resolve host display name from a snapshot subdirectory (IronSift-compatible).
///
/// - `dirname` / `dir` / `full` → entire folder name
/// - `segment` → `parent_dir_field`-th split by `delimiter` (1-based; IronSift zip device rule)
/// - `pulsesecure` → PulseSecure snapshot heuristic (falls back to segment field 4 if heuristic fails)
pub fn resolve_host_name_ex(
    dirname: &str,
    host_from: &str,
    parent_dir_field: Option<usize>,
    delimiter: char,
) -> String {
    let name = dirname.trim().trim_end_matches('/');
    match host_from.trim().to_ascii_lowercase().as_str() {
        "dirname" | "dir" | "full" => name.to_string(),
        "segment" | "parent_dir" | "field" => {
            let field = parent_dir_field.unwrap_or(4).max(1);
            rustmite_sift::parent_dir_segment_tag(name, field, delimiter)
                .unwrap_or_else(|| name.to_string())
        }
        "pulsesecure" | "pulse" => {
            if let Some(field) = parent_dir_field.filter(|f| *f >= 1) {
                return rustmite_sift::parent_dir_segment_tag(name, field, delimiter)
                    .unwrap_or_else(|| host_name_from_pulsesecure_dir(name));
            }
            host_name_from_pulsesecure_dir(name)
        }
        _ => {
            // Unknown mode: prefer explicit segment if provided, else dirname.
            if let Some(field) = parent_dir_field.filter(|f| *f >= 1) {
                rustmite_sift::parent_dir_segment_tag(name, field, delimiter)
                    .unwrap_or_else(|| name.to_string())
            } else {
                name.to_string()
            }
        }
    }
}

/// Split a PulseSecure (or mixed) JSONL blob into process / file / socket rows.
pub fn parse_mixed_snapshot_jsonl(
    content: &str,
    default_machine: &str,
) -> (Vec<RawLogEntry>, Vec<RawFileEntry>, Vec<SocketObs>, usize) {
    parse_mixed_snapshot_jsonl_with_map(
        content,
        default_machine,
        &crate::ingest_map::VirtualIngestMap::default(),
    )
}

/// Parse one NDJSON line into process / file / socket (or skip).
pub enum MixedLine {
    Process(RawLogEntry),
    File(RawFileEntry),
    Socket(SocketObs),
    Skip,
}

pub fn parse_mixed_snapshot_line(
    line: &str,
    default_machine: &str,
    map: &crate::ingest_map::VirtualIngestMap,
) -> MixedLine {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
        return MixedLine::Skip;
    }
    let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
        return MixedLine::Skip;
    };
    let event_type = v
        .get("event_type")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    match event_type.as_str() {
        "process" => {
            match crate::ingest_map::process_from_value(&v, map, default_machine)
                .or_else(|| parse_jsonl_process_line(line, default_machine).ok())
            {
                Some(e) => MixedLine::Process(e),
                None => MixedLine::Skip,
            }
        }
        "file_information" | "file" | "file_meta" => {
            match crate::ingest_map::file_from_value(&v, map, default_machine)
                .or_else(|| file_entry_from_value(&v, default_machine))
            {
                Some(e) => MixedLine::File(e),
                None => MixedLine::Skip,
            }
        }
        "network_connection" | "socket" | "connection" => match socket_from_value(&v) {
            Some(s) => MixedLine::Socket(s),
            None => MixedLine::Skip,
        },
        "iptables_rule" | "iptables" => MixedLine::Skip,
        "" => {
            if has_process_hints(&v) {
                if let Some(e) = crate::ingest_map::process_from_value(&v, map, default_machine)
                    .or_else(|| parse_jsonl_process_line(line, default_machine).ok())
                {
                    MixedLine::Process(e)
                } else if let Some(e) = crate::ingest_map::file_from_value(&v, map, default_machine)
                    .or_else(|| file_entry_from_value(&v, default_machine))
                {
                    MixedLine::File(e)
                } else {
                    MixedLine::Skip
                }
            } else if let Some(e) = crate::ingest_map::file_from_value(&v, map, default_machine)
                .or_else(|| file_entry_from_value(&v, default_machine))
            {
                MixedLine::File(e)
            } else if let Some(e) = crate::ingest_map::process_from_value(&v, map, default_machine)
                .or_else(|| parse_jsonl_process_line(line, default_machine).ok())
            {
                MixedLine::Process(e)
            } else {
                MixedLine::Skip
            }
        }
        _ => MixedLine::Skip,
    }
}

/// Like [`parse_mixed_snapshot_jsonl`], preferring the host/profile field map when set.
pub fn parse_mixed_snapshot_jsonl_with_map(
    content: &str,
    default_machine: &str,
    map: &crate::ingest_map::VirtualIngestMap,
) -> (Vec<RawLogEntry>, Vec<RawFileEntry>, Vec<SocketObs>, usize) {
    let mut procs = Vec::new();
    let mut files = Vec::new();
    let mut sockets = Vec::new();
    let mut skipped = 0usize;

    for line in content.lines() {
        match parse_mixed_snapshot_line(line, default_machine, map) {
            MixedLine::Process(e) => procs.push(e),
            MixedLine::File(e) => files.push(e),
            MixedLine::Socket(s) => sockets.push(s),
            MixedLine::Skip => {
                let t = line.trim();
                if !t.is_empty() && !t.starts_with('#') && !t.starts_with("//") {
                    skipped += 1;
                }
            }
        }
    }
    (procs, files, sockets, skipped)
}

fn has_process_hints(v: &serde_json::Value) -> bool {
    v.get("pid").is_some()
        || v.get("command").is_some()
        || v.get("cmdline").is_some()
        || v.get("CommandLine").is_some()
}

fn file_entry_from_value(v: &serde_json::Value, default_machine: &str) -> Option<RawFileEntry> {
    let path = v
        .get("file_path")
        .or_else(|| v.get("path"))
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())?
        .to_string();
    let machine_id = v
        .get("machine_id")
        .or_else(|| v.get("hostname"))
        .or_else(|| v.get("host"))
        .and_then(|x| x.as_str())
        .unwrap_or(default_machine)
        .to_string();
    Some(RawFileEntry {
        machine_id,
        path,
        uid: v
            .get("uid")
            .and_then(|x| x.as_u64())
            .unwrap_or(0) as u32,
        timestamp: v
            .get("timestamp")
            .and_then(|x| x.as_str())
            .map(str::to_string),
        mtime: v
            .get("date")
            .or_else(|| v.get("mtime"))
            .and_then(|x| x.as_str())
            .map(str::to_string),
        permissions: v
            .get("permissions")
            .or_else(|| v.get("mode"))
            .and_then(|x| x.as_str())
            .map(str::to_string),
        owner: v
            .get("owner")
            .and_then(|x| x.as_str())
            .map(str::to_string),
        group: v
            .get("group")
            .and_then(|x| x.as_str())
            .map(str::to_string),
        size: v.get("size").and_then(|x| x.as_u64()),
    })
}

fn socket_from_value(v: &serde_json::Value) -> Option<SocketObs> {
    let protocol = v
        .get("protocol")
        .and_then(|x| x.as_str())
        .unwrap_or("tcp")
        .to_string();
    let local_ip = v
        .get("source_ip")
        .or_else(|| v.get("local_ip"))
        .and_then(|x| x.as_str())
        .unwrap_or("*")
        .to_string();
    let remote_ip = v
        .get("destination_ip")
        .or_else(|| v.get("remote_ip"))
        .and_then(|x| x.as_str())
        .unwrap_or("*")
        .to_string();
    let local_port = parse_port(v.get("source_port").or_else(|| v.get("local_port")));
    let remote_port = parse_port(
        v.get("destination_port")
            .or_else(|| v.get("remote_port")),
    );
    let owning_pid = v
        .get("program_pid")
        .or_else(|| v.get("pid"))
        .and_then(|x| x.as_i64())
        .map(|n| n as i32);
    Some(SocketObs {
        inode: BigInt::from_u64(0),
        family: "inet".into(),
        protocol,
        state: "unknown".into(),
        local_ip,
        local_port,
        remote_ip,
        remote_port,
        uid: 0,
        owning_pid,
        owning_comm: None,
        owner_unresolved: owning_pid.is_none(),
    })
}

fn parse_port(v: Option<&serde_json::Value>) -> u16 {
    match v {
        Some(serde_json::Value::Number(n)) => n.as_u64().unwrap_or(0) as u16,
        Some(serde_json::Value::String(s)) => s.parse().unwrap_or(0),
        _ => 0,
    }
}

fn process_obs_from_raw(e: &RawLogEntry) -> Observation {
    // Heal older imports that basenamed `[kworker/0:0H]` → `0:0H]`.
    let name = {
        let n = e.name.trim();
        let p = e.path.trim();
        if rustmite_sift::looks_like_kernel_thread_name(p)
            && !rustmite_sift::looks_like_kernel_thread_name(n)
        {
            p.to_string()
        } else {
            e.name.clone()
        }
    };
    let (comm, exe, cmdline) = if e.path.is_empty() && !e.args.is_empty() {
        let parts: Vec<PathBytes> = std::iter::once(name.as_str())
            .chain(e.args.split_whitespace())
            .map(PathBytes::from_str)
            .collect();
        (name, None, parts)
    } else {
        let mut cmdline = vec![PathBytes::from_str(if e.path.is_empty() {
            name.as_str()
        } else {
            e.path.as_str()
        })];
        if !e.args.is_empty() {
            for p in e.args.split_whitespace() {
                cmdline.push(PathBytes::from_str(p));
            }
        }
        let exe = if e.path.is_empty() {
            None
        } else {
            Some(PathBytes::from_str(&e.path))
        };
        (name, exe, cmdline)
    };
    Observation::Process(ProcessObs {
        pid: e.pid as i32,
        ppid: e.ppid as i32,
        comm,
        exe,
        exe_deleted: false,
        exe_memfd: false,
        cmdline,
        cwd: None,
        root: None,
        uids: [e.uid, e.uid, e.uid, e.uid],
        gids: [0, 0, 0, 0],
        username: None,
        starttime: 0,
        num_threads: 1,
        tty: 0,
        state: 'S',
        caps_eff: 0,
        ns: Default::default(),
        rwx_maps: 0,
        unbacked_exec: 0,
        listen_ports: vec![],
        selinux: None,
        environ_flags: vec![],
    })
}

fn file_obs_from_raw(e: &RawFileEntry) -> Observation {
    let mode = parse_ls_mode(e.permissions.as_deref().unwrap_or(""));
    Observation::FileMeta(FileMetaObs {
        path: PathBytes::from_str(&e.path),
        mode,
        uid: e.uid,
        gid: 0,
        size: BigInt::from_u64(e.size.unwrap_or(0)),
        inode: BigInt::from_u64(0),
        nlink: 1,
        setuid: mode & 0o4000 != 0,
        setgid: mode & 0o2000 != 0,
        immutable: false,
        owner: e.owner.clone(),
        group: e.group.clone(),
    })
}

/// Parse `drwxr-xr-x.` / `-rwxr-xr-x` style permission strings into a unix mode.
fn parse_ls_mode(s: &str) -> u32 {
    let s = s.trim().trim_end_matches('.');
    if s.len() < 10 {
        return 0;
    }
    let chars: Vec<char> = s.chars().collect();
    let mut mode = 0u32;
    // skip type char
    let bits = [
        (1, 'r', 0o400),
        (2, 'w', 0o200),
        (3, 'x', 0o100),
        (3, 's', 0o4100),
        (3, 'S', 0o4000),
        (4, 'r', 0o040),
        (5, 'w', 0o020),
        (6, 'x', 0o010),
        (6, 's', 0o2010),
        (6, 'S', 0o2000),
        (7, 'r', 0o004),
        (8, 'w', 0o002),
        (9, 'x', 0o001),
        (9, 't', 0o1001),
        (9, 'T', 0o1000),
    ];
    for &(idx, ch, bit) in &bits {
        if chars.get(idx) == Some(&ch) {
            mode |= bit;
        }
    }
    mode
}

/// Normalize optional arch / kernel / OS strings for host updates.
pub fn platform_patch(
    arch: Option<&str>,
    kernel: Option<&str>,
    os: Option<&str>,
) -> UpdateHost {
    let mut patch = UpdateHost::default();
    if let Some(a) = arch.map(str::trim).filter(|s| !s.is_empty()) {
        let known = Arch::from_uname(a);
        patch.arch = Some(if known == Arch::Unknown {
            a.to_string()
        } else {
            known.as_str().to_string()
        });
    }
    if let Some(k) = kernel.map(str::trim).filter(|s| !s.is_empty()) {
        patch.kernel = Some(k.to_string());
    }
    if let Some(o) = os.map(str::trim).filter(|s| !s.is_empty()) {
        patch.os = Some(o.to_string());
    }
    patch
}

fn host_scan_arch(host: &HostRecord) -> Arch {
    host.arch
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(Arch::from_uname)
        .unwrap_or(Arch::Unknown)
}

fn merge_operator_labels(
    labels: &mut BTreeMap<String, String>,
    extra: Option<&BTreeMap<String, String>>,
) {
    let Some(extra) = extra else {
        return;
    };
    for (k, v) in extra {
        let key = k.trim();
        let val = v.trim();
        if key.is_empty() || val.is_empty() {
            continue;
        }
        labels.insert(key.to_string(), val.to_string());
    }
}

async fn ensure_virtual_host(
    state: &AppState,
    display_name: &str,
    source_label: Option<&str>,
    profile: Option<&crate::virtual_agents::VirtualAgentProfile>,
    platform: Option<&UpdateHost>,
    extra_labels: Option<&BTreeMap<String, String>>,
) -> Result<(HostRecord, bool), ApiError> {
    let before = state.store.list_hosts().await?;
    let prev = before.iter().find(|h| h.display_name == display_name);
    let existed = prev.is_some();
    let mut labels = prev
        .map(|h| h.labels.clone())
        .unwrap_or_default();
    merge_operator_labels(&mut labels, extra_labels);
    labels.insert("agent".into(), "virtual".into());
    if let Some(src) = source_label {
        labels.insert("source".into(), src.to_string());
    }
    if let Some(p) = profile {
        crate::virtual_agents::apply_profile_to_labels(&mut labels, p)
            .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e))?;
    }
    let host = state
        .store
        .upsert_host(UpsertHost {
            id: None,
            tenant_id: Uuid::nil(),
            display_name: display_name.to_string(),
            primary_addr: None,
            ssh_port: Some(0),
            labels,
            timeouts: Default::default(),
            agent_kind: Some("virtual".into()),
            ingest_token: if existed {
                None
            } else {
                Some(format!("va-{}", Uuid::new_v4()))
            },
        })
        .await?;
    let mut patch = UpdateHost {
        auth_status: Some("virtual".into()),
        auth_detail: Some("virtual agent — snapshot ingest".into()),
        auth_checked_at: Some(crate::sys_metrics::utc_now_rfc3339()),
        agent_kind: Some("virtual".into()),
        ..Default::default()
    };
    if let Some(p) = platform {
        if p.arch.is_some() {
            patch.arch = p.arch.clone();
        }
        if p.kernel.is_some() {
            patch.kernel = p.kernel.clone();
        }
        if p.os.is_some() {
            patch.os = p.os.clone();
        }
    }
    let host = state.store.update_host(host.id, patch).await?;
    Ok((host, !existed))
}

async fn emit_tree_progress(
    state: &AppState,
    message: String,
    detail: Option<serde_json::Value>,
) {
    let _ = state
        .store
        .push_activity(rustmite_store::ActivityEvent {
            id: Uuid::new_v4(),
            ts: crate::sys_metrics::utc_now_rfc3339(),
            level: "progress".into(),
            kind: "import.tree".into(),
            message,
            scan_id: None,
            host_id: None,
            node_id: None,
            detail,
        })
        .await;
}

/// Operator: import a directory tree of host snapshots.
pub async fn import_virtual_tree(
    State(state): State<AppState>,
    Json(body): Json<ImportTreeBody>,
) -> Result<impl IntoResponse, ApiError> {
    let root = PathBuf::from(body.path.trim());
    if !root.is_dir() {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            format!("not a directory: {}", root.display()),
        ));
    }
    let host_from = body.host_from.clone();
    let parent_dir_field = body.parent_dir_field;
    let delimiter = body
        .delimiter
        .chars()
        .next()
        .filter(|c| !c.is_whitespace())
        .unwrap_or('-');
    let profile = if let Some(pid) = body
        .virtual_agent_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(state.virtual_agents.get(pid).await.ok_or_else(|| {
            ApiError(
                StatusCode::BAD_REQUEST,
                format!("unknown virtual agent profile: {pid}"),
            )
        })?)
    } else {
        None
    };
    let kind = VirtualIngestKind::parse(
        body.kind
            .as_deref()
            .or(profile.as_ref().map(|p| p.kind.as_str()))
            .unwrap_or("auto"),
    );
    let mut child_dirs: Vec<PathBuf> = fs::read_dir(&root)
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e.to_string()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    child_dirs.sort();

    if child_dirs.is_empty() {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            format!("no subdirectories under {}", root.display()),
        ));
    }

    let day_children: Vec<(String, PathBuf)> = child_dirs
        .iter()
        .filter_map(|p| {
            let name = p.file_name()?.to_str()?.to_string();
            if looks_like_iso_day_folder(&name) {
                Some((name, p.clone()))
            } else {
                None
            }
        })
        .collect();
    let force_campaign = body.campaign == Some(true) || body.days.as_ref().is_some_and(|d| !d.is_empty());
    let auto_campaign = !day_children.is_empty() && day_children.len() == child_dirs.len();
    let campaign = force_campaign || auto_campaign;

    // Each work unit is (host_subdir_root, optional day label for source=tree:YYYY-MM-DD).
    let mut host_roots: Vec<(PathBuf, Option<String>)> = Vec::new();
    let mut days_imported: Vec<String> = Vec::new();

    if campaign {
        if day_children.is_empty() {
            return Err(ApiError(
                StatusCode::BAD_REQUEST,
                format!(
                    "campaign import expected YYYY-MM-DD day folders under {}",
                    root.display()
                ),
            ));
        }
        let selected: Vec<(String, PathBuf)> = if let Some(want) = body.days.as_ref() {
            let want: Vec<String> = want
                .iter()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if want.is_empty() {
                day_children
            } else {
                let mut picked = Vec::new();
                for name in &want {
                    if !looks_like_iso_day_folder(name) {
                        return Err(ApiError(
                            StatusCode::BAD_REQUEST,
                            format!("invalid day folder name: {name} (expected YYYY-MM-DD)"),
                        ));
                    }
                    let path = root.join(name);
                    if !path.is_dir() {
                        return Err(ApiError(
                            StatusCode::BAD_REQUEST,
                            format!("day folder not found: {}", path.display()),
                        ));
                    }
                    picked.push((name.clone(), path));
                }
                picked
            }
        } else {
            day_children
        };
        for (day, day_path) in selected {
            let mut host_dirs: Vec<PathBuf> = fs::read_dir(&day_path)
                .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e.to_string()))?
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.is_dir())
                .collect();
            host_dirs.sort();
            days_imported.push(day.clone());
            for dir in host_dirs {
                host_roots.push((dir, Some(day.clone())));
            }
        }
        if host_roots.is_empty() {
            return Err(ApiError(
                StatusCode::BAD_REQUEST,
                format!(
                    "no host subdirectories under selected day folders in {}",
                    root.display()
                ),
            ));
        }
    } else {
        for dir in child_dirs {
            host_roots.push((dir, None));
        }
    }

    if let Some(want) = body.host_dirs.as_ref().filter(|v| !v.is_empty()) {
        let want: std::collections::BTreeSet<String> = want
            .iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        host_roots.retain(|(dir, _)| {
            dir.file_name()
                .and_then(|s| s.to_str())
                .map(|n| want.contains(n))
                .unwrap_or(false)
        });
        if host_roots.is_empty() {
            return Err(ApiError(
                StatusCode::BAD_REQUEST,
                format!(
                    "no matching host directories for host_dirs filter under {}",
                    root.display()
                ),
            ));
        }
    }

    let mut results = Vec::new();
    let mut ok = 0usize;
    let mut failed = 0usize;
    let mut skipped = 0usize;
    let platform = platform_patch(body.arch.as_deref(), body.kernel.as_deref(), body.os.as_deref());
    let platform_ref = if platform.arch.is_some()
        || platform.kernel.is_some()
        || platform.os.is_some()
    {
        Some(&platform)
    } else {
        None
    };
    let scan_tags = coalesce_scan_tags(body.scan_tags.clone(), body.scan_tag.clone());
    let hosts_total = host_roots.len();
    emit_tree_progress(
        &state,
        format!(
            "Tree import start · {} host folder(s){} under {}",
            hosts_total,
            if campaign {
                format!(" across {} day(s)", days_imported.len())
            } else {
                String::new()
            },
            root.display()
        ),
        Some(serde_json::json!({
            "phase": "start",
            "campaign": campaign,
            "days": days_imported,
            "hosts_total": hosts_total,
            "root": root.display().to_string(),
        })),
    )
    .await;

    for (idx, (dir, day)) in host_roots.into_iter().enumerate() {
        let index = idx + 1;
        let dirname = dir
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("host")
            .to_string();
        let display_name =
            resolve_host_name_ex(&dirname, &host_from, parent_dir_field, delimiter);
        let source_label = body.source_label.clone().or_else(|| {
            day.as_ref()
                .map(|d| format!("tree:{d}"))
                .or_else(|| {
                    root.file_name()
                        .and_then(|s| s.to_str())
                        .map(|s| format!("tree:{s}"))
                })
        });
        let day_prefix = day
            .as_ref()
            .map(|d| format!("{d} · "))
            .unwrap_or_default();
        emit_tree_progress(
            &state,
            format!("[{index}/{hosts_total}] {day_prefix}importing {display_name}"),
            Some(serde_json::json!({
                "phase": "host_start",
                "index": index,
                "total": hosts_total,
                "day": day,
                "dir": dirname,
                "display_name": display_name,
            })),
        )
        .await;
        tracing::info!(
            index,
            total = hosts_total,
            day = day.as_deref().unwrap_or(""),
            %display_name,
            dir = %dirname,
            "tree import host start"
        );

        let mut row = ImportTreeHostResult {
            dir: dirname.clone(),
            host_id: Uuid::nil(),
            display_name: display_name.clone(),
            created: false,
            scan_id: None,
            processes: 0,
            files: 0,
            sockets: 0,
            skipped: 0,
            error: None,
            day: day.clone(),
        };

        let parent_tag = parent_dir_scan_tag(&dir, day.as_deref());
        let host_scan_tags = with_parent_scan_tag(&scan_tags, parent_tag.as_deref());

        match import_one_host_dir(
            &state,
            &dir,
            &display_name,
            source_label.as_deref(),
            body.replace,
            body.create_scan,
            kind,
            profile.as_ref(),
            platform_ref,
            &host_scan_tags,
            body.labels.as_ref(),
        )
        .await
        {
            Ok(mut r) => {
                r.day = day.clone();
                emit_tree_progress(
                    &state,
                    format!(
                        "[{index}/{hosts_total}] {day_prefix}ok {}{} · {}p / {}f / {}s",
                        r.display_name,
                        if r.created { " (new)" } else { "" },
                        r.processes,
                        r.files,
                        r.sockets
                    ),
                    Some(serde_json::json!({
                        "phase": "host_ok",
                        "index": index,
                        "total": hosts_total,
                        "day": day,
                        "dir": dirname,
                        "display_name": r.display_name,
                        "created": r.created,
                        "processes": r.processes,
                        "files": r.files,
                        "sockets": r.sockets,
                        "scan_id": r.scan_id,
                    })),
                )
                .await;
                row = r;
                ok += 1;
            }
            Err(e) => {
                // Empty snapshot folders (no .jsonl) are common in PulseSecure day trees.
                let soft = e.starts_with("no .jsonl under ");
                emit_tree_progress(
                    &state,
                    format!(
                        "[{index}/{hosts_total}] {day_prefix}{} {display_name}: {e}",
                        if soft { "skip" } else { "fail" }
                    ),
                    Some(serde_json::json!({
                        "phase": if soft { "host_skip" } else { "host_fail" },
                        "index": index,
                        "total": hosts_total,
                        "day": day,
                        "dir": dirname,
                        "display_name": display_name,
                        "error": e,
                    })),
                )
                .await;
                row.error = Some(e);
                if soft {
                    skipped += 1;
                } else {
                    failed += 1;
                }
            }
        }
        results.push(row);
        // Let concurrent /v1/activity polls and other requests run between hosts.
        tokio::task::yield_now().await;
    }

    emit_tree_progress(
        &state,
        format!(
            "Tree import done · {ok} ok · {failed} failed · {skipped} skipped{}",
            if campaign {
                format!(" · {} day(s)", days_imported.len())
            } else {
                String::new()
            }
        ),
        Some(serde_json::json!({
            "phase": "done",
            "hosts_ok": ok,
            "hosts_failed": failed,
            "hosts_skipped": skipped,
            "campaign": campaign,
            "days": days_imported,
        })),
    )
    .await;

    Ok(Json(serde_json::json!({
        "ok": failed == 0,
        "summary": ImportTreeSummary {
            root: root.display().to_string(),
            hosts_ok: ok,
            hosts_failed: failed,
            hosts_skipped: skipped,
            campaign,
            days: days_imported,
            results,
        }
    })))
}

/// Browser folder upload → one virtual host per top-level subdirectory (same as server tree import).
pub async fn import_virtual_tree_upload(
    State(state): State<AppState>,
    Json(body): Json<ImportTreeUploadBody>,
) -> Result<impl IntoResponse, ApiError> {
    if body.files.is_empty() {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "files required (folder upload with relative paths)".into(),
        ));
    }
    let host_from = body.host_from.clone();
    let parent_dir_field = body.parent_dir_field;
    let delimiter = body
        .delimiter
        .chars()
        .next()
        .filter(|c| !c.is_whitespace())
        .unwrap_or('-');
    let profile = if let Some(pid) = body
        .virtual_agent_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(state.virtual_agents.get(pid).await.ok_or_else(|| {
            ApiError(
                StatusCode::BAD_REQUEST,
                format!("unknown virtual agent profile: {pid}"),
            )
        })?)
    } else {
        None
    };
    let kind = VirtualIngestKind::parse(
        body.kind
            .as_deref()
            .or(profile.as_ref().map(|p| p.kind.as_str()))
            .unwrap_or("auto"),
    );
    let source_label = body
        .source_label
        .clone()
        .unwrap_or_else(|| "tree:upload".into());

    // Group by host subdirectory. Peel a shared selected/day folder prefix when present:
    //   2026-05-10/HOST-A/a.jsonl + 2026-05-10/HOST-B/b.jsonl → hosts HOST-A, HOST-B
    let mut entries: Vec<(Vec<String>, String)> = Vec::new();
    for f in body.files {
        let rel = f.name.replace('\\', "/");
        let rel = rel.strip_prefix("./").unwrap_or(rel.as_str());
        let parts: Vec<String> = rel
            .split('/')
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        if parts.is_empty() {
            continue;
        }
        entries.push((parts, f.content));
    }

    let mut start = 0usize;
    while start < 4 && !entries.is_empty() {
        let mut at = std::collections::BTreeSet::new();
        for (parts, _) in &entries {
            if let Some(p) = parts.get(start) {
                at.insert(p.clone());
            }
        }
        if at.len() != 1 {
            break;
        }
        if !entries.iter().all(|(parts, _)| parts.len() > start + 1) {
            break;
        }
        let mut next = std::collections::BTreeSet::new();
        for (parts, _) in &entries {
            if let Some(p) = parts.get(start + 1) {
                next.insert(p.clone());
            }
        }
        if next.len() >= 2 {
            start += 1;
            break;
        }
        if next.len() == 1 && entries.iter().all(|(parts, _)| parts.len() > start + 2) {
            start += 1;
            continue;
        }
        break;
    }

    let mut by_dir: std::collections::BTreeMap<String, Vec<(String, String)>> =
        std::collections::BTreeMap::new();
    let mut root_files: Vec<(String, String)> = Vec::new();
    // Last peeled path segment (often a YYYY-MM-DD day folder) → scan tag.
    let peeled_parent: Option<String> = if start > 0 {
        entries
            .first()
            .and_then(|(parts, _)| parts.get(start - 1).cloned())
    } else {
        None
    };
    for (parts, content) in entries {
        if parts.len() <= start + 1 {
            root_files.push((parts.join("/"), content));
            continue;
        }
        let dir = parts[start].clone();
        let rest = parts[start + 1..].join("/");
        by_dir.entry(dir).or_default().push((rest, content));
    }

    if by_dir.is_empty() {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "folder upload has no host subdirectories — use single-host create, or upload a day folder whose children are host directories".into(),
        ));
    }
    if !root_files.is_empty() {
        tracing::warn!(
            count = root_files.len(),
            peel = start,
            "tree upload: ignoring {} file(s) outside host subdirectories",
            root_files.len()
        );
    }

    let mut results = Vec::new();
    let mut ok = 0usize;
    let mut failed = 0usize;
    let mut skipped = 0usize;
    let platform = platform_patch(body.arch.as_deref(), body.kernel.as_deref(), body.os.as_deref());
    let platform_ref = if platform.arch.is_some()
        || platform.kernel.is_some()
        || platform.os.is_some()
    {
        Some(&platform)
    } else {
        None
    };
    let scan_tags = with_parent_scan_tag(
        &coalesce_scan_tags(body.scan_tags.clone(), body.scan_tag.clone()),
        peeled_parent.as_deref(),
    );

    for (dirname, files) in by_dir {
        let display_name =
            resolve_host_name_ex(&dirname, &host_from, parent_dir_field, delimiter);
        let mut row = ImportTreeHostResult {
            dir: dirname.clone(),
            host_id: Uuid::nil(),
            display_name: display_name.clone(),
            created: false,
            scan_id: None,
            processes: 0,
            files: 0,
            sockets: 0,
            skipped: 0,
            error: None,
            day: peeled_parent.clone().filter(|d| looks_like_iso_day_folder(d)),
        };
        match import_one_host_files(
            &state,
            &dirname,
            &display_name,
            Some(source_label.as_str()),
            body.replace,
            body.create_scan,
            kind,
            profile.as_ref(),
            &files,
            platform_ref,
            &scan_tags,
            body.labels.as_ref(),
        )
        .await
        {
            Ok(mut r) => {
                r.day = row.day.clone();
                row = r;
                ok += 1;
            }
            Err(e) => {
                let soft = e.starts_with("no .jsonl") || e.starts_with("no ingest files");
                row.error = Some(e);
                if soft {
                    skipped += 1;
                } else {
                    failed += 1;
                }
            }
        }
        results.push(row);
        tokio::task::yield_now().await;
    }

    Ok(Json(serde_json::json!({
        "ok": failed == 0,
        "summary": ImportTreeSummary {
            root: "upload".into(),
            hosts_ok: ok,
            hosts_failed: failed,
            hosts_skipped: skipped,
            campaign: false,
            days: Vec::new(),
            results,
        }
    })))
}

/// Caps for in-memory scan embedding while streaming large host trees.
const MAX_PROC_OBS_IN_VIRTUAL_SCAN: usize = 5_000;
const MAX_SOCK_OBS_IN_VIRTUAL_SCAN: usize = 2_000;
const STREAM_FLUSH_LINES: usize = 400;

/// Inventory totals for a virtual-import scan (may exceed embedded observation caps).
#[derive(Clone, Copy, Debug, Default)]
pub struct VirtualImportInventoryTotals {
    pub processes: usize,
    pub files: usize,
    pub sockets: usize,
}

async fn import_one_host_dir(
    state: &AppState,
    dir: &Path,
    display_name: &str,
    source_label: Option<&str>,
    replace: bool,
    create_scan: bool,
    _kind: VirtualIngestKind,
    profile: Option<&crate::virtual_agents::VirtualAgentProfile>,
    platform: Option<&UpdateHost>,
    scan_tags: &[String],
    extra_labels: Option<&BTreeMap<String, String>>,
) -> Result<ImportTreeHostResult, String> {
    use std::io::{BufRead, BufReader};

    let mut jsonl_paths = Vec::new();
    collect_jsonl_files_under(dir, true, &mut jsonl_paths)?;
    jsonl_paths.sort();
    if jsonl_paths.is_empty() {
        return Err(format!("no .jsonl under {}", dir.display()));
    }
    let dirname = dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("host");

    let (host, created) =
        ensure_virtual_host(state, display_name, source_label, profile, platform, extra_labels)
            .await
            .map_err(|e| e.1.clone())?;
    let map = crate::ingest_map::map_for_host(&host);

    // Stream JSONL → disk NDJSON. Never load every source file into RAM at once
    // (PulseSecure vpn trees are multi‑GB and used to wedge the control plane).
    if replace {
        let _ = replace_virtual_process_logs(&host, "");
        let _ = replace_virtual_file_logs(&host, "");
    }

    let mut proc_ndjson = String::new();
    let mut file_ndjson = String::new();
    let mut proc_batch = 0usize;
    let mut file_batch = 0usize;
    let mut proc_total = 0usize;
    let mut file_total = 0usize;
    let mut sock_total = 0usize;
    let mut skipped = 0usize;
    let mut sample_procs: Vec<RawLogEntry> = Vec::new();
    let mut sample_files: Vec<RawFileEntry> = Vec::new();
    let mut sample_socks: Vec<SocketObs> = Vec::new();
    let mut ingest_names: Vec<String> = Vec::new();
    let mut lines_seen = 0usize;

    for p in &jsonl_paths {
        let name = p
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("snapshot.jsonl")
            .to_string();
        ingest_names.push(name);
        let file = fs::File::open(p).map_err(|e| format!("{}: {e}", p.display()))?;
        let reader = BufReader::with_capacity(256 * 1024, file);
        for line in reader.lines() {
            let line = line.map_err(|e| format!("{}: {e}", p.display()))?;
            lines_seen += 1;
            match parse_mixed_snapshot_line(&line, display_name, &map) {
                MixedLine::Process(mut e) => {
                    if e.machine_id.is_empty() || e.machine_id == "_" {
                        e.machine_id = display_name.to_string();
                    }
                    if sample_procs.len() < MAX_PROC_OBS_IN_VIRTUAL_SCAN {
                        sample_procs.push(e.clone());
                    }
                    proc_ndjson
                        .push_str(&serde_json::to_string(&e).map_err(|e| e.to_string())?);
                    proc_ndjson.push('\n');
                    proc_batch += 1;
                    proc_total += 1;
                }
                MixedLine::File(mut e) => {
                    if e.machine_id.is_empty() {
                        e.machine_id = display_name.to_string();
                    }
                    if sample_files.len() < MAX_FILE_OBS_IN_VIRTUAL_SCAN {
                        sample_files.push(e.clone());
                    }
                    file_ndjson
                        .push_str(&serde_json::to_string(&e).map_err(|e| e.to_string())?);
                    file_ndjson.push('\n');
                    file_batch += 1;
                    file_total += 1;
                }
                MixedLine::Socket(s) => {
                    if sample_socks.len() < MAX_SOCK_OBS_IN_VIRTUAL_SCAN {
                        sample_socks.push(s);
                    }
                    sock_total += 1;
                }
                MixedLine::Skip => {
                    let t = line.trim();
                    if !t.is_empty() && !t.starts_with('#') && !t.starts_with("//") {
                        skipped += 1;
                    }
                }
            }
            if proc_batch >= STREAM_FLUSH_LINES {
                crate::sift_api::append_virtual_process_logs(&host, &proc_ndjson)?;
                proc_ndjson.clear();
                proc_batch = 0;
            }
            if file_batch >= STREAM_FLUSH_LINES {
                crate::sift_api::append_virtual_file_logs(&host, &file_ndjson)?;
                file_ndjson.clear();
                file_batch = 0;
            }
            if lines_seen % 2_000 == 0 {
                tokio::task::yield_now().await;
            }
        }
    }
    if !proc_ndjson.is_empty() {
        crate::sift_api::append_virtual_process_logs(&host, &proc_ndjson)?;
    }
    if !file_ndjson.is_empty() {
        crate::sift_api::append_virtual_file_logs(&host, &file_ndjson)?;
    }

    let _ = crate::sift_api::record_virtual_import_provenance(
        &host,
        Some(dirname),
        &ingest_names,
        replace,
    );
    let (folders, file_names) = crate::sift_api::load_virtual_import_provenance(&host);
    let folders = if folders.is_empty() {
        import_folders_from_files(Some(dirname), &ingest_names)
    } else {
        folders
    };
    let file_names = if file_names.is_empty() {
        ingest_names
    } else {
        file_names
    };

    let mut scan_id = None;
    if create_scan {
        match create_virtual_import_scan_with_provenance(
            state,
            &host,
            &sample_procs,
            &sample_files,
            &sample_socks,
            &format!("tree-import:{dirname}"),
            &folders,
            &file_names,
            scan_tags,
            Some(VirtualImportInventoryTotals {
                processes: proc_total,
                files: file_total,
                sockets: sock_total,
            }),
        )
        .await
        {
            Ok(sid) => scan_id = Some(sid),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    host = %display_name,
                    "tree import: host saved but scan record failed"
                );
            }
        }
    }

    crate::platform_ch::sync_virtual_host_from_state(state, host.id.0).await;

    Ok(ImportTreeHostResult {
        dir: dirname.to_string(),
        host_id: host.id.0,
        display_name: host.display_name,
        created,
        scan_id,
        processes: proc_total,
        files: file_total,
        sockets: sock_total,
        skipped,
        error: None,
        day: None,
    })
}

async fn import_one_host_files(
    state: &AppState,
    dirname: &str,
    display_name: &str,
    source_label: Option<&str>,
    replace: bool,
    create_scan: bool,
    _kind: VirtualIngestKind,
    profile: Option<&crate::virtual_agents::VirtualAgentProfile>,
    files: &[(String, String)],
    platform: Option<&UpdateHost>,
    scan_tags: &[String],
    extra_labels: Option<&BTreeMap<String, String>>,
) -> Result<ImportTreeHostResult, String> {
    let ingest_files: Vec<(String, String)> = files
        .iter()
        .filter(|(name, _)| {
            let lower = name.to_ascii_lowercase();
            lower.ends_with(".jsonl")
                || lower.ends_with(".ndjson")
                || lower.ends_with(".json")
                || lower.ends_with(".csv")
        })
        .cloned()
        .collect();
    if ingest_files.is_empty() {
        return Err(format!("no ingest files under {dirname}"));
    }

    let (host, created) =
        ensure_virtual_host(state, display_name, source_label, profile, platform, extra_labels)
            .await
            .map_err(|e| e.1.clone())?;

    let map = crate::ingest_map::map_for_host(&host);
    let mut all_proc = Vec::new();
    let mut all_file = Vec::new();
    let mut all_sock = Vec::new();
    let mut skipped = 0usize;

    for (_name, content) in &ingest_files {
        let (procs, files, socks, skip) =
            parse_mixed_snapshot_jsonl_with_map(content, display_name, &map);
        all_proc.extend(procs);
        all_file.extend(files);
        all_sock.extend(socks);
        skipped += skip;
    }

    for e in &mut all_proc {
        if e.machine_id.is_empty() || e.machine_id == "_" {
            e.machine_id = display_name.to_string();
        }
    }
    for e in &mut all_file {
        if e.machine_id.is_empty() {
            e.machine_id = display_name.to_string();
        }
    }

    let mut proc_ndjson = String::new();
    for e in &all_proc {
        proc_ndjson.push_str(&serde_json::to_string(e).map_err(|e| e.to_string())?);
        proc_ndjson.push('\n');
    }
    let mut file_ndjson = String::new();
    for e in &all_file {
        file_ndjson.push_str(&serde_json::to_string(e).map_err(|e| e.to_string())?);
        file_ndjson.push('\n');
    }

    if replace {
        if !proc_ndjson.is_empty() {
            replace_virtual_process_logs(&host, &proc_ndjson)?;
        } else {
            let _ = replace_virtual_process_logs(&host, "");
        }
        if !file_ndjson.is_empty() {
            replace_virtual_file_logs(&host, &file_ndjson)?;
        } else {
            let _ = replace_virtual_file_logs(&host, "");
        }
    } else {
        if !proc_ndjson.is_empty() {
            crate::sift_api::append_virtual_process_logs(&host, &proc_ndjson)?;
        }
        if !file_ndjson.is_empty() {
            crate::sift_api::append_virtual_file_logs(&host, &file_ndjson)?;
        }
    }

    let ingest_names: Vec<String> = ingest_files.iter().map(|(n, _)| n.clone()).collect();
    let _ = crate::sift_api::record_virtual_import_provenance(
        &host,
        Some(dirname),
        &ingest_names,
        replace,
    );
    let (folders, file_names) = crate::sift_api::load_virtual_import_provenance(&host);
    let folders = if folders.is_empty() {
        import_folders_from_files(Some(dirname), &ingest_names)
    } else {
        folders
    };
    let file_names = if file_names.is_empty() {
        ingest_names
    } else {
        file_names
    };

    let mut scan_id = None;
    if create_scan {
        let totals = VirtualImportInventoryTotals {
            processes: all_proc.len(),
            files: all_file.len(),
            sockets: all_sock.len(),
        };
        let proc_sample = &all_proc[..all_proc.len().min(MAX_PROC_OBS_IN_VIRTUAL_SCAN)];
        let file_sample = &all_file[..all_file.len().min(MAX_FILE_OBS_IN_VIRTUAL_SCAN)];
        let sock_sample = &all_sock[..all_sock.len().min(MAX_SOCK_OBS_IN_VIRTUAL_SCAN)];
        match create_virtual_import_scan_with_provenance(
            state,
            &host,
            proc_sample,
            file_sample,
            sock_sample,
            &format!("tree-import:{dirname}"),
            &folders,
            &file_names,
            scan_tags,
            Some(totals),
        )
        .await
        {
            Ok(sid) => scan_id = Some(sid),
            Err(e) => {
                // Host + ingest already persisted — don't fail the whole import for scan OOM.
                tracing::warn!(
                    error = %e,
                    host = %display_name,
                    "tree import: host saved but scan record failed"
                );
            }
        }
    }

    // Index JSONL (and scan-observation fallback) into ClickHouse *after* the
    // import scan is recorded so Hunt sees rows even if JSONL timestamps were bad.
    crate::platform_ch::sync_virtual_host_from_state(state, host.id.0).await;

    Ok(ImportTreeHostResult {
        dir: dirname.to_string(),
        host_id: host.id.0,
        display_name: host.display_name,
        created,
        scan_id,
        processes: all_proc.len(),
        files: all_file.len(),
        sockets: all_sock.len(),
        skipped,
        error: None,
        day: None,
    })
}

/// Max file-meta observations embedded in a virtual-import scan.
/// Full file inventory remains in ingest `files.jsonl` for Fleet Sift; embedding
/// every PulseSecure `file_information` row (40k+/host) OOMs the control plane.
const MAX_FILE_OBS_IN_VIRTUAL_SCAN: usize = 1_500;

/// Derive unique folder paths from ingested file relative paths + an optional root label.
pub fn import_folders_from_files(root: Option<&str>, file_names: &[String]) -> Vec<String> {
    use std::collections::BTreeSet;
    let mut folders = BTreeSet::new();
    if let Some(r) = root.map(str::trim).filter(|s| !s.is_empty()) {
        folders.insert(r.replace('\\', "/"));
    }
    for name in file_names {
        let n = name.replace('\\', "/").trim_start_matches("./").to_string();
        if n.is_empty() {
            continue;
        }
        let parts: Vec<&str> = n.split('/').filter(|p| !p.is_empty()).collect();
        if parts.len() < 2 {
            continue;
        }
        // All parent prefixes: a/b/c.jsonl → a, a/b
        for i in 1..parts.len() {
            folders.insert(parts[..i].join("/"));
        }
    }
    folders.into_iter().collect()
}

/// Record a finished scan for a virtual-agent import (tree or single-host feed).
/// Observations are stored so Scans / Hunt / checks can use the snapshot like a live scan.
pub async fn create_virtual_import_scan(
    state: &AppState,
    host: &HostRecord,
    procs: &[RawLogEntry],
    files: &[RawFileEntry],
    socks: &[SocketObs],
    source: &str,
) -> Result<Uuid, String> {
    create_virtual_import_scan_with_provenance(
        state,
        host,
        procs,
        files,
        socks,
        source,
        &[],
        &[],
        &[],
        None,
    )
    .await
}

/// Like [`create_virtual_import_scan`], also recording which folders/files fed the JSONL.
///
/// `procs` / `files` / `socks` are the rows embedded in the scan (already capped by the
/// caller when needed). Pass [`VirtualImportInventoryTotals`] when the true inventory is
/// larger than these slices so the UI can show “N of M” and deep-link to Hunt.
pub async fn create_virtual_import_scan_with_provenance(
    state: &AppState,
    host: &HostRecord,
    procs: &[RawLogEntry],
    files: &[RawFileEntry],
    socks: &[SocketObs],
    source: &str,
    import_folders: &[String],
    import_files: &[String],
    scan_tags: &[String],
    inventory_totals: Option<VirtualImportInventoryTotals>,
) -> Result<Uuid, String> {
    // Clear any stuck active scan for this host by completing as cancelled isn't available —
    // enqueue will conflict; try enqueue and surface a clear error.
    let job = state
        .store
        .enqueue_scan(EnqueueScan {
            host_id: host.id,
            check_set: "virtual-import".into(),
            priority: 5,
        })
        .await
        .map_err(|e| e.to_string())?;

    let procs_kept = procs.len().min(MAX_PROC_OBS_IN_VIRTUAL_SCAN);
    let files_kept = files.len().min(MAX_FILE_OBS_IN_VIRTUAL_SCAN);
    let socks_kept = socks.len().min(MAX_SOCK_OBS_IN_VIRTUAL_SCAN);
    let totals = inventory_totals.unwrap_or(VirtualImportInventoryTotals {
        processes: procs.len(),
        files: files.len(),
        sockets: socks.len(),
    });
    let procs_total = totals.processes.max(procs_kept);
    let files_total = totals.files.max(files_kept);
    let socks_total = totals.sockets.max(socks_kept);
    let procs_truncated = procs_total > procs_kept;
    let files_truncated = files_total > files_kept;

    let mut observations: Vec<Observation> =
        Vec::with_capacity(procs_kept + files_kept + socks_kept);
    for e in &procs[..procs_kept] {
        observations.push(process_obs_from_raw(e));
    }
    for e in &files[..files_kept] {
        observations.push(file_obs_from_raw(e));
    }
    for s in &socks[..socks_kept] {
        observations.push(Observation::Socket(s.clone()));
    }

    let obs_count = observations.len() as u32;
    if !observations.is_empty() {
        state
            .store
            .insert_observations_typed(job.id, host.id, "virtual.import", observations)
            .await
            .map_err(|e| e.to_string())?;
    }

    let now = crate::sys_metrics::utc_now_rfc3339();
    let mut reason = source.to_string();
    let mut cap_bits = Vec::new();
    if procs_truncated {
        cap_bits.push(format!("{procs_kept}/{procs_total} processes"));
    }
    if files_truncated {
        cap_bits.push(format!("{files_kept}/{files_total} files"));
    }
    if !cap_bits.is_empty() {
        reason.push_str(&format!(
            " (scan embeds {}; full inventory in ingest / Hunt)",
            cap_bits.join(", ")
        ));
    }
    let inventory = Some(ScanInventorySummary {
        processes: procs_total as u32,
        files: files_total as u32,
        sockets: socks_total as u32,
        processes_in_scan: procs_kept as u32,
        files_in_scan: files_kept as u32,
        sockets_in_scan: socks_kept as u32,
    });
    let meta = ScanMeta {
        scan_id: job.id,
        host_id: host.id,
        node_id: rustmite_proto::NodeId(Uuid::nil()),
        outcome: ScanOutcome::Complete,
        delivery: DeliveryReport {
            method: rustmite_proto::DeliveryMethod::PureCommand,
            encoder: Some("jsonl-import".into()),
            bytes_transferred: 0,
            cleanup_ok: true,
            cleanup_forced: false,
            fallback_reason: Some(reason),
        },
        probe_version: "virtual-import".into(),
        // Prefer operator-set host identity; never invent x86_64 for virtual imports.
        arch: host_scan_arch(host),
        kernel: host.kernel.clone().unwrap_or_default(),
        os: host
            .os
            .clone()
            .or_else(|| Some("virtual-snapshot".into())),
        os_id: host
            .os_id
            .clone()
            .or_else(|| Some("virtual".into())),
        os_version: host.os_version.clone(),
        boot_id: String::new(),
        caps: Default::default(),
        collectors: vec![],
        applicable_checks: 0,
        fired: 0,
        not_applicable: 0,
        started_at: now.clone(),
        finished_at: now,
        duration_ms: 0,
        bytes_from_probe: 0,
        observation_count: obs_count,
        node_signature: None,
        import_folders: import_folders.to_vec(),
        import_files: import_files.to_vec(),
        tags: rustmite_store::normalize_scan_tags(scan_tags.to_vec()),
        inventory,
    };

    state
        .store
        .complete_scan(CompleteScan {
            scan_id: job.id,
            meta,
            outcome: "complete".into(),
        })
        .await
        .map_err(|e| e.to_string())?;

    let _ = state
        .store
        .push_activity(rustmite_store::ActivityEvent {
            id: Uuid::new_v4(),
            ts: crate::sys_metrics::utc_now_rfc3339(),
            level: "info".into(),
            kind: "scan.virtual_import".into(),
            message: format!(
                "Imported snapshot for {} ({} proc{ptrunc} / {} file{ftrunc} / {} sock)",
                host.display_name,
                procs_total,
                files_total,
                socks_total,
                ptrunc = if procs_truncated {
                    format!(", {procs_kept} in scan")
                } else {
                    String::new()
                },
                ftrunc = if files_truncated {
                    format!(", {files_kept} in scan")
                } else {
                    String::new()
                },
            ),
            scan_id: Some(job.id),
            host_id: Some(host.id),
            node_id: None,
            detail: Some(serde_json::json!({
                "source": source,
                "check_set": "virtual-import",
                "tags": scan_tags,
                "processes_total": procs_total,
                "processes_in_scan": procs_kept,
                "processes_truncated": procs_truncated,
                "files_total": files_total,
                "files_in_scan": files_kept,
                "files_truncated": files_truncated,
                "sockets_total": socks_total,
                "import_folders": import_folders,
                "import_files": import_files,
            })),
        })
        .await;

    crate::anomark_api::spawn_post_scan_anomark(
        state.clone(),
        host.id.0,
        job.id.0,
        "virtual-import",
    );

    Ok(job.id.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pulsesecure_host_extraction() {
        assert_eq!(
            host_name_from_pulsesecure_dir(
                "PulseSecure-Periodicsnapshot-standalone-HOSTEXAMPLE01-20260511-0012"
            ),
            "HOSTEXAMPLE01"
        );
        assert_eq!(
            host_name_from_pulsesecure_dir(
                "PulseSecure-Periodicsnapshot-standalone-EDGEVPN01EXAMPLE-20260512-1621"
            ),
            "EDGEVPN01EXAMPLE"
        );
        assert_eq!(
            host_name_from_pulsesecure_dir(
                "PulseSecure-Periodicsnapshot-CLUSTER_LIC-LIC_EXAMPLE-20260513-2130"
            ),
            "LIC_EXAMPLE"
        );
    }

    #[test]
    fn parse_mixed_pulse_lines() {
        let content = r#"
{"timestamp":"2026-05-11T00:10:06","event_type":"file_information","permissions":"drwxr-xr-x.","owner":"root","group":"root","size":4096,"file_path":"/data/var","date":"2025-09-23T00:00:00"}
{"timestamp":"2026-05-11T00:10:06","event_type":"process","user":"0","command":"/sbin/init auto","pid":1,"ppid":0}
{"timestamp":"2026-05-11T00:10:06","event_type":"network_connection","protocol":"tcp","source_ip":"*","destination_ip":"*","source_port":"800","destination_port":"*","program_pid":null}
{"timestamp":"2026-05-11T00:10:06","event_type":"iptables_rule","chain":"INPUT"}
"#;
        let (p, f, s, skip) = parse_mixed_snapshot_jsonl(content, "HOST");
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].pid, 1);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].path, "/data/var");
        assert_eq!(s.len(), 1);
        assert!(skip >= 1);
    }

    #[test]
    fn dirname_and_segment_host_names() {
        let folder = "PulseSecure-Periodicsnapshot-standalone-HOSTEXAMPLE01-20260504-0011";
        assert_eq!(resolve_host_name_ex(folder, "dirname", None, '-'), folder);
        assert_eq!(
            resolve_host_name_ex(folder, "segment", Some(4), '-').as_str(),
            "HOSTEXAMPLE01"
        );
        assert_eq!(
            resolve_host_name_ex(folder, "pulsesecure", None, '-').as_str(),
            "HOSTEXAMPLE01"
        );
        assert_eq!(
            resolve_host_name_ex("web-edge-01", "dirname", None, '-').as_str(),
            "web-edge-01"
        );
    }

    #[test]
    fn import_folders_from_nested_jsonl_paths() {
        let files = vec![
            "HOST01/processes.jsonl".into(),
            "HOST01/logs/files.jsonl".into(),
            "flat.jsonl".into(),
        ];
        let folders = import_folders_from_files(Some("day-2026-05-11"), &files);
        assert!(folders.iter().any(|f| f == "day-2026-05-11"));
        assert!(folders.iter().any(|f| f == "HOST01"));
        assert!(folders.iter().any(|f| f == "HOST01/logs"));
        assert!(!folders.iter().any(|f| f.ends_with(".jsonl")));
    }
}