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

use std::fs;
use std::path::{Path, PathBuf};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use rustmite_proto::{
    Arch, BigInt, DeliveryReport, FileMetaObs, Observation, PathBytes, ProcessObs, ScanMeta,
    ScanOutcome, SocketObs,
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
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportTreeSummary {
    pub root: String,
    pub hosts_ok: usize,
    pub hosts_failed: usize,
    #[serde(default)]
    pub hosts_skipped: usize,
    pub results: Vec<ImportTreeHostResult>,
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
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            skipped += 1;
            continue;
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
                    Some(e) => procs.push(e),
                    None => skipped += 1,
                }
            }
            "file_information" | "file" | "file_meta" => {
                match crate::ingest_map::file_from_value(&v, map, default_machine)
                    .or_else(|| file_entry_from_value(&v, default_machine))
                {
                    Some(e) => files.push(e),
                    None => skipped += 1,
                }
            }
            "network_connection" | "socket" | "connection" => {
                match socket_from_value(&v) {
                    Some(s) => sockets.push(s),
                    None => skipped += 1,
                }
            }
            "iptables_rule" | "iptables" => {
                skipped += 1;
            }
            "" => {
                if has_process_hints(&v) {
                    if let Some(e) = crate::ingest_map::process_from_value(&v, map, default_machine)
                        .or_else(|| parse_jsonl_process_line(line, default_machine).ok())
                    {
                        procs.push(e);
                    } else if let Some(e) =
                        crate::ingest_map::file_from_value(&v, map, default_machine)
                            .or_else(|| file_entry_from_value(&v, default_machine))
                    {
                        files.push(e);
                    } else {
                        skipped += 1;
                    }
                } else if let Some(e) = crate::ingest_map::file_from_value(&v, map, default_machine)
                    .or_else(|| file_entry_from_value(&v, default_machine))
                {
                    files.push(e);
                } else if let Some(e) =
                    crate::ingest_map::process_from_value(&v, map, default_machine)
                        .or_else(|| parse_jsonl_process_line(line, default_machine).ok())
                {
                    procs.push(e);
                } else {
                    skipped += 1;
                }
            }
            _ => skipped += 1,
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
    let (comm, exe, cmdline) = if e.path.is_empty() && !e.args.is_empty() {
        let parts: Vec<PathBytes> = std::iter::once(e.name.as_str())
            .chain(e.args.split_whitespace())
            .map(PathBytes::from_str)
            .collect();
        (e.name.clone(), None, parts)
    } else {
        let mut cmdline = vec![PathBytes::from_str(if e.path.is_empty() {
            e.name.as_str()
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
        (e.name.clone(), exe, cmdline)
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

async fn ensure_virtual_host(
    state: &AppState,
    display_name: &str,
    source_label: Option<&str>,
    profile: Option<&crate::virtual_agents::VirtualAgentProfile>,
) -> Result<(HostRecord, bool), ApiError> {
    let before = state.store.list_hosts().await?;
    let prev = before.iter().find(|h| h.display_name == display_name);
    let existed = prev.is_some();
    let mut labels = prev
        .map(|h| h.labels.clone())
        .unwrap_or_default();
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
    let host = state
        .store
        .update_host(
            host.id,
            UpdateHost {
                auth_status: Some("virtual".into()),
                auth_detail: Some("virtual agent — snapshot ingest".into()),
                auth_checked_at: Some(crate::sys_metrics::utc_now_rfc3339()),
                agent_kind: Some("virtual".into()),
                ..Default::default()
            },
        )
        .await?;
    Ok((host, !existed))
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
    let source_label = body
        .source_label
        .clone()
        .or_else(|| {
            root.file_name()
                .and_then(|s| s.to_str())
                .map(|s| format!("tree:{s}"))
        });

    let mut subdirs: Vec<PathBuf> = fs::read_dir(&root)
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e.to_string()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    subdirs.sort();

    if subdirs.is_empty() {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            format!("no subdirectories under {}", root.display()),
        ));
    }

    let mut results = Vec::new();
    let mut ok = 0usize;
    let mut failed = 0usize;
    let mut skipped = 0usize;

    for dir in subdirs {
        let dirname = dir
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("host")
            .to_string();
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
        };

        match import_one_host_dir(
            &state,
            &dir,
            &display_name,
            source_label.as_deref(),
            body.replace,
            body.create_scan,
            kind,
            profile.as_ref(),
        )
        .await
        {
            Ok(r) => {
                row = r;
                ok += 1;
            }
            Err(e) => {
                // Empty snapshot folders (no .jsonl) are common in PulseSecure day trees.
                let soft = e.starts_with("no .jsonl under ");
                row.error = Some(e);
                if soft {
                    skipped += 1;
                } else {
                    failed += 1;
                }
            }
        }
        results.push(row);
    }

    Ok(Json(serde_json::json!({
        "ok": failed == 0,
        "summary": ImportTreeSummary {
            root: root.display().to_string(),
            hosts_ok: ok,
            hosts_failed: failed,
            hosts_skipped: skipped,
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
        )
        .await
        {
            Ok(r) => {
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
    }

    Ok(Json(serde_json::json!({
        "ok": failed == 0,
        "summary": ImportTreeSummary {
            root: "upload".into(),
            hosts_ok: ok,
            hosts_failed: failed,
            hosts_skipped: skipped,
            results,
        }
    })))
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
) -> Result<ImportTreeHostResult, String> {
    let mut jsonl_paths = Vec::new();
    collect_jsonl_files_under(dir, true, &mut jsonl_paths)?;
    jsonl_paths.sort();
    if jsonl_paths.is_empty() {
        return Err(format!("no .jsonl under {}", dir.display()));
    }
    let mut files = Vec::new();
    for p in &jsonl_paths {
        let content = fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
        let name = p
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("snapshot.jsonl")
            .to_string();
        files.push((name, content));
    }
    let dirname = dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("host");
    import_one_host_files(
        state,
        dirname,
        display_name,
        source_label,
        replace,
        create_scan,
        _kind,
        profile,
        &files,
    )
    .await
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

    let (host, created) = ensure_virtual_host(state, display_name, source_label, profile)
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

    crate::platform_ch::sync_virtual_host_from_state(state, host.id.0).await;

    let mut scan_id = None;
    if create_scan {
        match create_virtual_import_scan(
            state,
            &host,
            &all_proc,
            &all_file,
            &all_sock,
            &format!("tree-import:{dirname}"),
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
    })
}

/// Max file-meta observations embedded in a virtual-import scan.
/// Full file inventory remains in ingest `files.jsonl` for Fleet Sift; embedding
/// every PulseSecure `file_information` row (40k+/host) OOMs the control plane.
const MAX_FILE_OBS_IN_VIRTUAL_SCAN: usize = 1_500;

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

    let files_total = files.len();
    let files_kept = files.len().min(MAX_FILE_OBS_IN_VIRTUAL_SCAN);
    let files_truncated = files_total > files_kept;

    let mut observations: Vec<Observation> =
        Vec::with_capacity(procs.len() + files_kept + socks.len());
    for e in procs {
        observations.push(process_obs_from_raw(e));
    }
    for e in &files[..files_kept] {
        observations.push(file_obs_from_raw(e));
    }
    for s in socks {
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
    if files_truncated {
        reason.push_str(&format!(
            " (scan embeds {files_kept}/{files_total} file rows; full inventory in ingest JSONL)"
        ));
    }
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
        arch: Arch::X86_64,
        kernel: String::new(),
        os: Some("virtual-snapshot".into()),
        os_id: Some("virtual".into()),
        os_version: None,
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
                "Imported snapshot for {} ({} proc / {} file{trunc} / {} sock)",
                host.display_name,
                procs.len(),
                files_total,
                socks.len(),
                trunc = if files_truncated {
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
                "files_total": files_total,
                "files_in_scan": files_kept,
                "files_truncated": files_truncated,
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
}