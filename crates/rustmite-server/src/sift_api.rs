//! Fleet Sift (IronSift) — TF-IDF + DBSCAN, file fleet, temporal diffs, virtual ingest.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use rustmite_proto::Observation;
use rustmite_sift::{
    analyze_files_fleet, analyze_fleet, build_file_profiles, build_machine_snapshot, build_profiles,
    compare_temporal, observations_to_connections, observations_to_file_logs, process_obs_to_raw,
    AnalysisReport, DetectionConfig, RawFileEntry, RawLogEntry, TemporalDiff,
};
use rustmite_store::{HostId, HostRecord, Store};
use serde::{Deserialize, Serialize};
use tracing::info;
use uuid::Uuid;

use crate::routes::{ApiError, AppState};

fn sift_root() -> PathBuf {
    PathBuf::from(".dev/sift-platform")
}

fn ingest_dir() -> PathBuf {
    PathBuf::from(".dev/ingest")
}

fn unix_secs_to_rfc3339(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let tod = secs % 86400;
    let h = tod / 3600;
    let m = (tod % 3600) / 60;
    let s = tod % 60;
    let (y, mo, d) = crate::sys_metrics::civil_from_days(days);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

pub fn ensure_sift_dirs() {
    let _ = fs::create_dir_all(sift_root());
    let _ = fs::create_dir_all(ingest_dir());
    let _ = fs::create_dir_all(sift_root().join("runs"));
}

#[derive(Debug, Deserialize)]
pub struct FleetSiftBody {
    #[serde(default)]
    pub host_ids: Vec<Uuid>,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    /// Soft tag match against host label keys/values (and comma-split `labels.tags`).
    #[serde(default)]
    pub tags: Vec<String>,
    /// Only include hosts whose `last_scan_at` is on/after this ISO timestamp.
    #[serde(default)]
    pub scan_after: Option<String>,
    /// Only include hosts whose `last_scan_at` is on/before this ISO timestamp.
    #[serde(default)]
    pub scan_before: Option<String>,
    /// Which finished scan inventory to use per host.
    /// - `latest` / `1` — newest finished scan (default)
    /// - `previous` / `2` — second-newest
    /// - `3`…`N` — Nth newest (1-based), capped by retained scan history
    #[serde(default = "default_inventory")]
    pub inventory: String,
    /// Optional per-host scan override (`host_id` → `scan_id`).
    #[serde(default)]
    pub scan_ids: BTreeMap<String, Uuid>,
    /// Optional inline DetectionConfig override (takes precedence over profile).
    #[serde(default)]
    pub config: Option<DetectionConfig>,
    /// Named SQLite detection profile id (IronSift). Used when `config` is absent.
    #[serde(default)]
    pub detection_config_id: Option<String>,
    /// `process` (default), `file`, or `both`.
    #[serde(default = "default_mode")]
    pub mode: String,
}

fn default_mode() -> String {
    "process".into()
}

fn default_inventory() -> String {
    "latest".into()
}

#[derive(Debug, Serialize)]
pub struct FleetSiftResponse {
    pub run_id: String,
    /// When this run was produced (RFC3339 UTC).
    pub created_at: String,
    pub machines: usize,
    pub anomalies: usize,
    pub mode: String,
    pub report: serde_json::Value,
    pub file_report: Option<serde_json::Value>,
    pub sources: Vec<FleetSiftSource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detection_config_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detection_config_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct FleetSiftSource {
    pub host_id: String,
    pub display_name: String,
    pub agent_kind: String,
    pub process_rows: usize,
    pub file_rows: usize,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_scan_at: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

fn host_matches_labels(h: &HostRecord, want: &BTreeMap<String, String>) -> bool {
    want.iter()
        .all(|(k, v)| h.labels.get(k).map(|x| x == v).unwrap_or(false))
}

fn host_matches_tags(h: &HostRecord, tags: &[String]) -> bool {
    if tags.is_empty() {
        return true;
    }
    tags.iter().all(|want| {
        let w = want.trim();
        if w.is_empty() {
            return true;
        }
        let wl = w.to_ascii_lowercase();
        h.labels.iter().any(|(k, v)| {
            if k.eq_ignore_ascii_case(w) || v.eq_ignore_ascii_case(w) {
                return true;
            }
            v.split(|c: char| c == ',' || c == ';' || c.is_whitespace())
                .any(|p| p.trim().eq_ignore_ascii_case(w))
                || k.to_ascii_lowercase().contains(&wl)
                || v.to_ascii_lowercase().contains(&wl)
        })
    })
}

fn parse_scan_ts(s: &str) -> Option<i64> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    // Accept unix seconds or ISO-ish prefixes sortable as strings after normalize.
    if let Ok(n) = t.parse::<i64>() {
        return Some(n);
    }
    // Fallback: strip non-digits for rough compare of ISO timestamps (YYYYMMDDHHMMSS).
    let digits: String = t.chars().filter(|c| c.is_ascii_digit()).take(14).collect();
    digits.parse::<i64>().ok()
}

fn host_in_scan_window(
    h: &HostRecord,
    after: &Option<String>,
    before: &Option<String>,
) -> bool {
    if after.is_none() && before.is_none() {
        return true;
    }
    let Some(ref last) = h.last_scan_at else {
        return false;
    };
    let Some(ts) = parse_scan_ts(last) else {
        return false;
    };
    if let Some(ref a) = after {
        if let Some(at) = parse_scan_ts(a) {
            if ts < at {
                return false;
            }
        }
    }
    if let Some(ref b) = before {
        if let Some(bt) = parse_scan_ts(b) {
            if ts > bt {
                return false;
            }
        }
    }
    true
}

fn resolve_fleet_detection_config(
    state: &AppState,
    body: &FleetSiftBody,
) -> Result<(DetectionConfig, Option<String>, Option<String>), ApiError> {
    let store = state.sift_platform.get().ok();

    let profile_name = |id: &str| -> Option<String> {
        let store = store.as_ref()?;
        store
            .get_detection_config_profile_detail(id)
            .ok()
            .map(|(meta, _)| meta.name)
    };

    if let Some(ref cfg) = body.config {
        let id = body
            .detection_config_id
            .as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let name = id
            .as_deref()
            .and_then(profile_name)
            .or_else(|| Some("inline".into()));
        return Ok((cfg.clone(), id, name));
    }

    let store = state.sift_platform.get()?;
    if let Some(ref id) = body.detection_config_id {
        let id = id.trim();
        if !id.is_empty() {
            let (meta, cfg) = store
                .get_detection_config_profile_detail(id)
                .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e.to_string()))?;
            return Ok((cfg, Some(meta.id), Some(meta.name)));
        }
    }
    let (cfg, profiles, selected_id) = store
        .run_config_with_profiles()
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let name = selected_id.as_ref().and_then(|sid| {
        profiles
            .iter()
            .find(|p| &p.id == sid)
            .map(|p| p.name.clone())
    });
    Ok((cfg, selected_id, name))
}

fn report_json(report: &AnalysisReport) -> serde_json::Value {
    let cluster_distribution: serde_json::Map<String, serde_json::Value> = report
        .cluster_stats
        .iter()
        .map(|(k, v)| {
            let key = match k {
                Some(id) => format!("cluster_{id}"),
                None => "outliers".into(),
            };
            (key, serde_json::json!(v))
        })
        .collect();
    serde_json::json!({
        "total_analyzed": report.total_analyzed,
        "anomalies": report.anomalies.iter().map(|a| serde_json::json!({
            "machine_id": a.machine_id,
            "severity": a.severity.as_str().to_lowercase(),
            "anomaly_score": a.distance_score,
            "cluster_assignment": a.cluster_assignment,
            "risk_factors": a.anomalous_features,
            "process_count": a.process_count,
            "suspicious_process_count": a.suspicious_process_count,
        })).collect::<Vec<_>>(),
        "cluster_distribution": cluster_distribution,
        "analysis_type": match report.analysis_type {
            rustmite_sift::AnalysisType::Process => "process",
            rustmite_sift::AnalysisType::File => "file",
        },
    })
}

pub fn load_virtual_jsonl(host: &HostRecord) -> Vec<RawLogEntry> {
    let path = ingest_dir()
        .join(host.id.0.to_string())
        .join("processes.jsonl");
    if !path.is_file() {
        return Vec::new();
    }
    let Ok(raw) = fs::read_to_string(&path) else {
        return Vec::new();
    };
    let machine = host.display_name.clone();
    let mut out = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(mut row) = serde_json::from_str::<RawLogEntry>(line) {
            if row.machine_id.trim().is_empty() {
                row.machine_id = machine.clone();
            }
            out.push(row);
            continue;
        }
        // PulseSecure / vendor JSONL (command/cmdline) and loose shapes.
        if let Ok(mut row) = rustmite_sift::parse_jsonl_process_line(line, &machine) {
            if row.machine_id.trim().is_empty() {
                row.machine_id = machine.clone();
            }
            out.push(row);
            continue;
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            let name = v
                .get("name")
                .or_else(|| v.get("comm"))
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            if name.is_empty() {
                continue;
            }
            out.push(RawLogEntry {
                machine_id: v
                    .get("machine_id")
                    .or_else(|| v.get("host"))
                    .and_then(|x| x.as_str())
                    .unwrap_or(machine.as_str())
                    .to_string(),
                pid: v.get("pid").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
                ppid: v.get("ppid").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
                name,
                uid: v.get("uid").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
                path: v
                    .get("path")
                    .or_else(|| v.get("exe"))
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                args: v
                    .get("args")
                    .or_else(|| v.get("cmdline"))
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                timestamp: v
                    .get("timestamp")
                    .and_then(|x| x.as_str())
                    .map(str::to_string),
            });
        }
    }
    out
}

pub fn load_virtual_files_jsonl(host: &HostRecord) -> Vec<RawFileEntry> {
    let path = ingest_dir()
        .join(host.id.0.to_string())
        .join("files.jsonl");
    if !path.is_file() {
        return Vec::new();
    }
    let Ok(raw) = fs::read_to_string(&path) else {
        return Vec::new();
    };
    let machine = host.display_name.clone();
    let mut out = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(mut row) = serde_json::from_str::<RawFileEntry>(line) {
            if row.machine_id.trim().is_empty() {
                row.machine_id = machine.clone();
            }
            out.push(row);
            continue;
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            let path = v
                .get("path")
                .or_else(|| v.get("file"))
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            if path.is_empty() {
                continue;
            }
            out.push(RawFileEntry {
                machine_id: v
                    .get("machine_id")
                    .or_else(|| v.get("host"))
                    .and_then(|x| x.as_str())
                    .unwrap_or(machine.as_str())
                    .to_string(),
                path,
                uid: v.get("uid").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
                timestamp: v
                    .get("timestamp")
                    .and_then(|x| x.as_str())
                    .map(str::to_string),
                mtime: v
                    .get("mtime")
                    .or_else(|| v.get("date"))
                    .and_then(|x| {
                        x.as_str()
                            .map(str::to_string)
                            .or_else(|| x.as_i64().map(|n| n.to_string()))
                    }),
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
            });
        }
    }
    out
}

async fn obs_for_host_inventory(
    state: &AppState,
    host: &HostRecord,
    inventory: &str,
    scan_override: Option<Uuid>,
) -> Result<Vec<rustmite_store::StoredObservation>, ApiError> {
    let rows = state
        .store
        .list_observations(Some(host.id), 50_000)
        .await?;
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    if let Some(sid) = scan_override {
        return Ok(rows
            .into_iter()
            .filter(|o| o.scan_id.0 == sid)
            .collect());
    }
    // Distinct scan ids in reverse append order (newest last → reverse iter).
    let mut seen = std::collections::HashSet::new();
    let mut ordered: Vec<Uuid> = Vec::new();
    for o in rows.iter().rev() {
        if seen.insert(o.scan_id.0) {
            ordered.push(o.scan_id.0);
        }
    }
    let pick = {
        let key = inventory.trim().to_ascii_lowercase();
        let idx0 = match key.as_str() {
            "" | "latest" | "current" | "newest" => Some(0usize),
            "previous" | "prev" | "prior" => Some(1usize),
            other => other.parse::<usize>().ok().and_then(|n| {
                if n == 0 {
                    Some(0)
                } else {
                    Some(n.saturating_sub(1))
                }
            }),
        };
        match idx0 {
            Some(i) => ordered.get(i).copied().or_else(|| ordered.last().copied()),
            None => ordered.first().copied(),
        }
    };
    let Some(scan_id) = pick else {
        return Ok(Vec::new());
    };
    Ok(rows
        .into_iter()
        .filter(|o| o.scan_id.0 == scan_id)
        .collect())
}

async fn latest_scan_obs(
    state: &AppState,
    host: &HostRecord,
) -> Result<Vec<rustmite_store::StoredObservation>, ApiError> {
    obs_for_host_inventory(state, host, "latest", None).await
}

async fn process_rows_for_host(
    state: &AppState,
    host: &HostRecord,
) -> Result<(Vec<RawLogEntry>, String), ApiError> {
    process_rows_for_host_ex(state, host, "latest", None).await
}

async fn process_rows_for_host_ex(
    state: &AppState,
    host: &HostRecord,
    inventory: &str,
    scan_override: Option<Uuid>,
) -> Result<(Vec<RawLogEntry>, String), ApiError> {
    if host.agent_kind.eq_ignore_ascii_case("virtual") {
        let rows = obs_for_host_inventory(state, host, inventory, scan_override).await?;
        if !rows.is_empty() {
            let machine = host.display_name.clone();
            let mut out = Vec::new();
            for o in rows.iter().filter(|o| o.kind == "process") {
                if let Observation::Process(p) = &o.data {
                    out.push(process_obs_to_raw(&machine, p, None));
                }
            }
            if !out.is_empty() {
                return Ok((out, "virtual_scan".into()));
            }
        }
        if scan_override.is_none() && inventory.eq_ignore_ascii_case("latest") {
            return Ok((load_virtual_jsonl(host), "virtual_ingest".into()));
        }
        return Ok((Vec::new(), "virtual_scan".into()));
    }
    let rows = obs_for_host_inventory(state, host, inventory, scan_override).await?;
    let machine = host.display_name.clone();
    let mut out = Vec::new();
    for o in rows.iter().filter(|o| o.kind == "process") {
        if let Observation::Process(p) = &o.data {
            out.push(process_obs_to_raw(&machine, p, None));
        } else if let Observation::HiddenProcess(h) = &o.data {
            out.push(RawLogEntry {
                machine_id: machine.clone(),
                pid: h.pid.max(0) as u32,
                ppid: 0,
                name: h.comm.clone().unwrap_or_else(|| "(hidden)".into()),
                uid: h.uid.unwrap_or(0),
                path: h
                    .exe
                    .as_ref()
                    .map(|b| String::from_utf8_lossy(&b.0).into_owned())
                    .unwrap_or_default(),
                args: String::new(),
                timestamp: None,
            });
        }
    }
    Ok((out, "scan_observations".into()))
}

async fn file_rows_for_host(
    state: &AppState,
    host: &HostRecord,
) -> Result<(Vec<RawFileEntry>, String), ApiError> {
    file_rows_for_host_ex(state, host, "latest", None).await
}

async fn file_rows_for_host_ex(
    state: &AppState,
    host: &HostRecord,
    inventory: &str,
    scan_override: Option<Uuid>,
) -> Result<(Vec<RawFileEntry>, String), ApiError> {
    if host.agent_kind.eq_ignore_ascii_case("virtual") {
        let rows = obs_for_host_inventory(state, host, inventory, scan_override).await?;
        if !rows.is_empty() {
            let machine = host.display_name.clone();
            let obs: Vec<_> = rows.into_iter().map(|o| o.data).collect();
            let converted = observations_to_file_logs(&machine, &obs, None);
            if !converted.is_empty() {
                return Ok((converted, "virtual_scan".into()));
            }
        }
        if scan_override.is_none() && inventory.eq_ignore_ascii_case("latest") {
            return Ok((load_virtual_files_jsonl(host), "virtual_ingest".into()));
        }
        return Ok((Vec::new(), "virtual_scan".into()));
    }
    let rows = obs_for_host_inventory(state, host, inventory, scan_override).await?;
    let machine = host.display_name.clone();
    let obs: Vec<_> = rows.into_iter().map(|o| o.data).collect();
    Ok((
        observations_to_file_logs(&machine, &obs, None),
        "scan_observations".into(),
    ))
}

pub async fn run_fleet_sift(
    State(state): State<AppState>,
    Json(body): Json<FleetSiftBody>,
) -> Result<impl IntoResponse, ApiError> {
    ensure_sift_dirs();
    let mode = body.mode.to_ascii_lowercase();
    let want_process = matches!(mode.as_str(), "process" | "both" | "");
    let want_file = matches!(mode.as_str(), "file" | "both");

    let (config, detection_config_id, detection_config_name) =
        resolve_fleet_detection_config(&state, &body)?;

    let hosts = state.store.list_hosts().await?;
    let filter_ids: Option<HashSet<Uuid>> = if body.host_ids.is_empty() {
        None
    } else {
        Some(body.host_ids.iter().copied().collect())
    };

    let mut all_logs: Vec<RawLogEntry> = Vec::new();
    let mut all_files: Vec<RawFileEntry> = Vec::new();
    let mut sources = Vec::new();

    for h in hosts {
        if let Some(ref ids) = filter_ids {
            if !ids.contains(&h.id.0) {
                continue;
            }
        }
        if !host_matches_labels(&h, &body.labels) {
            continue;
        }
        if !host_matches_tags(&h, &body.tags) {
            continue;
        }
        if !host_in_scan_window(&h, &body.scan_after, &body.scan_before) {
            continue;
        }

        let mut process_rows = 0usize;
        let mut file_rows = 0usize;
        let mut source = String::new();

        if want_process {
            let override_id = body.scan_ids.get(&h.id.0.to_string()).copied();
            let (rows, src) =
                process_rows_for_host_ex(&state, &h, &body.inventory, override_id).await?;
            process_rows = rows.len();
            source = src;
            all_logs.extend(rows);
        }
        if want_file {
            let override_id = body.scan_ids.get(&h.id.0.to_string()).copied();
            let (rows, src) =
                file_rows_for_host_ex(&state, &h, &body.inventory, override_id).await?;
            file_rows = rows.len();
            if source.is_empty() {
                source = src;
            }
            all_files.extend(rows);
        }

        if process_rows == 0 && file_rows == 0 {
            continue;
        }
        sources.push(FleetSiftSource {
            host_id: h.id.0.to_string(),
            display_name: h.display_name.clone(),
            agent_kind: h.agent_kind.clone(),
            process_rows,
            file_rows,
            source,
            last_scan_at: h.last_scan_at.clone(),
            labels: h.labels.clone(),
        });
    }

    if sources.len() < 2 {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            format!(
                "fleet sift needs data from ≥2 hosts (got {}); widen filters, scan SSH hosts, or POST /v1/ingest/logs for virtual agents",
                sources.len()
            ),
        ));
    }

    let mut machines = 0usize;
    let mut anomalies = 0usize;
    let mut process_report = serde_json::json!({});
    let mut file_report = None;

    if want_process && !all_logs.is_empty() {
        let profiles = build_profiles(all_logs, &config);
        machines = machines.max(profiles.len());
        let report = analyze_fleet(&profiles, &config).map_err(|e| {
            ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        })?;
        anomalies += report.anomalies.len();
        process_report = report_json(&report);
    }

    if want_file && !all_files.is_empty() {
        let profiles = build_file_profiles(all_files, &config);
        machines = machines.max(profiles.len());
        let report = analyze_files_fleet(&profiles, &config).map_err(|e| {
            ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        })?;
        anomalies += report.anomalies.len();
        file_report = Some(report_json(&report));
    }

    let run_id = Uuid::new_v4().to_string();
    let created_at = crate::sys_metrics::utc_now_rfc3339();
    let out_path = sift_root().join("runs").join(format!("{run_id}.json"));
    if let Ok(json) = serde_json::to_vec_pretty(&serde_json::json!({
        "run_id": run_id,
        "created_at": created_at,
        "mode": mode,
        "sources": sources,
        "report": process_report,
        "file_report": file_report,
        "machines": machines,
        "anomalies": anomalies,
        "detection_config_id": detection_config_id,
        "detection_config_name": detection_config_name,
    })) {
        let _ = fs::write(&out_path, json);
    }

    info!(
        run_id = %run_id,
        machines,
        anomalies,
        %mode,
        config = detection_config_name.as_deref().unwrap_or("default"),
        "fleet sift complete"
    );

    Ok(Json(FleetSiftResponse {
        run_id,
        created_at,
        machines,
        anomalies,
        mode,
        report: process_report,
        file_report,
        sources,
        detection_config_id,
        detection_config_name,
    }))
}

#[derive(Debug, Deserialize)]
pub struct TemporalBody {
    pub host_id: Uuid,
    /// Optional older scan id; defaults to previous finished scan.
    #[serde(default)]
    pub baseline_scan_id: Option<Uuid>,
    #[serde(default)]
    pub current_scan_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct TemporalResponse {
    pub host_id: String,
    pub display_name: String,
    pub baseline_label: String,
    pub current_label: String,
    pub diff: TemporalDiffJson,
}

#[derive(Debug, Serialize)]
pub struct TemporalDiffJson {
    pub new_processes: Vec<String>,
    pub new_files: Vec<String>,
    pub modified_files: Vec<String>,
    pub new_connections: Vec<String>,
}

fn temporal_to_json(diff: &TemporalDiff) -> TemporalDiffJson {
    TemporalDiffJson {
        new_processes: diff
            .new_processes
            .iter()
            .map(|p| format!("{} ({})", p.name, p.path))
            .collect(),
        new_files: diff
            .new_files
            .iter()
            .map(|f| f.path.to_string())
            .collect(),
        modified_files: diff
            .modified_files
            .iter()
            .map(|(path, old, new)| {
                format!("{path} (was: {old:?}, now: {new:?})")
            })
            .collect(),
        new_connections: diff.new_connections.clone(),
    }
}

async fn obs_for_scan(
    state: &AppState,
    host_id: HostId,
    scan_id: rustmite_proto::ScanId,
) -> Result<Vec<Observation>, ApiError> {
    let rows = state.store.list_observations(Some(host_id), 50_000).await?;
    Ok(rows
        .into_iter()
        .filter(|o| o.scan_id == scan_id)
        .map(|o| o.data)
        .collect())
}

pub async fn run_temporal_sift(
    State(state): State<AppState>,
    Json(body): Json<TemporalBody>,
) -> Result<impl IntoResponse, ApiError> {
    let host = state.store.get_host(HostId(body.host_id)).await?;
    if host.agent_kind.eq_ignore_ascii_case("virtual") {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "temporal compare needs two SSH scan snapshots; virtual agents use fleet sift".into(),
        ));
    }

    let scans = state.store.list_scans(200).await.unwrap_or_default();
    let finished: Vec<_> = scans
        .into_iter()
        .filter_map(|s| {
            let job = s.job?;
            if job.host_id != host.id {
                return None;
            }
            let st = job.state.to_ascii_lowercase();
            if st == "complete" || st == "failed" || s.meta.is_some() {
                Some(job)
            } else {
                None
            }
        })
        .collect();

    let current_id = body
        .current_scan_id
        .map(rustmite_proto::ScanId)
        .or_else(|| finished.first().map(|j| j.id));
    let baseline_id = body
        .baseline_scan_id
        .map(rustmite_proto::ScanId)
        .or_else(|| finished.get(1).map(|j| j.id));

    let (Some(cur), Some(base)) = (current_id, baseline_id) else {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "need at least two finished scans on this host for temporal compare".into(),
        ));
    };

    let config = DetectionConfig::default();
    let machine = host.display_name.clone();
    let cur_obs = obs_for_scan(&state, host.id, cur).await?;
    let base_obs = obs_for_scan(&state, host.id, base).await?;

    let cur_procs = {
        let mut v = Vec::new();
        for o in &cur_obs {
            if let Observation::Process(p) = o {
                v.push(process_obs_to_raw(&machine, p, None));
            }
        }
        v
    };
    let base_procs = {
        let mut v = Vec::new();
        for o in &base_obs {
            if let Observation::Process(p) = o {
                v.push(process_obs_to_raw(&machine, p, None));
            }
        }
        v
    };
    let cur_files = observations_to_file_logs(&machine, &cur_obs, None);
    let base_files = observations_to_file_logs(&machine, &base_obs, None);
    let cur_conns = observations_to_connections(&machine, &cur_obs, None);
    let base_conns = observations_to_connections(&machine, &base_obs, None);

    let baseline = build_machine_snapshot(
        &machine,
        &format!("scan-{}", base.0),
        base_procs,
        base_files,
        base_conns,
        &config,
    );
    let current = build_machine_snapshot(
        &machine,
        &format!("scan-{}", cur.0),
        cur_procs,
        cur_files,
        cur_conns,
        &config,
    );
    let diff = compare_temporal(&baseline, &current);

    Ok(Json(TemporalResponse {
        host_id: host.id.0.to_string(),
        display_name: host.display_name,
        baseline_label: format!("scan-{}", base.0),
        current_label: format!("scan-{}", cur.0),
        diff: temporal_to_json(&diff),
    }))
}

#[derive(Debug, Deserialize)]
pub struct ListRunsQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    50
}

pub async fn list_sift_runs(
    Query(q): Query<ListRunsQuery>,
) -> Result<impl IntoResponse, ApiError> {
    ensure_sift_dirs();
    let dir = sift_root().join("runs");
    let mut runs = Vec::new();
    if let Ok(rd) = fs::read_dir(&dir) {
        for ent in rd.flatten() {
            let path = ent.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let meta = ent.metadata().ok();
            let modified = meta
                .and_then(|m| m.modified().ok())
                .and_then(|t| {
                    t.duration_since(std::time::UNIX_EPOCH)
                        .ok()
                        .map(|d| d.as_secs())
                })
                .unwrap_or(0);
            let id = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            if let Ok(raw) = fs::read_to_string(&path) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
                    let report = v.get("report");
                    let anomalies = v
                        .get("anomalies")
                        .and_then(|a| a.as_u64())
                        .or_else(|| {
                            report
                                .and_then(|r| r.get("anomalies"))
                                .and_then(|a| a.as_array())
                                .map(|a| a.len() as u64)
                        });
                    let created_at = v
                        .get("created_at")
                        .and_then(|x| x.as_str())
                        .map(str::to_string)
                        .unwrap_or_else(|| unix_secs_to_rfc3339(modified));
                    runs.push(serde_json::json!({
                        "run_id": id,
                        "created_at": created_at,
                        "modified_unix": modified,
                        "machines": v.get("machines").cloned()
                            .or_else(|| report.and_then(|r| r.get("total_analyzed")).cloned()),
                        "anomalies": anomalies,
                        "mode": v.get("mode").cloned().unwrap_or(serde_json::json!("process")),
                        "detection_config_name": v.get("detection_config_name").cloned(),
                        "path": path.display().to_string(),
                    }));
                }
            }
        }
    }
    runs.sort_by(|a, b| {
        let am = a.get("modified_unix").and_then(|x| x.as_u64()).unwrap_or(0);
        let bm = b.get("modified_unix").and_then(|x| x.as_u64()).unwrap_or(0);
        bm.cmp(&am)
    });
    runs.truncate(q.limit.max(1).min(500));
    Ok(Json(serde_json::json!({ "runs": runs })))
}

pub async fn get_sift_run(
    AxumPath(id): AxumPath<String>,
) -> Result<impl IntoResponse, ApiError> {
    let path = sift_root().join("runs").join(format!("{id}.json"));
    let raw = fs::read_to_string(&path).map_err(|_| {
        ApiError(StatusCode::NOT_FOUND, format!("sift run {id} not found"))
    })?;
    let v: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(v))
}

fn sanitize_sift_run_id(id: &str) -> Result<&str, ApiError> {
    let id = id.trim();
    if id.is_empty()
        || id.contains('/')
        || id.contains('\\')
        || id.contains("..")
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ApiError(StatusCode::BAD_REQUEST, "invalid sift run id".into()));
    }
    Ok(id)
}

pub async fn delete_sift_run(
    AxumPath(id): AxumPath<String>,
) -> Result<impl IntoResponse, ApiError> {
    let id = sanitize_sift_run_id(&id)?;
    let path = sift_root().join("runs").join(format!("{id}.json"));
    if !path.is_file() {
        return Err(ApiError(
            StatusCode::NOT_FOUND,
            format!("sift run {id} not found"),
        ));
    }
    fs::remove_file(&path).map_err(|e| {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to delete sift run: {e}"),
        )
    })?;
    info!(run_id = %id, "fleet sift run deleted");
    Ok(Json(serde_json::json!({ "ok": true, "deleted": id })))
}

pub async fn delete_all_sift_runs() -> Result<impl IntoResponse, ApiError> {
    ensure_sift_dirs();
    let dir = sift_root().join("runs");
    let mut deleted = 0usize;
    if let Ok(rd) = fs::read_dir(&dir) {
        for ent in rd.flatten() {
            let path = ent.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if fs::remove_file(&path).is_ok() {
                deleted += 1;
            }
        }
    }
    info!(deleted, "fleet sift runs cleared");
    Ok(Json(serde_json::json!({ "ok": true, "deleted": deleted })))
}

pub async fn sift_config(State(state): State<AppState>) -> impl IntoResponse {
    if let Ok(store) = state.sift_platform.get() {
        if let Ok((cfg, profiles, selected_id)) = store.run_config_with_profiles() {
            return Json(serde_json::json!({
                "config": cfg,
                "profiles": profiles,
                "selected_id": selected_id,
            }))
            .into_response();
        }
        return Json(serde_json::json!({
            "config": store.get_run_config(),
            "profiles": [],
            "selected_id": null,
        }))
        .into_response();
    }
    let path = Path::new("crates/rustmite-sift/config/default_sift.json");
    let cfg = if path.is_file() {
        fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str::<DetectionConfig>(&s).ok())
            .unwrap_or_default()
    } else {
        DetectionConfig::default()
    };
    Json(serde_json::json!({
        "config": cfg,
        "profiles": [],
        "selected_id": null,
    }))
    .into_response()
}

/// Resolve host by ingest token for virtual-agent ingest.
pub async fn host_by_ingest_token(
    store: &dyn Store,
    token: &str,
) -> Result<HostRecord, ApiError> {
    let token = token.trim();
    if token.is_empty() {
        return Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "ingest token required".into(),
        ));
    }
    let hosts = store.list_hosts().await?;
    hosts
        .into_iter()
        .find(|h| {
            h.ingest_token
                .as_deref()
                .map(|t| t == token)
                .unwrap_or(false)
        })
        .ok_or_else(|| {
            ApiError(
                StatusCode::UNAUTHORIZED,
                "unknown ingest token".into(),
            )
        })
}

pub fn append_virtual_process_logs(host: &HostRecord, body: &str) -> Result<usize, String> {
    append_virtual_logs(host, "processes.jsonl", body)
}

/// Replace (truncate) process NDJSON for a virtual host — used for new snapshots.
pub fn replace_virtual_process_logs(host: &HostRecord, body: &str) -> Result<usize, String> {
    replace_virtual_logs(host, "processes.jsonl", body)
}

/// Append file-access NDJSON for a virtual host (`files.jsonl`).
pub fn append_virtual_file_logs(host: &HostRecord, body: &str) -> Result<usize, String> {
    append_virtual_logs(host, "files.jsonl", body)
}

/// Replace (truncate) file NDJSON for a virtual host — used for new snapshots.
pub fn replace_virtual_file_logs(host: &HostRecord, body: &str) -> Result<usize, String> {
    replace_virtual_logs(host, "files.jsonl", body)
}

fn append_virtual_logs(host: &HostRecord, filename: &str, body: &str) -> Result<usize, String> {
    ensure_sift_dirs();
    let dir = ingest_dir().join(host.id.0.to_string());
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join(filename);
    let mut n = 0usize;
    let mut out = String::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let _v: serde_json::Value =
            serde_json::from_str(line).map_err(|e| format!("invalid JSONL: {e}"))?;
        out.push_str(line);
        out.push('\n');
        n += 1;
    }
    if n == 0 {
        return Err("empty body".into());
    }
    use std::io::Write;
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| e.to_string())?;
    f.write_all(out.as_bytes()).map_err(|e| e.to_string())?;
    Ok(n)
}

fn replace_virtual_logs(host: &HostRecord, filename: &str, body: &str) -> Result<usize, String> {
    ensure_sift_dirs();
    let dir = ingest_dir().join(host.id.0.to_string());
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join(filename);
    let mut n = 0usize;
    let mut out = String::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let _v: serde_json::Value =
            serde_json::from_str(line).map_err(|e| format!("invalid JSONL: {e}"))?;
        out.push_str(line);
        out.push('\n');
        n += 1;
    }
    // Allow empty replace (clear snapshot).
    fs::write(&path, out.as_bytes()).map_err(|e| e.to_string())?;
    Ok(n)
}

/// Collect `*.jsonl` / `*.ndjson` under a directory (IronSift-style), publicly for tree import.
pub fn collect_jsonl_files_under(
    dir: &Path,
    recursive: bool,
    out: &mut Vec<PathBuf>,
) -> Result<(), String> {
    collect_jsonl_under(dir, recursive, out)
}

/// Kind override for virtual-agent file/directory import (IronSift-style).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum VirtualIngestKind {
    #[default]
    Auto,
    Processes,
    Files,
}

impl VirtualIngestKind {
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "files" | "file" => Self::Files,
            "processes" | "process" | "procs" => Self::Processes,
            _ => Self::Auto,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct VirtualImportFileResult {
    pub name: String,
    pub processes: usize,
    pub files: usize,
    pub skipped: usize,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VirtualImportSummary {
    pub host_id: Uuid,
    pub files_processed: usize,
    pub processes_appended: usize,
    pub files_appended: usize,
    pub skipped: usize,
    pub results: Vec<VirtualImportFileResult>,
}

/// Collect ingestible paths the way IronSift does:
/// - file → that file (jsonl/ndjson/json/csv)
/// - directory → recursive `*.jsonl` / `*.ndjson` only (see `import_jsonl_recursive`)
fn collect_ironsift_paths(root: &Path, recursive: bool, out: &mut Vec<PathBuf>) -> Result<(), String> {
    if root.is_file() {
        if is_ingest_file(root) {
            out.push(root.to_path_buf());
            return Ok(());
        }
        return Err(format!(
            "unsupported file type {} (use .jsonl / .ndjson / .json / .csv)",
            root.display()
        ));
    }
    if !root.is_dir() {
        return Err(format!("not a file or directory: {}", root.display()));
    }
    collect_jsonl_under(root, recursive, out)?;
    Ok(())
}

fn collect_jsonl_under(dir: &Path, recursive: bool, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.is_dir() {
            if recursive {
                collect_jsonl_under(&path, true, out)?;
            }
        } else if is_jsonl_file(&path) {
            out.push(path);
        }
    }
    Ok(())
}

fn is_jsonl_file(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .as_deref(),
        Some("jsonl" | "ndjson")
    )
}

fn is_ingest_file(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .as_deref(),
        Some("jsonl" | "ndjson" | "json" | "csv")
    )
}

fn default_machine_for_host(host: &HostRecord) -> String {
    if !host.display_name.trim().is_empty() {
        host.display_name.clone()
    } else {
        host.id.0.to_string()
    }
}

fn resolve_kind_for_content(
    content: &str,
    name: &str,
    kind: VirtualIngestKind,
) -> VirtualIngestKind {
    match kind {
        VirtualIngestKind::Processes | VirtualIngestKind::Files => kind,
        VirtualIngestKind::Auto => {
            // Prefer IronSift sniff when we can write a temp sample; else line heuristics.
            let ext = Path::new(name)
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if ext == "csv" {
                // CSV: try process schema first (IronSift --input default).
                return VirtualIngestKind::Processes;
            }
            sniff_content_kind(content)
        }
    }
}

fn sniff_content_kind(content: &str) -> VirtualIngestKind {
    use rustmite_sift::{parse_jsonl_process_line, RawFileEntry};

    // PulseSecure (and similar): event_type rows may be sectioned (all files, then processes).
    let (event_proc, event_file) = snapshot_event_type_counts(content);
    if event_proc > 0 && event_file > 0 {
        return VirtualIngestKind::Auto; // normalize_ingest_content handles mixed
    }
    if event_proc > 0 && event_file == 0 {
        return VirtualIngestKind::Processes;
    }
    if event_file > 0 && event_proc == 0 {
        return VirtualIngestKind::Files;
    }

    let mut proc = 0u32;
    let mut file = 0u32;
    let sample = content.lines().filter(|l| {
        let t = l.trim();
        !t.is_empty() && !t.starts_with('#') && !t.starts_with("//")
    }).take(80);
    for line in sample {
        let t = line.trim();
        // JSON array → sniff first elements
        if t.starts_with('[') {
            if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(content.trim()) {
                for item in arr.iter().take(40) {
                    if let Ok(s) = serde_json::to_string(item) {
                        if parse_jsonl_process_line(&s, "_").is_ok() {
                            if looks_like_file_row(item) {
                                file += 1;
                            } else {
                                proc += 1;
                            }
                        } else if serde_json::from_str::<RawFileEntry>(&s)
                            .map(|e| !e.path.trim().is_empty())
                            .unwrap_or(false)
                        {
                            file += 1;
                        }
                    }
                }
                break;
            }
        }
        if parse_jsonl_process_line(t, "_").is_ok() {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(t) {
                if looks_like_file_row(&v) && !looks_like_process_row(&v) {
                    file += 1;
                    continue;
                }
            }
            proc += 1;
            continue;
        }
        if serde_json::from_str::<RawFileEntry>(t)
            .map(|e| !e.path.trim().is_empty())
            .unwrap_or(false)
        {
            file += 1;
        }
    }
    if file > 0 && proc == 0 {
        VirtualIngestKind::Files
    } else if proc > 0 && file == 0 {
        VirtualIngestKind::Processes
    } else if file > proc {
        VirtualIngestKind::Files
    } else {
        VirtualIngestKind::Processes
    }
}

/// True when content has both process and file event_type rows (PulseSecure snapshots).
/// Scans the **whole** file — PulseSecure puts all `file_information` first, then processes.
fn content_looks_mixed_snapshot(content: &str) -> bool {
    let mut has_proc = false;
    let mut has_file = false;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Fast path: avoid full JSON parse when event_type is obvious in the line.
        let lower = line.to_ascii_lowercase();
        if !has_proc
            && (lower.contains("\"event_type\":\"process\"")
                || lower.contains("\"event_type\": \"process\""))
        {
            has_proc = true;
        }
        if !has_file
            && (lower.contains("\"event_type\":\"file_information\"")
                || lower.contains("\"event_type\": \"file_information\"")
                || lower.contains("\"event_type\":\"file\"")
                || lower.contains("\"event_type\": \"file\""))
        {
            has_file = true;
        }
        if has_proc && has_file {
            return true;
        }
    }
    false
}

/// Count event_type hints across the full content (for Auto kind resolution).
fn snapshot_event_type_counts(content: &str) -> (u32, u32) {
    let mut event_proc = 0u32;
    let mut event_file = 0u32;
    for line in content.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("\"event_type\":\"process\"")
            || lower.contains("\"event_type\": \"process\"")
        {
            event_proc += 1;
        } else if lower.contains("\"event_type\":\"file_information\"")
            || lower.contains("\"event_type\": \"file_information\"")
            || lower.contains("\"event_type\":\"file_meta\"")
            || lower.contains("\"event_type\": \"file_meta\"")
        {
            event_file += 1;
        }
    }
    (event_proc, event_file)
}

fn looks_like_file_row(v: &serde_json::Value) -> bool {
    let has_path = v.get("path").or_else(|| v.get("file_path")).is_some();
    let has_mtime = v.get("mtime").or_else(|| v.get("date")).is_some();
    let has_mode = v.get("permissions").or_else(|| v.get("mode")).is_some();
    let has_proc = looks_like_process_row(v);
    has_path && (has_mtime || has_mode || !has_proc)
}

fn looks_like_process_row(v: &serde_json::Value) -> bool {
    v.get("pid").is_some()
        || v.get("ppid").is_some()
        || v.get("cmdline").is_some()
        || v.get("command").is_some()
        || v.get("CommandLine").is_some()
        || v.get("comm").is_some()
        || v.get("process_name").is_some()
}

/// Normalize one file's content into process + file NDJSON using IronSift parsers.
pub fn normalize_ingest_content(
    content: &str,
    name: &str,
    kind: VirtualIngestKind,
    default_machine: &str,
) -> (String, String, VirtualImportFileResult) {
    normalize_ingest_content_with_map(
        content,
        name,
        kind,
        default_machine,
        &crate::ingest_map::VirtualIngestMap::default(),
    )
}

/// Like [`normalize_ingest_content`], applying a per-host / virtual-agent field map.
pub fn normalize_ingest_content_with_map(
    content: &str,
    name: &str,
    kind: VirtualIngestKind,
    default_machine: &str,
    map: &crate::ingest_map::VirtualIngestMap,
) -> (String, String, VirtualImportFileResult) {
    use rustmite_sift::{parse_files_json_logs, parse_jsonl_logs, parse_jsonl_process_line};

    let mut proc_out = String::new();
    let mut file_out = String::new();
    let mut result = VirtualImportFileResult {
        name: name.to_string(),
        processes: 0,
        files: 0,
        skipped: 0,
        errors: Vec::new(),
    };

    let trimmed = content.trim();
    if trimmed.is_empty() {
        result.skipped = 1;
        result.errors.push("empty content".into());
        return (proc_out, file_out, result);
    }

    let ext = Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    // PulseSecure (and similar) mixed snapshots: one JSONL with process + file + socket.
    // Do not let file-row dominance drop process lines.
    if ext != "csv"
        && matches!(kind, VirtualIngestKind::Auto)
        && content_looks_mixed_snapshot(trimmed)
    {
        info!(
            file = %name,
            "mixed snapshot detected — extracting process + file rows"
        );
        let (procs, files, _socks, skipped) =
            crate::ingest_tree::parse_mixed_snapshot_jsonl_with_map(trimmed, default_machine, map);
        result.skipped += skipped;
        for e in procs {
            if let Ok(line) = serde_json::to_string(&e) {
                proc_out.push_str(&line);
                proc_out.push('\n');
                result.processes += 1;
            }
        }
        for e in files {
            if e.path.trim().is_empty() {
                result.skipped += 1;
                continue;
            }
            if let Ok(line) = serde_json::to_string(&e) {
                file_out.push_str(&line);
                file_out.push('\n');
                result.files += 1;
            }
        }
        if result.processes == 0 && result.files == 0 && result.errors.is_empty() {
            result
                .errors
                .push("mixed snapshot: no process/file rows parsed".into());
        }
        return (proc_out, file_out, result);
    }

    let resolved = resolve_kind_for_content(trimmed, name, kind);

    if ext == "csv" {
        match resolved {
            VirtualIngestKind::Files => {
                match parse_csv_files(trimmed, default_machine) {
                    Ok(entries) => {
                        for e in entries {
                            if let Ok(line) = serde_json::to_string(&e) {
                                file_out.push_str(&line);
                                file_out.push('\n');
                                result.files += 1;
                            }
                        }
                    }
                    Err(e) => result.errors.push(format!("csv files: {e}")),
                }
            }
            _ => match parse_csv_processes(trimmed, default_machine) {
                Ok(entries) => {
                    for e in entries {
                        if let Ok(line) = serde_json::to_string(&e) {
                            proc_out.push_str(&line);
                            proc_out.push('\n');
                            result.processes += 1;
                        }
                    }
                }
                Err(e) => result.errors.push(format!("csv processes: {e}")),
            },
        }
        if result.processes == 0 && result.files == 0 && result.errors.is_empty() {
            result.errors.push("no CSV rows parsed".into());
        }
        return (proc_out, file_out, result);
    }

    match resolved {
        VirtualIngestKind::Files => {
            match parse_files_json_logs(trimmed, default_machine) {
                Ok(entries) => {
                    for e in entries {
                        if e.path.trim().is_empty() {
                            result.skipped += 1;
                            continue;
                        }
                        if let Ok(line) = serde_json::to_string(&e) {
                            file_out.push_str(&line);
                            file_out.push('\n');
                            result.files += 1;
                        }
                    }
                }
                Err(e) => result.errors.push(format!("file parse: {e}")),
            }
        }
        VirtualIngestKind::Processes | VirtualIngestKind::Auto => {
            // IronSift JSONL process path: parse_jsonl_logs (tolerant per-line).
            match parse_jsonl_logs(trimmed, default_machine) {
                Ok(entries) if !entries.is_empty() => {
                    for e in entries {
                        if let Ok(line) = serde_json::to_string(&e) {
                            proc_out.push_str(&line);
                            proc_out.push('\n');
                            result.processes += 1;
                        }
                    }
                }
                Ok(_) | Err(_) => {
                    // Fallback: JSON array via per-line / per-element parse_jsonl_process_line
                    if trimmed.starts_with('[') {
                        if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(trimmed) {
                            for item in arr {
                                let Ok(line) = serde_json::to_string(&item) else {
                                    result.skipped += 1;
                                    continue;
                                };
                                match parse_jsonl_process_line(&line, default_machine) {
                                    Ok(e) => {
                                        if let Ok(s) = serde_json::to_string(&e) {
                                            proc_out.push_str(&s);
                                            proc_out.push('\n');
                                            result.processes += 1;
                                        }
                                    }
                                    Err(err) => {
                                        result.skipped += 1;
                                        if result.errors.len() < 8 {
                                            result.errors.push(err.to_string());
                                        }
                                    }
                                }
                            }
                        } else {
                            result.errors.push("invalid JSON array".into());
                        }
                    } else {
                        // Line-oriented with explicit errors (parse_jsonl_logs already warned away)
                        for line in trimmed.lines() {
                            let line = line.trim();
                            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                                continue;
                            }
                            if let Some(e) = crate::ingest_map::process_from_value(
                                &serde_json::from_str(line).unwrap_or(serde_json::Value::Null),
                                map,
                                default_machine,
                            )
                            .or_else(|| parse_jsonl_process_line(line, default_machine).ok())
                            {
                                if let Ok(s) = serde_json::to_string(&e) {
                                    proc_out.push_str(&s);
                                    proc_out.push('\n');
                                    result.processes += 1;
                                }
                            } else {
                                result.skipped += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    if result.processes == 0 && result.files == 0 && result.errors.is_empty() {
        result.errors.push("no rows parsed (expected IronSift JSONL/JSON/CSV process or file rows)".into());
    }
    (proc_out, file_out, result)
}

fn parse_csv_processes(content: &str, default_machine: &str) -> Result<Vec<RawLogEntry>, String> {
    let mut rdr = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(content.as_bytes());
    let mut out = Vec::new();
    for row in rdr.deserialize::<RawLogEntry>() {
        let mut e = row.map_err(|e| e.to_string())?;
        if e.machine_id.is_empty() {
            e.machine_id = default_machine.to_string();
        }
        out.push(e);
    }
    Ok(out)
}

fn parse_csv_files(content: &str, default_machine: &str) -> Result<Vec<RawFileEntry>, String> {
    let mut rdr = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(content.as_bytes());
    let mut out = Vec::new();
    for row in rdr.deserialize::<RawFileEntry>() {
        let mut e = row.map_err(|e| e.to_string())?;
        if e.machine_id.is_empty() {
            e.machine_id = default_machine.to_string();
        }
        if e.path.trim().is_empty() {
            continue;
        }
        out.push(e);
    }
    Ok(out)
}

/// Import server-local path (file or directory) and/or inline file payloads into a virtual host.
///
/// Directory import mirrors IronSift `--ingest-jsonl-dir`: recursive `*.jsonl` / `*.ndjson`.
/// Single-file import mirrors `--input`: `.jsonl` / `.json` / `.csv`.
pub fn import_virtual_feed_data(
    host: &HostRecord,
    path: Option<&str>,
    recursive: bool,
    kind: VirtualIngestKind,
    inline_files: &[(String, String)],
) -> Result<VirtualImportSummary, String> {
    import_virtual_feed_data_opts(host, path, recursive, kind, inline_files, false)
}

/// Import with optional replace of existing processes.jsonl / files.jsonl.
pub fn import_virtual_feed_data_opts(
    host: &HostRecord,
    path: Option<&str>,
    recursive: bool,
    kind: VirtualIngestKind,
    inline_files: &[(String, String)],
    replace: bool,
) -> Result<VirtualImportSummary, String> {
    let is_virtual = host.agent_kind.eq_ignore_ascii_case("virtual")
        || host
            .auth_status
            .as_deref()
            .map(|s| s.eq_ignore_ascii_case("virtual"))
            .unwrap_or(false);
    if !is_virtual {
        return Err("host is not a virtual agent".into());
    }
    let default_machine = default_machine_for_host(host);
    let map = crate::ingest_map::map_for_host(host);
    let mut paths: Vec<PathBuf> = Vec::new();
    if let Some(p) = path.map(str::trim).filter(|s| !s.is_empty()) {
        // Reject values that look like ingest tokens accidentally pasted into path.
        if p.starts_with("va-") && Uuid::parse_str(p.trim_start_matches("va-")).is_ok() {
            return Err(
                "path looks like an ingest token (va-…); upload files or set a real filesystem path"
                    .into(),
            );
        }
        let root = PathBuf::from(p);
        if !root.exists() {
            return Err(format!(
                "path not found on server: {p} (server-local path only; use Upload files for browser files)"
            ));
        }
        if root.is_dir() {
            // Day-folder layout (many host subdirs) must use Import tree, not single-host ingest.
            if let Ok(rd) = fs::read_dir(&root) {
                let mut hostish = 0usize;
                for ent in rd.flatten() {
                    let sub = ent.path();
                    if !sub.is_dir() {
                        continue;
                    }
                    let has_jsonl = fs::read_dir(&sub)
                        .ok()
                        .map(|it| {
                            it.flatten().any(|e| {
                                e.path()
                                    .extension()
                                    .and_then(|x| x.to_str())
                                    .map(|x| x.eq_ignore_ascii_case("jsonl") || x.eq_ignore_ascii_case("ndjson"))
                                    .unwrap_or(false)
                            })
                        })
                        .unwrap_or(false);
                    if has_jsonl {
                        hostish += 1;
                        if hostish >= 2 {
                            return Err(format!(
                                "{p} looks like a fleet day folder ({hostish}+ host subdirs). \
                                 Use Settings → Virtual agents → Import tree (not a single virtual agent path)."
                            ));
                        }
                    }
                }
            }
        }
        collect_ironsift_paths(&root, recursive, &mut paths)?;
        paths.sort();
        if paths.is_empty() {
            return Err(format!(
                "no .jsonl/.ndjson files found under {} (IronSift directory ingest)",
                root.display()
            ));
        }
    }

    let mut summary = VirtualImportSummary {
        host_id: host.id.0,
        files_processed: 0,
        processes_appended: 0,
        files_appended: 0,
        skipped: 0,
        results: Vec::new(),
    };

    let root_for_names = path
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);

    let mut all_proc = String::new();
    let mut all_file = String::new();

    for p in &paths {
        let name = match root_for_names.as_ref() {
            Some(root) if root.is_dir() => p
                .strip_prefix(root)
                .unwrap_or(p.as_path())
                .to_string_lossy()
                .replace('\\', "/"),
            _ => p
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("file")
                .to_string(),
        };
        let name = if name.is_empty() {
            p.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("file")
                .to_string()
        } else {
            name
        };
        let content = fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
        let (proc, file, res) =
            normalize_ingest_content_with_map(&content, &name, kind, &default_machine, &map);
        summary.files_processed += 1;
        summary.skipped += res.skipped;
        summary.processes_appended += res.processes;
        summary.files_appended += res.files;
        all_proc.push_str(&proc);
        all_file.push_str(&file);
        summary.results.push(res);
    }

    for (name, content) in inline_files {
        let (proc, file, res) =
            normalize_ingest_content_with_map(content, name, kind, &default_machine, &map);
        summary.files_processed += 1;
        summary.skipped += res.skipped;
        summary.processes_appended += res.processes;
        summary.files_appended += res.files;
        all_proc.push_str(&proc);
        all_file.push_str(&file);
        summary.results.push(res);
    }

    if summary.files_processed == 0 {
        return Err("no files to import (provide a server path to a .jsonl file/dir, or upload files[])".into());
    }
    if !all_proc.is_empty() {
        if replace {
            replace_virtual_process_logs(host, &all_proc)?;
        } else {
            append_virtual_process_logs(host, &all_proc)?;
        }
    } else if replace {
        let _ = replace_virtual_process_logs(host, "");
    }
    if !all_file.is_empty() {
        if replace {
            replace_virtual_file_logs(host, &all_file)?;
        } else {
            append_virtual_file_logs(host, &all_file)?;
        }
    } else if replace {
        let _ = replace_virtual_file_logs(host, "");
    }
    // ClickHouse sync is done by async callers via platform_ch::sync_virtual_host_from_state.
    if summary.processes_appended == 0 && summary.files_appended == 0 {
        let hints: Vec<String> = summary
            .results
            .iter()
            .flat_map(|r| r.errors.iter().cloned())
            .take(5)
            .collect();
        return Err(format!(
            "parsed 0 rows from {} file(s) (skipped {}).{}",
            summary.files_processed,
            summary.skipped,
            if hints.is_empty() {
                String::new()
            } else {
                format!(" errors: {}", hints.join("; "))
            }
        ));
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mixed_pulsesecure_feed_extracts_processes_and_files() {
        let content = r#"
{"timestamp":"2026-05-11T00:10:06","event_type":"file_information","permissions":"drwxr-xr-x.","owner":"root","group":"root","size":4096,"file_path":"/data/var","date":"2025-09-23T00:00:00"}
{"timestamp":"2026-05-11T00:10:06","event_type":"process","user":"0","command":"/sbin/init auto","pid":1,"ppid":0}
{"timestamp":"2026-05-11T00:10:06","event_type":"network_connection","protocol":"tcp","source_ip":"*","destination_ip":"*","source_port":"800","destination_port":"*","program_pid":null}
{"timestamp":"2026-05-11T00:10:06","event_type":"file_information","permissions":"-rw-r--r--.","owner":"root","group":"root","size":12,"file_path":"/etc/hostname","date":"2025-01-01T00:00:00"}
{"timestamp":"2026-05-11T00:10:06","event_type":"process","user":"0","command":"/usr/sbin/sshd -D","pid":42,"ppid":1}
"#;
        assert!(content_looks_mixed_snapshot(content));
        let (proc_out, file_out, res) = normalize_ingest_content(
            content,
            "snapshot.jsonl",
            VirtualIngestKind::Auto,
            "HOST",
        );
        assert_eq!(res.processes, 2, "proc errors: {:?}", res.errors);
        assert_eq!(res.files, 2, "file errors: {:?}", res.errors);
        assert!(proc_out.contains("sshd") || proc_out.contains("init"));
        assert!(file_out.contains("/data/var"));
    }

    #[test]
    fn mixed_detects_when_processes_come_after_many_files() {
        // Real PulseSecure layout: tens of thousands of file rows, then processes.
        let mut content = String::new();
        for i in 0..250 {
            content.push_str(&format!(
                r#"{{"timestamp":"2026-05-11T00:10:06","event_type":"file_information","file_path":"/tmp/f{i}","permissions":"-rw-r--r--","size":1}}"#
            ));
            content.push('\n');
        }
        content.push_str(
            r#"{"timestamp":"2026-05-11T00:10:06","event_type":"process","user":"0","command":"/sbin/init","pid":1,"ppid":0}"#,
        );
        content.push('\n');
        assert!(content_looks_mixed_snapshot(&content));
        let (_p, _f, res) = normalize_ingest_content(
            &content,
            "late-proc.jsonl",
            VirtualIngestKind::Auto,
            "HOST",
        );
        assert_eq!(res.processes, 1, "errors: {:?}", res.errors);
        assert_eq!(res.files, 250);
    }
}
