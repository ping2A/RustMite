//! Dedicated AnoMark multi-model APIs: train, list, apply to hosts, auto-run after scan.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use rustmite_proto::Observation;
use rustmite_sift::{
    process_obs_to_raw, AnoMarkTrainRequest, CreateDatasetRequest, CreateRunRequest, DatasetKind,
    RawLogEntry, RunDetectorMode,
};
use rustmite_store::{ActivityEvent, HostId, HostRecord, Store};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use crate::routes::{ApiError, AppState};
use crate::sift_api::load_virtual_jsonl;

fn auto_config_path() -> PathBuf {
    PathBuf::from(".dev/anomark-auto.json")
}

/// Auto-run AnoMark after successful scans.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnoMarkAutoConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Training id to use; empty = platform default model path.
    #[serde(default)]
    pub model_id: Option<String>,
    #[serde(default = "default_suspect")]
    pub suspect_percent: f64,
    /// Only run when scan check_set is in this list (empty = any).
    #[serde(default)]
    pub check_sets: Vec<String>,
    /// Max process lines to score per host (protect large inventories).
    #[serde(default = "default_max_cmds")]
    pub max_commands: usize,
    /// If non-empty, only these host ids run auto AnoMark.
    #[serde(default)]
    pub host_ids: Vec<Uuid>,
    /// Soft tag match (all must match host labels / tags). Empty = any.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Exact label matches (e.g. env=prod). Empty = any.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    /// Restrict to agent kind (`ssh` / `virtual`). Empty = any.
    #[serde(default)]
    pub agent_kind: Option<String>,
}

fn default_suspect() -> f64 {
    95.0
}
fn default_max_cmds() -> usize {
    5_000
}

impl Default for AnoMarkAutoConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            model_id: None,
            suspect_percent: 95.0,
            check_sets: vec![
                "standard".into(),
                "deep".into(),
                "incident".into(),
                "virtual-import".into(),
            ],
            max_commands: 5_000,
            host_ids: vec![],
            tags: vec![],
            labels: BTreeMap::new(),
            agent_kind: None,
        }
    }
}

#[derive(Clone, Default)]
pub struct AnoMarkAutoStore(Arc<Mutex<AnoMarkAutoConfig>>);

impl AnoMarkAutoStore {
    pub fn load() -> Self {
        let cfg = fs::read_to_string(auto_config_path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        Self(Arc::new(Mutex::new(cfg)))
    }

    pub fn get(&self) -> AnoMarkAutoConfig {
        self.0.lock().map(|g| g.clone()).unwrap_or_default()
    }

    pub fn set(&self, cfg: AnoMarkAutoConfig) -> Result<AnoMarkAutoConfig, String> {
        let _ = fs::create_dir_all(".dev");
        fs::write(
            auto_config_path(),
            serde_json::to_string_pretty(&cfg).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        if let Ok(mut g) = self.0.lock() {
            *g = cfg.clone();
        }
        Ok(cfg)
    }
}

pub fn anomark_routes() -> Router<AppState> {
    Router::new()
        .route("/v1/anomark/models", get(list_models).post(train_model))
        .route("/v1/anomark/models/{id}", delete(delete_model).get(get_model))
        .route("/v1/anomark/models/{id}/favorite", put(favorite_model))
        .route("/v1/anomark/models/{id}/inspect", get(inspect_model))
        .route("/v1/anomark/score", post(score_command))
        .route("/v1/anomark/apply", post(apply_to_hosts))
        .route("/v1/anomark/auto", get(get_auto).put(put_auto))
        .route("/v1/anomark/availability", get(availability))
}

pub async fn availability(State(state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    let store = state.sift_platform.get()?;
    Ok(Json(store.anomark_availability()))
}

pub async fn list_models(State(state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    let store = state.sift_platform.get_restored(&state).await?;
    let trains = store.list_anomark_trainings_for_display();
    Ok(Json(serde_json::json!({ "models": trains })))
}

pub async fn get_model(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let store = state.sift_platform.get()?;
    let t = store
        .list_anomark_trainings()
        .into_iter()
        .find(|t| t.id == id)
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, format!("model {id} not found")))?;
    Ok(Json(t))
}

#[derive(Debug, Deserialize)]
pub struct TrainModelBody {
    /// Display name for this model.
    pub name: String,
    /// Train from these hosts' process inventories (cmdline / command).
    #[serde(default)]
    pub host_ids: Vec<Uuid>,
    /// Which finished scan to use: `latest`/`1`, `previous`/`2`, or Nth newest.
    #[serde(default = "default_inventory")]
    pub inventory: String,
    /// Or train from a server-local JSONL/CSV/TXT path.
    #[serde(default)]
    pub path: Option<String>,
    /// Or paste training lines (one command per line).
    #[serde(default)]
    pub lines: Option<String>,
    #[serde(default = "default_order")]
    pub order: u8,
    #[serde(default = "default_column")]
    pub column: String,
}

fn default_order() -> u8 {
    4
}
fn default_column() -> String {
    "cmdline".into()
}
fn default_inventory() -> String {
    "1".into()
}

pub async fn train_model(
    State(state): State<AppState>,
    Json(body): Json<TrainModelBody>,
) -> Result<impl IntoResponse, ApiError> {
    let name = body.name.trim();
    if name.is_empty() {
        return Err(ApiError(StatusCode::BAD_REQUEST, "name required".into()));
    }
    let store = state.sift_platform.get()?;
    let training_path = resolve_training_input(&state, &body).await?;
    let req = AnoMarkTrainRequest {
        name: name.to_string(),
        training_path: training_path.display().to_string(),
        dataset_ids: vec![],
        tags: vec!["rustmite".into()],
        column: body.column,
        order: body.order,
        output_model_path: String::new(),
    };
    let result = store
        .train_anomark(req)
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e.to_string()))?;
    // Clean temp training file if we created one under .dev
    if training_path.starts_with(".dev/anomark-train-input") {
        let _ = fs::remove_file(&training_path);
    }
    if let Some(ch) = state.clickhouse.as_ref() {
        if let Err(e) =
            crate::platform_ch::sync_anomark_training(ch, &store, &result.train_id).await
        {
            warn!(error = %e, "AnoMark ClickHouse persist failed");
        }
        crate::platform_ch::sync_sift_db(ch).await;
    }
    let _ = state
        .store
        .push_activity(ActivityEvent {
            id: Uuid::new_v4(),
            ts: crate::sys_metrics::utc_now_rfc3339(),
            level: "info".into(),
            kind: "anomark.trained".into(),
            message: format!("AnoMark model '{}' trained ({})", name, result.train_id),
            scan_id: None,
            host_id: None,
            node_id: None,
            detail: Some(serde_json::json!({
                "train_id": result.train_id,
                "name": name,
                "lines": result.record.training_line_count,
            })),
        })
        .await;
    Ok((StatusCode::CREATED, Json(result)))
}

async fn resolve_training_input(
    state: &AppState,
    body: &TrainModelBody,
) -> Result<PathBuf, ApiError> {
    if let Some(path) = body.path.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let p = PathBuf::from(path);
        if !p.is_file() {
            return Err(ApiError(
                StatusCode::BAD_REQUEST,
                format!("training path not found: {path}"),
            ));
        }
        return Ok(p);
    }
    if let Some(text) = body.lines.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let _ = fs::create_dir_all(".dev");
        let path = PathBuf::from(format!(".dev/anomark-train-input-{}.txt", Uuid::new_v4()));
        fs::write(&path, text).map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        return Ok(path);
    }
    if body.host_ids.is_empty() {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "provide path, lines, or host_ids to train from".into(),
        ));
    }
    let mut out = String::new();
    let mut n = 0usize;
    let inventory = body.inventory.trim();
    for id in &body.host_ids {
        let host = state.store.get_host(HostId(*id)).await?;
        for cmd in collect_host_commands(state, &host, inventory).await? {
            // JSONL with cmdline column (AnoMark default)
            if let Ok(line) = serde_json::to_string(&serde_json::json!({
                "cmdline": cmd,
                "machine_id": host.display_name,
            })) {
                out.push_str(&line);
                out.push('\n');
                n += 1;
            }
        }
    }
    if n == 0 {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "no process command lines found on selected hosts".into(),
        ));
    }
    let _ = fs::create_dir_all(".dev");
    let path = PathBuf::from(format!(".dev/anomark-train-input-{}.jsonl", Uuid::new_v4()));
    fs::write(&path, out).map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(path)
}

async fn collect_host_commands(
    state: &AppState,
    host: &HostRecord,
    inventory: &str,
) -> Result<Vec<String>, ApiError> {
    let mut cmds = Vec::new();
    let process_rows = process_obs_for_inventory(state, host, inventory).await?;
    if !process_rows.is_empty() {
        for o in process_rows {
            if let Observation::Process(p) = o.data {
                let raw = process_obs_to_raw(&host.display_name, &p, None);
                let cmd = cmdline_from_raw(&raw);
                if !cmd.is_empty() {
                    cmds.push(cmd);
                }
            }
        }
        return Ok(cmds);
    }
    // Virtual hosts: fall back to current ingest JSONL only for latest inventory.
    if host.agent_kind.eq_ignore_ascii_case("virtual") && is_latest_inventory(inventory) {
        for row in load_virtual_jsonl(host) {
            let cmd = cmdline_from_raw(&row);
            if !cmd.is_empty() {
                cmds.push(cmd);
            }
        }
    }
    Ok(cmds)
}

fn is_latest_inventory(inventory: &str) -> bool {
    matches!(
        inventory.trim().to_ascii_lowercase().as_str(),
        "" | "latest" | "current" | "newest" | "1" | "0"
    )
}

fn inventory_index0(inventory: &str) -> usize {
    let key = inventory.trim().to_ascii_lowercase();
    match key.as_str() {
        "" | "latest" | "current" | "newest" => 0,
        "previous" | "prev" | "prior" => 1,
        other => other
            .parse::<usize>()
            .map(|n| if n == 0 { 0 } else { n.saturating_sub(1) })
            .unwrap_or(0),
    }
}

fn cmdline_from_raw(raw: &RawLogEntry) -> String {
    let cmd = if raw.args.is_empty() {
        if raw.path.is_empty() {
            raw.name.clone()
        } else {
            raw.path.clone()
        }
    } else if raw.path.is_empty() {
        format!("{} {}", raw.name, raw.args)
    } else {
        format!("{} {}", raw.path, raw.args)
    };
    cmd.trim().to_string()
}

async fn process_obs_for_inventory(
    state: &AppState,
    host: &HostRecord,
    inventory: &str,
) -> Result<Vec<rustmite_store::StoredObservation>, ApiError> {
    let rows = state
        .store
        .list_observations(Some(host.id), 50_000)
        .await?;
    let process: Vec<_> = rows
        .into_iter()
        .filter(|o| o.kind == "process")
        .collect();
    if process.is_empty() {
        return Ok(Vec::new());
    }
    let mut seen = HashSet::new();
    let mut ordered: Vec<Uuid> = Vec::new();
    for o in process.iter().rev() {
        if seen.insert(o.scan_id.0) {
            ordered.push(o.scan_id.0);
        }
    }
    let idx = inventory_index0(inventory);
    let Some(scan_id) = ordered
        .get(idx)
        .copied()
        .or_else(|| ordered.last().copied())
    else {
        return Ok(Vec::new());
    };
    Ok(process
        .into_iter()
        .filter(|o| o.scan_id.0 == scan_id)
        .collect())
}

pub async fn delete_model(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let store = state.sift_platform.get()?;
    store
        .delete_anomark_training(&id)
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e.to_string()))?;
    if let Some(ch) = state.clickhouse.as_ref() {
        crate::platform_ch::delete_anomark_training_ch(ch, &id).await;
        crate::platform_ch::sync_sift_db(ch).await;
    }
    Ok(Json(serde_json::json!({ "ok": true, "deleted": id })))
}

#[derive(Debug, Deserialize)]
pub struct FavoriteBody {
    pub favorite: bool,
}

pub async fn favorite_model(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<FavoriteBody>,
) -> Result<impl IntoResponse, ApiError> {
    let store = state.sift_platform.get()?;
    store
        .set_anomark_training_favorite(&id, body.favorite)
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e.to_string()))?;
    if let Some(ch) = state.clickhouse.as_ref() {
        let _ = crate::platform_ch::sync_anomark_training(ch, &store, &id).await;
        crate::platform_ch::sync_sift_db(ch).await;
    }
    Ok(Json(serde_json::json!({ "ok": true, "id": id, "favorite": body.favorite })))
}

pub async fn inspect_model(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let store = state.sift_platform.get()?;
    let insp = store
        .inspect_anomark_training_model(&id)
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok(Json(insp))
}

#[derive(Debug, Deserialize)]
pub struct ScoreBody {
    pub command: String,
    #[serde(default)]
    pub machine: Option<String>,
    #[serde(default)]
    pub model_id: Option<String>,
    #[serde(default = "default_suspect")]
    pub suspect_percent: f64,
}

pub async fn score_command(
    State(state): State<AppState>,
    Json(body): Json<ScoreBody>,
) -> Result<impl IntoResponse, ApiError> {
    let store = state.sift_platform.get()?;
    let score = store
        .score_anomark_command(
            &body.command,
            body.machine.as_deref(),
            body.model_id.as_deref(),
            body.suspect_percent,
        )
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok(Json(score))
}

#[derive(Debug, Deserialize)]
pub struct ApplyBody {
    /// Model (training) id; omit to use platform default model_path.
    #[serde(default)]
    pub model_id: Option<String>,
    /// Hosts to score (required, at least one).
    pub host_ids: Vec<Uuid>,
    /// Which finished scan inventory to score: `1`/`latest`, `2`/`previous`, …
    #[serde(default = "default_inventory")]
    pub inventory: String,
    #[serde(default = "default_suspect")]
    pub suspect_percent: f64,
    #[serde(default = "default_max_cmds")]
    pub max_commands: usize,
    /// Also sync + run AnomarkOnly fleet detection (needs ≥1 host with data).
    #[serde(default)]
    pub fleet_run: bool,
}

#[derive(Debug, Serialize)]
pub struct ApplyHostResult {
    pub host_id: Uuid,
    pub display_name: String,
    pub scored: usize,
    pub suspects: usize,
    pub sample: Vec<serde_json::Value>,
}

pub async fn apply_to_hosts(
    State(state): State<AppState>,
    Json(body): Json<ApplyBody>,
) -> Result<impl IntoResponse, ApiError> {
    if body.host_ids.is_empty() {
        return Err(ApiError(StatusCode::BAD_REQUEST, "host_ids required".into()));
    }
    let result = apply_anomark_inner(&state, &body).await?;
    Ok(Json(result))
}

async fn apply_anomark_inner(
    state: &AppState,
    body: &ApplyBody,
) -> Result<serde_json::Value, ApiError> {
    let platform = state.sift_platform.get()?;
    let model_id = body
        .model_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let mut host_results = Vec::new();
    let mut total_suspects = 0usize;
    let mut total_scored = 0usize;

    for id in &body.host_ids {
        let host = state.store.get_host(HostId(*id)).await?;
        let cmds = collect_host_commands(state, &host, body.inventory.trim()).await?;
        let mut suspects = 0usize;
        let mut scored = 0usize;
        let mut sample = Vec::new();
        for cmd in cmds.into_iter().take(body.max_commands.max(1)) {
            match platform.score_anomark_command(
                &cmd,
                Some(&host.display_name),
                model_id,
                body.suspect_percent,
            ) {
                Ok(score) => {
                    scored += 1;
                    if score.is_suspect {
                        suspects += 1;
                        if sample.len() < 25 {
                            sample.push(serde_json::json!({
                                "command": cmd,
                                "log_likelihood": score.log_likelihood,
                                "threshold": score.suspect_threshold_ln,
                                "margin_ln": score.margin_ln,
                            }));
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, host = %host.display_name, "anomark score failed");
                }
            }
        }
        total_scored += scored;
        total_suspects += suspects;
        let _ = state
            .store
            .push_activity(ActivityEvent {
                id: Uuid::new_v4(),
                ts: crate::sys_metrics::utc_now_rfc3339(),
                level: if suspects > 0 { "warn" } else { "info" }.into(),
                kind: "anomark.apply".into(),
                message: format!(
                    "AnoMark on {}: {suspects}/{scored} suspect commands",
                    host.display_name
                ),
                scan_id: None,
                host_id: Some(host.id),
                node_id: None,
                detail: Some(serde_json::json!({
                    "model_id": model_id,
                    "suspects": suspects,
                    "scored": scored,
                })),
            })
            .await;
        host_results.push(ApplyHostResult {
            host_id: host.id.0,
            display_name: host.display_name,
            scored,
            suspects,
            sample,
        });
    }

    let mut fleet_run = None;
    if body.fleet_run && body.host_ids.len() >= 1 {
        match sync_and_run_anomark(
            state,
            &body.host_ids,
            model_id,
            body.suspect_percent,
            body.inventory.trim(),
        )
        .await
        {
            Ok(v) => fleet_run = Some(v),
            Err(e) => {
                warn!(error = %e.1, "anomark fleet run skipped");
            }
        }
    }

    Ok(serde_json::json!({
        "ok": true,
        "model_id": model_id,
        "inventory": body.inventory,
        "suspect_percent": body.suspect_percent,
        "total_scored": total_scored,
        "total_suspects": total_suspects,
        "hosts": host_results,
        "fleet_run": fleet_run,
    }))
}

async fn sync_and_run_anomark(
    state: &AppState,
    host_ids: &[Uuid],
    model_id: Option<&str>,
    suspect_percent: f64,
    inventory: &str,
) -> Result<serde_json::Value, ApiError> {
    // Reuse sync logic via a minimal NDJSON export for these hosts, then AnomarkOnly run.
    let platform = state.sift_platform.get()?;
    let mut ndjson = String::new();
    let mut hosts_used = 0usize;
    for id in host_ids {
        let host = state.store.get_host(HostId(*id)).await?;
        let mut got = false;
        for cmd in collect_host_commands(state, &host, inventory).await? {
            let line = serde_json::json!({
                "machine_id": host.display_name,
                "pid": 0,
                "ppid": 0,
                "name": cmd.split_whitespace().next().unwrap_or("cmd"),
                "uid": 0,
                "path": "",
                "args": cmd,
            });
            if let Ok(s) = serde_json::to_string(&line) {
                ndjson.push_str(&s);
                ndjson.push('\n');
                got = true;
            }
        }
        if got {
            hosts_used += 1;
        }
    }
    if hosts_used == 0 {
        return Err(ApiError(StatusCode::BAD_REQUEST, "no commands to sync".into()));
    }
    let _ = fs::create_dir_all(".dev/sift-platform/data");
    let path = PathBuf::from(format!(
        ".dev/sift-platform/data/anomark-apply-{}.jsonl",
        Uuid::new_v4()
    ));
    fs::write(&path, &ndjson)
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let (dataset, _) = platform
        .create_dataset(CreateDatasetRequest {
            name: format!("anomark-apply-{}", Uuid::new_v4()),
            source_path: path.display().to_string(),
            kind: DatasetKind::Process,
            tags: vec!["anomark-apply".into()],
            schema_profile: "osquery-5.22.1".into(),
            ingest_default_machine_id: None,
        })
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let run_req = CreateRunRequest {
        dataset_ids: vec![dataset.id.clone()],
        baseline_tags: vec![],
        candidate_tags: vec![],
        enable_anomark: true,
        anomark_train_id: model_id.map(|s| s.to_string()),
        anomark_suspect_percent: suspect_percent,
        detection_config_id: None,
        detection_focus: Default::default(),
        detector_mode: RunDetectorMode::AnomarkOnly,
        enable_sigma_stable: false,
    };
    let run = platform
        .run_detection(run_req)
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok(serde_json::json!({ "dataset_id": dataset.id, "run": run }))
}

pub async fn get_auto(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.anomark_auto.get())
}

pub async fn put_auto(
    State(state): State<AppState>,
    Json(body): Json<AnoMarkAutoConfig>,
) -> Result<impl IntoResponse, ApiError> {
    let cfg = state
        .anomark_auto
        .set(body)
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e))?;
    if let Some(ch) = state.clickhouse.as_ref() {
        if let Ok(v) = serde_json::to_value(&cfg) {
            crate::platform_ch::sync_anomark_auto(ch, &v).await;
        }
    }
    Ok(Json(cfg))
}

/// Fire-and-forget AnoMark apply after a successful scan (if auto-config enabled).
pub fn spawn_post_scan_anomark(state: AppState, host_id: Uuid, check_set: &str) {
    let cfg = state.anomark_auto.get();
    if !cfg.enabled {
        return;
    }
    if !cfg.check_sets.is_empty()
        && !cfg
            .check_sets
            .iter()
            .any(|s| s.eq_ignore_ascii_case(check_set))
    {
        return;
    }
    tokio::spawn(async move {
        let host = match state.store.get_host(HostId(host_id)).await {
            Ok(h) => h,
            Err(e) => {
                warn!(host_id = %host_id, error = %e, "post-scan AnoMark host lookup failed");
                return;
            }
        };
        if !auto_host_in_scope(&cfg, &host) {
            return;
        }
        let body = ApplyBody {
            model_id: cfg.model_id.clone(),
            host_ids: vec![host_id],
            inventory: "1".into(),
            suspect_percent: cfg.suspect_percent,
            max_commands: cfg.max_commands,
            fleet_run: false,
        };
        match apply_anomark_inner(&state, &body).await {
            Ok(v) => {
                let suspects = v
                    .get("total_suspects")
                    .and_then(|x| x.as_u64())
                    .unwrap_or(0);
                info!(
                    host_id = %host_id,
                    suspects,
                    "post-scan AnoMark complete"
                );
            }
            Err(e) => {
                warn!(host_id = %host_id, error = %e.1, "post-scan AnoMark failed");
            }
        }
    });
}

fn auto_host_in_scope(cfg: &AnoMarkAutoConfig, host: &HostRecord) -> bool {
    if !cfg.host_ids.is_empty() && !cfg.host_ids.iter().any(|id| *id == host.id.0) {
        return false;
    }
    if let Some(kind) = cfg.agent_kind.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        if !host.agent_kind.eq_ignore_ascii_case(kind) {
            return false;
        }
    }
    if !cfg.labels.is_empty()
        && !cfg
            .labels
            .iter()
            .all(|(k, v)| host.labels.get(k).map(|x| x == v).unwrap_or(false))
    {
        return false;
    }
    if !cfg.tags.is_empty() && !host_matches_tags(host, &cfg.tags) {
        return false;
    }
    true
}

fn host_matches_tags(h: &HostRecord, tags: &[String]) -> bool {
    if tags.is_empty() {
        return true;
    }
    tags.iter().all(|want| {
        let want = want.trim().to_ascii_lowercase();
        if want.is_empty() {
            return true;
        }
        h.labels.iter().any(|(k, v)| {
            let k = k.to_ascii_lowercase();
            let v = v.to_ascii_lowercase();
            if k == "tags" || k == "tag" {
                v.split(|c: char| c == ',' || c == ';' || c.is_whitespace())
                    .any(|t| t.trim() == want)
            } else {
                v == want || k == want || format!("{k}:{v}") == want
            }
        })
    })
}
