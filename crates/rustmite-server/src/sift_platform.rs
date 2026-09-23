//! IronSift platform APIs — datasets, AnoMark, honeycomb (vendored PlatformStore).
//! Sigma/sigmazero is not used; RustMite rules cover detections.

use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use rustmite_proto::Observation;
use rustmite_sift::{
    process_obs_to_raw, AnoMarkSettings, CreateDatasetRequest, CreateDetectionConfigRequest,
    CreateRunRequest, DatasetKind, DetectionConfig, PlatformStore, SelectDetectionConfigRequest,
    UpdateDetectionConfigRequest,
};
use rustmite_store::Store;
use serde::Deserialize;
use tracing::info;
use uuid::Uuid;

use crate::routes::{ApiError, AppState};
use crate::sift_api::{ensure_sift_dirs, load_virtual_files_jsonl, load_virtual_jsonl};

fn platform_db_path() -> PathBuf {
    PathBuf::from(".dev/sift-platform/db.json")
}

fn platform_data_dir() -> PathBuf {
    PathBuf::from(".dev/sift-platform/data")
}

/// Shared platform store (IronSift SQLite + db.json).
#[derive(Clone, Default)]
pub struct SiftPlatform(Arc<Mutex<Option<PlatformStore>>>);

impl SiftPlatform {
    pub fn get(&self) -> Result<PlatformStore, ApiError> {
        let mut g = self
            .0
            .lock()
            .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "platform lock".into()))?;
        if g.is_none() {
            ensure_sift_dirs();
            let _ = fs::create_dir_all(platform_data_dir());
            let store = PlatformStore::load_or_create(
                platform_db_path()
                    .to_str()
                    .unwrap_or(".dev/sift-platform/db.json"),
            )
            .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            *g = Some(store);
        }
        Ok(g.as_ref().unwrap().clone())
    }

    /// Load platform store, restoring db.json / AnoMark models from ClickHouse when missing.
    pub async fn get_restored(&self, state: &AppState) -> Result<PlatformStore, ApiError> {
        if let Some(ch) = state.clickhouse.as_ref() {
            let _ = crate::platform_ch::restore_sift_db(ch).await;
        }
        let store = self.get()?;
        if let Some(ch) = state.clickhouse.as_ref() {
            let _ = crate::platform_ch::restore_anomark_trainings(ch, &store).await;
        }
        Ok(store)
    }
}

pub async fn platform_health(State(state): State<AppState>) -> impl IntoResponse {
    match state.sift_platform.get() {
        Ok(store) => Json(serde_json::json!({
            "ok": true,
            "db": store.db_json_path(),
            "events": store.events_sqlite_path(),
            "datasets": store.list_datasets().len(),
            "runs": store.list_runs().len(),
        })),
        Err(e) => Json(serde_json::json!({ "ok": false, "error": e.1 })),
    }
}

pub async fn list_datasets(State(state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    let store = state.sift_platform.get()?;
    Ok(Json(store.list_datasets()))
}

pub async fn list_platform_runs(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let store = state.sift_platform.get()?;
    Ok(Json(store.list_runs()))
}

pub async fn get_platform_run(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let store = state.sift_platform.get()?;
    let run = store
        .get_run(&id)
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, format!("run {id} not found")))?;
    Ok(Json(run))
}

pub async fn get_run_detections(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let store = state.sift_platform.get()?;
    let findings = store.findings_for_run_detections_api(&id).ok_or_else(|| {
        ApiError(StatusCode::NOT_FOUND, format!("run {id} not found"))
    })?;
    Ok(Json(findings))
}

#[derive(Debug, Deserialize)]
pub struct HoneycombQuery {
    pub run_id: String,
    #[serde(default)]
    pub min_score: Option<f64>,
    #[serde(default)]
    pub severity: Option<String>,
}

pub async fn get_honeycomb(
    State(state): State<AppState>,
    Query(q): Query<HoneycombQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let store = state.sift_platform.get()?;
    let cells = if q.min_score.is_some() || q.severity.is_some() {
        store.honeycomb_for_run_filtered(&q.run_id, q.min_score, q.severity.as_deref())
    } else {
        store.honeycomb_for_run(&q.run_id)
    }
    .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, format!("run {} not found", q.run_id)))?;
    Ok(Json(cells))
}

pub async fn anomark_availability(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let store = state.sift_platform.get()?;
    Ok(Json(store.anomark_availability()))
}

pub async fn get_anomark_config(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let store = state.sift_platform.get()?;
    Ok(Json(store.get_anomark_settings()))
}

pub async fn set_anomark_config(
    State(state): State<AppState>,
    Json(body): Json<AnoMarkSettings>,
) -> Result<impl IntoResponse, ApiError> {
    let store = state.sift_platform.get()?;
    let cfg = store
        .set_anomark_settings(body)
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok(Json(cfg))
}

pub async fn create_platform_run(
    State(state): State<AppState>,
    Json(body): Json<CreateRunRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let store = state.sift_platform.get()?;
    let run = store
        .run_detection(body)
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok(Json(run))
}

#[derive(Debug, Deserialize)]
pub struct SyncFleetBody {
    #[serde(default)]
    pub host_ids: Vec<Uuid>,
    #[serde(default)]
    pub name: Option<String>,
    /// Also create a detection run after sync.
    #[serde(default)]
    pub run: bool,
    #[serde(default)]
    pub enable_anomark: bool,
}

/// Export latest process (+ file) rows from all hosts into an IronSift dataset.
pub async fn sync_fleet_dataset(
    State(state): State<AppState>,
    Json(body): Json<SyncFleetBody>,
) -> Result<impl IntoResponse, ApiError> {
    let store = state.sift_platform.get()?;
    let hosts = state.store.list_hosts().await?;
    let filter: Option<std::collections::HashSet<Uuid>> = if body.host_ids.is_empty() {
        None
    } else {
        Some(body.host_ids.iter().copied().collect())
    };

    let mut ndjson = String::new();
    let mut hosts_used = 0usize;
    let mut process_rows = 0usize;
    let mut file_rows = 0usize;

    for h in &hosts {
        if let Some(ref ids) = filter {
            if !ids.contains(&h.id.0) {
                continue;
            }
        }
        let machine = &h.display_name;
        let mut got = false;

        if h.agent_kind.eq_ignore_ascii_case("virtual") {
            for row in load_virtual_jsonl(h) {
                if let Ok(line) = serde_json::to_string(&row) {
                    ndjson.push_str(&line);
                    ndjson.push('\n');
                    process_rows += 1;
                    got = true;
                }
            }
            for row in load_virtual_files_jsonl(h) {
                if let Ok(line) = serde_json::to_string(&row) {
                    ndjson.push_str(&line);
                    ndjson.push('\n');
                    file_rows += 1;
                    got = true;
                }
            }
        } else {
            let rows = state
                .store
                .list_observations(Some(h.id), 50_000)
                .await
                .unwrap_or_default();
            let latest = rows.iter().rev().map(|o| o.scan_id).next();
            let Some(scan_id) = latest else {
                continue;
            };
            let obs: Vec<_> = rows
                .into_iter()
                .filter(|o| o.scan_id == scan_id)
                .map(|o| o.data)
                .collect();
            for o in &obs {
                if let Observation::Process(p) = o {
                    let raw = process_obs_to_raw(machine, p, None);
                    if let Ok(line) = serde_json::to_string(&raw) {
                        ndjson.push_str(&line);
                        ndjson.push('\n');
                        process_rows += 1;
                        got = true;
                    }
                }
            }
            let files = rustmite_sift::observations_to_file_logs(machine, &obs, None);
            for f in files {
                if let Ok(line) = serde_json::to_string(&f) {
                    ndjson.push_str(&line);
                    ndjson.push('\n');
                    file_rows += 1;
                    got = true;
                }
            }
        }
        if got {
            hosts_used += 1;
        }
    }

    if hosts_used < 2 {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            format!("need process/file data from ≥2 hosts to sync (got {hosts_used})"),
        ));
    }

    let path = platform_data_dir().join(format!("fleet-sync-{}.jsonl", Uuid::new_v4()));
    fs::write(&path, &ndjson)
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let kind = if process_rows > 0 && file_rows > 0 {
        DatasetKind::Mixed
    } else if file_rows > 0 {
        DatasetKind::File
    } else {
        DatasetKind::Process
    };

    let name = body
        .name
        .unwrap_or_else(|| format!("rustmite-fleet-{}", chrono_like_stamp()));
    let (dataset, summary) = store
        .create_dataset(CreateDatasetRequest {
            name,
            source_path: path.display().to_string(),
            kind,
            tags: vec!["rustmite-fleet".into(), "auto-sync".into()],
            schema_profile: "osquery-5.22.1".into(),
            ingest_default_machine_id: None,
        })
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    info!(
        dataset_id = %dataset.id,
        hosts_used,
        process_rows,
        file_rows,
        "fleet synced into IronSift platform dataset"
    );

    let mut run = None;
    if body.run {
        let run_req = make_run_request(dataset.id.clone(), body.enable_anomark);
        run = Some(
            store
                .run_detection(run_req)
                .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e.to_string()))?,
        );
    }

    Ok(Json(serde_json::json!({
        "dataset": dataset,
        "ingest": summary,
        "hosts_used": hosts_used,
        "process_rows": process_rows,
        "file_rows": file_rows,
        "run": run,
    })))
}

async fn maybe_sync_sift_db(state: &AppState) {
    if let Some(ch) = state.clickhouse.as_ref() {
        crate::platform_ch::sync_sift_db(ch).await;
    }
}

/// Active detection config + named profiles (IronSift-compatible).
pub async fn list_detection_configs(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let store = state.sift_platform.get_restored(&state).await?;
    let (config, profiles, selected_id) = store
        .run_config_with_profiles()
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(serde_json::json!({
        "config": config,
        "profiles": profiles,
        "selected_id": selected_id,
    })))
}

pub async fn get_detection_config(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let store = state.sift_platform.get()?;
    let (profile, config) = store
        .get_detection_config_profile_detail(&id)
        .map_err(|e| {
            let msg = e.to_string();
            let code = if msg.contains("not found") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::BAD_REQUEST
            };
            ApiError(code, msg)
        })?;
    Ok(Json(serde_json::json!({ "profile": profile, "config": config })))
}

pub async fn create_detection_config(
    State(state): State<AppState>,
    Json(body): Json<CreateDetectionConfigRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let store = state.sift_platform.get()?;
    let (id, profile) = store
        .create_detection_config_profile(body)
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e.to_string()))?;
    maybe_sync_sift_db(&state).await;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "id": id, "profile": profile })),
    ))
}

pub async fn update_detection_config(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<UpdateDetectionConfigRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let store = state.sift_platform.get()?;
    store
        .update_detection_config_profile(&id, body)
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e.to_string()))?;
    maybe_sync_sift_db(&state).await;
    Ok(Json(serde_json::json!({ "ok": true })))
}

pub async fn delete_detection_config(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let store = state.sift_platform.get()?;
    store
        .delete_detection_config_profile(&id)
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e.to_string()))?;
    maybe_sync_sift_db(&state).await;
    Ok(Json(serde_json::json!({ "ok": true })))
}

pub async fn select_detection_config(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let store = state.sift_platform.get()?;
    let req = SelectDetectionConfigRequest { id: id.clone() };
    store
        .select_detection_config_profile(&req.id)
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e.to_string()))?;
    let config = store.get_run_config();
    maybe_sync_sift_db(&state).await;
    Ok(Json(serde_json::json!({
        "ok": true,
        "selected_id": id,
        "config": config,
    })))
}

/// Update the currently selected profile in place (or set run_config if none).
pub async fn put_active_detection_config(
    State(state): State<AppState>,
    Json(body): Json<DetectionConfig>,
) -> Result<impl IntoResponse, ApiError> {
    let store = state.sift_platform.get()?;
    let cfg = store
        .set_run_config(body)
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e.to_string()))?;
    maybe_sync_sift_db(&state).await;
    Ok(Json(cfg))
}

fn chrono_like_stamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}

fn make_run_request(dataset_id: String, enable_anomark: bool) -> CreateRunRequest {
    serde_json::from_value(serde_json::json!({
        "dataset_ids": [dataset_id],
        "enable_anomark": enable_anomark,
        "enable_sigma_stable": false,
        "anomark_suspect_percent": 95.0,
    }))
    .expect("CreateRunRequest serde defaults")
}
