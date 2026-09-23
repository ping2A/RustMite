use std::net::SocketAddr;
use std::path::PathBuf;

use axum::body::Body;
use axum::extract::{Multipart, Path, Query, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::Json;
use axum::Router;
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing::warn;
use tracing_subscriber::EnvFilter;

use rustmite_sift::{
    AnoMarkSettings, AnoMarkTrainRequest, CreateDatasetRequest, CreateDetectionConfigRequest,
    CreateRunRequest, DeleteDatasetEventsRequest, DetectionConfig, DATASET_INSPECT_MAX_SAMPLE,
    PlatformStore, ReasonPrecedentKey, RunUserTriage, SelectDetectionConfigRequest,
    SigmaZeroCheckRequest, SigmaZeroSettings, UpdateDetectionConfigRequest,
};

const UI_HTML: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/web/index.html"));
const RUN_FINDINGS_HTML: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/web/run-findings.html"));
const RUN_FINDINGS_UI_JS: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/web/run-findings-ui.js"));
const LOGO_PNG: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/.github/logo.png"));

#[derive(Clone)]
struct AppState {
    store: PlatformStore,
}

#[derive(Debug, Serialize)]
struct ApiError {
    error: String,
}

#[derive(Debug, Deserialize)]
struct TagRequest {
    tags: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct PutRunTriageRequest {
    user_triage: RunUserTriage,
}

#[derive(Debug, Deserialize)]
struct PutAnomarkTrainFavoriteRequest {
    favorite: bool,
}

#[derive(Debug, Deserialize)]
struct HoneycombQuery {
    run_id: String,
    min_score: Option<f64>,
    severity: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UploadQuery {
    name: Option<String>,
    tags: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DatasetInspectQuery {
    #[serde(default)]
    process_limit: Option<u32>,
    #[serde(default)]
    file_limit: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct AppendTestBody {
    ndjson: String,
}

#[derive(Debug, Deserialize)]
struct ScoreAnomarkCommandBody {
    command: String,
    /// Hostname / machine_id prefix — same rule as detection runs (`"{machine} {command}"` scored).
    #[serde(default)]
    machine_name: Option<String>,
    #[serde(default)]
    train_id: Option<String>,
    /// Percent of ln(prior) for threshold (55–99.999); lower = flag more commands. Default 95 (matches fleet scoring).
    #[serde(default = "default_anomark_suspect_percent")]
    suspect_percent: f64,
}

fn default_anomark_suspect_percent() -> f64 {
    95.0
}

fn clamp_inspect_limit(x: Option<u32>) -> u32 {
    let d = x.unwrap_or(200);
    d.clamp(1, DATASET_INSPECT_MAX_SAMPLE)
}

/// Default `RUST_LOG` when unset: info for app + HTTP request/response tracing.
fn init_logging() {
    let fallback: EnvFilter = "info,tower_http=info,tower=info,axum::rejection=warn"
        .parse()
        .expect("built-in tracing filter");
    let filter = match std::env::var("RUST_LOG") {
        Ok(s) if !s.trim().is_empty() => match s.parse::<EnvFilter>() {
            Ok(f) => f,
            Err(e) => {
                eprintln!("IronSift: invalid RUST_LOG ({e}); using built-in default");
                fallback
            }
        },
        _ => fallback,
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .init();
}

fn log_platform_storage(store: &PlatformStore) {
    println!("IronSift platform storage:");
    let cwd = std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|e| format!("(unavailable: {})", e));
    println!("  working directory: {}", cwd);

    let db = store.db_json_path();
    let sql = store.events_sqlite_path();
    println!("  platform metadata (JSON): {}", db);
    println!("  ingested events (SQLite): {}", sql);

    if let Ok(abs) = std::path::Path::new(db).canonicalize() {
        println!("  metadata (absolute): {}", abs.display());
    }
    if let Ok(abs) = std::path::Path::new(sql).canonicalize() {
        println!("  SQLite (absolute): {}", abs.display());
    }

    if let Some(parent) = std::path::Path::new(db).parent() {
        let trains = parent.join("anomark-trains");
        println!("  AnoMark trainings dir: {}/", trains.display());
        if let Ok(abs) = trains.canonicalize() {
            println!("  AnoMark trainings dir (absolute): {}/", abs.display());
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_logging();
    let store = PlatformStore::load_or_create(".ironsift-platform/db.json")?;
    log_platform_storage(&store);
    let state = AppState { store };

    let app = Router::new()
        .route("/", get(ui))
        .route("/run/:id", get(run_findings_page))
        .route("/run-findings-ui.js", get(run_findings_ui_js))
        .route("/logo.png", get(logo_png))
        .route("/api/health", get(health))
        .route("/api/datasets", get(list_datasets).post(create_dataset))
        .route("/api/datasets/purge", post(purge_datasets))
        .route("/api/datasets/:id/inspect", get(inspect_dataset))
        .route("/api/datasets/:id/append-test-data", post(append_dataset_test_data))
        .route("/api/datasets/:id/delete-events", post(delete_dataset_events))
        .route("/api/datasets/upload", post(upload_dataset))
        .route("/api/datasets/:id/tags", post(add_tags))
        .route("/api/datasets/:id/tags/remove", post(remove_tags))
        .route("/api/runs/purge", post(purge_runs))
        .route("/api/runs", get(list_runs).post(create_run))
        .route(
            "/api/runs/:id",
            get(get_run).delete(delete_run),
        )
        .route("/api/runs/:id/detections", get(get_run_detections))
        .route("/api/runs/:id/triage-precedent", get(get_run_triage_precedent))
        .route(
            "/api/runs/:id/triage-precedent/ignore",
            post(post_run_triage_precedent_ignore),
        )
        .route(
            "/api/runs/:id/triage-precedent/unignore",
            post(post_run_triage_precedent_unignore),
        )
        .route("/api/runs/:id/triage", put(put_run_triage))
        .route("/api/fleet/honeycomb", get(get_honeycomb))
        .route("/api/fleet/triage-precedent", get(get_fleet_triage_precedent))
        .route(
            "/api/fleet/triage-precedent/drop",
            post(post_fleet_triage_precedent_drop),
        )
        .route(
            "/api/fleet/triage-precedent/undrop",
            post(post_fleet_triage_precedent_undrop),
        )
        .route(
            "/api/fleet/triage-precedent/delete",
            post(post_fleet_triage_precedent_delete),
        )
        .route("/api/anomark/config", get(get_anomark_config).post(set_anomark_config))
        .route("/api/anomark/availability", get(get_anomark_availability))
        .route("/api/anomark/inspect", get(inspect_anomark_configured_model))
        .route("/api/anomark/train", post(train_anomark))
        .route("/api/anomark/trains", get(list_anomark_trains))
        .route("/api/anomark/trains/purge", post(purge_anomark_trains))
        .route("/api/anomark/score-command", post(score_anomark_command))
        .route(
            "/api/anomark/trains/:id",
            delete(delete_anomark_train),
        )
        .route(
            "/api/anomark/trains/:id/favorite",
            put(put_anomark_train_favorite),
        )
        .route(
            "/api/anomark/trains/:id/inspect",
            get(inspect_anomark_training_model),
        )
        .route(
            "/api/anomark/trains/:id/model",
            get(download_anomark_model),
        )
        .route(
            "/api/anomark/trains/:id/training-data",
            get(download_anomark_training_data),
        )
        .route("/api/run-config", get(get_run_config).post(set_run_config))
        .route(
            "/api/detection-configs",
            get(list_detection_configs).post(create_detection_config),
        )
        .route("/api/detection-configs/select", post(select_detection_config))
        .route(
            "/api/detection-configs/:id",
            get(get_detection_config_detail)
                .put(update_detection_config)
                .delete(delete_detection_config),
        )
        .route("/api/sigma-zero/config", get(get_sigma_config).post(set_sigma_config))
        .route("/api/sigma-zero/rule-templates", get(get_sigma_rule_templates))
        .route("/api/sigma-zero/stable-rules", get(list_sigma_stable_rules))
        .route("/api/sigma-zero/check", post(check_sigma_zero))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr: SocketAddr = "0.0.0.0:8080".parse()?;
    println!("IronSift server listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn ui() -> Html<&'static str> {
    Html(UI_HTML)
}

/// Standalone shareable page for one run’s findings (`GET /run/{id}`).
async fn run_findings_page(Path(_run_id): Path<String>) -> Html<&'static str> {
    Html(RUN_FINDINGS_HTML)
}

async fn run_findings_ui_js() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "application/javascript; charset=utf-8")],
        RUN_FINDINGS_UI_JS,
    )
}

async fn logo_png() -> Response {
    Response::builder()
        .header(CONTENT_TYPE, "image/png")
        .header(CACHE_CONTROL, "public, max-age=86400")
        .body(Body::from(LOGO_PNG))
        .unwrap()
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status":"ok"}))
}

async fn list_datasets(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "datasets": state.store.list_datasets() }))
}

async fn list_runs(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "runs": state.store.list_runs() }))
}

async fn create_dataset(
    State(state): State<AppState>,
    Json(req): Json<CreateDatasetRequest>,
) -> impl IntoResponse {
    match state.store.create_dataset(req) {
        Ok((ds, ingest_summary)) => (
            StatusCode::CREATED,
            Json(serde_json::json!({ "dataset": ds, "ingest_summary": ingest_summary })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::to_value(ApiError {
                error: e.to_string(),
            }).unwrap_or_default()),
        )
            .into_response(),
    }
}

async fn add_tags(
    Path(id): Path<String>,
    State(state): State<AppState>,
    Json(req): Json<TagRequest>,
) -> impl IntoResponse {
    match state.store.add_dataset_tags(&id, &req.tags) {
        Ok((ds, ingest_summary)) => (
            StatusCode::OK,
            Json(serde_json::json!({ "dataset": ds, "ingest_summary": ingest_summary })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::to_value(ApiError {
                error: e.to_string(),
            }).unwrap_or_default()),
        )
            .into_response(),
    }
}

async fn remove_tags(
    Path(id): Path<String>,
    State(state): State<AppState>,
    Json(req): Json<TagRequest>,
) -> impl IntoResponse {
    match state.store.remove_dataset_tags(&id, &req.tags) {
        Ok((ds, ingest_summary)) => (
            StatusCode::OK,
            Json(serde_json::json!({ "dataset": ds, "ingest_summary": ingest_summary })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::to_value(ApiError {
                error: e.to_string(),
            }).unwrap_or_default()),
        )
            .into_response(),
    }
}

async fn inspect_dataset(
    Path(id): Path<String>,
    Query(q): Query<DatasetInspectQuery>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let pl = clamp_inspect_limit(q.process_limit);
    let fl = clamp_inspect_limit(q.file_limit);
    match state.store.inspect_dataset(&id, pl, fl) {
        Ok(info) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "inspection": info,
                "inspect_limits": { "process_limit": pl, "file_limit": fl, "max_per_kind": DATASET_INSPECT_MAX_SAMPLE }
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::to_value(ApiError {
                error: e.to_string(),
            }).unwrap_or_default()),
        )
            .into_response(),
    }
}

async fn append_dataset_test_data(
    Path(id): Path<String>,
    State(state): State<AppState>,
    Json(body): Json<AppendTestBody>,
) -> impl IntoResponse {
    match state.store.append_dataset_test_ndjson(&id, &body.ndjson) {
        Ok(summary) => (
            StatusCode::OK,
            Json(serde_json::json!({ "summary": summary })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::to_value(ApiError {
                error: e.to_string(),
            })
            .unwrap_or_default()),
        )
            .into_response(),
    }
}

async fn delete_dataset_events(
    Path(id): Path<String>,
    State(state): State<AppState>,
    Json(body): Json<DeleteDatasetEventsRequest>,
) -> impl IntoResponse {
    match state.store.delete_dataset_events(&id, body) {
        Ok((deleted_process, deleted_file)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "deleted_process": deleted_process,
                "deleted_file": deleted_file,
            })),
        )
            .into_response(),
        Err(e) => {
            let msg = e.to_string();
            let status = if msg.contains("not found") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::BAD_REQUEST
            };
            (
                status,
                Json(serde_json::to_value(ApiError { error: msg }).unwrap_or_default()),
            )
                .into_response()
        }
    }
}

async fn purge_datasets(State(state): State<AppState>) -> impl IntoResponse {
    match state.store.delete_all_datasets() {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "status": "ok" }))).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::to_value(ApiError {
                error: e.to_string(),
            }).unwrap_or_default()),
        )
            .into_response(),
    }
}

async fn create_run(
    State(state): State<AppState>,
    Json(req): Json<CreateRunRequest>,
) -> impl IntoResponse {
    let dataset_count = req.dataset_ids.len();
    let enable_anomark = req.enable_anomark;
    let enable_sigma_stable = req.enable_sigma_stable;
    let detection_focus = req.detection_focus;
    let detector_mode = req.detector_mode;
    match state.store.run_detection(req) {
        Ok(run) => {
            info!(
                run_id = %run.id,
                datasets = dataset_count,
                enable_anomark = enable_anomark,
                enable_sigma_stable = enable_sigma_stable,
                ?detection_focus,
                ?detector_mode,
                "POST /api/runs — detection run completed"
            );
            (StatusCode::CREATED, Json(serde_json::json!({ "run": run }))).into_response()
        }
        Err(e) => {
            warn!(error = %e, "POST /api/runs — failed");
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::to_value(ApiError {
                    error: e.to_string(),
                }).unwrap_or_default()),
            )
                .into_response()
        }
    }
}

async fn delete_run(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match state.store.delete_run(&id) {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "status": "ok" }))).into_response(),
        Err(e) => {
            let msg = e.to_string();
            let code = if msg.contains("not found") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::BAD_REQUEST
            };
            (
                code,
                Json(serde_json::to_value(ApiError { error: msg }).unwrap_or_default()),
            )
                .into_response()
        }
    }
}

async fn purge_runs(State(state): State<AppState>) -> impl IntoResponse {
    match state.store.delete_all_runs() {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "status": "ok" }))).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::to_value(ApiError {
                error: e.to_string(),
            })
            .unwrap_or_default()),
        )
            .into_response(),
    }
}

async fn get_anomark_config(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "config": state.store.get_anomark_settings() }))
}

async fn get_anomark_availability(State(state): State<AppState>) -> Json<serde_json::Value> {
    let a = state.store.anomark_availability();
    Json(serde_json::json!({ "availability": a }))
}

async fn set_anomark_config(
    State(state): State<AppState>,
    Json(req): Json<AnoMarkSettings>,
) -> impl IntoResponse {
    match state.store.set_anomark_settings(req) {
        Ok(cfg) => (StatusCode::OK, Json(serde_json::json!({ "config": cfg }))).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::to_value(ApiError {
                error: e.to_string(),
            }).unwrap_or_default()),
        )
            .into_response(),
    }
}

async fn train_anomark(
    State(state): State<AppState>,
    Json(req): Json<AnoMarkTrainRequest>,
) -> impl IntoResponse {
    match state.store.train_anomark(req) {
        Ok(result) => (StatusCode::OK, Json(serde_json::json!({ "result": result }))).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::to_value(ApiError {
                error: e.to_string(),
            }).unwrap_or_default()),
        )
            .into_response(),
    }
}

async fn list_anomark_trains(State(state): State<AppState>) -> Json<serde_json::Value> {
    let trainings = state.store.list_anomark_trainings_for_display();
    Json(serde_json::json!({ "trainings": trainings }))
}

async fn put_anomark_train_favorite(
    Path(id): Path<String>,
    State(state): State<AppState>,
    Json(body): Json<PutAnomarkTrainFavoriteRequest>,
) -> impl IntoResponse {
    match state
        .store
        .set_anomark_training_favorite(&id, body.favorite)
    {
        Ok(()) => {
            info!(
                target: "rustmite_sift::anomark",
                train_id = %id,
                favorite = body.favorite,
                "AnoMark training favorite updated"
            );
            (StatusCode::OK, Json(serde_json::json!({ "status": "ok" }))).into_response()
        }
        Err(e) => {
            let msg = e.to_string();
            warn!(
                target: "rustmite_sift::anomark",
                train_id = %id,
                error = %msg,
                "AnoMark training favorite update failed"
            );
            let code = if msg.contains("not found") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::BAD_REQUEST
            };
            (
                code,
                Json(serde_json::to_value(ApiError { error: msg }).unwrap_or_default()),
            )
                .into_response()
        }
    }
}

async fn delete_anomark_train(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match state.store.delete_anomark_training(&id) {
        Ok(()) => {
            info!(
                target: "rustmite_sift::anomark",
                train_id = %id,
                "AnoMark training deleted"
            );
            (StatusCode::OK, Json(serde_json::json!({ "status": "ok" }))).into_response()
        }
        Err(e) => {
            let msg = e.to_string();
            warn!(
                target: "rustmite_sift::anomark",
                train_id = %id,
                error = %msg,
                "AnoMark training delete failed"
            );
            let code = if msg.contains("not found") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::BAD_REQUEST
            };
            (
                code,
                Json(serde_json::to_value(ApiError { error: msg }).unwrap_or_default()),
            )
                .into_response()
        }
    }
}

async fn purge_anomark_trains(State(state): State<AppState>) -> impl IntoResponse {
    match state.store.delete_all_anomark_trainings() {
        Ok(removed) => {
            info!(
                target: "rustmite_sift::anomark",
                removed,
                "AnoMark trainings purged"
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({ "status": "ok", "removed": removed })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::to_value(ApiError {
                    error: e.to_string(),
                })
                .unwrap_or_default(),
            ),
        )
            .into_response(),
    }
}

async fn score_anomark_command(
    State(state): State<AppState>,
    Json(body): Json<ScoreAnomarkCommandBody>,
) -> impl IntoResponse {
    let tid = body
        .train_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let cmd_bytes = body.command.len();
    let machine = body
        .machine_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    match state
        .store
        .score_anomark_command(&body.command, machine, tid, body.suspect_percent)
    {
        Ok(score) => {
            info!(
                target: "rustmite_sift::anomark",
                train_id = ?score.train_id,
                source = %score.source,
                cmd_bytes,
                order = score.order,
                is_suspect = score.is_suspect,
                suspect_percent_used = score.suspect_percent_used,
                margin_ln = score.margin_ln,
                log_likelihood = score.log_likelihood,
                suspect_threshold_ln = score.suspect_threshold_ln,
                model_path = %score.model_path,
                "AnoMark score-command OK"
            );
            (StatusCode::OK, Json(serde_json::json!({ "score": score }))).into_response()
        }
        Err(e) => {
            warn!(
                target: "rustmite_sift::anomark",
                requested_train_id = ?tid,
                cmd_bytes,
                error = %e,
                "AnoMark score-command failed"
            );
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::to_value(ApiError {
                    error: e.to_string(),
                })
                .unwrap_or_default()),
            )
                .into_response()
        }
    }
}

async fn inspect_anomark_configured_model(State(state): State<AppState>) -> impl IntoResponse {
    match state.store.inspect_anomark_configured_model() {
        Ok(inspection) => {
            info!(
                target: "rustmite_sift::anomark",
                model_path = %inspection.model_path,
                file_size_bytes = inspection.file_size_bytes,
                order = inspection.order,
                is_trained = inspection.is_trained,
                num_contexts = inspection.num_contexts,
                num_transitions = inspection.num_transitions,
                alphabet_len = inspection.alphabet_len,
                suspect_threshold_ln = inspection.suspect_threshold_ln,
                "AnoMark inspect configured model OK"
            );
            (StatusCode::OK, Json(serde_json::json!({ "inspection": inspection }))).into_response()
        }
        Err(e) => {
            warn!(
                target: "rustmite_sift::anomark",
                error = %e,
                "AnoMark inspect configured model failed"
            );
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::to_value(ApiError {
                    error: e.to_string(),
                })
                .unwrap_or_default()),
            )
                .into_response()
        }
    }
}

async fn inspect_anomark_training_model(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match state.store.inspect_anomark_training_model(&id) {
        Ok(inspection) => {
            info!(
                target: "rustmite_sift::anomark",
                train_id = %id,
                model_path = %inspection.model_path,
                file_size_bytes = inspection.file_size_bytes,
                order = inspection.order,
                is_trained = inspection.is_trained,
                num_contexts = inspection.num_contexts,
                suspect_threshold_ln = inspection.suspect_threshold_ln,
                "AnoMark inspect training model OK"
            );
            (StatusCode::OK, Json(serde_json::json!({ "inspection": inspection }))).into_response()
        }
        Err(e) => {
            warn!(
                target: "rustmite_sift::anomark",
                train_id = %id,
                error = %e,
                "AnoMark inspect training model failed"
            );
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::to_value(ApiError {
                    error: e.to_string(),
                })
                .unwrap_or_default()),
            )
                .into_response()
        }
    }
}

async fn download_anomark_model(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let Some(path) = state.store.anomark_train_stored_model_path(&id) else {
        return not_found("training job or model not found");
    };
    let data = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::to_value(ApiError {
                    error: e.to_string(),
                })
                .unwrap_or_default()),
            )
                .into_response();
        }
    };
    let name = format!("anomark-model-{}.bin", &id);
    file_download_response(
        &data,
        "application/octet-stream",
        &name,
    )
    .unwrap_or_else(|e| (StatusCode::INTERNAL_SERVER_ERROR, e).into_response())
}

async fn download_anomark_training_data(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let Some(path) = state.store.anomark_train_stored_training_data_path(&id) else {
        return not_found("training job or data file not found");
    };
    let data = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    serde_json::to_value(ApiError {
                        error: e.to_string(),
                    })
                    .unwrap_or_default(),
                ),
            )
                .into_response();
        }
    };
    let name = format!("anomark-training-{}.jsonl", &id);
    file_download_response(
        &data,
        "application/x-ndjson",
        &name,
    )
    .unwrap_or_else(|e| (StatusCode::INTERNAL_SERVER_ERROR, e).into_response())
}

fn not_found(msg: &str) -> axum::response::Response {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::to_value(ApiError {
            error: msg.to_string(),
        })
        .unwrap_or_default()),
    )
        .into_response()
}

fn file_download_response(
    data: &[u8],
    content_type: &str,
    filename: &str,
) -> Result<axum::response::Response, String> {
    use axum::http::header::{HeaderName, HeaderValue};

    let cd = format!(r#"attachment; filename="{}""#, filename.replace('\"', ""));
    let disp = HeaderValue::from_str(&cd).map_err(|e| e.to_string())?;
    let ty = HeaderValue::from_str(content_type).map_err(|e| e.to_string())?;
    Response::builder()
        .status(StatusCode::OK)
        .header(HeaderName::from_static("content-type"), ty)
        .header(HeaderName::from_static("content-disposition"), disp)
        .body(Body::from(data.to_vec()))
        .map_err(|e| e.to_string())
}

async fn get_run_config(State(state): State<AppState>) -> impl IntoResponse {
    match state.store.run_config_with_profiles() {
        Ok((config, profiles, selected_id)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "config": config,
                "profiles": profiles,
                "selected_id": selected_id,
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::to_value(ApiError {
                error: e.to_string(),
            })
            .unwrap_or_default()),
        )
            .into_response(),
    }
}

async fn list_detection_configs(State(state): State<AppState>) -> impl IntoResponse {
    match state.store.run_config_with_profiles() {
        Ok((config, profiles, selected_id)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "config": config,
                "profiles": profiles,
                "selected_id": selected_id,
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::to_value(ApiError {
                error: e.to_string(),
            })
            .unwrap_or_default()),
        )
            .into_response(),
    }
}

async fn get_detection_config_detail(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match state.store.get_detection_config_profile_detail(&id) {
        Ok((profile, config)) => (
            StatusCode::OK,
            Json(serde_json::json!({ "profile": profile, "config": config })),
        )
            .into_response(),
        Err(e) => {
            let msg = e.to_string();
            let status = if msg.contains("not found") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::BAD_REQUEST
            };
            (
                status,
                Json(serde_json::to_value(ApiError { error: msg }).unwrap_or_default()),
            )
                .into_response()
        }
    }
}

async fn create_detection_config(
    State(state): State<AppState>,
    Json(req): Json<CreateDetectionConfigRequest>,
) -> impl IntoResponse {
    match state.store.create_detection_config_profile(req) {
        Ok((id, profile)) => (
            StatusCode::CREATED,
            Json(serde_json::json!({ "id": id, "profile": profile })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::to_value(ApiError {
                error: e.to_string(),
            })
            .unwrap_or_default()),
        )
            .into_response(),
    }
}

async fn update_detection_config(
    Path(id): Path<String>,
    State(state): State<AppState>,
    Json(req): Json<UpdateDetectionConfigRequest>,
) -> impl IntoResponse {
    match state.store.update_detection_config_profile(&id, req) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::to_value(ApiError {
                error: e.to_string(),
            })
            .unwrap_or_default()),
        )
            .into_response(),
    }
}

async fn delete_detection_config(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match state.store.delete_detection_config_profile(&id) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::to_value(ApiError {
                error: e.to_string(),
            })
            .unwrap_or_default()),
        )
            .into_response(),
    }
}

async fn select_detection_config(
    State(state): State<AppState>,
    Json(req): Json<SelectDetectionConfigRequest>,
) -> impl IntoResponse {
    let id = req.id.trim();
    if id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::to_value(ApiError {
                error: "id is required".to_string(),
            })
            .unwrap_or_default()),
        )
            .into_response();
    }
    match state.store.select_detection_config_profile(id) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::to_value(ApiError {
                error: e.to_string(),
            })
            .unwrap_or_default()),
        )
            .into_response(),
    }
}

async fn set_run_config(
    State(state): State<AppState>,
    Json(req): Json<DetectionConfig>,
) -> impl IntoResponse {
    match state.store.set_run_config(req) {
        Ok(cfg) => (StatusCode::OK, Json(serde_json::json!({ "config": cfg }))).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::to_value(ApiError {
                error: e.to_string(),
            }).unwrap_or_default()),
        )
            .into_response(),
    }
}

async fn get_sigma_config(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "config": state.store.get_sigma_zero_settings() }))
}

async fn set_sigma_config(
    State(state): State<AppState>,
    Json(req): Json<SigmaZeroSettings>,
) -> impl IntoResponse {
    match state.store.set_sigma_zero_settings(req) {
        Ok(cfg) => (StatusCode::OK, Json(serde_json::json!({ "config": cfg }))).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::to_value(ApiError {
                error: e.to_string(),
            }).unwrap_or_default()),
        )
            .into_response(),
    }
}

async fn get_sigma_rule_templates() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "templates": PlatformStore::default_sigma_rule_templates()
    }))
}

async fn list_sigma_stable_rules(State(state): State<AppState>) -> impl IntoResponse {
    match state.store.list_sigma_stable_rules() {
        Ok(rules) => (StatusCode::OK, Json(serde_json::json!({ "rules": rules }))).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::to_value(ApiError {
                error: e.to_string(),
            })
            .unwrap_or_default()),
        )
            .into_response(),
    }
}

async fn check_sigma_zero(
    State(state): State<AppState>,
    Json(req): Json<SigmaZeroCheckRequest>,
) -> impl IntoResponse {
    let uses_log_path = !req.log_path.trim().is_empty();
    let n_dataset_ids = req.dataset_ids.len();
    match state.store.check_sigma_zero(req) {
        Ok(result) => {
            info!(
                target: "rustmite_sift::sigma",
                status = %result.status,
                rules_match_count = result.rules_match_count,
                line_count = result.line_count,
                rules_source = %result.rules_source,
                process_log_source = %result.process_log_source,
                file_log_source = %result.file_log_source,
                source_datasets = result.source_dataset_ids.len(),
                uses_log_path,
                request_dataset_ids = n_dataset_ids,
                "POST /api/sigma-zero/check OK"
            );
            (StatusCode::OK, Json(serde_json::json!({ "result": result }))).into_response()
        }
        Err(e) => {
            warn!(
                target: "rustmite_sift::sigma",
                error = %e,
                uses_log_path,
                request_dataset_ids = n_dataset_ids,
                "POST /api/sigma-zero/check failed"
            );
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::to_value(ApiError {
                    error: e.to_string(),
                }).unwrap_or_default()),
            )
                .into_response()
        }
    }
}

async fn get_run(Path(id): Path<String>, State(state): State<AppState>) -> impl IntoResponse {
    match state.store.get_run(&id) {
        Some(run) => (StatusCode::OK, Json(serde_json::json!({ "run": run }))).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::to_value(ApiError {
                error: "run not found".to_string(),
            }).unwrap_or_default()),
        )
            .into_response(),
    }
}

async fn get_run_detections(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let findings_opt = state.store.findings_for_run_detections_api(&id);
    match findings_opt {
        Some(findings) => {
            let Some(run) = state.store.get_run(&id) else {
                warn!(run_id = %id, "GET /api/runs/:id/detections — run disappeared after sync");
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::to_value(ApiError {
                        error: "run not found".to_string(),
                    }).unwrap_or_default()),
                )
                    .into_response();
            };
            info!(
                run_id = %id,
                findings = findings.len(),
                "GET /api/runs/:id/detections"
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "findings": findings,
                    "dataset_ids": run.dataset_ids,
                    "user_triage": run.user_triage.without_excluded_reason_decisions(),
                    "run_request": run.request,
                    "sigma_stable_stats": run.sigma_stable_stats,
                    "created_at": run.created_at,
                })),
            )
                .into_response()
        }
        None => {
            warn!(run_id = %id, "GET /api/runs/:id/detections — run not found");
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::to_value(ApiError {
                    error: "run not found".to_string(),
                }).unwrap_or_default()),
            )
                .into_response()
        }
    }
}

async fn get_run_triage_precedent(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match state.store.triage_precedent_for_run(&id) {
        Some(bundle) => {
            info!(
                run_id = %id,
                entries = bundle.entries.len(),
                suppressed = bundle.suppressed.len(),
                "GET /api/runs/:id/triage-precedent"
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "run_id": id,
                    "entries": bundle.entries,
                    "suppressed": bundle.suppressed,
                })),
            )
                .into_response()
        }
        None => {
            warn!(run_id = %id, "GET /api/runs/:id/triage-precedent — run not found");
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::to_value(ApiError {
                    error: "run not found".to_string(),
                }).unwrap_or_default()),
            )
                .into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
struct ReasonPrecedentKeyBody {
    detector: String,
    reason: String,
}

async fn post_run_triage_precedent_ignore(
    Path(id): Path<String>,
    State(state): State<AppState>,
    Json(body): Json<ReasonPrecedentKeyBody>,
) -> impl IntoResponse {
    let key = ReasonPrecedentKey {
        detector: body.detector.trim().to_string(),
        reason: body.reason,
    };
    match state.store.add_triage_precedent_ignore(&id, key) {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response(),
        Err(e) => {
            let msg = e.to_string();
            let status = if msg.contains("run not found") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::BAD_REQUEST
            };
            (
                status,
                Json(serde_json::to_value(ApiError { error: msg }).unwrap_or_default()),
            )
                .into_response()
        }
    }
}

async fn post_run_triage_precedent_unignore(
    Path(id): Path<String>,
    State(state): State<AppState>,
    Json(body): Json<ReasonPrecedentKeyBody>,
) -> impl IntoResponse {
    let key = ReasonPrecedentKey {
        detector: body.detector.trim().to_string(),
        reason: body.reason,
    };
    match state.store.remove_triage_precedent_ignore(&id, &key) {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response(),
        Err(e) => {
            let msg = e.to_string();
            let status = if msg.contains("run not found") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::BAD_REQUEST
            };
            (
                status,
                Json(serde_json::to_value(ApiError { error: msg }).unwrap_or_default()),
            )
                .into_response()
        }
    }
}

async fn put_run_triage(
    Path(id): Path<String>,
    State(state): State<AppState>,
    Json(req): Json<PutRunTriageRequest>,
) -> impl IntoResponse {
    match state.store.update_run_user_triage(&id, req.user_triage) {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response(),
        Err(e) => {
            let msg = e.to_string();
            let status = if msg.contains("run not found") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::BAD_REQUEST
            };
            (
                status,
                Json(serde_json::to_value(ApiError { error: msg }).unwrap_or_default()),
            )
                .into_response()
        }
    }
}

async fn get_honeycomb(
    Query(q): Query<HoneycombQuery>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match state
        .store
        .honeycomb_for_run_filtered(&q.run_id, q.min_score, q.severity.as_deref())
    {
        Some(cells) => {
            info!(
                run_id = %q.run_id,
                cells = cells.len(),
                min_score = ?q.min_score,
                severity = ?q.severity,
                "GET /api/fleet/honeycomb"
            );
            (StatusCode::OK, Json(serde_json::json!({ "cells": cells }))).into_response()
        }
        None => {
            warn!(run_id = %q.run_id, "GET /api/fleet/honeycomb — run not found");
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::to_value(ApiError {
                    error: "run not found".to_string(),
                }).unwrap_or_default()),
            )
                .into_response()
        }
    }
}

async fn get_fleet_triage_precedent(State(state): State<AppState>) -> impl IntoResponse {
    let entries = state.store.triage_precedent_fleet_global();
    let dropped = state.store.fleet_triage_precedent_drops();
    let n = entries.len();
    let d = dropped.len();
    info!(entries = n, dropped = d, "GET /api/fleet/triage-precedent");
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "scope": "fleet",
            "run_id": serde_json::Value::Null,
            "entries": entries,
            "suppressed": [],
            "dropped": dropped,
        })),
    )
        .into_response()
}

async fn post_fleet_triage_precedent_drop(
    State(state): State<AppState>,
    Json(body): Json<ReasonPrecedentKeyBody>,
) -> impl IntoResponse {
    let key = ReasonPrecedentKey {
        detector: body.detector.trim().to_string(),
        reason: body.reason,
    };
    match state.store.add_fleet_triage_precedent_drop(key) {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response(),
        Err(e) => {
            let msg = e.to_string();
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::to_value(ApiError { error: msg }).unwrap_or_default()),
            )
                .into_response()
        }
    }
}

async fn post_fleet_triage_precedent_undrop(
    State(state): State<AppState>,
    Json(body): Json<ReasonPrecedentKeyBody>,
) -> impl IntoResponse {
    let key = ReasonPrecedentKey {
        detector: body.detector.trim().to_string(),
        reason: body.reason,
    };
    match state.store.remove_fleet_triage_precedent_drop(&key) {
        Ok(true) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response(),
        Ok(false) => (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true, "unchanged": true })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::to_value(ApiError {
                error: e.to_string(),
            })
            .unwrap_or_default()),
        )
            .into_response(),
    }
}

async fn post_fleet_triage_precedent_delete(
    State(state): State<AppState>,
    Json(body): Json<ReasonPrecedentKeyBody>,
) -> impl IntoResponse {
    let key = ReasonPrecedentKey {
        detector: body.detector.trim().to_string(),
        reason: body.reason,
    };
    match state.store.delete_fleet_triage_precedent_entry(key) {
        Ok(true) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response(),
        Ok(false) => (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true, "unchanged": true })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::to_value(ApiError {
                error: e.to_string(),
            })
            .unwrap_or_default()),
        )
            .into_response(),
    }
}

async fn upload_dataset(
    State(state): State<AppState>,
    Query(q): Query<UploadQuery>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let mut saved_paths: Vec<PathBuf> = Vec::new();
    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or_default().to_string();
        if name != "file" {
            continue;
        }
        let filename = field
            .file_name()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "upload.bin".to_string());
        let bytes = match field.bytes().await {
            Ok(b) => b,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::to_value(ApiError {
                        error: format!("failed reading upload bytes: {}", e),
                    }).unwrap_or_default()),
                )
                    .into_response()
            }
        };
        let mut path = PathBuf::from(".ironsift-platform/uploads");
        if let Err(e) = std::fs::create_dir_all(&path) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::to_value(ApiError {
                    error: format!("failed creating upload dir: {}", e),
                }).unwrap_or_default()),
            )
                .into_response();
        }
        let safe_name = format!("{}-{}", uuid::Uuid::new_v4(), filename);
        path.push(safe_name);
        if let Err(e) = tokio::fs::write(&path, bytes).await {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::to_value(ApiError {
                    error: format!("failed writing upload: {}", e),
                }).unwrap_or_default()),
            )
                .into_response();
        }
        saved_paths.push(path);
    }

    if saved_paths.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::to_value(ApiError {
                error: "missing file field".to_string(),
            }).unwrap_or_default()),
        )
            .into_response();
    }

    let tags: Vec<String> = q
        .tags
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let mut imported = Vec::new();
    let mut ingest_summaries = Vec::new();
    for (idx, path) in saved_paths.iter().enumerate() {
        let name = if idx == 0 { q.name.clone() } else { None };
        match state
            .store
            .import_file_auto(path.to_str().unwrap_or_default(), name, tags.clone(), None, None)
        {
            Ok((ds, summary)) => {
                imported.push(ds);
                ingest_summaries.push(summary);
            }
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::to_value(ApiError {
                        error: e.to_string(),
                    }).unwrap_or_default()),
                )
                    .into_response()
            }
        }
    }
    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "datasets": imported,
            "ingest_summaries": ingest_summaries
        })),
    )
        .into_response()
}
