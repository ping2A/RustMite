use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine as _;
use rustmite_checks::CheckEngine;
use rustmite_notify::{AlertEvent, NotifySink, WebhookSink};
use rustmite_proto::{HostId, NodeId, Observation, ScanId, Severity};
use rustmite_store::{
    ActivityEvent, CompleteScan, DeleteHostsRequest, EnqueueScan, FindingFilter, HostKeyPin,
    InMemoryStore, Store, TagSshKeysRequest, UpdateHost, UpsertHost, UpsertSshZone,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::bearer_auth;
use crate::clickhouse::ClickHouseClient;
use crate::openapi::openapi_json;
use crate::settings::RuntimeSettings;
use crate::ssh_hunter;
use crate::sys_metrics::MetricsHub;
use crate::ui;
use rustmite_transport::{
    test_host_connectivity, ConnectivityTestOpts, NoiseKeypair, SshTimeouts,
};

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<InMemoryStore>,
    pub api_token: Option<String>,
    pub checks: Arc<crate::check_catalog::CheckCatalog>,
    pub check_sets: Arc<crate::check_sets::CheckSetStore>,
    pub webhook: Option<Arc<WebhookSink>>,
    pub metrics: Arc<MetricsHub>,
    pub settings: Arc<RuntimeSettings>,
    pub clickhouse: Option<Arc<ClickHouseClient>>,
    pub noise_keypair: Arc<NoiseKeypair>,
    pub noise_xx_enabled: bool,
    /// Fleet credential encryption public key — server seals, only nodes open
    /// ([Sandfly-style](https://docs.sandflysecurity.com/docs/credentials-security)).
    pub cred_pubkey: Arc<tokio::sync::RwLock<Option<rustmite_crypto::CredPublicKey>>>,
    /// Live-editable probe/agent resource envelope (memory, CPU, bandwidth, deadlines).
    pub probe_limits: Arc<tokio::sync::RwLock<rustmite_proto::Limits>>,
    /// Live-editable fleet host reachability checker (Settings panel).
    pub host_health: Arc<tokio::sync::RwLock<crate::host_health::HostHealthConfig>>,
    /// IronSift platform store (AnoMark / Sigma / honeycomb).
    pub sift_platform: crate::sift_platform::SiftPlatform,
    /// Named virtual-agent profiles (JSONL field mappings).
    pub virtual_agents: crate::virtual_agents::VirtualAgentStore,
}

pub fn operator_router(state: AppState) -> Router {
    let token = state.api_token.clone();
    Router::new()
        .route("/", get(ui::index))
        .route("/ui", get(ui::index))
        .route("/ui/", get(ui::index))
        .route("/ui/assets/{*path}", get(ui_asset))
        .route("/v1/health", get(health))
        .route("/health", get(health))
        .route("/v1/version", get(version_inventory))
        .route("/v1/openapi.json", get(openapi))
        .route("/v1/summary", get(summary))
        .route("/v1/checks", get(list_checks).post(create_check))
        .route("/v1/checks/reload", axum::routing::post(reload_checks))
        .route(
            "/v1/checks/validate",
            axum::routing::post(validate_check),
        )
        .route(
            "/v1/checks/{id}",
            get(get_check)
                .put(put_check)
                .patch(patch_check)
                .delete(delete_check),
        )
        .route(
            "/v1/checks/{id}/validate",
            axum::routing::post(validate_check_by_id),
        )
        .route(
            "/v1/checks/{id}/test",
            axum::routing::post(test_check_by_id),
        )
        .route("/v1/nodes", get(list_nodes))
        .route("/v1/scans", get(list_scans))
        .route("/v1/activity", get(list_activity))
        .route("/v1/queue", get(get_queue))
        .route("/v1/metrics", get(get_metrics))
        .route("/v1/settings", get(get_settings).put(put_settings_partial))
        .route(
            "/v1/check-sets",
            get(get_check_sets).put(put_check_sets).post(reset_check_sets),
        )
        .route("/v1/data/summary", get(data_summary))
        .route("/v1/data/clear", axum::routing::post(data_clear))
        .route(
            "/v1/credentials/ssh-identity",
            axum::routing::post(upload_ssh_identity),
        )
        .route(
            "/v1/credentials/ssh-password",
            axum::routing::post(store_ssh_password),
        )
        .route("/v1/ssh/summary", get(ssh_summary))
        .route("/v1/ssh/keys", get(ssh_keys).post(ssh_tag_keys))
        .route("/v1/ssh/keys/{fingerprint}", get(ssh_key_detail))
        .route("/v1/ssh/users", get(ssh_users))
        .route("/v1/ssh/hosts", get(ssh_hosts))
        .route("/v1/ssh/graph", get(ssh_graph))
        .route("/v1/ssh/tags", get(ssh_tags))
        .route(
            "/v1/ssh/zones",
            get(ssh_zones).post(ssh_create_zone),
        )
        .route("/v1/ssh/zones/{id}", axum::routing::delete(ssh_delete_zone))
        .route("/v1/hosts", get(list_hosts).post(create_host))
        .route("/v1/hosts/test", axum::routing::post(test_host_connection))
        .route("/v1/hosts/delete", axum::routing::post(delete_hosts_bulk))
        .route(
            "/v1/hosts/{id}",
            get(get_host)
                .patch(update_host)
                .delete(delete_host),
        )
        .route("/v1/hosts/{id}/scan", axum::routing::post(trigger_scan))
        .route("/v1/hosts/{id}/processes", get(host_processes))
        .route("/v1/hosts/{id}/files", get(host_files))
        .route("/v1/hosts/{id}/connections", get(host_connections))
        .route("/v1/hosts/{id}/keys", axum::routing::post(pin_host_key))
        .route(
            "/v1/hosts/{id}/baseline",
            axum::routing::post(capture_baseline).get(get_baseline),
        )
        .route("/v1/findings", get(list_findings).delete(clear_findings))
        .route("/v1/scans/{id}", get(get_scan))
        .route("/v1/scans/{id}/coverage", get(scan_coverage))
        .route("/v1/hunt", axum::routing::post(hunt))
        .route("/v1/hunt/rpl", axum::routing::post(hunt_rpl))
        .route("/v1/hunt/rpl/compile", axum::routing::post(hunt_rpl_compile))
        .route("/v1/hunt/rpl/fields", get(hunt_rpl_fields))
        .route("/v1/hunt/rpl/histogram", axum::routing::post(hunt_rpl_histogram))
        .route("/v1/sift/config", get(crate::sift_api::sift_config))
        .route(
            "/v1/sift/detection-configs",
            get(crate::sift_platform::list_detection_configs)
                .post(crate::sift_platform::create_detection_config),
        )
        .route(
            "/v1/sift/detection-configs/active",
            axum::routing::put(crate::sift_platform::put_active_detection_config),
        )
        .route(
            "/v1/sift/detection-configs/{id}",
            get(crate::sift_platform::get_detection_config)
                .put(crate::sift_platform::update_detection_config)
                .delete(crate::sift_platform::delete_detection_config),
        )
        .route(
            "/v1/sift/detection-configs/{id}/select",
            axum::routing::post(crate::sift_platform::select_detection_config),
        )
        .route("/v1/sift/runs", get(crate::sift_api::list_sift_runs).post(crate::sift_api::run_fleet_sift).delete(crate::sift_api::delete_all_sift_runs))
        .route(
            "/v1/sift/runs/{id}",
            get(crate::sift_api::get_sift_run).delete(crate::sift_api::delete_sift_run),
        )
        .route(
            "/v1/sift/temporal",
            axum::routing::post(crate::sift_api::run_temporal_sift),
        )
        .route(
            "/v1/sift/platform/health",
            get(crate::sift_platform::platform_health),
        )
        .route(
            "/v1/sift/platform/datasets",
            get(crate::sift_platform::list_datasets),
        )
        .route(
            "/v1/sift/platform/sync",
            axum::routing::post(crate::sift_platform::sync_fleet_dataset),
        )
        .route(
            "/v1/sift/platform/runs",
            get(crate::sift_platform::list_platform_runs)
                .post(crate::sift_platform::create_platform_run),
        )
        .route(
            "/v1/sift/platform/runs/{id}",
            get(crate::sift_platform::get_platform_run),
        )
        .route(
            "/v1/sift/platform/runs/{id}/detections",
            get(crate::sift_platform::get_run_detections),
        )
        .route(
            "/v1/sift/platform/honeycomb",
            get(crate::sift_platform::get_honeycomb),
        )
        .route(
            "/v1/sift/platform/anomark/availability",
            get(crate::sift_platform::anomark_availability),
        )
        .route(
            "/v1/sift/platform/anomark/config",
            get(crate::sift_platform::get_anomark_config)
                .post(crate::sift_platform::set_anomark_config),
        )
        .merge(crate::ingest_virtual::virtual_ingest_routes())
        .merge(crate::virtual_agents::virtual_agent_routes())
        .merge(crate::anomark_api::anomark_routes())
        .layer(middleware::from_fn(move |req, next| {
            let token = token.clone();
            async move { bearer_auth(token, req, next).await }
        }))
        .with_state(state)
}

async fn ui_asset(
    axum::extract::Path(path): axum::extract::Path<String>,
) -> axum::response::Response {
    let uri: axum::http::Uri = format!("/ui/assets/{path}")
        .parse()
        .unwrap_or_else(|_| "/ui/assets/".parse().unwrap());
    ui::asset(uri).await
}

pub fn node_router(state: AppState) -> Router {
    Router::new()
        .route("/v1/nodes/register", axum::routing::post(node_register))
        .route("/v1/nodes/lease", axum::routing::post(node_lease))
        .route("/v1/nodes/results", axum::routing::post(node_results))
        .route("/v1/nodes/heartbeat", axum::routing::post(node_heartbeat))
        .route("/v1/nodes/progress", axum::routing::post(node_progress))
        .route("/v1/nodes/noise/xx", axum::routing::post(noise_xx_step))
        .with_state(state)
}

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let m = state.metrics.snapshot();
    Json(serde_json::json!({
        "status": "ok",
        "hostname": m.hostname,
        "scope": m.scope,
        "pid": m.pid,
        "process_name": m.process_name,
        "cpu_pct": m.cpu_pct,
        "mem_pct": m.mem_pct,
        "disk_pct": m.disk_pct,
        "uptime_secs": m.uptime_secs,
        "process_uptime_secs": m.process_uptime_secs,
        "clickhouse": state.clickhouse.is_some(),
        "store_backend": if state.clickhouse.is_some() { "clickhouse" } else { "json" },
        "noise_xx": state.noise_xx_enabled,
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn version_inventory() -> impl IntoResponse {
    Json(crate::version_info::collect_version_inventory())
}

async fn get_metrics(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.metrics.snapshot())
}

async fn get_settings(State(state): State<AppState>) -> impl IntoResponse {
    Json(settings_export(&state).await)
}

async fn settings_export(state: &AppState) -> crate::settings::SettingsExport {
    let mut export = state.settings.export();
    export.effective.scan_history_per_host = state.store.scan_history_per_host();
    let live = state.probe_limits.read().await.clone();
    export.effective.probe_max_rss_bytes = live.max_rss_bytes;
    export.effective.probe_max_observations = live.max_observations;
    export.effective.probe_max_output_bytes = live.max_output_bytes;
    export.effective.probe_max_files_examined = live.max_files_examined;
    export.effective.probe_max_bytes_hashed = live.max_bytes_hashed;
    export.effective.probe_nice = live.nice;
    export.effective.probe_io_idle = live.io_idle;
    export.effective.probe_max_transfer_bps = live.max_transfer_bps;
    export.effective.probe_max_cpu_pct = live.max_cpu_pct;
    export.effective.probe_max_open_files = live.max_open_files;
    let hh = state.host_health.read().await.clone();
    export.effective.host_health_enabled = hh.enabled;
    export.effective.host_health_interval_secs = hh.interval_secs;
    export.effective.host_health_concurrency = hh.concurrency;
    export.effective.host_health_connect_timeout_secs = hh.connect_timeout_secs;
    export
}

#[derive(Deserialize)]
pub struct SettingsPartialBody {
    /// Finished scans retained per host (fleet default).
    pub scan_history_per_host: Option<usize>,
    /// Probe/agent resource envelope (optional fields merge onto current).
    #[serde(default)]
    pub probe_limits: Option<ProbeLimitsPatch>,
    /// Fleet host reachability checker (optional fields merge onto current).
    #[serde(default)]
    pub host_health: Option<HostHealthPatch>,
}

#[derive(Deserialize, Default)]
pub struct HostHealthPatch {
    pub enabled: Option<bool>,
    pub interval_secs: Option<u64>,
    pub concurrency: Option<usize>,
    pub connect_timeout_secs: Option<u64>,
}

#[derive(Deserialize, Default)]
pub struct ProbeLimitsPatch {
    pub max_rss_bytes: Option<u64>,
    pub max_observations: Option<u32>,
    pub max_output_bytes: Option<u64>,
    pub max_files_examined: Option<u32>,
    pub max_bytes_hashed: Option<u64>,
    pub nice: Option<i8>,
    pub io_idle: Option<bool>,
    pub max_transfer_bps: Option<u64>,
    pub max_cpu_pct: Option<u8>,
    pub max_open_files: Option<u32>,
    /// Wall-clock scan deadline in seconds (maps to ScanRequest.deadline_ms).
    pub deadline_secs: Option<u64>,
}

fn probe_limits_path() -> PathBuf {
    PathBuf::from(".dev/probe-limits.json")
}

fn save_probe_limits(limits: &rustmite_proto::Limits) {
    let path = probe_limits_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(raw) = serde_json::to_string_pretty(limits) {
        let _ = std::fs::write(path, raw);
    }
}

async fn put_settings_partial(
    State(state): State<AppState>,
    Json(body): Json<SettingsPartialBody>,
) -> Result<impl IntoResponse, ApiError> {
    if let Some(n) = body.scan_history_per_host {
        if n > 200 {
            return Err(ApiError(
                StatusCode::BAD_REQUEST,
                "scan_history_per_host must be <= 200".into(),
            ));
        }
        state.store.set_scan_history_per_host(n);
        let path = PathBuf::from(".dev/scan-history-per-host");
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&path, format!("{n}\n"));
        let pruned = state.store.prune_scan_history(None, n).await?;
        let _ = state
            .store
            .push_activity(ActivityEvent {
                id: Uuid::new_v4(),
                ts: crate::sys_metrics::utc_now_rfc3339(),
                level: "info".into(),
                kind: "settings.updated".into(),
                message: format!("scan_history_per_host set to {n} (pruned {pruned} old scan(s))"),
                scan_id: None,
                host_id: None,
                node_id: None,
                detail: Some(serde_json::json!({
                    "scan_history_per_host": n,
                    "pruned_scans": pruned,
                })),
            })
            .await;
        state.store.mark_dirty_public();
    }
    if let Some(patch) = body.probe_limits {
        let mut guard = state.probe_limits.write().await;
        if let Some(v) = patch.max_rss_bytes {
            guard.max_rss_bytes = v.max(4 * 1024 * 1024);
        }
        if let Some(v) = patch.max_observations {
            guard.max_observations = v.max(1_000);
        }
        if let Some(v) = patch.max_output_bytes {
            guard.max_output_bytes = v.max(1024 * 1024);
        }
        if let Some(v) = patch.max_files_examined {
            guard.max_files_examined = v.max(1_000);
        }
        if let Some(v) = patch.max_bytes_hashed {
            guard.max_bytes_hashed = v;
        }
        if let Some(v) = patch.nice {
            guard.nice = v.clamp(-20, 19);
        }
        if let Some(v) = patch.io_idle {
            guard.io_idle = v;
        }
        if let Some(v) = patch.max_transfer_bps {
            guard.max_transfer_bps = v;
        }
        if let Some(v) = patch.max_cpu_pct {
            guard.max_cpu_pct = v.min(100);
        }
        if let Some(v) = patch.max_open_files {
            guard.max_open_files = v;
        }
        save_probe_limits(&guard);
        let snapshot = guard.clone();
        drop(guard);
        let _ = state
            .store
            .push_activity(ActivityEvent {
                id: Uuid::new_v4(),
                ts: crate::sys_metrics::utc_now_rfc3339(),
                level: "info".into(),
                kind: "settings.updated".into(),
                message: "probe agent resource limits updated".into(),
                scan_id: None,
                host_id: None,
                node_id: None,
                detail: Some(serde_json::json!({ "probe_limits": snapshot })),
            })
            .await;
        // Optional: also update fleet scan timeout when deadline_secs provided.
        if let Some(secs) = patch.deadline_secs {
            if secs == 0 || secs > 3600 {
                return Err(ApiError(
                    StatusCode::BAD_REQUEST,
                    "probe deadline_secs must be 1..=3600".into(),
                ));
            }
            // Persist as scan_timeout via activity note; live value is settings.scan_timeout_secs (restart).
            let path = PathBuf::from(".dev/probe-deadline-secs");
            let _ = std::fs::write(&path, format!("{secs}\n"));
        }
        state.store.mark_dirty_public();
    }
    if let Some(patch) = body.host_health {
        let mut guard = state.host_health.write().await;
        if let Some(v) = patch.enabled {
            guard.enabled = v;
        }
        if let Some(v) = patch.interval_secs {
            guard.interval_secs = v;
        }
        if let Some(v) = patch.concurrency {
            guard.concurrency = v;
        }
        if let Some(v) = patch.connect_timeout_secs {
            guard.connect_timeout_secs = v;
        }
        *guard = guard.clone().sanitized();
        crate::host_health::save_host_health_config(&guard);
        let snapshot = guard.clone();
        drop(guard);
        let _ = state
            .store
            .push_activity(ActivityEvent {
                id: Uuid::new_v4(),
                ts: crate::sys_metrics::utc_now_rfc3339(),
                level: "info".into(),
                kind: "settings.updated".into(),
                message: format!(
                    "host health checker {} (every {}s, concurrency {})",
                    if snapshot.enabled { "enabled" } else { "disabled" },
                    snapshot.interval_secs,
                    snapshot.concurrency
                ),
                scan_id: None,
                host_id: None,
                node_id: None,
                detail: Some(serde_json::json!({ "host_health": snapshot })),
            })
            .await;
        state.store.mark_dirty_public();
    }
    Ok(Json(settings_export(&state).await))
}

#[derive(Deserialize)]
pub struct DataClearBody {
    /// One or more of: findings, scans, observations, activity, baselines, host_keys,
    /// events, virtual_ingest, ssh_identities, ssh_passwords, all
    #[serde(default)]
    pub targets: Vec<String>,
}

fn count_virtual_ingest_dirs() -> (usize, u64) {
    let root = std::path::PathBuf::from(".dev/ingest");
    let Ok(rd) = std::fs::read_dir(&root) else {
        return (0, 0);
    };
    let mut hosts = 0usize;
    let mut bytes = 0u64;
    for ent in rd.flatten() {
        let path = ent.path();
        if !path.is_dir() {
            continue;
        }
        hosts += 1;
        if let Ok(files) = std::fs::read_dir(&path) {
            for f in files.flatten() {
                if let Ok(meta) = f.metadata() {
                    bytes = bytes.saturating_add(meta.len());
                }
            }
        }
    }
    (hosts, bytes)
}

#[derive(Debug, Clone, serde::Serialize)]
struct CredFileMeta {
    name: String,
    path: String,
    bytes: u64,
    sealed: bool,
    modified_at: Option<String>,
    /// Host display names that reference this credential via labels.
    used_by: Vec<String>,
}

async fn list_stored_credentials(
    state: &AppState,
    kind: Option<&str>,
) -> Result<Vec<CredFileMeta>, ApiError> {
    let rows = state.store.list_credentials(kind).await?;
    let mut out: Vec<CredFileMeta> = rows
        .into_iter()
        .map(|c| {
            let sealed_len = base64::engine::general_purpose::STANDARD
                .decode(c.sealed_b64.as_bytes())
                .map(|b| b.len() as u64)
                .unwrap_or(0);
            CredFileMeta {
                name: c.id.clone(),
                path: c.id.clone(),
                bytes: if c.plaintext_bytes > 0 {
                    c.plaintext_bytes
                } else {
                    sealed_len
                },
                sealed: true,
                modified_at: Some(if c.updated_at.is_empty() {
                    c.created_at
                } else {
                    c.updated_at
                }),
                used_by: Vec::new(),
            }
        })
        .collect();
    out.sort_by(|a, b| b.name.cmp(&a.name));
    Ok(out)
}

fn attach_cred_usage(files: &mut [CredFileMeta], hosts: &[rustmite_store::HostRecord], label_key: &str) {
    for f in files.iter_mut() {
        let mut used = Vec::new();
        for h in hosts {
            let Some(raw) = h.labels.get(label_key) else {
                continue;
            };
            let hit = raw == &f.path
                || raw == &f.name
                || raw.ends_with(&format!("/{}", f.name))
                || std::path::Path::new(raw)
                    .file_name()
                    .and_then(|s| s.to_str())
                    == Some(f.name.as_str());
            if hit {
                used.push(h.display_name.clone());
            }
        }
        used.sort();
        used.dedup();
        f.used_by = used;
    }
}

fn purge_cred_dir(dir: &str) -> usize {
    let root = std::path::PathBuf::from(dir);
    let Ok(rd) = std::fs::read_dir(&root) else {
        return 0;
    };
    let mut n = 0usize;
    for ent in rd.flatten() {
        let path = ent.path();
        if !path.is_file() {
            continue;
        }
        if path
            .file_name()
            .and_then(|s| s.to_str())
            .map(|n| n.starts_with('.'))
            .unwrap_or(true)
        {
            continue;
        }
        if std::fs::remove_file(&path).is_ok() {
            n += 1;
        }
    }
    n
}

async fn data_summary(State(state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    let counts = state.store.data_counts().await?;
    let hosts = state.store.list_hosts().await.unwrap_or_default();
    let mut events: Option<u64> = None;
    let mut platform_blobs: Option<u64> = None;
    let mut clickhouse = false;
    if let Some(ch) = &state.clickhouse {
        clickhouse = true;
        events = ch.events_count().await.ok();
        platform_blobs = ch.platform_blobs_live_count().await.ok();
    }
    let (virtual_hosts, virtual_bytes) = count_virtual_ingest_dirs();

    let mut ssh_identities = list_stored_credentials(&state, Some("identity")).await?;
    let mut ssh_passwords = list_stored_credentials(&state, Some("password")).await?;
    attach_cred_usage(&mut ssh_identities, &hosts, "ssh_identity");
    attach_cred_usage(&mut ssh_passwords, &hosts, "ssh_password_file");

    let hosts_with_identity = hosts
        .iter()
        .filter(|h| h.labels.contains_key("ssh_identity"))
        .count();
    let hosts_with_password = hosts
        .iter()
        .filter(|h| h.labels.contains_key("ssh_password_file"))
        .count();

    Ok(Json(serde_json::json!({
        "hosts": counts.hosts,
        "findings": counts.findings,
        "scans": counts.scans,
        "observations": counts.observations,
        "activity": counts.activity,
        "nodes": counts.nodes,
        "baselines": counts.baselines,
        "host_keys": counts.host_keys,
        "ssh_keys": counts.ssh_keys,
        "ssh_placements": counts.ssh_placements,
        "ssh_zones": counts.ssh_zones,
        "credentials": counts.credentials,
        "events": events,
        "platform_blobs": platform_blobs,
        "virtual_ingest_hosts": virtual_hosts,
        "virtual_ingest_bytes": virtual_bytes,
        "clickhouse": clickhouse,
        "ssh_identities_count": ssh_identities.len(),
        "ssh_passwords_count": ssh_passwords.len(),
        "hosts_with_ssh_identity": hosts_with_identity,
        "hosts_with_ssh_password": hosts_with_password,
        "ssh_identities": ssh_identities,
        "ssh_passwords": ssh_passwords,
        "ssh_identities_dir": "database",
        "ssh_secrets_dir": "database",
        "credential_storage": "database",
        "groups": [
            {
                "id": "operational",
                "title": "Operational",
                "items": ["findings", "scans", "observations", "activity", "baselines", "host_keys"]
            },
            {
                "id": "hunt",
                "title": "Hunt",
                "items": ["events", "virtual_ingest"]
            },
            {
                "id": "credentials",
                "title": "Credentials",
                "items": ["ssh_identities", "ssh_passwords"]
            },
            {
                "id": "inventory",
                "title": "Inventory (kept on Clear all)",
                "items": ["hosts", "nodes", "ssh_keys", "ssh_placements", "ssh_zones"]
            },
            {
                "id": "platform",
                "title": "Platform",
                "items": ["platform_blobs"]
            }
        ],
    })))
}

async fn data_clear(
    State(state): State<AppState>,
    Json(body): Json<DataClearBody>,
) -> Result<impl IntoResponse, ApiError> {
    let mut targets: Vec<String> = body
        .targets
        .into_iter()
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect();
    targets.sort();
    targets.dedup();
    if targets.is_empty() {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "targets required (findings, scans, observations, activity, baselines, host_keys, events, virtual_ingest, ssh_identities, ssh_passwords, or all)".into(),
        ));
    }
    let all = targets.iter().any(|t| t == "all");
    // "all" clears operational + hunt only — credentials must be cleared explicitly.
    let want = |name: &str| {
        if matches!(name, "ssh_identities" | "ssh_passwords") {
            targets.iter().any(|t| t == name)
        } else {
            all || targets.iter().any(|t| t == name)
        }
    };

    let mut purged = serde_json::Map::new();

    if want("findings") {
        let n = state.store.clear_all_findings().await?;
        purged.insert("findings".into(), serde_json::json!(n));
    }
    if want("scans") {
        let n = state.store.clear_all_scans().await?;
        purged.insert("scans".into(), serde_json::json!(n));
    }
    if want("observations") {
        let n = state.store.clear_all_observations().await?;
        purged.insert("observations".into(), serde_json::json!(n));
    }
    if want("activity") {
        let n = state.store.clear_all_activity().await?;
        purged.insert("activity".into(), serde_json::json!(n));
    }
    if want("baselines") {
        let n = state.store.clear_all_baselines().await?;
        purged.insert("baselines".into(), serde_json::json!(n));
    }
    if want("host_keys") {
        let n = state.store.clear_all_host_keys().await?;
        purged.insert("host_keys".into(), serde_json::json!(n));
    }
    if want("events") {
        match &state.clickhouse {
            Some(ch) => {
                let before = ch.events_count().await.unwrap_or(0);
                ch.clear_events()
                    .await
                    .map_err(|e| ApiError(StatusCode::BAD_GATEWAY, e.to_string()))?;
                purged.insert("events".into(), serde_json::json!(before));
            }
            None => {
                return Err(ApiError(
                    StatusCode::BAD_REQUEST,
                    "ClickHouse not configured — cannot clear events".into(),
                ));
            }
        }
    }
    if want("virtual_ingest") {
        let n = crate::platform_ch::purge_all_virtual_ingest(&state).await;
        purged.insert("virtual_ingest".into(), serde_json::json!(n));
    }
    if want("ssh_identities") {
        let n = state.store.clear_credentials(Some("identity")).await?;
        let _ = purge_cred_dir(".dev/ssh-identities");
        purged.insert("ssh_identities".into(), serde_json::json!(n));
    }
    if want("ssh_passwords") {
        let n = state.store.clear_credentials(Some("password")).await?;
        let _ = purge_cred_dir(".dev/ssh-secrets");
        purged.insert("ssh_passwords".into(), serde_json::json!(n));
    }

    if purged.is_empty() {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            format!(
                "unknown targets; use findings, scans, observations, activity, baselines, host_keys, events, virtual_ingest, ssh_identities, ssh_passwords, or all (got: {})",
                targets.join(", ")
            ),
        ));
    }

    let _ = state
        .store
        .push_activity(ActivityEvent {
            id: Uuid::new_v4(),
            ts: crate::sys_metrics::utc_now_rfc3339(),
            level: "warn".into(),
            kind: "data.cleared".into(),
            message: format!("cleared data: {}", purged.keys().cloned().collect::<Vec<_>>().join(", ")),
            scan_id: None,
            host_id: None,
            node_id: None,
            detail: Some(serde_json::Value::Object(purged.clone())),
        })
        .await;

    // Ensure control-plane wipe hits ClickHouse promptly (hosts kept).
    state.store.mark_dirty_public();

    Ok(Json(serde_json::json!({
        "purged": purged,
        "summary": state.store.data_counts().await?,
    })))
}

async fn get_check_sets(State(state): State<AppState>) -> impl IntoResponse {
    let engine = state.checks.snapshot().await;
    Json(state.check_sets.export(&engine).await)
}

async fn put_check_sets(
    State(state): State<AppState>,
    Json(body): Json<crate::check_sets::CheckSetsPutBody>,
) -> Result<impl IntoResponse, ApiError> {
    let engine = state.checks.snapshot().await;
    let export = state
        .check_sets
        .put(body, &engine)
        .await
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e))?;
    let _ = state
        .store
        .push_activity(ActivityEvent {
            id: Uuid::new_v4(),
            ts: crate::sys_metrics::utc_now_rfc3339(),
            level: "info".into(),
            kind: "check_sets.updated".into(),
            message: "scan profile check sets updated".into(),
            scan_id: None,
            host_id: None,
            node_id: None,
            detail: None,
        })
        .await;
    Ok(Json(export))
}

async fn reset_check_sets(State(state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    let engine = state.checks.snapshot().await;
    let export = state
        .check_sets
        .reset_defaults(&engine)
        .await
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(export))
}

#[derive(Deserialize)]
pub struct UploadSshIdentityBody {
    /// Original filename hint (e.g. id_ed25519).
    #[serde(default)]
    pub name: Option<String>,
    /// PEM / OpenSSH private key text.
    pub pem: String,
}

fn sanitize_identity_name(raw: &str) -> String {
    let base = std::path::Path::new(raw)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("id_ed25519");
    let cleaned: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        "id_ed25519".into()
    } else {
        cleaned
    }
}

async fn require_cred_pubkey(
    state: &AppState,
) -> Result<rustmite_crypto::CredPublicKey, ApiError> {
    state
        .cred_pubkey
        .read()
        .await
        .clone()
        .ok_or_else(|| {
            ApiError(
                StatusCode::SERVICE_UNAVAILABLE,
                "no credential encryption public key — start a scanner node first (it publishes cred.pub) or set --cred-pubkey / RUSTMITE_CRED_PUBKEY".into(),
            )
        })
}

async fn upload_ssh_identity(
    State(state): State<AppState>,
    Json(body): Json<UploadSshIdentityBody>,
) -> Result<impl IntoResponse, ApiError> {
    let pem = body.pem.trim();
    if pem.is_empty() {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "pem (private key contents) required".into(),
        ));
    }
    if !pem.contains("PRIVATE KEY") && !pem.contains("OPENSSH PRIVATE KEY") {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "file does not look like an OpenSSH/PEM private key".into(),
        ));
    }
    if pem.len() > 64 * 1024 {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "key file too large (max 64 KiB)".into(),
        ));
    }

    let pubk = require_cred_pubkey(&state).await?;
    let hint = sanitize_identity_name(body.name.as_deref().unwrap_or("id_ed25519"));
    let pem_bytes = format!("{}\n", pem.replace("\r\n", "\n"));
    let saved = crate::credentials::store_sealed_credential(
        &state,
        "identity",
        &hint,
        pem_bytes.as_bytes(),
        &pubk,
    )
    .await?;

    let msg = format!(
        "SSH identity sealed for scanner nodes (X25519 / ChaCha20-Poly1305). Stored in database as {}.",
        saved.id
    );
    audit_credential_event(
        &state,
        "credential.ssh_identity_uploaded",
        &msg,
        serde_json::json!({
            "name": saved.id,
            "path": saved.id,
            "bytes": saved.plaintext_bytes,
            "storage": "database",
            "sealed": true,
            "node_only": true,
        }),
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "name": saved.id,
            "path": saved.id,
            "id": saved.id,
            "bytes": saved.plaintext_bytes,
            "storage": "database",
            "sealed": true,
            "node_only": true,
            "note": "Credential cannot be read again by the server or UI — only scanner nodes can decrypt it.",
        })),
    ))
}

#[derive(Deserialize)]
pub struct StoreSshPasswordBody {
    /// Optional name hint for the secret file.
    #[serde(default)]
    pub name: Option<String>,
    /// SSH password (sealed into the control-plane database; never returned).
    pub password: String,
}

async fn store_ssh_password(
    State(state): State<AppState>,
    Json(body): Json<StoreSshPasswordBody>,
) -> Result<impl IntoResponse, ApiError> {
    let password = body.password;
    if password.is_empty() {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "password required".into(),
        ));
    }
    if password.len() > 8 * 1024 {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "password too large (max 8 KiB)".into(),
        ));
    }

    let pubk = require_cred_pubkey(&state).await?;
    let hint = sanitize_identity_name(body.name.as_deref().unwrap_or("ssh-password"));
    let bytes = password.len() as u64;
    let saved = crate::credentials::store_sealed_credential(
        &state,
        "password",
        &hint,
        password.as_bytes(),
        &pubk,
    )
    .await?;

    let msg = format!(
        "SSH password sealed for scanner nodes (X25519 / ChaCha20-Poly1305). Stored in database as {}.",
        saved.id
    );
    audit_credential_event(
        &state,
        "credential.ssh_password_stored",
        &msg,
        serde_json::json!({
            "name": saved.id,
            "path": saved.id,
            "bytes": bytes,
            "storage": "database",
            "sealed": true,
            "node_only": true,
        }),
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "name": saved.id,
            "path": saved.id,
            "id": saved.id,
            "bytes": bytes,
            "storage": "database",
            "sealed": true,
            "node_only": true,
            "note": "Credential cannot be read again by the server or UI — only scanner nodes can decrypt it.",
        })),
    ))
}

async fn audit_credential_event(
    state: &AppState,
    kind: &str,
    message: &str,
    detail: serde_json::Value,
) {
    let _ = state
        .store
        .push_activity(ActivityEvent {
            id: Uuid::new_v4(),
            ts: crate::sys_metrics::utc_now_rfc3339(),
            level: "info".into(),
            kind: kind.into(),
            message: message.into(),
            scan_id: None,
            host_id: None,
            node_id: None,
            detail: Some(detail.clone()),
        })
        .await;

    if let Some(ch) = state.clickhouse.as_ref() {
        let path = detail
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let row = serde_json::json!({
            "timestamp": chrono_like_now(),
            "message": message,
            "source_type": "rustmite_server",
            "source": "operator",
            "platform": "linux",
            "host_id": "",
            "host_name": "",
            "scan_id": "",
            "collector": "credential",
            "kind": kind,
            "check_id": "",
            "data_type": "credential",
            "process_name": "rustmite-server",
            "process_id": std::process::id() as u32,
            "user": "",
            "path": path,
            "src_ip": "",
            "dest_ip": "",
            "file_hash": "",
            "severity": "info",
            "exe_memfd": 0,
            "ext": detail.to_string(),
        });
        let _ = ch.insert_json_each_row("events", &[row]).await;
    }
}

fn chrono_like_now() -> String {
    // ClickHouse JSONEachRow accepts RFC3339-ish timestamps.
    crate::sys_metrics::utc_now_rfc3339()
}

/// Resolve a node-sealed credential box as base64 for lease delivery (server cannot decrypt).
async fn resolve_lease_cred_box(state: &AppState, reference: &str) -> Option<String> {
    crate::credentials::resolve_cred_box_b64(state, reference)
        .await
        .ok()
}

fn stored_cred_unreachable_err(kind: &str) -> ApiError {
    ApiError(
        StatusCode::UNPROCESSABLE_ENTITY,
        format!(
            "stored {kind} is sealed for scanner nodes only — the server cannot decrypt it. \
             Use a one-shot password/identity in this test request, or run a live scan from a node."
        ),
    )
}

#[derive(Deserialize)]
struct SshListQuery {
    #[serde(default)]
    q: String,
    #[serde(default)]
    tag: String,
    #[serde(default)]
    reused: bool,
    #[serde(default)]
    weak: bool,
    #[serde(default = "default_ssh_limit")]
    limit: usize,
}

fn default_ssh_limit() -> usize {
    500
}

async fn ssh_summary(State(state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    // Lazy heal: older scans collected keys into observations but never into the hunter store.
    let now = crate::sys_metrics::utc_now_rfc3339();
    match ssh_hunter::backfill_from_store(state.store.as_ref(), 50_000, &now).await {
        Ok(n) if n > 0 => {
            tracing::info!(placements = n, "SSH Hunter backfilled from stored observations");
            state.store.mark_dirty_public();
        }
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, "SSH Hunter backfill skipped"),
    }
    match ssh_hunter::ensure_default_zones(state.store.as_ref()).await {
        Ok(n) if n > 0 => {
            tracing::info!(zones = n, "SSH Hunter default zones created");
            state.store.mark_dirty_public();
        }
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, "SSH Hunter default zones skipped"),
    }

    let keys = state.store.list_ssh_keys().await?;
    let placements = state.store.list_ssh_placements(None, None, None).await?;
    let zones = state.store.list_ssh_zones().await?;
    let mut summary = ssh_hunter::build_summary(&keys, &placements, zones.len());
    summary.reused_keys = summary.reused_keys.max(ssh_hunter::lateral_findings(&placements));
    Ok(Json(summary))
}

async fn ssh_keys(
    State(state): State<AppState>,
    Query(q): Query<SshListQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let keys = state.store.list_ssh_keys().await?;
    let placements = state.store.list_ssh_placements(None, None, None).await?;
    let rows = ssh_hunter::enrich_keys(&keys, &placements);
    let filtered = ssh_hunter::filter_keys(&rows, &q.q, &q.tag, q.reused, q.weak);
    let limit = q.limit.clamp(1, 5_000);
    let out: Vec<_> = filtered.into_iter().take(limit).cloned().collect();
    Ok(Json(serde_json::json!({
        "total": out.len(),
        "keys": out,
    })))
}

async fn ssh_key_detail(
    State(state): State<AppState>,
    Path(fingerprint): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let fp = urlencoding_decode(&fingerprint);
    let key = state
        .store
        .get_ssh_key(&fp)
        .await?
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, format!("ssh key {fp}")))?;
    let placements = state
        .store
        .list_ssh_placements(Some(&fp), None, None)
        .await?;
    let hosts = state.store.list_hosts().await?;
    let host_index = ssh_hunter::host_map(hosts);
    let places: Vec<_> = placements
        .into_iter()
        .map(|p| {
            let host = host_index.get(&p.host_id.0);
            serde_json::json!({
                "host_id": p.host_id,
                "display_name": host.map(|h| &h.display_name),
                "primary_addr": host.and_then(|h| h.primary_addr.clone()),
                "username": p.username,
                "path": p.path,
                "role": p.role,
                "options": p.options,
                "seen_at": p.seen_at,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({
        "key": key,
        "placements": places,
        "host_count": places.len(),
    })))
}

async fn ssh_tag_keys(
    State(state): State<AppState>,
    Json(body): Json<TagSshKeysRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if body.fingerprints.is_empty() {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "fingerprints required".into(),
        ));
    }
    let n = state.store.tag_ssh_keys(body).await?;
    Ok(Json(serde_json::json!({ "updated": n })))
}

async fn ssh_users(
    State(state): State<AppState>,
    Query(q): Query<SshListQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let placements = state.store.list_ssh_placements(None, None, None).await?;
    let mut users = ssh_hunter::build_users(&placements);
    if !q.q.is_empty() {
        let needle = q.q.to_lowercase();
        users.retain(|u| u.username.to_lowercase().contains(&needle));
    }
    users.truncate(q.limit.clamp(1, 5_000));
    Ok(Json(serde_json::json!({ "users": users })))
}

async fn ssh_hosts(
    State(state): State<AppState>,
    Query(q): Query<SshListQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let placements = state.store.list_ssh_placements(None, None, None).await?;
    let hosts = state.store.list_hosts().await?;
    let host_index = ssh_hunter::host_map(hosts);
    let mut rows = ssh_hunter::build_hosts(&placements, &host_index);
    if !q.q.is_empty() {
        let needle = q.q.to_lowercase();
        rows.retain(|h| {
            format!(
                "{} {} {}",
                h.display_name,
                h.primary_addr.as_deref().unwrap_or(""),
                h.usernames.join(" ")
            )
            .to_lowercase()
            .contains(&needle)
        });
    }
    rows.truncate(q.limit.clamp(1, 5_000));
    Ok(Json(serde_json::json!({ "hosts": rows })))
}

#[derive(Deserialize)]
struct SshGraphQuery {
    #[serde(default = "default_graph_limit")]
    limit: usize,
}

fn default_graph_limit() -> usize {
    40
}

async fn ssh_graph(
    State(state): State<AppState>,
    Query(q): Query<SshGraphQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let keys = state.store.list_ssh_keys().await?;
    let placements = state.store.list_ssh_placements(None, None, None).await?;
    let hosts = state.store.list_hosts().await?;
    let host_index = ssh_hunter::host_map(hosts);
    let graph = ssh_hunter::build_graph(&keys, &placements, &host_index, q.limit.clamp(5, 200));
    Ok(Json(graph))
}

async fn ssh_tags(State(state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(serde_json::json!({
        "tags": state.store.list_ssh_key_tags().await?
    })))
}

async fn ssh_zones(State(state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    let zones = state.store.list_ssh_zones().await?;
    let hosts = state.store.list_hosts().await?;
    let keys = state.store.list_ssh_keys().await?;
    let views = ssh_hunter::zone_views(&zones, &hosts, &keys);
    Ok(Json(serde_json::json!({ "zones": views })))
}

#[derive(Deserialize)]
struct CreateZoneBody {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub host_selectors: Vec<String>,
    #[serde(default)]
    pub key_tags: Vec<String>,
    #[serde(default)]
    pub policy: Option<String>,
}

async fn ssh_create_zone(
    State(state): State<AppState>,
    Json(body): Json<CreateZoneBody>,
) -> Result<impl IntoResponse, ApiError> {
    let zone = state
        .store
        .upsert_ssh_zone(UpsertSshZone {
            id: None,
            name: body.name,
            description: body.description,
            host_selectors: body.host_selectors,
            key_tags: body.key_tags,
            policy: body.policy.unwrap_or_else(|| "alert_on_cross_zone".into()),
        })
        .await?;
    Ok((StatusCode::CREATED, Json(zone)))
}

async fn ssh_delete_zone(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    state.store.delete_ssh_zone(id).await?;
    Ok(StatusCode::NO_CONTENT)
}

fn urlencoding_decode(s: &str) -> String {
    // Minimal decode for fingerprints in path segments (%3A → :).
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = &s[i + 1..i + 3];
            if let Ok(v) = u8::from_str_radix(hex, 16) {
                out.push(v as char);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(' ');
        } else {
            out.push(bytes[i] as char);
        }
        i += 1;
    }
    out
}

async fn openapi() -> impl IntoResponse {
    Json(openapi_json())
}

async fn summary(State(state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    let hosts = state.store.list_hosts().await?;
    let findings = state
        .store
        .list_findings(FindingFilter {
            limit: 50_000,
            ..Default::default()
        })
        .await?;
    let scans = state.store.list_scans(50_000).await?;
    let nodes = state.store.list_nodes().await?;
    let mut by_sev: BTreeMap<String, u32> = BTreeMap::new();
    for f in &findings {
        let key = format!("{:?}", f.severity).to_lowercase();
        *by_sev.entry(key).or_default() += 1;
    }
    let mut by_profile: BTreeMap<String, u32> = BTreeMap::new();
    let mut by_env: BTreeMap<String, u32> = BTreeMap::new();
    let mut never_scanned = 0u32;
    let mut failed = 0u32;
    for h in &hosts {
        let profile = h
            .labels
            .get("profile")
            .cloned()
            .unwrap_or_else(|| "unknown".into());
        *by_profile.entry(profile).or_default() += 1;
        let env = h
            .labels
            .get("env")
            .cloned()
            .unwrap_or_else(|| "unknown".into());
        *by_env.entry(env).or_default() += 1;
        if h.last_scan_at.is_none() {
            never_scanned += 1;
        }
        if h.last_outcome
            .as_deref()
            .is_some_and(|o| o != "complete")
        {
            failed += 1;
        }
    }
    let engine = state.checks.snapshot().await;
    let enabled = engine.len();
    let total = engine.manifests().len();
    let queue = state.store.queue_snapshot().await?;
    Ok(Json(serde_json::json!({
        "hosts": hosts.len(),
        "findings": findings.len(),
        "findings_by_severity": by_sev,
        "hosts_by_profile": by_profile,
        "hosts_by_env": by_env,
        "hosts_never_scanned": never_scanned,
        "hosts_failed_outcome": failed,
        "scans": scans.len(),
        "nodes": nodes.len(),
        "checks_enabled": enabled,
        "checks_total": total,
        "queue": {
            "queued": queue.queued,
            "leased": queue.leased,
            "running": queue.running,
            "complete": queue.complete,
            "failed": queue.failed,
            "active_count": queue.active.len(),
        },
    })))
}

async fn list_checks(State(state): State<AppState>) -> impl IntoResponse {
    let engine = state.checks.snapshot().await;
    let sets = state.check_sets.export(&engine).await;
    let checks: Vec<_> = engine
        .manifests()
        .iter()
        .map(|m| {
            let id = m.id.as_str();
            let mut in_sets = serde_json::Map::new();
            for (set_id, plan) in &sets.effective {
                in_sets.insert(
                    set_id.clone(),
                    serde_json::json!(plan.checks.iter().any(|c| c == id)),
                );
            }
            serde_json::json!({
                "id": id,
                "version": m.version,
                "name": m.name,
                "title": m.title,
                "check_type": m.check_type,
                "severity": m.severity,
                "confidence": m.confidence,
                "enabled": m.enabled,
                "cost": m.cost,
                "match_on": m.match_on,
                "where_expr": m.where_expr,
                "collectors": m.required_collectors(),
                "attack": m.attack,
                "rationale": m.rationale,
                "false_positives": m.false_positives,
                "evidence_fields": m.evidence_fields,
                "scan_sets": in_sets,
                "is_anomark": m.is_anomark_rule(),
                "anomark": m.anomark_options().map(|o| serde_json::json!({
                    "model_id": o.model_id,
                    "suspect_percent": o.suspect_percent,
                    "tags": o.tags,
                    "max_commands": o.max_commands,
                })),
            })
        })
        .collect();
    Json(checks)
}

fn check_json(
    m: &rustmite_checks::CheckManifest,
    toml_text: &str,
    path: &std::path::Path,
    scan_sets: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "id": m.id.as_str(),
        "version": m.version,
        "name": m.name,
        "title": m.title,
        "check_type": m.check_type,
        "severity": m.severity,
        "confidence": m.confidence,
        "enabled": m.enabled,
        "cost": m.cost,
        "match_on": m.match_on,
        "where_expr": m.where_expr,
        "collectors": m.required_collectors(),
        "attack": m.attack,
        "rationale": m.rationale,
        "false_positives": m.false_positives,
        "evidence_fields": m.evidence_fields,
        "references": m.references,
        "path": path.display().to_string(),
        "toml": toml_text,
        "scan_sets": scan_sets,
        "is_anomark": m.is_anomark_rule(),
        "anomark": m.anomark_options().map(|o| serde_json::json!({
            "model_id": o.model_id,
            "suspect_percent": o.suspect_percent,
            "tags": o.tags,
            "max_commands": o.max_commands,
        })),
    })
}

async fn scan_sets_for_id(state: &AppState, id: &str) -> serde_json::Value {
    let engine = state.checks.snapshot().await;
    let sets = state.check_sets.export(&engine).await;
    let mut in_sets = serde_json::Map::new();
    for (set_id, plan) in &sets.effective {
        in_sets.insert(
            set_id.clone(),
            serde_json::json!(plan.checks.iter().any(|c| c == id)),
        );
    }
    serde_json::Value::Object(in_sets)
}

async fn get_check(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let (path, toml_text) = state.checks.read_toml(&id).map_err(|e| {
        ApiError(StatusCode::NOT_FOUND, e)
    })?;
    let m = rustmite_checks::load_manifest(&toml_text)
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let scan_sets = scan_sets_for_id(&state, &id).await;
    Ok(Json(check_json(&m, &toml_text, &path, scan_sets)))
}

#[derive(Deserialize)]
pub struct PutCheckBody {
    pub toml: String,
}

async fn create_check(
    State(state): State<AppState>,
    Json(body): Json<PutCheckBody>,
) -> Result<impl IntoResponse, ApiError> {
    let m = state
        .checks
        .create_toml(&body.toml)
        .await
        .map_err(|e| {
            let status = if e.contains("already exists") {
                StatusCode::CONFLICT
            } else {
                StatusCode::BAD_REQUEST
            };
            ApiError(status, e)
        })?;
    let id = m.id.as_str().to_string();
    let (path, toml_text) = state
        .checks
        .read_toml(&id)
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let _ = state
        .store
        .push_activity(ActivityEvent {
            id: Uuid::new_v4(),
            ts: crate::sys_metrics::utc_now_rfc3339(),
            level: "info".into(),
            kind: "check.created".into(),
            message: format!("Created check {id}"),
            scan_id: None,
            host_id: None,
            node_id: None,
            detail: Some(serde_json::json!({ "check_id": id, "version": m.version })),
        })
        .await;
    let scan_sets = scan_sets_for_id(&state, &id).await;
    Ok((
        StatusCode::CREATED,
        Json(check_json(&m, &toml_text, &path, scan_sets)),
    ))
}

async fn put_check(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<PutCheckBody>,
) -> Result<impl IntoResponse, ApiError> {
    let m = state
        .checks
        .write_toml(&id, &body.toml)
        .await
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e))?;
    let (path, toml_text) = state
        .checks
        .read_toml(&id)
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let _ = state
        .store
        .push_activity(ActivityEvent {
            id: Uuid::new_v4(),
            ts: crate::sys_metrics::utc_now_rfc3339(),
            level: "info".into(),
            kind: "check.updated".into(),
            message: format!("Updated check {id}"),
            scan_id: None,
            host_id: None,
            node_id: None,
            detail: Some(serde_json::json!({ "check_id": id, "version": m.version })),
        })
        .await;
    let scan_sets = scan_sets_for_id(&state, &id).await;
    Ok(Json(check_json(&m, &toml_text, &path, scan_sets)))
}

async fn delete_check(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let path = state
        .checks
        .delete_toml(&id)
        .await
        .map_err(|e| {
            let status = if e.contains("not found") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::BAD_REQUEST
            };
            ApiError(status, e)
        })?;
    let engine = state.checks.snapshot().await;
    let _ = state.check_sets.remove_check_id(&id, &engine).await;
    let _ = state
        .store
        .push_activity(ActivityEvent {
            id: Uuid::new_v4(),
            ts: crate::sys_metrics::utc_now_rfc3339(),
            level: "info".into(),
            kind: "check.deleted".into(),
            message: format!("Deleted check {id}"),
            scan_id: None,
            host_id: None,
            node_id: None,
            detail: Some(serde_json::json!({
                "check_id": id,
                "path": path.display().to_string(),
            })),
        })
        .await;
    Ok(Json(serde_json::json!({
        "ok": true,
        "deleted": id,
        "path": path.display().to_string(),
    })))
}

#[derive(Deserialize)]
pub struct PatchCheckBody {
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Per-scan-profile membership: { "pulse": true, "standard": false, ... }
    #[serde(default)]
    pub scan_sets: Option<BTreeMap<String, bool>>,
}

async fn patch_check(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<PatchCheckBody>,
) -> Result<impl IntoResponse, ApiError> {
    if body.enabled.is_none() && body.scan_sets.is_none() {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "enabled and/or scan_sets required".into(),
        ));
    }
    if let Some(enabled) = body.enabled {
        state
            .checks
            .set_enabled(&id, enabled)
            .await
            .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e))?;
    }
    if let Some(ref toggles) = body.scan_sets {
        let engine = state.checks.snapshot().await;
        let export = state.check_sets.export(&engine).await;
        let mut sets = BTreeMap::new();
        for set_id in crate::check_sets::CHECK_SET_IDS {
            let mut ids = export
                .effective
                .get(*set_id)
                .map(|p| p.checks.clone())
                .unwrap_or_default();
            if let Some(on) = toggles.get(*set_id) {
                if *on {
                    if !ids.iter().any(|c| c == &id) {
                        ids.push(id.clone());
                    }
                } else {
                    ids.retain(|c| c != &id);
                }
            }
            ids.sort();
            ids.dedup();
            sets.insert((*set_id).to_string(), ids);
        }
        state
            .check_sets
            .put(
                crate::check_sets::CheckSetsPutBody { sets },
                &engine,
            )
            .await
            .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e))?;
    }
    let (path, toml_text) = state
        .checks
        .read_toml(&id)
        .map_err(|e| ApiError(StatusCode::NOT_FOUND, e))?;
    let m = rustmite_checks::load_manifest(&toml_text)
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let scan_sets = scan_sets_for_id(&state, &id).await;
    let _ = state
        .store
        .push_activity(ActivityEvent {
            id: Uuid::new_v4(),
            ts: crate::sys_metrics::utc_now_rfc3339(),
            level: "info".into(),
            kind: "check.patched".into(),
            message: format!("Patched check {id}"),
            scan_id: None,
            host_id: None,
            node_id: None,
            detail: Some(serde_json::json!({
                "check_id": id,
                "enabled": body.enabled,
                "scan_sets": body.scan_sets,
            })),
        })
        .await;
    Ok(Json(check_json(&m, &toml_text, &path, scan_sets)))
}

async fn reload_checks(State(state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    let n = state
        .checks
        .reload()
        .await
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(serde_json::json!({
        "reloaded": n,
        "path": state.checks.dir().display().to_string(),
    })))
}

#[derive(Debug, Deserialize)]
pub struct ValidateCheckBody {
    /// Full TOML manifest (draft). When omitted with `{id}` routes, the saved file is used.
    #[serde(default)]
    pub toml: Option<String>,
    /// Optional host scope for dry-run observations.
    #[serde(default)]
    pub host_id: Option<Uuid>,
    /// Max observations to load for dry-run (default 5000).
    #[serde(default = "default_validate_obs_limit")]
    pub limit: usize,
    /// Max hit samples returned (default 25).
    #[serde(default = "default_validate_sample")]
    pub sample_limit: usize,
    /// When true, also persist findings (Mobipwn-style “run”); default dry-run only.
    #[serde(default)]
    pub create_findings: bool,
    /// Optional inline observations (JSON Observation enum values) instead of store data.
    #[serde(default)]
    pub observations: Option<Vec<Observation>>,
}

fn default_validate_obs_limit() -> usize {
    5_000
}

fn default_validate_sample() -> usize {
    25
}

fn validate_check_response(
    engine: &CheckEngine,
    observations: &[Observation],
    sample_limit: usize,
    source: &str,
) -> serde_json::Value {
    let started = std::time::Instant::now();
    let hits = engine.evaluate(observations);
    let elapsed_ms = started.elapsed().as_millis() as u64;
    let sample: Vec<_> = hits.iter().take(sample_limit.max(1)).collect();
    let m = engine.manifests().first();
    serde_json::json!({
        "ok": true,
        "source": source,
        "compile": {
            "id": m.map(|x| x.id.as_str()),
            "name": m.map(|x| x.name.clone()),
            "match_on": m.map(|x| x.match_on.clone()),
            "where_expr": m.map(|x| x.where_expr.clone()),
            "collectors": m.map(|x| x.required_collectors()),
            "enabled": m.map(|x| x.enabled),
        },
        "dry_run": {
            "observations_scanned": observations.len(),
            "hit_count": hits.len(),
            "elapsed_ms": elapsed_ms,
            "sample": sample,
        },
        "errors": [],
    })
}

async fn load_obs_for_validate(
    state: &AppState,
    host_id: Option<Uuid>,
    limit: usize,
    inline: Option<Vec<Observation>>,
) -> Result<Vec<Observation>, ApiError> {
    if let Some(obs) = inline {
        return Ok(obs);
    }
    let lim = limit.clamp(1, 50_000);
    let rows = state
        .store
        .list_observations(host_id.map(HostId), lim)
        .await?;
    Ok(rows.into_iter().map(|o| o.data).collect())
}

/// Type-check a candidate check manifest and dry-run over recent (or inline) observations.
async fn validate_check(
    State(state): State<AppState>,
    Json(body): Json<ValidateCheckBody>,
) -> Result<impl IntoResponse, ApiError> {
    let toml = body.toml.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let Some(toml) = toml else {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "toml required for POST /v1/checks/validate (or use /v1/checks/{id}/validate)".into(),
        ));
    };
    let engine = CheckEngine::from_toml_for_test(toml).map_err(|e| {
        ApiError(
            StatusCode::BAD_REQUEST,
            format!("check compile failed: {e}"),
        )
    })?;
    let observations =
        load_obs_for_validate(&state, body.host_id, body.limit, body.observations).await?;
    let mut resp = validate_check_response(&engine, &observations, body.sample_limit, "draft_toml");
    if body.create_findings {
        resp["create_findings"] = serde_json::json!({
            "supported": false,
            "detail": "use a host scan to persist findings; dry-run only from Rules workbench",
        });
    }
    Ok(Json(resp))
}

async fn validate_check_by_id(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<ValidateCheckBody>,
) -> Result<impl IntoResponse, ApiError> {
    let toml = if let Some(t) = body.toml.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        t.to_string()
    } else {
        let (_path, text) = state.checks.read_toml(&id).map_err(|e| {
            ApiError(StatusCode::NOT_FOUND, e.to_string())
        })?;
        text
    };
    let engine = CheckEngine::from_toml_for_test(&toml).map_err(|e| {
        ApiError(
            StatusCode::BAD_REQUEST,
            format!("check compile failed: {e}"),
        )
    })?;
    // Ensure the draft id matches the path id when both present.
    if let Some(m) = engine.manifests().first() {
        if m.id.as_str() != id {
            return Err(ApiError(
                StatusCode::BAD_REQUEST,
                format!(
                    "manifest id '{}' does not match path id '{id}'",
                    m.id.as_str()
                ),
            ));
        }
    }
    let observations =
        load_obs_for_validate(&state, body.host_id, body.limit, body.observations).await?;
    Ok(Json(validate_check_response(
        &engine,
        &observations,
        body.sample_limit,
        "saved_or_override",
    )))
}

/// Mobipwn-style rule test / dry-run (never creates findings unless explicitly supported later).
async fn test_check_by_id(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(mut body): Json<ValidateCheckBody>,
) -> Result<impl IntoResponse, ApiError> {
    // Test always dry-runs; create_findings is informational only today.
    body.create_findings = false;
    let toml = if let Some(t) = body.toml.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        t.to_string()
    } else {
        let (_path, text) = state.checks.read_toml(&id).map_err(|e| {
            ApiError(StatusCode::NOT_FOUND, e.to_string())
        })?;
        text
    };
    let engine = CheckEngine::from_toml_for_test(&toml).map_err(|e| {
        ApiError(
            StatusCode::BAD_REQUEST,
            format!("check compile failed: {e}"),
        )
    })?;
    let observations =
        load_obs_for_validate(&state, body.host_id, body.limit, body.observations).await?;
    let mut resp = validate_check_response(&engine, &observations, body.sample_limit, "test");
    resp["mode"] = serde_json::json!("dry_run");
    resp["check_id"] = serde_json::json!(id);
    Ok(Json(resp))
}

async fn list_nodes(State(state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(state.store.list_nodes().await?))
}

#[derive(Deserialize)]
pub struct LimitQuery {
    pub limit: Option<usize>,
}

async fn list_scans(
    State(state): State<AppState>,
    Query(q): Query<LimitQuery>,
) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(
        state.store.list_scans(q.limit.unwrap_or(100)).await?,
    ))
}

async fn list_activity(
    State(state): State<AppState>,
    Query(q): Query<LimitQuery>,
) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(
        state.store.list_activity(q.limit.unwrap_or(200)).await?,
    ))
}

async fn get_queue(State(state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(state.store.queue_snapshot().await?))
}

#[derive(Deserialize)]
pub struct CreateHostBody {
    pub display_name: String,
    pub primary_addr: Option<String>,
    pub ssh_port: Option<u16>,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    pub tenant_id: Option<Uuid>,
    #[serde(default)]
    pub timeouts: rustmite_store::HostTimeouts,
    /// `ssh` (default), `agentlite`, or `virtual`.
    #[serde(default)]
    pub agent_kind: Option<String>,
    /// Optional: persist last connectivity test result on create.
    #[serde(default)]
    pub auth_status: Option<String>,
    #[serde(default)]
    pub auth_detail: Option<String>,
}

async fn create_host(
    State(state): State<AppState>,
    Json(body): Json<CreateHostBody>,
) -> Result<impl IntoResponse, ApiError> {
    let label_set = |k: &str| {
        body.labels
            .get(k)
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
    };
    let has_cred = label_set("credential")
        || label_set("ssh_identity")
        || label_set("ssh_password_file")
        || (label_set("ssh_user")
            && (label_set("ssh_identity") || label_set("ssh_password_file") || label_set("credential")));
    let mut host = state
        .store
        .upsert_host(UpsertHost {
            id: None,
            tenant_id: body.tenant_id.unwrap_or(Uuid::nil()),
            display_name: body.display_name,
            primary_addr: body.primary_addr,
            ssh_port: body.ssh_port,
            labels: body.labels,
            timeouts: body.timeouts,
            agent_kind: body.agent_kind,
            ingest_token: None,
        })
        .await?;

    let auth_status = body.auth_status.or_else(|| {
        if has_cred {
            None
        } else {
            Some("no_credential".into())
        }
    });
    if auth_status.is_some() || body.auth_detail.is_some() {
        host = state
            .store
            .update_host(
                host.id,
                UpdateHost {
                    auth_status,
                    auth_detail: body.auth_detail.or_else(|| {
                        if has_cred {
                            None
                        } else {
                            Some(
                                "No SSH credential configured — scans will fail until credentials are set and tested"
                                    .into(),
                            )
                        }
                    }),
                    auth_checked_at: Some(crate::sys_metrics::utc_now_rfc3339()),
                    ..Default::default()
                },
            )
            .await?;
    }
    Ok((StatusCode::CREATED, Json(host)))
}

async fn list_hosts(State(state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(state.store.list_hosts().await?))
}

#[derive(Deserialize)]
pub struct UpdateHostBody {
    pub display_name: Option<String>,
    pub primary_addr: Option<String>,
    pub ssh_port: Option<u16>,
    pub labels: Option<BTreeMap<String, String>>,
    pub label_patch: Option<BTreeMap<String, String>>,
    pub timeouts: Option<rustmite_store::HostTimeouts>,
    pub auth_status: Option<String>,
    pub auth_detail: Option<String>,
    pub auth_checked_at: Option<String>,
    #[serde(default)]
    pub agent_kind: Option<String>,
}

async fn update_host(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateHostBody>,
) -> Result<impl IntoResponse, ApiError> {
    let host = state
        .store
        .update_host(
            HostId(id),
            UpdateHost {
                display_name: body.display_name,
                primary_addr: body.primary_addr,
                ssh_port: body.ssh_port,
                labels: body.labels,
                label_patch: body.label_patch,
                timeouts: body.timeouts,
                auth_status: body.auth_status,
                auth_detail: body.auth_detail,
                auth_checked_at: body.auth_checked_at,
                agent_kind: body.agent_kind,
                ..Default::default()
            },
        )
        .await?;
    Ok(Json(host))
}

#[derive(Deserialize)]
pub struct TestHostBody {
    pub host: String,
    #[serde(default = "default_ssh_port")]
    pub ssh_port: u16,
    pub username: Option<String>,
    /// Credential id (or legacy path) for a sealed SSH private key in the database.
    pub identity: Option<String>,
    /// One-shot password for the test (not persisted; use /v1/credentials/ssh-password to store).
    pub password: Option<String>,
    /// Credential id (or legacy path) for a sealed password in the database.
    pub password_file: Option<String>,
    /// Prefer `publickey` or `password` when both credentials are present.
    pub auth_method: Option<String>,
    /// When true (default), missing credentials counts as a failed test.
    #[serde(default = "default_true")]
    pub require_auth: bool,
    /// If set, persist the result onto this host id.
    pub host_id: Option<Uuid>,
    pub connect_timeout_secs: Option<u64>,
}

fn default_ssh_port() -> u16 {
    22
}
fn default_true() -> bool {
    true
}

async fn test_host_connection(
    State(state): State<AppState>,
    Json(body): Json<TestHostBody>,
) -> Result<impl IntoResponse, ApiError> {
    let host = body.host.trim();
    if host.is_empty() {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "host address required".into(),
        ));
    }
    if body.ssh_port == 0 {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "ssh_port must be > 0".into(),
        ));
    }

    let prefer_password = body
        .auth_method
        .as_deref()
        .map(str::trim)
        .map(|s| s.eq_ignore_ascii_case("password"))
        .unwrap_or(false);

    let identity = body
        .identity
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| {
            if prefer_password {
                None
            } else {
                std::env::var("RUSTMITE_SSH_IDENTITY").ok()
            }
        });

    let password_inline = body
        .password
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let password_file = body
        .password_file
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let password_from_file = match password_file.as_deref() {
        Some(r) => {
            if state
                .store
                .get_credential(r)
                .await?
                .is_some()
            {
                return Err(stored_cred_unreachable_err("password"));
            }
            let p = std::path::PathBuf::from(r);
            let raw = std::fs::read(&p).map_err(|e| {
                ApiError(
                    StatusCode::BAD_REQUEST,
                    format!("read password file {}: {e}", p.display()),
                )
            })?;
            if rustmite_crypto::is_cred_box(&raw)
                || raw.starts_with(rustmite_crypto::SEALED_MAGIC)
            {
                return Err(stored_cred_unreachable_err("password"));
            }
            let pw = String::from_utf8_lossy(&raw)
                .trim_end_matches(['\r', '\n'])
                .to_string();
            if pw.is_empty() {
                return Err(ApiError(
                    StatusCode::BAD_REQUEST,
                    format!("password file empty: {}", p.display()),
                ));
            }
            Some(pw)
        }
        None => None,
    };
    let password = password_inline.or(password_from_file);

    // Prefer publickey unless the caller asked for password and supplied one.
    // Stored node-sealed identities cannot be opened on the server.
    let (identity_path, identity_pem, password) = if prefer_password && password.is_some() {
        (None, None, password)
    } else if let Some(ref reference) = identity {
        if state
            .store
            .get_credential(reference)
            .await?
            .is_some()
        {
            return Err(stored_cred_unreachable_err("SSH identity"));
        }
        let path = std::path::PathBuf::from(reference);
        let raw = std::fs::read(&path).map_err(|e| {
            ApiError(
                StatusCode::BAD_REQUEST,
                format!("read identity {}: {e}", path.display()),
            )
        })?;
        if rustmite_crypto::is_cred_box(&raw) || raw.starts_with(rustmite_crypto::SEALED_MAGIC) {
            return Err(stored_cred_unreachable_err("SSH identity"));
        }
        let pem = String::from_utf8_lossy(&raw).to_string();
        if pem.trim().is_empty() {
            return Err(ApiError(
                StatusCode::BAD_REQUEST,
                format!("identity empty: {}", path.display()),
            ));
        }
        (Some(path), Some(pem), None)
    } else {
        (None, None, password)
    };

    let username = body
        .username
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| std::env::var("RUSTMITE_SSH_USER").ok())
        .or_else(|| {
            if identity_pem.is_some() || password.is_some() {
                Some("root".into())
            } else {
                None
            }
        });

    let mut timeouts = SshTimeouts::default();
    if let Some(s) = body.connect_timeout_secs {
        timeouts.connect = std::time::Duration::from_secs(s.max(1).min(60));
        timeouts.auth = std::time::Duration::from_secs((s * 2).max(5).min(60));
        timeouts.command = std::time::Duration::from_secs(15);
    } else {
        timeouts.connect = std::time::Duration::from_secs(state.settings.ssh_connect_timeout_secs);
        timeouts.auth = std::time::Duration::from_secs(state.settings.ssh_auth_timeout_secs);
        timeouts.command = std::time::Duration::from_secs(15);
    }

    let report = test_host_connectivity(ConnectivityTestOpts {
        host,
        port: body.ssh_port,
        username: username.as_deref(),
        identity: None,
        identity_pem: identity_pem.as_deref(),
        password: password.as_deref(),
        timeouts,
        require_auth: body.require_auth,
    })
    .await
    .map_err(|e| ApiError(StatusCode::BAD_GATEWAY, e.to_string()))?;

    let mut saved_host = None;
    if let Some(id) = body.host_id {
        let detail = report
            .stages
            .iter()
            .rev()
            .find(|s| !s.ok)
            .map(|s| s.detail.clone())
            .or_else(|| report.stages.last().map(|s| s.detail.clone()));
        let mut patch = UpdateHost {
            auth_status: Some(report.auth_status.clone()),
            auth_detail: detail,
            auth_checked_at: Some(crate::sys_metrics::utc_now_rfc3339()),
            ..Default::default()
        };
        if let Some(arch) = report.arch.clone() {
            patch.arch = Some(arch);
        }
        if let Some(kernel) = report.kernel.clone() {
            patch.kernel = Some(kernel);
        }
        if let Some(os) = report.os.clone() {
            patch.os = Some(os);
        }
        if let Some(os_id) = report.os_id.clone() {
            patch.os_id = Some(os_id);
        }
        if let Some(os_version) = report.os_version.clone() {
            patch.os_version = Some(os_version);
        }
        if let (Some(kt), Some(fp)) = (&report.host_key_type, &report.host_key_fingerprint) {
            let _ = state
                .store
                .pin_host_key(HostKeyPin {
                    host_id: HostId(id),
                    key_type: kt.clone(),
                    fingerprint: fp.clone(),
                })
                .await;
        }
        saved_host = Some(state.store.update_host(HostId(id), patch).await?);
    }

    Ok(Json(serde_json::json!({
        "ok": report.ok,
        "auth_status": report.auth_status,
        "auth_method": report.auth_method,
        "stages": report.stages,
        "host_key_type": report.host_key_type,
        "host_key_fingerprint": report.host_key_fingerprint,
        "uname": report.uname,
        "arch": report.arch,
        "kernel": report.kernel,
        "os": report.os,
        "os_id": report.os_id,
        "os_version": report.os_version,
        "identity_used": identity_path.as_ref().map(|p| p.display().to_string()),
        "password_used": password.is_some(),
        "username_used": username,
        "host": saved_host,
    })))
}

async fn delete_host(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    // Capture display name before cascade so side-channel purge can match events
    // keyed by machine_id / host_name as well as UUID.
    let host = state.store.get_host(HostId(id)).await?;
    let name = host.display_name.clone();
    state.store.delete_host(HostId(id)).await?;
    crate::platform_ch::purge_host_artifacts(&state, id, Some(name.as_str())).await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct BulkDeleteBody {
    pub host_ids: Vec<Uuid>,
}

async fn delete_hosts_bulk(
    State(state): State<AppState>,
    Json(body): Json<BulkDeleteBody>,
) -> Result<impl IntoResponse, ApiError> {
    if body.host_ids.is_empty() {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "host_ids required".into(),
        ));
    }
    if body.host_ids.len() > 5_000 {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "host_ids limited to 5000 per request".into(),
        ));
    }
    // Resolve names before delete so purge still knows host_name for events cleanup.
    let mut names: std::collections::HashMap<Uuid, String> = std::collections::HashMap::new();
    for id in &body.host_ids {
        if let Ok(h) = state.store.get_host(HostId(*id)).await {
            names.insert(*id, h.display_name);
        }
    }
    let ids = body.host_ids.clone();
    let result = state
        .store
        .delete_hosts(DeleteHostsRequest {
            host_ids: body.host_ids.into_iter().map(HostId).collect(),
        })
        .await?;
    let missing: std::collections::HashSet<Uuid> = result
        .missing
        .iter()
        .map(|h| h.0)
        .collect();
    for id in ids {
        if missing.contains(&id) {
            continue;
        }
        crate::platform_ch::purge_host_artifacts(
            &state,
            id,
            names.get(&id).map(String::as_str),
        )
        .await;
    }
    Ok(Json(result))
}

async fn get_host(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let host = state.store.get_host(HostId(id)).await?;
    let pin = state.store.get_host_key(HostId(id)).await?;
    let findings = state
        .store
        .list_findings(FindingFilter {
            host_id: Some(HostId(id)),
            limit: 50,
            ..Default::default()
        })
        .await?;
    Ok(Json(serde_json::json!({
        "host": host,
        "host_key": pin,
        "open_findings": findings.len(),
        "findings": findings,
    })))
}

#[derive(Deserialize)]
pub struct HostInventoryQuery {
    #[serde(default = "default_inventory_limit")]
    pub limit: usize,
    /// Exact scan UUID to load. Takes precedence over `inventory`.
    #[serde(default)]
    pub scan_id: Option<Uuid>,
    /// Nth newest finished scan with this inventory kind: `1`/`latest`, `2`/`previous`, …
    #[serde(default)]
    pub inventory: Option<String>,
}

fn default_inventory_limit() -> usize {
    10_000
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

/// Resolve which scan's observations to return for a host inventory kind.
async fn host_kind_rows(
    state: &AppState,
    host_id: HostId,
    kind: &str,
    limit: usize,
    scan_override: Option<Uuid>,
    inventory: Option<&str>,
) -> Result<(Option<Uuid>, Vec<rustmite_store::StoredObservation>), ApiError> {
    let rows = state
        .store
        .list_observations(Some(host_id), 50_000)
        .await?;
    let of_kind: Vec<_> = rows
        .into_iter()
        .filter(|o| o.kind == kind)
        .collect();
    if of_kind.is_empty() {
        return Ok((None, Vec::new()));
    }
    let scan_id = if let Some(sid) = scan_override {
        sid
    } else {
        let mut seen = std::collections::HashSet::new();
        let mut ordered: Vec<Uuid> = Vec::new();
        for o in of_kind.iter().rev() {
            if seen.insert(o.scan_id.0) {
                ordered.push(o.scan_id.0);
            }
        }
        let idx = inventory
            .map(inventory_index0)
            .unwrap_or(0);
        ordered
            .get(idx)
            .copied()
            .or_else(|| ordered.first().copied())
            .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "no scans for inventory".into()))?
    };
    let mut out: Vec<_> = of_kind
        .into_iter()
        .filter(|o| o.scan_id.0 == scan_id)
        .collect();
    if out.len() > limit && limit > 0 {
        out.truncate(limit);
    }
    Ok((Some(scan_id), out))
}

/// Latest process inventory for a host (scan observations, or virtual ingest JSONL).
async fn host_processes(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(q): Query<HostInventoryQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let host = state.store.get_host(HostId(id)).await?;
    let limit = q.limit.max(1);
    let is_virtual = host.agent_kind.eq_ignore_ascii_case("virtual")
        || host
            .auth_status
            .as_deref()
            .map(|s| s.eq_ignore_ascii_case("virtual"))
            .unwrap_or(false);

    if is_virtual {
        crate::platform_ch::ensure_virtual_local(&state, host.id.0).await;
    }

    let (scan_id, rows) = host_kind_rows(
        &state,
        HostId(id),
        "process",
        limit,
        q.scan_id,
        q.inventory.as_deref(),
    )
    .await?;
    let mut processes: Vec<serde_json::Value> = rows
        .iter()
        .filter_map(|o| match &o.data {
            Observation::Process(p) => serde_json::to_value(p).ok(),
            other => serde_json::to_value(other).ok(),
        })
        .collect();
    let mut source = if !processes.is_empty() { "scan" } else { "none" };

    // Virtual agents: fall back to ingest JSONL only for latest (no scan override).
    let want_latest = q.scan_id.is_none()
        && q.inventory
            .as_deref()
            .map(|s| {
                matches!(
                    s.trim().to_ascii_lowercase().as_str(),
                    "" | "latest" | "current" | "newest" | "1" | "0"
                )
            })
            .unwrap_or(true);
    if is_virtual && want_latest && processes.is_empty() {
        let raw = crate::sift_api::load_virtual_jsonl(&host);
        if !raw.is_empty() {
            processes = raw
                .into_iter()
                .take(limit)
                .map(|e| virtual_process_row(&e))
                .collect();
            source = "virtual_ingest";
        }
    }

    Ok(Json(serde_json::json!({
        "host_id": id,
        "scan_id": scan_id,
        "inventory": q.inventory.clone().unwrap_or_else(|| "1".into()),
        "source": source,
        "count": processes.len(),
        "processes": processes,
    })))
}

fn virtual_process_row(e: &rustmite_sift::RawLogEntry) -> serde_json::Value {
    let mut cmdline = Vec::new();
    if !e.path.is_empty() {
        cmdline.push(serde_json::json!({ "s": e.path }));
    } else if !e.name.is_empty() {
        cmdline.push(serde_json::json!({ "s": e.name }));
    }
    for a in e.args.split_whitespace() {
        cmdline.push(serde_json::json!({ "s": a }));
    }
    serde_json::json!({
        "pid": e.pid,
        "ppid": e.ppid,
        "comm": e.name,
        "exe": { "s": e.path },
        "cmdline": cmdline,
        "uids": [e.uid, e.uid, e.uid, e.uid],
        "username": null,
        "state": "S",
        "exe_memfd": false,
        "exe_deleted": false,
        "listen_ports": [],
        "ns": {},
        "environ_flags": [],
    })
}

/// Latest file inventory for a host (scan `file_meta` / entropy, or virtual ingest JSONL).
async fn host_files(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(q): Query<HostInventoryQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let host = state.store.get_host(HostId(id)).await?;
    let limit = q.limit.max(1);
    let is_virtual = host.agent_kind.eq_ignore_ascii_case("virtual")
        || host
            .auth_status
            .as_deref()
            .map(|s| s.eq_ignore_ascii_case("virtual"))
            .unwrap_or(false);

    if is_virtual {
        crate::platform_ch::ensure_virtual_local(&state, host.id.0).await;
    }

    // Prefer file_meta; if that scan has none, try file_entropy for the same pick.
    let (mut scan_id, meta_rows) = host_kind_rows(
        &state,
        HostId(id),
        "file_meta",
        limit,
        q.scan_id,
        q.inventory.as_deref(),
    )
    .await?;
    let mut files: Vec<serde_json::Value> = meta_rows
        .iter()
        .filter_map(|o| match &o.data {
            Observation::FileMeta(f) => serde_json::to_value(f).ok(),
            Observation::FileEntropy(f) => serde_json::to_value(f).ok(),
            other => serde_json::to_value(other).ok(),
        })
        .collect();
    if files.is_empty() {
        let (sid2, entropy_rows) = host_kind_rows(
            &state,
            HostId(id),
            "file_entropy",
            limit,
            q.scan_id.or(scan_id),
            q.inventory.as_deref(),
        )
        .await?;
        if scan_id.is_none() {
            scan_id = sid2;
        }
        files = entropy_rows
            .iter()
            .filter_map(|o| match &o.data {
                Observation::FileMeta(f) => serde_json::to_value(f).ok(),
                Observation::FileEntropy(f) => serde_json::to_value(f).ok(),
                other => serde_json::to_value(other).ok(),
            })
            .collect();
    }

    // Enrich FileMeta rows: octal mode, flags, and owner/group from account observations
    // on the same scan when the collector only stored numeric uid/gid.
    if !files.is_empty() {
        let uid_names = {
            let (_, acct_rows) = host_kind_rows(
                &state,
                HostId(id),
                "account",
                50_000,
                scan_id.or(q.scan_id),
                q.inventory.as_deref(),
            )
            .await
            .unwrap_or((None, Vec::new()));
            let mut uids = std::collections::HashMap::<u32, String>::new();
            for o in &acct_rows {
                if let Observation::Account(a) = &o.data {
                    uids.entry(a.uid).or_insert_with(|| a.username.clone());
                }
            }
            uids
        };
        for f in &mut files {
            let Some(obj) = f.as_object_mut() else {
                continue;
            };
            if let Some(mode) = obj.get("mode").and_then(|v| v.as_u64()) {
                obj.insert(
                    "mode_octal".into(),
                    serde_json::json!(format!("{:04o}", mode as u32 & 0o7777)),
                );
            }
            let setuid = obj
                .get("setuid")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let setgid = obj
                .get("setgid")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let immutable = obj
                .get("immutable")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let mut flags: Vec<&str> = Vec::new();
            if setuid {
                flags.push("setuid");
            }
            if setgid {
                flags.push("setgid");
            }
            if immutable {
                flags.push("immutable");
            }
            if let Some(mode) = obj.get("mode").and_then(|v| v.as_u64()) {
                if mode & 0o002 != 0 {
                    flags.push("world_writable");
                }
            }
            obj.insert("flags".into(), serde_json::json!(flags));
            let owner_missing = obj
                .get("owner")
                .map(|v| v.is_null() || v.as_str().map(|s| s.is_empty()).unwrap_or(true))
                .unwrap_or(true);
            if owner_missing {
                if let Some(uid) = obj.get("uid").and_then(|v| v.as_u64()) {
                    if let Some(name) = uid_names.get(&(uid as u32)) {
                        obj.insert("owner".into(), serde_json::json!(name));
                    }
                }
            }
        }
    }

    let mut source = if !files.is_empty() { "scan" } else { "none" };

    let want_latest = q.scan_id.is_none()
        && q.inventory
            .as_deref()
            .map(|s| {
                matches!(
                    s.trim().to_ascii_lowercase().as_str(),
                    "" | "latest" | "current" | "newest" | "1" | "0"
                )
            })
            .unwrap_or(true);
    if is_virtual && want_latest && files.is_empty() {
        let raw = crate::sift_api::load_virtual_files_jsonl(&host);
        if !raw.is_empty() {
            files = raw
                .into_iter()
                .take(limit)
                .map(|e| {
                    serde_json::json!({
                        "path": { "s": e.path },
                        "size": e.size,
                        "mode": e.permissions,
                        "uid": e.uid,
                        "owner": e.owner,
                        "group": e.group,
                        "mtime": e.mtime,
                        "machine_id": e.machine_id,
                    })
                })
                .collect();
            source = "virtual_ingest";
        }
    }

    Ok(Json(serde_json::json!({
        "host_id": id,
        "scan_id": scan_id,
        "inventory": q.inventory.clone().unwrap_or_else(|| "1".into()),
        "source": source,
        "count": files.len(),
        "files": files,
    })))
}

/// Latest scan's open network connections (`socket` observations).
async fn host_connections(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(q): Query<HostInventoryQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let host = state.store.get_host(HostId(id)).await?;
    let limit = q.limit.max(1);
    let (scan_id, rows) = host_kind_rows(
        &state,
        HostId(id),
        "socket",
        limit,
        q.scan_id,
        q.inventory.as_deref(),
    )
    .await?;
    let connections: Vec<serde_json::Value> = rows
        .iter()
        .filter_map(|o| match &o.data {
            Observation::Socket(s) => serde_json::to_value(s).ok(),
            other => serde_json::to_value(other).ok(),
        })
        .collect();
    let source = if scan_id.is_some() {
        "scan"
    } else if host.agent_kind.eq_ignore_ascii_case("virtual") {
        "virtual_ingest"
    } else {
        "none"
    };

    Ok(Json(serde_json::json!({
        "host_id": id,
        "scan_id": scan_id,
        "inventory": q.inventory.clone().unwrap_or_else(|| "1".into()),
        "source": source,
        "count": connections.len(),
        "connections": connections,
    })))
}

fn latest_kind_inventory(
    rows: &[rustmite_store::StoredObservation],
    kind: &str,
) -> (Option<Uuid>, Vec<serde_json::Value>) {
    // Prefer the chronologically last matching row's scan (append order), not
    // max(UUID), so inventory tracks the most recent successful collection.
    let latest_scan = rows
        .iter()
        .rev()
        .find(|o| o.kind == kind)
        .map(|o| o.scan_id.0);
    let Some(scan_id) = latest_scan else {
        return (None, Vec::new());
    };
    let out: Vec<serde_json::Value> = rows
        .iter()
        .filter(|o| o.kind == kind && o.scan_id.0 == scan_id)
        .filter_map(|o| match &o.data {
            Observation::Process(p) => serde_json::to_value(p).ok(),
            Observation::Socket(s) => serde_json::to_value(s).ok(),
            other => serde_json::to_value(other).ok(),
        })
        .collect();
    (Some(scan_id), out)
}

#[derive(Deserialize)]
pub struct ScanBody {
    #[serde(default = "default_check_set")]
    pub check_set: String,
    #[serde(default = "default_priority")]
    pub priority: i32,
}

fn default_check_set() -> String {
    "standard".into()
}
fn default_priority() -> i32 {
    100
}

async fn trigger_scan(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<ScanBody>,
) -> Result<impl IntoResponse, ApiError> {
    let host = state.store.get_host(HostId(id)).await?;
    if host.agent_kind.eq_ignore_ascii_case("virtual") {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "virtual agents cannot be SSH-scanned — push logs via POST /v1/ingest/logs".into(),
        ));
    }
    let job = state
        .store
        .enqueue_scan(EnqueueScan {
            host_id: HostId(id),
            check_set: body.check_set,
            priority: body.priority,
        })
        .await?;
    Ok((StatusCode::ACCEPTED, Json(job)))
}

#[derive(Deserialize)]
pub struct PinKeyBody {
    pub key_type: String,
    pub fingerprint: String,
}

async fn pin_host_key(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<PinKeyBody>,
) -> Result<impl IntoResponse, ApiError> {
    state
        .store
        .pin_host_key(HostKeyPin {
            host_id: HostId(id),
            key_type: body.key_type,
            fingerprint: body.fingerprint,
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct BaselineBody {
    #[serde(default = "default_baseline_name")]
    pub name: String,
    pub payload: serde_json::Value,
}

fn default_baseline_name() -> String {
    "default".into()
}

async fn capture_baseline(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<BaselineBody>,
) -> Result<impl IntoResponse, ApiError> {
    state
        .store
        .upsert_baseline(HostId(id), &body.name, body.payload)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_baseline(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(q): Query<BaselineNameQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let name = q.name.unwrap_or_else(default_baseline_name);
    let b = state.store.get_baseline(HostId(id), &name).await?;
    Ok(Json(b))
}

#[derive(Deserialize)]
pub struct BaselineNameQuery {
    pub name: Option<String>,
}

#[derive(Deserialize)]
pub struct FindingsQuery {
    pub host: Option<Uuid>,
    pub check_id: Option<String>,
    pub severity: Option<String>,
    pub limit: Option<usize>,
}

fn parse_severity(s: &str) -> Option<Severity> {
    match s.to_ascii_lowercase().as_str() {
        "info" => Some(Severity::Info),
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

async fn list_findings(
    State(state): State<AppState>,
    Query(q): Query<FindingsQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let findings = state
        .store
        .list_findings(FindingFilter {
            host_id: q.host.map(HostId),
            severity: q.severity.as_deref().and_then(parse_severity),
            check_id: q.check_id,
            limit: q.limit.unwrap_or(100),
        })
        .await?;
    Ok(Json(findings))
}

async fn clear_findings(State(state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    let purged = state.store.clear_all_findings().await?;
    let _ = state
        .store
        .push_activity(ActivityEvent {
            id: Uuid::new_v4(),
            ts: crate::sys_metrics::utc_now_rfc3339(),
            level: "info".into(),
            kind: "findings.cleared".into(),
            message: format!("cleared {purged} finding(s)"),
            scan_id: None,
            host_id: None,
            node_id: None,
            detail: Some(serde_json::json!({ "purged": purged })),
        })
        .await;
    Ok(Json(serde_json::json!({ "purged": purged })))
}

async fn get_scan(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(state.store.get_scan(ScanId(id)).await?))
}

async fn scan_coverage(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let status = state.store.get_scan(ScanId(id)).await?;
    let meta = status.meta;
    Ok(Json(serde_json::json!({
        "scan_id": id,
        "applicable": meta.as_ref().map(|m| m.applicable_checks).unwrap_or(0),
        "fired": meta.as_ref().map(|m| m.fired).unwrap_or(status.findings.len() as u32),
        "not_applicable": meta.as_ref().map(|m| m.not_applicable).unwrap_or(0),
        "pass": meta.as_ref().map(|m| m.applicable_checks.saturating_sub(m.fired + m.not_applicable)).unwrap_or(0),
        "findings": status.findings.len(),
        "outcome": meta.as_ref().map(|m| format!("{:?}", m.outcome)),
    })))
}

#[derive(Deserialize)]
pub struct HuntBody {
    pub where_expr: String,
    pub match_on: String,
    pub host: Option<Uuid>,
    #[serde(default = "default_hunt_limit")]
    pub limit: usize,
}

fn default_hunt_limit() -> usize {
    1000
}

async fn hunt(
    State(state): State<AppState>,
    Json(body): Json<HuntBody>,
) -> Result<impl IntoResponse, ApiError> {
    let obs = state
        .store
        .list_observations(body.host.map(HostId), body.limit)
        .await?;
    let observations: Vec<Observation> = obs.into_iter().map(|o| o.data).collect();
    // Keep hunt dry-run manifests valid under the catalog [test.expect] gate.
    let toml = format!(
        r#"
id = "RM-HUNT-TEMP"
version = 1
name = "hunt"
type = "custom"
severity = "info"
confidence = "medium"
enabled = true
cost = "trivial"
match = "{}"
where = '''{}'''
title = "hunt hit"
evidence_fields = []
attack = []

[test]
fires_on = ["hostile-catalog"]
silent_on = ["clean-ubuntu2204"]
source = "collector"

[test.expect]
title_contains = "hunt"
"#,
        body.match_on, body.where_expr
    );
    let engine =
        CheckEngine::from_toml(&toml).map_err(|e| ApiError(StatusCode::BAD_REQUEST, e.to_string()))?;
    let hits = engine.evaluate(&observations);
    Ok(Json(hits))
}

#[derive(Deserialize)]
pub struct RplHuntBody {
    /// RPL pipe query (mobipwn-compatible), e.g. `process_name="ssh" | head 50`
    pub query: String,
    pub time_from: Option<String>,
    pub time_to: Option<String>,
    #[serde(default = "default_hunt_limit")]
    pub limit: usize,
}

#[derive(Deserialize)]
pub struct RplHistogramBody {
    pub query: String,
    pub time_from: Option<String>,
    pub time_to: Option<String>,
    /// Bucket width in minutes (default 60).
    #[serde(default = "default_hist_span")]
    pub span_minutes: u32,
}

fn default_hist_span() -> u32 {
    60
}

fn compile_rpl_sql(
    body: &RplHuntBody,
    database: &str,
    apply_limit: bool,
) -> Result<(rustmite_rpl::RplQuery, String), ApiError> {
    let parsed = rustmite_rpl::parse_rpl(&body.query)
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e.to_string()))?;
    let mut sql = rustmite_rpl::generate_clickhouse_sql(
        &parsed,
        database,
        body.time_from.as_deref(),
        body.time_to.as_deref(),
    )
    .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e.to_string()))?;
    if apply_limit && !rustmite_rpl::timechart::should_skip_row_limit(&parsed) {
        sql = rustmite_rpl::apply_row_limit(sql, body.limit.min(10_000) as u32);
    }
    Ok((parsed, sql))
}

fn row_columns(rows: &[serde_json::Value]) -> Vec<String> {
    let mut cols = Vec::new();
    for row in rows.iter().take(50) {
        if let Some(obj) = row.as_object() {
            for k in obj.keys() {
                if !cols.iter().any(|c| c == k) {
                    cols.push(k.clone());
                }
            }
        }
    }
    cols
}

fn detect_viz(query: &str, columns: &[String]) -> &'static str {
    let q = query.to_ascii_lowercase();
    if columns.iter().any(|c| c == "bucket")
        && columns.iter().any(|c| c == "c" || c == "count")
    {
        return "timechart";
    }
    if q.contains("| timechart") {
        return "timechart";
    }
    if q.contains("| stats") {
        return "stats";
    }
    if columns.len() == 1 {
        return "single_value";
    }
    "table"
}

async fn hunt_rpl(
    State(state): State<AppState>,
    Json(body): Json<RplHuntBody>,
) -> Result<impl IntoResponse, ApiError> {
    let db = state
        .clickhouse
        .as_ref()
        .map(|c| c.database().to_string())
        .unwrap_or_else(|| "rustmite".into());
    let (_parsed, sql) = compile_rpl_sql(&body, &db, true)?;

    if let Some(ch) = &state.clickhouse {
        let rows = ch
            .query_json_each_row(&sql)
            .await
            .map_err(|e| ApiError(StatusCode::BAD_GATEWAY, e.to_string()))?;
        let columns = row_columns(&rows);
        let viz = detect_viz(&body.query, &columns);
        return Ok(Json(serde_json::json!({
            "engine": "clickhouse",
            "sql": sql,
            "count": rows.len(),
            "columns": columns,
            "viz": viz,
            "rows": rows,
        })));
    }

    Ok(Json(serde_json::json!({
        "engine": "sql_only",
        "sql": sql,
        "count": 0,
        "columns": [],
        "viz": detect_viz(&body.query, &[]),
        "rows": [],
        "hint": "ClickHouse not connected — run ./dev.sh restart (uses CLICKHOUSE_* in .dev/config.env; default rustmite/rustmite)",
    })))
}

async fn hunt_rpl_compile(
    State(state): State<AppState>,
    Json(body): Json<RplHuntBody>,
) -> Result<impl IntoResponse, ApiError> {
    let db = state
        .clickhouse
        .as_ref()
        .map(|c| c.database().to_string())
        .unwrap_or_else(|| "rustmite".into());
    let (parsed, sql) = compile_rpl_sql(&body, &db, true)?;
    let fields: Vec<&str> = rustmite_rpl::fields::SEARCHABLE_FIELDS
        .iter()
        .map(|f| f.name)
        .collect();
    Ok(Json(serde_json::json!({
        "sql": sql,
        "has_timechart": rustmite_rpl::timechart::should_skip_row_limit(&parsed),
        "fields": fields,
    })))
}

async fn hunt_rpl_fields() -> impl IntoResponse {
    let fields: Vec<serde_json::Value> = rustmite_rpl::fields::SEARCHABLE_FIELDS
        .iter()
        .map(|f| {
            serde_json::json!({
                "name": f.name,
                "column": f.column,
                "numeric": rustmite_rpl::fields::is_numeric_field(f.name),
            })
        })
        .collect();
    Json(serde_json::json!({ "fields": fields }))
}

async fn hunt_rpl_histogram(
    State(state): State<AppState>,
    Json(body): Json<RplHistogramBody>,
) -> Result<impl IntoResponse, ApiError> {
    let parsed = rustmite_rpl::parse_rpl(&body.query)
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e.to_string()))?;
    let db = state
        .clickhouse
        .as_ref()
        .map(|c| c.database().to_string())
        .unwrap_or_else(|| "rustmite".into());
    // Histogram uses the search clause only (pipes like stats/timechart are ignored).
    let mut search_only = parsed;
    search_only.commands.clear();
    let where_sql = rustmite_rpl::generate_events_where_clause(
        &search_only,
        body.time_from.as_deref(),
        body.time_to.as_deref(),
    )
    .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e.to_string()))?;
    let span = body.span_minutes.clamp(1, 24 * 60);
    let sql = format!(
        "SELECT toStartOfInterval(timestamp, INTERVAL {span} MINUTE) AS bucket, count() AS c \
         FROM {db}.events WHERE ({where_sql}) GROUP BY bucket ORDER BY bucket ASC"
    );

    if let Some(ch) = &state.clickhouse {
        let rows = ch
            .query_json_each_row(&sql)
            .await
            .map_err(|e| ApiError(StatusCode::BAD_GATEWAY, e.to_string()))?;
        let buckets: Vec<serde_json::Value> = rows
            .into_iter()
            .map(|r| {
                serde_json::json!({
                    "bucket": r.get("bucket").cloned().unwrap_or(serde_json::Value::Null),
                    "count": r.get("c").cloned().unwrap_or(serde_json::json!(0)),
                })
            })
            .collect();
        return Ok(Json(serde_json::json!({
            "sql": sql,
            "buckets": buckets,
            "span_minutes": span,
        })));
    }

    Ok(Json(serde_json::json!({
        "sql": sql,
        "buckets": [],
        "span_minutes": span,
        "hint": "ClickHouse not connected — check Settings → ClickHouse and ./dev.sh status",
    })))
}

#[derive(Deserialize)]
pub struct NoiseXxBody {
    /// Base64 Noise handshake message from the peer.
    pub message: String,
    /// Handshake step: 1 (client->server first), 2 (server reply consumed by client), 3 (client final).
    pub step: u8,
    /// Optional session id so multi-message XX can be correlated (stateless demo uses ephemeral).
    pub session: Option<String>,
}

/// Stateless demo of Noise XX message processing — returns server reply + peer fingerprint
/// once the handshake finishes. Production should keep HandshakeState in a session map.
async fn noise_xx_step(
    State(state): State<AppState>,
    Json(body): Json<NoiseXxBody>,
) -> Result<impl IntoResponse, ApiError> {
    if !state.noise_xx_enabled {
        return Err(ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "Noise XX disabled".into(),
        ));
    }
    let msg = base64::engine::general_purpose::STANDARD
        .decode(&body.message)
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, format!("base64: {e}")))?;
    let mut server =
        rustmite_transport::NoiseServerHandshake::new(&state.noise_keypair).map_err(|e| {
            ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        })?;
    let mut out = vec![0u8; 2048];
    // For a full multi-round session the state must be retained; here we only acknowledge
    // step semantics and publish the server static fingerprint for clients to pin.
    let _ = (body.step, msg, &mut server, &mut out);
    Ok(Json(serde_json::json!({
        "pattern": rustmite_transport::NOISE_PATTERN,
        "server_fingerprint": state.settings.noise_xx_server_fingerprint,
        "enabled": true,
        "note": "Full XX session state is established per connection; clients must complete e / e,ee,s,es / s,se and pin the server fingerprint",
    })))
}

#[derive(Deserialize)]
pub struct RegisterBody {
    pub id: Uuid,
    pub name: String,
    pub capacity: i32,
    pub version: String,
    /// X25519 public key (hex) for sealing SSH credentials to this node's private key.
    #[serde(default)]
    pub cred_pubkey: Option<String>,
}

async fn node_register(
    State(state): State<AppState>,
    Json(body): Json<RegisterBody>,
) -> Result<impl IntoResponse, ApiError> {
    if let Some(ref hex) = body.cred_pubkey {
        let pubk = rustmite_crypto::CredPublicKey::from_hex(hex).map_err(|e| {
            ApiError(
                StatusCode::BAD_REQUEST,
                format!("invalid cred_pubkey: {e}"),
            )
        })?;
        let mut guard = state.cred_pubkey.write().await;
        let changed = guard.as_ref() != Some(&pubk);
        *guard = Some(pubk);
        if changed {
            // Persist so uploads work after restart even before the next node register.
            let path = rustmite_crypto::default_cred_pub_path();
            if let Err(e) = pubk.write_file(&path) {
                tracing::warn!(error = %e, path = %path.display(), "failed to persist cred.pub");
            } else {
                tracing::info!(
                    path = %path.display(),
                    fingerprint = %pubk.to_hex(),
                    "credential encryption public key registered from scanner node"
                );
            }
        }
    }
    state
        .store
        .register_node(rustmite_store::NodeRegistration {
            id: NodeId(body.id),
            name: body.name,
            capacity: body.capacity,
            version: body.version,
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct LeaseBody {
    pub node_id: Uuid,
    pub capacity: usize,
}

async fn node_lease(
    State(state): State<AppState>,
    Json(body): Json<LeaseBody>,
) -> Result<impl IntoResponse, ApiError> {
    let jobs = state
        .store
        .lease_jobs(NodeId(body.node_id), body.capacity)
        .await?;
    let mut enriched = Vec::new();
    for job in jobs {
        let host = state
            .store
            .list_hosts()
            .await?
            .into_iter()
            .find(|h| h.id == job.host_id);
        let pin = state.store.get_host_key(job.host_id).await.ok().flatten();
        let engine = state.checks.snapshot().await;
        let resolved = state.check_sets.resolve(&job.check_set, &engine).await;
        enriched.push(serde_json::json!({
            "id": job.id,
            "host_id": job.host_id,
            "check_set": job.check_set,
            "priority": job.priority,
            "state": job.state,
            "primary_addr": host.as_ref().and_then(|h| h.primary_addr.clone()),
            "ssh_port": host.as_ref().map(|h| h.ssh_port),
            "host_key_fingerprint": pin.as_ref().map(|p| p.fingerprint.clone()),
            "host_key_type": pin.as_ref().map(|p| p.key_type.clone()),
            "timeouts": host.as_ref().map(|h| &h.timeouts),
            "scan_timeout_secs": host
                .as_ref()
                .and_then(|h| h.timeouts.scan_timeout_secs)
                .or(Some(state.settings.scan_timeout_secs)),
            "ssh_connect_timeout_secs": host
                .as_ref()
                .and_then(|h| h.timeouts.connect_timeout_secs)
                .or(Some(state.settings.ssh_connect_timeout_secs)),
            "ssh_auth_timeout_secs": host
                .as_ref()
                .and_then(|h| h.timeouts.auth_timeout_secs)
                .or(Some(state.settings.ssh_auth_timeout_secs)),
            "ssh_cmd_timeout_secs": host
                .as_ref()
                .and_then(|h| h.timeouts.cmd_timeout_secs)
                .or(Some(state.settings.ssh_cmd_timeout_secs)),
            "ssh_inactivity_timeout_secs": host
                .as_ref()
                .and_then(|h| h.timeouts.inactivity_timeout_secs)
                .or(Some(state.settings.ssh_inactivity_timeout_secs)),
            "ssh_delivery_timeout_secs": host
                .as_ref()
                .and_then(|h| h.timeouts.delivery_timeout_secs)
                .or(Some(state.settings.ssh_delivery_timeout_secs)),
            "ssh_connect_delay_ms": host
                .as_ref()
                .and_then(|h| h.timeouts.connect_delay_ms)
                .or(Some(state.settings.ssh_connect_delay_ms)),
            "ssh_timeout_jitter_pct": state.settings.ssh_timeout_jitter_pct,
            "probe_limits": state.probe_limits.read().await.clone(),
            "ssh_user": host.as_ref().and_then(|h| h.labels.get("ssh_user").cloned()),
            "ssh_auth": host.as_ref().and_then(|h| h.labels.get("ssh_auth").cloned()),
            "ssh_identity": host.as_ref().and_then(|h| h.labels.get("ssh_identity").cloned()),
            "ssh_password_file": host.as_ref().and_then(|h| h.labels.get("ssh_password_file").cloned()),
            // Ciphertext only — nodes decrypt with their private credential key.
            "ssh_identity_box": match host.as_ref().and_then(|h| h.labels.get("ssh_identity")) {
                Some(r) => resolve_lease_cred_box(&state, r).await,
                None => None,
            },
            "ssh_password_box": match host
                .as_ref()
                .and_then(|h| h.labels.get("ssh_password_file"))
            {
                Some(r) => resolve_lease_cred_box(&state, r).await,
                None => None,
            },
            "ssh_sudo": host.as_ref().and_then(|h| {
                h.labels.get("ssh_sudo").map(|v| {
                    matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
                })
            }),
            "ssh_sudo_mode": host.as_ref().and_then(|h| h.labels.get("ssh_sudo_mode").cloned()),
            "ssh_sudo_password_file": host
                .as_ref()
                .and_then(|h| h.labels.get("ssh_sudo_password_file").cloned()),
            "ssh_sudo_password_box": match host
                .as_ref()
                .and_then(|h| h.labels.get("ssh_sudo_password_file"))
            {
                Some(r) => resolve_lease_cred_box(&state, r).await,
                None => None,
            },
            "scan_mode": host.as_ref().and_then(|h| {
                h.labels.get("scan_mode").cloned().or_else(|| {
                    if rustmite_store::is_agentlite_kind(&h.agent_kind) {
                        Some("ssh_commands".into())
                    } else {
                        None
                    }
                })
            }),
            "agent_kind": host.as_ref().map(|h| h.agent_kind.clone()),
            "collect_paths": host.as_ref().and_then(|h| h.labels.get("collect_paths").cloned()),
            "collectors": resolved.collectors,
            "check_ids": resolved.check_ids,
        }));
    }
    Ok(Json(enriched))
}

fn default_outcome_complete() -> String {
    "complete".into()
}

#[derive(Deserialize)]
pub struct ProgressBody {
    pub scan_id: Uuid,
    pub node_id: Uuid,
    pub stage: String,
    #[serde(default)]
    pub pct: Option<u8>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}

async fn node_progress(
    State(state): State<AppState>,
    Json(body): Json<ProgressBody>,
) -> Result<impl IntoResponse, ApiError> {
    let state_s = body.state.as_deref().unwrap_or("running");
    let stage = body.message.as_deref().unwrap_or(body.stage.as_str());
    let _ = body.node_id; // reserved for auth / audit later
    state
        .store
        .update_scan_progress(ScanId(body.scan_id), state_s, Some(stage), body.pct)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct ResultsBody {
    pub scan_id: Uuid,
    pub host_id: Uuid,
    pub node_id: Uuid,
    #[serde(default = "default_outcome_complete")]
    pub outcome: String,
    #[serde(default)]
    pub observations: Vec<Observation>,
    #[serde(default)]
    pub findings: Vec<rustmite_proto::Finding>,
    pub meta: Option<rustmite_proto::ScanMeta>,
    pub presented_host_key: Option<HostKeyPinBody>,
}

#[derive(Deserialize)]
pub struct HostKeyPinBody {
    pub key_type: String,
    pub fingerprint: String,
}

async fn node_results(
    State(state): State<AppState>,
    Json(body): Json<ResultsBody>,
) -> Result<impl IntoResponse, ApiError> {
    if !body.observations.is_empty() {
        state
            .store
            .insert_observations_typed(
                ScanId(body.scan_id),
                HostId(body.host_id),
                "probe",
                body.observations.clone(),
            )
            .await?;

        // Fan observations into ClickHouse `events` so RPL hunts (process_name=…) work.
        if let Some(ch) = state.clickhouse.as_ref() {
            let host_name = state
                .store
                .get_host(HostId(body.host_id))
                .await
                .ok()
                .map(|h| h.display_name)
                .unwrap_or_else(|| body.host_id.to_string());
            let ctx = crate::events_ingest::EventContext {
                host_id: body.host_id,
                host_name: &host_name,
                scan_id: body.scan_id,
                collector: "probe",
                timestamp: &crate::sys_metrics::utc_now_rfc3339(),
            };
            let rows = crate::events_ingest::observations_to_events(&ctx, &body.observations);
            for chunk in rows.chunks(500) {
                if let Err(e) = ch.insert_json_each_row("events", chunk).await {
                    tracing::warn!(error = %e, rows = chunk.len(), "ClickHouse events ingest failed");
                    break;
                }
            }
        }
    }

    // Feed SSH Hunter (authorized_keys + host keys) from this scan's observations.
    if !body.observations.is_empty() {
        let n = ssh_hunter::ingest_observations(
            state.store.as_ref(),
            HostId(body.host_id),
            &body.observations,
            &crate::sys_metrics::utc_now_rfc3339(),
        )
        .await;
        if n > 0 {
            tracing::debug!(host = %body.host_id, keys = n, "SSH Hunter updated from scan results");
            let _ = state
                .store
                .push_activity(ActivityEvent {
                    id: Uuid::new_v4(),
                    ts: crate::sys_metrics::utc_now_rfc3339(),
                    level: "info".into(),
                    kind: "ssh.hunter.ingest".into(),
                    message: format!("SSH Hunter ingested {n} key placement(s) from scan"),
                    scan_id: Some(ScanId(body.scan_id)),
                    host_id: Some(HostId(body.host_id)),
                    node_id: None,
                    detail: Some(serde_json::json!({ "placements": n })),
                })
                .await;
        }
    }

    let mut findings = body.findings;
    let now = crate::sys_metrics::utc_now_rfc3339();
    if findings.is_empty() && !body.observations.is_empty() {
        let check_set = state
            .store
            .get_scan(ScanId(body.scan_id))
            .await
            .ok()
            .and_then(|s| s.job.map(|j| j.check_set))
            .unwrap_or_else(|| "standard".into());
        let resolved = {
            let engine = state.checks.snapshot().await;
            state.check_sets.resolve(&check_set, &engine).await
        };
        let engine = state.checks.snapshot().await;
        let allow: std::collections::HashSet<&str> =
            resolved.check_ids.iter().map(|s| s.as_str()).collect();
        let drafts = if allow.is_empty() {
            engine.evaluate(&body.observations)
        } else {
            engine.evaluate_filtered(&body.observations, Some(&allow))
        };
        findings = drafts
            .into_iter()
            .enumerate()
            .map(|(i, d)| rustmite_proto::Finding {
                id: rustmite_proto::FindingId::new_v7(),
                scan_id: ScanId(body.scan_id),
                host_id: HostId(body.host_id),
                check_id: d.check_id,
                check_version: d.check_version,
                check_type: d.check_type,
                severity: d.severity,
                confidence: d.confidence,
                title: d.title,
                evidence: d.evidence,
                observation_ref: rustmite_proto::ObservationRef {
                    scan_id: ScanId(body.scan_id),
                    seq: i as u32,
                    kind: d.match_kind,
                },
                attack: d.attack,
                first_seen: now.clone(),
                last_seen: now.clone(),
                status: rustmite_proto::FindingStatus::New,
                suppressed_by: None,
                correlation_id: None,
            })
            .collect();
    } else {
        for f in &mut findings {
            if f.first_seen.trim().is_empty() {
                f.first_seen = now.clone();
            }
            if f.last_seen.trim().is_empty() {
                f.last_seen = now.clone();
            }
            if f.scan_id.0.is_nil() {
                f.scan_id = ScanId(body.scan_id);
            }
            if f.host_id.0.is_nil() {
                f.host_id = HostId(body.host_id);
            }
        }
    }

    // modules.lkm re-evaluated: drop stale RM-KERN-0001 (e.g. built-in module FPs) for this host.
    let module_obs_present = body.observations.iter().any(|o| {
        matches!(
            o,
            rustmite_proto::Observation::Module(_) | rustmite_proto::Observation::HiddenModule(_)
        )
    });
    if module_obs_present {
        let _ = state
            .store
            .clear_findings_for_host_checks(HostId(body.host_id), &["RM-KERN-0001"])
            .await;
    }

    // net.sockets re-evaluated: drop stale orphan-listener FPs (non-root fd walk gaps).
    let socket_obs_present = body.observations.iter().any(|o| {
        matches!(
            o,
            rustmite_proto::Observation::Socket(_) | rustmite_proto::Observation::HiddenSocket(_)
        )
    });
    if socket_obs_present {
        let _ = state
            .store
            .clear_findings_for_host_checks(HostId(body.host_id), &["RM-NET-0002"])
            .await;
    }

    if !findings.is_empty() {
        if let Some(wh) = &state.webhook {
            for f in &findings {
                let ev = AlertEvent::from_finding(f);
                if let Err(e) = wh.notify(&ev) {
                    tracing::warn!(error = %e, "webhook notify failed");
                }
            }
        }
        state.store.insert_findings(findings.clone()).await?;
    }

    if let Some(hk) = body.presented_host_key {
        let _ = state
            .store
            .pin_host_key(HostKeyPin {
                host_id: HostId(body.host_id),
                key_type: hk.key_type,
                fingerprint: hk.fingerprint,
            })
            .await;
    }

    // Enrich host OS/kernel from recon.inventory when the probe collected it.
    {
        let mut patch = UpdateHost::default();
        let mut any = false;
        for o in &body.observations {
            let rustmite_proto::Observation::Recon(r) = o else {
                continue;
            };
            if r.category != "host" {
                continue;
            }
            if let Some(serde_json::Value::String(os)) = r.data.get("os") {
                if !os.trim().is_empty() {
                    patch.os = Some(os.clone());
                    any = true;
                }
            }
            if let Some(serde_json::Value::String(id)) = r.data.get("os_id") {
                if !id.trim().is_empty() {
                    patch.os_id = Some(id.clone());
                    any = true;
                }
            }
            if let Some(serde_json::Value::String(ver)) = r.data.get("os_version") {
                if !ver.trim().is_empty() {
                    patch.os_version = Some(ver.clone());
                    any = true;
                }
            }
            if let Some(serde_json::Value::String(rel)) = r.data.get("osrelease") {
                if !rel.trim().is_empty() {
                    patch.kernel = Some(rel.clone());
                    any = true;
                }
            }
        }
        if any {
            let _ = state
                .store
                .update_host(HostId(body.host_id), patch)
                .await;
        }
    }

    let check_set = state
        .store
        .get_scan(ScanId(body.scan_id))
        .await
        .ok()
        .and_then(|s| s.job.map(|j| j.check_set))
        .unwrap_or_else(|| "standard".into());

    if let Some(meta) = body.meta {
        state
            .store
            .complete_scan(CompleteScan {
                scan_id: ScanId(body.scan_id),
                meta,
                outcome: body.outcome.clone(),
            })
            .await?;
    } else {
        use rustmite_proto::{Arch, DeliveryReport, ScanMeta, ScanOutcome};
        let meta = ScanMeta {
            scan_id: ScanId(body.scan_id),
            host_id: HostId(body.host_id),
            node_id: NodeId(body.node_id),
            outcome: match body.outcome.as_str() {
                "host_key_changed" => ScanOutcome::HostKeyChanged {
                    expected: String::new(),
                    got: String::new(),
                },
                "probe_crashed" => ScanOutcome::ProbeCrashed {
                    signal: None,
                    exit: None,
                    stderr_tail: String::new(),
                },
                "timeout" => ScanOutcome::Timeout { elapsed_ms: 0 },
                "auth_failed" => ScanOutcome::AuthFailed {
                    reason: String::new(),
                },
                "delivery_failed" => ScanOutcome::DeliveryFailed {
                    reason: String::new(),
                },
                "unreachable" => ScanOutcome::Unreachable {
                    reason: String::new(),
                },
                "partial" => ScanOutcome::Partial {
                    failed_collectors: vec![],
                },
                "failed" => ScanOutcome::DeliveryFailed {
                    reason: "failed".into(),
                },
                _ => ScanOutcome::Complete,
            },
            delivery: DeliveryReport::default(),
            probe_version: "unknown".into(),
            arch: Arch::Unknown,
            kernel: String::new(),
            os: None,
            os_id: None,
            os_version: None,
            boot_id: String::new(),
            caps: Default::default(),
            collectors: vec![],
            applicable_checks: state.checks.len().await as u32,
            fired: findings.len() as u32,
            not_applicable: 0,
            started_at: String::new(),
            finished_at: String::new(),
            duration_ms: 0,
            bytes_from_probe: 0,
            observation_count: body.observations.len() as u32,
            node_signature: None,
        };
        state
            .store
            .complete_scan(CompleteScan {
                scan_id: ScanId(body.scan_id),
                meta,
                outcome: body.outcome.clone(),
            })
            .await?;
    }

    let failed = matches!(
        body.outcome.as_str(),
        "unreachable"
            | "timeout"
            | "auth_failed"
            | "delivery_failed"
            | "probe_crashed"
            | "host_key_changed"
            | "failed"
    );
    if !failed {
        crate::anomark_api::spawn_post_scan_anomark(
            state.clone(),
            body.host_id,
            body.scan_id,
            &check_set,
        );
    }

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct HeartbeatBody {
    pub node_id: Uuid,
    pub in_flight: i32,
}

async fn node_heartbeat(
    State(state): State<AppState>,
    Json(body): Json<HeartbeatBody>,
) -> Result<impl IntoResponse, ApiError> {
    state
        .store
        .heartbeat_node(NodeId(body.node_id), body.in_flight)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug)]
pub struct ApiError(pub StatusCode, pub String);

impl From<rustmite_store::StoreError> for ApiError {
    fn from(e: rustmite_store::StoreError) -> Self {
        let code = match &e {
            rustmite_store::StoreError::NotFound(_) => StatusCode::NOT_FOUND,
            rustmite_store::StoreError::Conflict(_) => StatusCode::CONFLICT,
            rustmite_store::StoreError::Invalid(_) => StatusCode::BAD_REQUEST,
            rustmite_store::StoreError::Backend(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        Self(code, e.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let body = Json(serde_json::json!({
            "type": "about:blank",
            "title": self.0.canonical_reason().unwrap_or("error"),
            "status": self.0.as_u16(),
            "detail": self.1,
        }));
        (self.0, body).into_response()
    }
}

/// Resolve checks directory for the server binary.
pub fn default_checks_dir() -> PathBuf {
    let cwd = PathBuf::from("checks");
    if cwd.is_dir() {
        return cwd;
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../checks")
}
