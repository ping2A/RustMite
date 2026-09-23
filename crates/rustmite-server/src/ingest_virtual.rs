//! Virtual agent — agentless log ingest from external sinks.

use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use rustmite_store::{HostId, Store, UpdateHost, UpsertHost};
use serde::Deserialize;
use uuid::Uuid;

use crate::routes::{ApiError, AppState};
use crate::sift_api::{
    append_virtual_file_logs, append_virtual_process_logs, host_by_ingest_token,
    import_virtual_feed_data_opts, load_virtual_files_jsonl, load_virtual_jsonl, VirtualIngestKind,
};

/// 1 GiB — browser folder uploads (JSONL day folders) easily exceed tens of MiB
/// once inlined as JSON. The UI also chunks large payloads under this ceiling.
pub const VIRTUAL_INGEST_BODY_LIMIT: usize = 1024 * 1024 * 1024;

#[derive(Debug, Deserialize)]
pub struct InlineIngestFile {
    pub name: String,
    pub content: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateVirtualHostBody {
    pub display_name: String,
    #[serde(default)]
    pub labels: std::collections::BTreeMap<String, String>,
    /// Optional fixed ingest token; generated when omitted.
    #[serde(default)]
    pub ingest_token: Option<String>,
    /// Optional IronSift-style import at create time.
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default = "default_true")]
    pub recursive: bool,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub files: Vec<InlineIngestFile>,
    /// When true (default), record a finished scan snapshot for this import.
    #[serde(default = "default_true")]
    pub create_scan: bool,
    /// Replace (truncate) current virtual JSONL when importing. Default true for
    /// create/update-from-folder flows so re-uploading a day folder refreshes data.
    #[serde(default = "default_true")]
    pub replace: bool,
    /// Named virtual-agent profile id (Settings → Virtual agents). Applies field mapping labels.
    #[serde(default)]
    pub virtual_agent_id: Option<String>,
}

fn default_true() -> bool {
    true
}

pub async fn create_virtual_host(
    State(state): State<AppState>,
    Json(body): Json<CreateVirtualHostBody>,
) -> Result<impl IntoResponse, ApiError> {
    let name = body.display_name.trim();
    if name.is_empty() {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "display_name required".into(),
        ));
    }

    let before = state.store.list_hosts().await?;
    let prev = before.iter().find(|h| h.display_name == name);
    let created = prev.is_none();

    let token = body
        .ingest_token
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| prev.and_then(|h| h.ingest_token.clone()))
        .unwrap_or_else(|| format!("va-{}", Uuid::new_v4()));

    let wants_import = body
        .path
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .is_some()
        || !body.files.is_empty();

    let mut labels = prev
        .map(|h| h.labels.clone())
        .unwrap_or_default();
    for (k, v) in body.labels {
        labels.insert(k, v);
    }
    let mut kind_from_profile: Option<String> = None;
    if let Some(pid) = body
        .virtual_agent_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let profile = state
            .virtual_agents
            .get(pid)
            .await
            .ok_or_else(|| {
                ApiError(
                    StatusCode::BAD_REQUEST,
                    format!("unknown virtual agent profile: {pid}"),
                )
            })?;
        crate::virtual_agents::apply_profile_to_labels(&mut labels, &profile)
            .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e))?;
        kind_from_profile = Some(profile.kind.clone());
    }

    let host = state
        .store
        .upsert_host(UpsertHost {
            id: None,
            tenant_id: Uuid::nil(),
            display_name: name.to_string(),
            primary_addr: None,
            ssh_port: Some(0),
            labels,
            timeouts: Default::default(),
            agent_kind: Some("virtual".into()),
            // Preserve existing token on update unless the caller supplied one.
            ingest_token: if created {
                Some(token.clone())
            } else {
                body.ingest_token
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
            },
        })
        .await?;

    // Ensure auth_status reflects virtual (no SSH health).
    let host = state
        .store
        .update_host(
            host.id,
            UpdateHost {
                auth_status: Some("virtual".into()),
                auth_detail: Some("virtual agent — log ingest only".into()),
                auth_checked_at: Some(crate::sys_metrics::utc_now_rfc3339()),
                agent_kind: Some("virtual".into()),
                ingest_token: host.ingest_token.clone().or(Some(token.clone())),
                ..Default::default()
            },
        )
        .await?;

    let mut import_summary = None;
    let mut import_error = None;
    let mut scan_id = None;
    let mut scan_error = None;
    if wants_import {
        let kind = VirtualIngestKind::parse(
            body.kind
                .as_deref()
                .or(kind_from_profile.as_deref())
                .unwrap_or("auto"),
        );
        let inline: Vec<(String, String)> = body
            .files
            .into_iter()
            .map(|f| (f.name, f.content))
            .collect();
        match import_virtual_feed_data_opts(
            &host,
            body.path.as_deref(),
            body.recursive,
            kind,
            &inline,
            body.replace,
        ) {
            Ok(s) => {
                crate::platform_ch::sync_virtual_host_from_state(&state, host.id.0).await;
                if body.create_scan {
                    match record_virtual_feed_scan(
                        &state,
                        &host,
                        body.path.as_deref().unwrap_or("upload"),
                    )
                    .await
                    {
                        Ok(sid) => scan_id = Some(sid),
                        Err(e) => {
                            tracing::warn!(error = %e, "virtual create: import ok but scan record failed");
                            scan_error = Some(e);
                        }
                    }
                }
                import_summary = Some(s);
            }
            Err(e) => import_error = Some(e),
        }
    }

    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    let token_out = host
        .ingest_token
        .clone()
        .unwrap_or(token);

    Ok((
        status,
        Json(serde_json::json!({
            "host": host,
            "created": created,
            "ingest": {
                "endpoint": "/v1/ingest/logs",
                "authorization": format!("Bearer {token_out}"),
                "ingest_token": token_out,
                "content_type": "application/x-ndjson",
                "example_line": {
                    "name": "sshd",
                    "pid": 1,
                    "ppid": 0,
                    "uid": 0,
                    "path": "/usr/sbin/sshd",
                    "args": "",
                    "timestamp": "2026-01-01T00:00:00Z"
                }
            },
            "import": import_summary,
            "import_error": import_error,
            "scan_id": scan_id,
            "scan_error": scan_error,
        })),
    ))
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())?;
    let t = auth.strip_prefix("Bearer ").unwrap_or(auth).trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

/// Push NDJSON process (or file) logs for a virtual host identified by ingest token.
///
/// Default stream is processes. Set `X-RustMite-Ingest: files` (or `?kind=files`) for file rows.
pub async fn ingest_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<IngestQuery>,
    body: String,
) -> Result<impl IntoResponse, ApiError> {
    let token = bearer_token(&headers).ok_or_else(|| {
        ApiError(
            StatusCode::UNAUTHORIZED,
            "Authorization: Bearer <ingest_token> required".into(),
        )
    })?;
    let host = host_by_ingest_token(state.store.as_ref(), &token).await?;
    let kind = q
        .kind
        .or_else(|| {
            headers
                .get("x-rustmite-ingest")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        })
        .unwrap_or_else(|| "processes".into())
        .to_ascii_lowercase();
    let n = if kind == "files" || kind == "file" {
        append_virtual_file_logs(&host, &body)
    } else {
        append_virtual_process_logs(&host, &body)
    }
    .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e))?;
    crate::platform_ch::sync_virtual_host_from_state(&state, host.id.0).await;
    Ok(Json(serde_json::json!({
        "ok": true,
        "host_id": host.id,
        "display_name": host.display_name,
        "kind": kind,
        "appended": n,
        "path": format!(
            ".dev/ingest/{}/{}.jsonl",
            host.id.0,
            if kind.starts_with("file") { "files" } else { "processes" }
        ),
    })))
}

#[derive(Debug, Deserialize, Default)]
pub struct IngestQuery {
    #[serde(default)]
    pub kind: Option<String>,
}

/// Same as ingest_logs but scoped by host id (token must still match that host).
pub async fn ingest_logs_for_host(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Query(q): Query<IngestQuery>,
    body: String,
) -> Result<impl IntoResponse, ApiError> {
    let token = bearer_token(&headers).ok_or_else(|| {
        ApiError(
            StatusCode::UNAUTHORIZED,
            "Authorization: Bearer <ingest_token> required".into(),
        )
    })?;
    let host = host_by_ingest_token(state.store.as_ref(), &token).await?;
    if host.id != HostId(id) {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "ingest token does not match host id".into(),
        ));
    }
    let kind = q
        .kind
        .or_else(|| {
            headers
                .get("x-rustmite-ingest")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        })
        .unwrap_or_else(|| "processes".into())
        .to_ascii_lowercase();
    let n = if kind == "files" || kind == "file" {
        append_virtual_file_logs(&host, &body)
    } else {
        append_virtual_process_logs(&host, &body)
    }
    .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e))?;
    crate::platform_ch::sync_virtual_host_from_state(&state, host.id.0).await;
    Ok(Json(serde_json::json!({
        "ok": true,
        "host_id": host.id,
        "kind": kind,
        "appended": n,
    })))
}

#[derive(Debug, Deserialize)]
pub struct ImportVirtualFeedBody {
    /// Server-local file or directory (IronSift `--input` / `--ingest-jsonl-dir`).
    #[serde(default)]
    pub path: Option<String>,
    /// Recurse into directories (default true).
    #[serde(default = "default_true")]
    pub recursive: bool,
    /// `auto` | `processes` | `files`
    #[serde(default)]
    pub kind: Option<String>,
    /// Browser-uploaded / pasted file payloads.
    #[serde(default)]
    pub files: Vec<InlineIngestFile>,
    /// Replace existing processes.jsonl / files.jsonl instead of appending.
    #[serde(default)]
    pub replace: bool,
    /// When true (default), record a finished scan so imports appear under Scans.
    #[serde(default = "default_true")]
    pub create_scan: bool,
    /// Optional profile to (re)apply before import — updates host `ingest_map` labels.
    #[serde(default)]
    pub virtual_agent_id: Option<String>,
}

async fn record_virtual_feed_scan(
    state: &AppState,
    host: &rustmite_store::HostRecord,
    source: &str,
) -> Result<Uuid, String> {
    let procs = load_virtual_jsonl(host);
    let files = load_virtual_files_jsonl(host);
    if procs.is_empty() && files.is_empty() {
        return Err("no process/file rows to attach to scan".into());
    }
    crate::ingest_tree::create_virtual_import_scan(
        state,
        host,
        &procs,
        &files,
        &[],
        &format!("feed-import:{source}"),
    )
    .await
}

/// Operator endpoint: feed a virtual agent from raw files or a directory (IronSift-style).
pub async fn import_virtual_feed(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<ImportVirtualFeedBody>,
) -> Result<impl IntoResponse, ApiError> {
    let mut host = state.store.get_host(HostId(id)).await?;
    let mut kind_from_profile: Option<String> = None;
    if let Some(pid) = body
        .virtual_agent_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let profile = state.virtual_agents.get(pid).await.ok_or_else(|| {
            ApiError(
                StatusCode::BAD_REQUEST,
                format!("unknown virtual agent profile: {pid}"),
            )
        })?;
        let mut labels = host.labels.clone();
        crate::virtual_agents::apply_profile_to_labels(&mut labels, &profile)
            .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e))?;
        kind_from_profile = Some(profile.kind.clone());
        host = state
            .store
            .update_host(
                host.id,
                UpdateHost {
                    labels: Some(labels),
                    ..Default::default()
                },
            )
            .await?;
    }
    let kind = VirtualIngestKind::parse(
        body.kind
            .as_deref()
            .or(kind_from_profile.as_deref())
            .unwrap_or("auto"),
    );
    let inline: Vec<(String, String)> = body
        .files
        .into_iter()
        .map(|f| (f.name, f.content))
        .collect();
    let source_label = body
        .path
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("upload")
        .to_string();
    let summary = crate::sift_api::import_virtual_feed_data_opts(
        &host,
        body.path.as_deref(),
        body.recursive,
        kind,
        &inline,
        body.replace,
    )
    .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e))?;
    crate::platform_ch::sync_virtual_host_from_state(&state, host.id.0).await;

    let mut scan_id = None;
    let mut scan_error = None;
    if body.create_scan {
        match record_virtual_feed_scan(&state, &host, &source_label).await {
            Ok(sid) => scan_id = Some(sid),
            Err(e) => {
                tracing::warn!(error = %e, host = %host.display_name, "virtual feed: scan record failed");
                scan_error = Some(e);
            }
        }
    }

    Ok(Json(serde_json::json!({
        "ok": true,
        "host_id": host.id,
        "display_name": host.display_name,
        "summary": summary,
        "scan_id": scan_id,
        "scan_error": scan_error,
        "virtual_agent": host.labels.get(crate::virtual_agents::PROFILE_LABEL_KEY),
    })))
}

/// Nested router with a raised body limit for create/import payloads.
pub fn virtual_ingest_routes() -> Router<AppState> {
    Router::new()
        .route("/v1/hosts/virtual", post(create_virtual_host))
        .route(
            "/v1/hosts/virtual/import-tree",
            post(crate::ingest_tree::import_virtual_tree),
        )
        .route(
            "/v1/hosts/virtual/import-tree-upload",
            post(crate::ingest_tree::import_virtual_tree_upload),
        )
        .route("/v1/hosts/{id}/ingest/import", post(import_virtual_feed))
        .route("/v1/ingest/logs", post(ingest_logs))
        .route("/v1/ingest/logs/{id}", post(ingest_logs_for_host))
        .layer(DefaultBodyLimit::max(VIRTUAL_INGEST_BODY_LIMIT))
}
