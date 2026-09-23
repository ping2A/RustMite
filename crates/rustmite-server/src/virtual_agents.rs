//! Named virtual-agent profiles: JSONL field mappings used when creating / importing hosts.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::ingest_map::{
    map_to_label_value, preview_process_lines, sniff_keys, VirtualIngestMap, LABEL_KEY,
};
use crate::routes::{ApiError, AppState};

pub const PROFILE_LABEL_KEY: &str = "virtual_agent";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VirtualAgentProfile {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Built-in preset this profile started from (`pulsesecure`, `osquery`, `sysmon`, `custom`).
    #[serde(default = "default_preset")]
    pub preset: String,
    #[serde(default)]
    pub map: VirtualIngestMap,
    /// Default ingest kind when importing (`auto` | `processes` | `files`).
    #[serde(default = "default_kind")]
    pub kind: String,
    #[serde(default)]
    pub updated_at: String,
}

fn default_preset() -> String {
    "pulsesecure".into()
}
fn default_kind() -> String {
    "auto".into()
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct VirtualAgentFile {
    #[serde(default = "schema_v1")]
    schema_version: u32,
    #[serde(default)]
    profiles: Vec<VirtualAgentProfile>,
}

fn schema_v1() -> u32 {
    1
}

fn default_path() -> PathBuf {
    PathBuf::from(".dev/virtual-agents.json")
}

fn now_rfc3339() -> String {
    crate::sys_metrics::utc_now_rfc3339()
}

fn seed_profiles() -> Vec<VirtualAgentProfile> {
    let ts = now_rfc3339();
    VirtualIngestMap::presets()
        .into_iter()
        .filter(|(id, _)| *id != "custom")
        .map(|(id, blurb)| {
            let map = VirtualIngestMap::from_preset(id);
            VirtualAgentProfile {
                id: id.to_string(),
                name: match id {
                    "pulsesecure" => "PulseSecure".into(),
                    "osquery" => "osquery / IronSift".into(),
                    "sysmon" => "Sysmon / Windows".into(),
                    _ => id.to_string(),
                },
                description: blurb.to_string(),
                preset: map.preset.clone(),
                map,
                kind: "auto".into(),
                updated_at: ts.clone(),
            }
        })
        .collect()
}

#[derive(Clone)]
pub struct VirtualAgentStore {
    path: PathBuf,
    inner: Arc<RwLock<VirtualAgentFile>>,
}

impl VirtualAgentStore {
    pub fn load_or_create(path: impl AsRef<Path>) -> Self {
        let path = path.as_ref().to_path_buf();
        let file = if path.is_file() {
            match std::fs::read_to_string(&path)
                .ok()
                .and_then(|s| serde_json::from_str::<VirtualAgentFile>(&s).ok())
            {
                Some(mut f) if !f.profiles.is_empty() => {
                    f.schema_version = 1;
                    f
                }
                _ => VirtualAgentFile {
                    schema_version: 1,
                    profiles: seed_profiles(),
                },
            }
        } else {
            VirtualAgentFile {
                schema_version: 1,
                profiles: seed_profiles(),
            }
        };
        let store = Self {
            path: path.clone(),
            inner: Arc::new(RwLock::new(file.clone())),
        };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(raw) = serde_json::to_string_pretty(&file) {
            let _ = std::fs::write(&path, raw);
        }
        store
    }

    async fn persist(&self) -> Result<(), String> {
        let snapshot = {
            let guard = self.inner.read().await;
            guard.clone()
        };
        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| e.to_string())?;
        }
        let raw = serde_json::to_string_pretty(&snapshot).map_err(|e| e.to_string())?;
        tokio::fs::write(&self.path, raw)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn list(&self) -> Vec<VirtualAgentProfile> {
        let guard = self.inner.read().await;
        let mut v = guard.profiles.clone();
        v.sort_by(|a, b| a.name.to_ascii_lowercase().cmp(&b.name.to_ascii_lowercase()));
        v
    }

    pub async fn get(&self, id: &str) -> Option<VirtualAgentProfile> {
        let guard = self.inner.read().await;
        guard.profiles.iter().find(|p| p.id == id).cloned()
    }

    pub async fn upsert(&self, mut profile: VirtualAgentProfile) -> Result<VirtualAgentProfile, String> {
        let id = profile.id.trim();
        if id.is_empty() {
            return Err("id required".into());
        }
        if profile.name.trim().is_empty() {
            return Err("name required".into());
        }
        profile.id = id.to_string();
        profile.updated_at = now_rfc3339();
        profile.map.preset = if profile.preset.trim().is_empty() {
            "custom".into()
        } else {
            profile.preset.trim().to_string()
        };
        {
            let mut guard = self.inner.write().await;
            if let Some(slot) = guard.profiles.iter_mut().find(|p| p.id == profile.id) {
                *slot = profile.clone();
            } else {
                guard.profiles.push(profile.clone());
            }
        }
        self.persist().await?;
        Ok(profile)
    }

    pub async fn delete(&self, id: &str) -> Result<bool, String> {
        let removed = {
            let mut guard = self.inner.write().await;
            let before = guard.profiles.len();
            guard.profiles.retain(|p| p.id != id);
            guard.profiles.len() != before
        };
        if removed {
            self.persist().await?;
        }
        Ok(removed)
    }
}

/// Apply a profile onto host labels (`virtual_agent` + `ingest_map` JSON).
pub fn apply_profile_to_labels(
    labels: &mut BTreeMap<String, String>,
    profile: &VirtualAgentProfile,
) -> Result<(), String> {
    labels.insert(PROFILE_LABEL_KEY.to_string(), profile.id.clone());
    labels.insert(LABEL_KEY.to_string(), map_to_label_value(&profile.map)?);
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct UpsertProfileBody {
    #[serde(default)]
    pub id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub preset: Option<String>,
    #[serde(default)]
    pub map: Option<VirtualIngestMap>,
    #[serde(default)]
    pub kind: Option<String>,
    /// When set, reset `map` from a built-in preset before applying optional `map` overlay.
    #[serde(default)]
    pub from_preset: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PreviewBody {
    pub sample: String,
    #[serde(default)]
    pub map: Option<VirtualIngestMap>,
    #[serde(default)]
    pub profile_id: Option<String>,
    #[serde(default = "default_machine_preview")]
    pub default_machine: String,
    #[serde(default = "default_preview_limit")]
    pub limit: usize,
}

fn default_machine_preview() -> String {
    "preview-host".into()
}
fn default_preview_limit() -> usize {
    12
}

pub fn virtual_agent_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/virtual-agents",
            get(list_profiles).post(create_profile),
        )
        .route("/v1/virtual-agents/presets", get(list_presets))
        .route("/v1/virtual-agents/preview", post(preview_mapping))
        .route(
            "/v1/virtual-agents/{id}",
            get(get_profile).put(update_profile).delete(delete_profile),
        )
}

async fn list_presets() -> impl IntoResponse {
    let presets: Vec<_> = VirtualIngestMap::presets()
        .into_iter()
        .map(|(id, blurb)| {
            serde_json::json!({
                "id": id,
                "description": blurb,
                "map": VirtualIngestMap::from_preset(id),
            })
        })
        .collect();
    Json(serde_json::json!({ "presets": presets }))
}

async fn list_profiles(State(state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(serde_json::json!({
        "profiles": state.virtual_agents.list().await,
    })))
}

async fn get_profile(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
) -> Result<impl IntoResponse, ApiError> {
    let p = state
        .virtual_agents
        .get(&id)
        .await
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, format!("virtual agent {id} not found")))?;
    Ok(Json(p))
}

async fn create_profile(
    State(state): State<AppState>,
    Json(body): Json<UpsertProfileBody>,
) -> Result<impl IntoResponse, ApiError> {
    let id = body
        .id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("va-{}", Uuid::new_v4()));
    if state.virtual_agents.get(&id).await.is_some() {
        return Err(ApiError(
            StatusCode::CONFLICT,
            format!("virtual agent {id} already exists"),
        ));
    }
    let profile = build_profile(id, body)?;
    let saved = state
        .virtual_agents
        .upsert(profile)
        .await
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e))?;
    Ok((StatusCode::CREATED, Json(saved)))
}

async fn update_profile(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<UpsertProfileBody>,
) -> Result<impl IntoResponse, ApiError> {
    if state.virtual_agents.get(&id).await.is_none() {
        return Err(ApiError(
            StatusCode::NOT_FOUND,
            format!("virtual agent {id} not found"),
        ));
    }
    let profile = build_profile(id, body)?;
    let saved = state
        .virtual_agents
        .upsert(profile)
        .await
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e))?;
    Ok(Json(saved))
}

async fn delete_profile(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
) -> Result<impl IntoResponse, ApiError> {
    let removed = state
        .virtual_agents
        .delete(&id)
        .await
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    if !removed {
        return Err(ApiError(
            StatusCode::NOT_FOUND,
            format!("virtual agent {id} not found"),
        ));
    }
    Ok(Json(serde_json::json!({ "ok": true, "id": id })))
}

async fn preview_mapping(
    State(state): State<AppState>,
    Json(body): Json<PreviewBody>,
) -> Result<impl IntoResponse, ApiError> {
    let map = if let Some(m) = body.map {
        m
    } else if let Some(id) = body.profile_id.as_deref() {
        state
            .virtual_agents
            .get(id)
            .await
            .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, format!("virtual agent {id} not found")))?
            .map
    } else {
        VirtualIngestMap::default()
    };
    let keys = sniff_keys(&body.sample, 200);
    let rows = preview_process_lines(
        &body.sample,
        &map,
        &body.default_machine,
        body.limit.max(1).min(50),
    );
    Ok(Json(serde_json::json!({
        "keys": keys,
        "rows": rows,
        "map": map,
    })))
}

fn build_profile(id: String, body: UpsertProfileBody) -> Result<VirtualAgentProfile, ApiError> {
    let mut map = if let Some(preset) = body.from_preset.as_deref().filter(|s| !s.is_empty()) {
        VirtualIngestMap::from_preset(preset)
    } else if let Some(preset) = body.preset.as_deref().filter(|s| !s.is_empty()) {
        VirtualIngestMap::from_preset(preset)
    } else {
        VirtualIngestMap::default()
    };
    if let Some(overlay) = body.map {
        map = overlay;
    }
    let preset = body
        .preset
        .or(body.from_preset)
        .unwrap_or_else(|| map.preset.clone());
    map.preset = if preset == "custom" {
        "custom".into()
    } else {
        preset.clone()
    };
    Ok(VirtualAgentProfile {
        id,
        name: body.name.trim().to_string(),
        description: body.description.trim().to_string(),
        preset,
        map,
        kind: body
            .kind
            .unwrap_or_else(default_kind)
            .trim()
            .to_ascii_lowercase(),
        updated_at: now_rfc3339(),
    })
}
