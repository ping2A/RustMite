//! Operator filesystem browser for picking server-local ingest paths.
//!
//! Roots default to the process cwd plus common data dirs, overridable with
//! `RUSTMITE_FS_ROOTS` (colon- or comma-separated absolute/relative paths).

use std::fs;
use std::path::{Path, PathBuf};

use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::routes::{ApiError, AppState};

const MAX_ENTRIES: usize = 500;

#[derive(Debug, Serialize)]
struct FsRoot {
    path: String,
    label: String,
}

#[derive(Debug, Serialize)]
struct FsEntry {
    name: String,
    path: String,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
}

#[derive(Debug, Serialize)]
struct FsListResponse {
    roots: Vec<FsRoot>,
    path: String,
    parent: Option<String>,
    entries: Vec<FsEntry>,
    dirs_only: bool,
}

#[derive(Debug, Deserialize)]
struct FsListQuery {
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    dirs_only: bool,
}

pub fn fs_browse_routes() -> Router<AppState> {
    Router::new().route("/v1/fs/list", get(list_fs))
}

fn configured_roots() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(raw) = std::env::var("RUSTMITE_FS_ROOTS") {
        for part in raw.split(|c| c == ':' || c == ',') {
            let p = part.trim();
            if p.is_empty() {
                continue;
            }
            out.push(PathBuf::from(p));
        }
    }
    if out.is_empty() {
        if let Ok(cwd) = std::env::current_dir() {
            out.push(cwd);
        }
        for candidate in ["/data", "/var/log", "/tmp", "/Users", "/home"] {
            let p = PathBuf::from(candidate);
            if p.is_dir() {
                out.push(p);
            }
        }
    }
    let mut canon = Vec::new();
    for root in out {
        match root.canonicalize() {
            Ok(c) if c.is_dir() => {
                if !canon.iter().any(|x| x == &c) {
                    canon.push(c);
                }
            }
            _ => {
                // Keep unresolved roots that exist as dirs (rare permission edge).
                if root.is_dir() && !canon.iter().any(|x| x == &root) {
                    canon.push(root);
                }
            }
        }
    }
    canon
}

fn roots_payload(roots: &[PathBuf]) -> Vec<FsRoot> {
    roots
        .iter()
        .map(|p| {
            let path = p.display().to_string();
            let label = p
                .file_name()
                .and_then(|s| s.to_str())
                .map(|s| format!("{s}  ·  {path}"))
                .unwrap_or_else(|| path.clone());
            FsRoot { path, label }
        })
        .collect()
}

fn resolve_requested(raw: &str, roots: &[PathBuf]) -> Result<PathBuf, ApiError> {
    let trimmed = raw.trim();
    let candidate = if trimmed.is_empty() {
        roots
            .first()
            .cloned()
            .ok_or_else(|| ApiError(StatusCode::BAD_REQUEST, "no browseable roots configured".into()))?
    } else {
        let p = PathBuf::from(trimmed);
        if p.is_absolute() {
            p
        } else {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(p)
        }
    };
    let canon = candidate.canonicalize().map_err(|e| {
        ApiError(
            StatusCode::BAD_REQUEST,
            format!("cannot open {}: {e}", candidate.display()),
        )
    })?;
    if !roots.iter().any(|r| canon.starts_with(r)) {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            format!(
                "path is outside allowed roots (set RUSTMITE_FS_ROOTS): {}",
                canon.display()
            ),
        ));
    }
    Ok(canon)
}

fn parent_within_roots(path: &Path, roots: &[PathBuf]) -> Option<String> {
    let parent = path.parent()?;
    if roots.iter().any(|r| parent.starts_with(r) || parent == r) {
        Some(parent.display().to_string())
    } else {
        None
    }
}

fn is_interesting_file(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".jsonl")
        || lower.ends_with(".ndjson")
        || lower.ends_with(".json")
        || lower.ends_with(".csv")
}

async fn list_fs(Query(q): Query<FsListQuery>) -> Result<impl IntoResponse, ApiError> {
    let roots = configured_roots();
    if roots.is_empty() {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "no browseable roots — set RUSTMITE_FS_ROOTS".into(),
        ));
    }
    let path = resolve_requested(q.path.as_deref().unwrap_or(""), &roots)?;
    if !path.is_dir() {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            format!("not a directory: {}", path.display()),
        ));
    }

    let mut entries = Vec::new();
    let rd = fs::read_dir(&path).map_err(|e| {
        ApiError(
            StatusCode::BAD_REQUEST,
            format!("cannot list {}: {e}", path.display()),
        )
    })?;
    for ent in rd.flatten() {
        let name = ent.file_name().to_string_lossy().to_string();
        if name.starts_with('.') {
            continue;
        }
        let meta = match ent.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let full = ent.path();
        let canon = full.canonicalize().unwrap_or(full);
        if !roots.iter().any(|r| canon.starts_with(r)) {
            continue;
        }
        if meta.is_dir() {
            entries.push(FsEntry {
                name,
                path: canon.display().to_string(),
                kind: "dir",
                size: None,
            });
        } else if meta.is_file() && !q.dirs_only {
            entries.push(FsEntry {
                name,
                path: canon.display().to_string(),
                kind: "file",
                size: Some(meta.len()),
            });
        }
        if entries.len() >= MAX_ENTRIES {
            break;
        }
    }

    entries.sort_by(|a, b| match (a.kind, b.kind) {
        ("dir", "file") => std::cmp::Ordering::Less,
        ("file", "dir") => std::cmp::Ordering::Greater,
        _ => {
            let ai = is_interesting_file(&a.name);
            let bi = is_interesting_file(&b.name);
            match (ai, bi) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => a.name.to_ascii_lowercase().cmp(&b.name.to_ascii_lowercase()),
            }
        }
    });

    Ok(Json(FsListResponse {
        roots: roots_payload(&roots),
        path: path.display().to_string(),
        parent: parent_within_roots(&path, &roots),
        entries,
        dirs_only: q.dirs_only,
    }))
}
