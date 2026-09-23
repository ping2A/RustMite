//! Persist AnoMark models + virtual JSONL ingest into ClickHouse (`rm_platform_blobs`).

use std::fs;
use std::path::PathBuf;

use base64::Engine;
use rustmite_sift::PlatformStore;
use tracing::{info, warn};
use uuid::Uuid;

use crate::clickhouse::ClickHouseClient;
use crate::routes::AppState;

pub const KIND_VIRTUAL_PROCESSES: &str = "virtual_processes";
pub const KIND_VIRTUAL_FILES: &str = "virtual_files";
pub const KIND_ANOMARK_TRAINING: &str = "anomark_training";
pub const KIND_ANOMARK_AUTO: &str = "anomark_auto";
pub const KIND_SIFT_DB: &str = "sift_platform_db";

fn ingest_dir() -> PathBuf {
    PathBuf::from(".dev/ingest")
}

/// Remove `.dev/ingest/{host_id}/` if present. Used by [`purge_host_artifacts`].
pub fn remove_virtual_ingest_dir(host_id: Uuid) -> Result<bool, String> {
    let dir = ingest_dir().join(host_id.to_string());
    if !dir.exists() {
        return Ok(false);
    }
    fs::remove_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(true)
}

fn platform_db_path() -> PathBuf {
    PathBuf::from(".dev/sift-platform/db.json")
}

/// Write current on-disk virtual ingest JSONL for a host into ClickHouse.
pub async fn sync_virtual_host(
    ch: &ClickHouseClient,
    host_id: Uuid,
) -> Result<(), crate::clickhouse::ClickHouseError> {
    let dir = ingest_dir().join(host_id.to_string());
    for (kind, name) in [
        (KIND_VIRTUAL_PROCESSES, "processes.jsonl"),
        (KIND_VIRTUAL_FILES, "files.jsonl"),
    ] {
        let path = dir.join(name);
        let payload = if path.is_file() {
            fs::read_to_string(&path).unwrap_or_default()
        } else {
            String::new()
        };
        let lines = payload.lines().filter(|l| !l.trim().is_empty()).count();
        let meta = serde_json::json!({
            "filename": name,
            "lines": lines,
            "bytes": payload.len(),
        });
        ch.upsert_platform_blob(kind, &host_id.to_string(), &meta, &payload)
            .await?;
    }
    Ok(())
}

/// Restore virtual ingest files from ClickHouse when local cache is missing/empty.
pub async fn restore_virtual_host(
    ch: &ClickHouseClient,
    host_id: Uuid,
) -> Result<bool, crate::clickhouse::ClickHouseError> {
    let dir = ingest_dir().join(host_id.to_string());
    let _ = fs::create_dir_all(&dir);
    let mut restored = false;
    for (kind, name) in [
        (KIND_VIRTUAL_PROCESSES, "processes.jsonl"),
        (KIND_VIRTUAL_FILES, "files.jsonl"),
    ] {
        let path = dir.join(name);
        let local_empty = !path.is_file()
            || fs::metadata(&path)
                .map(|m| m.len() == 0)
                .unwrap_or(true);
        if !local_empty {
            continue;
        }
        if let Some((_meta, payload)) = ch.get_platform_blob(kind, &host_id.to_string()).await? {
            if !payload.is_empty() {
                fs::write(&path, payload.as_bytes()).map_err(|e| {
                    crate::clickhouse::ClickHouseError::Msg(format!("restore {name}: {e}"))
                })?;
                restored = true;
                info!(%host_id, file = name, bytes = payload.len(), "restored virtual ingest from ClickHouse");
            }
        }
    }
    Ok(restored)
}

pub async fn sync_virtual_host_from_state(state: &AppState, host_id: Uuid) {
    let Some(ch) = state.clickhouse.as_ref() else {
        return;
    };
    if let Err(e) = sync_virtual_host(ch, host_id).await {
        warn!(error = %e, %host_id, "ClickHouse virtual ingest sync failed");
    }
}

/// Remove all host-scoped artifacts outside the control-plane store.
///
/// Called after [`Store::delete_host`] (which already cascades scans, findings,
/// observations, baselines, activity, and SSH placements). This covers:
/// - on-disk virtual ingest (`.dev/ingest/{host_id}/`)
/// - ClickHouse `rm_platform_blobs` virtual process/file payloads
/// - ClickHouse `events` rows for this host id (and display name when known)
///
/// Virtual-agent *profiles* (Settings) are shared templates and are not deleted.
pub async fn purge_host_artifacts(
    state: &AppState,
    host_id: Uuid,
    display_name: Option<&str>,
) {
    // 1) Local virtual JSONL cache
    match remove_virtual_ingest_dir(host_id) {
        Ok(true) => info!(%host_id, "removed virtual ingest directory"),
        Ok(false) => {}
        Err(e) => warn!(error = %e, %host_id, "failed to remove virtual ingest directory"),
    }

    let Some(ch) = state.clickhouse.as_ref() else {
        return;
    };
    let id = host_id.to_string();

    // 2) Platform blobs keyed by host UUID
    for kind in [KIND_VIRTUAL_PROCESSES, KIND_VIRTUAL_FILES] {
        if let Err(e) = ch.delete_platform_blob(kind, &id).await {
            warn!(error = %e, %host_id, kind, "ClickHouse virtual blob delete failed");
        }
    }

    // 3) Hunt / ingest events (UUID + optional display name used as machine_id)
    if let Err(e) = ch.delete_events_for_host(&id).await {
        warn!(error = %e, %host_id, "ClickHouse events delete failed");
    }
    if let Some(name) = display_name.map(str::trim).filter(|s| !s.is_empty()) {
        if name != id {
            if let Err(e) = ch.delete_events_for_host(name).await {
                warn!(
                    error = %e,
                    %host_id,
                    host_name = %name,
                    "ClickHouse events delete by host_name failed"
                );
            }
        }
    }
}

/// Remove every on-disk virtual ingest directory and matching ClickHouse blobs.
/// Returns how many host directories were removed.
pub async fn purge_all_virtual_ingest(state: &AppState) -> usize {
    let root = ingest_dir();
    let mut n = 0usize;
    if let Ok(rd) = fs::read_dir(&root) {
        for ent in rd.flatten() {
            let path = ent.path();
            if !path.is_dir() {
                continue;
            }
            let id = path
                .file_name()
                .and_then(|s| s.to_str())
                .and_then(|s| Uuid::parse_str(s).ok());
            if let Some(hid) = id {
                match remove_virtual_ingest_dir(hid) {
                    Ok(true) => n += 1,
                    Ok(false) => {}
                    Err(e) => warn!(error = %e, %hid, "virtual ingest purge failed"),
                }
                if let Some(ch) = state.clickhouse.as_ref() {
                    let sid = hid.to_string();
                    for kind in [KIND_VIRTUAL_PROCESSES, KIND_VIRTUAL_FILES] {
                        let _ = ch.delete_platform_blob(kind, &sid).await;
                    }
                }
            } else if let Err(e) = fs::remove_dir_all(&path) {
                warn!(error = %e, path = %path.display(), "virtual ingest purge failed");
            } else {
                n += 1;
            }
        }
    }
    n
}

pub async fn ensure_virtual_local(state: &AppState, host_id: Uuid) {
    let Some(ch) = state.clickhouse.as_ref() else {
        return;
    };
    if let Err(e) = restore_virtual_host(ch, host_id).await {
        warn!(error = %e, %host_id, "ClickHouse virtual ingest restore failed");
    }
}

/// Persist one AnoMark training (record JSON + model.bin base64 + optional training input).
pub async fn sync_anomark_training(
    ch: &ClickHouseClient,
    store: &PlatformStore,
    train_id: &str,
) -> Result<(), crate::clickhouse::ClickHouseError> {
    let rec = store
        .list_anomark_trainings()
        .into_iter()
        .find(|t| t.id == train_id)
        .ok_or_else(|| {
            crate::clickhouse::ClickHouseError::Msg(format!("training {train_id} not in platform db"))
        })?;
    let model_path = store.anomark_train_stored_model_path(train_id);
    let model_b64 = model_path
        .as_ref()
        .filter(|p| p.is_file())
        .and_then(|p| fs::read(p).ok())
        .map(|b| base64::engine::general_purpose::STANDARD.encode(b))
        .unwrap_or_default();
    let training_b64 = store
        .anomark_train_stored_training_data_path(train_id)
        .filter(|p| p.is_file())
        .and_then(|p| fs::read(p).ok())
        .map(|b| base64::engine::general_purpose::STANDARD.encode(b))
        .unwrap_or_default();
    let meta = serde_json::json!({
        "record": rec,
        "has_model": !model_b64.is_empty(),
        "has_training_data": !training_b64.is_empty(),
        "model_bytes": model_b64.len(),
    });
    let payload = serde_json::json!({
        "model_b64": model_b64,
        "training_b64": training_b64,
    })
    .to_string();
    ch.upsert_platform_blob(KIND_ANOMARK_TRAINING, train_id, &meta, &payload)
        .await?;
    info!(%train_id, "AnoMark training persisted to ClickHouse");
    Ok(())
}

pub async fn delete_anomark_training_ch(ch: &ClickHouseClient, train_id: &str) {
    if let Err(e) = ch
        .delete_platform_blob(KIND_ANOMARK_TRAINING, train_id)
        .await
    {
        warn!(error = %e, %train_id, "ClickHouse AnoMark delete failed");
    }
}

/// Restore all AnoMark trainings from ClickHouse into the platform data dir + db.json records.
pub async fn restore_anomark_trainings(
    ch: &ClickHouseClient,
    store: &PlatformStore,
) -> Result<usize, crate::clickhouse::ClickHouseError> {
    let ids = ch.list_platform_blob_ids(KIND_ANOMARK_TRAINING).await?;
    let mut n = 0usize;
    let root = PathBuf::from(".dev/sift-platform");
    for id in ids {
        let Some((meta, payload)) = ch.get_platform_blob(KIND_ANOMARK_TRAINING, &id).await? else {
            continue;
        };
        let Ok(body) = serde_json::from_str::<serde_json::Value>(&payload) else {
            continue;
        };
        let model_b64 = body
            .get("model_b64")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let training_b64 = body
            .get("training_b64")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let out_dir = root.join("anomark-trains").join(&id);
        let _ = fs::create_dir_all(&out_dir);
        if !model_b64.is_empty() {
            if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(model_b64) {
                let _ = fs::write(out_dir.join("model.bin"), bytes);
            }
        }
        if !training_b64.is_empty() {
            if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(training_b64) {
                let _ = fs::write(out_dir.join("training_input.jsonl"), bytes);
            }
        }
        // Re-import record into platform db if missing.
        if let Some(rec_v) = meta.get("record") {
            if let Ok(rec) = serde_json::from_value::<rustmite_sift::AnoMarkTrainRecord>(rec_v.clone())
            {
                let existing = store.list_anomark_trainings();
                if !existing.iter().any(|t| t.id == id) {
                    let _ = store.import_anomark_training_record(rec);
                }
            }
        }
        n += 1;
    }
    if n > 0 {
        info!(count = n, "restored AnoMark trainings from ClickHouse");
    }
    Ok(n)
}

pub async fn sync_anomark_auto(ch: &ClickHouseClient, cfg: &serde_json::Value) {
    if let Err(e) = ch
        .upsert_platform_blob(KIND_ANOMARK_AUTO, "default", cfg, &cfg.to_string())
        .await
    {
        warn!(error = %e, "ClickHouse AnoMark auto config sync failed");
    }
}

pub async fn restore_anomark_auto(ch: &ClickHouseClient) -> Option<serde_json::Value> {
    match ch.get_platform_blob(KIND_ANOMARK_AUTO, "default").await {
        Ok(Some((_meta, payload))) => serde_json::from_str(&payload).ok(),
        _ => None,
    }
}

pub async fn sync_sift_db(ch: &ClickHouseClient) {
    let path = platform_db_path();
    if !path.is_file() {
        return;
    }
    let Ok(raw) = fs::read_to_string(&path) else {
        return;
    };
    let meta = serde_json::json!({ "path": path.display().to_string(), "bytes": raw.len() });
    if let Err(e) = ch
        .upsert_platform_blob(KIND_SIFT_DB, "db.json", &meta, &raw)
        .await
    {
        warn!(error = %e, "ClickHouse sift db.json sync failed");
    }
}

pub async fn restore_sift_db(ch: &ClickHouseClient) -> bool {
    let path = platform_db_path();
    if path.is_file() {
        return false;
    }
    match ch.get_platform_blob(KIND_SIFT_DB, "db.json").await {
        Ok(Some((_m, payload))) if !payload.is_empty() => {
            let _ = fs::create_dir_all(path.parent().unwrap_or_else(|| std::path::Path::new(".")));
            if fs::write(&path, payload.as_bytes()).is_ok() {
                info!("restored sift platform db.json from ClickHouse");
                return true;
            }
            false
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remove_virtual_ingest_dir_deletes_host_folder() {
        let id = Uuid::new_v4();
        let dir = ingest_dir().join(id.to_string());
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("processes.jsonl"), "{\"pid\":1}\n").unwrap();
        assert!(dir.is_dir());
        assert!(remove_virtual_ingest_dir(id).unwrap());
        assert!(!dir.exists());
        assert!(!remove_virtual_ingest_dir(id).unwrap());
    }
}
