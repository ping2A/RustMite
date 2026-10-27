//! Persist AnoMark models + virtual JSONL ingest into ClickHouse (`rm_platform_blobs`).

use std::fs;
use std::path::PathBuf;

use base64::Engine;
use rustmite_sift::PlatformStore;
use tracing::{info, warn};
use uuid::Uuid;

use rustmite_store::{InMemoryStore, Store};

use crate::clickhouse::ClickHouseClient;
use crate::routes::AppState;

pub const KIND_VIRTUAL_PROCESSES: &str = "virtual_processes";
pub const KIND_VIRTUAL_FILES: &str = "virtual_files";
pub const KIND_VIRTUAL_PROVENANCE: &str = "virtual_provenance";
pub const KIND_ANOMARK_TRAINING: &str = "anomark_training";
pub const KIND_SIFT_DB: &str = "sift_platform_db";

/// ClickHouse blob kinds that back virtual ingest (download / reingest).
pub const VIRTUAL_INGEST_BLOB_KINDS: &[&str] = &[
    KIND_VIRTUAL_PROCESSES,
    KIND_VIRTUAL_FILES,
    KIND_VIRTUAL_PROVENANCE,
];

pub fn virtual_blob_filename(kind: &str) -> &'static str {
    match kind {
        KIND_VIRTUAL_PROCESSES => "processes.jsonl",
        KIND_VIRTUAL_FILES => "files.jsonl",
        KIND_VIRTUAL_PROVENANCE => "import_provenance.json",
        _ => "blob.json",
    }
}

pub fn virtual_blob_kind_from_slug(slug: &str) -> Option<&'static str> {
    match slug.trim().to_ascii_lowercase().as_str() {
        "processes" | "process" | "virtual_processes" => Some(KIND_VIRTUAL_PROCESSES),
        "files" | "file" | "virtual_files" => Some(KIND_VIRTUAL_FILES),
        "provenance" | "import_provenance" | "virtual_provenance" => Some(KIND_VIRTUAL_PROVENANCE),
        _ => None,
    }
}

fn blob_meta_lines(meta: &serde_json::Value) -> Option<u32> {
    meta.get("original_lines")
        .or_else(|| meta.get("lines"))
        .and_then(|v| v.as_u64())
        .map(|n| n as u32)
}

fn parse_blob_meta_field(v: &serde_json::Value) -> serde_json::Value {
    if let Some(s) = v.as_str() {
        serde_json::from_str(s).unwrap_or_else(|_| serde_json::json!({}))
    } else if v.is_object() {
        v.clone()
    } else {
        serde_json::json!({})
    }
}

/// Fill `meta.inventory` for older virtual-import scans that predate totals:
/// in-scan counts from observations, true totals from platform-blob line counts.
/// Persists when enriched. Returns true when inventory was written.
pub async fn enrich_virtual_scan_inventory(
    state: &AppState,
    meta: &mut rustmite_proto::ScanMeta,
) -> bool {
    if meta.inventory.is_some() {
        return false;
    }
    if meta.probe_version != "virtual-import" {
        return false;
    }

    let scan_id = meta.scan_id.0;
    let host_id = meta.host_id;
    let obs = match state
        .store
        .list_observations(Some(host_id), 200_000)
        .await
    {
        Ok(rows) => rows,
        Err(_) => return false,
    };
    let mut processes_in_scan = 0u32;
    let mut files_in_scan = 0u32;
    let mut sockets_in_scan = 0u32;
    for o in &obs {
        if o.scan_id.0 != scan_id {
            continue;
        }
        match o.kind.as_str() {
            "process" => processes_in_scan = processes_in_scan.saturating_add(1),
            "file_meta" | "file_entropy" => files_in_scan = files_in_scan.saturating_add(1),
            "socket" | "hidden_socket" => sockets_in_scan = sockets_in_scan.saturating_add(1),
            _ => {}
        }
    }

    let mut processes = processes_in_scan;
    let mut files = files_in_scan;
    let sockets = sockets_in_scan;

    if let Some(ch) = state.clickhouse.as_ref() {
        if let Ok(blobs) = ch.list_platform_blobs_for_id(&host_id.0.to_string()).await {
            for row in blobs {
                let kind = row.get("kind").and_then(|v| v.as_str()).unwrap_or("");
                let meta_v = row
                    .get("meta")
                    .map(parse_blob_meta_field)
                    .unwrap_or_else(|| serde_json::json!({}));
                let Some(lines) = blob_meta_lines(&meta_v) else {
                    continue;
                };
                match kind {
                    KIND_VIRTUAL_PROCESSES => processes = processes.max(lines),
                    KIND_VIRTUAL_FILES => files = files.max(lines),
                    _ => {}
                }
            }
        }
    }

    // Disk / CH preferred counts when the host record is still around.
    if let Ok(host) = state.store.get_host(host_id).await {
        let proc_n = crate::sift_api::virtual_ingest_count_preferred(
            state,
            &host,
            KIND_VIRTUAL_PROCESSES,
        )
        .await as u32;
        let file_n =
            crate::sift_api::virtual_ingest_count_preferred(state, &host, KIND_VIRTUAL_FILES)
                .await as u32;
        processes = processes.max(proc_n).max(processes_in_scan);
        files = files.max(file_n).max(files_in_scan);
    }

    if processes_in_scan == 0 && files_in_scan == 0 && sockets_in_scan == 0 && processes == 0 && files == 0
    {
        return false;
    }

    let inventory = rustmite_proto::ScanInventorySummary {
        processes,
        files,
        sockets,
        processes_in_scan,
        files_in_scan,
        sockets_in_scan,
    };
    meta.inventory = Some(inventory.clone());
    if let Err(e) = state
        .store
        .update_scan_inventory(meta.scan_id, inventory)
        .await
    {
        warn!(error = %e, scan_id = %scan_id, "failed to persist enriched scan inventory");
    }
    true
}

fn ingest_dir() -> PathBuf {
    crate::sift_api::ingest_dir()
}

/// Remove the host virtual-ingest directory if present. Used by [`purge_host_artifacts`].
pub fn remove_virtual_ingest_dir(host_id: Uuid) -> Result<bool, String> {
    let dir = ingest_dir().join(host_id.to_string());
    if !dir.exists() {
        return Ok(false);
    }
    fs::remove_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(true)
}

fn display_name_from_ingest_dir(dir: &std::path::Path) -> String {
    let prov = dir.join("import_provenance.json");
    if let Ok(raw) = fs::read_to_string(&prov) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
            let folder = v
                .get("source_path")
                .and_then(|x| x.as_str())
                .or_else(|| {
                    v.get("folders")
                        .and_then(|x| x.as_array())
                        .and_then(|a| a.first())
                        .and_then(|x| x.as_str())
                })
                .unwrap_or("");
            let base = folder
                .rsplit('/')
                .next()
                .unwrap_or(folder)
                .trim();
            if !base.is_empty() {
                return crate::ingest_tree::resolve_host_name_ex(base, "pulsesecure", None, '-');
            }
        }
    }
    dir.file_name()
        .and_then(|s| s.to_str())
        .map(|s| format!("recovered-{s}"))
        .unwrap_or_else(|| "recovered-host".into())
}

/// Recreate virtual host records for on-disk `ingest/{uuid}/` directories that have
/// JSONL but no matching control-plane host (e.g. after a truncate-before-insert
/// persist failure wiped `cp_entities` while leaving ingest + platform blobs).
pub async fn rehydrate_hosts_from_ingest_dirs(store: &InMemoryStore) -> usize {
    let root = ingest_dir();
    let Ok(rd) = fs::read_dir(&root) else {
        return 0;
    };
    let mut created = 0usize;
    for ent in rd.flatten() {
        let path = ent.path();
        if !path.is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let Ok(hid) = Uuid::parse_str(name) else {
            continue;
        };
        let has_data = path.join("processes.jsonl").is_file() || path.join("files.jsonl").is_file();
        if !has_data {
            continue;
        }
        if store.get_host(rustmite_proto::HostId(hid)).await.is_ok() {
            continue;
        }
        let display_name = display_name_from_ingest_dir(&path);
        let mut labels = std::collections::BTreeMap::new();
        labels.insert("agent".into(), "virtual".into());
        labels.insert("source".into(), "rehydrate:ingest".into());
        match store
            .upsert_host(rustmite_store::UpsertHost {
                id: Some(rustmite_proto::HostId(hid)),
                tenant_id: Uuid::nil(),
                display_name: display_name.clone(),
                primary_addr: None,
                ssh_port: Some(0),
                labels,
                timeouts: Default::default(),
                agent_kind: Some("virtual".into()),
                ingest_token: Some(format!("va-{hid}")),
            })
            .await
        {
            Ok(_) => {
                let _ = store
                    .update_host(
                        rustmite_proto::HostId(hid),
                        rustmite_store::UpdateHost {
                            auth_status: Some("virtual".into()),
                            auth_detail: Some(
                                "rehydrated from on-disk virtual ingest after control-plane loss"
                                    .into(),
                            ),
                            auth_checked_at: Some(crate::sys_metrics::utc_now_rfc3339()),
                            agent_kind: Some("virtual".into()),
                            ..Default::default()
                        },
                    )
                    .await;
                created += 1;
                info!(%hid, %display_name, "rehydrated virtual host from ingest dir");
            }
            Err(e) => warn!(error = %e, %hid, %display_name, "rehydrate upsert failed"),
        }
    }
    if created > 0 {
        store.mark_dirty_public();
        info!(created, "rehydrated virtual hosts from orphaned ingest directories");
    }
    created
}

fn platform_db_path() -> PathBuf {
    PathBuf::from(".dev/sift-platform/db.json")
}

/// Soft ceiling for a single platform-blob payload. Larger JSONL is truncated at a
/// line boundary so import cannot OOM the control plane (JSONEachRow re-escapes
/// the payload and roughly doubles peak RAM).
const MAX_PLATFORM_BLOB_BYTES: usize = 16 * 1024 * 1024;

/// Read a staging file for ClickHouse upsert, truncating huge inventories.
/// Never loads more than [`MAX_PLATFORM_BLOB_BYTES`] (+ one line) into RAM.
fn read_blob_payload(path: &std::path::Path) -> Result<(String, bool, u64, usize), String> {
    use std::io::Read;
    let original_bytes = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if original_bytes == 0 {
        return Ok((String::new(), false, 0, 0));
    }
    if (original_bytes as usize) <= MAX_PLATFORM_BLOB_BYTES {
        let payload = fs::read_to_string(path).map_err(|e| e.to_string())?;
        let lines = payload.lines().filter(|l| !l.trim().is_empty()).count();
        return Ok((payload, false, original_bytes, lines));
    }
    // Cap at line boundary so truncated JSONL stays valid — read only the head.
    let mut f = fs::File::open(path).map_err(|e| e.to_string())?;
    let mut take = vec![0u8; MAX_PLATFORM_BLOB_BYTES];
    let mut n = 0usize;
    while n < take.len() {
        match f.read(&mut take[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.to_string()),
        }
    }
    take.truncate(n);
    let end = take
        .iter()
        .rposition(|b| *b == b'\n')
        .map(|i| i + 1)
        .unwrap_or(take.len());
    let payload = String::from_utf8_lossy(&take[..end]).into_owned();
    let lines = payload.lines().filter(|l| !l.trim().is_empty()).count();
    Ok((payload, true, original_bytes, lines))
}

/// Write current on-disk virtual ingest staging files into ClickHouse blobs.
/// Skips missing local files so an existing durable blob is not wiped empty.
/// Returns `true` when any blob was truncated for size (caller should keep disk).
pub async fn sync_virtual_host(
    ch: &ClickHouseClient,
    host_id: Uuid,
) -> Result<bool, crate::clickhouse::ClickHouseError> {
    let dir = ingest_dir().join(host_id.to_string());
    let mut any_truncated = false;
    for (kind, name) in [
        (KIND_VIRTUAL_PROCESSES, "processes.jsonl"),
        (KIND_VIRTUAL_FILES, "files.jsonl"),
        (KIND_VIRTUAL_PROVENANCE, "import_provenance.json"),
    ] {
        let path = dir.join(name);
        if !path.is_file() {
            continue;
        }
        let (payload, truncated, original_bytes, lines) =
            tokio::task::spawn_blocking({
                let path = path.clone();
                move || read_blob_payload(&path)
            })
            .await
            .map_err(|e| crate::clickhouse::ClickHouseError::Msg(format!("join: {e}")))?
            .map_err(crate::clickhouse::ClickHouseError::Msg)?;
        if payload.is_empty() {
            continue;
        }
        if truncated {
            any_truncated = true;
            warn!(
                %host_id,
                file = name,
                original_bytes,
                stored_bytes = payload.len(),
                "virtual ingest blob truncated for ClickHouse size cap"
            );
        }
        let meta = serde_json::json!({
            "filename": name,
            "lines": lines,
            "bytes": payload.len(),
            "original_bytes": original_bytes,
            "truncated": truncated,
            "max_blob_bytes": MAX_PLATFORM_BLOB_BYTES,
        });
        ch.upsert_platform_blob(kind, &host_id.to_string(), &meta, &payload)
            .await?;
        // Drop payload before the next large file.
        drop(payload);
        tokio::task::yield_now().await;
    }
    Ok(any_truncated)
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
    // Hunt index streams from on-disk JSONL first (bounded memory). Doing this
    // before the platform-blob upsert avoids loading multi‑hundred‑MB files into
    // RAM twice (disk → CH JSON string → CH read-back).
    if let Err(e) = index_virtual_host_events(state.store.as_ref(), ch, host_id, true).await {
        warn!(error = %e, %host_id, "ClickHouse virtual events index failed");
    }
    let truncated = match sync_virtual_host(ch, host_id).await {
        Ok(t) => t,
        Err(e) => {
            warn!(error = %e, %host_id, "ClickHouse virtual ingest sync failed");
            return;
        }
    };
    // Keep local staging when the CH blob was truncated — Fleet Sift / download
    // can still use the full on-disk JSONL via the disk fallback path.
    if truncated {
        info!(
            %host_id,
            "kept local virtual ingest cache (ClickHouse blob truncated for size)"
        );
        return;
    }
    match remove_virtual_ingest_dir(host_id) {
        Ok(true) => info!(%host_id, "purged local virtual ingest cache after ClickHouse sync"),
        Ok(false) => {}
        Err(e) => warn!(error = %e, %host_id, "failed to purge local virtual ingest cache"),
    }
}

/// Rebuild Hunt events (+ optional virtual-import scan) from ClickHouse blobs.
pub async fn reingest_virtual_host_from_blobs(
    state: &AppState,
    host_id: Uuid,
) -> Result<serde_json::Value, String> {
    let Some(ch) = state.clickhouse.as_ref() else {
        return Err("ClickHouse not configured".into());
    };
    let host = state
        .store
        .get_host(rustmite_proto::HostId(host_id))
        .await
        .map_err(|e| e.to_string())?;
    let mut blobs = Vec::new();
    for kind in VIRTUAL_INGEST_BLOB_KINDS {
        match ch.get_platform_blob(kind, &host_id.to_string()).await {
            Ok(Some((meta, payload))) if !payload.is_empty() => {
                blobs.push(serde_json::json!({
                    "kind": kind,
                    "filename": virtual_blob_filename(kind),
                    "bytes": payload.len(),
                    "lines": meta.get("lines").cloned().unwrap_or(serde_json::json!(null)),
                }));
            }
            Ok(_) => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    if blobs.is_empty() {
        return Err("no virtual ingest blobs in ClickHouse for this host".into());
    }
    index_virtual_host_events(state.store.as_ref(), ch, host_id, true)
        .await
        .map_err(|e| e.to_string())?;
    let scan_rebuilt = rebuild_virtual_import_scan(state, &host)
        .await
        .unwrap_or(false);
    Ok(serde_json::json!({
        "ok": true,
        "host_id": host_id,
        "blobs": blobs,
        "scan_rebuilt": scan_rebuilt,
    }))
}

/// After control-plane loss / rehydrate: ensure each virtual host has
/// platform blobs + a virtual-import scan + Hunt `events` in ClickHouse.
pub async fn ensure_virtual_fleet_in_clickhouse(state: &AppState) {
    let Some(ch) = state.clickhouse.as_ref() else {
        return;
    };
    let Ok(hosts) = state.store.list_hosts().await else {
        return;
    };
    let scans = state.store.list_scans(20_000).await.unwrap_or_default();
    let mut repaired_scans = 0usize;
    let mut indexed = 0usize;
    let mut synced_blobs = 0usize;

    for h in hosts {
        let is_v = h.agent_kind.eq_ignore_ascii_case("virtual")
            || h.auth_status
                .as_deref()
                .map(|s| s.eq_ignore_ascii_case("virtual"))
                .unwrap_or(false);
        if !is_v {
            continue;
        }
        let hid = h.id.0;

        // 1) Platform blobs (durable JSONL copies in ClickHouse).
        let need_blob = match ch
            .get_platform_blob(KIND_VIRTUAL_PROCESSES, &hid.to_string())
            .await
        {
            Ok(None) => true,
            Ok(Some(_)) => false,
            Err(_) => true,
        };
        if need_blob {
            match sync_virtual_host(ch, hid).await {
                Ok(_) => synced_blobs += 1,
                Err(e) => warn!(error = %e, %hid, "ClickHouse blob sync failed"),
            }
        }

        // 2) Control-plane virtual-import scan (observations + scan meta).
        let has_scan = scans.iter().any(|s| {
            let hid_match = s
                .job
                .as_ref()
                .map(|j| j.host_id == h.id)
                .or_else(|| s.meta.as_ref().map(|m| m.host_id == h.id))
                .unwrap_or(false);
            let virtual_set = s
                .job
                .as_ref()
                .map(|j| j.check_set == "virtual-import")
                .or_else(|| {
                    s.meta
                        .as_ref()
                        .map(|m| m.probe_version == "virtual-import")
                })
                .unwrap_or(false);
            hid_match && virtual_set
        });
        if !has_scan {
            match rebuild_virtual_import_scan(state, &h).await {
                Ok(true) => repaired_scans += 1,
                Ok(false) => {}
                Err(e) => warn!(error = %e, %hid, host = %h.display_name, "scan rebuild failed"),
            }
            // Let the store flusher persist this scan before the next heavy host.
            tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        }

        // 3) Hunt events — only fill missing/tiny indexes here. Stale file caps
        // (old 5k vs 50k) are upgraded slowly afterward so boot cannot OOM.
        let existing = virtual_events_count(ch, &hid.to_string())
            .await
            .unwrap_or(0);
        if existing < 400 {
            match index_virtual_host_events(state.store.as_ref(), ch, hid, false).await {
                Ok(()) => indexed += 1,
                Err(e) => warn!(error = %e, %hid, "Hunt events index failed"),
            }
        } else {
            indexed += 1;
        }

        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }

    info!(
        synced_blobs,
        repaired_scans,
        indexed,
        "ClickHouse virtual fleet repair finished"
    );
}

/// Upgrade virtual hosts whose Hunt `file_meta` index is still on the old 5k cap.
/// One host at a time with a cool-down so the control plane stays responsive.
pub async fn upgrade_stale_virtual_hunt_indexes(state: &AppState) {
    let Some(ch) = state.clickhouse.as_ref() else {
        return;
    };
    let Ok(hosts) = state.store.list_hosts().await else {
        return;
    };
    let mut upgraded = 0usize;
    let mut skipped = 0usize;
    for h in hosts {
        let is_v = h.agent_kind.eq_ignore_ascii_case("virtual")
            || h.auth_status
                .as_deref()
                .map(|s| s.eq_ignore_ascii_case("virtual"))
                .unwrap_or(false);
        if !is_v {
            continue;
        }
        let hid = h.id.0;
        let indexed_files = virtual_events_kind_count(ch, &hid.to_string(), "file_meta")
            .await
            .unwrap_or(0);
        let expected_files = expected_hunt_file_events(ch, hid).await;
        if expected_files == 0 || indexed_files + 200 >= expected_files {
            skipped += 1;
            continue;
        }
        info!(
            %hid,
            host = %h.display_name,
            indexed_files,
            expected_files,
            "upgrading stale Hunt file index"
        );
        match index_virtual_host_events(state.store.as_ref(), ch, hid, true).await {
            Ok(()) => upgraded += 1,
            Err(e) => warn!(error = %e, %hid, "stale Hunt file index upgrade failed"),
        }
        // Pace ~50k-row hosts so RSS / ClickHouse mutations do not kill the process.
        tokio::time::sleep(std::time::Duration::from_secs(20)).await;
    }
    info!(upgraded, skipped, "stale Hunt file index upgrade finished");
}

async fn rebuild_virtual_import_scan(
    state: &AppState,
    host: &rustmite_store::HostRecord,
) -> Result<bool, String> {
    let proc_total = crate::sift_api::virtual_ingest_count_preferred(
        state,
        host,
        KIND_VIRTUAL_PROCESSES,
    )
    .await;
    let file_total =
        crate::sift_api::virtual_ingest_count_preferred(state, host, KIND_VIRTUAL_FILES).await;
    // Cap rows embedded in the control-plane scan (full inventory stays in CH blobs).
    let mut procs = crate::sift_api::load_virtual_jsonl_preferred(state, host).await;
    if procs.len() > 5_000 {
        procs.truncate(5_000);
    }
    let files =
        crate::sift_api::load_virtual_files_jsonl_preferred(state, host, 1_500).await;
    if procs.is_empty() && files.is_empty() {
        return Ok(false);
    }
    let (folders, file_names) =
        crate::sift_api::load_virtual_import_provenance_preferred(state, host).await;
    let source = folders
        .first()
        .map(|f| format!("rehydrate:{f}"))
        .unwrap_or_else(|| format!("rehydrate:{}", host.display_name));
    let sid = crate::ingest_tree::create_virtual_import_scan_with_provenance(
        state,
        host,
        &procs,
        &files,
        &[],
        &source,
        &folders,
        &file_names,
        &[],
        Some(crate::ingest_tree::VirtualImportInventoryTotals {
            processes: proc_total.max(procs.len()),
            files: file_total.max(files.len()),
            sockets: 0,
        }),
    )
    .await?;
    info!(
        host_id = %host.id.0,
        host = %host.display_name,
        scan_id = %sid,
        processes = procs.len(),
        processes_total = proc_total,
        files = files.len(),
        files_total = file_total,
        "rebuilt virtual-import scan into control plane / ClickHouse"
    );
    Ok(true)
}

/// Soft cap for Hunt `file_meta` rows per virtual host (full inventory stays in blobs).
const MAX_HUNT_FILE_EVENTS: usize = 50_000;

/// Count existing virtual-ingest hunt rows for a host (UUID or display name).
async fn virtual_events_count(
    ch: &ClickHouseClient,
    host_key: &str,
) -> Result<u64, crate::clickhouse::ClickHouseError> {
    let hid = host_key.replace('\\', "\\\\").replace('\'', "\\'");
    let raw = ch
        .query_raw(&format!(
            "SELECT count() FROM events WHERE (host_id = '{hid}' OR host_name = '{hid}') \
             AND source = 'virtual_ingest'"
        ))
        .await?;
    Ok(raw.trim().parse().unwrap_or(0))
}

/// Count virtual-ingest hunt rows of one kind for a host (UUID or display name).
async fn virtual_events_kind_count(
    ch: &ClickHouseClient,
    host_key: &str,
    kind: &str,
) -> Result<u64, crate::clickhouse::ClickHouseError> {
    let hid = host_key.replace('\\', "\\\\").replace('\'', "\\'");
    let kind_esc = kind.replace('\\', "\\\\").replace('\'', "\\'");
    let raw = ch
        .query_raw(&format!(
            "SELECT count() FROM events WHERE (host_id = '{hid}' OR host_name = '{hid}') \
             AND source = 'virtual_ingest' AND kind = '{kind_esc}'"
        ))
        .await?;
    Ok(raw.trim().parse().unwrap_or(0))
}

/// Expected Hunt file_meta rows for this host: min(blob/disk lines, MAX_HUNT_FILE_EVENTS).
async fn expected_hunt_file_events(ch: &ClickHouseClient, host_id: Uuid) -> u64 {
    let cap = MAX_HUNT_FILE_EVENTS as u64;
    if let Ok(blobs) = ch.list_platform_blobs_for_id(&host_id.to_string()).await {
        for row in blobs {
            if row.get("kind").and_then(|v| v.as_str()) != Some(KIND_VIRTUAL_FILES) {
                continue;
            }
            let meta_v = row
                .get("meta")
                .map(parse_blob_meta_field)
                .unwrap_or_else(|| serde_json::json!({}));
            if let Some(lines) = blob_meta_lines(&meta_v) {
                return (lines as u64).min(cap);
            }
        }
    }
    // Fallback when blob meta has no line count: approximate from local JSONL size.
    let file_path = ingest_dir().join(host_id.to_string()).join("files.jsonl");
    if let Ok(meta) = tokio::fs::metadata(&file_path).await {
        // ~250 bytes/line typical for PulseSecure file trees.
        return (meta.len() / 250).max(1).min(cap);
    }
    0
}

/// True when ClickHouse already has hunt rows for this virtual host (skip boot restore).
pub async fn virtual_host_events_present(ch: &ClickHouseClient, host_id: Uuid) -> bool {
    match virtual_events_count(ch, &host_id.to_string()).await {
        Ok(n) if n > 0 => true,
        _ => false,
    }
}

/// Replace ClickHouse virtual-ingest `events` rows for a host from platform blobs
/// (preferred) or on-disk JSONL fallback.
///
/// Streams JSONL → event rows → ClickHouse in small chunks so PulseSecure day
/// trees (~40–50k files/host) do not OOM the control plane.
///
/// When `force` is false, skip work if hunt rows already exist (fast docker upgrades).
pub async fn index_virtual_host_events(
    store: &InMemoryStore,
    ch: &ClickHouseClient,
    host_id: Uuid,
    force: bool,
) -> Result<(), crate::clickhouse::ClickHouseError> {
    let host = match store.get_host(rustmite_proto::HostId(host_id)).await {
        Ok(h) => h,
        Err(_) => return Ok(()),
    };
    ch.ensure_events_schema().await?;

    if !force {
        let host_key = host_id.to_string();
        let existing = virtual_events_count(ch, &host_key).await.unwrap_or(0);
        let by_name = if existing == 0 && host.display_name.trim() != host_key.as_str() {
            virtual_events_count(ch, host.display_name.trim())
                .await
                .unwrap_or(0)
        } else {
            0
        };
        let total = existing + by_name;
        // Tiny leftover counts are treated as incomplete (prior crash mid-index).
        if total >= 400 {
            let indexed_files = virtual_events_kind_count(ch, &host_key, "file_meta")
                .await
                .unwrap_or(0);
            let indexed_files = if indexed_files == 0 && by_name > 0 {
                virtual_events_kind_count(ch, host.display_name.trim(), "file_meta")
                    .await
                    .unwrap_or(0)
            } else {
                indexed_files
            };
            let expected_files = expected_hunt_file_events(ch, host_id).await;
            // Stale indexes from the old 5k file cap must be rebuilt up to 50k.
            let files_complete =
                expected_files == 0 || indexed_files + 200 >= expected_files;
            if files_complete {
                info!(
                    %host_id,
                    events = total,
                    indexed_files,
                    expected_files,
                    "virtual ingest events already present — skip reindex"
                );
                return Ok(());
            }
            info!(
                %host_id,
                events = total,
                indexed_files,
                expected_files,
                "virtual ingest file index incomplete — reindex"
            );
        }
    }

    let _ = ch
        .delete_virtual_events_for_host(&host_id.to_string())
        .await;
    if host.display_name.trim() != host_id.to_string() {
        let _ = ch
            .delete_virtual_events_for_host(&host.display_name)
            .await;
    }

    let dir = ingest_dir().join(host_id.to_string());
    let proc_path = dir.join("processes.jsonl");
    let file_path = dir.join("files.jsonl");
    // Prefer on-disk JSONL when present (streaming, bounded memory). Only pull the
    // full platform blob from ClickHouse when the local staging cache was purged.
    let (procs_n, proc_events) = if proc_path.is_file() {
        stream_jsonl_events_to_ch(
            ch,
            &proc_path,
            None,
            |line| parse_process_event_line(host_id, &host.display_name, line),
        )
        .await?
    } else {
        match ch
            .get_platform_blob(KIND_VIRTUAL_PROCESSES, &host_id.to_string())
            .await
        {
            Ok(Some((_, payload))) if !payload.is_empty() => {
                stream_payload_events_to_ch(ch, &payload, None, |line| {
                    parse_process_event_line(host_id, &host.display_name, line)
                })
                .await?
            }
            _ => (0, 0),
        }
    };
    // Cap Hunt file_meta rows — full inventory lives in rm_platform_blobs / local JSONL.
    // Streaming keeps peak RAM bounded; still soft-cap so a huge fleet cannot explode `events`.
    let (files_n, file_events) = if file_path.is_file() {
        stream_jsonl_events_to_ch(
            ch,
            &file_path,
            Some(MAX_HUNT_FILE_EVENTS),
            |line| parse_file_event_line(host_id, &host.display_name, line),
        )
        .await?
    } else {
        match ch
            .get_platform_blob(KIND_VIRTUAL_FILES, &host_id.to_string())
            .await
        {
            Ok(Some((_, payload))) if !payload.is_empty() => {
                stream_payload_events_to_ch(ch, &payload, Some(MAX_HUNT_FILE_EVENTS), |line| {
                    parse_file_event_line(host_id, &host.display_name, line)
                })
                .await?
            }
            _ => (0, 0),
        }
    };

    let mut events = proc_events + file_events;

    // Fallback: scan observations when local JSONL is empty.
    if events == 0 {
        if let Ok(obs) = store
            .list_observations(Some(rustmite_proto::HostId(host_id)), 50_000)
            .await
        {
            let now = crate::sys_metrics::utc_now_rfc3339();
            let mut by_scan: std::collections::HashMap<
                Uuid,
                Vec<rustmite_proto::Observation>,
            > = std::collections::HashMap::new();
            for o in obs {
                if matches!(
                    o.kind.as_str(),
                    "process" | "file_meta" | "file_entropy" | "socket"
                ) {
                    by_scan.entry(o.scan_id.0).or_default().push(o.data);
                }
            }
            let mut buf: Vec<serde_json::Value> = Vec::with_capacity(500);
            for (scan_id, observations) in by_scan {
                let ctx = crate::events_ingest::EventContext {
                    host_id,
                    host_name: &host.display_name,
                    scan_id,
                    collector: "virtual.import",
                    timestamp: &now,
                };
                for row in crate::events_ingest::observations_to_events(&ctx, &observations) {
                    let mut row = row;
                    if let Some(obj) = row.as_object_mut() {
                        obj.insert("source".into(), serde_json::json!("virtual_ingest"));
                        obj.insert(
                            "source_type".into(),
                            serde_json::json!("rustmite_virtual"),
                        );
                    }
                    buf.push(row);
                    if buf.len() >= 500 {
                        events += ch.insert_json_each_row("events", &buf).await?;
                        buf.clear();
                        tokio::task::yield_now().await;
                    }
                }
            }
            if !buf.is_empty() {
                events += ch.insert_json_each_row("events", &buf).await?;
            }
        }
    }

    info!(
        %host_id,
        processes = procs_n,
        files = files_n,
        events,
        "indexed virtual ingest into ClickHouse events"
    );
    Ok(())
}

fn parse_process_event_line(
    host_id: Uuid,
    host_name: &str,
    line: &str,
) -> Option<serde_json::Value> {
    let machine = host_name;
    let entry = if let Ok(mut row) = serde_json::from_str::<rustmite_sift::RawLogEntry>(line) {
        if row.machine_id.trim().is_empty() {
            row.machine_id = machine.to_string();
        }
        row
    } else if let Ok(mut row) = rustmite_sift::parse_jsonl_process_line(line, machine) {
        if row.machine_id.trim().is_empty() {
            row.machine_id = machine.to_string();
        }
        row
    } else {
        return None;
    };
    crate::events_ingest::virtual_processes_to_events(host_id, host_name, &[entry]).pop()
}

fn parse_file_event_line(
    host_id: Uuid,
    host_name: &str,
    line: &str,
) -> Option<serde_json::Value> {
    let machine = host_name;
    let entry = if let Ok(mut row) = serde_json::from_str::<rustmite_sift::RawFileEntry>(line) {
        if row.machine_id.trim().is_empty() {
            row.machine_id = machine.to_string();
        }
        row
    } else if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
        let path = v
            .get("path")
            .or_else(|| v.get("file"))
            .or_else(|| v.get("file_path"))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if path.is_empty() {
            return None;
        }
        rustmite_sift::RawFileEntry {
            machine_id: v
                .get("machine_id")
                .or_else(|| v.get("host"))
                .and_then(|x| x.as_str())
                .unwrap_or(machine)
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
        }
    } else {
        return None;
    };
    crate::events_ingest::virtual_files_to_events(host_id, host_name, &[entry]).pop()
}

/// Stream a JSONL payload (from platform blob) into ClickHouse `events`.
async fn stream_payload_events_to_ch<F>(
    ch: &ClickHouseClient,
    payload: &str,
    max_events: Option<usize>,
    mut map_line: F,
) -> Result<(usize, usize), crate::clickhouse::ClickHouseError>
where
    F: FnMut(&str) -> Option<serde_json::Value>,
{
    let mut lines_n = 0usize;
    let mut events_n = 0usize;
    let mut buf: Vec<serde_json::Value> = Vec::with_capacity(500);
    for line in payload.lines() {
        if max_events.is_some_and(|m| events_n + buf.len() >= m) {
            break;
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        lines_n += 1;
        if let Some(row) = map_line(line) {
            buf.push(row);
        }
        if buf.len() >= 200 {
            events_n += ch.insert_json_each_row("events", &buf).await?;
            buf.clear();
            tokio::task::yield_now().await;
            tokio::time::sleep(std::time::Duration::from_millis(15)).await;
        }
    }
    flush_event_buf(ch, &mut buf, max_events, &mut events_n).await?;
    Ok((lines_n, events_n))
}

/// Stream a JSONL file into ClickHouse `events` line-by-line (bounded memory).
/// When `max_events` is set, stop after that many inserted event rows.
async fn stream_jsonl_events_to_ch<F>(
    ch: &ClickHouseClient,
    path: &std::path::Path,
    max_events: Option<usize>,
    mut map_line: F,
) -> Result<(usize, usize), crate::clickhouse::ClickHouseError>
where
    F: FnMut(&str) -> Option<serde_json::Value>,
{
    use std::io::{BufRead, BufReader};

    if !path.is_file() {
        return Ok((0, 0));
    }
    let file = fs::File::open(path).map_err(|e| {
        crate::clickhouse::ClickHouseError::Msg(format!("open {}: {e}", path.display()))
    })?;
    let reader = BufReader::new(file);
    let mut lines_n = 0usize;
    let mut events_n = 0usize;
    let mut buf: Vec<serde_json::Value> = Vec::with_capacity(200);
    for line in reader.lines() {
        if max_events.is_some_and(|m| events_n + buf.len() >= m) {
            break;
        }
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                return Err(crate::clickhouse::ClickHouseError::Msg(format!(
                    "read {}: {e}",
                    path.display()
                )));
            }
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        lines_n += 1;
        if let Some(row) = map_line(line) {
            buf.push(row);
        }
        if buf.len() >= 200 {
            events_n += ch.insert_json_each_row("events", &buf).await?;
            buf.clear();
            tokio::task::yield_now().await;
            tokio::time::sleep(std::time::Duration::from_millis(15)).await;
        }
    }
    flush_event_buf(ch, &mut buf, max_events, &mut events_n).await?;
    Ok((lines_n, events_n))
}

async fn flush_event_buf(
    ch: &ClickHouseClient,
    buf: &mut Vec<serde_json::Value>,
    max_events: Option<usize>,
    events_n: &mut usize,
) -> Result<(), crate::clickhouse::ClickHouseError> {
    if buf.is_empty() {
        return Ok(());
    }
    if let Some(m) = max_events {
        let room = m.saturating_sub(*events_n);
        if room == 0 {
            buf.clear();
            return Ok(());
        } else if buf.len() > room {
            buf.truncate(room);
        }
    }
    if !buf.is_empty() {
        *events_n += ch.insert_json_each_row("events", buf).await?;
        buf.clear();
    }
    Ok(())
}

/// Remove all host-scoped artifacts outside the control-plane store.
///
/// Called after [`Store::delete_host`] (which already cascades scans, findings,
/// observations, baselines, activity, and SSH placements). This covers:
/// - on-disk virtual ingest (`ingest/{host_id}/`)
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
    for kind in VIRTUAL_INGEST_BLOB_KINDS {
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
/// Returns how many host directories / blob hosts were purged.
///
/// ClickHouse blobs are **hard-deleted** + optimized so Data tab size drops;
/// soft-deletes alone leave payload bytes in `system.parts`.
pub async fn purge_all_virtual_ingest(state: &AppState) -> usize {
    let root = ingest_dir();
    let mut n = 0usize;
    let mut seen: std::collections::HashSet<Uuid> = std::collections::HashSet::new();
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
                seen.insert(hid);
                match remove_virtual_ingest_dir(hid) {
                    Ok(true) => n += 1,
                    Ok(false) => {}
                    Err(e) => warn!(error = %e, %hid, "virtual ingest purge failed"),
                }
            } else if let Err(e) = fs::remove_dir_all(&path) {
                warn!(error = %e, path = %path.display(), "virtual ingest purge failed");
            } else {
                n += 1;
            }
        }
    }
    if let Some(ch) = state.clickhouse.as_ref() {
        // Count live blob hosts before hard delete (for the purged counter).
        for kind in [KIND_VIRTUAL_PROCESSES, KIND_VIRTUAL_FILES, KIND_VIRTUAL_PROVENANCE] {
            if let Ok(ids) = ch.list_platform_blob_ids(kind).await {
                for sid in ids {
                    if let Ok(hid) = Uuid::parse_str(&sid) {
                        seen.insert(hid);
                    }
                    let _ = ch.delete_virtual_events_for_host(&sid).await;
                }
            }
        }
        if let Err(e) = ch.clear_virtual_ingest_blobs().await {
            warn!(error = %e, "ClickHouse virtual ingest hard clear failed");
        } else {
            info!("ClickHouse virtual ingest blobs hard-cleared + optimized");
        }
        n = n.max(seen.len());
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
    // Soft reindex — also upgrades stale file caps (old 5k → 50k) for this host only.
    if let Err(e) = index_virtual_host_events(state.store.as_ref(), ch, host_id, false).await {
        warn!(error = %e, %host_id, "ClickHouse virtual events index failed");
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
