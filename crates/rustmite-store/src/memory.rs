use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use async_trait::async_trait;
use dashmap::DashMap;
use rustmite_proto::{Finding, HostId, NodeId, ScanId, ScanMeta};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{StoreError, StoreResult};
use crate::traits::Store;
use crate::types::{
    ActivityEvent, CompleteScan, DeleteHostsRequest, DeleteHostsResult, EnqueueScan, FindingFilter,
    HostKeyPin, HostRecord, NodeRegistration, QueueSnapshot, ScanJob, ScanStatus, SshKeyPlacement,
    SshKeyRecord, SshSecurityZone, StoredCredential, StoredObservation, TagSshKeysRequest,
    UpdateHost, UpsertHost, UpsertSshPlacement, UpsertSshZone,
};

#[derive(Default)]
struct Inner {
    nodes: HashMap<Uuid, NodeRegistration>,
    jobs: Vec<ScanJob>,
    metas: HashMap<Uuid, ScanMeta>,
    observations: Vec<StoredObservation>,
    findings: Vec<Finding>,
    host_keys: HashMap<Uuid, HostKeyPin>,
    baselines: HashMap<(Uuid, String), serde_json::Value>,
    activity: Vec<ActivityEvent>,
    ssh_keys: HashMap<String, SshKeyRecord>,
    ssh_placements: Vec<SshKeyPlacement>,
    ssh_zones: HashMap<Uuid, SshSecurityZone>,
    /// Node-sealed SSH credentials keyed by id.
    credentials: HashMap<String, StoredCredential>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BaselineRow {
    pub host_id: Uuid,
    pub name: String,
    pub payload: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetaRow {
    pub scan_id: Uuid,
    pub meta: ScanMeta,
}

/// On-disk / ClickHouse snapshot of the control-plane store.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoreSnapshot {
    pub schema_version: u32,
    pub saved_at: String,
    pub hosts: Vec<HostRecord>,
    pub jobs: Vec<ScanJob>,
    pub metas: Vec<MetaRow>,
    pub observations: Vec<StoredObservation>,
    pub findings: Vec<Finding>,
    pub host_keys: Vec<HostKeyPin>,
    pub baselines: Vec<BaselineRow>,
    pub activity: Vec<ActivityEvent>,
    pub ssh_keys: Vec<SshKeyRecord>,
    pub ssh_placements: Vec<SshKeyPlacement>,
    pub ssh_zones: Vec<SshSecurityZone>,
    /// Node-sealed SSH credentials (ciphertext only).
    #[serde(default)]
    pub credentials: Vec<StoredCredential>,
}

/// Process-local store for tests and development, optionally snapshotted to disk.
pub struct InMemoryStore {
    hosts: DashMap<Uuid, HostRecord>,
    hosts_by_name: DashMap<(Uuid, String), Uuid>,
    inner: Mutex<Inner>,
    persist_path: Mutex<Option<PathBuf>>,
    dirty: AtomicBool,
    /// Monotonic counter bumped on every mark_dirty; used to avoid clearing
    /// dirty after a flush that raced with newer mutations.
    dirty_gen: std::sync::atomic::AtomicU64,
    /// Fleet default: finished scans retained per host (host label may override).
    scan_history_per_host: std::sync::atomic::AtomicUsize,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self {
            hosts: DashMap::new(),
            hosts_by_name: DashMap::new(),
            inner: Mutex::new(Inner::default()),
            persist_path: Mutex::new(None),
            dirty: AtomicBool::new(false),
            dirty_gen: std::sync::atomic::AtomicU64::new(0),
            scan_history_per_host: std::sync::atomic::AtomicUsize::new(3),
        }
    }

    pub fn set_scan_history_per_host(&self, keep: usize) {
        self.scan_history_per_host
            .store(keep.min(200), Ordering::SeqCst);
    }

    pub fn scan_history_per_host(&self) -> usize {
        self.scan_history_per_host.load(Ordering::SeqCst)
    }

    fn history_keep_for_host(&self, host_id: HostId) -> usize {
        if let Some(h) = self.hosts.get(&host_id.0) {
            for key in ["scan_history", "scan_history_per_host"] {
                if let Some(raw) = h.labels.get(key) {
                    if let Ok(n) = raw.trim().parse::<usize>() {
                        return n.min(200);
                    }
                }
            }
        }
        self.scan_history_per_host()
    }

    /// Load an existing snapshot if present, then persist future writes to `path`.
    pub fn open(path: impl AsRef<Path>) -> StoreResult<Self> {
        let path = path.as_ref().to_path_buf();
        let store = Self::new();
        if path.exists() {
            store.load_from(&path)?;
            store.dirty.store(false, Ordering::SeqCst);
        }
        *store
            .persist_path
            .lock()
            .map_err(|e| StoreError::Backend(e.to_string()))? = Some(path);
        Ok(store)
    }

    pub fn persist_path(&self) -> Option<PathBuf> {
        self.persist_path
            .lock()
            .ok()
            .and_then(|g| g.clone())
    }

    pub fn host_count(&self) -> usize {
        self.hosts.len()
    }

    pub fn finding_count(&self) -> usize {
        self.inner
            .lock()
            .map(|g| g.findings.len())
            .unwrap_or(0)
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty.load(Ordering::SeqCst)
    }

    pub fn dirty_generation(&self) -> u64 {
        self.dirty_gen.load(Ordering::SeqCst)
    }

    pub fn clear_dirty(&self) {
        self.dirty.store(false, Ordering::SeqCst);
    }

    /// Clear dirty only if no newer mutation happened since `gen` was sampled.
    pub fn clear_dirty_if(&self, gen: u64) {
        if self.dirty_gen.load(Ordering::SeqCst) == gen {
            self.dirty.store(false, Ordering::SeqCst);
        }
    }

    pub fn mark_dirty_public(&self) {
        self.mark_dirty();
    }

    /// Drop finished scans beyond `keep` (newest kept). Active jobs are never removed.
    /// Returns how many scan jobs were deleted. Also drops metas + observations for those ids.
    fn prune_scan_history_locked(
        inner: &mut Inner,
        host_id: Option<HostId>,
        keep: usize,
    ) -> usize {
        use std::collections::{HashMap, HashSet};

        let mut by_host: HashMap<Uuid, Vec<(usize, Uuid)>> = HashMap::new();
        for (idx, job) in inner.jobs.iter().enumerate() {
            if let Some(hid) = host_id {
                if job.host_id != hid {
                    continue;
                }
            }
            let finished = matches!(job.state.as_str(), "complete" | "failed");
            if !finished {
                continue;
            }
            by_host
                .entry(job.host_id.0)
                .or_default()
                .push((idx, job.id.0));
        }

        let mut drop_ids: HashSet<Uuid> = HashSet::new();
        for (_hid, mut entries) in by_host {
            // UUID v7 / time-ish: keep newest ids.
            entries.sort_by(|a, b| b.1.cmp(&a.1));
            for (_idx, id) in entries.into_iter().skip(keep) {
                drop_ids.insert(id);
            }
        }
        if drop_ids.is_empty() {
            return 0;
        }

        let before = inner.jobs.len();
        inner.jobs.retain(|j| !drop_ids.contains(&j.id.0));
        let removed = before.saturating_sub(inner.jobs.len());
        for id in &drop_ids {
            inner.metas.remove(id);
        }
        inner
            .observations
            .retain(|o| !drop_ids.contains(&o.scan_id.0));
        removed
    }

    /// Disable JSON file persistence (used when ClickHouse is the durable backend).
    pub fn clear_persist_path(&self) -> StoreResult<()> {
        *self
            .persist_path
            .lock()
            .map_err(|e| StoreError::Backend(e.to_string()))? = None;
        Ok(())
    }

    pub fn export_snapshot(&self) -> StoreResult<StoreSnapshot> {
        self.snapshot()
    }

    pub fn import_snapshot(&self, snap: StoreSnapshot) -> StoreResult<()> {
        self.restore(snap)?;
        self.dirty.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// True when the store has no hosts (and typically no findings).
    pub fn is_empty(&self) -> bool {
        self.host_count() == 0 && self.finding_count() == 0
    }

    fn mark_dirty(&self) {
        self.dirty_gen.fetch_add(1, Ordering::SeqCst);
        self.dirty.store(true, Ordering::SeqCst);
    }

    /// Write the snapshot if anything changed since the last successful save.
    pub fn save_if_dirty(&self) -> StoreResult<bool> {
        if !self.dirty.load(Ordering::SeqCst) {
            return Ok(false);
        }
        self.save()
    }

    /// Force-write the snapshot (no-op if persistence is disabled).
    pub fn save(&self) -> StoreResult<bool> {
        let path = {
            let guard = self
                .persist_path
                .lock()
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            match guard.as_ref() {
                Some(p) => p.clone(),
                None => return Ok(false),
            }
        };
        let snap = self.snapshot()?;
        let bytes = serde_json::to_vec(&snap)
            .map_err(|e| StoreError::Backend(format!("serialize store: {e}")))?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| StoreError::Backend(format!("create {}: {e}", parent.display())))?;
            }
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, &bytes)
            .map_err(|e| StoreError::Backend(format!("write {}: {e}", tmp.display())))?;
        std::fs::rename(&tmp, &path)
            .map_err(|e| StoreError::Backend(format!("rename {}: {e}", path.display())))?;
        self.dirty.store(false, Ordering::SeqCst);
        Ok(true)
    }

    fn snapshot(&self) -> StoreResult<StoreSnapshot> {
        let inner = self
            .inner
            .lock()
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        let hosts: Vec<HostRecord> = self.hosts.iter().map(|e| e.value().clone()).collect();
        Ok(StoreSnapshot {
            schema_version: 1,
            saved_at: Self::now_rfc3339(),
            hosts,
            jobs: inner.jobs.clone(),
            metas: inner
                .metas
                .iter()
                .map(|(id, meta)| MetaRow {
                    scan_id: *id,
                    meta: meta.clone(),
                })
                .collect(),
            observations: inner.observations.clone(),
            findings: inner.findings.clone(),
            host_keys: inner.host_keys.values().cloned().collect(),
            baselines: inner
                .baselines
                .iter()
                .map(|((host_id, name), payload)| BaselineRow {
                    host_id: *host_id,
                    name: name.clone(),
                    payload: payload.clone(),
                })
                .collect(),
            activity: inner.activity.clone(),
            ssh_keys: inner.ssh_keys.values().cloned().collect(),
            ssh_placements: inner.ssh_placements.clone(),
            ssh_zones: inner.ssh_zones.values().cloned().collect(),
            credentials: inner.credentials.values().cloned().collect(),
        })
    }

    fn load_from(&self, path: &Path) -> StoreResult<()> {
        let bytes = std::fs::read(path)
            .map_err(|e| StoreError::Backend(format!("read {}: {e}", path.display())))?;
        if bytes.is_empty() {
            return Ok(());
        }
        let snap: StoreSnapshot = serde_json::from_slice(&bytes)
            .map_err(|e| StoreError::Backend(format!("parse {}: {e}", path.display())))?;
        self.restore(snap)
    }

    fn restore(&self, snap: StoreSnapshot) -> StoreResult<()> {
        self.hosts.clear();
        self.hosts_by_name.clear();
        for host in snap.hosts {
            self.hosts_by_name
                .insert((host.tenant_id, host.display_name.clone()), host.id.0);
            self.hosts.insert(host.id.0, host);
        }
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        // Load metas first so we can heal jobs that finished (have ScanMeta) but
        // were left leased/running/queued after a crash or bad progress ordering.
        inner.metas = snap
            .metas
            .into_iter()
            .map(|row| (row.scan_id, row.meta))
            .collect();
        inner.jobs = snap
            .jobs
            .into_iter()
            .map(|mut job| {
                let meta = inner.metas.get(&job.id.0).cloned();
                Self::heal_job_state(&mut job, meta.as_ref());
                job
            })
            .collect();
        inner.observations = snap.observations;
        inner.findings = snap.findings;
        inner.host_keys = snap
            .host_keys
            .into_iter()
            .map(|pin| (pin.host_id.0, pin))
            .collect();
        inner.baselines = snap
            .baselines
            .into_iter()
            .map(|row| ((row.host_id, row.name), row.payload))
            .collect();
        inner.activity = snap.activity;
        inner.ssh_keys = snap
            .ssh_keys
            .into_iter()
            .map(|k| (k.fingerprint.clone(), k))
            .collect();
        inner.ssh_placements = snap.ssh_placements;
        inner.ssh_zones = snap.ssh_zones.into_iter().map(|z| (z.id, z)).collect();
        inner.credentials = snap
            .credentials
            .into_iter()
            .map(|c| (c.id.clone(), c))
            .collect();
        inner.nodes.clear();
        Ok(())
    }

    fn now_rfc3339() -> String {
        OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| OffsetDateTime::now_utc().to_string())
    }

    /// Mark finished-but-stuck jobs as complete/failed. Never requeues.
    fn heal_finished_job(job: &mut ScanJob, meta: Option<&ScanMeta>) -> bool {
        if matches!(job.state.as_str(), "complete" | "failed") {
            return false;
        }

        let stage = job.progress_stage.as_deref().unwrap_or("");
        let stage_l = stage.to_ascii_lowercase();
        let terminal_stage = stage_l == "complete"
            || stage_l.contains("finished")
            || stage_l.starts_with("failed")
            || stage_l.contains("post results")
            || matches!(
                stage_l.as_str(),
                "timeout"
                    | "partial"
                    | "probe_crashed"
                    | "delivery_failed"
                    | "auth_failed"
                    | "host_key_changed"
                    | "unreachable"
            );
        let finished_pct = job.progress_pct == Some(100);
        let has_meta = meta.is_some();

        if !(has_meta || (finished_pct && terminal_stage)) {
            return false;
        }

        let failed = meta
            .map(|m| {
                !matches!(
                    m.outcome,
                    rustmite_proto::ScanOutcome::Complete
                        | rustmite_proto::ScanOutcome::Partial { .. }
                )
            })
            .unwrap_or_else(|| {
                stage_l.contains("fail")
                    || matches!(
                        stage_l.as_str(),
                        "timeout"
                            | "probe_crashed"
                            | "delivery_failed"
                            | "auth_failed"
                            | "host_key_changed"
                            | "unreachable"
                    )
            });
        job.state = if failed { "failed" } else { "complete" }.into();
        job.leased_by = None;
        job.progress_pct = Some(100);
        if job.progress_stage.as_deref().is_none_or(|s| {
            s.is_empty() || s.contains("requeued") || s.contains("post results")
        }) {
            job.progress_stage = Some(if failed { "failed" } else { "complete" }.into());
        }
        true
    }

    /// Snapshot import: finalize finished jobs, then requeue true in-flight work.
    fn heal_job_state(job: &mut ScanJob, meta: Option<&ScanMeta>) {
        if Self::heal_finished_job(job, meta) {
            return;
        }
        if matches!(job.state.as_str(), "leased" | "running") {
            job.state = "queued".into();
            job.leased_by = None;
            job.progress_stage = Some("requeued after restart".into());
        }
    }

    /// Live heal: only finalize jobs that already have results / terminal progress.
    fn heal_jobs_locked(inner: &mut Inner) -> bool {
        let meta_map: HashMap<Uuid, ScanMeta> = inner
            .metas
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        let mut changed = false;
        for job in &mut inner.jobs {
            if Self::heal_finished_job(job, meta_map.get(&job.id.0)) {
                changed = true;
            }
        }
        changed
    }

    fn push_activity_locked(inner: &mut Inner, mut event: ActivityEvent) {
        if event.ts.is_empty() {
            event.ts = Self::now_rfc3339();
        }
        if event.id.is_nil() {
            event.id = Uuid::now_v7();
        }
        inner.activity.push(event);
        const CAP: usize = 8_000;
        if inner.activity.len() > CAP {
            let drop_n = inner.activity.len() - CAP;
            inner.activity.drain(0..drop_n);
        }
    }
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Store for InMemoryStore {
    async fn upsert_host(&self, req: UpsertHost) -> StoreResult<HostRecord> {
        let key = (req.tenant_id, req.display_name.clone());
        let id = if let Some(id) = req.id {
            id
        } else if let Some(existing) = self.hosts_by_name.get(&key) {
            HostId(*existing)
        } else {
            HostId::new_v7()
        };

        let prev = self.hosts.get(&id.0).map(|e| e.value().clone());
        let record = HostRecord {
            id,
            tenant_id: req.tenant_id,
            display_name: req.display_name.clone(),
            primary_addr: req.primary_addr,
            ssh_port: req.ssh_port.unwrap_or(22),
            arch: prev.as_ref().and_then(|p| p.arch.clone()),
            kernel: prev.as_ref().and_then(|p| p.kernel.clone()),
            os: prev.as_ref().and_then(|p| p.os.clone()),
            os_id: prev.as_ref().and_then(|p| p.os_id.clone()),
            os_version: prev.as_ref().and_then(|p| p.os_version.clone()),
            agent_kind: req
                .agent_kind
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(crate::types::normalize_agent_kind)
                .or_else(|| prev.as_ref().map(|p| p.agent_kind.clone()))
                .unwrap_or_else(|| "ssh".into()),
            ingest_token: req
                .ingest_token
                .clone()
                .or_else(|| prev.as_ref().and_then(|p| p.ingest_token.clone())),
            labels: req.labels,
            last_scan_at: prev.as_ref().and_then(|p| p.last_scan_at.clone()),
            last_outcome: prev.as_ref().and_then(|p| p.last_outcome.clone()),
            timeouts: req.timeouts,
            auth_status: prev.as_ref().and_then(|p| p.auth_status.clone()),
            auth_detail: prev.as_ref().and_then(|p| p.auth_detail.clone()),
            auth_checked_at: prev.as_ref().and_then(|p| p.auth_checked_at.clone()),
        };
        // Drop stale name index if renamed.
        if let Some(prev) = &prev {
            if prev.display_name != record.display_name || prev.tenant_id != record.tenant_id {
                self.hosts_by_name
                    .remove(&(prev.tenant_id, prev.display_name.clone()));
            }
        }
        self.hosts_by_name.insert(key, id.0);
        self.hosts.insert(id.0, record.clone());
        self.mark_dirty();
        Ok(record)
    }

    async fn list_hosts(&self) -> StoreResult<Vec<HostRecord>> {
        let mut out: Vec<_> = self.hosts.iter().map(|e| e.value().clone()).collect();
        out.sort_by(|a, b| a.display_name.cmp(&b.display_name));
        Ok(out)
    }

    async fn get_host(&self, id: HostId) -> StoreResult<HostRecord> {
        self.hosts
            .get(&id.0)
            .map(|e| e.value().clone())
            .ok_or_else(|| StoreError::NotFound(format!("host {id}")))
    }

    async fn update_host(&self, id: HostId, req: UpdateHost) -> StoreResult<HostRecord> {
        let mut host = self
            .hosts
            .get(&id.0)
            .map(|e| e.value().clone())
            .ok_or_else(|| StoreError::NotFound(format!("host {id}")))?;

        let old_key = (host.tenant_id, host.display_name.clone());

        if let Some(name) = req.display_name {
            let name = name.trim().to_string();
            if name.is_empty() {
                return Err(StoreError::Invalid("display_name cannot be empty".into()));
            }
            host.display_name = name;
        }
        if let Some(addr) = req.primary_addr {
            host.primary_addr = if addr.trim().is_empty() {
                None
            } else {
                Some(addr.trim().to_string())
            };
        }
        if let Some(port) = req.ssh_port {
            if port == 0 {
                return Err(StoreError::Invalid("ssh_port must be > 0".into()));
            }
            host.ssh_port = port;
        }
        if let Some(labels) = req.labels {
            host.labels = labels;
        }
        if let Some(patch) = req.label_patch {
            for (k, v) in patch {
                if v.is_empty() {
                    host.labels.remove(&k);
                } else {
                    host.labels.insert(k, v);
                }
            }
        }
        if let Some(timeouts) = req.timeouts {
            host.timeouts = timeouts;
        }
        if let Some(status) = req.auth_status {
            host.auth_status = if status.trim().is_empty() {
                None
            } else {
                Some(status)
            };
        }
        if let Some(detail) = req.auth_detail {
            host.auth_detail = if detail.trim().is_empty() {
                None
            } else {
                Some(detail)
            };
        }
        if let Some(at) = req.auth_checked_at {
            host.auth_checked_at = if at.trim().is_empty() {
                None
            } else {
                Some(at)
            };
        }
        if let Some(arch) = req.arch {
            host.arch = if arch.trim().is_empty() {
                None
            } else {
                Some(arch)
            };
        }
        if let Some(kernel) = req.kernel {
            host.kernel = if kernel.trim().is_empty() {
                None
            } else {
                Some(kernel)
            };
        }
        if let Some(os) = req.os {
            host.os = if os.trim().is_empty() { None } else { Some(os) };
        }
        if let Some(os_id) = req.os_id {
            host.os_id = if os_id.trim().is_empty() {
                None
            } else {
                Some(os_id)
            };
        }
        if let Some(os_version) = req.os_version {
            host.os_version = if os_version.trim().is_empty() {
                None
            } else {
                Some(os_version)
            };
        }
        if let Some(kind) = req.agent_kind {
            host.agent_kind = crate::types::normalize_agent_kind(&kind);
        }
        if let Some(tok) = req.ingest_token {
            host.ingest_token = if tok.trim().is_empty() {
                None
            } else {
                Some(tok)
            };
        }

        let new_key = (host.tenant_id, host.display_name.clone());
        if old_key != new_key {
            self.hosts_by_name.remove(&old_key);
            self.hosts_by_name.insert(new_key, id.0);
        }
        self.hosts.insert(id.0, host.clone());
        self.mark_dirty();
        Ok(host)
    }

    async fn delete_host(&self, id: HostId) -> StoreResult<()> {
        let removed = self
            .hosts
            .remove(&id.0)
            .ok_or_else(|| StoreError::NotFound(format!("host {id}")))?;
        self.hosts_by_name
            .remove(&(removed.1.tenant_id, removed.1.display_name.clone()));

        let mut inner = self
            .inner
            .lock()
            .map_err(|e| StoreError::Backend(e.to_string()))?;

        use std::collections::HashSet;
        let drop_scan_ids: HashSet<Uuid> = inner
            .jobs
            .iter()
            .filter(|j| j.host_id == id)
            .map(|j| j.id.0)
            .collect();

        // Cascade: scans → metas → observations → findings → keys → baselines →
        // activity → SSH placements. Orphan SSH key records (no remaining placements)
        // are pruned so hunter data does not linger after the last host that held them.
        inner.jobs.retain(|j| j.host_id != id);
        for sid in &drop_scan_ids {
            inner.metas.remove(sid);
        }
        inner.observations.retain(|o| {
            o.host_id != id && !drop_scan_ids.contains(&o.scan_id.0)
        });
        inner.findings.retain(|f| {
            f.host_id != id && !drop_scan_ids.contains(&f.scan_id.0)
        });
        inner.host_keys.remove(&id.0);
        inner
            .baselines
            .retain(|(hid, _), _| *hid != id.0);
        inner.activity.retain(|a| a.host_id != Some(id));
        inner.ssh_placements.retain(|p| p.host_id != id);

        let live_fps: HashSet<String> = inner
            .ssh_placements
            .iter()
            .map(|p| p.fingerprint.clone())
            .collect();
        inner
            .ssh_keys
            .retain(|fp, _| live_fps.contains(fp));

        drop(inner);
        self.mark_dirty();
        Ok(())
    }

    async fn delete_hosts(&self, req: DeleteHostsRequest) -> StoreResult<DeleteHostsResult> {
        let mut deleted = 0;
        let mut missing = Vec::new();
        for id in req.host_ids {
            match self.delete_host(id).await {
                Ok(()) => deleted += 1,
                Err(StoreError::NotFound(_)) => missing.push(id),
                Err(e) => return Err(e),
            }
        }
        Ok(DeleteHostsResult { deleted, missing })
    }

    async fn enqueue_scan(&self, req: EnqueueScan) -> StoreResult<ScanJob> {
        if !self.hosts.contains_key(&req.host_id.0) {
            return Err(StoreError::NotFound(format!("host {}", req.host_id)));
        }
        let mut inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        let active = inner
            .jobs
            .iter()
            .any(|j| {
                j.host_id == req.host_id
                    && matches!(j.state.as_str(), "queued" | "leased" | "running")
            });
        if active {
            return Err(StoreError::Conflict(
                "one active scan per host".into(),
            ));
        }
        let now = Self::now_rfc3339();
        let host_id = req.host_id;
        let host_name = self
            .hosts
            .get(&host_id.0)
            .map(|h| h.display_name.clone())
            .unwrap_or_else(|| host_id.to_string());
        let job = ScanJob {
            id: ScanId::new_v7(),
            host_id,
            check_set: req.check_set,
            priority: req.priority,
            state: "queued".into(),
            leased_by: None,
            attempts: 0,
            progress_pct: Some(0),
            progress_stage: Some("queued".into()),
            updated_at: Some(now.clone()),
        };
        Self::push_activity_locked(
            &mut inner,
            ActivityEvent {
                id: Uuid::nil(),
                ts: now,
                level: "info".into(),
                kind: "scan.queued".into(),
                message: format!(
                    "Scan queued for {host_name} (check_set={}, priority={})",
                    job.check_set, job.priority
                ),
                scan_id: Some(job.id),
                host_id: Some(job.host_id),
                node_id: None,
                detail: Some(serde_json::json!({ "check_set": job.check_set, "priority": job.priority })),
            },
        );
        inner.jobs.push(job.clone());
        drop(inner);
        self.mark_dirty();
        Ok(job)
    }

    async fn lease_jobs(&self, node_id: NodeId, capacity: usize) -> StoreResult<Vec<ScanJob>> {
        let mut inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        let mut queued: Vec<usize> = inner
            .jobs
            .iter()
            .enumerate()
            .filter(|(_, j)| j.state == "queued")
            .map(|(i, _)| i)
            .collect();
        queued.sort_by(|&a, &b| {
            inner.jobs[b]
                .priority
                .cmp(&inner.jobs[a].priority)
        });
        let mut leased = Vec::new();
        let now = Self::now_rfc3339();
        for idx in queued.into_iter().take(capacity) {
            let snap = {
                let job = &mut inner.jobs[idx];
                job.state = "leased".into();
                job.leased_by = Some(node_id);
                job.attempts += 1;
                job.progress_pct = Some(5);
                job.progress_stage = Some("leased to node".into());
                job.updated_at = Some(now.clone());
                job.clone()
            };
            leased.push(snap.clone());
            Self::push_activity_locked(
                &mut inner,
                ActivityEvent {
                    id: Uuid::nil(),
                    ts: now.clone(),
                    level: "info".into(),
                    kind: "scan.leased".into(),
                    message: format!("Scan {} leased to node {node_id}", snap.id),
                    scan_id: Some(snap.id),
                    host_id: Some(snap.host_id),
                    node_id: Some(node_id),
                    detail: None,
                },
            );
        }
        drop(inner);
        if !leased.is_empty() {
            self.mark_dirty();
        }
        Ok(leased)
    }

    async fn complete_scan(&self, req: CompleteScan) -> StoreResult<()> {
        let mut inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        let (host_id, node_id, failed) = {
            let job = inner
                .jobs
                .iter_mut()
                .find(|j| j.id == req.scan_id)
                .ok_or_else(|| StoreError::NotFound(format!("scan {}", req.scan_id)))?;
            let host_id = job.host_id;
            let node_id = job.leased_by;
            let failed = req.outcome.contains("fail")
                || matches!(
                    req.outcome.as_str(),
                    "unreachable"
                        | "timeout"
                        | "partial"
                        | "probe_crashed"
                        | "delivery_failed"
                        | "auth_failed"
                        | "host_key_changed"
                );
            job.state = if failed {
                "failed".into()
            } else {
                "complete".into()
            };
            job.progress_pct = Some(100);
            job.progress_stage = Some(req.outcome.clone());
            job.updated_at = Some(Self::now_rfc3339());
            if let Some(mut host) = self.hosts.get_mut(&host_id.0) {
                host.last_scan_at = Some(OffsetDateTime::now_utc().to_string());
                host.last_outcome = Some(req.outcome.clone());
                let arch = req.meta.arch.as_str();
                if arch != "unknown" && !arch.is_empty() {
                    host.arch = Some(arch.to_string());
                }
                if !req.meta.kernel.trim().is_empty() {
                    host.kernel = Some(req.meta.kernel.clone());
                }
                if let Some(os) = req.meta.os.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
                    host.os = Some(os.to_string());
                }
                if let Some(os_id) = req
                    .meta
                    .os_id
                    .as_ref()
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                {
                    host.os_id = Some(os_id.to_string());
                }
                if let Some(os_version) = req
                    .meta
                    .os_version
                    .as_ref()
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                {
                    host.os_version = Some(os_version.to_string());
                }
            }
            (host_id, node_id, failed)
        };
        Self::push_activity_locked(
            &mut inner,
            ActivityEvent {
                id: Uuid::nil(),
                ts: Self::now_rfc3339(),
                level: if failed { "error" } else { "info" }.into(),
                kind: if failed {
                    "scan.error".into()
                } else {
                    "scan.complete".into()
                },
                message: format!(
                    "Scan {} finished ({}) — fired={}",
                    req.scan_id, req.outcome, req.meta.fired
                ),
                scan_id: Some(req.scan_id),
                host_id: Some(host_id),
                node_id,
                detail: Some(serde_json::json!({
                    "outcome": req.outcome,
                    "fired": req.meta.fired,
                    "applicable": req.meta.applicable_checks,
                    "duration_ms": req.meta.duration_ms,
                })),
            },
        );
        let mut meta = req.meta;
        let finished = Self::now_rfc3339();
        if meta.finished_at.trim().is_empty() {
            meta.finished_at = finished.clone();
        }
        if meta.started_at.trim().is_empty() {
            if meta.duration_ms > 0 {
                let start = OffsetDateTime::now_utc()
                    - time::Duration::milliseconds(meta.duration_ms as i64);
                meta.started_at = start
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_else(|_| finished.clone());
            } else {
                meta.started_at = finished;
            }
        }
        inner.metas.insert(req.scan_id.0, meta);
        let keep = self.history_keep_for_host(host_id);
        let _ = Self::prune_scan_history_locked(&mut inner, Some(host_id), keep);
        drop(inner);
        self.mark_dirty();
        Ok(())
    }

    async fn insert_observations(&self, rows: Vec<StoredObservation>) -> StoreResult<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let mut inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        inner.observations.extend(rows);
        drop(inner);
        self.mark_dirty();
        Ok(())
    }

    async fn insert_findings(&self, findings: Vec<Finding>) -> StoreResult<()> {
        if findings.is_empty() {
            return Ok(());
        }
        let mut inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        inner.findings.extend(findings);
        drop(inner);
        self.mark_dirty();
        Ok(())
    }

    async fn clear_findings_for_host_checks(
        &self,
        host_id: HostId,
        check_ids: &[&str],
    ) -> StoreResult<()> {
        if check_ids.is_empty() {
            return Ok(());
        }
        let mut inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        let before = inner.findings.len();
        inner.findings.retain(|f| {
            !(f.host_id == host_id && check_ids.iter().any(|c| f.check_id.as_str() == *c))
        });
        let removed = before.saturating_sub(inner.findings.len());
        drop(inner);
        if removed > 0 {
            self.mark_dirty();
        }
        Ok(())
    }

    async fn clear_findings_by_checks(&self, check_ids: &[&str]) -> StoreResult<usize> {
        if check_ids.is_empty() {
            return Ok(0);
        }
        let mut inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        let before = inner.findings.len();
        inner.findings.retain(|f| !check_ids.iter().any(|c| f.check_id.as_str() == *c));
        let removed = before.saturating_sub(inner.findings.len());
        drop(inner);
        if removed > 0 {
            self.mark_dirty();
        }
        Ok(removed)
    }

    async fn clear_all_findings(&self) -> StoreResult<usize> {
        let mut inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        let removed = inner.findings.len();
        inner.findings.clear();
        drop(inner);
        if removed > 0 {
            self.mark_dirty();
        }
        Ok(removed)
    }

    async fn clear_all_scans(&self) -> StoreResult<usize> {
        let mut inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        let removed = inner.jobs.len() + inner.metas.len();
        inner.jobs.clear();
        inner.metas.clear();
        drop(inner);
        if removed > 0 {
            self.mark_dirty();
        }
        Ok(removed)
    }

    async fn clear_all_observations(&self) -> StoreResult<usize> {
        let mut inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        let removed = inner.observations.len();
        inner.observations.clear();
        drop(inner);
        if removed > 0 {
            self.mark_dirty();
        }
        Ok(removed)
    }

    async fn clear_all_activity(&self) -> StoreResult<usize> {
        let mut inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        let removed = inner.activity.len();
        inner.activity.clear();
        drop(inner);
        if removed > 0 {
            self.mark_dirty();
        }
        Ok(removed)
    }

    async fn clear_all_baselines(&self) -> StoreResult<usize> {
        let mut inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        let removed = inner.baselines.len();
        inner.baselines.clear();
        drop(inner);
        if removed > 0 {
            self.mark_dirty();
        }
        Ok(removed)
    }

    async fn clear_all_host_keys(&self) -> StoreResult<usize> {
        let mut inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        let removed = inner.host_keys.len();
        inner.host_keys.clear();
        drop(inner);
        if removed > 0 {
            self.mark_dirty();
        }
        Ok(removed)
    }

    async fn prune_scan_history(
        &self,
        host_id: Option<HostId>,
        keep: usize,
    ) -> StoreResult<usize> {
        let mut inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        let removed = Self::prune_scan_history_locked(&mut inner, host_id, keep);
        drop(inner);
        if removed > 0 {
            self.mark_dirty();
        }
        Ok(removed)
    }

    async fn data_counts(&self) -> StoreResult<crate::types::DataCounts> {
        let hosts = self.hosts.len();
        let inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(crate::types::DataCounts {
            hosts,
            findings: inner.findings.len(),
            scans: inner.jobs.len(),
            observations: inner.observations.len(),
            activity: inner.activity.len(),
            nodes: inner.nodes.len(),
            baselines: inner.baselines.len(),
            host_keys: inner.host_keys.len(),
            ssh_keys: inner.ssh_keys.len(),
            ssh_placements: inner.ssh_placements.len(),
            ssh_zones: inner.ssh_zones.len(),
            credentials: inner.credentials.len(),
        })
    }

    async fn list_findings(&self, filter: FindingFilter) -> StoreResult<Vec<Finding>> {
        let inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        let mut out: Vec<_> = inner
            .findings
            .iter()
            .filter(|f| {
                filter.host_id.map(|h| f.host_id == h).unwrap_or(true)
                    && filter
                        .severity
                        .map(|s| f.severity == s)
                        .unwrap_or(true)
                    && filter
                        .check_id
                        .as_ref()
                        .map(|c| f.check_id.as_str() == c)
                        .unwrap_or(true)
            })
            .cloned()
            .collect();
        out.sort_by(|a, b| {
            b.last_seen
                .cmp(&a.last_seen)
                .then_with(|| b.first_seen.cmp(&a.first_seen))
                .then_with(|| b.id.0.cmp(&a.id.0))
        });
        out.truncate(filter.limit);
        Ok(out)
    }

    async fn get_scan(&self, scan_id: ScanId) -> StoreResult<ScanStatus> {
        let mut inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        let meta = inner.metas.get(&scan_id.0).cloned();
        let mut healed = false;
        if let Some(job) = inner.jobs.iter_mut().find(|j| j.id == scan_id) {
            healed = Self::heal_finished_job(job, meta.as_ref());
        }
        let job = inner.jobs.iter().find(|j| j.id == scan_id).cloned();
        let findings = inner
            .findings
            .iter()
            .filter(|f| f.scan_id == scan_id)
            .cloned()
            .collect();
        drop(inner);
        if healed {
            self.mark_dirty();
        }
        Ok(ScanStatus {
            job,
            meta,
            findings,
        })
    }

    async fn list_scans(&self, limit: usize) -> StoreResult<Vec<ScanStatus>> {
        let mut inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        let healed = Self::heal_jobs_locked(&mut inner);
        let mut jobs = inner.jobs.clone();
        jobs.sort_by(|a, b| b.id.0.cmp(&a.id.0));
        let out = jobs
            .into_iter()
            .take(limit)
            .map(|job| {
                let meta = inner.metas.get(&job.id.0).cloned();
                let findings = inner
                    .findings
                    .iter()
                    .filter(|f| f.scan_id == job.id)
                    .cloned()
                    .collect();
                ScanStatus {
                    job: Some(job),
                    meta,
                    findings,
                }
            })
            .collect();
        drop(inner);
        if healed {
            self.mark_dirty();
        }
        Ok(out)
    }

    async fn list_nodes(&self) -> StoreResult<Vec<NodeRegistration>> {
        let inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        let mut out: Vec<_> = inner.nodes.values().cloned().collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    async fn push_activity(&self, event: ActivityEvent) -> StoreResult<()> {
        let mut inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        Self::push_activity_locked(&mut inner, event);
        drop(inner);
        self.mark_dirty();
        Ok(())
    }

    async fn list_activity(&self, limit: usize) -> StoreResult<Vec<ActivityEvent>> {
        let inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        let n = inner.activity.len().min(limit);
        let start = inner.activity.len() - n;
        let mut out: Vec<_> = inner.activity[start..].to_vec();
        out.reverse(); // newest first
        Ok(out)
    }

    async fn queue_snapshot(&self) -> StoreResult<QueueSnapshot> {
        let mut inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        let healed = Self::heal_jobs_locked(&mut inner);
        let mut snap = QueueSnapshot::default();
        for j in &inner.jobs {
            match j.state.as_str() {
                "queued" => snap.queued += 1,
                "leased" => snap.leased += 1,
                "running" => snap.running += 1,
                "failed" => snap.failed += 1,
                "complete" => snap.complete += 1,
                _ => {}
            }
            if matches!(j.state.as_str(), "queued" | "leased" | "running") {
                snap.active.push(j.clone());
            }
        }
        snap.active.sort_by(|a, b| b.priority.cmp(&a.priority));
        drop(inner);
        if healed {
            self.mark_dirty();
        }
        Ok(snap)
    }

    async fn update_scan_progress(
        &self,
        scan_id: ScanId,
        state: &str,
        stage: Option<&str>,
        pct: Option<u8>,
    ) -> StoreResult<()> {
        let mut inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        let meta = inner.metas.get(&scan_id.0).cloned();
        let (host_id, node_id, stage_s, pct_v) = {
            let job = inner
                .jobs
                .iter_mut()
                .find(|j| j.id == scan_id)
                .ok_or_else(|| StoreError::NotFound(format!("scan {scan_id}")))?;
            // Never reopen a finished job via late progress heartbeats.
            if !(matches!(job.state.as_str(), "complete" | "failed")
                && matches!(state, "running" | "leased" | "queued"))
            {
                job.state = state.into();
            }
            if let Some(s) = stage {
                job.progress_stage = Some(s.into());
            }
            if let Some(p) = pct {
                job.progress_pct = Some(p.min(100));
            }
            // If results already landed, or progress itself is terminal @ 100%, finalize.
            let _ = Self::heal_finished_job(job, meta.as_ref());
            job.updated_at = Some(Self::now_rfc3339());
            (
                job.host_id,
                job.leased_by,
                job.progress_stage.clone().unwrap_or_else(|| state.into()),
                job.progress_pct.unwrap_or(0),
            )
        };
        let host_label = self
            .hosts
            .get(&host_id.0)
            .map(|h| h.display_name.clone())
            .unwrap_or_else(|| host_id.to_string());
        Self::push_activity_locked(
            &mut inner,
            ActivityEvent {
                id: Uuid::nil(),
                ts: Self::now_rfc3339(),
                level: "progress".into(),
                kind: "scan.progress".into(),
                message: format!("{host_label}: {stage_s} ({pct_v}%)"),
                scan_id: Some(scan_id),
                host_id: Some(host_id),
                node_id,
                detail: Some(serde_json::json!({
                    "state": state,
                    "stage": stage,
                    "pct": pct,
                })),
            },
        );
        drop(inner);
        self.mark_dirty();
        Ok(())
    }

    async fn register_node(&self, reg: NodeRegistration) -> StoreResult<()> {
        let mut inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        inner.nodes.insert(reg.id.0, reg);
        Ok(())
    }

    async fn heartbeat_node(&self, node_id: NodeId, _in_flight: i32) -> StoreResult<()> {
        let inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        if !inner.nodes.contains_key(&node_id.0) {
            return Err(StoreError::NotFound(format!("node {node_id}")));
        }
        Ok(())
    }

    async fn pin_host_key(&self, pin: HostKeyPin) -> StoreResult<()> {
        let mut inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        inner.host_keys.insert(pin.host_id.0, pin);
        drop(inner);
        self.mark_dirty();
        Ok(())
    }

    async fn get_host_key(
        &self,
        host_id: rustmite_proto::HostId,
    ) -> StoreResult<Option<HostKeyPin>> {
        let inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(inner.host_keys.get(&host_id.0).cloned())
    }

    async fn list_observations(
        &self,
        host_id: Option<rustmite_proto::HostId>,
        limit: usize,
    ) -> StoreResult<Vec<StoredObservation>> {
        let inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        // Newest scans are appended; keep the most recent `limit` rows so
        // inventory endpoints (process/socket) see the latest scan, not the
        // oldest truncated prefix.
        let mut out: Vec<_> = inner
            .observations
            .iter()
            .filter(|o| host_id.map(|h| o.host_id == h).unwrap_or(true))
            .cloned()
            .collect();
        if out.len() > limit {
            let skip = out.len() - limit;
            out = out.split_off(skip);
        }
        Ok(out)
    }

    async fn list_observations_of_kind(
        &self,
        host_id: rustmite_proto::HostId,
        kind: &str,
        limit: usize,
    ) -> StoreResult<(Option<rustmite_proto::ScanId>, Vec<StoredObservation>)> {
        let inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        let matching: Vec<_> = inner
            .observations
            .iter()
            .filter(|o| o.host_id == host_id && o.kind == kind)
            .collect();
        let Some(last) = matching.last() else {
            return Ok((None, Vec::new()));
        };
        let scan_id = last.scan_id;
        let mut out: Vec<StoredObservation> = matching
            .into_iter()
            .filter(|o| o.scan_id == scan_id)
            .cloned()
            .collect();
        if out.len() > limit && limit > 0 {
            out.truncate(limit);
        }
        Ok((Some(scan_id), out))
    }

    async fn upsert_baseline(
        &self,
        host_id: rustmite_proto::HostId,
        name: &str,
        payload: serde_json::Value,
    ) -> StoreResult<()> {
        let mut inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        inner
            .baselines
            .insert((host_id.0, name.to_string()), payload);
        drop(inner);
        self.mark_dirty();
        Ok(())
    }

    async fn get_baseline(
        &self,
        host_id: rustmite_proto::HostId,
        name: &str,
    ) -> StoreResult<Option<serde_json::Value>> {
        let inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(inner.baselines.get(&(host_id.0, name.to_string())).cloned())
    }

    async fn upsert_ssh_placement(&self, req: UpsertSshPlacement) -> StoreResult<SshKeyRecord> {
        if req.fingerprint.trim().is_empty() {
            return Err(StoreError::Invalid("fingerprint required".into()));
        }
        let now = req
            .seen_at
            .clone()
            .unwrap_or_else(Self::now_rfc3339);
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| StoreError::Backend(e.to_string()))?;

        let record = {
            let entry = inner
                .ssh_keys
                .entry(req.fingerprint.clone())
                .or_insert_with(|| SshKeyRecord {
                    fingerprint: req.fingerprint.clone(),
                    key_type: req.key_type.clone(),
                    bits: req.bits,
                    comment: req.comment.clone(),
                    first_seen: now.clone(),
                    last_seen: now.clone(),
                    tags: req.tags.clone(),
                });
            if !req.key_type.is_empty() {
                entry.key_type = req.key_type.clone();
            }
            if req.bits.is_some() {
                entry.bits = req.bits;
            }
            if req.comment.is_some() {
                entry.comment = req.comment.clone();
            }
            entry.last_seen = now.clone();
            for t in &req.tags {
                if !entry.tags.iter().any(|x| x == t) {
                    entry.tags.push(t.clone());
                }
            }
            entry.clone()
        };

        let placement = SshKeyPlacement {
            fingerprint: req.fingerprint,
            host_id: req.host_id,
            username: req.username,
            path: req.path,
            role: if req.role.is_empty() {
                "authorized".into()
            } else {
                req.role
            },
            options: req.options,
            seen_at: now,
        };
        if let Some(existing) = inner.ssh_placements.iter_mut().find(|p| {
            p.fingerprint == placement.fingerprint
                && p.host_id == placement.host_id
                && p.username == placement.username
                && p.role == placement.role
        }) {
            *existing = placement;
        } else {
            inner.ssh_placements.push(placement);
        }
        drop(inner);
        self.mark_dirty();
        Ok(record)
    }

    async fn list_ssh_keys(&self) -> StoreResult<Vec<SshKeyRecord>> {
        let inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        let mut out: Vec<_> = inner.ssh_keys.values().cloned().collect();
        out.sort_by(|a, b| b.last_seen.cmp(&a.last_seen).then(a.fingerprint.cmp(&b.fingerprint)));
        Ok(out)
    }

    async fn get_ssh_key(&self, fingerprint: &str) -> StoreResult<Option<SshKeyRecord>> {
        let inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(inner.ssh_keys.get(fingerprint).cloned())
    }

    async fn list_ssh_placements(
        &self,
        fingerprint: Option<&str>,
        host_id: Option<rustmite_proto::HostId>,
        username: Option<&str>,
    ) -> StoreResult<Vec<SshKeyPlacement>> {
        let inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        let mut out: Vec<_> = inner
            .ssh_placements
            .iter()
            .filter(|p| fingerprint.map(|f| p.fingerprint == f).unwrap_or(true))
            .filter(|p| host_id.map(|h| p.host_id == h).unwrap_or(true))
            .filter(|p| username.map(|u| p.username == u).unwrap_or(true))
            .cloned()
            .collect();
        out.sort_by(|a, b| {
            a.fingerprint
                .cmp(&b.fingerprint)
                .then(a.username.cmp(&b.username))
        });
        Ok(out)
    }

    async fn tag_ssh_keys(&self, req: TagSshKeysRequest) -> StoreResult<usize> {
        let mut inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        let mut n = 0usize;
        for fp in &req.fingerprints {
            let Some(key) = inner.ssh_keys.get_mut(fp) else {
                continue;
            };
            if let Some(set) = &req.set {
                key.tags = set.clone();
            } else {
                for t in &req.add {
                    if !key.tags.iter().any(|x| x == t) {
                        key.tags.push(t.clone());
                    }
                }
                if !req.remove.is_empty() {
                    key.tags.retain(|t| !req.remove.iter().any(|r| r == t));
                }
            }
            n += 1;
        }
        drop(inner);
        if n > 0 {
            self.mark_dirty();
        }
        Ok(n)
    }

    async fn list_ssh_key_tags(&self) -> StoreResult<Vec<String>> {
        let inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        let mut tags: Vec<String> = inner
            .ssh_keys
            .values()
            .flat_map(|k| k.tags.iter().cloned())
            .collect();
        tags.sort();
        tags.dedup();
        Ok(tags)
    }

    async fn list_ssh_zones(&self) -> StoreResult<Vec<SshSecurityZone>> {
        let inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        let mut out: Vec<_> = inner.ssh_zones.values().cloned().collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    async fn upsert_ssh_zone(&self, req: UpsertSshZone) -> StoreResult<SshSecurityZone> {
        if req.name.trim().is_empty() {
            return Err(StoreError::Invalid("zone name required".into()));
        }
        let mut inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        let id = req.id.unwrap_or_else(Uuid::now_v7);
        let zone = SshSecurityZone {
            id,
            name: req.name.trim().to_string(),
            description: req.description,
            host_selectors: req.host_selectors,
            key_tags: req.key_tags,
            policy: if req.policy.is_empty() {
                "alert_on_cross_zone".into()
            } else {
                req.policy
            },
        };
        inner.ssh_zones.insert(id, zone.clone());
        drop(inner);
        self.mark_dirty();
        Ok(zone)
    }

    async fn delete_ssh_zone(&self, id: Uuid) -> StoreResult<()> {
        let mut inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        if inner.ssh_zones.remove(&id).is_none() {
            return Err(StoreError::NotFound(format!("ssh zone {id}")));
        }
        drop(inner);
        self.mark_dirty();
        Ok(())
    }

    async fn upsert_credential(&self, mut cred: StoredCredential) -> StoreResult<StoredCredential> {
        if cred.id.trim().is_empty() {
            return Err(StoreError::Invalid("credential id required".into()));
        }
        if cred.sealed_b64.trim().is_empty() {
            return Err(StoreError::Invalid("sealed_b64 required".into()));
        }
        let kind = cred.kind.trim().to_ascii_lowercase();
        if kind != "identity" && kind != "password" {
            return Err(StoreError::Invalid(
                "credential kind must be identity or password".into(),
            ));
        }
        cred.kind = kind;
        let now = Self::now_rfc3339();
        let mut inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        if let Some(prev) = inner.credentials.get(&cred.id) {
            cred.created_at = prev.created_at.clone();
        } else if cred.created_at.is_empty() {
            cred.created_at = now.clone();
        }
        cred.updated_at = now;
        inner.credentials.insert(cred.id.clone(), cred.clone());
        drop(inner);
        self.mark_dirty();
        Ok(cred)
    }

    async fn get_credential(&self, id: &str) -> StoreResult<Option<StoredCredential>> {
        let key = cred_lookup_key(id);
        let inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        if let Some(c) = inner.credentials.get(&key) {
            return Ok(Some(c.clone()));
        }
        // Also match by basename if callers pass a full path.
        Ok(inner
            .credentials
            .values()
            .find(|c| c.id == key || id.ends_with(&c.id) || id.ends_with(&format!("/{}", c.id)))
            .cloned())
    }

    async fn list_credentials(&self, kind: Option<&str>) -> StoreResult<Vec<StoredCredential>> {
        let inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        let mut out: Vec<_> = inner
            .credentials
            .values()
            .filter(|c| kind.map(|k| c.kind.eq_ignore_ascii_case(k)).unwrap_or(true))
            .cloned()
            .collect();
        out.sort_by(|a, b| b.updated_at.cmp(&a.updated_at).then(a.id.cmp(&b.id)));
        Ok(out)
    }

    async fn delete_credential(&self, id: &str) -> StoreResult<bool> {
        let key = cred_lookup_key(id);
        let mut inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        let removed = inner.credentials.remove(&key).is_some();
        drop(inner);
        if removed {
            self.mark_dirty();
        }
        Ok(removed)
    }

    async fn clear_credentials(&self, kind: Option<&str>) -> StoreResult<usize> {
        let mut inner = self.inner.lock().map_err(|e| StoreError::Backend(e.to_string()))?;
        let before = inner.credentials.len();
        if let Some(k) = kind {
            inner
                .credentials
                .retain(|_, c| !c.kind.eq_ignore_ascii_case(k));
        } else {
            inner.credentials.clear();
        }
        let removed = before.saturating_sub(inner.credentials.len());
        drop(inner);
        if removed > 0 {
            self.mark_dirty();
        }
        Ok(removed)
    }
}

fn cred_lookup_key(id_or_path: &str) -> String {
    std::path::Path::new(id_or_path.trim())
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(id_or_path.trim())
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmite_proto::{
        CheckId, CheckType, Confidence, FindingId, FindingStatus, ObservationRef, ScanId,
        Severity,
    };
    use std::collections::BTreeMap;

    #[tokio::test]
    async fn upsert_enqueue_lease_complete() {
        let store = InMemoryStore::new();
        let tenant = Uuid::nil();
        let host = store
            .upsert_host(UpsertHost {
                id: None,
                tenant_id: tenant,
                display_name: "web-1".into(),
                primary_addr: Some("10.0.0.1".into()),
                ssh_port: Some(22),
                labels: BTreeMap::new(),
                timeouts: Default::default(),
                agent_kind: None,
                ingest_token: None,
            })
            .await
            .unwrap();

        let job = store
            .enqueue_scan(EnqueueScan {
                host_id: host.id,
                check_set: "standard".into(),
                priority: 50,
            })
            .await
            .unwrap();
        assert_eq!(job.state, "queued");

        let node = NodeId::new_v4();
        store
            .register_node(NodeRegistration {
                id: node,
                name: "n1".into(),
                capacity: 4,
                version: "0.1.0".into(),
            })
            .await
            .unwrap();

        let leased = store.lease_jobs(node, 2).await.unwrap();
        assert_eq!(leased.len(), 1);
        assert_eq!(leased[0].state, "leased");

        let finding = Finding {
            id: FindingId::new_v7(),
            scan_id: job.id,
            host_id: host.id,
            check_id: CheckId::new("RM-PROC-0001"),
            check_version: 1,
            check_type: CheckType::Process,
            severity: Severity::High,
            confidence: Confidence::High,
            title: "hidden process".into(),
            evidence: serde_json::Map::new(),
            observation_ref: ObservationRef {
                scan_id: job.id,
                seq: 0,
                kind: "hidden_process".into(),
            },
            attack: vec![],
            first_seen: "now".into(),
            last_seen: "now".into(),
            status: FindingStatus::New,
            suppressed_by: None,
            correlation_id: None,
        };
        store.insert_findings(vec![finding]).await.unwrap();
        let listed = store
            .list_findings(FindingFilter {
                host_id: Some(host.id),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(listed.len(), 1);

        use rustmite_proto::{Arch, DeliveryReport, ScanOutcome};
        let meta = ScanMeta {
            scan_id: job.id,
            host_id: host.id,
            node_id: node,
            outcome: ScanOutcome::Complete,
            delivery: DeliveryReport::default(),
            probe_version: "0.1.0".into(),
            arch: Arch::X86_64,
            kernel: "6.1".into(),
            os: None,
            os_id: None,
            os_version: None,
            boot_id: "x".into(),
            caps: Default::default(),
            collectors: vec![],
            applicable_checks: 1,
            fired: 1,
            not_applicable: 0,
            started_at: "a".into(),
            finished_at: "b".into(),
            duration_ms: 10,
            bytes_from_probe: 0,
            observation_count: 1,
            node_signature: None,
        };
        store
            .complete_scan(CompleteScan {
                scan_id: job.id,
                meta,
                outcome: "complete".into(),
            })
            .await
            .unwrap();
        let status = store.get_scan(job.id).await.unwrap();
        assert!(status.meta.is_some());
    }

    #[tokio::test]
    async fn update_and_delete_host_cascades() {
        let store = InMemoryStore::new();
        let host = store
            .upsert_host(UpsertHost {
                id: None,
                tenant_id: Uuid::nil(),
                display_name: "db-1".into(),
                primary_addr: Some("10.0.0.2".into()),
                ssh_port: Some(22),
                labels: BTreeMap::from([("env".into(), "prod".into())]),
                timeouts: Default::default(),
                agent_kind: None,
                ingest_token: None,
            })
            .await
            .unwrap();

        let updated = store
            .update_host(
                host.id,
                UpdateHost {
                    display_name: Some("db-1-renamed".into()),
                    ssh_port: Some(2222),
                    label_patch: Some(BTreeMap::from([
                        ("env".into(), "staging".into()),
                        ("tags".into(), "linux".into()),
                    ])),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.display_name, "db-1-renamed");
        assert_eq!(updated.ssh_port, 2222);
        assert_eq!(updated.labels.get("env").map(String::as_str), Some("staging"));
        assert_eq!(updated.labels.get("tags").map(String::as_str), Some("linux"));

        let job = store
            .enqueue_scan(EnqueueScan {
                host_id: host.id,
                check_set: "pulse".into(),
                priority: 1,
            })
            .await
            .unwrap();
        store
            .insert_findings(vec![Finding {
                id: FindingId::new_v7(),
                scan_id: job.id,
                host_id: host.id,
                check_id: CheckId::new("RM-TEST-0001"),
                check_version: 1,
                check_type: CheckType::Process,
                severity: Severity::Low,
                confidence: Confidence::High,
                title: "t".into(),
                evidence: serde_json::Map::new(),
                observation_ref: ObservationRef {
                    scan_id: job.id,
                    seq: 0,
                    kind: "process".into(),
                },
                attack: vec![],
                first_seen: "a".into(),
                last_seen: "a".into(),
                status: FindingStatus::New,
                suppressed_by: None,
                correlation_id: None,
            }])
            .await
            .unwrap();

        store.delete_host(host.id).await.unwrap();
        assert!(store.get_host(host.id).await.is_err());
        assert!(store.list_hosts().await.unwrap().is_empty());
        assert!(store
            .list_findings(FindingFilter {
                host_id: Some(host.id),
                limit: 10,
                ..Default::default()
            })
            .await
            .unwrap()
            .is_empty());
        assert!(
            store.list_scans(100).await.unwrap().is_empty(),
            "scan jobs for deleted host must be removed"
        );
        assert!(
            store
                .list_observations(Some(host.id), 100)
                .await
                .unwrap()
                .is_empty(),
            "observations for deleted host must be removed"
        );
        // Orphan scan metas must not linger (list_scans joins jobs↔metas).
        {
            let inner = store.inner.lock().unwrap();
            assert!(
                inner.metas.is_empty(),
                "scan metas for deleted host scans must be removed"
            );
        }
    }

    #[tokio::test]
    async fn delete_host_prunes_orphan_ssh_keys() {
        let store = InMemoryStore::new();
        let host = store
            .upsert_host(UpsertHost {
                id: None,
                tenant_id: Uuid::nil(),
                display_name: "ssh-host".into(),
                primary_addr: Some("10.0.0.9".into()),
                ssh_port: Some(22),
                labels: BTreeMap::new(),
                timeouts: Default::default(),
                agent_kind: None,
                ingest_token: None,
            })
            .await
            .unwrap();
        let keep = store
            .upsert_host(UpsertHost {
                id: None,
                tenant_id: Uuid::nil(),
                display_name: "keep-host".into(),
                primary_addr: Some("10.0.0.10".into()),
                ssh_port: Some(22),
                labels: BTreeMap::new(),
                timeouts: Default::default(),
                agent_kind: None,
                ingest_token: None,
            })
            .await
            .unwrap();

        store
            .upsert_ssh_placement(UpsertSshPlacement {
                fingerprint: "fp-orphan".into(),
                host_id: host.id,
                username: "root".into(),
                path: "/root/.ssh/authorized_keys".into(),
                role: "authorized".into(),
                key_type: "ssh-ed25519".into(),
                bits: None,
                comment: None,
                options: vec![],
                tags: vec![],
                seen_at: None,
            })
            .await
            .unwrap();
        store
            .upsert_ssh_placement(UpsertSshPlacement {
                fingerprint: "fp-shared".into(),
                host_id: host.id,
                username: "root".into(),
                path: "/root/.ssh/authorized_keys".into(),
                role: "authorized".into(),
                key_type: "ssh-ed25519".into(),
                bits: None,
                comment: None,
                options: vec![],
                tags: vec![],
                seen_at: None,
            })
            .await
            .unwrap();
        store
            .upsert_ssh_placement(UpsertSshPlacement {
                fingerprint: "fp-shared".into(),
                host_id: keep.id,
                username: "ubuntu".into(),
                path: "/home/ubuntu/.ssh/authorized_keys".into(),
                role: "authorized".into(),
                key_type: "ssh-ed25519".into(),
                bits: None,
                comment: None,
                options: vec![],
                tags: vec![],
                seen_at: None,
            })
            .await
            .unwrap();

        store.delete_host(host.id).await.unwrap();

        assert!(
            store.get_ssh_key("fp-orphan").await.unwrap().is_none(),
            "SSH key with no remaining placements must be pruned"
        );
        assert!(
            store.get_ssh_key("fp-shared").await.unwrap().is_some(),
            "SSH key still placed on another host must be kept"
        );
        assert!(
            store
                .list_ssh_placements(None, Some(host.id), None)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store
                .list_ssh_placements(Some("fp-shared"), None, None)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn snapshot_survives_reload() {
        let dir = std::env::temp_dir().join(format!("rustmite-store-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("store.json");
        let host_id;
        {
            let store = InMemoryStore::open(&path).unwrap();
            let host = store
                .upsert_host(UpsertHost {
                    id: None,
                    tenant_id: Uuid::nil(),
                    display_name: "keep-me".into(),
                    primary_addr: Some("10.1.2.3".into()),
                    ssh_port: Some(22),
                    labels: BTreeMap::new(),
                    timeouts: Default::default(),
                    agent_kind: None,
                    ingest_token: None,
                })
                .await
                .unwrap();
            host_id = host.id;
            store
                .insert_findings(vec![Finding {
                    id: FindingId::new_v7(),
                    scan_id: ScanId::new_v7(),
                    host_id,
                    check_id: CheckId::new("RM-TEST-0001"),
                    check_version: 1,
                    check_type: CheckType::Process,
                    severity: Severity::Low,
                    confidence: Confidence::High,
                    title: "survives restart".into(),
                    evidence: serde_json::Map::new(),
                    observation_ref: ObservationRef {
                        scan_id: ScanId::new_v7(),
                        seq: 0,
                        kind: "process".into(),
                    },
                    attack: vec![],
                    first_seen: "a".into(),
                    last_seen: "a".into(),
                    status: FindingStatus::New,
                    suppressed_by: None,
                    correlation_id: None,
                }])
                .await
                .unwrap();
            store.save().unwrap();
        }
        let restored = InMemoryStore::open(&path).unwrap();
        assert_eq!(restored.host_count(), 1);
        assert_eq!(restored.get_host(host_id).await.unwrap().display_name, "keep-me");
        assert_eq!(restored.finding_count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn import_heals_queued_job_that_already_has_meta() {
        use rustmite_proto::{
            Arch, DeliveryMethod, DeliveryReport, ScanMeta, ScanOutcome,
        };

        let dir = std::env::temp_dir().join(format!("rm-heal-{}", Uuid::now_v7()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("store.json");
        let scan_id = ScanId::new_v7();
        let host_id = HostId::new_v7();
        let node_id = NodeId::new_v7();

        {
            let store = InMemoryStore::open(&path).unwrap();
            store
                .upsert_host(UpsertHost {
                    id: Some(host_id),
                    tenant_id: Uuid::nil(),
                    display_name: "vm".into(),
                    primary_addr: Some("10.0.0.9".into()),
                    ssh_port: Some(22),
                    labels: BTreeMap::new(),
                    timeouts: Default::default(),
                    agent_kind: None,
                    ingest_token: None,
                })
                .await
                .unwrap();
            // Simulate restart requeue of a finished scan: meta present, state queued.
            {
                let mut inner = store.inner.lock().unwrap();
                inner.jobs.push(ScanJob {
                    id: scan_id,
                    host_id,
                    check_set: "standard".into(),
                    priority: 50,
                    state: "queued".into(),
                    leased_by: None,
                    attempts: 1,
                    progress_pct: Some(100),
                    progress_stage: Some("requeued after restart".into()),
                    updated_at: Some("t1".into()),
                });
                inner.metas.insert(
                    scan_id.0,
                    ScanMeta {
                        scan_id,
                        host_id,
                        node_id,
                        outcome: ScanOutcome::Complete,
                        delivery: DeliveryReport {
                            method: DeliveryMethod::Memfd,
                            encoder: None,
                            bytes_transferred: 0,
                            cleanup_ok: true,
                            cleanup_forced: false,
                            fallback_reason: None,
                        },
                        probe_version: "test".into(),
                        arch: Arch::X86_64,
                        kernel: "6".into(),
                        os: None,
                        os_id: None,
                        os_version: None,
                        boot_id: "b".into(),
                        caps: Default::default(),
                        collectors: vec![],
                        applicable_checks: 1,
                        fired: 0,
                        not_applicable: 0,
                        started_at: "t0".into(),
                        finished_at: "t1".into(),
                        duration_ms: 1,
                        bytes_from_probe: 0,
                        observation_count: 0,
                        node_signature: None,
                    },
                );
            }
            store.save().unwrap();
        }

        let restored = InMemoryStore::open(&path).unwrap();
        let scans = restored.list_scans(10).await.unwrap();
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].job.as_ref().unwrap().state, "complete");
        assert!(scans[0].meta.is_some());
        let q = restored.queue_snapshot().await.unwrap();
        assert_eq!(q.queued, 0);
        assert_eq!(q.complete, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn empty_caps_deserializes_in_scan_meta() {
        let raw = r#"{
            "scan_id":"00000000-0000-7000-8000-000000000001",
            "host_id":"00000000-0000-7000-8000-000000000002",
            "node_id":"00000000-0000-7000-8000-000000000003",
            "outcome":{"kind":"complete"},
            "delivery":{
                "method":"tmpfs","encoder":null,"bytes_transferred":0,
                "cleanup_ok":true,"cleanup_forced":false,"fallback_reason":null
            },
            "probe_version":"","arch":"unknown","kernel":"","boot_id":"",
            "caps":{},
            "collectors":[],
            "applicable_checks":0,"fired":0,"not_applicable":0,
            "started_at":"","finished_at":"","duration_ms":0,
            "bytes_from_probe":0,"observation_count":0,"node_signature":null
        }"#;
        let meta: rustmite_proto::ScanMeta = serde_json::from_str(raw).expect("caps {} ok");
        assert!(matches!(
            meta.outcome,
            rustmite_proto::ScanOutcome::Complete
        ));
    }

    #[tokio::test]
    async fn agentlite_kind_persists_on_upsert_and_update() {
        let store = InMemoryStore::new();
        let host = store
            .upsert_host(UpsertHost {
                id: None,
                tenant_id: Uuid::nil(),
                display_name: "lite-1".into(),
                primary_addr: Some("10.0.0.9".into()),
                ssh_port: Some(22),
                labels: BTreeMap::new(),
                timeouts: Default::default(),
                agent_kind: Some("agent_lite".into()),
                ingest_token: None,
            })
            .await
            .unwrap();
        assert_eq!(host.agent_kind, "agentlite");
        assert!(crate::types::is_agentlite_kind(&host.agent_kind));

        let updated = store
            .update_host(
                host.id,
                UpdateHost {
                    agent_kind: Some("ssh".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.agent_kind, "ssh");

        let back = store
            .update_host(
                host.id,
                UpdateHost {
                    agent_kind: Some("ssh_commands".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(back.agent_kind, "agentlite");
    }
}
