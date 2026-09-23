use async_trait::async_trait;
use rustmite_proto::{Finding, NodeId, Observation};
use uuid::Uuid;

use crate::error::StoreResult;
use crate::types::{
    ActivityEvent, CompleteScan, DeleteHostsRequest, DeleteHostsResult, EnqueueScan, FindingFilter,
    HostKeyPin, HostRecord, NodeRegistration, QueueSnapshot, ScanJob, ScanStatus, SshKeyPlacement,
    SshKeyRecord, SshSecurityZone, StoredObservation, TagSshKeysRequest, UpdateHost, UpsertHost,
    UpsertSshPlacement, UpsertSshZone,
};

#[async_trait]
pub trait Store: Send + Sync {
    async fn upsert_host(&self, req: UpsertHost) -> StoreResult<HostRecord>;
    async fn list_hosts(&self) -> StoreResult<Vec<HostRecord>>;
    async fn get_host(&self, id: rustmite_proto::HostId) -> StoreResult<HostRecord> {
        self.list_hosts()
            .await?
            .into_iter()
            .find(|h| h.id == id)
            .ok_or_else(|| crate::error::StoreError::NotFound(format!("host {id}")))
    }
    async fn update_host(
        &self,
        id: rustmite_proto::HostId,
        req: UpdateHost,
    ) -> StoreResult<HostRecord> {
        let _ = (id, req);
        Err(crate::error::StoreError::Backend(
            "update_host not implemented".into(),
        ))
    }
    async fn delete_host(&self, id: rustmite_proto::HostId) -> StoreResult<()> {
        let _ = id;
        Err(crate::error::StoreError::Backend(
            "delete_host not implemented".into(),
        ))
    }
    async fn delete_hosts(&self, req: DeleteHostsRequest) -> StoreResult<DeleteHostsResult> {
        let mut deleted = 0;
        let mut missing = Vec::new();
        for id in req.host_ids {
            match self.delete_host(id).await {
                Ok(()) => deleted += 1,
                Err(crate::error::StoreError::NotFound(_)) => missing.push(id),
                Err(e) => return Err(e),
            }
        }
        Ok(DeleteHostsResult { deleted, missing })
    }
    async fn enqueue_scan(&self, req: EnqueueScan) -> StoreResult<ScanJob>;
    async fn lease_jobs(&self, node_id: NodeId, capacity: usize) -> StoreResult<Vec<ScanJob>>;
    async fn complete_scan(&self, req: CompleteScan) -> StoreResult<()>;
    async fn insert_observations(&self, rows: Vec<StoredObservation>) -> StoreResult<()>;
    async fn insert_findings(&self, findings: Vec<Finding>) -> StoreResult<()>;
    async fn list_findings(&self, filter: FindingFilter) -> StoreResult<Vec<Finding>>;

    /// Drop prior findings for `host_id` whose `check_id` is in `check_ids`.
    /// Used so a re-scan that re-evaluates a check clears stale alerts (e.g. fixed FPs).
    async fn clear_findings_for_host_checks(
        &self,
        host_id: rustmite_proto::HostId,
        check_ids: &[&str],
    ) -> StoreResult<()> {
        let _ = (host_id, check_ids);
        Ok(())
    }

    /// Drop all findings whose `check_id` is in `check_ids` (fleet-wide).
    async fn clear_findings_by_checks(&self, check_ids: &[&str]) -> StoreResult<usize> {
        let _ = check_ids;
        Ok(0)
    }

    /// Drop every finding (fleet-wide cleanup).
    async fn clear_all_findings(&self) -> StoreResult<usize> {
        Ok(0)
    }

    /// Drop scan jobs + metas (history and queue).
    async fn clear_all_scans(&self) -> StoreResult<usize> {
        Ok(0)
    }

    /// Drop stored scan observations (control-plane).
    async fn clear_all_observations(&self) -> StoreResult<usize> {
        Ok(0)
    }

    /// Drop activity feed events.
    async fn clear_all_activity(&self) -> StoreResult<usize> {
        Ok(0)
    }

    /// Drop host baselines (integrity / drift snapshots).
    async fn clear_all_baselines(&self) -> StoreResult<usize> {
        Ok(0)
    }

    /// Drop pinned SSH host keys.
    async fn clear_all_host_keys(&self) -> StoreResult<usize> {
        Ok(0)
    }

    /// Keep the newest `keep` finished scans per host (active jobs always retained).
    /// When `host_id` is `None`, prune every host. Returns number of scan jobs removed.
    async fn prune_scan_history(
        &self,
        host_id: Option<rustmite_proto::HostId>,
        keep: usize,
    ) -> StoreResult<usize> {
        let _ = (host_id, keep);
        Ok(0)
    }

    /// Counts for the Data page.
    async fn data_counts(&self) -> StoreResult<crate::types::DataCounts> {
        Ok(crate::types::DataCounts::default())
    }

    async fn list_scans(&self, limit: usize) -> StoreResult<Vec<ScanStatus>> {
        let _ = limit;
        Ok(vec![])
    }

    async fn list_nodes(&self) -> StoreResult<Vec<NodeRegistration>> {
        Ok(vec![])
    }

    async fn push_activity(&self, event: ActivityEvent) -> StoreResult<()> {
        let _ = event;
        Ok(())
    }

    async fn list_activity(&self, limit: usize) -> StoreResult<Vec<ActivityEvent>> {
        let _ = limit;
        Ok(vec![])
    }

    async fn queue_snapshot(&self) -> StoreResult<QueueSnapshot> {
        Ok(QueueSnapshot::default())
    }

    async fn update_scan_progress(
        &self,
        scan_id: rustmite_proto::ScanId,
        state: &str,
        stage: Option<&str>,
        pct: Option<u8>,
    ) -> StoreResult<()> {
        let _ = (scan_id, state, stage, pct);
        Ok(())
    }

    async fn get_scan(&self, scan_id: rustmite_proto::ScanId) -> StoreResult<ScanStatus> {
        let _ = scan_id;
        Ok(ScanStatus::default())
    }

    async fn register_node(&self, reg: NodeRegistration) -> StoreResult<()> {
        let _ = reg;
        Ok(())
    }

    async fn heartbeat_node(&self, node_id: NodeId, in_flight: i32) -> StoreResult<()> {
        let _ = (node_id, in_flight);
        Ok(())
    }

    async fn pin_host_key(&self, pin: HostKeyPin) -> StoreResult<()> {
        let _ = pin;
        Ok(())
    }

    async fn get_host_key(
        &self,
        host_id: rustmite_proto::HostId,
    ) -> StoreResult<Option<HostKeyPin>> {
        let _ = host_id;
        Ok(None)
    }

    async fn list_observations(
        &self,
        host_id: Option<rustmite_proto::HostId>,
        limit: usize,
    ) -> StoreResult<Vec<StoredObservation>> {
        let _ = (host_id, limit);
        Ok(vec![])
    }

    /// Observations of a single `kind` for a host, taken from the latest scan
    /// that produced that kind (avoids truncation when other kinds dominate).
    async fn list_observations_of_kind(
        &self,
        host_id: rustmite_proto::HostId,
        kind: &str,
        limit: usize,
    ) -> StoreResult<(Option<rustmite_proto::ScanId>, Vec<StoredObservation>)> {
        let rows = self.list_observations(Some(host_id), limit.max(1) * 4).await?;
        let latest = rows.iter().rev().find(|o| o.kind == kind).map(|o| o.scan_id);
        let Some(scan_id) = latest else {
            return Ok((None, Vec::new()));
        };
        let out: Vec<_> = rows
            .into_iter()
            .filter(|o| o.kind == kind && o.scan_id == scan_id)
            .take(limit.max(1))
            .collect();
        Ok((Some(scan_id), out))
    }

    async fn upsert_baseline(
        &self,
        host_id: rustmite_proto::HostId,
        name: &str,
        payload: serde_json::Value,
    ) -> StoreResult<()> {
        let _ = (host_id, name, payload);
        Ok(())
    }

    async fn get_baseline(
        &self,
        host_id: rustmite_proto::HostId,
        name: &str,
    ) -> StoreResult<Option<serde_json::Value>> {
        let _ = (host_id, name);
        Ok(None)
    }

    // —— SSH Hunter (key graph) ————————————————————————————————

    async fn upsert_ssh_placement(&self, req: UpsertSshPlacement) -> StoreResult<SshKeyRecord> {
        let _ = req;
        Err(crate::error::StoreError::Backend(
            "upsert_ssh_placement not implemented".into(),
        ))
    }

    async fn list_ssh_keys(&self) -> StoreResult<Vec<SshKeyRecord>> {
        Ok(vec![])
    }

    async fn get_ssh_key(&self, fingerprint: &str) -> StoreResult<Option<SshKeyRecord>> {
        Ok(self
            .list_ssh_keys()
            .await?
            .into_iter()
            .find(|k| k.fingerprint == fingerprint))
    }

    async fn list_ssh_placements(
        &self,
        fingerprint: Option<&str>,
        host_id: Option<rustmite_proto::HostId>,
        username: Option<&str>,
    ) -> StoreResult<Vec<SshKeyPlacement>> {
        let _ = (fingerprint, host_id, username);
        Ok(vec![])
    }

    async fn tag_ssh_keys(&self, req: TagSshKeysRequest) -> StoreResult<usize> {
        let _ = req;
        Ok(0)
    }

    async fn list_ssh_key_tags(&self) -> StoreResult<Vec<String>> {
        Ok(vec![])
    }

    async fn list_ssh_zones(&self) -> StoreResult<Vec<SshSecurityZone>> {
        Ok(vec![])
    }

    async fn upsert_ssh_zone(&self, req: UpsertSshZone) -> StoreResult<SshSecurityZone> {
        let _ = req;
        Err(crate::error::StoreError::Backend(
            "upsert_ssh_zone not implemented".into(),
        ))
    }

    async fn delete_ssh_zone(&self, id: Uuid) -> StoreResult<()> {
        let _ = id;
        Err(crate::error::StoreError::Backend(
            "delete_ssh_zone not implemented".into(),
        ))
    }

    /// Upsert a node-sealed SSH credential (ciphertext only).
    async fn upsert_credential(
        &self,
        cred: crate::types::StoredCredential,
    ) -> StoreResult<crate::types::StoredCredential> {
        let _ = cred;
        Err(crate::error::StoreError::Backend(
            "upsert_credential not implemented".into(),
        ))
    }

    async fn get_credential(
        &self,
        id: &str,
    ) -> StoreResult<Option<crate::types::StoredCredential>> {
        let _ = id;
        Ok(None)
    }

    async fn list_credentials(
        &self,
        kind: Option<&str>,
    ) -> StoreResult<Vec<crate::types::StoredCredential>> {
        let _ = kind;
        Ok(vec![])
    }

    async fn delete_credential(&self, id: &str) -> StoreResult<bool> {
        let _ = id;
        Ok(false)
    }

    async fn clear_credentials(&self, kind: Option<&str>) -> StoreResult<usize> {
        let _ = kind;
        Ok(0)
    }

    /// Convenience: wrap typed observations into stored rows.
    async fn insert_observations_typed(
        &self,
        scan_id: rustmite_proto::ScanId,
        host_id: rustmite_proto::HostId,
        collector: &str,
        observations: Vec<Observation>,
    ) -> StoreResult<()> {
        let rows = observations
            .into_iter()
            .enumerate()
            .map(|(i, data)| {
                let kind = observation_kind(&data);
                StoredObservation {
                    scan_id,
                    host_id,
                    seq: i as u32,
                    collector: collector.to_string(),
                    kind,
                    data,
                }
            })
            .collect();
        self.insert_observations(rows).await
    }
}

fn observation_kind(o: &Observation) -> String {
    match o {
        Observation::Process(_) => "process",
        Observation::HiddenProcess(_) => "hidden_process",
        Observation::Socket(_) => "socket",
        Observation::HiddenSocket(_) => "hidden_socket",
        Observation::Module(_) => "module",
        Observation::HiddenModule(_) => "hidden_module",
        Observation::BpfProg(_) => "bpf_prog",
        Observation::FileMeta(_) => "file_meta",
        Observation::FileEntropy(_) => "file_entropy",
        Observation::ElfInfo(_) => "elf_info",
        Observation::Preload(_) => "preload",
        Observation::ScheduledTask(_) => "scheduled_task",
        Observation::Service(_) => "service",
        Observation::Account(_) => "account",
        Observation::ShadowEntry(_) => "shadow_entry",
        Observation::SudoRule(_) => "sudo_rule",
        Observation::AuthorizedKey(_) => "authorized_key",
        Observation::SshHostKey(_) => "ssh_host_key",
        Observation::DirAnomaly(_) => "dir_anomaly",
        Observation::Timestomp(_) => "timestomp",
        Observation::Mount(_) => "mount",
        Observation::LogIntegrity(_) => "log_integrity",
        Observation::UtmpSession(_) => "utmp_session",
        Observation::IntegrityMismatch(_) => "integrity_mismatch",
        Observation::IocHit(_) => "ioc_hit",
        Observation::ContainerInfo(_) => "container_info",
        Observation::Recon(_) => "recon",
        Observation::Policy(_) => "policy",
    }
    .to_string()
}
