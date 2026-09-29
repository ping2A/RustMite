use rustmite_proto::{Finding, HostId, NodeId, Observation, ScanId, ScanMeta, Severity};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostTimeouts {
    /// Sleep before opening TCP (stagger / rate-limit), milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_delay_ms: Option<u64>,
    /// TCP + SSH handshake timeout (seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_timeout_secs: Option<u64>,
    /// Public-key auth timeout (seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_timeout_secs: Option<u64>,
    /// Per remote command / fingerprint exec timeout (seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cmd_timeout_secs: Option<u64>,
    /// SSH channel inactivity timeout (seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inactivity_timeout_secs: Option<u64>,
    /// Probe delivery wall-clock (seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_timeout_secs: Option<u64>,
    /// Full scan deadline override (seconds); falls back to fleet `scan_timeout_secs`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_timeout_secs: Option<u64>,
}

impl Default for HostTimeouts {
    fn default() -> Self {
        Self {
            connect_delay_ms: None,
            connect_timeout_secs: None,
            auth_timeout_secs: None,
            cmd_timeout_secs: None,
            inactivity_timeout_secs: None,
            delivery_timeout_secs: None,
            scan_timeout_secs: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostRecord {
    pub id: HostId,
    pub tenant_id: Uuid,
    pub display_name: String,
    pub primary_addr: Option<String>,
    pub ssh_port: u16,
    pub arch: Option<String>,
    pub kernel: Option<String>,
    /// Human OS label (`PRETTY_NAME` from `/etc/os-release`, else `uname -s`).
    #[serde(default)]
    pub os: Option<String>,
    /// Distro id (`ubuntu`, `debian`, `rhel`, …).
    #[serde(default)]
    pub os_id: Option<String>,
    /// Distro version id (`22.04`, `9`, …).
    #[serde(default)]
    pub os_version: Option<String>,
    /// `ssh` (default) = ephemeral probe over SSH; `agentlite` = SSH commands only (no binary);
    /// `virtual` = log-only ingest host.
    #[serde(default = "default_agent_kind")]
    pub agent_kind: String,
    /// Bearer token for `POST /v1/ingest/logs` (virtual agents).
    #[serde(default)]
    pub ingest_token: Option<String>,
    pub labels: BTreeMap<String, String>,
    pub last_scan_at: Option<String>,
    pub last_outcome: Option<String>,
    /// Per-host delay / connection / command timeouts (unset → fleet defaults).
    #[serde(default)]
    pub timeouts: HostTimeouts,
    /// Last connectivity / auth check: ok | unreachable | no_sshd | auth_failed | no_credential | partial | never
    #[serde(default)]
    pub auth_status: Option<String>,
    #[serde(default)]
    pub auth_detail: Option<String>,
    #[serde(default)]
    pub auth_checked_at: Option<String>,
}

fn default_agent_kind() -> String {
    "ssh".into()
}

/// Normalize host agent kind to a canonical value.
pub fn normalize_agent_kind(raw: &str) -> String {
    match raw.trim().to_ascii_lowercase().as_str() {
        "virtual" | "virt" | "ingest" => "virtual".into(),
        "agentlite" | "agent_lite" | "lite" | "ssh_commands" | "pure_command" => {
            "agentlite".into()
        }
        _ => "ssh".into(),
    }
}

/// True when the host uses SSH-commands-only collection (no probe binary).
pub fn is_agentlite_kind(kind: &str) -> bool {
    normalize_agent_kind(kind) == "agentlite"
}

#[cfg(test)]
mod agent_kind_tests {
    use super::*;

    #[test]
    fn normalize_agent_kind_aliases() {
        for raw in ["agentlite", "AgentLite", "agent_lite", "lite", "ssh_commands", "pure_command"] {
            assert_eq!(normalize_agent_kind(raw), "agentlite", "{raw}");
            assert!(is_agentlite_kind(raw));
        }
        for raw in ["virtual", "virt", "ingest", "VIRTUAL"] {
            assert_eq!(normalize_agent_kind(raw), "virtual", "{raw}");
            assert!(!is_agentlite_kind(raw));
        }
        for raw in ["ssh", "", "probe", "full"] {
            assert_eq!(normalize_agent_kind(raw), "ssh", "{raw}");
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpsertHost {
    pub id: Option<HostId>,
    pub tenant_id: Uuid,
    pub display_name: String,
    pub primary_addr: Option<String>,
    pub ssh_port: Option<u16>,
    pub labels: BTreeMap<String, String>,
    #[serde(default)]
    pub timeouts: HostTimeouts,
    /// `ssh` (default), `agentlite`, or `virtual`.
    #[serde(default)]
    pub agent_kind: Option<String>,
    #[serde(default)]
    pub ingest_token: Option<String>,
}

/// Partial update for an existing host (PATCH /v1/hosts/{id}).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UpdateHost {
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub primary_addr: Option<String>,
    #[serde(default)]
    pub ssh_port: Option<u16>,
    /// When set, replaces the full labels map.
    #[serde(default)]
    pub labels: Option<BTreeMap<String, String>>,
    /// When set, merges into existing labels (empty string removes a key).
    #[serde(default)]
    pub label_patch: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub timeouts: Option<HostTimeouts>,
    #[serde(default)]
    pub auth_status: Option<String>,
    #[serde(default)]
    pub auth_detail: Option<String>,
    #[serde(default)]
    pub auth_checked_at: Option<String>,
    #[serde(default)]
    pub arch: Option<String>,
    #[serde(default)]
    pub kernel: Option<String>,
    #[serde(default)]
    pub os: Option<String>,
    #[serde(default)]
    pub os_id: Option<String>,
    #[serde(default)]
    pub os_version: Option<String>,
    #[serde(default)]
    pub agent_kind: Option<String>,
    #[serde(default)]
    pub ingest_token: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeleteHostsRequest {
    pub host_ids: Vec<HostId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeleteHostsResult {
    pub deleted: usize,
    pub missing: Vec<HostId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnqueueScan {
    pub host_id: HostId,
    pub check_set: String,
    pub priority: i32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanJob {
    pub id: ScanId,
    pub host_id: HostId,
    pub check_set: String,
    pub priority: i32,
    pub state: String,
    pub leased_by: Option<NodeId>,
    pub attempts: i32,
    /// 0–100 while running; None when idle/complete.
    #[serde(default)]
    pub progress_pct: Option<u8>,
    /// Human stage label (e.g. "delivering probe", "collector:decloak.process").
    #[serde(default)]
    pub progress_stage: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

/// Operator-console activity / scan progress log line.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActivityEvent {
    pub id: Uuid,
    pub ts: String,
    /// info | progress | warn | error
    pub level: String,
    /// e.g. scan.queued, scan.running, scan.collector, scan.complete, scan.error
    pub kind: String,
    pub message: String,
    pub scan_id: Option<ScanId>,
    pub host_id: Option<HostId>,
    pub node_id: Option<NodeId>,
    #[serde(default)]
    pub detail: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DataCounts {
    pub hosts: usize,
    pub findings: usize,
    pub scans: usize,
    pub observations: usize,
    pub activity: usize,
    pub nodes: usize,
    #[serde(default)]
    pub baselines: usize,
    #[serde(default)]
    pub host_keys: usize,
    #[serde(default)]
    pub ssh_keys: usize,
    #[serde(default)]
    pub ssh_placements: usize,
    #[serde(default)]
    pub ssh_zones: usize,
    #[serde(default)]
    pub credentials: usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct QueueSnapshot {
    pub queued: usize,
    pub leased: usize,
    pub running: usize,
    pub complete: usize,
    pub failed: usize,
    pub active: Vec<ScanJob>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredObservation {
    pub scan_id: ScanId,
    pub host_id: HostId,
    pub seq: u32,
    pub collector: String,
    pub kind: String,
    pub data: Observation,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FindingFilter {
    pub host_id: Option<HostId>,
    pub severity: Option<Severity>,
    pub check_id: Option<String>,
    pub limit: usize,
}

impl Default for FindingFilter {
    fn default() -> Self {
        Self {
            host_id: None,
            severity: None,
            check_id: None,
            limit: 100,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompleteScan {
    pub scan_id: ScanId,
    pub meta: ScanMeta,
    pub outcome: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeRegistration {
    pub id: NodeId,
    pub name: String,
    pub capacity: i32,
    pub version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostKeyPin {
    pub host_id: HostId,
    pub key_type: String,
    pub fingerprint: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ScanStatus {
    pub job: Option<ScanJob>,
    pub meta: Option<ScanMeta>,
    pub findings: Vec<Finding>,
}

/// Fleet-wide SSH public key (SSH Hunter).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SshKeyRecord {
    pub fingerprint: String,
    pub key_type: String,
    #[serde(default)]
    pub bits: Option<u32>,
    #[serde(default)]
    pub comment: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Node-sealed SSH credential (identity PEM or password).
///
/// The control plane stores ciphertext only (`sealed_b64`). Scanner nodes decrypt
/// with their private credential key. Compromising the DB alone cannot recover SSH secrets.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredCredential {
    /// Stable id — same naming scheme as legacy filenames (`{stamp}-{hint}`).
    pub id: String,
    /// `identity` (private key) or `password`.
    pub kind: String,
    /// Base64 of `RMBOX1` sealed blob (never plaintext).
    pub sealed_b64: String,
    /// Plaintext length before sealing (for UI sizing; not the secret).
    #[serde(default)]
    pub plaintext_bytes: u64,
    pub created_at: String,
    pub updated_at: String,
}

/// Where an SSH key was observed (authorized_keys / host key / pub file).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SshKeyPlacement {
    pub fingerprint: String,
    pub host_id: HostId,
    pub username: String,
    pub path: String,
    /// authorized | host | user_private_pub
    pub role: String,
    #[serde(default)]
    pub options: Vec<String>,
    pub seen_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpsertSshPlacement {
    pub fingerprint: String,
    pub key_type: String,
    #[serde(default)]
    pub bits: Option<u32>,
    #[serde(default)]
    pub comment: Option<String>,
    pub host_id: HostId,
    pub username: String,
    pub path: String,
    #[serde(default = "default_ssh_role")]
    pub role: String,
    #[serde(default)]
    pub options: Vec<String>,
    #[serde(default)]
    pub seen_at: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

fn default_ssh_role() -> String {
    "authorized".into()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SshSecurityZone {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    /// Host label tags that belong to this zone (match `labels.tags` / env / profile).
    #[serde(default)]
    pub host_selectors: Vec<String>,
    /// Key tags that are allowed / expected in this zone.
    #[serde(default)]
    pub key_tags: Vec<String>,
    /// allow | alert_on_cross_zone | deny_unknown
    #[serde(default = "default_zone_policy")]
    pub policy: String,
}

fn default_zone_policy() -> String {
    "alert_on_cross_zone".into()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpsertSshZone {
    pub id: Option<Uuid>,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub host_selectors: Vec<String>,
    #[serde(default)]
    pub key_tags: Vec<String>,
    #[serde(default = "default_zone_policy")]
    pub policy: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TagSshKeysRequest {
    pub fingerprints: Vec<String>,
    /// Tags to add (merged with existing).
    #[serde(default)]
    pub add: Vec<String>,
    /// Tags to remove.
    #[serde(default)]
    pub remove: Vec<String>,
    /// When set, replace the full tag set instead of merge.
    #[serde(default)]
    pub set: Option<Vec<String>>,
}

