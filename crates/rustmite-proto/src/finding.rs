//! Finding and scan metadata types.

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ids::{CheckId, FindingId, HostId, NodeId, ScanId};
use crate::{
    Arch, CheckType, Confidence, DeliveryMethod, FindingStatus, ScanOutcome, Severity,
};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub id: FindingId,
    pub scan_id: ScanId,
    pub host_id: HostId,
    pub check_id: CheckId,
    pub check_version: u32,
    pub check_type: CheckType,
    pub severity: Severity,
    pub confidence: Confidence,
    pub title: String,
    pub evidence: serde_json::Map<String, serde_json::Value>,
    pub observation_ref: ObservationRef,
    pub attack: Vec<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub status: FindingStatus,
    pub suppressed_by: Option<String>,
    pub correlation_id: Option<Uuid>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ObservationRef {
    pub scan_id: ScanId,
    pub seq: u32,
    pub kind: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ScanMeta {
    pub scan_id: ScanId,
    pub host_id: HostId,
    pub node_id: NodeId,
    pub outcome: ScanOutcome,
    pub delivery: DeliveryReport,
    pub probe_version: String,
    pub arch: Arch,
    pub kernel: String,
    /// Distro pretty name when known (`PRETTY_NAME`).
    #[serde(default)]
    pub os: Option<String>,
    #[serde(default)]
    pub os_id: Option<String>,
    #[serde(default)]
    pub os_version: Option<String>,
    pub boot_id: String,
    pub caps: crate::CapabilitySet,
    pub collectors: Vec<crate::CollectorReport>,
    pub applicable_checks: u32,
    pub fired: u32,
    pub not_applicable: u32,
    pub started_at: String,
    pub finished_at: String,
    pub duration_ms: u64,
    pub bytes_from_probe: u64,
    pub observation_count: u32,
    pub node_signature: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeliveryReport {
    pub method: DeliveryMethod,
    pub encoder: Option<String>,
    pub bytes_transferred: u64,
    pub cleanup_ok: bool,
    pub cleanup_forced: bool,
    pub fallback_reason: Option<String>,
}

impl Default for DeliveryReport {
    fn default() -> Self {
        Self {
            method: DeliveryMethod::Memfd,
            encoder: None,
            bytes_transferred: 0,
            cleanup_ok: true,
            cleanup_forced: false,
            fallback_reason: None,
        }
    }
}
