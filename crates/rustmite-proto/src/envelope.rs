//! NDJSON envelope stream from the probe.

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use crate::ids::CollectorId;
use crate::observation::Observation;
use crate::{Arch, CollectorStatus};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Envelope {
    Hello(Hello),
    Obs {
        c: String,
        n: u32,
        d: Observation,
    },
    CollectorStatus {
        c: String,
        status: CollectorStatus,
        reason: Option<String>,
        stats: Stats,
    },
    Summary(Summary),
    Error {
        c: Option<String>,
        code: String,
        msg: String,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Hello {
    pub schema: u16,
    pub probe_version: String,
    pub arch: Arch,
    pub kernel: String,
    pub boot_id: String,
    pub euid: u32,
    pub pid: i32,
    pub nonce: String,
    pub caps: CapabilitySet,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct CapabilitySet {
    pub memfd_create: bool,
    pub statx: bool,
    pub sock_diag: bool,
    pub bpf_prog_iter: bool,
    pub map_files: bool,
    pub cgroup_v2: bool,
    pub kallsyms_readable: bool,
    pub tracefs_readable: bool,
    pub proc_sched_debug: bool,
    pub audit_netlink: bool,
    pub proc_exe_readable: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct Stats {
    pub observations: u32,
    pub bytes_read: u64,
    pub elapsed_ms: u64,
    #[serde(default)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Summary {
    pub outcome: String,
    pub collectors: Vec<CollectorReport>,
    pub observation_count: u32,
    pub bytes_out: u64,
    pub elapsed_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CollectorReport {
    pub id: String,
    pub status: CollectorStatus,
    pub reason: Option<String>,
    pub observations: u32,
    pub elapsed_ms: u64,
}

impl CollectorReport {
    pub fn complete(id: CollectorId, observations: u32, elapsed_ms: u64) -> Self {
        Self {
            id: id.as_str().into(),
            status: CollectorStatus::Complete,
            reason: None,
            observations,
            elapsed_ms,
        }
    }

    pub fn unsupported(id: CollectorId, reason: impl Into<String>) -> Self {
        Self {
            id: id.as_str().into(),
            status: CollectorStatus::Unsupported,
            reason: Some(reason.into()),
            observations: 0,
            elapsed_ms: 0,
        }
    }

    pub fn not_applicable(id: CollectorId, reason: impl Into<String>) -> Self {
        Self {
            id: id.as_str().into(),
            status: CollectorStatus::NotApplicable,
            reason: Some(reason.into()),
            observations: 0,
            elapsed_ms: 0,
        }
    }

    pub fn failed(id: CollectorId, reason: impl Into<String>) -> Self {
        Self {
            id: id.as_str().into(),
            status: CollectorStatus::Failed,
            reason: Some(reason.into()),
            observations: 0,
            elapsed_ms: 0,
        }
    }
}
