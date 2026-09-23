//! Scan request / plan types (probe stdin).

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::enums::ProbeMode;
use crate::SCHEMA_VERSION;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ScanRequest {
    pub schema: u16,
    pub scan_id: Uuid,
    pub nonce: [u8; 32],
    pub deadline_ms: u32,
    pub mode: ProbeMode,
    pub plan: CollectionPlan,
    pub limits: Limits,
    pub issued_at: u64,
    pub issuer_sig: Option<String>,
}

impl ScanRequest {
    pub fn new_scan(scan_id: Uuid, collectors: Vec<CollectorSpec>) -> Self {
        Self {
            schema: SCHEMA_VERSION,
            scan_id,
            nonce: [0u8; 32],
            deadline_ms: 60_000,
            mode: ProbeMode::Scan,
            plan: CollectionPlan {
                collectors,
                scopes: PathScopes::default(),
                prefilters: Vec::new(),
                ioc: IocSet::default(),
                compress_output: false,
            },
            limits: Limits::default(),
            issued_at: 0,
            issuer_sig: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct CollectionPlan {
    pub collectors: Vec<CollectorSpec>,
    pub scopes: PathScopes,
    pub prefilters: Vec<CompiledPredicate>,
    pub ioc: IocSet,
    #[serde(default)]
    pub compress_output: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CollectorSpec {
    pub id: String,
    #[serde(default)]
    pub options: serde_json::Map<String, serde_json::Value>,
}

impl CollectorSpec {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            options: serde_json::Map::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct PathScopes {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub max_depth: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompiledPredicate {
    pub bytecode: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct IocSet {
    pub hashes_sha256: Vec<String>,
    pub path_globs: Vec<String>,
    pub strings: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Limits {
    pub max_rss_bytes: u64,
    pub max_observations: u32,
    pub max_output_bytes: u64,
    pub max_files_examined: u32,
    pub max_bytes_hashed: u64,
    pub nice: i8,
    pub io_idle: bool,
    /// Cap probe + result transfer rate (bytes/sec). `0` = unlimited.
    #[serde(default)]
    pub max_transfer_bps: u64,
    /// Soft CPU target percent (1–100). `0` = rely on `nice` / SCHED_IDLE only.
    #[serde(default)]
    pub max_cpu_pct: u8,
    /// RLIMIT_NOFILE soft ceiling. `0` = leave process default.
    #[serde(default)]
    pub max_open_files: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_rss_bytes: 24 * 1024 * 1024,
            max_observations: 500_000,
            max_output_bytes: 64 * 1024 * 1024,
            max_files_examined: 2_000_000,
            max_bytes_hashed: 8 * 1024 * 1024 * 1024,
            nice: 19,
            io_idle: true,
            max_transfer_bps: 0,
            max_cpu_pct: 0,
            max_open_files: 256,
        }
    }
}

/// Budget tracker used by collectors (cooperative).
#[derive(Debug)]
pub struct Budget {
    pub max_observations: u32,
    pub max_output_bytes: u64,
    pub max_files: u32,
    pub max_bytes_hashed: u64,
    pub deadline_ms: u32,
    observations: core::sync::atomic::AtomicU32,
    bytes_out: core::sync::atomic::AtomicU64,
    files: core::sync::atomic::AtomicU32,
    bytes_hashed: core::sync::atomic::AtomicU64,
    pub start_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BudgetExceeded {
    Observations,
    OutputBytes,
    Files,
    BytesHashed,
    Deadline,
}

impl core::fmt::Display for BudgetExceeded {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Observations => f.write_str("max_observations exceeded"),
            Self::OutputBytes => f.write_str("max_output_bytes exceeded"),
            Self::Files => f.write_str("max_files_examined exceeded"),
            Self::BytesHashed => f.write_str("max_bytes_hashed exceeded"),
            Self::Deadline => f.write_str("deadline_ms exceeded"),
        }
    }
}

impl Budget {
    pub fn new(limits: &Limits, deadline_ms: u32, start_ms: u64) -> Self {
        Self {
            max_observations: limits.max_observations,
            max_output_bytes: limits.max_output_bytes,
            max_files: limits.max_files_examined,
            max_bytes_hashed: limits.max_bytes_hashed,
            deadline_ms,
            observations: core::sync::atomic::AtomicU32::new(0),
            bytes_out: core::sync::atomic::AtomicU64::new(0),
            files: core::sync::atomic::AtomicU32::new(0),
            bytes_hashed: core::sync::atomic::AtomicU64::new(0),
            start_ms,
        }
    }

    pub fn check(&self, now_ms: u64) -> Result<(), BudgetExceeded> {
        if self.deadline_ms > 0
            && now_ms.saturating_sub(self.start_ms) > u64::from(self.deadline_ms)
        {
            return Err(BudgetExceeded::Deadline);
        }
        if self.observations.load(core::sync::atomic::Ordering::Relaxed) >= self.max_observations {
            return Err(BudgetExceeded::Observations);
        }
        if self.bytes_out.load(core::sync::atomic::Ordering::Relaxed) >= self.max_output_bytes {
            return Err(BudgetExceeded::OutputBytes);
        }
        if self.files.load(core::sync::atomic::Ordering::Relaxed) >= self.max_files {
            return Err(BudgetExceeded::Files);
        }
        if self
            .bytes_hashed
            .load(core::sync::atomic::Ordering::Relaxed)
            >= self.max_bytes_hashed
        {
            return Err(BudgetExceeded::BytesHashed);
        }
        Ok(())
    }

    /// Wall-clock check (probe / live collectors).
    #[cfg(feature = "std")]
    pub fn check_wall(&self) -> Result<(), BudgetExceeded> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        self.check(now)
    }

    pub fn record_observation(&self) {
        self.observations
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }

    pub fn record_bytes(&self, n: u64) {
        self.bytes_out
            .fetch_add(n, core::sync::atomic::Ordering::Relaxed);
    }

    pub fn record_file(&self) {
        self.files
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }

    pub fn record_bytes_hashed(&self, n: u64) {
        self.bytes_hashed
            .fetch_add(n, core::sync::atomic::Ordering::Relaxed);
    }

    pub fn observation_count(&self) -> u32 {
        self.observations
            .load(core::sync::atomic::Ordering::Relaxed)
    }

    pub fn files_examined(&self) -> u32 {
        self.files.load(core::sync::atomic::Ordering::Relaxed)
    }

    pub fn bytes_hashed(&self) -> u64 {
        self.bytes_hashed
            .load(core::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
mod budget_tests {
    use super::*;

    fn tight_limits() -> Limits {
        Limits {
            max_rss_bytes: 8 * 1024 * 1024,
            max_observations: 3,
            max_output_bytes: 100,
            max_files_examined: 2,
            max_bytes_hashed: 50,
            nice: 19,
            io_idle: true,
            max_transfer_bps: 1024,
            max_cpu_pct: 10,
            max_open_files: 32,
        }
    }

    #[test]
    fn deadline_trips() {
        let b = Budget::new(&tight_limits(), 100, 1_000);
        assert!(b.check(1_050).is_ok());
        assert_eq!(b.check(1_101), Err(BudgetExceeded::Deadline));
    }

    #[test]
    fn observations_cap() {
        let b = Budget::new(&tight_limits(), 60_000, 0);
        b.record_observation();
        b.record_observation();
        assert!(b.check(0).is_ok());
        b.record_observation();
        assert_eq!(b.check(0), Err(BudgetExceeded::Observations));
    }

    #[test]
    fn output_bytes_cap() {
        let b = Budget::new(&tight_limits(), 60_000, 0);
        b.record_bytes(99);
        assert!(b.check(0).is_ok());
        b.record_bytes(1);
        assert_eq!(b.check(0), Err(BudgetExceeded::OutputBytes));
    }

    #[test]
    fn files_and_hash_caps() {
        let b = Budget::new(&tight_limits(), 60_000, 0);
        b.record_file();
        assert!(b.check(0).is_ok());
        b.record_file();
        assert_eq!(b.check(0), Err(BudgetExceeded::Files));

        let b2 = Budget::new(&tight_limits(), 60_000, 0);
        b2.record_bytes_hashed(50);
        assert_eq!(b2.check(0), Err(BudgetExceeded::BytesHashed));
    }

    #[test]
    fn limits_serde_roundtrip_includes_transfer_and_cpu() {
        let l = tight_limits();
        let raw = serde_json::to_string(&l).unwrap();
        let back: Limits = serde_json::from_str(&raw).unwrap();
        assert_eq!(back.max_transfer_bps, 1024);
        assert_eq!(back.max_cpu_pct, 10);
        assert_eq!(back.max_open_files, 32);
        assert_eq!(back.nice, 19);
    }

    #[test]
    fn zero_deadline_means_unlimited_time() {
        let b = Budget::new(&Limits::default(), 0, 0);
        assert!(b.check(u64::MAX).is_ok());
    }

    #[test]
    fn display_messages_are_stable() {
        assert_eq!(
            BudgetExceeded::Deadline.to_string(),
            "deadline_ms exceeded"
        );
        assert_eq!(
            BudgetExceeded::Observations.to_string(),
            "max_observations exceeded"
        );
    }
}
