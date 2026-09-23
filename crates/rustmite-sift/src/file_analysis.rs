//! File-based fleet analysis: build file profiles and run DBSCAN + mtime anomaly detection.

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use chrono::{DateTime, Utc};
use ndarray::Array2;
use linfa::traits::Transformer;
use linfa_clustering::Dbscan;
use rayon::prelude::*;
use log;
use regex::Regex;

use crate::config::{DetectionConfig, FileRecentMtimeConfig};
use crate::interner::SharedInterner;
use crate::report::{AnalysisReport, AnalysisType, AnomalyDetails, AnomalyLevel};
use crate::types::{FileSignature, MachineFileProfile, RawFileEntry};
use crate::utils::{
    compile_regex_list, compile_wildcard_list, file_path_matches_exclusion,
    is_path_suspicious_compiled, is_path_whitelisted_compiled, parse_log_datetime,
    unix_permission_flags,
};

/// High-impact credential / boot paths: always eligible for the “recent mtime” signal (tighter
/// window than the old global 24h rule).
fn is_critical_credential_path(path: &str) -> bool {
    matches!(path, "/etc/shadow" | "/etc/gshadow")
        || path.starts_with("/etc/sudoers")
        || path.starts_with("/boot/")
        || path.ends_with("/authorized_keys")
}

/// System locations where a recent mtime matters only together with elevated or risky access.
fn is_system_path_for_recent_mtime(path: &str) -> bool {
    path.starts_with("/etc/")
        || path.starts_with("/bin/")
        || path.starts_with("/sbin/")
        || path.starts_with("/usr/bin/")
        || path.starts_with("/usr/sbin/")
        || path.starts_with("/root/")
        || path == "/etc"
}

fn is_volatile_recent_mtime_path(path: &str, cfg: &FileRecentMtimeConfig) -> bool {
    cfg.volatile_path_prefixes
        .iter()
        .any(|p| path.starts_with(p.as_str()))
}

/// Whether mtime was updated shortly before the observed access, in a **low-FP** way:
/// - Skip volatile paths (logs, caches, `/run`, …).
/// - Require modification at or before access (small clock skew allowed).
/// - Use short windows; do **not** flag routine user reads of recently updated config (e.g. apt).
fn recently_modified_heuristic(
    frt: &FileRecentMtimeConfig,
    path: &str,
    access: DateTime<Utc>,
    mtime: DateTime<Utc>,
    uid: u32,
    path_suspicious: bool,
    is_world_writable: bool,
    is_group_writable: bool,
) -> bool {
    if is_volatile_recent_mtime_path(path, frt) {
        return false;
    }

    let skew = chrono::Duration::minutes(frt.clock_skew_minutes.max(0));
    // mtime far in the future vs access → bad data or skew; ignore.
    if mtime > access + skew {
        return false;
    }

    let delta = access.signed_duration_since(mtime);
    let delta = if delta < chrono::Duration::zero() {
        chrono::Duration::zero()
    } else {
        delta
    };

    let max_critical = chrono::Duration::hours(frt.max_hours_critical_paths as i64);
    let max_system = chrono::Duration::hours(frt.max_hours_system_elevated as i64);
    let max_suspicious = chrono::Duration::hours(frt.max_hours_suspicious_only as i64);

    let elevated_or_risky = uid == 0
        || path_suspicious
        || is_world_writable
        || (is_group_writable && (path.contains("/etc") || path.contains("/tmp")));

    if is_critical_credential_path(path) {
        return delta <= max_critical;
    }

    if is_system_path_for_recent_mtime(path) && elevated_or_risky {
        return delta <= max_system;
    }

    if path_suspicious {
        return delta <= max_suspicious;
    }

    false
}

/// Paths where owner/group/size are expected to be uniform across a homogeneous fleet.
fn path_supports_fleet_metadata_baseline(path: &str) -> bool {
    path.starts_with("/etc/")
        || path.contains("/bin/")
        || path.contains("/sbin/")
        || path.starts_with("/usr/bin/")
        || path.starts_with("/usr/sbin/")
        || path.starts_with("/var/log/")
}

/// Per-path fleet comparison: same path on ≥3 hosts, a string value (owner/group) must match a
/// majority that appears at least twice; hosts with a different value are flagged.
fn fleet_string_metadata_outliers(
    profiles: &[MachineFileProfile],
    field: impl Fn(&MachineFileProfile) -> &HashMap<Arc<str>, Arc<str>>,
    field_label: &str,
) -> HashMap<usize, Vec<String>> {
    let mut path_hosts: HashMap<Arc<str>, Vec<(usize, Arc<str>)>> = HashMap::new();
    for (i, p) in profiles.iter().enumerate() {
        for (path, val) in field(p) {
            if !path_supports_fleet_metadata_baseline(path.as_ref()) {
                continue;
            }
            path_hosts
                .entry(path.clone())
                .or_default()
                .push((i, val.clone()));
        }
    }
    let mut out: HashMap<usize, Vec<String>> = HashMap::new();
    for (path, rows) in path_hosts {
        if rows.len() < 3 {
            continue;
        }
        let mut freq: HashMap<Arc<str>, usize> = HashMap::new();
        for (_, ref v) in &rows {
            *freq.entry(v.clone()).or_insert(0) += 1;
        }
        let (mode, mode_count) = freq.into_iter().max_by_key(|(_, c)| *c).unwrap();
        if mode_count < 2 {
            continue;
        }
        for (machine_idx, v) in rows {
            if v != mode {
                out.entry(machine_idx).or_default().push(format!(
                    "METADATA ANOMALY: {} on {} is '{}' (fleet majority: '{}')",
                    field_label,
                    path.as_ref(),
                    v.as_ref(),
                    mode.as_ref()
                ));
            }
        }
    }
    out
}

/// Same path on ≥3 hosts with recorded size; majority size must appear at least twice.
fn fleet_size_metadata_outliers(profiles: &[MachineFileProfile]) -> HashMap<usize, Vec<String>> {
    let mut path_hosts: HashMap<Arc<str>, Vec<(usize, u64)>> = HashMap::new();
    for (i, p) in profiles.iter().enumerate() {
        for (path, sz) in &p.file_path_size {
            if !path_supports_fleet_metadata_baseline(path.as_ref()) {
                continue;
            }
            path_hosts
                .entry(path.clone())
                .or_default()
                .push((i, *sz));
        }
    }
    let mut out: HashMap<usize, Vec<String>> = HashMap::new();
    for (path, rows) in path_hosts {
        if rows.len() < 3 {
            continue;
        }
        let mut freq: HashMap<u64, usize> = HashMap::new();
        for (_, sz) in &rows {
            *freq.entry(*sz).or_insert(0) += 1;
        }
        let (mode_size, mode_count) = freq.into_iter().max_by_key(|(_, c)| *c).unwrap();
        if mode_count < 2 {
            continue;
        }
        for (machine_idx, sz) in rows {
            if sz != mode_size {
                out.entry(machine_idx).or_default().push(format!(
                    "METADATA ANOMALY: size on {} is {} bytes (fleet majority: {} bytes)",
                    path.as_ref(),
                    sz,
                    mode_size
                ));
            }
        }
    }
    out
}

/// Paths that appear on each machine index (deduplicated per host).
fn path_to_machine_indices(profiles: &[MachineFileProfile]) -> HashMap<Arc<str>, Vec<usize>> {
    let mut m: HashMap<Arc<str>, HashSet<usize>> = HashMap::new();
    for (i, p) in profiles.iter().enumerate() {
        for sig in p.counts.keys() {
            m.entry(sig.path.clone()).or_default().insert(i);
        }
    }
    m.into_iter()
        .map(|(path, set)| {
            let mut v: Vec<usize> = set.into_iter().collect();
            v.sort_unstable();
            (path, v)
        })
        .collect()
}

/// Minimum hosts that must see a path before fleet comparison applies (same spirit as metadata baselines).
const FLEET_PATH_MIN_HOSTS: usize = 3;
/// Majority class must appear at least this many times.
const FLEET_PATH_MIN_MAJORITY: usize = 2;

/// Per-profile, per-path boolean indexes built once before fleet comparisons.
///
/// Replaces the previous `path_class_*(profile, path)` linear scans of `profile.counts.keys()` —
/// each lookup becomes a single hashmap probe. With ~40k unique signatures per machine and tens
/// of thousands of distinct paths in `path_machines`, the old approach was O(paths × machines ×
/// signatures); now it's O(paths × machines + total_signatures).
struct ProfilePathIndex {
    /// `path -> any signature with this path is uid==0`. `/proc` and `/sys` keys are omitted so
    /// callers see them as "not seen" (matches the legacy `path_class_root_uid` semantics).
    has_root_uid: HashMap<Arc<str>, bool>,
    is_world_writable: HashMap<Arc<str>, bool>,
    is_group_writable: HashMap<Arc<str>, bool>,
    recently_modified: HashMap<Arc<str>, bool>,
}

fn build_profile_path_index(profile: &MachineFileProfile) -> ProfilePathIndex {
    let cap = profile.counts.len();
    let mut has_root_uid: HashMap<Arc<str>, bool> = HashMap::with_capacity(cap);
    let mut is_world_writable: HashMap<Arc<str>, bool> = HashMap::with_capacity(cap);
    let mut is_group_writable: HashMap<Arc<str>, bool> = HashMap::with_capacity(cap);
    let mut recently_modified: HashMap<Arc<str>, bool> = HashMap::with_capacity(cap);
    for sig in profile.counts.keys() {
        let path = &sig.path;
        let p = path.as_ref();
        if !(p.starts_with("/proc") || p.starts_with("/sys")) {
            let e = has_root_uid.entry(path.clone()).or_insert(false);
            if sig.uid == 0 {
                *e = true;
            }
        }
        let e = is_world_writable.entry(path.clone()).or_insert(false);
        if sig.is_world_writable {
            *e = true;
        }
        let e = is_group_writable.entry(path.clone()).or_insert(false);
        if sig.is_group_writable {
            *e = true;
        }
        let e = recently_modified.entry(path.clone()).or_insert(false);
        if sig.recently_modified {
            *e = true;
        }
    }
    ProfilePathIndex {
        has_root_uid,
        is_world_writable,
        is_group_writable,
        recently_modified,
    }
}

/// For paths seen on enough hosts, compare a boolean attribute per host (e.g. root vs non-root).
/// Unanimous paths are ignored; ties are ignored. Only the **minority** hosts get detail strings.
///
/// Reads from precomputed [`ProfilePathIndex::*`] maps (`O(1)` per lookup) instead of scanning
/// `profile.counts.keys()` — this is what makes the file fleet pass tractable on hosts with
/// 40k+ files. The slice holds *references* to per-profile attribute maps to avoid cloning
/// 4 copies × ~40k entries × 20 hosts on every fleet pass.
fn fleet_path_binary_outliers_indexed(
    profiles_count: usize,
    path_machines: &HashMap<Arc<str>, Vec<usize>>,
    path_indexes: &[&HashMap<Arc<str>, bool>],
    path_gate: impl Fn(&str) -> bool,
    minority_true_detail: impl Fn(&str, usize, usize, usize) -> String,
    minority_false_detail: impl Fn(&str, usize, usize, usize) -> String,
) -> HashMap<usize, Vec<String>> {
    debug_assert_eq!(path_indexes.len(), profiles_count);
    let mut out: HashMap<usize, Vec<String>> = HashMap::new();
    for (path, machine_idxs) in path_machines {
        if machine_idxs.len() < FLEET_PATH_MIN_HOSTS || !path_gate(path.as_ref()) {
            continue;
        }
        let mut true_machines: Vec<usize> = Vec::new();
        let mut false_machines: Vec<usize> = Vec::new();
        for &mi in machine_idxs {
            match path_indexes[mi].get(path).copied() {
                Some(true) => true_machines.push(mi),
                Some(false) => false_machines.push(mi),
                None => {}
            }
        }
        let n_true = true_machines.len();
        let n_false = false_machines.len();
        if n_true == 0 || n_false == 0 {
            continue;
        }
        let n_classified = n_true + n_false;
        if n_classified < FLEET_PATH_MIN_HOSTS {
            continue;
        }
        let path_s = path.as_ref();
        if n_true > n_false && n_true >= FLEET_PATH_MIN_MAJORITY {
            let msg = minority_false_detail(path_s, n_true, n_false, n_classified);
            for mi in false_machines {
                out.entry(mi).or_default().push(msg.clone());
            }
        } else if n_false > n_true && n_false >= FLEET_PATH_MIN_MAJORITY {
            let msg = minority_true_detail(path_s, n_false, n_true, n_classified);
            for mi in true_machines {
                out.entry(mi).or_default().push(msg.clone());
            }
        }
    }
    out
}

fn merge_fleet_details(
    into: &mut HashMap<usize, Vec<String>>,
    from: HashMap<usize, Vec<String>>,
) {
    for (k, mut v) in from {
        into.entry(k).or_default().append(&mut v);
    }
}

/// Per-collapsed-bucket OR-merged risk flags taken from the **original** [`FileSignature`]s seen
/// on a host (before fleet equivalence stripped metadata fields).
///
/// The fleet rare-bucket key intentionally drops `permissions`, `owner`, `recently_modified`, etc.
/// to keep noisy log-line variations from splitting one logical file into multiple rare entries.
/// The interestingness gate and the qualifier still want those flags, so we precompute them once
/// while collapsing the host's profile.
#[derive(Default, Clone, Copy)]
struct FileBucketRisk {
    is_suspicious_path: bool,
    is_world_writable: bool,
    is_group_writable: bool,
    recently_modified: bool,
    has_root_uid: bool,
}

impl FileBucketRisk {
    fn merge(&mut self, sig: &FileSignature) {
        self.is_suspicious_path |= sig.is_suspicious_path;
        self.is_world_writable |= sig.is_world_writable;
        self.is_group_writable |= sig.is_group_writable;
        self.recently_modified |= sig.recently_modified;
        if sig.uid == 0 {
            self.has_root_uid = true;
        }
    }
}

/// Whether a fleet-unique bucket looks suspicious enough to surface as a "Rare file access"
/// reason on its own, **without** a fleet-relative comparison.
///
/// A typical endpoint inventory of 40k+ files contains a long tail of one-of-a-kind user data,
/// caches, and per-host generated files — those should never become detection findings.
/// The gate keeps signatures that match at least one of:
/// - matches `suspicious_path_patterns` (configured) or sits in well-known abuse paths;
/// - world or group writable;
/// - read with `mtime` close to access (already heuristic-gated by recent-mtime config);
/// - root UID outside the volatile `/proc /sys /dev` namespaces;
/// - lives under a system-administered directory (`/etc /bin /sbin /usr/bin /usr/sbin
///   /usr/local/{bin,sbin} /root /boot /var/spool/cron`) — fleet-unique system files are
///   inherently noteworthy.
fn is_rare_file_interesting(path: &str, risk: &FileBucketRisk) -> bool {
    if risk.is_suspicious_path {
        return true;
    }
    if risk.is_world_writable || risk.is_group_writable {
        return true;
    }
    if risk.recently_modified {
        return true;
    }
    if risk.has_root_uid
        && !path.starts_with("/proc")
        && !path.starts_with("/sys")
        && !path.starts_with("/dev")
    {
        return true;
    }
    if path.starts_with("/etc/")
        || path.starts_with("/bin/")
        || path.starts_with("/sbin/")
        || path.starts_with("/usr/bin/")
        || path.starts_with("/usr/sbin/")
        || path.starts_with("/usr/local/bin/")
        || path.starts_with("/usr/local/sbin/")
        || path.starts_with("/root/")
        || path.starts_with("/boot/")
        || path.starts_with("/var/spool/cron/")
    {
        return true;
    }
    false
}

/// Higher = more important; used to order the per-host rare-file examples before the cap.
fn rare_file_priority(path: &str, risk: &FileBucketRisk) -> u32 {
    let mut s: u32 = 0;
    if risk.is_suspicious_path {
        s += 5;
    }
    if risk.is_world_writable {
        s += 4;
    } else if risk.is_group_writable {
        s += 2;
    }
    if risk.recently_modified {
        s += 3;
    }
    if risk.has_root_uid
        && !path.starts_with("/proc")
        && !path.starts_with("/sys")
        && !path.starts_with("/dev")
    {
        s += 2;
    }
    if path.starts_with("/etc/")
        || path.starts_with("/bin/")
        || path.starts_with("/sbin/")
        || path.starts_with("/usr/bin/")
        || path.starts_with("/usr/sbin/")
        || path.starts_with("/root/")
        || path.starts_with("/boot/")
        || path.starts_with("/var/spool/cron/")
    {
        s += 1;
    }
    s
}

/// Short bracketed qualifier appended to "Rare file access" reasons so the analyst sees *why* the
/// signature was kept (root, world-writable, suspicious path, …) without needing the raw row.
fn rare_file_qualifier(risk: &FileBucketRisk) -> String {
    let mut tags: Vec<&'static str> = Vec::new();
    if risk.is_suspicious_path {
        tags.push("suspicious_path");
    }
    if risk.is_world_writable {
        tags.push("world_writable");
    } else if risk.is_group_writable {
        tags.push("group_writable");
    }
    if risk.recently_modified {
        tags.push("recent_mtime");
    }
    if risk.has_root_uid {
        tags.push("uid=0");
    }
    if tags.is_empty() {
        String::new()
    } else {
        format!(" [{}]", tags.join(","))
    }
}

/// Whether a raw file row should be ingested into file profiles. Applies glob whitelist (pass
/// [`crate::utils::compile_wildcard_list`] on `DetectionConfig::whitelisted_path_patterns`) and
/// regex exclusions from [`crate::utils::compile_regex_list`].
///
/// Rows for which this returns `false` must not appear in `MachineFileProfile` aggregates;
/// [`merge_file_log_into_profile`] enforces the same rules so callers cannot accidentally merge
/// excluded paths.
pub fn should_ingest_file_entry(
    entry: &RawFileEntry,
    path_exclude_res: &[Regex],
    filename_exclude_res: &[Regex],
    whitelist_res: &[Regex],
) -> bool {
    if !whitelist_res.is_empty() && is_path_whitelisted_compiled(&entry.path, whitelist_res) {
        return false;
    }
    if file_path_matches_exclusion(&entry.path, path_exclude_res, filename_exclude_res) {
        return false;
    }
    true
}

/// Append one file access log to a profile (batch and streaming loaders).
///
/// No-ops when the row is excluded by `file_excluded_*` regexes or the path whitelist (see
/// [`should_ingest_file_entry`]); the profile is not updated.
pub(crate) fn merge_file_log_into_profile(
    profile: &mut MachineFileProfile,
    entry: &RawFileEntry,
    config: &DetectionConfig,
    interner: &SharedInterner,
    file_counts: Option<&mut HashMap<String, u32>>,
    path_exclude_res: &[Regex],
    filename_exclude_res: &[Regex],
    suspicious_path_res: &[Regex],
    whitelist_res: &[Regex],
) {
    if !should_ingest_file_entry(entry, path_exclude_res, filename_exclude_res, whitelist_res) {
        return;
    }

    let path_is_suspicious = is_path_suspicious_compiled(&entry.path, suspicious_path_res);
    let timestamp = entry.timestamp.as_ref().and_then(|s| parse_log_datetime(s));
    let mtime = entry.mtime.as_ref().and_then(|s| parse_log_datetime(s));
    let uid = effective_file_uid(entry);
    let (is_world_writable, is_group_writable) = entry
        .permissions
        .as_deref()
        .map(unix_permission_flags)
        .unwrap_or((false, false));
    let recently_modified = match (timestamp, mtime) {
        (Some(ts), Some(mt)) => recently_modified_heuristic(
            &config.file_recent_mtime,
            &entry.path,
            ts,
            mt,
            uid,
            path_is_suspicious,
            is_world_writable,
            is_group_writable,
        ),
        _ => false,
    };
    let permissions = entry.permissions.as_deref().and_then(|p| {
        let t = p.trim();
        if t.is_empty() {
            None
        } else {
            Some(interner.intern(t))
        }
    });
    let owner = entry.owner.as_deref().and_then(|o| {
        let t = o.trim();
        if t.is_empty() {
            None
        } else {
            Some(interner.intern(t))
        }
    });
    let group = entry.group.as_deref().and_then(|g| {
        let t = g.trim();
        if t.is_empty() {
            None
        } else {
            Some(interner.intern(t))
        }
    });
    let sig = FileSignature {
        path: interner.intern(&entry.path),
        uid,
        is_suspicious_path: path_is_suspicious,
        has_mtime_anomaly: false,
        recently_modified,
        permissions,
        owner,
        group,
        size: entry.size,
        is_world_writable,
        is_group_writable,
    };
    if let Some(fc) = file_counts {
        let file_key = format!(
            "{}:{}:{:?}:{:?}:{:?}",
            sig.path, sig.uid, sig.permissions, sig.owner, sig.size
        );
        let is_new_file = !fc.contains_key(&file_key);
        fc.entry(file_key).and_modify(|c| *c += 1).or_insert(1);
        if config.debug_display && is_new_file {
            let risk_flags: Vec<&str> = [
                if path_is_suspicious {
                    Some("SUSPICIOUS_PATH")
                } else {
                    None
                },
                if entry.path.contains("/etc")
                    || entry.path.contains("/bin")
                    || entry.path.contains("/sbin")
                {
                    Some("SYSTEM_DIRECTORY")
                } else {
                    None
                },
                if uid == 0 {
                    Some("ROOT_ACCESS")
                } else {
                    None
                },
                if recently_modified {
                    Some("RECENTLY_MODIFIED")
                } else {
                    None
                },
            ]
            .into_iter()
            .flatten()
            .collect();
            let risk_str = if risk_flags.is_empty() {
                String::new()
            } else {
                format!(" [{}]", risk_flags.join(", "))
            };
            log::debug!(
                "New file access in {}: {} (uid: {}){}",
                profile.id,
                entry.path,
                uid,
                risk_str
            );
        }
    }
    profile.add_file(sig, timestamp, mtime);
}

fn effective_file_uid(entry: &RawFileEntry) -> u32 {
    if entry.uid != 0 {
        return entry.uid;
    }
    if let Some(ref o) = entry.owner {
        let o = o.trim();
        if o.eq_ignore_ascii_case("root") {
            return 0;
        }
        if let Ok(u) = o.parse::<u32>() {
            return u;
        }
    }
    entry.uid
}

pub fn build_file_profiles(
    entries: Vec<RawFileEntry>,
    config: &DetectionConfig,
) -> Vec<MachineFileProfile> {
    log::info!("Building file profiles from {} raw file entries", entries.len());

    let mut machine_entries: HashMap<String, Vec<RawFileEntry>> = HashMap::new();
    for entry in entries {
        machine_entries
            .entry(entry.machine_id.clone())
            .or_insert_with(Vec::new)
            .push(entry);
    }
    build_file_profiles_from_grouped(machine_entries, config)
}

/// Like [`build_file_profiles`] but takes file rows already grouped by `machine_id`.
///
/// On large fleets (e.g. 20 hosts × 40k file events) the SQLite-loaded run path streams rows
/// straight into `HashMap<machine, Vec<RawFileEntry>>` so we never hold a 200+ MB
/// `Vec<RawFileEntry>` *and* the same data duplicated as per-machine vectors at the same time;
/// this entry point lets that path skip the regroup step that [`build_file_profiles`] would do.
pub fn build_file_profiles_from_grouped(
    machine_entries: HashMap<String, Vec<RawFileEntry>>,
    config: &DetectionConfig,
) -> Vec<MachineFileProfile> {
    let whitelist_res = compile_wildcard_list(&config.whitelisted_path_patterns);
    let path_exclude_res = compile_regex_list(&config.file_excluded_path_regexes);
    let filename_exclude_res = compile_regex_list(&config.file_excluded_filename_regexes);
    let suspicious_path_res = compile_regex_list(&config.suspicious_path_patterns);

    if config.debug_display {
        let total_rows: usize = machine_entries.values().map(|v| v.len()).sum();
        let dropped: usize = machine_entries
            .values()
            .flat_map(|v| v.iter())
            .filter(|e| {
                !should_ingest_file_entry(e, &path_exclude_res, &filename_exclude_res, &whitelist_res)
            })
            .count();
        if dropped > 0 {
            log::debug!(
                "File ingest filter (whitelist + file_excluded_* regexes): raw_rows={}, excluded_rows={} (not merged into profiles)",
                total_rows,
                dropped
            );
        }
        log::debug!("Grouped into {} machines", machine_entries.len());
    }

    let mut profiles: Vec<MachineFileProfile> = machine_entries
        .par_iter()
        .map(|(machine_id, logs)| {
            let mut profile = MachineFileProfile::new(machine_id);
            let mut file_counts: HashMap<String, u32> = HashMap::new();
            // Per-machine interner: avoids a global mutex on every path/metadata intern when many
            // workers merge rows in parallel; dedup is only needed within one host's profile.
            let interner_par = SharedInterner::default();
            for entry in logs {
                let fc = if config.debug_display {
                    Some(&mut file_counts)
                } else {
                    None
                };
                merge_file_log_into_profile(
                    &mut profile,
                    entry,
                    config,
                    &interner_par,
                    fc,
                    &path_exclude_res,
                    &filename_exclude_res,
                    &suspicious_path_res,
                    &whitelist_res,
                );
            }
            profile
        })
        .collect();

    profiles.retain(|p| p.total_logs > 0);
    log::info!("Built {} machine file profiles", profiles.len());
    profiles
}

/// Normalize [`FileSignature`] for fleet **rare-file** doc frequency and **TF-IDF / DBSCAN** feature
/// columns (`DetectionConfig::file_rare_signature_includes_*`).
fn file_signature_fleet_equivalence(sig: &FileSignature, config: &DetectionConfig) -> FileSignature {
    let mut s = sig.clone();
    if !config.file_rare_signature_includes_recent_mtime {
        s.recently_modified = false;
    }
    if !config.file_rare_signature_includes_metadata {
        s.permissions = None;
        s.owner = None;
        s.group = None;
        s.is_world_writable = false;
        s.is_group_writable = false;
    }
    if !config.file_rare_signature_includes_size {
        s.size = None;
    }
    s
}

fn collapse_profile_counts_for_fleet(
    profile: &MachineFileProfile,
    config: &DetectionConfig,
) -> (
    HashMap<FileSignature, u32>,
    HashMap<FileSignature, FileBucketRisk>,
) {
    let mut counts: HashMap<FileSignature, u32> = HashMap::new();
    let mut risks: HashMap<FileSignature, FileBucketRisk> = HashMap::new();
    for (sig, &c) in &profile.counts {
        let key = file_signature_fleet_equivalence(sig, config);
        *counts.entry(key.clone()).or_insert(0) += c;
        risks.entry(key).or_default().merge(sig);
    }
    (counts, risks)
}

/// Stable fingerprint for “same inventory row” across hosts: path, uid, metadata fields from the
/// bucket key, optional **bucketed** mtime from the host profile. Does not include anomaly flags
/// (`has_mtime_anomaly`, …) so fleet-wide paths that split across equivalent keys still baseline.
fn file_inventory_fingerprint(
    sig: &FileSignature,
    mtime: Option<DateTime<Utc>>,
    mtime_bucket_secs: u64,
) -> u64 {
    let mut h = DefaultHasher::new();
    sig.path.as_ref().hash(&mut h);
    sig.uid.hash(&mut h);
    sig.permissions.as_deref().unwrap_or("").hash(&mut h);
    sig.owner.as_deref().unwrap_or("").hash(&mut h);
    sig.group.as_deref().unwrap_or("").hash(&mut h);
    sig.size.hash(&mut h);
    sig.is_world_writable.hash(&mut h);
    sig.is_group_writable.hash(&mut h);
    if mtime_bucket_secs > 0 {
        let bucket = mtime
            .map(|t| t.timestamp().div_euclid(mtime_bucket_secs as i64))
            .unwrap_or(i64::MIN / 4);
        bucket.hash(&mut h);
    }
    h.finish()
}

/// Fingerprints that appear on at least `ceil(min_host_fraction * n_hosts)` hosts (each host
/// counts at most once per fingerprint). Suspicious-path rows are omitted from baseline membership
/// when [`DetectionConfig::file_fleet_baseline_exclude_suspicious_paths`] is true.
fn fleet_baseline_fingerprint_set(
    profiles: &[MachineFileProfile],
    collapsed_counts: &[HashMap<FileSignature, u32>],
    config: &DetectionConfig,
) -> HashSet<u64> {
    let n_hosts = profiles.len();
    if !config.file_fleet_baseline_fingerprint_enabled || n_hosts < 2 {
        return HashSet::new();
    }
    let min_hosts = (config.file_fleet_baseline_min_host_fraction * n_hosts as f64)
        .ceil() as usize;
    let min_hosts = min_hosts.clamp(1, n_hosts);
    let bucket_secs = config.file_fleet_baseline_mtime_bucket_secs;

    let mut fp_host_occurrences: HashMap<u64, usize> = HashMap::new();
    for (host_idx, host_map) in collapsed_counts.iter().enumerate() {
        let profile = &profiles[host_idx];
        let mut seen_fp_this_host: HashSet<u64> = HashSet::new();
        for sig in host_map.keys() {
            if config.file_fleet_baseline_exclude_suspicious_paths && sig.is_suspicious_path {
                continue;
            }
            let mtime = profile.file_mtimes.get(&sig.path).copied();
            let fp = file_inventory_fingerprint(sig, mtime, bucket_secs);
            if seen_fp_this_host.insert(fp) {
                *fp_host_occurrences.entry(fp).or_insert(0) += 1;
            }
        }
    }

    fp_host_occurrences
        .into_iter()
        .filter(|&(_, count)| count >= min_hosts)
        .map(|(fp, _)| fp)
        .collect()
}

#[inline]
fn skip_rare_doc_for_fleet_baseline(
    sig: &FileSignature,
    profile: &MachineFileProfile,
    baseline_fps: &HashSet<u64>,
    config: &DetectionConfig,
) -> bool {
    if baseline_fps.is_empty() {
        return false;
    }
    if config.file_fleet_baseline_exclude_suspicious_paths && sig.is_suspicious_path {
        return false;
    }
    let mtime = profile.file_mtimes.get(&sig.path).copied();
    let fp = file_inventory_fingerprint(sig, mtime, config.file_fleet_baseline_mtime_bucket_secs);
    baseline_fps.contains(&fp)
}

pub fn analyze_files_fleet(
    profiles: &[MachineFileProfile],
    config: &DetectionConfig,
) -> Result<AnalysisReport, Box<dyn Error>> {
    if profiles.is_empty() {
        return Ok(AnalysisReport {
            anomalies: vec![],
            cluster_stats: HashMap::new(),
            total_analyzed: 0,
            config_used: config.clone(),
            analysis_type: AnalysisType::File,
        });
    }

    let mut file_mtimes_fleet: HashMap<Arc<str>, Vec<(usize, DateTime<Utc>)>> = HashMap::new();
    for (i, profile) in profiles.iter().enumerate() {
        for (path, mtime) in &profile.file_mtimes {
            file_mtimes_fleet
                .entry(path.clone())
                .or_insert_with(Vec::new)
                .push((i, *mtime));
        }
    }

    let mut mtime_anomaly_machines: HashSet<usize> = HashSet::new();
    let mut mtime_anomaly_details: HashMap<usize, Vec<String>> = HashMap::new();
    for (path, machine_mtimes) in &file_mtimes_fleet {
        if machine_mtimes.len() < 3 {
            continue;
        }
        let mut sorted_mtimes: Vec<DateTime<Utc>> =
            machine_mtimes.iter().map(|(_, mt)| *mt).collect();
        sorted_mtimes.sort();
        let median_mtime = sorted_mtimes[sorted_mtimes.len() / 2];
        for (machine_idx, mtime) in machine_mtimes {
            let diff = mtime.signed_duration_since(median_mtime);
            let diff_hours = diff.num_hours().abs();
            if diff_hours > 24 {
                mtime_anomaly_machines.insert(*machine_idx);
                let detail = if diff.num_hours() > 0 {
                    format!(
                        "MTIME ANOMALY: {} modified {}h NEWER than fleet baseline",
                        path.as_ref(),
                        diff_hours
                    )
                } else {
                    format!(
                        "MTIME ANOMALY: {} modified {}h OLDER than fleet baseline",
                        path.as_ref(),
                        diff_hours
                    )
                };
                mtime_anomaly_details
                    .entry(*machine_idx)
                    .or_insert_with(Vec::new)
                    .push(detail);
            }
        }
    }

    let mut metadata_anomaly_details: HashMap<usize, Vec<String>> = HashMap::new();
    for (k, v) in fleet_string_metadata_outliers(profiles, |p| &p.file_path_owner, "owner") {
        metadata_anomaly_details.entry(k).or_default().extend(v);
    }
    for (k, v) in fleet_string_metadata_outliers(profiles, |p| &p.file_path_group, "group") {
        metadata_anomaly_details.entry(k).or_default().extend(v);
    }
    for (k, v) in fleet_size_metadata_outliers(profiles) {
        metadata_anomaly_details.entry(k).or_default().extend(v);
    }
    let metadata_anomaly_machines: HashSet<usize> = metadata_anomaly_details.keys().copied().collect();

    // Fleet-relative access patterns: flag a host only when it differs from a clear majority on the
    // same path (≥3 hosts, majority ≥2). Avoids blanket "root access" / system-dir noise.
    let path_machines = path_to_machine_indices(profiles);

    // Build per-profile path indexes once. With 40k+ files per host this turns the four
    // fleet-binary-outlier passes from O(P × M × S) into O(P × M + total_signatures).
    let path_indexes: Vec<ProfilePathIndex> =
        profiles.par_iter().map(build_profile_path_index).collect();
    // Borrow each attribute map by reference per profile — cloning four full hashmaps × N hosts
    // here cost ~80 MB of redundant allocations on a 20-host fleet (each map has tens of
    // thousands of entries). The fleet passes only read these maps, so references are enough.
    let root_idx: Vec<&HashMap<Arc<str>, bool>> =
        path_indexes.iter().map(|i| &i.has_root_uid).collect();
    let ww_idx: Vec<&HashMap<Arc<str>, bool>> =
        path_indexes.iter().map(|i| &i.is_world_writable).collect();
    let gw_idx: Vec<&HashMap<Arc<str>, bool>> =
        path_indexes.iter().map(|i| &i.is_group_writable).collect();
    let recent_idx: Vec<&HashMap<Arc<str>, bool>> =
        path_indexes.iter().map(|i| &i.recently_modified).collect();
    let n_profiles = profiles.len();

    let mut fleet_access_details: HashMap<usize, Vec<String>> = HashMap::new();

    merge_fleet_details(
        &mut fleet_access_details,
        fleet_path_binary_outliers_indexed(
            n_profiles,
            &path_machines,
            &root_idx,
            |_| true,
            |path, n_maj_nonroot, _n_min_root, n_tot| {
                format!(
                    "FLEET OUTLIER: root UID access to {} — {} of {} hosts use non-root for this path (this host is in the minority)",
                    path, n_maj_nonroot, n_tot
                )
            },
            |path, n_maj_root, _n_min_nonroot, n_tot| {
                format!(
                    "FLEET OUTLIER: non-root access to {} — {} of {} hosts use root for this path (this host is in the minority)",
                    path, n_maj_root, n_tot
                )
            },
        ),
    );

    merge_fleet_details(
        &mut fleet_access_details,
        fleet_path_binary_outliers_indexed(
            n_profiles,
            &path_machines,
            &ww_idx,
            |_| true,
            |path, n_maj_not_ww, _n_min_ww, n_tot| {
                format!(
                    "FLEET OUTLIER: world-writable {} — {} of {} hosts are not world-writable (minority)",
                    path, n_maj_not_ww, n_tot
                )
            },
            |path, n_maj_ww, _n_min_not, n_tot| {
                format!(
                    "FLEET OUTLIER: non-world-writable {} — {} of {} hosts see world-writable mode (minority)",
                    path, n_maj_ww, n_tot
                )
            },
        ),
    );

    merge_fleet_details(
        &mut fleet_access_details,
        fleet_path_binary_outliers_indexed(
            n_profiles,
            &path_machines,
            &gw_idx,
            |p| p.contains("/etc") || p.contains("/tmp"),
            |path, n_maj_not_gw, _n_min_gw, n_tot| {
                format!(
                    "FLEET OUTLIER: group-writable {} under /etc or /tmp — {} of {} hosts are not group-writable (minority)",
                    path, n_maj_not_gw, n_tot
                )
            },
            |path, n_maj_gw, _n_min_not, n_tot| {
                format!(
                    "FLEET OUTLIER: not group-writable {} — {} of {} hosts see group-writable on this path (minority)",
                    path, n_maj_gw, n_tot
                )
            },
        ),
    );

    let fleet_recent_mtime_details = fleet_path_binary_outliers_indexed(
        n_profiles,
        &path_machines,
        &recent_idx,
        |_| true,
        |path, n_maj_not_recent, _n_min_recent, n_tot| {
            format!(
                "FLEET OUTLIER: mtime close to access on {} — {} of {} hosts do not show this pattern (minority)",
                path, n_maj_not_recent, n_tot
            )
        },
        |path, n_maj_recent, _n_min_not, n_tot| {
            format!(
                "FLEET OUTLIER: no recent mtime-at-access signal on {} — {} of {} hosts do (minority)",
                path, n_maj_recent, n_tot
            )
        },
    );
    let recent_fleet_machine_idxs: HashSet<usize> =
        fleet_recent_mtime_details.keys().copied().collect();
    merge_fleet_details(&mut fleet_access_details, fleet_recent_mtime_details);
    drop(path_indexes);

    let fleet_access_machines: HashSet<usize> = fleet_access_details.keys().copied().collect();

    // Split into two parallel Vecs without cloning either side. The previous code did
    // `collapsed.iter().map(|(c, _)| c.clone())` which deep-cloned hundreds of thousands of
    // `FileSignature` keys on a 20 × 40k file fleet — `unzip` moves both maps in place.
    let (collapsed_counts, collapsed_risks): (
        Vec<HashMap<FileSignature, u32>>,
        Vec<HashMap<FileSignature, FileBucketRisk>>,
    ) = profiles
        .par_iter()
        .map(|p| collapse_profile_counts_for_fleet(p, config))
        .collect::<Vec<_>>()
        .into_iter()
        .unzip();

    let fleet_baseline_fps =
        fleet_baseline_fingerprint_set(profiles, &collapsed_counts, config);

    // Doc frequency for every fleet bucket. Single pass, used for both rare-file detection and
    // TF-IDF / DBSCAN column selection (so the two stay consistent).
    let mut rare_doc_count: HashMap<FileSignature, usize> = HashMap::new();
    for (host_idx, m) in collapsed_counts.iter().enumerate() {
        let profile = &profiles[host_idx];
        for k in m.keys() {
            if skip_rare_doc_for_fleet_baseline(k, profile, &fleet_baseline_fps, config) {
                continue;
            }
            *rare_doc_count.entry(k.clone()).or_insert(0) += 1;
        }
    }

    let n_samples = profiles.len();

    // TF-IDF column selection
    //
    // - Drop universal features (`doc_freq == n_samples`): zero IDF, no clustering signal.
    // - Drop fleet-unique features (`doc_freq == 1`): they only push a single host away on a
    //   single dimension and rare-file detection already surfaces them with full context.
    // - When more middle-frequency columns remain than `file_max_unique_features`, keep the rarest
    //   first (lower `doc_freq` = higher IDF = more discriminative for outlier detection).
    let mut middle_feats: Vec<(FileSignature, usize)> = rare_doc_count
        .iter()
        .filter(|(_, &df)| df > 1 && df < n_samples)
        .map(|(k, &df)| (k.clone(), df))
        .collect();
    middle_feats.sort_by(|a, b| {
        a.1.cmp(&b.1)
            .then(a.0.path.cmp(&b.0.path))
            .then(a.0.uid.cmp(&b.0.uid))
            .then(a.0.is_suspicious_path.cmp(&b.0.is_suspicious_path))
            .then(a.0.has_mtime_anomaly.cmp(&b.0.has_mtime_anomaly))
            .then(a.0.recently_modified.cmp(&b.0.recently_modified))
            .then((&a.0.permissions, &a.0.owner, &a.0.group, &a.0.size).cmp(&(
                &b.0.permissions,
                &b.0.owner,
                &b.0.group,
                &b.0.size,
            )))
            .then(a.0.is_world_writable.cmp(&b.0.is_world_writable))
            .then(a.0.is_group_writable.cmp(&b.0.is_group_writable))
    });
    let max_features = config.file_max_unique_features.max(1);
    if middle_feats.len() > max_features {
        log::info!(
            "File fleet TF-IDF: capping feature columns to top {} (out of {} middle-frequency, total buckets {}); rarest features kept first",
            max_features,
            middle_feats.len(),
            rare_doc_count.len()
        );
        middle_feats.truncate(max_features);
    }
    let feature_list: Vec<FileSignature> = middle_feats.iter().map(|(k, _)| k.clone()).collect();
    let feature_doc_freq: Vec<usize> = middle_feats.iter().map(|(_, df)| *df).collect();
    let n_features = feature_list.len();

    let data = if n_features == 0 {
        Array2::<f64>::zeros((n_samples, 1))
    } else {
        let n_samples_f = n_samples as f64;
        let mut flat = vec![0.0f64; n_samples * n_features];
        flat.par_chunks_mut(n_features)
            .enumerate()
            .for_each(|(row_idx, row)| {
                let profile = &profiles[row_idx];
                let counts = &collapsed_counts[row_idx];
                if profile.total_logs == 0 {
                    return;
                }
                let tlog = profile.total_logs as f64;
                for (col_idx, feature) in feature_list.iter().enumerate() {
                    if let Some(&count) = counts.get(feature) {
                        let tf = count as f64 / tlog;
                        let doc_count = feature_doc_freq[col_idx].max(1) as f64;
                        let idf = (n_samples_f / doc_count).ln() + 1.0;
                        row[col_idx] = tf * idf;
                    }
                }
            });

        if config.normalize_features {
            flat.par_chunks_mut(n_features).for_each(|row| {
                let norm = row.iter().map(|x| x * x).sum::<f64>().sqrt();
                if norm > 0.0 {
                    for x in row.iter_mut() {
                        *x /= norm;
                    }
                }
            });
        }

        Array2::from_shape_vec((n_samples, n_features), flat).map_err(|e| -> Box<dyn Error> {
            format!("internal: file TF-IDF matrix shape: {}", e).into()
        })?
    };

    let clusters = Dbscan::params(config.dbscan_min_samples)
        .tolerance(config.dbscan_tolerance)
        .transform(&data)?;

    let mut cluster_counts: HashMap<Option<usize>, usize> = HashMap::new();
    for cluster_id in clusters.iter() {
        *cluster_counts.entry(*cluster_id).or_insert(0) += 1;
    }

    let largest_cluster = cluster_counts
        .iter()
        .filter(|(k, _)| k.is_some())
        .max_by_key(|(_, v)| *v)
        .map(|(k, _)| k.unwrap());

    let mut anomalies = Vec::new();
    for (i, cluster_id) in clusters.iter().enumerate() {
        let profile = &profiles[i];
        let mut suspicious_count = 0u32;
        let mut anomalous_features = Vec::new();
        let mut has_genuine_risk = false;

        if let Some(mtime_details) = mtime_anomaly_details.get(&i) {
            for detail in mtime_details {
                anomalous_features.push(detail.clone());
            }
            has_genuine_risk = true;
            suspicious_count += mtime_details.len() as u32;
        }
        if let Some(fleet_access) = fleet_access_details.get(&i) {
            for detail in fleet_access {
                anomalous_features.push(detail.clone());
            }
            has_genuine_risk = true;
            suspicious_count += fleet_access.len() as u32;
        }
        if let Some(meta_details) = metadata_anomaly_details.get(&i) {
            for detail in meta_details {
                anomalous_features.push(detail.clone());
            }
            has_genuine_risk = true;
            suspicious_count += meta_details.len() as u32;
        }

        // Per-bucket "rare across fleet" (doc frequency 1), same equivalence as TF-IDF columns.
        //
        // On endpoints with 40k+ files per host most signatures are fleet-unique (long-tail user
        // data, caches, generated files); we collect candidates first, gate by interestingness
        // (`is_rare_file_interesting`) when configured, then keep only the highest-priority
        // examples to avoid drowning the finding in noise. Risk markers come from the original
        // (un-collapsed) signatures so the gate keeps working when fleet equivalence strips
        // metadata fields (the default).
        let host_risks = &collapsed_risks[i];
        let empty_risk = FileBucketRisk::default();
        let mut rare_candidates: Vec<(u32, u32, &FileSignature, FileBucketRisk)> = Vec::new();
        let mut rare_unique_total: u32 = 0;
        for (bucket, &total_count) in &collapsed_counts[i] {
            if rare_doc_count.get(bucket).copied().unwrap_or(0) != 1 {
                continue;
            }
            rare_unique_total += 1;
            let risk = host_risks.get(bucket).copied().unwrap_or(empty_risk);
            if config.file_rare_requires_risk
                && !is_rare_file_interesting(bucket.path.as_ref(), &risk)
            {
                continue;
            }
            rare_candidates.push((rare_file_priority(bucket.path.as_ref(), &risk), total_count, bucket, risk));
        }
        rare_candidates.sort_by(|a, b| {
            b.0.cmp(&a.0)
                .then(b.1.cmp(&a.1))
                .then(a.2.path.cmp(&b.2.path))
                .then(a.2.uid.cmp(&b.2.uid))
        });
        let cap = config.file_max_rare_examples_per_host.max(1);
        let total_kept = rare_candidates.len();
        let truncated = total_kept.saturating_sub(cap);
        for (_, total_count, bucket, risk) in rare_candidates.iter().take(cap) {
            suspicious_count += total_count;
            has_genuine_risk = true;
            anomalous_features.push(format!(
                "Rare file access: {}{}",
                bucket.path,
                rare_file_qualifier(risk)
            ));
        }
        if truncated > 0 {
            anomalous_features.push(format!(
                "(+{} more rare files matched the same gate, not shown)",
                truncated
            ));
        }
        if config.file_rare_requires_risk
            && rare_unique_total > 0
            && total_kept == 0
            && config.debug_display
        {
            log::debug!(
                "File fleet: {} rare unique files on {} dropped by file_rare_requires_risk gate",
                rare_unique_total,
                profile.id
            );
        }

        let is_noise = cluster_id.is_none();
        let is_minority = cluster_id.is_some()
            && cluster_id.unwrap() != largest_cluster.unwrap_or(999);
        let has_mtime_anomaly = mtime_anomaly_machines.contains(&i);
        let has_recent_fleet = recent_fleet_machine_idxs.contains(&i);
        let has_metadata_fleet_anomaly = metadata_anomaly_machines.contains(&i);
        let has_fleet_access_outlier = fleet_access_machines.contains(&i);

        if is_noise
            || is_minority
            || has_genuine_risk
            || has_mtime_anomaly
            || has_fleet_access_outlier
            || has_metadata_fleet_anomaly
        {
            let severity = if has_mtime_anomaly || has_metadata_fleet_anomaly {
                AnomalyLevel::Critical
            } else if has_recent_fleet && has_genuine_risk {
                AnomalyLevel::Critical
            } else if has_genuine_risk {
                if suspicious_count > 5 {
                    AnomalyLevel::Critical
                } else {
                    AnomalyLevel::High
                }
            } else if has_recent_fleet {
                AnomalyLevel::High
            } else {
                // DBSCAN noise/minority only: no mtime, rare-file, metadata, or recent-fleet signals.
                AnomalyLevel::Low
            };

            if anomalous_features.is_empty() && (is_noise || is_minority) {
                anomalous_features.push(
                    "File inventory profile differs from fleet majority cluster (no mtime/rare-access/metadata gates tripped)."
                        .to_string(),
                );
            }

            anomalies.push(AnomalyDetails {
                machine_id: profile.id.clone(),
                severity,
                distance_score: if has_mtime_anomaly || has_metadata_fleet_anomaly {
                    2.0
                } else if is_noise {
                    1.5
                } else {
                    0.8
                },
                cluster_assignment: *cluster_id,
                anomalous_features,
                process_count: profile.total_logs,
                suspicious_process_count: suspicious_count,
            });
        }
    }

    Ok(AnalysisReport {
        anomalies,
        cluster_stats: cluster_counts,
        total_analyzed: n_samples,
        config_used: config.clone(),
        analysis_type: AnalysisType::File,
    })
}

#[cfg(test)]
mod tests {
    use super::should_ingest_file_entry;
    use crate::config::DetectionConfig;
    use crate::types::RawFileEntry;
    use crate::utils::{compile_regex_list, compile_wildcard_list};

    #[test]
    fn should_ingest_when_no_whitelist_or_exclusion() {
        let config = DetectionConfig::default();
        let wl = compile_wildcard_list(&config.whitelisted_path_patterns);
        let path_res = compile_regex_list(&config.file_excluded_path_regexes);
        let name_res = compile_regex_list(&config.file_excluded_filename_regexes);
        let entry = RawFileEntry {
            path: "/var/log/syslog".into(),
            ..Default::default()
        };
        assert!(should_ingest_file_entry(&entry, &path_res, &name_res, &wl));
    }

    #[test]
    fn should_not_ingest_when_path_matches_whitelist_pattern() {
        let mut config = DetectionConfig::default();
        config.whitelisted_path_patterns = vec!["/private/*".into()];
        let wl = compile_wildcard_list(&config.whitelisted_path_patterns);
        let path_res = compile_regex_list(&config.file_excluded_path_regexes);
        let name_res = compile_regex_list(&config.file_excluded_filename_regexes);
        let entry = RawFileEntry {
            path: "/private/tmp/x".into(),
            ..Default::default()
        };
        assert!(!should_ingest_file_entry(&entry, &path_res, &name_res, &wl));
    }

    #[test]
    fn should_not_ingest_when_excluded_by_path_regex() {
        let mut config = DetectionConfig::default();
        config
            .file_excluded_path_regexes
            .push("^/proc/".to_string());
        let wl = compile_wildcard_list(&config.whitelisted_path_patterns);
        let path_res = compile_regex_list(&config.file_excluded_path_regexes);
        let name_res = compile_regex_list(&config.file_excluded_filename_regexes);
        let entry = RawFileEntry {
            path: "/proc/self/maps".into(),
            ..Default::default()
        };
        assert!(!should_ingest_file_entry(&entry, &path_res, &name_res, &wl));
    }
}
