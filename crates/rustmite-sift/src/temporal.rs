//! Temporal comparison: same machine across time (snapshots, diff).

use std::collections::HashSet;
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::config::DetectionConfig;
use crate::file_analysis::build_file_profiles;
use crate::builder::build_profiles;
use crate::types::{
    FileSignature, MachineFileProfile, MachineProfile, ProcessSignature,
    RawConnectionEntry, RawFileEntry, RawLogEntry,
};

/// One point-in-time snapshot of a machine (processes, files, connections).
#[derive(Debug, Clone)]
pub struct MachineSnapshot {
    pub machine_id: String,
    pub snapshot_ts: String,
    pub process_profile: MachineProfile,
    pub file_profile: Option<MachineFileProfile>,
    pub connections: HashSet<String>,
}

/// Diff between two snapshots: new processes, new/modified files, new IPs.
#[derive(Debug, Clone, Default, Serialize)]
pub struct TemporalDiff {
    pub machine_id: String,
    pub from_ts: String,
    pub to_ts: String,
    pub new_processes: Vec<ProcessSignature>,
    pub new_files: Vec<FileSignature>,
    pub modified_files: Vec<(String, Option<DateTime<Utc>>, Option<DateTime<Utc>>)>,
    pub new_connections: Vec<String>,
}

impl TemporalDiff {
    pub fn is_empty(&self) -> bool {
        self.new_processes.is_empty()
            && self.new_files.is_empty()
            && self.modified_files.is_empty()
            && self.new_connections.is_empty()
    }

    pub fn has_changes(&self) -> bool {
        !self.is_empty()
    }

    pub fn print(&self) {
        println!(
            "=== Temporal diff: {} → {} (machine: {}) ===",
            self.from_ts, self.to_ts, self.machine_id
        );
        if !self.new_processes.is_empty() {
            println!("  New processes: {}", self.new_processes.len());
            for p in &self.new_processes {
                println!("    - {} (path: {}, uid: {})", p.name, p.path, p.uid);
            }
        }
        if !self.new_files.is_empty() {
            println!("  New files: {}", self.new_files.len());
            for f in &self.new_files {
                println!("    - {} (uid: {})", f.path, f.uid);
            }
        }
        if !self.modified_files.is_empty() {
            println!("  Modified files: {}", self.modified_files.len());
            for (path, old_opt, new_opt) in &self.modified_files {
                println!("    - {} (was: {:?}, now: {:?})", path, old_opt, new_opt);
            }
        }
        if !self.new_connections.is_empty() {
            println!("  New connections: {}", self.new_connections.len());
            for ip in &self.new_connections {
                println!("    - {}", ip);
            }
        }
        if self.is_empty() {
            println!("  (no changes)");
        }
    }
}

pub fn build_machine_snapshot(
    machine_id: &str,
    snapshot_ts: &str,
    process_entries: Vec<RawLogEntry>,
    file_entries: Vec<RawFileEntry>,
    connection_entries: Vec<RawConnectionEntry>,
    config: &DetectionConfig,
) -> MachineSnapshot {
    let process_profile = build_profiles(process_entries, config)
        .into_iter()
        .find(|p| p.id == machine_id)
        .unwrap_or_else(|| MachineProfile::new(machine_id));
    let file_profile = if file_entries.is_empty() {
        None
    } else {
        let profiles = build_file_profiles(file_entries, config);
        Some(
            profiles
                .into_iter()
                .find(|p| p.id == machine_id)
                .unwrap_or_else(|| MachineFileProfile::new(machine_id)),
        )
    };
    let connections: HashSet<String> = connection_entries.into_iter().map(|e| e.remote_ip).collect();
    MachineSnapshot {
        machine_id: machine_id.to_string(),
        snapshot_ts: snapshot_ts.to_string(),
        process_profile,
        file_profile,
        connections,
    }
}

pub fn compare_temporal(baseline: &MachineSnapshot, current: &MachineSnapshot) -> TemporalDiff {
    if baseline.machine_id != current.machine_id {
        return TemporalDiff {
            machine_id: current.machine_id.clone(),
            from_ts: baseline.snapshot_ts.clone(),
            to_ts: current.snapshot_ts.clone(),
            ..Default::default()
        };
    }
    let new_processes: Vec<ProcessSignature> = current
        .process_profile
        .counts
        .keys()
        .filter(|sig| !baseline.process_profile.counts.contains_key(sig))
        .cloned()
        .collect();
    let (new_files, modified_files) = match (&baseline.file_profile, &current.file_profile) {
        (None, None) => (Vec::new(), Vec::new()),
        (_, None) => (Vec::new(), Vec::new()),
        (None, Some(cur)) => {
            let new_files: Vec<FileSignature> = cur.counts.keys().cloned().collect();
            (new_files, Vec::new())
        }
        (Some(base), Some(cur)) => {
            let new_files: Vec<FileSignature> = cur
                .counts
                .keys()
                .filter(|sig| !base.counts.contains_key(sig))
                .cloned()
                .collect();
            let modified_files: Vec<(String, Option<DateTime<Utc>>, Option<DateTime<Utc>>)> = cur
                .file_mtimes
                .iter()
                .filter_map(|(path, new_mtime)| {
                    let old_mtime = base.file_mtimes.get(path);
                    if old_mtime != Some(new_mtime) && old_mtime.is_some() {
                        Some((
                            path.as_ref().to_string(),
                            base.file_mtimes.get(path).copied(),
                            Some(*new_mtime),
                        ))
                    } else if old_mtime.is_none()
                        && base.counts.keys().any(|s| s.path.as_ref() == path.as_ref())
                    {
                        Some((
                            path.as_ref().to_string(),
                            base.file_mtimes.get(path).copied(),
                            Some(*new_mtime),
                        ))
                    } else {
                        None
                    }
                })
                .collect();
            (new_files, modified_files)
        }
    };
    let new_connections: Vec<String> = current
        .connections
        .difference(&baseline.connections)
        .cloned()
        .collect();
    TemporalDiff {
        machine_id: current.machine_id.clone(),
        from_ts: baseline.snapshot_ts.clone(),
        to_ts: current.snapshot_ts.clone(),
        new_processes,
        new_files,
        modified_files,
        new_connections,
    }
}

pub fn compare_temporal_series(snapshots: &[MachineSnapshot]) -> Vec<TemporalDiff> {
    let mut diffs = Vec::new();
    for i in 1..snapshots.len() {
        diffs.push(compare_temporal(&snapshots[i - 1], &snapshots[i]));
    }
    diffs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DetectionConfig;
    use crate::types::{MachineProfile, RawLogEntry};
    use std::collections::HashSet;

    fn empty_snapshot(mid: &str, ts: &str) -> MachineSnapshot {
        MachineSnapshot {
            machine_id: mid.to_string(),
            snapshot_ts: ts.to_string(),
            process_profile: MachineProfile::new(mid),
            file_profile: None,
            connections: HashSet::new(),
        }
    }

    #[test]
    fn temporal_diff_empty_helpers() {
        let d = TemporalDiff::default();
        assert!(d.is_empty());
        assert!(!d.has_changes());
    }

    #[test]
    fn compare_temporal_series_empty_or_single_yields_no_diffs() {
        assert!(compare_temporal_series(&[]).is_empty());
        let s = empty_snapshot("m", "t1");
        assert!(compare_temporal_series(std::slice::from_ref(&s)).is_empty());
    }

    #[test]
    fn compare_temporal_mismatched_machine_returns_empty_diff_body() {
        let a = empty_snapshot("m1", "t1");
        let b = empty_snapshot("m2", "t2");
        let d = compare_temporal(&a, &b);
        assert_eq!(d.machine_id, "m2");
        assert!(d.new_processes.is_empty());
    }

    #[test]
    fn build_machine_snapshot_roundtrip_machine_id() {
        let config = DetectionConfig::default();
        let entries = vec![RawLogEntry {
            machine_id: "host1".into(),
            pid: 1,
            ppid: 0,
            name: "systemd".into(),
            uid: 0,
            path: "/usr/lib/systemd/systemd".into(),
            args: "--system".into(),
            timestamp: None,
        }];
        let snap = build_machine_snapshot("host1", "2024-01-01", entries, vec![], vec![], &config);
        assert_eq!(snap.machine_id, "host1");
        assert_eq!(snap.snapshot_ts, "2024-01-01");
        assert!(!snap.process_profile.counts.is_empty());
    }
}
