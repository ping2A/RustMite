//! `dir.hidden` — link-count vs listed-children mismatch on stash paths.

use rustmite_proto::{Confidence, CollectorCost, CollectorId, CollectorReport, DirAnomalyObs, Observation, PathBytes};
use rustmite_sys::dirent::DirEnt;

use crate::{emit, CollectCtx, CollectError, Collector, ObservationSink};

const SCAN_DIRS: &[(&str, &str)] = &[
    ("tmp", "/tmp"),
    ("dev/shm", "/dev/shm"),
    ("var/tmp", "/var/tmp"),
];

pub struct DirHiddenCollector;

impl Collector for DirHiddenCollector {
    fn id(&self) -> &'static str {
        CollectorId::DIR_HIDDEN.as_str()
    }

    fn cost(&self) -> CollectorCost {
        CollectorCost::Medium
    }

    fn collect(
        &self,
        ctx: &CollectCtx<'_>,
        sink: &mut dyn ObservationSink,
    ) -> Result<CollectorReport, CollectError> {
        let mut count = 0u32;
        let mut scanned = 0u32;

        for (rel, wire) in SCAN_DIRS {
            let Ok(st) = stat_path(ctx, rel) else {
                continue;
            };
            if !st.is_dir {
                continue;
            }
            scanned = scanned.saturating_add(1);
            let listed = count_listed_subdirs(ctx, rel);
            if let Some(detail) = nlink_mismatch_detail(st.nlink, listed) {
                emit(
                    ctx,
                    sink,
                    Observation::DirAnomaly(DirAnomalyObs {
                        path: PathBytes::from_str(wire),
                    // Catalog rules historically used link_count_mismatch; keep that name.
                    anomaly: String::from("link_count_mismatch"),
                    detail,
                    confidence: Confidence::High,
                }),
            )?;
            count = count.saturating_add(1);
            }
            // Dotdir stash under staging roots.
            if let Ok(ents) = list_entries(ctx, rel) {
                for ent in ents {
                    if ent.is_dot_or_dotdot() {
                        continue;
                    }
                    let name = String::from_utf8_lossy(&ent.name);
                    if !name.starts_with('.') {
                        continue;
                    }
                    let child = format!("{rel}/{name}");
                    if let Ok(st) = stat_path(ctx, &child) {
                        if st.is_dir {
                            emit(
                                ctx,
                                sink,
                                Observation::DirAnomaly(DirAnomalyObs {
                                    path: PathBytes::from_str(&format!("{wire}/{name}")),
                                    anomaly: String::from("dotdir_stash"),
                                    detail: format!("hidden directory under {wire}"),
                                    confidence: Confidence::Medium,
                                }),
                            )?;
                            count = count.saturating_add(1);
                        }
                    }
                }
            }
        }

        if scanned == 0 {
            return Ok(CollectorReport::unsupported(
                CollectorId::DIR_HIDDEN,
                "none of the scan paths exist",
            ));
        }

        Ok(CollectorReport::complete(CollectorId::DIR_HIDDEN, count, 0))
    }
}

fn stat_path(ctx: &CollectCtx<'_>, path: &str) -> Result<rustmite_sys::procfs::Statx, rustmite_sys::error::Errno> {
    ctx.fs.statx(path).or_else(|_| ctx.proc.statx(path))
}

fn list_entries(ctx: &CollectCtx<'_>, path: &str) -> Result<Vec<DirEnt>, rustmite_sys::error::Errno> {
    ctx.proc
        .list_dir_raw(path)
        .or_else(|_| ctx.fs.list_dir(path))
}

fn count_listed_subdirs(ctx: &CollectCtx<'_>, path: &str) -> usize {
    let Ok(entries) = list_entries(ctx, path) else {
        return 0;
    };
    let mut subdirs = 0usize;
    for ent in entries {
        if ent.is_dot_or_dotdot() {
            continue;
        }
        let child = if path.is_empty() {
            String::from_utf8_lossy(&ent.name).into_owned()
        } else {
            format!("{}/{}", path, String::from_utf8_lossy(&ent.name))
        };
        if let Ok(st) = stat_path(ctx, &child) {
            if st.is_dir {
                subdirs = subdirs.saturating_add(1);
            }
        } else if ent.file_type == DirEnt::DT_DIR {
            subdirs = subdirs.saturating_add(1);
        }
    }
    subdirs
}

fn nlink_mismatch_detail(nlink: u32, listed_subdirs: usize) -> Option<String> {
    if nlink < 2 {
        return None;
    }
    let expected = nlink.saturating_sub(2) as usize;
    if listed_subdirs == expected {
        return None;
    }
    Some(format!(
        "st_nlink={nlink} implies {expected} subdirs but listed {listed_subdirs}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmite_proto::{Budget, Limits};
    use rustmite_sys::{FixtureFs, FixtureProc};
    use crate::VecSink;

    fn budget() -> Budget {
        Budget::new(&Limits::default(), 60_000, 0)
    }

    #[test]
    fn nlink_mismatch_detected() {
        assert!(nlink_mismatch_detail(4, 1).is_some());

        let fx = FixtureProc::new("/tmp/rustmite-fx-dir").with_dir("tmp");
        let fs = FixtureFs::new();
        let b = budget();
        let ctx = CollectCtx {
            proc: &fx,
            fs: &fs,
            pid_probe: None,
            budget: &b,
            euid: 0,
            self_pid: 1,
            now_ms: 0,
        };
        let mut sink = VecSink::new();
        let report = DirHiddenCollector.collect(&ctx, &mut sink).expect("collect");
        assert_eq!(report.observations, 0);
    }
}
