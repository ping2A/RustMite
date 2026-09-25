//! `file.ioc` — setuid/setgid inventory + path IOC hits.
//!
//! Snapshot-side half of Elastic's Linux LPE framework: inventory dangerous
//! privilege bits on disk (SUID helpers / GTFOBins / staging-path setuid).
//! Runtime exec→uid_change sequences still need auditd/EDR ingest.

use rustmite_proto::{
    BigInt, CollectorCost, CollectorId, CollectorReport, FileMetaObs, IocHitObs, Observation,
    PathBytes, Severity,
};
use rustmite_sys::Statx;

use crate::{emit, CollectCtx, CollectError, Collector, ObservationSink};

/// Bounded roots — full FS walk is too expensive for a pulse scan.
const SCAN_ROOTS: &[&str] = &[
    "bin",
    "sbin",
    "usr/bin",
    "usr/sbin",
    "usr/lib",
    "usr/libexec",
    "usr/local/bin",
    "usr/local/sbin",
    "tmp",
    "var/tmp",
    "dev/shm",
    "dev",
    "home",
    "opt",
    "root",
];

/// Known rootkit / backdoor path fragments (path IOC).
const PATH_IOCS: &[&str] = &[
    "usr/bin/..",
    "lib/libudev.so.",
    "etc/rc.modules",
];

/// Max directory entries walked per collect (budget guard).
const MAX_ENTRIES: u32 = 8_000;

pub struct FileIocCollector;

impl Collector for FileIocCollector {
    fn id(&self) -> &'static str {
        CollectorId::FILE_IOC.as_str()
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
        let mut walked = 0u32;

        for root in SCAN_ROOTS {
            walk_dir(ctx, sink, root, 0, &mut count, &mut walked)?;
            if walked >= MAX_ENTRIES {
                break;
            }
        }

        for ioc in PATH_IOCS {
            if ctx.fs.statx(ioc).is_ok() || ctx.fs.read(ioc).is_ok() {
                let display = format!("/{}", ioc.trim_start_matches('/'));
                emit(
                    ctx,
                    sink,
                    Observation::IocHit(IocHitObs {
                        path: PathBytes::from(display),
                        ioc_kind: "path".into(),
                        ioc_value: (*ioc).into(),
                        severity: Severity::High,
                    }),
                )?;
                count = count.saturating_add(1);
            }
        }

        // Optional hash/string IOC feed for fixtures / lab packs.
        if let Ok(data) = ctx
            .fs
            .read("etc/rustmite/iocs.ndjson")
            .or_else(|_| ctx.proc.read("etc/rustmite/iocs.ndjson"))
        {
            for line in String::from_utf8_lossy(&data).lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                let kind = v.get("ioc_kind").and_then(|x| x.as_str()).unwrap_or("");
                let value = v.get("ioc_value").and_then(|x| x.as_str()).unwrap_or("");
                let path = v.get("path").and_then(|x| x.as_str()).unwrap_or("/ioc");
                if kind.is_empty() || value.is_empty() {
                    continue;
                }
                emit(
                    ctx,
                    sink,
                    Observation::IocHit(IocHitObs {
                        path: PathBytes::from(path),
                        ioc_kind: kind.into(),
                        ioc_value: value.into(),
                        severity: Severity::High,
                    }),
                )?;
                count = count.saturating_add(1);
            }
        }

        Ok(CollectorReport::complete(
            CollectorId::FILE_IOC,
            count,
            0,
        ))
    }
}

fn walk_dir(
    ctx: &CollectCtx<'_>,
    sink: &mut dyn ObservationSink,
    rel: &str,
    depth: u32,
    count: &mut u32,
    walked: &mut u32,
) -> Result<(), CollectError> {
    if depth > 6 || *walked >= MAX_ENTRIES {
        return Ok(());
    }
    let Ok(ents) = ctx.fs.list_dir(rel) else {
        return Ok(());
    };
    for ent in ents {
        if *walked >= MAX_ENTRIES {
            break;
        }
        *walked = walked.saturating_add(1);
        let name = match String::from_utf8(ent.name) {
            Ok(n) => n,
            Err(_) => continue,
        };
        if name == "." || name == ".." {
            continue;
        }
        let child = if rel.is_empty() {
            name.clone()
        } else {
            format!("{rel}/{name}")
        };
        let Ok(st) = ctx.fs.statx(&child) else {
            continue;
        };
        if st.is_dir {
            // Skip huge / noisy trees under home.
            if depth >= 1 && (name == ".cache" || name == ".npm" || name == "node_modules") {
                continue;
            }
            walk_dir(ctx, sink, &child, depth + 1, count, walked)?;
            continue;
        }
        if !st.is_reg {
            continue;
        }
        if let Some(obs) = file_meta_if_interesting(&child, &st) {
            emit(ctx, sink, Observation::FileMeta(obs))?;
            *count = count.saturating_add(1);
        }
    }
    Ok(())
}

fn file_meta_if_interesting(rel: &str, st: &Statx) -> Option<FileMetaObs> {
    let mode = st.mode;
    let setuid = mode & 0o4000 != 0;
    let setgid = mode & 0o2000 != 0;
    let world_writable = mode & 0o002 != 0;
    let executable = mode & 0o111 != 0;
    let under_dev = rel == "dev" || rel.starts_with("dev/");
    let large_under_dev = under_dev && !rel.starts_with("dev/shm") && st.is_reg && st.size > 4096;
    // Emit setuid/setgid always; also world-writable executables (RM-POL-0032);
    // also oversized regular files under /dev (RM-FILE-0010).
    if !(setuid || setgid || (world_writable && executable) || large_under_dev) {
        return None;
    }
    let display = format!("/{}", rel.trim_start_matches('/'));
    Some(FileMetaObs {
        path: PathBytes::from(display),
        mode,
        uid: st.uid,
        gid: st.gid,
        size: BigInt(st.size.to_string()),
        inode: BigInt(st.ino.to_string()),
        nlink: st.nlink,
        setuid,
        setgid,
        immutable: false,
        owner: None,
        group: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmite_proto::{Budget, Limits};
    use rustmite_sys::{FixtureFs, FixtureProc};

    use crate::sink::VecSink;

    #[test]
    fn finds_setuid_gtfobin() {
        let fs = FixtureFs::new().with_file_meta(
            "usr/bin/find",
            b"#!/bin/sh\n",
            0o104755, // setuid + rwxr-xr-x
            0,
        );
        let proc = FixtureProc::new("/tmp/rustmite-fx-ioc");
        let budget = Budget::new(&Limits::default(), 60_000, 0);
        let ctx = CollectCtx {
            proc: &proc,
            fs: &fs,
            pid_probe: None,
            budget: &budget,
            euid: 0,
            self_pid: 1,
            now_ms: 0,
        };
        let mut sink = VecSink::new();
        let report = FileIocCollector.collect(&ctx, &mut sink).expect("collect");
        assert!(report.observations >= 1);
        let hit = sink.observations.iter().any(|o| {
            matches!(
                o,
                Observation::FileMeta(f) if f.setuid && f.path.to_string_lossy().contains("find")
            )
        });
        assert!(hit, "expected setuid find FileMeta");
    }
}
