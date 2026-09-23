//! `decloak.process` — hidden process detection (docs/06 §2).

use std::collections::{BTreeMap, BTreeSet};

use rustmite_proto::{
    CollectorCost, CollectorId, CollectorReport, Confidence, HiddenProcessObs, Observation,
};
use rustmite_sys::{parse_proc_stat, PidLiveness, PidProbeView};

use crate::{emit, CollectCtx, CollectError, Collector, ObservationSink};

pub struct DecloakProcessCollector;

impl Collector for DecloakProcessCollector {
    fn id(&self) -> &'static str {
        CollectorId::DECLOAK_PROCESS.as_str()
    }

    fn cost(&self) -> CollectorCost {
        CollectorCost::Trivial
    }

    fn collect(
        &self,
        ctx: &CollectCtx<'_>,
        sink: &mut dyn ObservationSink,
    ) -> Result<CollectorReport, CollectError> {
        let probe = match ctx.pid_probe {
            Some(p) => p,
            None => {
                return Ok(CollectorReport::unsupported(
                    CollectorId::DECLOAK_PROCESS,
                    "no PidProbeView available",
                ));
            }
        };

        let pass1 = discover_hidden(ctx, probe)?;
        let pass2 = discover_hidden(ctx, probe)?;

        let mut emitted = 0u32;
        for (pid, info1) in &pass1 {
            if *pid == ctx.self_pid {
                continue;
            }
            let Some(info2) = pass2.get(pid) else {
                continue;
            };
            // Require stable starttime across passes when known.
            let start_ok = match (info1.starttime, info2.starttime) {
                (Some(a), Some(b)) => a == b,
                (None, None) => true,
                _ => false,
            };
            if !start_ok {
                continue;
            }
            // Merge sources from both passes.
            let mut sources_present: BTreeSet<String> = info1
                .sources_present
                .iter()
                .chain(info2.sources_present.iter())
                .cloned()
                .collect();
            let sources_absent: Vec<String> = vec![String::from("proc_listing")];

            let confidence = if sources_present.len() >= 2 {
                Confidence::High
            } else if sources_present.len() == 1 {
                Confidence::Medium
            } else {
                Confidence::Low
            };

            // Ensure we always list at least sched if alive.
            if sources_present.is_empty() {
                sources_present.insert(String::from("sched"));
            }

            let obs = HiddenProcessObs {
                pid: *pid,
                sources_present: sources_present.into_iter().collect(),
                sources_absent,
                comm: info2.comm.clone().or_else(|| info1.comm.clone()),
                exe: None,
                uid: None,
                starttime: info2.starttime.or(info1.starttime),
                cgroup: info2.cgroup.clone().or_else(|| info1.cgroup.clone()),
                passes_confirmed: 2,
                confidence,
                note: Some(String::from(
                    "present to scheduler / openat, absent from /proc listing",
                )),
            };
            emit(ctx, sink, Observation::HiddenProcess(obs))?;
            emitted = emitted.saturating_add(1);
        }

        Ok(CollectorReport::complete(
            CollectorId::DECLOAK_PROCESS,
            emitted,
            0,
        ))
    }
}

#[derive(Clone, Debug, Default)]
struct HiddenInfo {
    sources_present: Vec<String>,
    comm: Option<String>,
    starttime: Option<u64>,
    cgroup: Option<String>,
}

fn discover_hidden(
    ctx: &CollectCtx<'_>,
    probe: &dyn PidProbeView,
) -> Result<BTreeMap<i32, HiddenInfo>, CollectError> {
    let listed = list_proc_pids(ctx)?;
    let pid_max = read_pid_max(ctx).unwrap_or_else(|| probe.pid_max());
    let sweep_max = pid_max.min(65_536);

    let mut from_sched: BTreeSet<i32> = BTreeSet::new();
    let mut from_openat: BTreeSet<i32> = BTreeSet::new();
    let mut from_cgroup: BTreeSet<i32> = BTreeSet::new();
    let mut stat_cache: BTreeMap<i32, (Option<String>, Option<u64>)> = BTreeMap::new();

    for pid in 1..=sweep_max {
        if pid == ctx.self_pid {
            continue;
        }
        match probe.pid_exists(pid) {
            PidLiveness::Alive | PidLiveness::AliveNotOurs => {
                from_sched.insert(pid);
            }
            PidLiveness::Absent | PidLiveness::Unknown => {}
        }

        let stat_path = format!("proc/{pid}/stat");
        if ctx.proc.open_exists(&stat_path) {
            from_openat.insert(pid);
            if let Ok(data) = ctx.proc.read(&stat_path) {
                if let Ok(st) = parse_proc_stat(&data) {
                    stat_cache.insert(pid, (Some(st.comm), Some(st.starttime)));
                }
            }
        }
    }

    // Also pick up any PID referenced via cgroup files under listed procs / common paths.
    collect_cgroup_pids(ctx, &listed, &mut from_cgroup);

    let mut hidden: BTreeMap<i32, HiddenInfo> = BTreeMap::new();
    let present = from_sched
        .iter()
        .chain(from_openat.iter())
        .chain(from_cgroup.iter())
        .copied()
        .collect::<BTreeSet<_>>();

    for pid in present {
        if pid == ctx.self_pid || listed.contains(&pid) {
            continue;
        }
        let mut sources = Vec::new();
        if from_sched.contains(&pid) {
            sources.push(String::from("sched"));
        }
        if from_openat.contains(&pid) {
            sources.push(String::from("openat_stat"));
        }
        if from_cgroup.contains(&pid) {
            sources.push(String::from("cgroup"));
        }
        let (comm, starttime) = stat_cache
            .get(&pid)
            .cloned()
            .unwrap_or((None, probe.starttime(pid)));
        let starttime = starttime.or_else(|| probe.starttime(pid));
        let cgroup = read_cgroup_for_pid(ctx, pid);
        hidden.insert(
            pid,
            HiddenInfo {
                sources_present: sources,
                comm,
                starttime,
                cgroup,
            },
        );
    }

    Ok(hidden)
}

fn list_proc_pids(ctx: &CollectCtx<'_>) -> Result<BTreeSet<i32>, CollectError> {
    let ents = ctx.proc.list_dir_raw("proc")?;
    let mut set = BTreeSet::new();
    for e in ents {
        if e.is_dot_or_dotdot() {
            continue;
        }
        let name = e.name_str();
        if let Ok(pid) = name.parse::<i32>() {
            if pid > 0 {
                set.insert(pid);
            }
        }
    }
    Ok(set)
}

fn read_pid_max(ctx: &CollectCtx<'_>) -> Option<i32> {
    let data = ctx.proc.read("proc/sys/kernel/pid_max").ok()?;
    let s = core::str::from_utf8(&data).ok()?.trim();
    s.parse().ok()
}

fn collect_cgroup_pids(ctx: &CollectCtx<'_>, listed: &BTreeSet<i32>, out: &mut BTreeSet<i32>) {
    // Per-process cgroup file may reference only self; also try common cgroup.procs paths.
    for path in [
        "sys/fs/cgroup/cgroup.procs",
        "sys/fs/cgroup/system.slice/cgroup.procs",
    ] {
        if let Ok(data) = ctx.proc.read(path) {
            parse_pid_list(&data, out);
        }
    }
    for pid in listed {
        let path = format!("proc/{pid}/cgroup");
        if let Ok(data) = ctx.proc.read(&path) {
            // cgroup file is not a pid list; skip. Look for cgroup.procs via relative paths if present.
            let _ = data;
        }
    }
}

fn parse_pid_list(data: &[u8], out: &mut BTreeSet<i32>) {
    if let Ok(s) = core::str::from_utf8(data) {
        for line in s.lines() {
            if let Ok(pid) = line.trim().parse::<i32>() {
                if pid > 0 {
                    out.insert(pid);
                }
            }
        }
    }
}

fn read_cgroup_for_pid(ctx: &CollectCtx<'_>, pid: i32) -> Option<String> {
    let data = ctx.proc.read(&format!("proc/{pid}/cgroup")).ok()?;
    let s = core::str::from_utf8(&data).ok()?;
    s.lines().next().map(|l| l.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmite_proto::{Budget, Limits, Observation};
    use rustmite_sys::{FixtureFs, FixtureProc};
    use crate::VecSink;

    fn make_stat(pid: i32, comm: &str, starttime: u64) -> String {
        // Minimal fields after comm so parse_proc_stat works (need indices through starttime=19).
        format!(
            "{pid} ({comm}) S 0 {pid} {pid} 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 {starttime} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
        )
    }

    fn budget() -> Budget {
        Budget::new(&Limits::default(), 60_000, 0)
    }

    #[test]
    fn diamorphine_style_hidden_pid() {
        let fx = FixtureProc::new("/tmp/rustmite-fx-decloak")
            .with_dir("proc/1")
            .with_file("proc/1/stat", make_stat(1, "systemd", 100))
            .with_file("proc/sys/kernel/pid_max", "32768\n")
            .with_hidden_pid(31337, 88123)
            .with_file("proc/31337/stat", make_stat(31337, "kdevtmpfsi", 88123));

        let fs = FixtureFs::new();
        let b = budget();
        let ctx = CollectCtx {
            proc: &fx,
            fs: &fs,
            pid_probe: Some(&fx),
            budget: &b,
            euid: 0,
            self_pid: 99999,
            now_ms: 0,
        };
        let mut sink = VecSink::new();
        let report = DecloakProcessCollector
            .collect(&ctx, &mut sink)
            .expect("collect");
        assert_eq!(report.observations, 1);

        let found = sink.observations.iter().find_map(|o| match o {
            Observation::HiddenProcess(h) => Some(h),
            _ => None,
        });
        let h = found.expect("HiddenProcess");
        assert_eq!(h.pid, 31337);
        assert_eq!(h.passes_confirmed, 2);
        assert_eq!(h.confidence, Confidence::High);
        assert_eq!(h.starttime, Some(88123));
        assert!(h.sources_present.iter().any(|s| s == "sched"));
        assert!(h.sources_absent.iter().any(|s| s == "proc_listing"));
    }

    #[test]
    fn clean_no_hidden() {
        let fx = FixtureProc::new("/tmp/rustmite-fx-clean")
            .with_dir("proc/1")
            .with_file("proc/1/stat", make_stat(1, "systemd", 100))
            .with_file("proc/sys/kernel/pid_max", "1024\n")
            .with_alive_pid(1);

        let fs = FixtureFs::new();
        let b = budget();
        let ctx = CollectCtx {
            proc: &fx,
            fs: &fs,
            pid_probe: Some(&fx),
            budget: &b,
            euid: 0,
            self_pid: 99999,
            now_ms: 0,
        };
        let mut sink = VecSink::new();
        DecloakProcessCollector
            .collect(&ctx, &mut sink)
            .expect("collect");
        let hidden = sink
            .observations
            .iter()
            .any(|o| matches!(o, Observation::HiddenProcess(_)));
        assert!(!hidden);
    }
}
