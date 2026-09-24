//! `modules.lkm` — compare `/proc/modules` vs `/sys/module`.
//!
//! `/sys/module` also lists **built-in** (compiled-in) modules that never appear in
//! `/proc/modules` (e.g. `8250`, `ext4` when built-in). Those are not a rootkit Δ —
//! only **loadable** modules (sysfs entries with an `initstate` attribute) are
//! compared against `/proc/modules`.

use std::collections::BTreeSet;

use rustmite_proto::{CollectorCost, CollectorId, CollectorReport, ModuleObs, Observation};

use crate::{emit, CollectCtx, CollectError, Collector, ObservationSink};

pub struct ModulesLkmCollector;

impl Collector for ModulesLkmCollector {
    fn id(&self) -> &'static str {
        CollectorId::MODULES_LKM.as_str()
    }

    fn cost(&self) -> CollectorCost {
        CollectorCost::Low
    }

    fn collect(
        &self,
        ctx: &CollectCtx<'_>,
        sink: &mut dyn ObservationSink,
    ) -> Result<CollectorReport, CollectError> {
        let proc_mods = parse_proc_modules(ctx);
        // Loadable modules only — builtins live under /sys/module without initstate.
        let sys_mods = list_loadable_sys_modules(ctx);

        let mut count = 0u32;
        let all: BTreeSet<String> = proc_mods
            .keys()
            .chain(sys_mods.iter())
            .cloned()
            .collect();

        for name in all {
            let in_proc = proc_mods.contains_key(&name);
            let in_sysfs = sys_mods.contains(&name);
            let (size, refcount, used_by) = proc_mods
                .get(&name)
                .cloned()
                .unwrap_or((None, None, Vec::new()));

            let taint_flags = read_module_taint(ctx, &name);
            let obs = ModuleObs {
                name: name.clone(),
                size,
                refcount,
                used_by,
                in_sysfs,
                in_proc_modules: in_proc,
                taint_flags,
            };

            if in_proc != in_sysfs {
                // Disagreement among loadable modules — classic LKM hide signal.
                emit(ctx, sink, Observation::HiddenModule(obs))?;
            } else {
                emit(ctx, sink, Observation::Module(obs))?;
            }
            count = count.saturating_add(1);
        }

        Ok(CollectorReport::complete(
            CollectorId::MODULES_LKM,
            count,
            0,
        ))
    }
}

fn parse_proc_modules(
    ctx: &CollectCtx<'_>,
) -> std::collections::BTreeMap<String, (Option<u64>, Option<i32>, Vec<String>)> {
    let mut map = std::collections::BTreeMap::new();
    let Ok(data) = ctx.proc.read("proc/modules") else {
        return map;
    };
    let Ok(s) = core::str::from_utf8(&data) else {
        return map;
    };
    for line in s.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        // name size refcount used_by state address
        let Some(name) = parts.first().copied() else {
            continue;
        };
        let size = parts.get(1).and_then(|x| x.parse().ok());
        let refcount = parts.get(2).and_then(|x| x.parse().ok());
        let used_by = parts
            .get(3)
            .map(|u| {
                u.split(',')
                    .filter(|x| !x.is_empty() && *x != "-")
                    .map(|x| x.to_string())
                    .collect()
            })
            .unwrap_or_default();
        map.insert(name.to_string(), (size, refcount, used_by));
    }
    map
}

/// Loadable LKMs expose `/sys/module/<name>/initstate` (`live` / `coming` / `going`).
/// Built-in modules have a sysfs directory but no `initstate` — exclude them.
fn read_module_taint(ctx: &CollectCtx<'_>, name: &str) -> Option<String> {
    let path = format!("sys/module/{name}/taint");
    let data = ctx.proc.read(&path).ok().or_else(|| ctx.fs.read(&path).ok())?;
    let s = String::from_utf8_lossy(&data).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn list_loadable_sys_modules(ctx: &CollectCtx<'_>) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    let Ok(ents) = ctx.proc.list_dir_raw("sys/module") else {
        return set;
    };
    for e in ents {
        if e.is_dot_or_dotdot() {
            continue;
        }
        let name = e.name_str().into_owned();
        let initstate = format!("sys/module/{name}/initstate");
        if ctx.proc.open_exists(&initstate) || ctx.proc.read(&initstate).is_ok() {
            set.insert(name);
        }
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmite_proto::{Budget, Limits, Observation};
    use rustmite_sys::{FixtureFs, FixtureProc};

    use crate::VecSink;

    fn budget() -> Budget {
        Budget::new(&Limits::default(), 60_000, 0)
    }

    #[test]
    fn builtins_without_initstate_are_not_flagged() {
        let fx = FixtureProc::new("/tmp/rustmite-fx-lkm")
            .with_file("proc/modules", b"fuse 163840 1 - Live 0xffffffffc0\n")
            .with_dir("sys/module")
            .with_dir("sys/module/fuse")
            .with_file("sys/module/fuse/initstate", b"live\n")
            .with_dir("sys/module/8250") // built-in serial — no initstate
            .with_dir("sys/module/ext4");
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
        let report = ModulesLkmCollector.collect(&ctx, &mut sink).expect("collect");
        assert!(report.observations >= 1);
        let names: Vec<_> = sink
            .observations
            .iter()
            .filter_map(|o| match o {
                Observation::Module(m) | Observation::HiddenModule(m) => Some(m.name.as_str()),
                _ => None,
            })
            .collect();
        assert!(names.contains(&"fuse"));
        assert!(!names.contains(&"8250"));
        assert!(!names.contains(&"ext4"));
        assert!(sink.observations.iter().all(|o| !matches!(o, Observation::HiddenModule(_))));
    }

    #[test]
    fn loadable_sysfs_only_is_hidden() {
        let fx = FixtureProc::new("/tmp/rustmite-fx-lkm-hide")
            .with_file("proc/modules", b"")
            .with_dir("sys/module")
            .with_dir("sys/module/evil")
            .with_file("sys/module/evil/initstate", b"live\n");
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
        ModulesLkmCollector.collect(&ctx, &mut sink).expect("collect");
        assert!(sink.observations.iter().any(|o| matches!(
            o,
            Observation::HiddenModule(m) if m.name == "evil" && m.in_sysfs && !m.in_proc_modules
        )));
    }
}
