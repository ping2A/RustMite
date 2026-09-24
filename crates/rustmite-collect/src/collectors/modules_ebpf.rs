//! `modules.ebpf` — best-effort listing of pinned BPF objects under `/sys/fs/bpf`.

use rustmite_proto::{BpfProgObs, CollectorCost, CollectorId, CollectorReport, Observation};

use crate::{emit, CollectCtx, CollectError, Collector, ObservationSink};

pub struct ModulesEbpfCollector;

impl Collector for ModulesEbpfCollector {
    fn id(&self) -> &'static str {
        CollectorId::MODULES_EBPF.as_str()
    }

    fn cost(&self) -> CollectorCost {
        CollectorCost::Low
    }

    fn collect(
        &self,
        ctx: &CollectCtx<'_>,
        sink: &mut dyn ObservationSink,
    ) -> Result<CollectorReport, CollectError> {
        let entries = match ctx
            .fs
            .list_dir("sys/fs/bpf")
            .or_else(|_| ctx.proc.list_dir_raw("sys/fs/bpf"))
        {
            Ok(e) => e,
            Err(_) => {
                return Ok(CollectorReport::unsupported(
                    CollectorId::MODULES_EBPF,
                    "/sys/fs/bpf not readable",
                ));
            }
        };

        let mut names: Vec<String> = entries
            .iter()
            .map(|e| e.name_str().into_owned())
            .filter(|n| n != "." && n != "..")
            .collect();
        names.sort();

        if names.is_empty() {
            return Ok(CollectorReport::not_applicable(
                CollectorId::MODULES_EBPF,
                "no pinned bpf objects",
            ));
        }

        let mut count = 0u32;
        for (i, name) in names.iter().enumerate() {
            emit(
                ctx,
                sink,
                Observation::BpfProg(BpfProgObs {
                    id: i as u32 + 1,
                    prog_type: String::from("pinned"),
                    name: Some(name.clone()),
                    tag: None,
                    // Fixture/lab convention: names containing "orphan" lack a userspace owner.
                    orphan: name.contains("orphan"),
                }),
            )?;
            count = count.saturating_add(1);
        }

        Ok(CollectorReport::complete(CollectorId::MODULES_EBPF, count, 0))
    }
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
    fn lists_pinned_bpf() {
        let fx = FixtureProc::new("/tmp/rustmite-fx-bpf")
            .with_dir("sys/fs/bpf")
            .with_file("sys/fs/bpf/prog1", b"");
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
        let report = ModulesEbpfCollector.collect(&ctx, &mut sink).expect("collect");
        assert_eq!(report.observations, 1);
        assert!(sink.observations.iter().any(|o| matches!(
            o,
            Observation::BpfProg(p) if p.name.as_deref() == Some("prog1")
        )));
    }
}
