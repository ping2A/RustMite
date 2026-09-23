//! `mounts.inventory` — parse `/proc/mounts`.

use rustmite_proto::{CollectorCost, CollectorId, CollectorReport, MountObs, Observation, PathBytes};

use crate::{emit, CollectCtx, CollectError, Collector, ObservationSink};

pub struct MountsInventoryCollector;

impl Collector for MountsInventoryCollector {
    fn id(&self) -> &'static str {
        CollectorId::MOUNTS_INVENTORY.as_str()
    }

    fn cost(&self) -> CollectorCost {
        CollectorCost::Trivial
    }

    fn collect(
        &self,
        ctx: &CollectCtx<'_>,
        sink: &mut dyn ObservationSink,
    ) -> Result<CollectorReport, CollectError> {
        let Some(data) = read_path(ctx, "proc/mounts") else {
            return Ok(CollectorReport::unsupported(
                CollectorId::MOUNTS_INVENTORY,
                "proc/mounts unreadable",
            ));
        };

        let mut count = 0u32;
        for mount in parse_proc_mounts(&data) {
            emit(ctx, sink, Observation::Mount(mount))?;
            count = count.saturating_add(1);
        }

        Ok(CollectorReport::complete(
            CollectorId::MOUNTS_INVENTORY,
            count,
            0,
        ))
    }
}

fn read_path(ctx: &CollectCtx<'_>, path: &str) -> Option<Vec<u8>> {
    ctx.proc.read(path).ok().or_else(|| ctx.fs.read(path).ok())
}

fn parse_proc_mounts(data: &[u8]) -> Vec<MountObs> {
    let Ok(s) = core::str::from_utf8(data) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in s.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let device = parts[0].to_string();
        let mountpoint = parts[1].to_string();
        let fstype = parts[2].to_string();
        let options = parts[3].to_string();
        out.push(MountObs {
            device,
            mountpoint: PathBytes::from_str(&mountpoint),
            fstype,
            options,
        });
    }
    out
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
    fn parses_mounts() {
        let mounts = b"rootfs / rootfs rw 0 0\n/dev/sda1 / ext4 rw,relatime 0 0\n";
        let fx = FixtureProc::new("/tmp/rustmite-fx-mounts").with_file("proc/mounts", mounts);
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
        let report = MountsInventoryCollector.collect(&ctx, &mut sink).expect("collect");
        assert_eq!(report.observations, 2);
        assert!(sink.observations.iter().any(|o| matches!(
            o,
            Observation::Mount(m) if m.fstype == "ext4"
        )));
    }
}
