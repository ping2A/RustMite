//! `container.inventory` — detect container runtime hints.

use rustmite_proto::{CollectorCost, CollectorId, CollectorReport, ContainerObs, Observation};

use crate::{emit, CollectCtx, CollectError, Collector, ObservationSink};

pub struct ContainerInventoryCollector;

impl Collector for ContainerInventoryCollector {
    fn id(&self) -> &'static str {
        CollectorId::CONTAINER_INVENTORY.as_str()
    }

    fn cost(&self) -> CollectorCost {
        CollectorCost::Low
    }

    fn collect(
        &self,
        ctx: &CollectCtx<'_>,
        sink: &mut dyn ObservationSink,
    ) -> Result<CollectorReport, CollectError> {
        let dockerenv = path_exists(ctx, ".dockerenv")
            || path_exists(ctx, "run/.containerenv");
        let cgroup = read_path(ctx, "proc/1/cgroup");
        let (in_container, runtime) = infer_container(dockerenv, cgroup.as_deref());

        let docker_sock = path_exists(ctx, "var/run/docker.sock");
        let privileged = false;
        let host_pid_ns = false;

        emit(
            ctx,
            sink,
            Observation::ContainerInfo(ContainerObs {
                in_container,
                runtime,
                privileged,
                docker_sock_mounted: docker_sock,
                host_pid_ns,
            }),
        )?;

        Ok(CollectorReport::complete(
            CollectorId::CONTAINER_INVENTORY,
            1,
            0,
        ))
    }
}

fn read_path(ctx: &CollectCtx<'_>, path: &str) -> Option<Vec<u8>> {
    ctx.proc.read(path).ok().or_else(|| ctx.fs.read(path).ok())
}

fn path_exists(ctx: &CollectCtx<'_>, path: &str) -> bool {
    ctx.proc.open_exists(path) || ctx.fs.statx(path).is_ok()
}

fn infer_container(dockerenv: bool, cgroup: Option<&[u8]>) -> (bool, Option<String>) {
    if dockerenv {
        return (true, Some(String::from("docker")));
    }
    let Some(data) = cgroup else {
        return (false, None);
    };
    let Ok(s) = core::str::from_utf8(data) else {
        return (false, None);
    };
    let lower = s.to_ascii_lowercase();
    if lower.contains("docker") {
        return (true, Some(String::from("docker")));
    }
    if lower.contains("kubepods") || lower.contains("kube") {
        return (true, Some(String::from("kubernetes")));
    }
    if lower.contains("lxc") || lower.contains("liblxc") {
        return (true, Some(String::from("lxc")));
    }
    if lower.contains("containerd") {
        return (true, Some(String::from("containerd")));
    }
    (false, None)
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
    fn detects_dockerenv() {
        let fx = FixtureProc::new("/tmp/rustmite-fx-cont").with_file(".dockerenv", b"\n");
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
        ContainerInventoryCollector.collect(&ctx, &mut sink).expect("collect");
        assert!(sink.observations.iter().any(|o| matches!(
            o,
            Observation::ContainerInfo(c) if c.in_container && c.runtime.as_deref() == Some("docker")
        )));
    }
}
