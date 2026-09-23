//! `persistence.services` — systemd units under `/etc/systemd/system`.

use rustmite_proto::{CollectorCost, CollectorId, CollectorReport, Observation, PathBytes, ServiceObs};

use crate::{emit, CollectCtx, CollectError, Collector, ObservationSink};

pub struct ServicesCollector;

impl Collector for ServicesCollector {
    fn id(&self) -> &'static str {
        CollectorId::PERSISTENCE_SERVICES.as_str()
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
            .list_dir("etc/systemd/system")
            .or_else(|_| ctx.proc.list_dir_raw("etc/systemd/system"))
        {
            Ok(e) => e,
            Err(_) => {
                return Ok(CollectorReport::unsupported(
                    CollectorId::PERSISTENCE_SERVICES,
                    "etc/systemd/system not available",
                ));
            }
        };

        let mut count = 0u32;
        for ent in entries {
            let fname = ent.name_str();
            if !fname.ends_with(".service") {
                continue;
            }
            let rel = format!("etc/systemd/system/{fname}");
            let Some(data) = read_path(ctx, &rel) else {
                continue;
            };
            let s = String::from_utf8_lossy(&data);
            let (unit_type, exec_start) = parse_systemd_unit(&s);
            emit(
                ctx,
                sink,
                Observation::Service(ServiceObs {
                    name: fname.trim_end_matches(".service").to_string(),
                    path: PathBytes::from_str(&format!("/etc/systemd/system/{fname}")),
                    exec_start,
                    unit_type,
                }),
            )?;
            count = count.saturating_add(1);
        }

        Ok(CollectorReport::complete(
            CollectorId::PERSISTENCE_SERVICES,
            count,
            0,
        ))
    }
}

fn read_path(ctx: &CollectCtx<'_>, path: &str) -> Option<Vec<u8>> {
    ctx.proc.read(path).ok().or_else(|| ctx.fs.read(path).ok())
}

fn parse_systemd_unit(content: &str) -> (String, Option<String>) {
    let mut unit_type = String::from("service");
    let mut exec_start = None;
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(v) = line.strip_prefix("Type=") {
            unit_type = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("ExecStart=") {
            exec_start = Some(v.trim().to_string());
        }
    }
    (unit_type, exec_start)
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
    fn lists_systemd_units() {
        let unit = b"[Service]\nType=simple\nExecStart=/usr/bin/example\n";
        let fx = FixtureProc::new("/tmp/rustmite-fx-svc")
            .with_dir("etc/systemd/system")
            .with_file("etc/systemd/system/example.service", unit);
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
        let report = ServicesCollector.collect(&ctx, &mut sink).expect("collect");
        assert_eq!(report.observations, 1);
        assert!(sink.observations.iter().any(|o| matches!(
            o,
            Observation::Service(s) if s.name == "example"
        )));
    }
}
