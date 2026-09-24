//! `persistence.services` — systemd units, profile hooks, and sudoers rules.

use rustmite_proto::{
    CollectorCost, CollectorId, CollectorReport, Observation, PathBytes, ServiceObs, SudoRuleObs,
};

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
        let mut count = 0u32;
        count = count.saturating_add(emit_systemd(ctx, sink)?);
        count = count.saturating_add(emit_profile_hooks(ctx, sink)?);
        count = count.saturating_add(emit_sudoers(ctx, sink)?);
        if count == 0 {
            return Ok(CollectorReport::unsupported(
                CollectorId::PERSISTENCE_SERVICES,
                "no systemd/profile/sudoers content",
            ));
        }
        Ok(CollectorReport::complete(
            CollectorId::PERSISTENCE_SERVICES,
            count,
            0,
        ))
    }
}

fn emit_systemd(
    ctx: &CollectCtx<'_>,
    sink: &mut dyn ObservationSink,
) -> Result<u32, CollectError> {
    let entries = match ctx
        .fs
        .list_dir("etc/systemd/system")
        .or_else(|_| ctx.proc.list_dir_raw("etc/systemd/system"))
    {
        Ok(e) => e,
        Err(_) => return Ok(0),
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
    Ok(count)
}

fn emit_profile_hooks(
    ctx: &CollectCtx<'_>,
    sink: &mut dyn ObservationSink,
) -> Result<u32, CollectError> {
    let mut count = 0u32;
    let paths = [
        ("etc/profile.d", "/etc/profile.d"),
        ("etc/bash.bashrc", "/etc/bash.bashrc"),
        ("etc/profile", "/etc/profile"),
    ];
    for (rel, wire_prefix) in paths {
        if rel.ends_with(".d") {
            let Ok(ents) = ctx
                .fs
                .list_dir(rel)
                .or_else(|_| ctx.proc.list_dir_raw(rel))
            else {
                continue;
            };
            for ent in ents {
                let name = ent.name_str();
                if name == "." || name == ".." {
                    continue;
                }
                let child = format!("{rel}/{name}");
                let Some(data) = read_path(ctx, &child) else {
                    continue;
                };
                let body = String::from_utf8_lossy(&data);
                emit(
                    ctx,
                    sink,
                    Observation::Service(ServiceObs {
                        name: name.to_string(),
                        path: PathBytes::from_str(&format!("{wire_prefix}/{name}")),
                        exec_start: Some(body.trim().to_string()),
                        unit_type: String::from("script"),
                    }),
                )?;
                count = count.saturating_add(1);
            }
        } else if let Some(data) = read_path(ctx, rel) {
            let body = String::from_utf8_lossy(&data);
            emit(
                ctx,
                sink,
                Observation::Service(ServiceObs {
                    name: rel.rsplit('/').next().unwrap_or(rel).to_string(),
                    path: PathBytes::from_str(wire_prefix),
                    exec_start: Some(body.trim().to_string()),
                    unit_type: String::from("script"),
                }),
            )?;
            count = count.saturating_add(1);
        }
    }
    Ok(count)
}

fn emit_sudoers(
    ctx: &CollectCtx<'_>,
    sink: &mut dyn ObservationSink,
) -> Result<u32, CollectError> {
    let mut count = 0u32;
    let mut files = vec![("etc/sudoers".into(), "/etc/sudoers".into())];
    if let Ok(ents) = ctx
        .fs
        .list_dir("etc/sudoers.d")
        .or_else(|_| ctx.proc.list_dir_raw("etc/sudoers.d"))
    {
        for ent in ents {
            let name = ent.name_str();
            if name == "." || name == ".." {
                continue;
            }
            files.push((
                format!("etc/sudoers.d/{name}"),
                format!("/etc/sudoers.d/{name}"),
            ));
        }
    }
    for (rel, wire) in files {
        let Some(data) = read_path(ctx, &rel) else {
            continue;
        };
        let s = String::from_utf8_lossy(&data);
        for raw in s.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let upper = line.to_ascii_uppercase();
            let nopasswd = upper.contains("NOPASSWD");
            let all_commands = upper.contains(" ALL") && upper.contains(":ALL");
            let interesting = nopasswd
                || all_commands
                || upper.contains("!AUTHENTICATE")
                || upper.contains("SETENV");
            if !interesting {
                continue;
            }
            emit(
                ctx,
                sink,
                Observation::SudoRule(SudoRuleObs {
                    path: PathBytes::from_str(&wire),
                    line: line.to_string(),
                    nopasswd,
                    all_commands,
                }),
            )?;
            count = count.saturating_add(1);
        }
    }
    Ok(count)
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
        assert!(report.observations >= 1);
        assert!(sink.observations.iter().any(|o| matches!(
            o,
            Observation::Service(s) if s.name == "example"
        )));
    }

    #[test]
    fn emits_nopasswd_sudo() {
        let fx = FixtureProc::new("/tmp/rustmite-fx-sudo")
            .with_file("etc/sudoers", b"bob ALL=(ALL) NOPASSWD:ALL\n");
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
        ServicesCollector.collect(&ctx, &mut sink).expect("collect");
        assert!(sink.observations.iter().any(|o| matches!(
            o,
            Observation::SudoRule(r) if r.nopasswd && r.all_commands
        )));
    }
}
