//! `log.integrity` — utmp/wtmp tampering signals.

use rustmite_analyze::{parse_utmp, UTMP_RECORD_SIZE};
use rustmite_proto::{
    CollectorCost, CollectorId, CollectorReport, LogIntegrityObs, Observation, PathBytes,
};

use crate::{emit, CollectCtx, CollectError, Collector, ObservationSink};

const LOG_PATHS: &[(&str, &str)] = &[
    ("var/run/utmp", "/var/run/utmp"),
    ("var/log/wtmp", "/var/log/wtmp"),
    ("var/log/btmp", "/var/log/btmp"),
];

pub struct LogIntegrityCollector;

impl Collector for LogIntegrityCollector {
    fn id(&self) -> &'static str {
        CollectorId::LOG_INTEGRITY.as_str()
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

        for (rel, wire) in LOG_PATHS {
            let Some(data) = read_path(ctx, rel) else {
                continue;
            };
            saw_any = true;
            for issue in scan_utmp_integrity(&data) {
                emit(
                    ctx,
                    sink,
                    Observation::LogIntegrity(LogIntegrityObs {
                        path: PathBytes::from_str(wire),
                        issue: issue.0,
                        detail: issue.1,
                    }),
                )?;
                count = count.saturating_add(1);
            }
        }

        if !saw_any {
            return Ok(CollectorReport::unsupported(
                CollectorId::LOG_INTEGRITY,
                "utmp/wtmp/btmp not readable",
            ));
        }

        Ok(CollectorReport::complete(CollectorId::LOG_INTEGRITY, count, 0))
    }
}

fn read_path(ctx: &CollectCtx<'_>, path: &str) -> Option<Vec<u8>> {
    ctx.proc.read(path).ok().or_else(|| ctx.fs.read(path).ok())
}

fn scan_utmp_integrity(data: &[u8]) -> Vec<(String, String)> {
    let mut issues = Vec::new();
    if data.is_empty() {
        return issues;
    }
    if !data.len().is_multiple_of(UTMP_RECORD_SIZE) {
        issues.push((
            String::from("truncated"),
            format!("size {} not a multiple of {}", data.len(), UTMP_RECORD_SIZE),
        ));
    }
    if data.iter().all(|&b| b == 0) {
        issues.push((
            String::from("zeroed"),
            String::from("file is all zero bytes"),
        ));
    }
    if let Ok(records) = parse_utmp(data) {
        let mut prev_time = 0u64;
        let mut out_of_order = false;
        for rec in &records {
            if rec.time > 0 && rec.time < prev_time {
                out_of_order = true;
            }
            if rec.time > 0 {
                prev_time = rec.time;
            }
        }
        if out_of_order {
            issues.push((
                String::from("out_of_order"),
                String::from("utmp records not in chronological order"),
            ));
        }
    }
    issues
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

    fn synthetic_utmp_record() -> Vec<u8> {
        let mut rec = vec![0u8; UTMP_RECORD_SIZE];
        if let Some(b) = rec.get_mut(0..2) {
            b.copy_from_slice(&7i16.to_ne_bytes());
        }
        if let Some(b) = rec.get_mut(44..48) {
            b.copy_from_slice(b"root");
        }
        rec
    }

    #[test]
    fn detects_truncated_utmp() {
        let mut data = synthetic_utmp_record();
        data.truncate(UTMP_RECORD_SIZE / 2);
        let fx = FixtureProc::new("/tmp/rustmite-fx-log").with_file("var/run/utmp", data);
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
        let report = LogIntegrityCollector.collect(&ctx, &mut sink).expect("collect");
        assert!(report.observations >= 1);
        assert!(sink.observations.iter().any(|o| matches!(
            o,
            Observation::LogIntegrity(l) if l.issue == "truncated"
        )));
    }
}
