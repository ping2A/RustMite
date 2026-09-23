//! `session.inventory` — active sessions from utmp.

use rustmite_analyze::parse_utmp;
use rustmite_proto::{
    CollectorCost, CollectorId, CollectorReport, Observation, UtmpSessionObs,
};

use crate::{emit, CollectCtx, CollectError, Collector, ObservationSink};

/// `USER_PROCESS` and `LOGIN_PROCESS` in utmp.
const ACTIVE_UTMP_TYPES: &[u16] = &[7, 6];

pub struct SessionInventoryCollector;

impl Collector for SessionInventoryCollector {
    fn id(&self) -> &'static str {
        CollectorId::SESSION_INVENTORY.as_str()
    }

    fn cost(&self) -> CollectorCost {
        CollectorCost::Low
    }

    fn collect(
        &self,
        ctx: &CollectCtx<'_>,
        sink: &mut dyn ObservationSink,
    ) -> Result<CollectorReport, CollectError> {
        let Some(data) = read_path(ctx, "var/run/utmp") else {
            return Ok(CollectorReport::unsupported(
                CollectorId::SESSION_INVENTORY,
                "var/run/utmp unreadable",
            ));
        };

        let records = match parse_utmp(&data) {
            Ok(r) => r,
            Err(_) => {
                return Ok(CollectorReport::unsupported(
                    CollectorId::SESSION_INVENTORY,
                    "utmp parse failed",
                ));
            }
        };

        let mut count = 0u32;
        for rec in records {
            if !ACTIVE_UTMP_TYPES.contains(&rec.ut_type) || rec.user.is_empty() {
                continue;
            }
            emit(
                ctx,
                sink,
                Observation::UtmpSession(UtmpSessionObs {
                    user: rec.user,
                    line: rec.line,
                    host: rec.host,
                    pid: rec.pid,
                    typ: rec.ut_type,
                    time: rec.time,
                }),
            )?;
            count = count.saturating_add(1);
        }

        Ok(CollectorReport::complete(
            CollectorId::SESSION_INVENTORY,
            count,
            0,
        ))
    }
}

fn read_path(ctx: &CollectCtx<'_>, path: &str) -> Option<Vec<u8>> {
    ctx.proc.read(path).ok().or_else(|| ctx.fs.read(path).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmite_analyze::UTMP_RECORD_SIZE;
    use rustmite_proto::{Budget, Limits, Observation};
    use rustmite_sys::{FixtureFs, FixtureProc};
    use crate::VecSink;

    fn budget() -> Budget {
        Budget::new(&Limits::default(), 60_000, 0)
    }

    #[test]
    fn emits_active_session() {
        let mut rec = vec![0u8; UTMP_RECORD_SIZE];
        if let Some(b) = rec.get_mut(0..2) {
            b.copy_from_slice(&7i16.to_ne_bytes());
        }
        if let Some(b) = rec.get_mut(4..8) {
            b.copy_from_slice(&100i32.to_ne_bytes());
        }
        if let Some(b) = rec.get_mut(44..49) {
            b[..5].copy_from_slice(b"alice");
        }
        let fx = FixtureProc::new("/tmp/rustmite-fx-sess").with_file("var/run/utmp", rec);
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
        let report = SessionInventoryCollector.collect(&ctx, &mut sink).expect("collect");
        assert_eq!(report.observations, 1);
        assert!(sink.observations.iter().any(|o| matches!(
            o,
            Observation::UtmpSession(u) if u.user == "alice"
        )));
    }
}
