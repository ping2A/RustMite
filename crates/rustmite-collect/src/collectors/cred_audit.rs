//! `cred.audit` — `/etc/shadow` posture (algorithm + fingerprint only; raw hash zeroized).

use rustmite_analyze::parse_shadow;
use rustmite_proto::{CollectorCost, CollectorId, CollectorReport, Observation, ShadowEntryObs};
use zeroize::Zeroizing;

use crate::{emit, CollectCtx, CollectError, Collector, ObservationSink};

pub struct CredAuditCollector;

impl Collector for CredAuditCollector {
    fn id(&self) -> &'static str {
        CollectorId::CRED_AUDIT.as_str()
    }

    fn cost(&self) -> CollectorCost {
        CollectorCost::Low
    }

    fn collect(
        &self,
        ctx: &CollectCtx<'_>,
        sink: &mut dyn ObservationSink,
    ) -> Result<CollectorReport, CollectError> {
        // Root-only on live hosts; fixtures may still expose shadow for tests.
        if ctx.euid != 0 {
            return Ok(CollectorReport::unsupported(
                CollectorId::CRED_AUDIT,
                "shadow audit requires euid 0",
            ));
        }

        let raw = match ctx
            .proc
            .read("etc/shadow")
            .or_else(|_| ctx.fs.read("etc/shadow"))
        {
            Ok(d) => Zeroizing::new(d),
            Err(_) => {
                return Ok(CollectorReport::unsupported(
                    CollectorId::CRED_AUDIT,
                    "etc/shadow unreadable",
                ));
            }
        };

        let s = String::from_utf8_lossy(&raw);
        let mut count = 0u32;
        for e in parse_shadow(&s) {
            emit(
                ctx,
                sink,
                Observation::ShadowEntry(ShadowEntryObs {
                    username: e.username,
                    algorithm: e.algorithm,
                    empty_password: e.empty,
                    locked: e.locked,
                    hash_fingerprint: e.hash_fingerprint,
                }),
            )?;
            count = count.saturating_add(1);
        }
        // `raw` drops here and zeroizes.
        Ok(CollectorReport::complete(CollectorId::CRED_AUDIT, count, 0))
    }
}

#[cfg(test)]
mod tests {
    use rustmite_proto::{Budget, Limits, Observation};
    use rustmite_sys::{FixtureFs, FixtureProc};

    use super::*;
    use crate::{CollectCtx, VecSink};

    #[test]
    fn emits_algorithm_not_raw_hash() {
        let shadow = "root:$6$rounds=5000$salt$hashrest:19000:0:99999:7:::\n\
                      guest::19000:0:99999:7:::\n\
                      nobody:*:19000:0:99999:7:::\n\
                      weak:$1$salt$hash:1:0:99999:7:::\n";
        let fs = FixtureFs::new().with_file("etc/shadow", shadow);
        let proc = FixtureProc::new("/tmp/rustmite-cred-audit");
        let b = Budget::new(&Limits::default(), 60_000, 0);
        let ctx = CollectCtx {
            proc: &proc,
            fs: &fs,
            pid_probe: None,
            budget: &b,
            euid: 0,
            self_pid: 1,
            now_ms: 0,
        };
        let mut sink = VecSink::new();
        let report = CredAuditCollector.collect(&ctx, &mut sink).expect("collect");
        assert_eq!(report.observations, 4);
        let weak = sink
            .observations
            .iter()
            .find_map(|o| match o {
                Observation::ShadowEntry(s) if s.username == "weak" => Some(s),
                _ => None,
            })
            .expect("weak");
        assert_eq!(weak.algorithm, "md5crypt");
        assert!(weak.hash_fingerprint.is_some());
        // Ensure raw hash material never appears in observation fields.
        let json = serde_json::to_string(&sink.observations).expect("json");
        assert!(!json.contains("$1$salt$hash"));
        assert!(!json.contains("$6$rounds=5000$salt$hashrest"));
    }

    #[test]
    fn non_root_unsupported() {
        let fs = FixtureFs::new().with_file("etc/shadow", "root:!:1:0:99999:7:::\n");
        let proc = FixtureProc::new("/tmp/rustmite-cred-audit-noroot");
        let b = Budget::new(&Limits::default(), 60_000, 0);
        let ctx = CollectCtx {
            proc: &proc,
            fs: &fs,
            pid_probe: None,
            budget: &b,
            euid: 1000,
            self_pid: 1,
            now_ms: 0,
        };
        let mut sink = VecSink::new();
        let report = CredAuditCollector.collect(&ctx, &mut sink).expect("collect");
        assert_eq!(report.status, rustmite_proto::CollectorStatus::Unsupported);
    }
}
