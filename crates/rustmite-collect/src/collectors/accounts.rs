//! `persistence.accounts` — parse `/etc/passwd`.

use rustmite_analyze::parse_passwd;
use rustmite_proto::{AccountObs, CollectorCost, CollectorId, CollectorReport, Observation, PathBytes};

use crate::{emit, CollectCtx, CollectError, Collector, ObservationSink};

pub struct AccountsCollector;

impl Collector for AccountsCollector {
    fn id(&self) -> &'static str {
        CollectorId::PERSISTENCE_ACCOUNTS.as_str()
    }

    fn cost(&self) -> CollectorCost {
        CollectorCost::Low
    }

    fn collect(
        &self,
        ctx: &CollectCtx<'_>,
        sink: &mut dyn ObservationSink,
    ) -> Result<CollectorReport, CollectError> {
        let data = match ctx.proc.read("etc/passwd").or_else(|_| ctx.fs.read("etc/passwd")) {
            Ok(d) => d,
            Err(_) => {
                return Ok(CollectorReport::unsupported(
                    CollectorId::PERSISTENCE_ACCOUNTS,
                    "etc/passwd unreadable",
                ));
            }
        };
        let s = String::from_utf8_lossy(&data);
        let mut count = 0u32;
        for e in parse_passwd(&s) {
            emit(
                ctx,
                sink,
                Observation::Account(AccountObs {
                    username: e.username,
                    uid: e.uid,
                    gid: e.gid,
                    home: PathBytes::from(e.home),
                    shell: PathBytes::from(e.shell),
                    gecos: e.gecos,
                }),
            )?;
            count = count.saturating_add(1);
        }
        Ok(CollectorReport::complete(
            CollectorId::PERSISTENCE_ACCOUNTS,
            count,
            0,
        ))
    }
}
