//! `persistence.preload` — `/etc/ld.so.preload`.

use rustmite_proto::{CollectorCost, CollectorId, CollectorReport, Observation, PathBytes, PreloadObs};

use crate::{emit, CollectCtx, CollectError, Collector, ObservationSink};

pub struct PreloadCollector;

impl Collector for PreloadCollector {
    fn id(&self) -> &'static str {
        CollectorId::PERSISTENCE_PRELOAD.as_str()
    }

    fn cost(&self) -> CollectorCost {
        CollectorCost::Trivial
    }

    fn collect(
        &self,
        ctx: &CollectCtx<'_>,
        sink: &mut dyn ObservationSink,
    ) -> Result<CollectorReport, CollectError> {
        let path = "etc/ld.so.preload";
        let (present, entries) = match ctx.proc.read(path).or_else(|_| ctx.fs.read(path)) {
            Ok(data) => {
                let s = String::from_utf8_lossy(&data);
                let entries = s
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .flat_map(|l| l.split_whitespace())
                    .map(PathBytes::from_str)
                    .collect();
                (true, entries)
            }
            Err(_) => (false, Vec::new()),
        };

        emit(
            ctx,
            sink,
            Observation::Preload(PreloadObs {
                path: PathBytes::from_str("/etc/ld.so.preload"),
                entries,
                present,
            }),
        )?;

        Ok(CollectorReport::complete(
            CollectorId::PERSISTENCE_PRELOAD,
            1,
            0,
        ))
    }
}
