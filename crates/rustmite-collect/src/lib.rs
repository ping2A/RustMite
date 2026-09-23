//! Collectors — detection data sources over `ProcSource` / `FsSource`.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

pub mod error;
pub mod sink;
pub mod registry;
pub mod collectors;

#[cfg(test)]
mod tests_integration;

pub use error::CollectError;
pub use sink::{NdjsonSink, ObservationSink, VecSink};
pub use registry::{lookup, run_plan};

use rustmite_proto::{Budget, CollectorCost, CollectorReport, Observation};
use rustmite_sys::{FsSource, PidProbeView, ProcSource};

/// Shared collection context.
pub struct CollectCtx<'a> {
    pub proc: &'a dyn ProcSource,
    pub fs: &'a dyn FsSource,
    pub pid_probe: Option<&'a dyn PidProbeView>,
    pub budget: &'a Budget,
    pub euid: u32,
    pub self_pid: i32,
    pub now_ms: u64,
}

/// Uniform collector interface.
pub trait Collector: Send + Sync {
    fn id(&self) -> &'static str;
    fn cost(&self) -> CollectorCost;
    fn collect(
        &self,
        ctx: &CollectCtx<'_>,
        sink: &mut dyn ObservationSink,
    ) -> Result<CollectorReport, CollectError>;
}

/// Emit one observation, respecting budget.
pub(crate) fn emit(
    ctx: &CollectCtx<'_>,
    sink: &mut dyn ObservationSink,
    obs: Observation,
) -> Result<(), CollectError> {
    // Deterministic path for fixtures (start_ms typically 0).
    ctx.budget.check(ctx.now_ms)?;
    // Live probe: start_ms is unix epoch ms → also enforce wall-clock deadline.
    if ctx.budget.start_ms >= 1_000_000_000_000 {
        ctx.budget.check_wall()?;
    }
    sink.emit(obs)?;
    ctx.budget.record_observation();
    Ok(())
}
