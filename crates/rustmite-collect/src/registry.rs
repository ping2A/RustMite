//! Collector registry and plan runner.

use rustmite_proto::{CollectionPlan, CollectorReport, CollectorStatus};

use crate::collectors::{
    AccountsCollector, ContainerInventoryCollector, CredAuditCollector, DecloakProcessCollector,
    DirHiddenCollector, EntropyScanCollector, FileIntegrityCollector, FileIocCollector,
    LogIntegrityCollector, ModulesEbpfCollector, ModulesLkmCollector, MountsInventoryCollector,
    PreloadCollector, ProcessInventoryCollector, ReconCollector, ScheduledCollector,
    ServicesCollector, SessionInventoryCollector, SocketsCollector, SshKeysCollector,
};
use crate::{CollectCtx, CollectError, Collector, ObservationSink};

pub fn all_collectors() -> Vec<Box<dyn Collector>> {
    vec![
        Box::new(DecloakProcessCollector),
        Box::new(ProcessInventoryCollector),
        Box::new(ModulesLkmCollector),
        Box::new(SocketsCollector),
        Box::new(PreloadCollector),
        Box::new(AccountsCollector),
        Box::new(EntropyScanCollector),
        Box::new(ReconCollector),
        Box::new(ScheduledCollector),
        Box::new(ServicesCollector),
        Box::new(LogIntegrityCollector),
        Box::new(SessionInventoryCollector),
        Box::new(ContainerInventoryCollector),
        Box::new(MountsInventoryCollector),
        Box::new(ModulesEbpfCollector),
        Box::new(DirHiddenCollector),
        Box::new(SshKeysCollector),
        Box::new(FileIntegrityCollector),
        Box::new(FileIocCollector),
        Box::new(CredAuditCollector),
    ]
}

pub fn lookup(id: &str) -> Option<Box<dyn Collector>> {
    all_collectors().into_iter().find(|c| c.id() == id)
}

pub fn run_plan(
    plan: &CollectionPlan,
    ctx: &CollectCtx<'_>,
    sink: &mut dyn ObservationSink,
) -> Result<Vec<CollectorReport>, CollectError> {
    let mut reports = Vec::new();
    let ids: Vec<String> = if plan.collectors.is_empty() {
        all_collectors()
            .iter()
            .map(|c| c.id().to_string())
            .collect()
    } else {
        plan.collectors.iter().map(|c| c.id.clone()).collect()
    };

    for id in ids {
        let Some(col) = lookup(&id) else {
            reports.push(CollectorReport {
                id: id.clone(),
                status: CollectorStatus::Unsupported,
                reason: Some("unknown collector".into()),
                observations: 0,
                elapsed_ms: 0,
            });
            continue;
        };
        match col.collect(ctx, sink) {
            Ok(r) => reports.push(r),
            Err(CollectError::Budget(kind)) => {
                reports.push(CollectorReport {
                    id,
                    status: CollectorStatus::Truncated,
                    reason: Some(kind.to_string()),
                    observations: 0,
                    elapsed_ms: 0,
                });
                break;
            }
            Err(e) => {
                reports.push(CollectorReport {
                    id,
                    status: CollectorStatus::Failed,
                    reason: Some(e.to_string()),
                    observations: 0,
                    elapsed_ms: 0,
                });
            }
        }
    }
    Ok(reports)
}
