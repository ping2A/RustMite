//! `recon.inventory` — basic host recon facts.

use rustmite_proto::{CollectorCost, CollectorId, CollectorReport, Observation, ReconObs};

use crate::{emit, CollectCtx, CollectError, Collector, ObservationSink};

pub struct ReconCollector;

impl Collector for ReconCollector {
    fn id(&self) -> &'static str {
        CollectorId::RECON_INVENTORY.as_str()
    }

    fn cost(&self) -> CollectorCost {
        CollectorCost::Low
    }

    fn collect(
        &self,
        ctx: &CollectCtx<'_>,
        sink: &mut dyn ObservationSink,
    ) -> Result<CollectorReport, CollectError> {
        let mut data = serde_json::Map::new();

        if let Ok(v) = ctx.proc.read("proc/version") {
            let s = String::from_utf8_lossy(&v).trim().to_string();
            data.insert("kernel".into(), serde_json::Value::String(s));
        }
        if let Ok(v) = ctx.proc.read("proc/sys/kernel/osrelease") {
            let s = String::from_utf8_lossy(&v).trim().to_string();
            data.insert("osrelease".into(), serde_json::Value::String(s));
        }
        if let Ok(v) = ctx.proc.read("proc/sys/kernel/hostname") {
            let s = String::from_utf8_lossy(&v).trim().to_string();
            data.insert("hostname".into(), serde_json::Value::String(s));
        }
        // Distro identity from /etc/os-release (agentless path uses host root).
        let os_bytes = ctx
            .fs
            .read("etc/os-release")
            .or_else(|_| ctx.fs.read("/etc/os-release"));
        if let Ok(v) = os_bytes {
            let text = String::from_utf8_lossy(&v);
            let mut pretty = None;
            let mut id = None;
            let mut version = None;
            for line in text.lines() {
                let line = line.trim();
                let Some((k, raw)) = line.split_once('=') else {
                    continue;
                };
                let mut val = raw.trim().to_string();
                if (val.starts_with('"') && val.ends_with('"'))
                    || (val.starts_with('\'') && val.ends_with('\''))
                {
                    val = val[1..val.len() - 1].to_string();
                }
                match k.trim() {
                    "PRETTY_NAME" => pretty = Some(val),
                    "NAME" if pretty.is_none() => pretty = Some(val),
                    "ID" => id = Some(val),
                    "VERSION_ID" => version = Some(val),
                    "VERSION" if version.is_none() => version = Some(val),
                    _ => {}
                }
            }
            if let Some(p) = pretty {
                data.insert("os".into(), serde_json::Value::String(p));
            }
            if let Some(i) = id {
                data.insert("os_id".into(), serde_json::Value::String(i));
            }
            if let Some(ver) = version {
                data.insert("os_version".into(), serde_json::Value::String(ver));
            }
        }
        data.insert(
            "euid".into(),
            serde_json::Value::Number(ctx.euid.into()),
        );

        emit(
            ctx,
            sink,
            Observation::Recon(ReconObs {
                category: String::from("host"),
                data,
            }),
        )?;

        Ok(CollectorReport::complete(
            CollectorId::RECON_INVENTORY,
            1,
            0,
        ))
    }
}
