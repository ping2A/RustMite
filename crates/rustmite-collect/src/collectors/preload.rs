//! `persistence.preload` — `/etc/ld.so.preload` + suspicious `ld.so.conf*` paths.

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
        let mut count = 0u32;

        // Canonical LD_PRELOAD persistence file.
        count = count.saturating_add(emit_preload_file(
            ctx,
            sink,
            "etc/ld.so.preload",
            "/etc/ld.so.preload",
        )?);

        // Extra library search paths (hijack vector).
        let mut conf_paths: Vec<(String, String)> = Vec::new();
        if read_path(ctx, "etc/ld.so.conf").is_some() {
            conf_paths.push((
                "etc/ld.so.conf".into(),
                "/etc/ld.so.conf".into(),
            ));
        }
        if let Ok(ents) = ctx
            .fs
            .list_dir("etc/ld.so.conf.d")
            .or_else(|_| ctx.proc.list_dir_raw("etc/ld.so.conf.d"))
        {
            for ent in ents {
                let name = ent.name_str();
                if name == "." || name == ".." || !name.ends_with(".conf") {
                    continue;
                }
                let rel = format!("etc/ld.so.conf.d/{name}");
                let wire = format!("/etc/ld.so.conf.d/{name}");
                conf_paths.push((rel, wire));
            }
        }
        for (rel, wire) in conf_paths {
            count = count.saturating_add(emit_preload_file(ctx, sink, &rel, &wire)?);
        }

        Ok(CollectorReport::complete(
            CollectorId::PERSISTENCE_PRELOAD,
            count.max(1),
            0,
        ))
    }
}

fn emit_preload_file(
    ctx: &CollectCtx<'_>,
    sink: &mut dyn ObservationSink,
    rel: &str,
    wire: &str,
) -> Result<u32, CollectError> {
    let (present, entries) = match read_path(ctx, rel) {
        Some(data) => {
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
        None => (false, Vec::new()),
    };
    // Only emit absent ld.so.preload (canonical probe); skip absent conf fragments.
    if !present && rel != "etc/ld.so.preload" {
        return Ok(0);
    }
    emit(
        ctx,
        sink,
        Observation::Preload(PreloadObs {
            path: PathBytes::from_str(wire),
            entries,
            present,
        }),
    )?;
    Ok(1)
}

fn read_path(ctx: &CollectCtx<'_>, path: &str) -> Option<Vec<u8>> {
    ctx.proc.read(path).ok().or_else(|| ctx.fs.read(path).ok())
}
