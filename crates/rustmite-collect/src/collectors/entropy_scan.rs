//! `entropy` / `file.elf` — entropy + ELF analysis of suspicious paths.

use rustmite_analyze::{analyze_elf, shannon_entropy, sliding_window_max, sha256_hex};
use rustmite_proto::{
    BigInt, CollectorCost, CollectorId, CollectorReport, ElfInfoObs, FileEntropyObs, Observation,
    PathBytes,
};

use crate::{emit, CollectCtx, CollectError, Collector, ObservationSink};

pub struct EntropyScanCollector;

const DEFAULT_PATHS: &[&str] = &[
    "tmp/suspicious",
    "tmp/sample",
    "tmp/x",
    "dev/shm/x",
    "var/tmp/x",
];

impl Collector for EntropyScanCollector {
    fn id(&self) -> &'static str {
        CollectorId::ENTROPY.as_str()
    }

    fn cost(&self) -> CollectorCost {
        CollectorCost::High
    }

    fn collect(
        &self,
        ctx: &CollectCtx<'_>,
        sink: &mut dyn ObservationSink,
    ) -> Result<CollectorReport, CollectError> {
        let mut count = 0u32;
        for path in DEFAULT_PATHS {
            match scan_path(ctx, sink, path) {
                Ok(n) => count = count.saturating_add(n),
                Err(CollectError::Errno(_)) => continue,
                Err(e) => return Err(e),
            }
        }
        // Also scan any tmp files present under fixture listing if readable via proc-as-root overlay.
        if let Ok(ents) = ctx.proc.list_dir_raw("tmp") {
            for e in ents {
                if e.is_dot_or_dotdot() {
                    continue;
                }
                let name = e.name_str();
                let path = format!("tmp/{name}");
                if DEFAULT_PATHS.contains(&path.as_str()) {
                    continue;
                }
                match scan_path(ctx, sink, &path) {
                    Ok(n) => count = count.saturating_add(n),
                    Err(CollectError::Errno(_)) => continue,
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(CollectorReport::complete(CollectorId::ENTROPY, count, 0))
    }
}

fn scan_path(
    ctx: &CollectCtx<'_>,
    sink: &mut dyn ObservationSink,
    path: &str,
) -> Result<u32, CollectError> {
    let data = match ctx.proc.read(path) {
        Ok(d) => d,
        Err(_) => ctx.fs.read(path)?,
    };
    let entropy = shannon_entropy(&data);
    let (window_max, window_offset) = sliding_window_max(&data, 256);
    let elf = analyze_elf(&data);
    let hash = sha256_hex(&data);

    let mut n = 0u32;
    emit(
        ctx,
        sink,
        Observation::FileEntropy(FileEntropyObs {
            path: PathBytes::from_str(path),
            entropy,
            window_max: Some(window_max),
            window_offset: Some(window_offset as u64),
            size: BigInt::from_u64(data.len() as u64),
            is_elf: elf.is_elf,
            sha256: Some(hash),
        }),
    )?;
    n = n.saturating_add(1);

    if elf.is_elf {
        emit(
            ctx,
            sink,
            Observation::ElfInfo(ElfInfoObs {
                path: PathBytes::from_str(path),
                machine: elf.machine,
                is_static: elf.is_static,
                stripped: elf.stripped,
                interp: elf.interp.map(PathBytes::from),
                section_count: elf.section_count,
                has_rwx_segment: elf.has_rwx_segment,
                packer_hints: elf.packer_hints,
                entry: BigInt::from_u64(elf.entry),
            }),
        )?;
        n = n.saturating_add(1);
    }
    Ok(n)
}
