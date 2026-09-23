//! `file.integrity` — verify critical binaries against dpkg md5sums.

use rustmite_analyze::{
    is_critical_package_path, md5_hex, package_name_from_md5sums_filename, parse_md5sums,
};
use rustmite_proto::{
    CollectorCost, CollectorId, CollectorReport, IntegrityObs, Observation, PathBytes,
};

use crate::{emit, CollectCtx, CollectError, Collector, ObservationSink};

/// Paths relative to fixture/fs root that hold dpkg md5sums files.
const DPKG_INFO_DIR: &str = "var/lib/dpkg/info";

pub struct FileIntegrityCollector;

impl Collector for FileIntegrityCollector {
    fn id(&self) -> &'static str {
        CollectorId::FILE_INTEGRITY.as_str()
    }

    fn cost(&self) -> CollectorCost {
        CollectorCost::Medium
    }

    fn collect(
        &self,
        ctx: &CollectCtx<'_>,
        sink: &mut dyn ObservationSink,
    ) -> Result<CollectorReport, CollectError> {
        let entries = match ctx.fs.list_dir(DPKG_INFO_DIR) {
            Ok(e) => e,
            Err(_) => {
                return Ok(CollectorReport::unsupported(
                    CollectorId::FILE_INTEGRITY,
                    "dpkg info directory unreadable (rpm unsupported)",
                ));
            }
        };

        let mut count = 0u32;
        let mut saw_md5sums = false;
        for ent in entries {
            let name = match String::from_utf8(ent.name) {
                Ok(n) => n,
                Err(_) => continue,
            };
            if !name.ends_with(".md5sums") {
                continue;
            }
            saw_md5sums = true;
            let package = package_name_from_md5sums_filename(&name);
            let rel = format!("{DPKG_INFO_DIR}/{name}");
            let data = match ctx.fs.read(&rel) {
                Ok(d) => d,
                Err(_) => continue,
            };
            let body = String::from_utf8_lossy(&data);
            for entry in parse_md5sums(&body) {
                if !is_critical_package_path(&entry.path) {
                    continue;
                }
                let file_rel = entry.path.trim_start_matches('/').to_string();
                let file_data = match ctx.fs.read(&file_rel) {
                    Ok(d) => d,
                    Err(_) => continue,
                };
                let actual = md5_hex(&file_data);
                if actual.eq_ignore_ascii_case(&entry.md5_hex) {
                    continue;
                }
                let display = format!("/{}", file_rel.trim_start_matches('/'));
                emit(
                    ctx,
                    sink,
                    Observation::IntegrityMismatch(IntegrityObs {
                        path: PathBytes::from(display),
                        expected_hash: entry.md5_hex,
                        actual_hash: actual,
                        package: package.clone(),
                    }),
                )?;
                count = count.saturating_add(1);
            }
        }

        if !saw_md5sums {
            return Ok(CollectorReport::unsupported(
                CollectorId::FILE_INTEGRITY,
                "no dpkg md5sums present",
            ));
        }

        Ok(CollectorReport::complete(
            CollectorId::FILE_INTEGRITY,
            count,
            0,
        ))
    }
}

#[cfg(test)]
mod tests {
    use rustmite_analyze::md5_hex;
    use rustmite_proto::{Budget, Limits, Observation};
    use rustmite_sys::{FixtureFs, FixtureProc};

    use super::*;
    use crate::{CollectCtx, VecSink};

    #[test]
    fn detects_trojaned_ls() {
        let good = b"legit-ls\n";
        let evil = b"evil-ls\n";
        let expected = md5_hex(good);
        let md5sums = format!("{expected}  bin/ls\n");
        let fs = FixtureFs::new()
            .with_file("bin/ls", evil.as_slice())
            .with_file("var/lib/dpkg/info/coreutils.md5sums", md5sums);
        let proc = FixtureProc::new("/tmp/rustmite-integrity-test");
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
        let report = FileIntegrityCollector
            .collect(&ctx, &mut sink)
            .expect("collect");
        assert_eq!(report.observations, 1);
        assert!(matches!(
            &sink.observations[0],
            Observation::IntegrityMismatch(i)
                if i.path.to_string_lossy().contains("bin/ls")
                    && i.package.as_deref() == Some("coreutils")
                    && i.expected_hash != i.actual_hash
        ));
    }

    #[test]
    fn matching_hash_silent() {
        let good = b"legit-ls\n";
        let expected = md5_hex(good);
        let md5sums = format!("{expected}  bin/ls\n");
        let fs = FixtureFs::new()
            .with_file("bin/ls", good.as_slice())
            .with_file("var/lib/dpkg/info/coreutils.md5sums", md5sums);
        let proc = FixtureProc::new("/tmp/rustmite-integrity-ok");
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
        let report = FileIntegrityCollector
            .collect(&ctx, &mut sink)
            .expect("collect");
        assert_eq!(report.observations, 0);
        assert!(sink.observations.is_empty());
    }

    #[test]
    fn fixture_trojaned_ls_fires_integrity_mismatch() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/trojaned-ls");
        if !root.is_dir() {
            return;
        }
        let fs = FixtureFs::from_tree(&root);
        let proc = FixtureProc::new("/tmp/rustmite-trojaned-ls");
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
        let report = FileIntegrityCollector
            .collect(&ctx, &mut sink)
            .expect("collect");
        assert_eq!(report.observations, 1);
        assert!(sink.observations.iter().any(|o| matches!(
            o,
            Observation::IntegrityMismatch(i)
                if i.path.to_string_lossy().ends_with("/bin/ls")
                    && i.package.as_deref() == Some("coreutils")
        )));
    }
}
