//! RustMite CLI library helpers (scan-fixture shared with tests).
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use rustmite_checks::{load_manifest, CheckEngine, FindingDraft};
use rustmite_collect::{run_plan, CollectCtx, VecSink};
use rustmite_proto::{Budget, CollectionPlan, CollectorSpec, Limits, Observation};
use rustmite_sys::{parse_proc_stat, FixtureFs, FixtureProc, PidProbeView, ProcSource};
use serde::Deserialize;

#[derive(Debug, Deserialize, Default)]
pub struct FixtureManifest {
    #[serde(default)]
    pub hidden_pids: Vec<i32>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default, alias = "expected_findings")]
    pub expected_checks: Vec<String>,
}

pub struct ScanFixtureResult {
    pub observations: Vec<Observation>,
    pub findings: Vec<FindingDraft>,
    pub fixture_name: String,
    pub expected_checks: Vec<String>,
}

/// Load fixture tree, apply hidden_pids from manifest (or diamorphine heuristic),
/// run collectors + checks.
pub fn scan_fixture(fixture: &Path, checks_dir: &Path) -> Result<ScanFixtureResult> {
    let manifest = read_manifest(fixture)?;
    let mut proc = FixtureProc::from_tree(fixture)
        .with_context(|| format!("load fixture {}", fixture.display()))?;

    // Diamorphine: pid dirs exist on disk so from_tree lists them; hide for decloak.
    let hidden = if !manifest.hidden_pids.is_empty() {
        manifest.hidden_pids.clone()
    } else if fixture
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.contains("diamorphine-hidden-pid"))
    {
        vec![31337]
    } else {
        Vec::new()
    };

    for pid in hidden {
        let starttime = resolve_starttime(&proc, pid).unwrap_or(if pid == 31337 {
            88123
        } else {
            0
        });
        proc = proc.with_hidden_pid(pid, starttime);
    }

    let fs = FixtureFs::from_tree(fixture);
    let limits = Limits::default();
    let budget = Budget::new(&limits, 60_000, 0);
    let ctx = CollectCtx {
        proc: &proc,
        fs: &fs,
        pid_probe: Some(&proc as &dyn PidProbeView),
        budget: &budget,
        euid: 0,
        self_pid: i32::MAX,
        now_ms: 0,
    };

    let plan = CollectionPlan {
        collectors: vec![
            CollectorSpec::new("decloak.process"),
            CollectorSpec::new("process.inventory"),
            CollectorSpec::new("persistence.preload"),
            CollectorSpec::new("persistence.accounts"),
            CollectorSpec::new("modules.lkm"),
            CollectorSpec::new("net.sockets"),
            CollectorSpec::new("recon.inventory"),
            CollectorSpec::new("ssh.keys"),
            CollectorSpec::new("file.integrity"),
            CollectorSpec::new("cred.audit"),
            CollectorSpec::new("log.integrity"),
            CollectorSpec::new("persistence.scheduled"),
            CollectorSpec::new("persistence.services"),
            CollectorSpec::new("dir.hidden"),
            CollectorSpec::new("mounts.inventory"),
            CollectorSpec::new("container.inventory"),
            CollectorSpec::new("modules.ebpf"),
            CollectorSpec::new("session.inventory"),
        ],
        ..Default::default()
    };

    let mut sink = VecSink::new();
    let _reports = run_plan(&plan, &ctx, &mut sink).context("run collectors")?;

    let engine = CheckEngine::from_dir(checks_dir)
        .with_context(|| format!("load checks from {}", checks_dir.display()))?;
    let findings = engine.evaluate(&sink.observations);

    Ok(ScanFixtureResult {
        observations: sink.observations,
        findings,
        fixture_name: manifest
            .name
            .unwrap_or_else(|| fixture.display().to_string()),
        expected_checks: manifest.expected_checks,
    })
}

pub fn validate_check_file(path: &Path) -> Result<()> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;
    let m = load_manifest(&text).context("parse manifest")?;
    // Ensure the where expression compiles.
    let _ = CheckEngine::from_manifests(vec![m]).context("compile where")?;
    Ok(())
}

fn read_manifest(fixture: &Path) -> Result<FixtureManifest> {
    let path = fixture.join("manifest.toml");
    if !path.exists() {
        return Ok(FixtureManifest::default());
    }
    let text = std::fs::read_to_string(&path)?;
    Ok(toml::from_str(&text).unwrap_or_default())
}

fn resolve_starttime(proc: &FixtureProc, pid: i32) -> Option<u64> {
    proc.starttime(pid).or_else(|| {
        let data = proc.read(&format!("proc/{pid}/stat")).ok()?;
        parse_proc_stat(&data).ok().map(|s| s.starttime)
    })
}

/// Resolve checks directory relative to cwd or crate layout.
pub fn default_checks_dir() -> PathBuf {
    let cwd = PathBuf::from("checks");
    if cwd.is_dir() {
        return cwd;
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../checks")
}

/// Exit 1 if diamorphine fixture should have fired RM-PROC-0001 but did not.
pub fn diamorphine_assertion(fixture: &Path, findings: &[FindingDraft]) -> Result<()> {
    let is_diamorphine = fixture
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.contains("diamorphine-hidden-pid"))
        || fixture.display().to_string().contains("diamorphine-hidden-pid");
    if !is_diamorphine {
        return Ok(());
    }
    let fired = findings
        .iter()
        .any(|f| f.check_id.as_str() == "RM-PROC-0001");
    if !fired {
        bail!("RM-PROC-0001 should have fired on diamorphine-hidden-pid fixture but did not");
    }
    Ok(())
}
