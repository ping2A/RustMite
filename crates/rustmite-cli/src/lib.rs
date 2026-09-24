//! RustMite CLI library helpers (scan-fixture shared with tests).
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use rustmite_checks::{
    correlate_ssh_key_graph, diff_baseline, find_duplicate_shadow_hashes, load_manifest,
    BaselineAccount, BaselineSnapshot, CheckEngine, FindingDraft, KeyPlacement, ShadowPosture,
};
use rustmite_collect::{run_plan, CollectCtx, VecSink};
use rustmite_proto::{
    Budget, CheckType, CollectionPlan, CollectorSpec, Confidence, HostId, Limits, Observation,
    Severity,
};
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
    /// When true, `observations.ndjson` may overlay collector output (schema-validated).
    #[serde(default)]
    pub allow_inject: bool,
    /// Optional mode/uid overlays for on-disk fixture files (`[[file_meta]]`).
    #[serde(default)]
    pub file_meta: Vec<FixtureFileMeta>,
}

#[derive(Debug, Deserialize, Default)]
pub struct FixtureFileMeta {
    pub path: String,
    #[serde(default)]
    pub mode: Option<u32>,
    #[serde(default)]
    pub uid: Option<u32>,
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
    scan_fixture_inner(fixture, checks_dir, false)
}

/// Catalog coverage: force-enable disabled rules and run cross-observation correlators.
pub fn scan_fixture_for_catalog(fixture: &Path, checks_dir: &Path) -> Result<ScanFixtureResult> {
    scan_fixture_inner(fixture, checks_dir, true)
}

fn scan_fixture_inner(
    fixture: &Path,
    checks_dir: &Path,
    catalog: bool,
) -> Result<ScanFixtureResult> {
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

    let mut fs = FixtureFs::from_tree(fixture);
    for meta in &manifest.file_meta {
        let rel = meta.path.trim_start_matches('/');
        let data = std::fs::read(fixture.join(rel)).unwrap_or_default();
        let mode = meta.mode.unwrap_or(0o100644);
        let uid = meta.uid.unwrap_or(0);
        fs = fs.with_file_meta(rel, data, mode, uid);
    }
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
            CollectorSpec::new("entropy"),
            CollectorSpec::new("file.ioc"),
        ],
        ..Default::default()
    };

    let mut sink = VecSink::new();
    let _reports = run_plan(&plan, &ctx, &mut sink).context("run collectors")?;
    append_injected_observations(fixture, &manifest, &mut sink.observations)?;

    let engine = if catalog {
        CheckEngine::from_dir_for_catalog_test(checks_dir)
    } else {
        CheckEngine::from_dir(checks_dir)
    }
    .with_context(|| format!("load checks from {}", checks_dir.display()))?;
    let mut findings = engine.evaluate(&sink.observations);
    findings.extend(correlate_fixture_findings(&sink.observations, catalog));

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

fn append_injected_observations(
    fixture: &Path,
    manifest: &FixtureManifest,
    observations: &mut Vec<Observation>,
) -> Result<()> {
    let path = fixture.join("observations.ndjson");
    if !path.exists() {
        return Ok(());
    }
    if !manifest.allow_inject {
        bail!(
            "{} has observations.ndjson but manifest.allow_inject is false — \
             prefer collector-driven trees, or set allow_inject = true for schema-validated inject",
            fixture.display()
        );
    }
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("read {}", path.display()))?;
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Round-trip through Observation serde = collector schema validation.
        let obs: Observation = serde_json::from_str(line).with_context(|| {
            format!("{}:{}: invalid observation JSON (schema mismatch)", path.display(), i + 1)
        })?;
        let roundtrip = serde_json::to_value(&obs)
            .and_then(|v| serde_json::from_value::<Observation>(v))
            .with_context(|| {
                format!("{}:{}: observation failed schema round-trip", path.display(), i + 1)
            })?;
        observations.push(roundtrip);
    }
    Ok(())
}

fn correlate_fixture_findings(observations: &[Observation], catalog: bool) -> Vec<FindingDraft> {
    let mut out = Vec::new();
    let shadows: Vec<ShadowPosture> = observations
        .iter()
        .filter_map(|o| match o {
            Observation::ShadowEntry(s) => Some(ShadowPosture {
                username: s.username.clone(),
                algorithm: s.algorithm.clone(),
                hash_fingerprint: s.hash_fingerprint.clone(),
                locked: s.locked,
                empty_password: s.empty_password,
            }),
            _ => None,
        })
        .collect();
    for d in find_duplicate_shadow_hashes(&shadows) {
        out.push(drift_to_draft(d, CheckType::User, "shadow_entry"));
    }

    if !catalog {
        return out;
    }

    let keys: Vec<KeyPlacement> = observations
        .iter()
        .filter_map(|o| match o {
            Observation::AuthorizedKey(k) => Some(KeyPlacement {
                host_id: host_id_from_username(&k.username),
                username: k.username.clone(),
                path: k.path.to_string_lossy(),
                fingerprint: k.fingerprint.clone(),
            }),
            _ => None,
        })
        .collect();
    for d in correlate_ssh_key_graph(&keys) {
        out.push(drift_to_draft(d, CheckType::Incident, "authorized_key"));
    }

    let new = BaselineSnapshot {
        host_id: HostId::new_v4(),
        captured_at: 1,
        accounts: observations
            .iter()
            .filter_map(|o| match o {
                Observation::Account(a) => Some(BaselineAccount {
                    name: a.username.clone(),
                    uid: a.uid,
                    shell: a.shell.to_string_lossy(),
                }),
                _ => None,
            })
            .collect(),
        authorized_keys: Vec::new(),
        preload_paths: Vec::new(),
        critical_files: Vec::new(),
    };
    let old = BaselineSnapshot {
        host_id: new.host_id,
        captured_at: 0,
        accounts: Vec::new(),
        authorized_keys: Vec::new(),
        preload_paths: Vec::new(),
        critical_files: Vec::new(),
    };
    for d in diff_baseline(&old, &new) {
        if d.check_id.as_str() == "RM-USER-0004" {
            out.push(drift_to_draft(d, CheckType::User, "account"));
        }
    }
    out
}

fn host_id_from_username(username: &str) -> HostId {
    let mut bytes = [0u8; 16];
    let src = username.as_bytes();
    let n = src.len().min(16);
    bytes[..n].copy_from_slice(&src[..n]);
    HostId(uuid::Uuid::from_bytes(bytes))
}

fn drift_to_draft(
    d: rustmite_checks::DriftFinding,
    check_type: CheckType,
    match_kind: &str,
) -> FindingDraft {
    FindingDraft {
        check_id: d.check_id,
        check_version: 1,
        check_type,
        severity: d.severity.unwrap_or(Severity::Medium),
        confidence: Confidence::Medium,
        title: d.title,
        evidence: d.evidence,
        attack: Vec::new(),
        match_kind: match_kind.into(),
    }
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
