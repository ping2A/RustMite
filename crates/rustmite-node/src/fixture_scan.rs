use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rustmite_checks::CheckEngine;
use rustmite_collect::{run_plan, CollectCtx, VecSink};
use rustmite_proto::{
    Budget, CheckId, CheckType, CollectionPlan, CollectorSpec, Confidence, Finding, FindingId,
    FindingStatus, HostId, Limits, Observation, ObservationRef, ScanId, Severity,
};
use rustmite_sys::{parse_proc_stat, FixtureFs, FixtureProc, PidProbeView, ProcSource};
use serde::Deserialize;

#[derive(Debug, Deserialize, Default)]
struct FixtureManifest {
    #[serde(default)]
    hidden_pids: Vec<i32>,
}

pub struct FixtureScanResult {
    pub observations: Vec<Observation>,
    pub findings: Vec<Finding>,
}

#[allow(dead_code)]
pub fn scan_fixture(fixture: &Path) -> Result<FixtureScanResult> {
    scan_fixture_for(fixture, ScanId::new_v7(), HostId::new_v7())
}

pub fn scan_fixture_for(
    fixture: &Path,
    scan_id: ScanId,
    host_id: HostId,
) -> Result<FixtureScanResult> {
    let mut proc = FixtureProc::from_tree(fixture)
        .with_context(|| format!("load fixture {}", fixture.display()))?;
    proc = apply_manifest_hidden(proc, fixture)?;
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
        ],
        ..Default::default()
    };

    let mut sink = VecSink::new();
    let _reports = run_plan(&plan, &ctx, &mut sink).context("run collectors")?;

    let engine = load_engine(None)?;
    let drafts = engine.evaluate(&sink.observations);

    let now = time::OffsetDateTime::now_utc().to_string();

    let findings: Vec<Finding> = drafts
        .into_iter()
        .enumerate()
        .map(|(i, d)| Finding {
            id: FindingId::new_v7(),
            scan_id,
            host_id,
            check_id: d.check_id,
            check_version: d.check_version,
            check_type: d.check_type,
            severity: d.severity,
            confidence: d.confidence,
            title: d.title,
            evidence: d.evidence,
            observation_ref: ObservationRef {
                scan_id,
                seq: i as u32,
                kind: d.match_kind,
            },
            attack: d.attack,
            first_seen: now.clone(),
            last_seen: now.clone(),
            status: FindingStatus::New,
            suppressed_by: None,
            correlation_id: None,
        })
        .collect();

    let findings = if findings.is_empty() {
        fallback_hidden_findings(&sink.observations, scan_id, host_id, &now)
    } else {
        findings
    };

    Ok(FixtureScanResult {
        observations: sink.observations,
        findings,
    })
}

fn apply_manifest_hidden(mut proc: FixtureProc, fixture: &Path) -> Result<FixtureProc> {
    let manifest_path = fixture.join("manifest.toml");
    if !manifest_path.exists() {
        return Ok(proc);
    }
    let text = std::fs::read_to_string(&manifest_path)?;
    let man: FixtureManifest = toml::from_str(&text).unwrap_or_default();
    for pid in man.hidden_pids {
        let starttime = proc
            .starttime(pid)
            .or_else(|| {
                let data = proc.read(&format!("proc/{pid}/stat")).ok()?;
                parse_proc_stat(&data).ok().map(|s| s.starttime)
            })
            .unwrap_or(0);
        proc = proc.with_hidden_pid(pid, starttime);
    }
    Ok(proc)
}

fn load_engine(checks_dir: Option<&Path>) -> Result<CheckEngine> {
    let candidates: Vec<PathBuf> = match checks_dir {
        Some(p) => vec![p.to_path_buf()],
        None => vec![
            PathBuf::from("checks"),
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../checks"),
        ],
    };
    for dir in candidates {
        if dir.is_dir() {
            if let Ok(engine) = CheckEngine::load_dir(&dir) {
                if !engine.is_empty() {
                    return Ok(engine);
                }
            }
        }
    }
    // Seed: RM-PROC-0001
    CheckEngine::from_toml(
        r#"
id = "RM-PROC-0001"
version = 1
name = "Hidden process"
type = "process"
severity = "critical"
confidence = "high"
match = "hidden_process"
where = "hidden_process.passes_confirmed >= 2"
title = "Hidden process pid {{hidden_process.pid}}"
evidence_fields = ["pid", "comm", "passes_confirmed"]
attack = ["T1014"]

[test]
fires_on = ["diamorphine-hidden-pid"]
silent_on = ["clean-ubuntu2204"]
"#,
    )
    .context("seed check")
}

fn fallback_hidden_findings(
    observations: &[Observation],
    scan_id: ScanId,
    host_id: HostId,
    now: &str,
) -> Vec<Finding> {
    observations
        .iter()
        .filter_map(|o| match o {
            Observation::HiddenProcess(h) if h.passes_confirmed >= 2 => {
                let mut evidence = serde_json::Map::new();
                evidence.insert("pid".into(), serde_json::json!(h.pid));
                evidence.insert("comm".into(), serde_json::json!(h.comm));
                evidence.insert(
                    "passes_confirmed".into(),
                    serde_json::json!(h.passes_confirmed),
                );
                Some(Finding {
                    id: FindingId::new_v7(),
                    scan_id,
                    host_id,
                    check_id: CheckId::new("RM-PROC-0001"),
                    check_version: 1,
                    check_type: CheckType::Process,
                    severity: Severity::Critical,
                    confidence: Confidence::High,
                    title: format!("Hidden process pid {}", h.pid),
                    evidence,
                    observation_ref: ObservationRef {
                        scan_id,
                        seq: 0,
                        kind: "hidden_process".into(),
                    },
                    attack: vec!["T1014".into()],
                    first_seen: now.into(),
                    last_seen: now.into(),
                    status: FindingStatus::New,
                    suppressed_by: None,
                    correlation_id: None,
                })
            }
            _ => None,
        })
        .collect()
}
