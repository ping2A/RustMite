//! Catalog fixture tests: every check declares `[test]`, and named fixtures hold.
//!
//! Run: `cargo test -p rustmite-cli --test check_fixture_tests`

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use rustmite_checks::{
    load_dir, CheckManifest, CheckTestExpect, CheckTestSource, FindingDraft,
};
use rustmite_cli::{scan_fixture, scan_fixture_for_catalog};
use serde_json::Value as JsonValue;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn checks_dir() -> PathBuf {
    repo_root().join("checks")
}

fn fixtures_dir() -> PathBuf {
    repo_root().join("fixtures")
}

fn fixture_path(name: &str) -> PathBuf {
    fixtures_dir().join(name)
}

struct ScanCache {
    findings: HashMap<String, Vec<FindingDraft>>,
    allow_inject: HashMap<String, bool>,
}

impl ScanCache {
    fn load(needed: &HashSet<String>) -> Self {
        let mut findings = HashMap::new();
        let mut allow_inject = HashMap::new();
        for name in needed {
            let path = fixture_path(name);
            assert!(path.is_dir(), "missing fixture directory {}", path.display());
            let inject = path.join("observations.ndjson").is_file();
            let manifest_inject = std::fs::read_to_string(path.join("manifest.toml"))
                .ok()
                .and_then(|t| {
                    let v: toml::Value = toml::from_str(&t).ok()?;
                    v.get("allow_inject")?.as_bool()
                })
                .unwrap_or(false);
            allow_inject.insert(name.clone(), inject && manifest_inject);
            let result = if name == "hostile-catalog" || name.starts_with("hostile-") {
                scan_fixture_for_catalog(&path, &checks_dir())
            } else {
                scan_fixture(&path, &checks_dir())
            }
            .unwrap_or_else(|e| panic!("scan-fixture {name}: {e:#}"));
            findings.insert(name.clone(), result.findings);
        }
        Self {
            findings,
            allow_inject,
        }
    }

    fn ids(&self, fixture: &str) -> HashSet<String> {
        self.findings
            .get(fixture)
            .into_iter()
            .flatten()
            .map(|f| f.check_id.as_str().to_string())
            .collect()
    }

    fn findings_for<'a>(&'a self, fixture: &str, check_id: &str) -> Vec<&'a FindingDraft> {
        self.findings
            .get(fixture)
            .into_iter()
            .flatten()
            .filter(|f| f.check_id.as_str() == check_id)
            .collect()
    }
}

fn expect_matches(finding: &FindingDraft, expect: &CheckTestExpect) -> bool {
    if let Some(sub) = &expect.title_contains {
        if !finding.title.contains(sub) {
            return false;
        }
    }
    for (k, want) in &expect.evidence {
        let Some(got) = finding.evidence.get(k) else {
            return false;
        };
        if !json_loose_eq(got, want) {
            return false;
        }
    }
    true
}

fn json_loose_eq(got: &JsonValue, want: &JsonValue) -> bool {
    match (got, want) {
        (JsonValue::String(a), JsonValue::String(b)) => a == b,
        (JsonValue::Bool(a), JsonValue::Bool(b)) => a == b,
        (JsonValue::Number(a), JsonValue::Number(b)) => a.as_f64() == b.as_f64(),
        (JsonValue::Number(a), JsonValue::String(b)) => a.to_string() == *b,
        (JsonValue::String(a), JsonValue::Number(b)) => *a == b.to_string(),
        (JsonValue::Bool(a), JsonValue::String(b)) => {
            (*a && b.eq_ignore_ascii_case("true")) || (!*a && b.eq_ignore_ascii_case("false"))
        }
        _ => got == want,
    }
}

#[test]
fn every_check_declares_fixture_tests() {
    let manifests = load_dir(checks_dir()).expect("load checks catalog");
    assert!(
        manifests.len() >= 40,
        "expected expanded catalog, got {}",
        manifests.len()
    );
    let mut missing_silent = Vec::new();
    let mut missing_fires = Vec::new();
    let mut missing_expect = Vec::new();
    let mut missing_fixture = Vec::new();
    for m in &manifests {
        if m.test.silent_on.is_empty() {
            missing_silent.push(m.id.as_str().to_string());
        }
        if m.test.fires_on.is_empty() && !m.is_anomark_rule() {
            missing_fires.push(m.id.as_str().to_string());
        }
        if !m.is_anomark_rule() && !m.test.fires_on.is_empty() && m.test.expect.is_empty() {
            missing_expect.push(m.id.as_str().to_string());
        }
        for name in m.test.fires_on.iter().chain(m.test.silent_on.iter()) {
            if !fixture_path(name).is_dir() {
                missing_fixture.push(format!("{} → {}", m.id.as_str(), name));
            }
        }
    }
    assert!(
        missing_silent.is_empty(),
        "checks missing [test].silent_on: {missing_silent:?}"
    );
    assert!(
        missing_fires.is_empty(),
        "checks missing [test].fires_on: {missing_fires:?}"
    );
    assert!(
        missing_expect.is_empty(),
        "checks missing [test.expect]: {missing_expect:?}"
    );
    assert!(
        missing_fixture.is_empty(),
        "checks reference missing fixtures: {missing_fixture:?}"
    );
}

#[test]
fn check_fires_on_and_silent_on_fixtures() {
    let manifests = load_dir(checks_dir()).expect("load checks");
    let mut needed: HashSet<String> = HashSet::new();
    for m in &manifests {
        needed.extend(m.test.fires_on.iter().cloned());
        needed.extend(m.test.silent_on.iter().cloned());
    }
    let cache = ScanCache::load(&needed);

    let mut failures = Vec::new();
    for m in &manifests {
        let id = m.id.as_str();
        for fix in &m.test.fires_on {
            let fired = cache.ids(fix);
            if !fired.contains(id) {
                let mut v: Vec<_> = fired.iter().cloned().collect();
                v.sort();
                failures.push(format!("{id} should fire on {fix} (got {})", v.join(",")));
                continue;
            }
            // Source policy: collector rules must not rely on inject overlays.
            match m.test.source {
                CheckTestSource::Collector => {
                    if cache.allow_inject.get(fix).copied().unwrap_or(false) {
                        // Collector-sourced checks may share a fixture that also has inject
                        // for other rules, but they must still match expect from any finding.
                    }
                }
                CheckTestSource::Inject => {
                    if !cache.allow_inject.get(fix).copied().unwrap_or(false) {
                        failures.push(format!(
                            "{id} source=inject but fixture {fix} has no allow_inject observations.ndjson"
                        ));
                    }
                }
                CheckTestSource::Correlate => {}
            }
            if !m.test.expect.is_empty() {
                let hits = cache.findings_for(fix, id);
                if !hits.iter().any(|f| expect_matches(f, &m.test.expect)) {
                    let sample = hits
                        .first()
                        .map(|f| format!("title={:?} evidence={:?}", f.title, f.evidence))
                        .unwrap_or_else(|| "no findings".into());
                    failures.push(format!(
                        "{id} expect mismatch on {fix}: want title_contains={:?} evidence={:?}; got {sample}",
                        m.test.expect.title_contains, m.test.expect.evidence
                    ));
                }
            }
        }
        for fix in &m.test.silent_on {
            if cache.ids(fix).contains(id) {
                failures.push(format!("{id} should stay silent on {fix}"));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "fixture expectation failures:\n  {}",
        failures.join("\n  ")
    );
}

#[test]
fn collector_sourced_checks_do_not_require_inject_only_coverage() {
    let manifests = load_dir(checks_dir()).expect("load checks");
    let mut inject_only = Vec::new();
    for m in &manifests {
        if m.is_anomark_rule() || !matches!(m.test.source, CheckTestSource::Collector) {
            continue;
        }
        // Every fires_on fixture for a collector rule must exist as a tree; inject-only
        // fixtures (allow_inject + no meaningful collectors) are tracked separately.
        for fix in &m.test.fires_on {
            let path = fixture_path(fix);
            let has_tree = path.join("proc").is_dir()
                || path.join("etc").is_dir()
                || path.join("tmp").is_dir()
                || path.join("sys").is_dir();
            let inject = path.join("observations.ndjson").is_file();
            if inject && !has_tree {
                inject_only.push(format!("{} → {fix}", m.id.as_str()));
            }
        }
    }
    assert!(
        inject_only.is_empty(),
        "collector-sourced checks must use fixture trees, not inject-only NDJSON: {inject_only:?}"
    );
}

#[test]
fn clean_fixture_has_no_findings() {
    let needed = HashSet::from(["clean-ubuntu2204".to_string()]);
    let cache = ScanCache::load(&needed);
    let fired = cache.ids("clean-ubuntu2204");
    assert!(
        fired.is_empty(),
        "clean-ubuntu2204 must stay silent, got {fired:?}"
    );
}

#[test]
fn catalog_lists_all_toml_files() {
    let dir = checks_dir();
    let on_disk: HashSet<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .and_then(|x| x.to_str())
                .is_some_and(|x| x.eq_ignore_ascii_case("toml"))
        })
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    let loaded: HashSet<_> = load_dir(&dir)
        .unwrap()
        .into_iter()
        .map(|m: CheckManifest| format!("{}.toml", m.id.as_str()))
        .collect();
    let missing: Vec<_> = on_disk.difference(&loaded).cloned().collect();
    assert!(
        missing.is_empty(),
        "TOML files failed to load as checks: {missing:?}"
    );
}

#[test]
fn fixtures_dir_exists() {
    assert!(fixtures_dir().is_dir(), "fixtures/ missing");
    for name in [
        "clean-ubuntu2204",
        "diamorphine-hidden-pid",
        "memfd-exec",
        "trojaned-ls",
        "cred-audit-weak",
        "m5-collectors",
        "uid0-extra-account",
        "hostile-catalog",
    ] {
        assert!(
            Path::new(&fixture_path(name)).is_dir(),
            "expected fixture {name}"
        );
    }
}
