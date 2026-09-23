//! Host baseline snapshots and drift diffing (M7).

use rustmite_proto::{CheckId, HostId, Severity};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as JsonValue};

/// One passwd-derived account in a baseline.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineAccount {
    pub name: String,
    pub uid: u32,
    pub shell: String,
}

/// One authorized_keys fingerprint at a path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineAuthorizedKey {
    pub path: String,
    pub fingerprint: String,
}

/// Critical file hash recorded in a baseline.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineFileHash {
    pub path: String,
    pub sha256: String,
}

/// Signed snapshot of host state used for drift detection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineSnapshot {
    pub host_id: HostId,
    /// Epoch milliseconds when the snapshot was captured.
    pub captured_at: u64,
    pub accounts: Vec<BaselineAccount>,
    pub authorized_keys: Vec<BaselineAuthorizedKey>,
    pub preload_paths: Vec<String>,
    #[serde(default)]
    pub critical_files: Vec<BaselineFileHash>,
}

/// Drift finding emitted by comparing two baselines (check id ties to catalog rules).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DriftFinding {
    pub check_id: CheckId,
    pub title: String,
    pub evidence: Map<String, JsonValue>,
    #[serde(default)]
    pub severity: Option<Severity>,
}

/// Options controlling baseline diff behaviour.
#[derive(Clone, Debug, Default)]
pub struct DiffOptions {
    /// Paths whose hash change is attributable to a package update (auto-downgrade).
    pub package_changed_paths: Vec<String>,
}

/// Compare `old` → `new` and return drift findings (additive/changed dimensions only).
pub fn diff_baseline(old: &BaselineSnapshot, new: &BaselineSnapshot) -> Vec<DriftFinding> {
    diff_baseline_with(old, new, &DiffOptions::default())
}

/// Compare baselines with package-attribution downgrade support.
pub fn diff_baseline_with(
    old: &BaselineSnapshot,
    new: &BaselineSnapshot,
    opts: &DiffOptions,
) -> Vec<DriftFinding> {
    let mut out = Vec::new();

    let old_accounts: std::collections::BTreeSet<_> = old
        .accounts
        .iter()
        .map(|a| (a.name.as_str(), a.uid))
        .collect();
    for acct in &new.accounts {
        if !old_accounts.contains(&(acct.name.as_str(), acct.uid)) {
            out.push(DriftFinding {
                check_id: CheckId::new("RM-USER-0004"),
                title: format!("New account '{}' (uid {}) vs baseline", acct.name, acct.uid),
                evidence: Map::from_iter([
                    ("username".into(), JsonValue::String(acct.name.clone())),
                    ("uid".into(), JsonValue::Number(acct.uid.into())),
                    ("shell".into(), JsonValue::String(acct.shell.clone())),
                ]),
                severity: Some(Severity::Medium),
            });
        }
    }

    let old_keys: std::collections::BTreeSet<_> = old
        .authorized_keys
        .iter()
        .map(|k| (k.path.as_str(), k.fingerprint.as_str()))
        .collect();
    for key in &new.authorized_keys {
        if !old_keys.contains(&(key.path.as_str(), key.fingerprint.as_str())) {
            out.push(DriftFinding {
                check_id: CheckId::new("RM-USER-0008"),
                title: format!(
                    "New SSH authorized key {} at {}",
                    key.fingerprint, key.path
                ),
                evidence: Map::from_iter([
                    ("path".into(), JsonValue::String(key.path.clone())),
                    ("fingerprint".into(), JsonValue::String(key.fingerprint.clone())),
                ]),
                severity: Some(Severity::High),
            });
        }
    }

    let old_preload: std::collections::BTreeSet<_> =
        old.preload_paths.iter().cloned().collect();
    let new_preload: std::collections::BTreeSet<_> =
        new.preload_paths.iter().cloned().collect();
    for path in new_preload.difference(&old_preload) {
        out.push(preload_drift_finding("added", path));
    }
    for path in old_preload.difference(&new_preload) {
        out.push(preload_drift_finding("removed", path));
    }

    let old_files: std::collections::BTreeMap<_, _> = old
        .critical_files
        .iter()
        .map(|f| (f.path.as_str(), f.sha256.as_str()))
        .collect();
    let pkg_paths: std::collections::BTreeSet<_> = opts
        .package_changed_paths
        .iter()
        .map(|p| p.trim_start_matches('/').to_string())
        .collect();
    for file in &new.critical_files {
        match old_files.get(file.path.as_str()) {
            Some(prev) if *prev != file.sha256.as_str() => {
                let norm = file.path.trim_start_matches('/');
                let package_attributed = pkg_paths.contains(norm)
                    || pkg_paths.contains(&file.path)
                    || pkg_paths
                        .iter()
                        .any(|p| p == norm || p.trim_start_matches('/') == norm);
                let severity = if package_attributed {
                    Severity::Low
                } else {
                    Severity::High
                };
                out.push(DriftFinding {
                    check_id: CheckId::new("RM-DRIFT-0001"),
                    title: format!(
                        "Critical file hash changed vs baseline: {}",
                        file.path
                    ),
                    evidence: Map::from_iter([
                        ("path".into(), JsonValue::String(file.path.clone())),
                        ("expected_hash".into(), JsonValue::String((*prev).into())),
                        ("actual_hash".into(), JsonValue::String(file.sha256.clone())),
                        (
                            "package_attributed".into(),
                            JsonValue::Bool(package_attributed),
                        ),
                    ]),
                    severity: Some(severity),
                });
            }
            None => {
                // Newly tracked file — informational drift on account/SSH set is enough;
                // skip pure adds to critical_files to avoid noise on first expansion.
            }
            _ => {}
        }
    }

    out.sort_by(|a, b| {
        a.check_id
            .as_str()
            .cmp(b.check_id.as_str())
            .then_with(|| a.title.cmp(&b.title))
    });
    out
}

fn preload_drift_finding(change: &str, path: &str) -> DriftFinding {
    DriftFinding {
        check_id: CheckId::new("RM-PERSIST-0001"),
        title: format!("ld.so.preload path {change} vs baseline: {path}"),
        evidence: Map::from_iter([
            ("change".into(), JsonValue::String(change.into())),
            ("path".into(), JsonValue::String(path.into())),
        ]),
        severity: Some(Severity::High),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmite_proto::HostId;

    fn host() -> HostId {
        HostId::new_v4()
    }

    fn empty_snapshot() -> BaselineSnapshot {
        BaselineSnapshot {
            host_id: host(),
            captured_at: 1,
            accounts: vec![],
            authorized_keys: vec![],
            preload_paths: vec![],
            critical_files: vec![],
        }
    }

    #[test]
    fn diff_new_account() {
        let old = empty_snapshot();
        let mut new = old.clone();
        new.accounts.push(BaselineAccount {
            name: "backdoor".into(),
            uid: 1001,
            shell: "/bin/bash".into(),
        });
        let findings = diff_baseline(&old, &new);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_id.as_str(), "RM-USER-0004");
    }

    #[test]
    fn diff_new_authorized_key() {
        let old = empty_snapshot();
        let mut new = old.clone();
        new.authorized_keys.push(BaselineAuthorizedKey {
            path: "/root/.ssh/authorized_keys".into(),
            fingerprint: "SHA256:abc".into(),
        });
        let findings = diff_baseline(&old, &new);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_id.as_str(), "RM-USER-0008");
    }

    #[test]
    fn diff_preload_paths() {
        let mut old = empty_snapshot();
        old.preload_paths = vec!["/lib/evil.so".into()];
        let mut new = old.clone();
        new.preload_paths = vec!["/lib/evil.so".into(), "/lib/other.so".into()];
        let findings = diff_baseline(&old, &new);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_id.as_str(), "RM-PERSIST-0001");
        assert_eq!(
            findings[0].evidence.get("change").and_then(|v| v.as_str()),
            Some("added")
        );
    }

    #[test]
    fn critical_file_hash_change() {
        let mut old = empty_snapshot();
        old.critical_files.push(BaselineFileHash {
            path: "/usr/bin/sshd".into(),
            sha256: "aaa".into(),
        });
        let mut new = old.clone();
        if let Some(f) = new.critical_files.get_mut(0) {
            f.sha256 = "bbb".into();
        }
        let findings = diff_baseline(&old, &new);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_id.as_str(), "RM-DRIFT-0001");
        assert_eq!(findings[0].severity, Some(Severity::High));
    }

    #[test]
    fn package_attributed_change_downgraded() {
        let mut old = empty_snapshot();
        old.critical_files.push(BaselineFileHash {
            path: "/usr/bin/ls".into(),
            sha256: "aaa".into(),
        });
        let mut new = old.clone();
        if let Some(f) = new.critical_files.get_mut(0) {
            f.sha256 = "bbb".into();
        }
        let findings = diff_baseline_with(
            &old,
            &new,
            &DiffOptions {
                package_changed_paths: vec!["/usr/bin/ls".into()],
            },
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Some(Severity::Low));
        assert_eq!(
            findings[0]
                .evidence
                .get("package_attributed")
                .and_then(|v| v.as_bool()),
            Some(true)
        );
    }

    #[test]
    fn diff_unchanged_empty() {
        let snap = empty_snapshot();
        assert!(diff_baseline(&snap, &snap).is_empty());
    }
}
