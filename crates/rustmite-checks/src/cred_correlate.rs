//! Credential audit correlation (duplicate shadow fingerprints).

use std::collections::BTreeMap;

use rustmite_proto::{CheckId, Severity};
use serde_json::{Map, Value as JsonValue};

use crate::baseline::DriftFinding;

/// Shadow posture row (algorithm + fingerprint — never raw hash).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShadowPosture {
    pub username: String,
    pub algorithm: String,
    pub hash_fingerprint: Option<String>,
    pub locked: bool,
    pub empty_password: bool,
}

/// Emit RM-CRED-0002 when two accounts share the same password fingerprint.
pub fn find_duplicate_shadow_hashes(entries: &[ShadowPosture]) -> Vec<DriftFinding> {
    let mut by_fp: BTreeMap<&str, Vec<&ShadowPosture>> = BTreeMap::new();
    for e in entries {
        let Some(fp) = e.hash_fingerprint.as_deref() else {
            continue;
        };
        if e.locked || e.empty_password {
            continue;
        }
        by_fp.entry(fp).or_default().push(e);
    }

    let mut out = Vec::new();
    for (fp, group) in by_fp {
        if group.len() < 2 {
            continue;
        }
        let usernames: Vec<String> = group.iter().map(|e| e.username.clone()).collect();
        out.push(DriftFinding {
            check_id: CheckId::new("RM-CRED-0002"),
            title: format!(
                "Duplicate password hash across accounts: {}",
                usernames.join(", ")
            ),
            evidence: Map::from_iter([
                (
                    "usernames".into(),
                    JsonValue::Array(usernames.into_iter().map(JsonValue::String).collect()),
                ),
                ("hash_fingerprint".into(), JsonValue::String(fp.into())),
            ]),
            severity: Some(Severity::Medium),
        });
    }
    out.sort_by(|a, b| a.title.cmp(&b.title));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_fingerprints() {
        let findings = find_duplicate_shadow_hashes(&[
            ShadowPosture {
                username: "alice".into(),
                algorithm: "sha512crypt".into(),
                hash_fingerprint: Some("fp1".into()),
                locked: false,
                empty_password: false,
            },
            ShadowPosture {
                username: "bob".into(),
                algorithm: "sha512crypt".into(),
                hash_fingerprint: Some("fp1".into()),
                locked: false,
                empty_password: false,
            },
        ]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_id.as_str(), "RM-CRED-0002");
    }
}
