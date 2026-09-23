//! Cross-host SSH key placement graph (M7).

use std::collections::BTreeMap;

use rustmite_proto::{CheckId, HostId, Severity};
use serde_json::{Map, Value as JsonValue};

use crate::baseline::DriftFinding;

/// One authorized_keys placement observed on a host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPlacement {
    pub host_id: HostId,
    pub username: String,
    pub path: String,
    pub fingerprint: String,
}

/// Build bipartite key↔host edges and emit lateral-movement findings for reused keys.
pub fn correlate_ssh_key_graph(placements: &[KeyPlacement]) -> Vec<DriftFinding> {
    let mut by_fp: BTreeMap<&str, Vec<&KeyPlacement>> = BTreeMap::new();
    for p in placements {
        if p.fingerprint.is_empty() {
            continue;
        }
        by_fp.entry(p.fingerprint.as_str()).or_default().push(p);
    }

    let mut out = Vec::new();
    for (fp, places) in by_fp {
        let mut hosts: Vec<HostId> = places.iter().map(|p| p.host_id).collect();
        hosts.sort();
        hosts.dedup();
        if hosts.len() < 2 {
            continue;
        }
        let mut usernames: Vec<String> = places.iter().map(|p| p.username.clone()).collect();
        usernames.sort();
        usernames.dedup();
        out.push(DriftFinding {
            check_id: CheckId::new("RM-INC-0004"),
            title: format!(
                "SSH key {} authorised on {} hosts (possible stolen credential / lateral movement)",
                fp,
                hosts.len()
            ),
            evidence: Map::from_iter([
                ("fingerprint".into(), JsonValue::String(fp.into())),
                (
                    "host_count".into(),
                    JsonValue::Number((hosts.len() as u64).into()),
                ),
                (
                    "hosts".into(),
                    JsonValue::Array(
                        hosts
                            .iter()
                            .map(|h| JsonValue::String(h.to_string()))
                            .collect(),
                    ),
                ),
                (
                    "usernames".into(),
                    JsonValue::Array(
                        usernames
                            .into_iter()
                            .map(JsonValue::String)
                            .collect(),
                    ),
                ),
            ]),
            severity: Some(Severity::Critical),
        });
    }

    out.sort_by(|a, b| a.title.cmp(&b.title));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reused_key_fires_inc_0004() {
        let h1 = HostId::new_v4();
        let h2 = HostId::new_v4();
        let findings = correlate_ssh_key_graph(&[
            KeyPlacement {
                host_id: h1,
                username: "root".into(),
                path: "/root/.ssh/authorized_keys".into(),
                fingerprint: "SHA256:same".into(),
            },
            KeyPlacement {
                host_id: h2,
                username: "alice".into(),
                path: "/home/alice/.ssh/authorized_keys".into(),
                fingerprint: "SHA256:same".into(),
            },
            KeyPlacement {
                host_id: h1,
                username: "bob".into(),
                path: "/home/bob/.ssh/authorized_keys".into(),
                fingerprint: "SHA256:unique".into(),
            },
        ]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_id.as_str(), "RM-INC-0004");
        assert_eq!(findings[0].severity, Some(Severity::Critical));
    }

    #[test]
    fn single_host_key_silent() {
        let h1 = HostId::new_v4();
        let findings = correlate_ssh_key_graph(&[KeyPlacement {
            host_id: h1,
            username: "root".into(),
            path: "/root/.ssh/authorized_keys".into(),
            fingerprint: "SHA256:only".into(),
        }]);
        assert!(findings.is_empty());
    }
}
