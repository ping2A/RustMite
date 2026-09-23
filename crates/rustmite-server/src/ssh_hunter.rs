//! SSH Hunter aggregation helpers (Sandfly-style key / user / host investigation).

use std::collections::{BTreeMap, BTreeSet};

use rustmite_checks::{correlate_ssh_key_graph, KeyPlacement};
use rustmite_proto::{HostId, Observation};
use rustmite_store::{
    HostRecord, SshKeyPlacement, SshKeyRecord, SshSecurityZone, Store, UpsertSshPlacement,
    UpsertSshZone,
};
use serde::Serialize;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize)]
pub struct SshHunterSummary {
    pub keys: usize,
    pub placements: usize,
    pub users: usize,
    pub hosts_with_keys: usize,
    pub reused_keys: usize,
    pub weak_keys: usize,
    pub tagged_keys: usize,
    pub zones: usize,
    pub key_types: BTreeMap<String, usize>,
    pub top_reused: Vec<SshKeySummaryRow>,
    pub recent_keys: Vec<SshKeySummaryRow>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SshKeySummaryRow {
    pub fingerprint: String,
    pub key_type: String,
    pub comment: Option<String>,
    pub tags: Vec<String>,
    pub host_count: usize,
    pub user_count: usize,
    pub first_seen: String,
    pub last_seen: String,
    pub reused: bool,
    pub weak: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct SshUserRow {
    pub username: String,
    pub key_count: usize,
    pub host_count: usize,
    pub fingerprints: Vec<String>,
    pub hosts: Vec<Uuid>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SshHostRow {
    pub host_id: Uuid,
    pub display_name: String,
    pub primary_addr: Option<String>,
    pub key_count: usize,
    pub user_count: usize,
    pub fingerprints: Vec<String>,
    pub usernames: Vec<String>,
    pub labels: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SshGraph {
    pub nodes: Vec<SshGraphNode>,
    pub edges: Vec<SshGraphEdge>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SshGraphNode {
    pub id: String,
    pub kind: String,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SshGraphEdge {
    pub from: String,
    pub to: String,
    pub username: String,
    pub role: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct SshZoneView {
    pub zone: SshSecurityZone,
    pub matching_hosts: usize,
    pub matching_keys: usize,
    pub cross_zone_keys: usize,
}

fn is_weak(key: &SshKeyRecord) -> bool {
    key.key_type.contains("dss")
        || key.key_type == "ssh-rsa" && key.bits.map(|b| b < 2048).unwrap_or(true)
        || key.tags.iter().any(|t| t == "weak" || t == "deprecated" || t == "legacy")
}

pub fn enrich_keys(
    keys: &[SshKeyRecord],
    placements: &[SshKeyPlacement],
) -> Vec<SshKeySummaryRow> {
    let mut by_fp: BTreeMap<&str, Vec<&SshKeyPlacement>> = BTreeMap::new();
    for p in placements {
        by_fp.entry(p.fingerprint.as_str()).or_default().push(p);
    }
    let mut rows: Vec<_> = keys
        .iter()
        .map(|k| {
            let places = by_fp.get(k.fingerprint.as_str()).cloned().unwrap_or_default();
            let mut hosts: BTreeSet<Uuid> = BTreeSet::new();
            let mut users: BTreeSet<&str> = BTreeSet::new();
            for p in &places {
                hosts.insert(p.host_id.0);
                if p.username != "(host)" {
                    users.insert(p.username.as_str());
                }
            }
            let host_count = hosts.len();
            SshKeySummaryRow {
                fingerprint: k.fingerprint.clone(),
                key_type: k.key_type.clone(),
                comment: k.comment.clone(),
                tags: k.tags.clone(),
                host_count,
                user_count: users.len(),
                first_seen: k.first_seen.clone(),
                last_seen: k.last_seen.clone(),
                reused: host_count >= 2,
                weak: is_weak(k),
            }
        })
        .collect();
    rows.sort_by(|a, b| b.host_count.cmp(&a.host_count).then(a.fingerprint.cmp(&b.fingerprint)));
    rows
}

pub fn build_summary(
    keys: &[SshKeyRecord],
    placements: &[SshKeyPlacement],
    zones: usize,
) -> SshHunterSummary {
    let rows = enrich_keys(keys, placements);
    let mut users = BTreeSet::new();
    let mut hosts = BTreeSet::new();
    let mut key_types = BTreeMap::new();
    for p in placements {
        hosts.insert(p.host_id.0);
        if p.username != "(host)" {
            users.insert(p.username.as_str());
        }
    }
    for k in keys {
        *key_types.entry(k.key_type.clone()).or_insert(0usize) += 1;
    }
    let reused_keys = rows.iter().filter(|r| r.reused).count();
    let weak_keys = rows.iter().filter(|r| r.weak).count();
    let tagged_keys = keys.iter().filter(|k| !k.tags.is_empty()).count();
    let mut top_reused: Vec<_> = rows.iter().filter(|r| r.reused).cloned().collect();
    top_reused.truncate(10);
    let mut recent_keys = rows.clone();
    recent_keys.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
    recent_keys.truncate(12);

    SshHunterSummary {
        keys: keys.len(),
        placements: placements.len(),
        users: users.len(),
        hosts_with_keys: hosts.len(),
        reused_keys,
        weak_keys,
        tagged_keys,
        zones,
        key_types,
        top_reused,
        recent_keys,
    }
}

pub fn build_users(placements: &[SshKeyPlacement]) -> Vec<SshUserRow> {
    let mut map: BTreeMap<&str, (BTreeSet<&str>, BTreeSet<Uuid>)> = BTreeMap::new();
    for p in placements {
        if p.username == "(host)" || p.role == "host" {
            continue;
        }
        let entry = map.entry(p.username.as_str()).or_default();
        entry.0.insert(p.fingerprint.as_str());
        entry.1.insert(p.host_id.0);
    }
    let mut out: Vec<_> = map
        .into_iter()
        .map(|(username, (fps, hosts))| SshUserRow {
            username: username.into(),
            key_count: fps.len(),
            host_count: hosts.len(),
            fingerprints: fps.into_iter().map(str::to_string).collect(),
            hosts: hosts.into_iter().collect(),
        })
        .collect();
    out.sort_by(|a, b| b.host_count.cmp(&a.host_count).then(a.username.cmp(&b.username)));
    out
}

pub fn build_hosts(
    placements: &[SshKeyPlacement],
    host_index: &BTreeMap<Uuid, HostRecord>,
) -> Vec<SshHostRow> {
    let mut map: BTreeMap<Uuid, (BTreeSet<&str>, BTreeSet<&str>)> = BTreeMap::new();
    for p in placements {
        let entry = map.entry(p.host_id.0).or_default();
        entry.0.insert(p.fingerprint.as_str());
        if p.username != "(host)" {
            entry.1.insert(p.username.as_str());
        }
    }
    let mut out: Vec<_> = map
        .into_iter()
        .map(|(host_id, (fps, users))| {
            let host = host_index.get(&host_id);
            SshHostRow {
                host_id,
                display_name: host
                    .map(|h| h.display_name.clone())
                    .unwrap_or_else(|| host_id.to_string()),
                primary_addr: host.and_then(|h| h.primary_addr.clone()),
                key_count: fps.len(),
                user_count: users.len(),
                fingerprints: fps.into_iter().map(str::to_string).collect(),
                usernames: users.into_iter().map(str::to_string).collect(),
                labels: host.map(|h| h.labels.clone()).unwrap_or_default(),
            }
        })
        .collect();
    out.sort_by(|a, b| b.key_count.cmp(&a.key_count).then(a.display_name.cmp(&b.display_name)));
    out
}

pub fn build_graph(
    keys: &[SshKeyRecord],
    placements: &[SshKeyPlacement],
    host_index: &BTreeMap<Uuid, HostRecord>,
    limit_keys: usize,
) -> SshGraph {
    let rows = enrich_keys(keys, placements);
    let focus: BTreeSet<&str> = rows
        .iter()
        .filter(|r| r.reused || r.weak || r.tags.iter().any(|t| t == "critical" || t == "incident"))
        .take(limit_keys.max(1))
        .map(|r| r.fingerprint.as_str())
        .chain(
            rows.iter()
                .take(limit_keys.min(20))
                .map(|r| r.fingerprint.as_str()),
        )
        .collect();

    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut seen_nodes = BTreeSet::new();

    for fp in &focus {
        let key = keys.iter().find(|k| k.fingerprint == *fp);
        let id = format!("key:{fp}");
        if seen_nodes.insert(id.clone()) {
            nodes.push(SshGraphNode {
                id,
                kind: "key".into(),
                label: key
                    .and_then(|k| k.comment.clone())
                    .unwrap_or_else(|| short_fp(fp)),
                meta: Some(serde_json::json!({
                    "fingerprint": fp,
                    "key_type": key.map(|k| k.key_type.as_str()).unwrap_or(""),
                    "tags": key.map(|k| &k.tags).cloned().unwrap_or_default(),
                })),
            });
        }
    }

    for p in placements {
        if !focus.contains(p.fingerprint.as_str()) {
            continue;
        }
        let key_id = format!("key:{}", p.fingerprint);
        let host_id = format!("host:{}", p.host_id.0);
        if seen_nodes.insert(host_id.clone()) {
            let host = host_index.get(&p.host_id.0);
            nodes.push(SshGraphNode {
                id: host_id.clone(),
                kind: "host".into(),
                label: host
                    .map(|h| h.display_name.clone())
                    .unwrap_or_else(|| p.host_id.to_string()),
                meta: Some(serde_json::json!({
                    "host_id": p.host_id.0,
                    "addr": host.and_then(|h| h.primary_addr.clone()),
                })),
            });
        }
        if p.username != "(host)" {
            let user_id = format!("user:{}", p.username);
            if seen_nodes.insert(user_id.clone()) {
                nodes.push(SshGraphNode {
                    id: user_id.clone(),
                    kind: "user".into(),
                    label: p.username.clone(),
                    meta: None,
                });
            }
            edges.push(SshGraphEdge {
                from: key_id.clone(),
                to: user_id,
                username: p.username.clone(),
                role: p.role.clone(),
            });
        }
        edges.push(SshGraphEdge {
            from: key_id,
            to: host_id,
            username: p.username.clone(),
            role: p.role.clone(),
        });
    }

    SshGraph { nodes, edges }
}

pub fn zone_views(
    zones: &[SshSecurityZone],
    hosts: &[HostRecord],
    keys: &[SshKeyRecord],
) -> Vec<SshZoneView> {
    zones
        .iter()
        .map(|z| {
            let matching_hosts = hosts
                .iter()
                .filter(|h| host_matches_zone(h, z))
                .count();
            let matching_keys = keys
                .iter()
                .filter(|k| key_matches_zone(k, z))
                .count();
            let cross_zone_keys = keys
                .iter()
                .filter(|k| {
                    !z.key_tags.is_empty()
                        && k.tags.iter().any(|t| {
                            t == "shared" || t == "vendor" || t == "external" || t == "untrusted"
                        })
                        && !key_matches_zone(k, z)
                })
                .count();
            SshZoneView {
                zone: z.clone(),
                matching_hosts,
                matching_keys,
                cross_zone_keys,
            }
        })
        .collect()
}

fn host_matches_zone(host: &HostRecord, zone: &SshSecurityZone) -> bool {
    if zone.host_selectors.is_empty() {
        return false;
    }
    let hay: Vec<&str> = host
        .labels
        .values()
        .map(String::as_str)
        .chain(
            host.labels
                .get("tags")
                .into_iter()
                .flat_map(|t| t.split(|c| c == ',' || c == ';')),
        )
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    zone.host_selectors
        .iter()
        .any(|sel| hay.iter().any(|h| h.eq_ignore_ascii_case(sel)))
}

fn key_matches_zone(key: &SshKeyRecord, zone: &SshSecurityZone) -> bool {
    if zone.key_tags.is_empty() {
        return false;
    }
    zone.key_tags
        .iter()
        .any(|t| key.tags.iter().any(|kt| kt.eq_ignore_ascii_case(t)))
}

pub fn lateral_findings(placements: &[SshKeyPlacement]) -> usize {
    let kp: Vec<KeyPlacement> = placements
        .iter()
        .map(|p| KeyPlacement {
            host_id: p.host_id,
            username: p.username.clone(),
            path: p.path.clone(),
            fingerprint: p.fingerprint.clone(),
        })
        .collect();
    correlate_ssh_key_graph(&kp).len()
}

fn short_fp(fp: &str) -> String {
    let s = fp.strip_prefix("SHA256:").unwrap_or(fp);
    if s.len() <= 16 {
        fp.to_string()
    } else {
        format!("SHA256:{}…", &s[..12])
    }
}

pub fn host_map(hosts: Vec<HostRecord>) -> BTreeMap<Uuid, HostRecord> {
    hosts.into_iter().map(|h| (h.id.0, h)).collect()
}

pub fn filter_keys<'a>(
    rows: &'a [SshKeySummaryRow],
    q: &str,
    tag: &str,
    reused_only: bool,
    weak_only: bool,
) -> Vec<&'a SshKeySummaryRow> {
    let q = q.to_lowercase();
    rows.iter()
        .filter(|r| {
            if reused_only && !r.reused {
                return false;
            }
            if weak_only && !r.weak {
                return false;
            }
            if !tag.is_empty() && !r.tags.iter().any(|t| t.eq_ignore_ascii_case(tag)) {
                return false;
            }
            if q.is_empty() {
                return true;
            }
            let hay = format!(
                "{} {} {} {}",
                r.fingerprint,
                r.key_type,
                r.comment.as_deref().unwrap_or(""),
                r.tags.join(" ")
            )
            .to_lowercase();
            hay.contains(&q)
        })
        .collect()
}

#[allow(dead_code)]
pub fn host_id(id: Uuid) -> HostId {
    HostId(id)
}

/// Upsert SSH Hunter keys/placements from probe observations.
/// Returns how many authorized / host-key observations were applied.
pub async fn ingest_observations(
    store: &dyn Store,
    host_id: HostId,
    observations: &[Observation],
    seen_at: &str,
) -> usize {
    let mut n = 0usize;
    for obs in observations {
        let applied = match obs {
            Observation::AuthorizedKey(k) => {
                if k.fingerprint.trim().is_empty() {
                    continue;
                }
                store
                    .upsert_ssh_placement(UpsertSshPlacement {
                        fingerprint: k.fingerprint.clone(),
                        key_type: k.key_type.clone(),
                        bits: k.bits,
                        comment: k.comment.clone(),
                        host_id,
                        username: if k.username.trim().is_empty() {
                            "(unknown)".into()
                        } else {
                            k.username.clone()
                        },
                        path: k.path.to_string_lossy(),
                        role: "authorized".into(),
                        options: k.options.clone(),
                        seen_at: Some(seen_at.to_string()),
                        tags: Vec::new(),
                    })
                    .await
                    .is_ok()
            }
            Observation::SshHostKey(k) => {
                if k.fingerprint.trim().is_empty() {
                    continue;
                }
                store
                    .upsert_ssh_placement(UpsertSshPlacement {
                        fingerprint: k.fingerprint.clone(),
                        key_type: k.key_type.clone(),
                        bits: None,
                        comment: None,
                        host_id,
                        username: "(host)".into(),
                        path: k.path.to_string_lossy(),
                        role: "host".into(),
                        options: Vec::new(),
                        seen_at: Some(seen_at.to_string()),
                        tags: vec!["host-key".into()],
                    })
                    .await
                    .is_ok()
            }
            _ => false,
        };
        if applied {
            n = n.saturating_add(1);
        }
    }
    n
}

/// Rebuild SSH Hunter graph from stored observations when the graph is empty
/// (e.g. after upgrade before live ingest was wired).
pub async fn backfill_from_store(
    store: &dyn Store,
    obs_limit: usize,
    seen_at: &str,
) -> Result<usize, rustmite_store::StoreError> {
    let existing = store.list_ssh_keys().await?.len();
    if existing > 0 {
        return Ok(0);
    }
    let rows = store.list_observations(None, obs_limit).await?;
    let mut by_host: BTreeMap<Uuid, Vec<Observation>> = BTreeMap::new();
    for row in rows {
        match &row.data {
            Observation::AuthorizedKey(_) | Observation::SshHostKey(_) => {
                by_host.entry(row.host_id.0).or_default().push(row.data);
            }
            _ => {}
        }
    }
    let mut total = 0usize;
    for (hid, obs) in by_host {
        total = total.saturating_add(ingest_observations(store, HostId(hid), &obs, seen_at).await);
    }
    Ok(total)
}

/// Seed Sandfly-style default zones when none exist yet.
pub async fn ensure_default_zones(store: &dyn Store) -> Result<usize, rustmite_store::StoreError> {
    if !store.list_ssh_zones().await?.is_empty() {
        return Ok(0);
    }
    let zones = [
        (
            "Production",
            "Prod / gold hosts",
            vec!["prod", "gold"],
            vec!["deploy", "host-key"],
            "alert_on_cross_zone",
        ),
        (
            "Bastion / Jump",
            "Jump hosts and admin workstations",
            vec!["bastion", "dev-workstation"],
            vec!["shared", "critical"],
            "allow",
        ),
        (
            "Legacy / Weak",
            "Deprecated RSA and weak keys",
            vec!["legacy-centos"],
            vec!["legacy", "weak", "deprecated"],
            "deny_unknown",
        ),
    ];
    for (name, desc, selectors, tags, policy) in zones {
        store
            .upsert_ssh_zone(UpsertSshZone {
                id: None,
                name: name.into(),
                description: desc.into(),
                host_selectors: selectors.into_iter().map(str::to_string).collect(),
                key_tags: tags.into_iter().map(str::to_string).collect(),
                policy: policy.into(),
            })
            .await?;
    }
    Ok(3)
}
