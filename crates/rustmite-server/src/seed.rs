//! Large-scale demo fleet seeding for the operator console.

use std::collections::BTreeMap;

use rustmite_checks::CheckEngine;
use rustmite_proto::{
    Arch, CheckId, CheckType, Confidence, DeliveryReport, Finding, FindingId, FindingStatus,
    HostId, NodeId, ObservationRef, ScanMeta, ScanOutcome, Severity,
};
use rustmite_store::{
    CompleteScan, EnqueueScan, InMemoryStore, NodeRegistration, Store, UpsertHost,
    UpsertSshPlacement, UpsertSshZone,
};
use uuid::Uuid;

/// How many hosts to create when `--seed-demo` is set (override with `--seed-hosts`).
pub const DEFAULT_SEED_HOSTS: usize = 3_000;

#[derive(Clone, Copy)]
struct Profile {
    id: &'static str,
    role: &'static str,
    env: &'static str,
    region: &'static str,
    /// Relative weight in the fleet mix.
    weight: u32,
    /// Chance (0–100) this host has at least one finding.
    finding_pct: u32,
    /// Typical last scan outcome label.
    default_outcome: &'static str,
}

const PROFILES: &[Profile] = &[
    Profile {
        id: "clean-web",
        role: "web",
        env: "prod",
        region: "eu-west",
        weight: 22,
        finding_pct: 2,
        default_outcome: "complete",
    },
    Profile {
        id: "clean-db",
        role: "database",
        env: "prod",
        region: "eu-west",
        weight: 12,
        finding_pct: 3,
        default_outcome: "complete",
    },
    Profile {
        id: "clean-app",
        role: "app",
        env: "prod",
        region: "us-east",
        weight: 14,
        finding_pct: 4,
        default_outcome: "complete",
    },
    Profile {
        id: "staging-mix",
        role: "app",
        env: "staging",
        region: "us-east",
        weight: 10,
        finding_pct: 12,
        default_outcome: "complete",
    },
    Profile {
        id: "dev-workstation",
        role: "dev",
        env: "dev",
        region: "us-west",
        weight: 8,
        finding_pct: 18,
        default_outcome: "complete",
    },
    Profile {
        id: "legacy-centos",
        role: "legacy",
        env: "prod",
        region: "eu-central",
        weight: 6,
        finding_pct: 35,
        default_outcome: "complete",
    },
    Profile {
        id: "container-host",
        role: "k8s-node",
        env: "prod",
        region: "us-east",
        weight: 8,
        finding_pct: 10,
        default_outcome: "complete",
    },
    Profile {
        id: "bastion",
        role: "bastion",
        env: "prod",
        region: "eu-west",
        weight: 2,
        finding_pct: 20,
        default_outcome: "complete",
    },
    Profile {
        id: "lab-rootkit",
        role: "rootkit-lab",
        env: "lab",
        region: "lab",
        weight: 1,
        finding_pct: 100,
        default_outcome: "complete",
    },
    Profile {
        id: "compromised",
        role: "web",
        env: "prod",
        region: "ap-south",
        weight: 2,
        finding_pct: 100,
        default_outcome: "complete",
    },
    Profile {
        id: "cred-risk",
        role: "auth",
        env: "prod",
        region: "us-east",
        weight: 3,
        finding_pct: 80,
        default_outcome: "complete",
    },
    Profile {
        id: "drift-heavy",
        role: "config",
        env: "prod",
        region: "eu-west",
        weight: 4,
        finding_pct: 70,
        default_outcome: "complete",
    },
    Profile {
        id: "edge-appliance",
        role: "appliance",
        env: "edge",
        region: "edge",
        weight: 4,
        finding_pct: 15,
        default_outcome: "complete",
    },
    Profile {
        id: "unreachable",
        role: "unknown",
        env: "prod",
        region: "us-east",
        weight: 4,
        finding_pct: 0,
        default_outcome: "unreachable",
    },
];

fn pick_profile(i: usize) -> &'static Profile {
    let total: u32 = PROFILES.iter().map(|p| p.weight).sum();
    let mut slot = (mix(i) % total.max(1)) as u32;
    for p in PROFILES {
        if slot < p.weight {
            return p;
        }
        slot -= p.weight;
    }
    &PROFILES[0]
}

/// Deterministic mix function (not cryptographic).
fn mix(mut x: usize) -> u32 {
    x = x.wrapping_mul(0x9E37_79B9).wrapping_add(0x7F4A_7C15);
    x ^= x >> 16;
    x as u32
}

fn pct_hit(i: usize, salt: u32, pct: u32) -> bool {
    (mix(i.wrapping_add(salt as usize)) % 100) < pct
}

struct FindingSpec {
    check_id: &'static str,
    check_type: CheckType,
    severity: Severity,
    confidence: Confidence,
    title: String,
    evidence: serde_json::Map<String, serde_json::Value>,
    attack: Vec<&'static str>,
    kind: &'static str,
}

fn findings_for_profile(profile: &Profile, i: usize, host_name: &str) -> Vec<FindingSpec> {
    let mut out = Vec::new();
    if !pct_hit(i, 11, profile.finding_pct) && profile.finding_pct < 100 {
        return out;
    }

    match profile.id {
        "lab-rootkit" => {
            out.push(FindingSpec {
                check_id: "RM-PROC-0001",
                check_type: CheckType::Process,
                severity: Severity::Critical,
                confidence: Confidence::High,
                title: format!("Hidden process pid {} (kdevtmpfsi)", 30000 + (i % 1000)),
                evidence: map_json(&[
                    ("pid", serde_json::json!(30000 + (i % 1000))),
                    ("comm", serde_json::json!("kdevtmpfsi")),
                    ("host", serde_json::json!(host_name)),
                ]),
                attack: vec!["T1014"],
                kind: "hidden_process",
            });
            if pct_hit(i, 22, 60) {
                out.push(FindingSpec {
                    check_id: "RM-KERN-0001",
                    check_type: CheckType::Process,
                    severity: Severity::High,
                    confidence: Confidence::Medium,
                    title: "Suspicious kernel module / taint indicator".into(),
                    evidence: map_json(&[("module", serde_json::json!("diamorphine"))]),
                    attack: vec!["T1014"],
                    kind: "module",
                });
            }
        }
        "compromised" => {
            out.push(FindingSpec {
                check_id: "RM-FILE-0004",
                check_type: CheckType::File,
                severity: Severity::Critical,
                confidence: Confidence::High,
                title: "Integrity mismatch for /bin/ls".into(),
                evidence: map_json(&[
                    ("path", serde_json::json!("/bin/ls")),
                    ("package", serde_json::json!("coreutils")),
                ]),
                attack: vec!["T1554"],
                kind: "integrity_mismatch",
            });
            out.push(FindingSpec {
                check_id: "RM-PERSIST-0001",
                check_type: CheckType::File,
                severity: Severity::Critical,
                confidence: Confidence::High,
                title: "Non-empty /etc/ld.so.preload".into(),
                evidence: map_json(&[("path", serde_json::json!("/tmp/.x/lib.so"))]),
                attack: vec!["T1574.006"],
                kind: "preload",
            });
            if pct_hit(i, 33, 50) {
                out.push(FindingSpec {
                    check_id: "RM-PROC-0005",
                    check_type: CheckType::Process,
                    severity: Severity::High,
                    confidence: Confidence::High,
                    title: "Process executing from memfd".into(),
                    evidence: map_json(&[("exe", serde_json::json!("/memfd:payload"))]),
                    attack: vec!["T1620"],
                    kind: "process",
                });
            }
        }
        "cred-risk" => {
            out.push(FindingSpec {
                check_id: "RM-CRED-0001",
                check_type: CheckType::User,
                severity: Severity::High,
                confidence: Confidence::High,
                title: format!("Weak hash algorithm 'md5crypt' for account 'svc{i}'"),
                evidence: map_json(&[
                    ("username", serde_json::json!(format!("svc{i}"))),
                    ("algorithm", serde_json::json!("md5crypt")),
                ]),
                attack: vec!["T1110"],
                kind: "shadow_entry",
            });
            if pct_hit(i, 44, 40) {
                out.push(FindingSpec {
                    check_id: "RM-USER-0002",
                    check_type: CheckType::User,
                    severity: Severity::High,
                    confidence: Confidence::High,
                    title: "Passwordless account (empty shadow hash)".into(),
                    evidence: map_json(&[("username", serde_json::json!("guest"))]),
                    attack: vec!["T1078"],
                    kind: "shadow_entry",
                });
            }
        }
        "drift-heavy" => {
            out.push(FindingSpec {
                check_id: "RM-DRIFT-0001",
                check_type: CheckType::File,
                severity: Severity::High,
                confidence: Confidence::High,
                title: "Critical file drift / integrity mismatch for /etc/ssh/sshd_config".into(),
                evidence: map_json(&[("path", serde_json::json!("/etc/ssh/sshd_config"))]),
                attack: vec!["T1554"],
                kind: "integrity_mismatch",
            });
            if pct_hit(i, 55, 50) {
                out.push(FindingSpec {
                    check_id: "RM-USER-0004",
                    check_type: CheckType::User,
                    severity: Severity::Medium,
                    confidence: Confidence::Medium,
                    title: format!("New account 'ops{i}' vs baseline"),
                    evidence: map_json(&[("username", serde_json::json!(format!("ops{i}")))]),
                    attack: vec!["T1136"],
                    kind: "account",
                });
            }
        }
        "bastion" | "dev-workstation" => {
            out.push(FindingSpec {
                check_id: "RM-USER-0008",
                check_type: CheckType::User,
                severity: Severity::High,
                confidence: Confidence::Medium,
                title: format!(
                    "SSH authorized key for {} (SHA256:fleet-reuse-{:04x})",
                    if profile.id == "bastion" { "ubuntu" } else { "dev" },
                    mix(i) & 0xffff
                ),
                evidence: map_json(&[
                    ("username", serde_json::json!(if profile.id == "bastion" {
                        "ubuntu"
                    } else {
                        "dev"
                    })),
                    (
                        "fingerprint",
                        serde_json::json!(format!("SHA256:fleet-reuse-{:04x}", mix(i) & 0xffff)),
                    ),
                ]),
                attack: vec!["T1098.004"],
                kind: "authorized_key",
            });
        }
        "legacy-centos" => {
            out.push(FindingSpec {
                check_id: "RM-CRED-0005",
                check_type: CheckType::User,
                severity: Severity::Medium,
                confidence: Confidence::Medium,
                title: "Deprecated SSH key type ssh-rsa".into(),
                evidence: map_json(&[("key_type", serde_json::json!("ssh-rsa"))]),
                attack: vec!["T1110"],
                kind: "authorized_key",
            });
            if pct_hit(i, 66, 30) {
                out.push(FindingSpec {
                    check_id: "RM-NET-0003",
                    check_type: CheckType::Process,
                    severity: Severity::Medium,
                    confidence: Confidence::Low,
                    title: "Unexpected listening port vs allow-baseline".into(),
                    evidence: map_json(&[("port", serde_json::json!(4444 + (i % 50)))]),
                    attack: vec!["T1571"],
                    kind: "socket",
                });
            }
        }
        "container-host" => {
            if pct_hit(i, 77, 40) {
                out.push(FindingSpec {
                    check_id: "RM-POL-0032",
                    check_type: CheckType::Policy,
                    severity: Severity::Medium,
                    confidence: Confidence::Medium,
                    title: "Privileged container / docker.sock exposure indicator".into(),
                    evidence: map_json(&[("runtime", serde_json::json!("docker"))]),
                    attack: vec!["T1611"],
                    kind: "container",
                });
            }
        }
        "staging-mix" | "edge-appliance" | "clean-web" | "clean-db" | "clean-app" => {
            // Rare low-noise posture findings.
            if pct_hit(i, 88, profile.finding_pct.max(1)) {
                out.push(FindingSpec {
                    check_id: "RM-USER-0009",
                    check_type: CheckType::User,
                    severity: Severity::Medium,
                    confidence: Confidence::Low,
                    title: "authorized_keys with command= / missing from=".into(),
                    evidence: map_json(&[("username", serde_json::json!("deploy"))]),
                    attack: vec!["T1098.004"],
                    kind: "authorized_key",
                });
            }
        }
        _ => {}
    }
    out
}

fn map_json(pairs: &[(&str, serde_json::Value)]) -> serde_json::Map<String, serde_json::Value> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), v.clone()))
        .collect()
}

fn host_addr(i: usize, region: &str) -> String {
    let octet = match region {
        "eu-west" => 10,
        "eu-central" => 11,
        "us-east" => 20,
        "us-west" => 21,
        "ap-south" => 30,
        "lab" => 8,
        "edge" => 40,
        _ => 50,
    };
    format!(
        "10.{}.{}.{}",
        octet,
        (i / 254) % 254 + 1,
        (i % 254) + 1
    )
}

fn kernel_for(profile: &Profile, i: usize) -> String {
    match profile.id {
        "legacy-centos" => format!("3.10.0-{}", 1000 + (i % 200)),
        "edge-appliance" => "4.19.0-rt".into(),
        "lab-rootkit" => "6.1.0-lab".into(),
        "container-host" => "6.5.0-cloud".into(),
        _ => {
            let minors = [1, 2, 5, 6, 8];
            format!("6.{}.0", minors[i % minors.len()])
        }
    }
}

/// Seed a multi-profile fleet for console simulation.
pub async fn seed_demo(
    store: &InMemoryStore,
    checks: &CheckEngine,
    host_count: usize,
) -> anyhow::Result<()> {
    let host_count = host_count.max(1);
    tracing::info!(host_count, profiles = PROFILES.len(), "seeding demo fleet");

    // Nodes across regions / queues (Sandfly-style named queues).
    let node_specs = [
        ("node-eu-west-a", 64, "eu-west"),
        ("node-eu-west-b", 64, "eu-west"),
        ("node-us-east-a", 96, "us-east"),
        ("node-us-west-a", 48, "us-west"),
        ("node-lab", 16, "lab"),
        ("node-edge", 24, "edge"),
    ];
    let mut nodes = Vec::new();
    for (name, cap, _region) in node_specs {
        let id = NodeId::new_v4();
        store
            .register_node(NodeRegistration {
                id,
                name: name.into(),
                capacity: cap,
                version: "0.1.0".into(),
            })
            .await?;
        nodes.push(id);
    }

    let mut hosts: Vec<(HostId, &'static Profile, String)> = Vec::with_capacity(host_count);
    let mut profile_counts: BTreeMap<&str, usize> = BTreeMap::new();

    for i in 0..host_count {
        let profile = pick_profile(i);
        *profile_counts.entry(profile.id).or_default() += 1;
        let seq = profile_counts[&profile.id];
        let display_name = format!("{}-{}-{:04}", profile.id, profile.region, seq);
        let addr = host_addr(i, profile.region);
        let mut labels = BTreeMap::from([
            ("env".into(), profile.env.into()),
            ("role".into(), profile.role.into()),
            ("profile".into(), profile.id.into()),
            ("region".into(), profile.region.into()),
            ("os".into(), match profile.id {
                "legacy-centos" => "centos7",
                "edge-appliance" => "yocto",
                "container-host" => "ubuntu2204",
                "lab-rootkit" => "ubuntu2204",
                _ if i % 3 == 0 => "ubuntu2204",
                _ if i % 3 == 1 => "rhel9",
                _ => "debian12",
            }.into()),
            ("kernel".into(), kernel_for(profile, i)),
            ("tier".into(), match profile.env {
                "prod" => "gold",
                "staging" => "silver",
                "lab" | "dev" => "bronze",
                _ => "bronze",
            }.into()),
        ]);
        if profile.id == "unreachable" {
            labels.insert("status".into(), "inactive".into());
        }

        let host = store
            .upsert_host(UpsertHost {
                id: None,
                tenant_id: Uuid::nil(),
                display_name: display_name.clone(),
                primary_addr: Some(addr),
                ssh_port: Some(if profile.id == "edge-appliance" {
                    2222
                } else {
                    22
                }),
                labels,
                timeouts: Default::default(),
                agent_kind: None,
                ingest_token: None,
            })
            .await?;
        hosts.push((host.id, profile, display_name));

        if (i + 1) % 500 == 0 {
            tracing::info!(created = i + 1, host_count, "host seed progress");
        }
    }

    // Scans + findings: every host with findings gets a completed scan; sample clean hosts too.
    let mut findings_batch: Vec<Finding> = Vec::new();
    let mut scans_done = 0usize;
    let mut findings_total = 0usize;
    let applicable = checks.len() as u32;

    for (idx, (host_id, profile, name)) in hosts.iter().enumerate() {
        let specs = findings_for_profile(profile, idx, name);
        let should_scan = !specs.is_empty()
            || profile.default_outcome != "complete"
            || pct_hit(idx, 99, 8); // ~8% clean hosts still show recent scan coverage

        if !should_scan {
            continue;
        }

        let node = nodes[idx % nodes.len()];
        let job = store
            .enqueue_scan(EnqueueScan {
                host_id: *host_id,
                check_set: if profile.env == "lab" {
                    "incident".into()
                } else if pct_hit(idx, 3, 15) {
                    "deep".into()
                } else {
                    "standard".into()
                },
                priority: if specs.iter().any(|s| matches!(s.severity, Severity::Critical)) {
                    200
                } else {
                    100
                },
            })
            .await?;
        // Mark leased then complete (lease may no-op if capacity exhausted — still complete).
        let _ = store.lease_jobs(node, 1).await;

        let fired = specs.len() as u32;
        for (seq, spec) in specs.into_iter().enumerate() {
            findings_batch.push(Finding {
                id: FindingId::new_v7(),
                scan_id: job.id,
                host_id: *host_id,
                check_id: CheckId::new(spec.check_id),
                check_version: 1,
                check_type: spec.check_type,
                severity: spec.severity,
                confidence: spec.confidence,
                title: spec.title,
                evidence: spec.evidence,
                observation_ref: ObservationRef {
                    scan_id: job.id,
                    seq: seq as u32,
                    kind: spec.kind.into(),
                },
                attack: spec.attack.iter().map(|s| (*s).to_string()).collect(),
                first_seen: format!("2026-09-{:02}T{:02}:{:02}:00Z", 1 + (idx % 14), idx % 24, idx % 60),
                last_seen: format!("2026-09-15T{:02}:{:02}:00Z", idx % 24, idx % 60),
                status: if pct_hit(idx, 5, 10) {
                    FindingStatus::Acknowledged
                } else {
                    FindingStatus::New
                },
                suppressed_by: None,
                correlation_id: None,
            });
            findings_total += 1;
        }

        if findings_batch.len() >= 400 {
            store.insert_findings(std::mem::take(&mut findings_batch)).await?;
        }

        let outcome = profile.default_outcome;
        let meta = ScanMeta {
            scan_id: job.id,
            host_id: *host_id,
            node_id: node,
            outcome: match outcome {
                "unreachable" => ScanOutcome::Unreachable {
                    reason: "connection timed out".into(),
                },
                "host_key_changed" => ScanOutcome::HostKeyChanged {
                    expected: "SHA256:old".into(),
                    got: "SHA256:new".into(),
                },
                _ => ScanOutcome::Complete,
            },
            delivery: DeliveryReport::default(),
            probe_version: "0.1.0".into(),
            arch: if profile.id == "edge-appliance" && idx % 2 == 0 {
                Arch::Aarch64
            } else {
                Arch::X86_64
            },
            kernel: kernel_for(profile, idx),
            os: Some(match profile.id {
                "edge-appliance" => "Custom Linux".into(),
                "unreachable" => "Unknown".into(),
                _ => "Ubuntu 22.04 LTS".into(),
            }),
            os_id: Some(match profile.id {
                "edge-appliance" => "custom".into(),
                _ => "ubuntu".into(),
            }),
            os_version: Some("22.04".into()),
            boot_id: format!("boot-{idx}"),
            caps: Default::default(),
            collectors: vec![],
            applicable_checks: applicable,
            fired,
            not_applicable: if profile.id == "edge-appliance" { 12 } else { 0 },
            started_at: format!("2026-09-15T{:02}:00:00Z", idx % 24),
            finished_at: format!("2026-09-15T{:02}:00:{:02}Z", idx % 24, 5 + (idx % 40)),
            duration_ms: 3_000 + (mix(idx) % 20_000) as u64,
            bytes_from_probe: 2_000 + (mix(idx) % 80_000) as u64,
            observation_count: 50 + (mix(idx) % 5_000),
            node_signature: None,
        };
        store
            .complete_scan(CompleteScan {
                scan_id: job.id,
                meta,
                outcome: outcome.into(),
            })
            .await?;
        scans_done += 1;
    }

    if !findings_batch.is_empty() {
        store.insert_findings(findings_batch).await?;
    }

    // Leave a live queue so the console shows scanning-in-progress immediately.
    let mut live = 0usize;
    for (idx, (host_id, profile, _)) in hosts.iter().enumerate() {
        if live >= 10 {
            break;
        }
        if !matches!(
            profile.id,
            "clean-web" | "clean-app" | "staging-mix" | "container-host"
        ) {
            continue;
        }
        if idx % 41 != 0 {
            continue;
        }
        if store
            .enqueue_scan(EnqueueScan {
                host_id: *host_id,
                check_set: "standard".into(),
                priority: 180,
            })
            .await
            .is_ok()
        {
            live += 1;
        }
    }

    let ssh_stats = seed_ssh_hunter(store, &hosts).await?;

    tracing::info!(
        hosts = host_count,
        scans = scans_done,
        findings = findings_total,
        nodes = nodes.len(),
        live_queued = live,
        ssh_keys = ssh_stats.0,
        ssh_placements = ssh_stats.1,
        profiles = ?profile_counts,
        "demo fleet ready"
    );
    Ok(())
}

/// Build a Sandfly-style SSH Hunter graph for the demo fleet.
async fn seed_ssh_hunter(
    store: &InMemoryStore,
    hosts: &[(HostId, &Profile, String)],
) -> anyhow::Result<(usize, usize)> {
    // Shared "stolen" fleet keys reused across bastions / workstations.
    let shared = [
        ("SHA256:fleet-reuse-admin", "ssh-ed25519", "admin@laptop", "shared", "critical"),
        ("SHA256:fleet-reuse-ci", "ssh-ed25519", "ci-bot@github", "ci", "shared"),
        ("SHA256:fleet-reuse-vendor", "ecdsa-sha2-nistp256", "vendor-support", "vendor", "external"),
    ];
    let mut placements = 0usize;

    for (idx, (host_id, profile, _)) in hosts.iter().enumerate() {
        let env_tag = profile.env;
        let profile_tag = profile.id;

        // Host key for every scanned-ish host.
        if idx % 3 != 2 {
            store
                .upsert_ssh_placement(UpsertSshPlacement {
                    fingerprint: format!("SHA256:hostkey-{:04x}", mix(idx) & 0xffff),
                    key_type: "ssh-ed25519".into(),
                    bits: Some(256),
                    comment: Some(format!("host key {}", profile.id)),
                    host_id: *host_id,
                    username: "(host)".into(),
                    path: "/etc/ssh/ssh_host_ed25519_key.pub".into(),
                    role: "host".into(),
                    options: vec![],
                    seen_at: Some(format!(
                        "2026-09-{:02}T12:00:00Z",
                        1 + (idx % 14)
                    )),
                    tags: vec!["host-key".into(), env_tag.into()],
                })
                .await?;
            placements += 1;
        }

        match profile.id {
            "bastion" | "dev-workstation" => {
                let (fp, kt, comment, tag_a, tag_b) = shared[idx % shared.len()];
                let user = if profile.id == "bastion" { "ubuntu" } else { "dev" };
                store
                    .upsert_ssh_placement(UpsertSshPlacement {
                        fingerprint: format!("{fp}-{:04x}", mix(idx) & 0xffff),
                        key_type: kt.into(),
                        bits: Some(if kt.starts_with("ssh-rsa") { 2048 } else { 256 }),
                        comment: Some(comment.into()),
                        host_id: *host_id,
                        username: user.into(),
                        path: format!("/home/{user}/.ssh/authorized_keys"),
                        role: "authorized".into(),
                        options: if idx % 5 == 0 {
                            vec!["command=\"/bin/bash\"".into()]
                        } else {
                            vec![]
                        },
                        seen_at: Some(format!(
                            "2026-09-15T{:02}:00:00Z",
                            idx % 24
                        )),
                        tags: vec![
                            tag_a.into(),
                            tag_b.into(),
                            profile_tag.into(),
                            env_tag.into(),
                        ],
                    })
                    .await?;
                placements += 1;

                // Same shared admin key on every 4th bastion → cross-host reuse.
                if idx % 4 == 0 {
                    store
                        .upsert_ssh_placement(UpsertSshPlacement {
                            fingerprint: "SHA256:fleet-reuse-admin".into(),
                            key_type: "ssh-ed25519".into(),
                            bits: Some(256),
                            comment: Some("admin@laptop".into()),
                            host_id: *host_id,
                            username: user.into(),
                            path: format!("/home/{user}/.ssh/authorized_keys"),
                            role: "authorized".into(),
                            options: vec![],
                            seen_at: Some("2026-09-14T08:00:00Z".into()),
                            tags: vec![
                                "shared".into(),
                                "critical".into(),
                                "lateral".into(),
                                env_tag.into(),
                            ],
                        })
                        .await?;
                    placements += 1;
                }
            }
            "legacy-centos" => {
                store
                    .upsert_ssh_placement(UpsertSshPlacement {
                        fingerprint: format!("SHA256:legacy-rsa-{:04x}", mix(idx) & 0xffff),
                        key_type: "ssh-rsa".into(),
                        bits: Some(1024),
                        comment: Some("legacy-admin".into()),
                        host_id: *host_id,
                        username: "root".into(),
                        path: "/root/.ssh/authorized_keys".into(),
                        role: "authorized".into(),
                        options: vec![],
                        seen_at: Some("2026-08-01T00:00:00Z".into()),
                        tags: vec!["legacy".into(), "weak".into(), "deprecated".into()],
                    })
                    .await?;
                placements += 1;
            }
            "cred-risk" | "compromised" => {
                store
                    .upsert_ssh_placement(UpsertSshPlacement {
                        fingerprint: format!("SHA256:new-key-{:04x}", mix(idx) & 0xffff),
                        key_type: "ssh-ed25519".into(),
                        bits: Some(256),
                        comment: Some("unknown@attacker".into()),
                        host_id: *host_id,
                        username: "root".into(),
                        path: "/root/.ssh/authorized_keys".into(),
                        role: "authorized".into(),
                        options: vec![],
                        seen_at: Some("2026-09-15T18:00:00Z".into()),
                        tags: vec!["new".into(), "untrusted".into(), "incident".into()],
                    })
                    .await?;
                placements += 1;
            }
            "staging-mix" | "clean-web" | "clean-app" | "clean-db" if pct_hit(idx, 17, 25) => {
                store
                    .upsert_ssh_placement(UpsertSshPlacement {
                        fingerprint: format!("SHA256:deploy-{:04x}", mix(idx) & 0xffff),
                        key_type: "ssh-ed25519".into(),
                        bits: Some(256),
                        comment: Some("deploy@ci".into()),
                        host_id: *host_id,
                        username: "deploy".into(),
                        path: "/home/deploy/.ssh/authorized_keys".into(),
                        role: "authorized".into(),
                        options: vec!["from=\"10.0.0.0/8\"".into()],
                        seen_at: Some(format!("2026-09-10T{:02}:00:00Z", idx % 24)),
                        tags: vec!["deploy".into(), env_tag.into(), profile_tag.into()],
                    })
                    .await?;
                placements += 1;
            }
            _ => {}
        }
    }

    // Default security zones (Sandfly SSH Hunter).
    store
        .upsert_ssh_zone(UpsertSshZone {
            id: None,
            name: "Production".into(),
            description: "Prod hosts; shared/vendor keys should not appear".into(),
            host_selectors: vec!["prod".into(), "gold".into()],
            key_tags: vec!["deploy".into(), "host-key".into()],
            policy: "alert_on_cross_zone".into(),
        })
        .await?;
    store
        .upsert_ssh_zone(UpsertSshZone {
            id: None,
            name: "Bastion / Jump".into(),
            description: "Jump hosts and admin workstations".into(),
            host_selectors: vec!["bastion".into(), "dev-workstation".into()],
            key_tags: vec!["shared".into(), "critical".into()],
            policy: "allow".into(),
        })
        .await?;
    store
        .upsert_ssh_zone(UpsertSshZone {
            id: None,
            name: "Legacy / Weak".into(),
            description: "Deprecated RSA and weak keys".into(),
            host_selectors: vec!["legacy-centos".into()],
            key_tags: vec!["legacy".into(), "weak".into(), "deprecated".into()],
            policy: "deny_unknown".into(),
        })
        .await?;

    let keys = store.list_ssh_keys().await?.len();
    Ok((keys, placements))
}
