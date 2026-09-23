//! Background scan-progress simulator for the operator console (demo / lab).

use std::sync::Arc;
use std::time::Duration;

use rustmite_proto::{
    Arch, CheckId, CheckType, Confidence, DeliveryReport, Finding, FindingId, FindingStatus,
    ObservationRef, ScanMeta, ScanOutcome, Severity,
};
use rustmite_store::{CompleteScan, EnqueueScan, InMemoryStore, NodeRegistration, Store};
use uuid::Uuid;

const STAGES: &[&str] = &[
    "ssh connect / host-key verify",
    "fingerprint arch + kernel",
    "deliver stage0 loader (memfd)",
    "exec probe from anonymous fd",
    "collector: decloak.process",
    "collector: process.inventory",
    "collector: net.sockets",
    "collector: persistence.preload",
    "collector: ssh.keys",
    "collector: file.integrity",
    "stream NDJSON observations",
    "node normalise + sign results",
    "server evaluate checks",
];

const SIM_NODE_NAME: &str = "scan-sim";

/// Continuously lease queued jobs and emit stage-by-stage progress logs.
pub fn spawn_scan_simulator(store: Arc<InMemoryStore>) {
    tokio::spawn(async move {
        let mut tick: u64 = 0;
        loop {
            tokio::time::sleep(Duration::from_millis(900)).await;
            tick = tick.wrapping_add(1);
            if let Err(e) = sim_tick(&store, tick).await {
                tracing::debug!(error = %e, "scan simulator tick");
            }
        }
    });
}

async fn ensure_sim_node(store: &InMemoryStore) -> anyhow::Result<rustmite_proto::NodeId> {
    let nodes = store.list_nodes().await?;
    if let Some(n) = nodes.iter().find(|n| n.name == SIM_NODE_NAME) {
        return Ok(n.id);
    }
    let id = rustmite_proto::NodeId::new_v4();
    store
        .register_node(NodeRegistration {
            id,
            name: SIM_NODE_NAME.into(),
            capacity: 8,
            version: "sim".into(),
        })
        .await?;
    store
        .push_activity(rustmite_store::ActivityEvent {
            id: Uuid::nil(),
            ts: String::new(),
            level: "info".into(),
            kind: "node.sim".into(),
            message: "Scan simulator registered".into(),
            scan_id: None,
            host_id: None,
            node_id: Some(id),
            detail: None,
        })
        .await?;
    Ok(id)
}

fn host_is_live_ssh(h: &rustmite_store::HostRecord) -> bool {
    let labels = &h.labels;
    labels.contains_key("ssh_password_file")
        || labels.contains_key("ssh_identity")
        || labels
            .get("ssh_auth")
            .map(|v| v == "password" || v == "publickey")
            .unwrap_or(false)
}

async fn host_name(store: &InMemoryStore, host_id: rustmite_proto::HostId) -> String {
    store
        .get_host(host_id)
        .await
        .ok()
        .map(|h| h.display_name)
        .unwrap_or_else(|| host_id.to_string())
}

async fn sim_tick(store: &InMemoryStore, tick: u64) -> anyhow::Result<()> {
    if tick % 8 == 0 {
        top_up_queue(store).await?;
    }

    let sim_nid = ensure_sim_node(store).await?;
    let nodes = store.list_nodes().await?;
    let has_live_node = nodes.iter().any(|n| n.name != SIM_NODE_NAME);
    let hosts = store.list_hosts().await?;
    let host_live = |id: rustmite_proto::HostId| {
        hosts
            .iter()
            .find(|h| h.id == id)
            .map(host_is_live_ssh)
            .unwrap_or(false)
    };

    let snap = store.queue_snapshot().await?;

    // Warn on credentialed hosts stuck without a live scanner.
    if tick % 5 == 0 {
        for job in snap.active.iter().filter(|j| j.state == "queued") {
            if host_live(job.host_id) && !has_live_node {
                let name = host_name(store, job.host_id).await;
                store
                    .update_scan_progress(
                        job.id,
                        "queued",
                        Some("waiting for scanner node"),
                        Some(0),
                    )
                    .await?;
                store
                    .push_activity(rustmite_store::ActivityEvent {
                        id: Uuid::nil(),
                        ts: String::new(),
                        level: "warn".into(),
                        kind: "scan.waiting_node".into(),
                        message: format!(
                            "{name}: queued — start a live scanner node \
                             (`cargo run -p rustmite-node -- --server https://127.0.0.1:18443` \
                             or ./dev.sh with NODE=1)"
                        ),
                        scan_id: Some(job.id),
                        host_id: Some(job.host_id),
                        node_id: None,
                        detail: None,
                    })
                    .await?;
            }
        }
    }

    // Lease only demo (non-credentialed) jobs for the simulator.
    let demo_queued = snap
        .active
        .iter()
        .filter(|j| j.state == "queued" && !host_live(j.host_id))
        .count();
    if demo_queued > 0 {
        // Lease one-at-a-time; if we accidentally pick a live job, requeue it.
        for _ in 0..demo_queued.min(3) {
            let leased = store.lease_jobs(sim_nid, 1).await?;
            for job in leased {
                if host_live(job.host_id) {
                    store
                        .update_scan_progress(
                            job.id,
                            "queued",
                            Some(if has_live_node {
                                "queued for live node"
                            } else {
                                "waiting for scanner node"
                            }),
                            Some(0),
                        )
                        .await?;
                }
            }
        }
    }

    let snap = store.queue_snapshot().await?;
    for job in snap.active {
        // Only advance jobs owned by the simulator.
        if job.leased_by != Some(sim_nid) {
            continue;
        }
        if host_live(job.host_id) {
            continue;
        }
        match job.state.as_str() {
            "leased" => {
                let name = host_name(store, job.host_id).await;
                store
                    .update_scan_progress(job.id, "running", Some(STAGES[0]), Some(8))
                    .await?;
                store
                    .push_activity(rustmite_store::ActivityEvent {
                        id: Uuid::nil(),
                        ts: String::new(),
                        level: "progress".into(),
                        kind: "scan.progress".into(),
                        message: format!("{name}: {}", STAGES[0]),
                        scan_id: Some(job.id),
                        host_id: Some(job.host_id),
                        node_id: job.leased_by,
                        detail: Some(serde_json::json!({ "pct": 8, "stage": STAGES[0] })),
                    })
                    .await?;
            }
            "running" => {
                let pct = job.progress_pct.unwrap_or(8).saturating_add(7).min(96);
                let idx = ((pct as usize) / 8).min(STAGES.len() - 1);
                let name = host_name(store, job.host_id).await;
                if pct >= 96 {
                    finish_scan(store, &job).await?;
                } else {
                    store
                        .update_scan_progress(job.id, "running", Some(STAGES[idx]), Some(pct))
                        .await?;
                    store
                        .push_activity(rustmite_store::ActivityEvent {
                            id: Uuid::nil(),
                            ts: String::new(),
                            level: "progress".into(),
                            kind: "scan.progress".into(),
                            message: format!("{name}: {} ({pct}%)", STAGES[idx]),
                            scan_id: Some(job.id),
                            host_id: Some(job.host_id),
                            node_id: job.leased_by,
                            detail: Some(serde_json::json!({ "pct": pct, "stage": STAGES[idx] })),
                        })
                        .await?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

async fn top_up_queue(store: &InMemoryStore) -> anyhow::Result<()> {
    let snap = store.queue_snapshot().await?;
    let active = snap.queued + snap.leased + snap.running;
    if active >= 12 {
        return Ok(());
    }
    let hosts = store.list_hosts().await?;
    let need = 12usize.saturating_sub(active).min(4);
    let mut added = 0usize;
    for (i, h) in hosts.iter().enumerate() {
        if added >= need {
            break;
        }
        let profile = h.labels.get("profile").map(|s| s.as_str()).unwrap_or("");
        if !matches!(
            profile,
            "clean-web" | "clean-db" | "clean-app" | "staging-mix" | "container-host"
        ) {
            continue;
        }
        if i % 17 != (added * 3) % 17 {
            continue;
        }
        match store
            .enqueue_scan(EnqueueScan {
                host_id: h.id,
                check_set: if added % 3 == 0 {
                    "incident".into()
                } else {
                    "standard".into()
                },
                priority: 120 + added as i32,
            })
            .await
        {
            Ok(_) => added += 1,
            Err(_) => continue,
        }
    }
    Ok(())
}

async fn finish_scan(
    store: &InMemoryStore,
    job: &rustmite_store::ScanJob,
) -> anyhow::Result<()> {
    use rustmite_store::ActivityEvent;

    let host = store.get_host(job.host_id).await.ok();
    let host_label = host
        .as_ref()
        .map(|h| h.display_name.as_str())
        .unwrap_or("host");
    let profile = host
        .as_ref()
        .and_then(|h| h.labels.get("profile"))
        .cloned()
        .unwrap_or_default();

    let mut findings = Vec::new();
    if matches!(profile.as_str(), "compromised" | "lab-rootkit" | "cred-risk")
        || (job.check_set == "incident" && profile.contains("clean") && job.attempts % 5 == 0)
    {
        findings.push(Finding {
            id: FindingId::new_v7(),
            scan_id: job.id,
            host_id: job.host_id,
            check_id: CheckId::new("RM-PROC-0001"),
            check_version: 1,
            check_type: CheckType::Process,
            severity: Severity::High,
            confidence: Confidence::Medium,
            title: format!("Live scan hit on {host_label}"),
            evidence: serde_json::Map::from_iter([
                ("check_set".into(), serde_json::json!(job.check_set)),
                ("stage".into(), serde_json::json!("server evaluate checks")),
            ]),
            observation_ref: ObservationRef {
                scan_id: job.id,
                seq: 0,
                kind: "hidden_process".into(),
            },
            attack: vec!["T1014".into()],
            first_seen: String::new(),
            last_seen: String::new(),
            status: FindingStatus::New,
            suppressed_by: None,
            correlation_id: None,
        });
    }

    let fired = findings.len() as u32;
    if !findings.is_empty() {
        store.insert_findings(findings).await?;
        store
            .push_activity(ActivityEvent {
                id: Uuid::nil(),
                ts: String::new(),
                level: "warn".into(),
                kind: "finding.emitted".into(),
                message: format!("{host_label}: {fired} finding(s) emitted from scan {}", job.id),
                scan_id: Some(job.id),
                host_id: Some(job.host_id),
                node_id: job.leased_by,
                detail: None,
            })
            .await?;
    }

    let meta = ScanMeta {
        scan_id: job.id,
        host_id: job.host_id,
        node_id: job.leased_by.unwrap_or_else(rustmite_proto::NodeId::new_v4),
        outcome: ScanOutcome::Complete,
        delivery: DeliveryReport::default(),
        probe_version: "0.1.0".into(),
        arch: Arch::X86_64,
        kernel: "sim".into(),
            os: None,
            os_id: None,
            os_version: None,
        boot_id: "sim".into(),
        caps: Default::default(),
        collectors: vec![],
        applicable_checks: 57,
        fired,
        not_applicable: 0,
        started_at: String::new(),
        finished_at: String::new(),
        duration_ms: 4_000,
        bytes_from_probe: 12_000,
        observation_count: 80,
        node_signature: None,
    };
    store
        .complete_scan(CompleteScan {
            scan_id: job.id,
            meta,
            outcome: "complete".into(),
        })
        .await?;
    store
        .push_activity(ActivityEvent {
            id: Uuid::nil(),
            ts: String::new(),
            level: "info".into(),
            kind: "scan.complete".into(),
            message: format!("{host_label}: scan complete ({fired} findings)"),
            scan_id: Some(job.id),
            host_id: Some(job.host_id),
            node_id: job.leased_by,
            detail: None,
        })
        .await?;
    Ok(())
}
