//! Live SSH scan path for the node.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use reqwest::Client;
use rustmite_checks::{CheckEngine, FindingDraft};
use rustmite_proto::{
    CheckId, CollectorSpec, Finding, FindingId, FindingStatus, HostId, Observation,
    ObservationRef, ProbeMode, ScanId,
};
use rustmite_transport::{
    remote_scan, HostKeyPolicy, HostKeyRecord, ProbeCatalog, RemoteScanOpts, SshTimeouts,
    TransportError, DEFAULT_LINUX_TARGETS,
};
use uuid::Uuid;

use crate::sign;
use crate::LeaseJob;

/// Fallback collectors when the lease has no server-resolved plan (docs/01 §8).
fn collectors_for_check_set(check_set: &str) -> Vec<CollectorSpec> {
    let pulse = vec![
        CollectorSpec::new("decloak.process"),
        CollectorSpec::new("process.inventory"),
        CollectorSpec::new("recon.inventory"),
    ];
    let standard = {
        let mut v = pulse.clone();
        v.extend([
            CollectorSpec::new("persistence.preload"),
            CollectorSpec::new("persistence.accounts"),
            CollectorSpec::new("modules.lkm"),
            CollectorSpec::new("net.sockets"),
            CollectorSpec::new("persistence.services"),
            CollectorSpec::new("persistence.scheduled"),
            CollectorSpec::new("ssh.keys"),
        ]);
        v
    };
    let deep = {
        let mut v = standard.clone();
        v.extend([
            CollectorSpec::new("file.integrity"),
            CollectorSpec::new("file.ioc"),
            CollectorSpec::new("entropy"),
            CollectorSpec::new("dir.hidden"),
            CollectorSpec::new("log.integrity"),
            CollectorSpec::new("modules.ebpf"),
            CollectorSpec::new("cred.audit"),
            CollectorSpec::new("session.inventory"),
            CollectorSpec::new("mounts.inventory"),
            CollectorSpec::new("container.inventory"),
        ]);
        v
    };
    match check_set {
        "pulse" => pulse,
        "deep" | "incident" => deep,
        _ => standard, // standard + unknown
    }
}

fn collectors_for_job(job: &LeaseJob) -> Vec<CollectorSpec> {
    if !job.collectors.is_empty() {
        return job
            .collectors
            .iter()
            .map(|id| CollectorSpec::new(id))
            .collect();
    }
    collectors_for_check_set(&job.check_set)
}

fn check_set_deadline_secs(check_set: &str) -> Option<u64> {
    Some(match check_set {
        "pulse" => 60,
        "deep" | "incident" => 600,
        _ => 120,
    })
}

fn chrono_like_now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| time::OffsetDateTime::now_utc().to_string())
}

fn chrono_like_ago_ms(ms: u64) -> String {
    let t = time::OffsetDateTime::now_utc() - time::Duration::milliseconds(ms as i64);
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| t.to_string())
}

pub struct LiveOpts {
    /// Explicit single probe (overrides catalog).
    pub probe: Option<PathBuf>,
    pub loader: Option<PathBuf>,
    /// Extra search root for multi-arch probes (in addition to defaults).
    pub probe_dir: Option<PathBuf>,
    pub identity: Option<PathBuf>,
    pub ssh_user: String,
    pub checks: PathBuf,
    pub tofu: bool,
    /// Node private key used to open RMBOX1 credential boxes from the lease.
    pub cred_key: std::sync::Arc<rustmite_crypto::CredPrivateKey>,
}

async fn report_progress(
    client: &Client,
    server: &str,
    node_id: Uuid,
    scan_id: Uuid,
    stage: &str,
    pct: u8,
) {
    report_progress_state(client, server, node_id, scan_id, stage, pct, "running").await;
}

async fn report_progress_state(
    client: &Client,
    server: &str,
    node_id: Uuid,
    scan_id: Uuid,
    stage: &str,
    pct: u8,
    state: &str,
) {
    let url = format!("{}/v1/nodes/progress", server.trim_end_matches('/'));
    let _ = client
        .post(&url)
        .json(&serde_json::json!({
            "scan_id": scan_id,
            "node_id": node_id,
            "stage": stage,
            "pct": pct,
            "state": state,
            "message": stage,
        }))
        .send()
        .await;
}

pub async fn run_live_job(
    client: &Client,
    server: &str,
    node_id: Uuid,
    job: &LeaseJob,
    opts: LiveOpts,
) -> Result<()> {
    let host = job
        .primary_addr
        .clone()
        .ok_or_else(|| anyhow::anyhow!("lease job missing primary_addr"))?;
    let port = job.ssh_port.unwrap_or(22);
    let username = job
        .ssh_user
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| opts.ssh_user.clone());

    report_progress(client, server, node_id, job.id, "ssh connect / resolve credentials", 5).await;

    let password_file = job.ssh_password_file.as_deref();
    let identity_path = job
        .ssh_identity
        .as_ref()
        .map(PathBuf::from)
        .or_else(|| opts.identity.clone());
    let auth = job.ssh_auth.as_deref().unwrap_or("");
    let lease_password = open_lease_secret(
        &opts.cred_key,
        job.ssh_password_box.as_deref(),
        job.ssh_password.as_deref(),
    )?;
    let lease_pem = open_lease_secret(
        &opts.cred_key,
        job.ssh_identity_box.as_deref(),
        job.ssh_identity_pem.as_deref(),
    )?;

    // Prefer lease ciphertext (node-only decrypt). Fall back to local files / CLI identity.
    let password = if lease_password.is_some() || password_file.is_some() || auth == "password" {
        if let Some(pw) = lease_password {
            pw
        } else {
            let path = password_file
                .map(PathBuf::from)
                .ok_or_else(|| anyhow::anyhow!("ssh_password_file required for password auth"))?;
            open_secret_file(&opts.cred_key, &path)?
        }
    } else {
        String::new()
    };
    let identity_pem = if !password.is_empty() {
        None
    } else if let Some(pem) = lease_pem {
        Some(pem)
    } else if let Some(ref identity) = identity_path {
        if is_sealed_or_box_file(identity) {
            Some(open_secret_file(&opts.cred_key, identity)?)
        } else {
            None
        }
    } else {
        None
    };
    if !password.is_empty() && password.trim().is_empty() {
        bail!("ssh password is empty");
    }

    let credential = if !password.is_empty() {
        rustmite_transport::SshCredential::Password {
            password: &password,
        }
    } else if let Some(ref pem) = identity_pem {
        rustmite_transport::SshCredential::PublicKeyPem { pem }
    } else {
        let identity = identity_path.as_ref().ok_or_else(|| {
            anyhow::anyhow!("--identity / RUSTMITE_SSH_IDENTITY or host ssh_identity required")
        })?;
        rustmite_transport::SshCredential::PublicKey {
            identity: identity.as_path(),
        }
    };

    let sudo_enabled = job.ssh_sudo.unwrap_or(false);
    let sudo_mode = job
        .ssh_sudo_mode
        .as_deref()
        .unwrap_or(if !password.is_empty() {
            "ssh_password"
        } else {
            "nopasswd"
        })
        .to_ascii_lowercase();

    // Keep sudo password buffer alive for the RemoteScanOpts borrow below.
    let sudo_password_buf = if sudo_enabled && matches!(sudo_mode.as_str(), "password" | "sudo_password")
    {
        if let Some(pw) = open_lease_secret(
            &opts.cred_key,
            job.ssh_sudo_password_box.as_deref(),
            job.ssh_sudo_password.as_deref(),
        )? {
            Some(pw)
        } else {
            let path = job
                .ssh_sudo_password_file
                .as_ref()
                .map(PathBuf::from)
                .ok_or_else(|| {
                    anyhow::anyhow!("ssh_sudo_password_file required when ssh_sudo_mode=password")
                })?;
            let pw = open_secret_file(&opts.cred_key, &path)?;
            if pw.is_empty() {
                bail!("sudo password file {} is empty", path.display());
            }
            Some(pw)
        }
    } else {
        None
    };

    let sudo = if !sudo_enabled {
        rustmite_transport::SudoEscalation::None
    } else {
        match sudo_mode.as_str() {
            "nopasswd" | "n" | "-n" => rustmite_transport::SudoEscalation::Nopasswd,
            "ssh_password" | "reuse" => {
                if password.is_empty() {
                    bail!(
                        "ssh_sudo_mode=ssh_password requires password SSH auth (or set ssh_sudo_password_file)"
                    );
                }
                rustmite_transport::SudoEscalation::Password {
                    password: &password,
                }
            }
            "password" | "sudo_password" => rustmite_transport::SudoEscalation::Password {
                password: sudo_password_buf.as_deref().unwrap_or(""),
            },
            other => bail!("unknown ssh_sudo_mode '{other}' (use nopasswd|ssh_password|password)"),
        }
    };

    let mut roots = rustmite_transport::default_search_roots();
    if let Some(dir) = &opts.probe_dir {
        roots.insert(0, dir.clone());
    }
    let catalog = if opts.probe.is_none() {
        let cat = ProbeCatalog::discover(DEFAULT_LINUX_TARGETS, &roots);
        if cat.is_empty() {
            bail!(
                "no agentless probes found — build with `cargo xtask build-probes --all` or pass --probe"
            );
        }
        Some(cat)
    } else {
        None
    };

    let probe_elf = match &opts.probe {
        Some(p) => std::fs::read(p).with_context(|| format!("read probe {}", p.display()))?,
        None => Vec::new(),
    };
    let loader_elf = match &opts.loader {
        Some(p) => Some(std::fs::read(p).with_context(|| format!("read loader {}", p.display()))?),
        None => None,
    };

    let policy = if let Some(fp) = &job.host_key_fingerprint {
        HostKeyPolicy {
            pinned: vec![HostKeyRecord {
                key_type: job
                    .host_key_type
                    .clone()
                    .unwrap_or_else(|| "ssh-ed25519".into()),
                fingerprint: fp.clone(),
            }],
            allow_tofu: false,
        }
    } else {
        HostKeyPolicy {
            pinned: vec![],
            allow_tofu: opts.tofu,
        }
    };

    let timeouts = SshTimeouts::default()
        .overlay(
            job.ssh_connect_delay_ms,
            job.ssh_connect_timeout_secs,
            job.ssh_auth_timeout_secs,
            job.ssh_cmd_timeout_secs,
            job.ssh_inactivity_timeout_secs,
            job.ssh_delivery_timeout_secs,
        )
        .with_jitter(job.ssh_timeout_jitter_pct);
    let deadline_ms = job
        .scan_timeout_secs
        .or_else(|| check_set_deadline_secs(&job.check_set))
        .unwrap_or(120)
        .saturating_mul(1000)
        .min(u64::from(u32::MAX)) as u32;
    let limits = job.probe_limits.clone().unwrap_or_default();

    let collectors = collectors_for_job(job);
    report_progress(client, server, node_id, job.id, &format!("ssh connect {host}:{port} as {username}"), 12).await;
    if sudo.is_enabled() {
        report_progress(
            client,
            server,
            node_id,
            job.id,
            &format!("sudo escalate ({})", sudo.label()),
            15,
        )
        .await;
    }
    report_progress(
        client,
        server,
        node_id,
        job.id,
        &format!("check set {} ({} collectors)", job.check_set, collectors.len()),
        18,
    )
    .await;
    report_progress(client, server, node_id, job.id, "deliver / exec agentless probe", 25).await;

    let scan = match remote_scan(RemoteScanOpts {
        host: &host,
        port,
        username: &username,
        credential,
        policy,
        probe_elf: &probe_elf,
        loader_elf: loader_elf.as_deref(),
        probe_catalog: catalog.as_ref(),
        collectors,
        mode: ProbeMode::Scan,
        deadline_ms,
        limits,
        timeouts,
        sudo,
    })
    .await
    {
        Ok(s) => s,
        Err(TransportError::HostKeyChanged { expected, got }) => {
            report_progress(client, server, node_id, job.id, "host key changed — abort", 100).await;
            post_host_key_failure(client, server, node_id, job, &expected, &got).await?;
            return Ok(());
        }
        Err(e) => {
            report_progress(
                client,
                server,
                node_id,
                job.id,
                &format!("scan failed: {e}"),
                100,
            )
            .await;
            return Err(e.into());
        }
    };

    if let (Some(arch), Some(triple)) = (&scan.probe_arch, &scan.probe_triple) {
        tracing::info!(%arch, %triple, host = %host, "selected agentless probe for host");
        report_progress(
            client,
            server,
            node_id,
            job.id,
            &format!("probe selected ({triple})"),
            55,
        )
        .await;
    } else {
        report_progress(client, server, node_id, job.id, "stream observations", 55).await;
    }

    let observations: Vec<Observation> = scan
        .normalised
        .observations
        .iter()
        .map(|(_, _, o)| o.clone())
        .collect();

    let delivery_label = format!("{:?}", scan.delivery.method).to_ascii_lowercase();
    let obs_n = observations.len();
    report_progress(
        client,
        server,
        node_id,
        job.id,
        &format!(
            "evaluate checks ({obs_n} observations, delivery={delivery_label}{})",
            scan
                .delivery
                .fallback_reason
                .as_ref()
                .map(|r| format!(", fallback={r}"))
                .unwrap_or_default()
        ),
        80,
    )
    .await;

    if obs_n == 0 {
        let stderr_tail: String = {
            let s = scan.raw_stderr.trim();
            if s.len() <= 800 {
                s.to_string()
            } else {
                s[s.len() - 800..].to_string()
            }
        };
        report_progress(
            client,
            server,
            node_id,
            job.id,
            &format!(
                "probe returned 0 observations (delivery={delivery_label}); stderr={}",
                if stderr_tail.is_empty() {
                    "(empty)"
                } else {
                    stderr_tail.as_str()
                }
            ),
            100,
        )
        .await;
        bail!(
            "probe returned 0 observations (delivery={delivery_label}, stdout_bytes={}, stderr={})",
            scan.raw_stdout.len(),
            if stderr_tail.is_empty() {
                "(empty)"
            } else {
                stderr_tail.as_str()
            }
        );
    }

    let engine = CheckEngine::from_dir(&opts.checks)
        .with_context(|| format!("load checks {}", opts.checks.display()))?;
    let drafts = if job.check_ids.is_empty() {
        engine.evaluate(&observations)
    } else {
        let allow: std::collections::HashSet<&str> =
            job.check_ids.iter().map(|s| s.as_str()).collect();
        engine.evaluate_filtered(&observations, Some(&allow))
    };
    let findings = drafts_to_findings(drafts, ScanId(job.id), HostId(job.host_id));

    report_progress(
        client,
        server,
        node_id,
        job.id,
        &format!("post results ({} findings, {obs_n} observations)", findings.len()),
        92,
    )
    .await;

    let signature = sign::sign_payload(&serde_json::to_vec(&findings)?);
    let hello = scan.normalised.hello.as_ref();
    let summary = scan.normalised.summary.as_ref();
    let finished_at = chrono_like_now();
    let duration_ms = summary.map(|s| s.elapsed_ms).unwrap_or(0);
    let started_at = if duration_ms > 0 {
        // Approximate wall start from probe elapsed.
        chrono_like_ago_ms(duration_ms)
    } else {
        finished_at.clone()
    };
    let (outcome_flat, outcome_typed) =
        rustmite_node::outcome_from_normalised(&scan.normalised.outcome, obs_n);
    if outcome_flat != "complete" {
        report_progress(
            client,
            server,
            node_id,
            job.id,
            &format!("agent outcome={outcome_flat}"),
            90,
        )
        .await;
    }

    let url = format!("{}/v1/nodes/results", server.trim_end_matches('/'));
    client
        .post(&url)
        .json(&serde_json::json!({
            "scan_id": job.id,
            "host_id": job.host_id,
            "node_id": node_id,
            "outcome": outcome_flat,
            "findings": findings,
            "observations": observations,
            "presented_host_key": scan.presented_host_key.as_ref().map(|hk| serde_json::json!({
                "key_type": hk.key_type,
                "fingerprint": hk.fingerprint,
            })),
            "meta": {
                "scan_id": job.id,
                "host_id": job.host_id,
                "node_id": node_id,
                "outcome": outcome_typed,
                "delivery": {
                    "method": delivery_label,
                    "encoder": scan.delivery.encoder,
                    "bytes_transferred": scan.delivery.bytes_transferred,
                    "cleanup_ok": scan.delivery.cleanup_ok,
                    "cleanup_forced": false,
                    "fallback_reason": scan.delivery.fallback_reason,
                },
                "probe_version": hello.map(|h| h.probe_version.clone()).unwrap_or_default(),
                "arch": scan.probe_arch.clone().unwrap_or_else(|| format!("{:?}", scan.fingerprint.arch).to_ascii_lowercase()),
                "kernel": hello.map(|h| h.kernel.clone()).unwrap_or_else(|| scan.fingerprint.kernel.clone()),
                "os": scan.fingerprint.os.clone(),
                "os_id": scan.fingerprint.os_id.clone(),
                "os_version": scan.fingerprint.os_version.clone(),
                "boot_id": hello.map(|h| h.boot_id.clone()).unwrap_or_default(),
                "caps": hello.map(|h| serde_json::to_value(&h.caps).unwrap_or(serde_json::json!({}))).unwrap_or_else(|| serde_json::json!({
                    "memfd_create": false, "statx": false, "sock_diag": false, "bpf_prog_iter": false,
                    "map_files": false, "cgroup_v2": false, "kallsyms_readable": false,
                    "tracefs_readable": false, "proc_sched_debug": false, "audit_netlink": false,
                    "proc_exe_readable": false
                })),
                "collectors": summary.map(|s| &s.collectors).unwrap_or(&Vec::new()),
                "applicable_checks": 0,
                "fired": findings.len(),
                "not_applicable": 0,
                "started_at": started_at,
                "finished_at": finished_at,
                "duration_ms": duration_ms,
                "bytes_from_probe": scan.raw_stdout.len() as u64,
                "observation_count": obs_n,
                "node_signature": signature,
            },
        }))
        .send()
        .await?
        .error_for_status()?;

    // Must not post state=running after complete_scan — that re-opens the job
    // and blocks the next scan (one active scan per host).
    report_progress_state(client, server, node_id, job.id, "complete", 100, "complete").await;
    Ok(())
}

fn drafts_to_findings(drafts: Vec<FindingDraft>, scan_id: ScanId, host_id: HostId) -> Vec<Finding> {
    let now = time::OffsetDateTime::now_utc().to_string();
    drafts
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
        .collect()
}

async fn post_host_key_failure(
    client: &Client,
    server: &str,
    node_id: Uuid,
    job: &LeaseJob,
    expected: &str,
    got: &str,
) -> Result<()> {
    let now = time::OffsetDateTime::now_utc().to_string();
    let scan_id = ScanId(job.id);
    let host_id = HostId(job.host_id);
    let finding = Finding {
        id: FindingId::new_v7(),
        scan_id,
        host_id,
        check_id: CheckId("RM-TRANSPORT-HOSTKEY".into()),
        check_version: 1,
        check_type: rustmite_proto::CheckType::Policy,
        severity: rustmite_proto::Severity::Critical,
        confidence: rustmite_proto::Confidence::High,
        title: "SSH host key changed".into(),
        evidence: {
            let mut m = serde_json::Map::new();
            m.insert("expected".into(), serde_json::json!(expected));
            m.insert("got".into(), serde_json::json!(got));
            m
        },
        observation_ref: ObservationRef {
            scan_id,
            seq: 0,
            kind: "hostkey".into(),
        },
        attack: vec!["T1557".into()],
        first_seen: now.clone(),
        last_seen: now,
        status: FindingStatus::New,
        suppressed_by: None,
        correlation_id: None,
    };
    let url = format!("{}/v1/nodes/results", server.trim_end_matches('/'));
    client
        .post(&url)
        .json(&serde_json::json!({
            "scan_id": job.id,
            "host_id": job.host_id,
            "node_id": node_id,
            "outcome": "failed",
            "findings": [finding],
            "observations": [],
            "probe_version": "",
            "signature": "",
        }))
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

fn is_sealed_or_box_file(path: &std::path::Path) -> bool {
    std::fs::read(path)
        .map(|b| {
            rustmite_crypto::is_cred_box(&b) || b.starts_with(rustmite_crypto::SEALED_MAGIC)
        })
        .unwrap_or(false)
}

fn open_lease_secret(
    key: &rustmite_crypto::CredPrivateKey,
    box_b64: Option<&str>,
    plaintext: Option<&str>,
) -> Result<Option<String>> {
    if let Some(b64) = box_b64.map(str::trim).filter(|s| !s.is_empty()) {
        let raw = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            b64,
        )
        .context("decode credential box")?;
        let opened = rustmite_crypto::open_for_node(key, &raw)
            .context("decrypt credential box (wrong node key?)")?;
        let s = String::from_utf8_lossy(&opened)
            .trim_end_matches(['\r', '\n'])
            .to_string();
        return Ok(if s.is_empty() { None } else { Some(s) });
    }
    Ok(plaintext
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string))
}

fn open_secret_file(
    key: &rustmite_crypto::CredPrivateKey,
    path: &std::path::Path,
) -> Result<String> {
    let raw = std::fs::read(path).with_context(|| format!("read credential {}", path.display()))?;
    let opened = if rustmite_crypto::is_cred_box(&raw) {
        rustmite_crypto::open_for_node(key, &raw)
            .with_context(|| format!("decrypt credential box {}", path.display()))?
    } else if raw.starts_with(rustmite_crypto::SEALED_MAGIC) {
        bail!(
            "credential {} uses legacy shared-vault seal — re-upload after starting a node (Sandfly-style node-only boxes)"
            , path.display()
        );
    } else {
        // Plaintext local identity path (CLI --identity).
        zeroize::Zeroizing::new(raw)
    };
    Ok(String::from_utf8_lossy(&opened)
        .trim_end_matches(['\r', '\n'])
        .to_string())
}
