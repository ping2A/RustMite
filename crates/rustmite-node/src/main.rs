//! Scanner node: lease jobs from the control plane and post results.
#![forbid(unsafe_code)]

mod fixture_scan;
mod live_scan;
mod sign;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::sync::Semaphore;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(name = "rustmite-node", about = "RustMite scanner node")]
struct Args {
    #[arg(long, default_value = "https://127.0.0.1:18443")]
    server: String,

    /// Allow cleartext `http://` to the control plane (dev only). Agent traffic must
    /// normally be TLS — omit this / set `RUSTMITE_ALLOW_INSECURE=0`.
    #[arg(long, default_value_t = false, env = "RUSTMITE_ALLOW_INSECURE")]
    allow_insecure: bool,

    #[arg(long)]
    node_id: Option<Uuid>,

    #[arg(long, default_value_t = 4)]
    capacity: usize,

    /// Run collectors against a local fixture tree instead of live SSH
    #[arg(long)]
    fixture_mode: bool,

    #[arg(long, default_value = "fixtures/diamorphine-hidden-pid")]
    fixture: PathBuf,

    #[arg(long, default_value_t = 2)]
    poll_secs: u64,

    /// Path to a single Linux musl rustmite-probe (optional — omit to auto-pick by host arch)
    #[arg(long, env = "RUSTMITE_PROBE")]
    probe: Option<PathBuf>,

    #[arg(long, env = "RUSTMITE_LOADER")]
    loader: Option<PathBuf>,

    /// Extra probe search root (with defaults under target/ and .dev/probes/)
    #[arg(long, env = "RUSTMITE_PROBE_DIR")]
    probe_dir: Option<PathBuf>,

    /// Default SSH identity for hosts without a per-host key
    #[arg(long, env = "RUSTMITE_SSH_IDENTITY")]
    identity: Option<PathBuf>,

    #[arg(long, env = "RUSTMITE_SSH_USER", default_value = "rustmite")]
    ssh_user: String,

    #[arg(long, default_value = "checks")]
    checks: PathBuf,

    /// Path to X25519 credential *private* key (hex). Auto-generated with matching
    /// `.pub` beside it for the server. Only this node can decrypt sealed SSH secrets.
    #[arg(long, default_value = rustmite_crypto::DEFAULT_CRED_PRIV_PATH, env = "RUSTMITE_CRED_KEY")]
    cred_key: PathBuf,

    /// Where to write/read the matching public key (server loads this or receives it on register).
    #[arg(long, default_value = rustmite_crypto::DEFAULT_CRED_PUB_PATH, env = "RUSTMITE_CRED_PUBKEY")]
    cred_pubkey: PathBuf,

    /// Allow TOFU when host has no pinned key
    #[arg(long, default_value_t = true)]
    tofu: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let args = Args::parse();
    if args.server.starts_with("http://") && !args.allow_insecure {
        anyhow::bail!(
            "refusing cleartext control-plane URL {} — use https:// (or pass --allow-insecure for local lab only)",
            args.server
        );
    }
    let cred_key = rustmite_crypto::CredPrivateKey::load_or_generate(&args.cred_key, &args.cred_pubkey)
        .with_context(|| {
            format!(
                "load/generate credential keypair {} / {}",
                args.cred_key.display(),
                args.cred_pubkey.display()
            )
        })?;
    let cred_pub = cred_key.public_key();
    tracing::info!(
        priv_path = %args.cred_key.display(),
        pub_path = %args.cred_pubkey.display(),
        fingerprint = %cred_pub.to_hex(),
        "credential decrypt key ready (SSH secrets sealed to this public key)"
    );
    let cred_key = Arc::new(cred_key);
    let node_id = args.node_id.unwrap_or_else(Uuid::new_v4);
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .danger_accept_invalid_certs(true) // local lab: control-plane may use auto TLS
        .timeout(Duration::from_secs(120))
        .build()?;

    register(
        &client,
        &args.server,
        node_id,
        args.capacity,
        &cred_pub.to_hex(),
    )
    .await?;
    tracing::info!(
        %node_id,
        server = %args.server,
        fixture_mode = args.fixture_mode,
        "node registered"
    );

    let sem = Arc::new(Semaphore::new(args.capacity));
    let mut host_locks: HashMap<Uuid, Arc<Semaphore>> = HashMap::new();

    loop {
        heartbeat(&client, &args.server, node_id, 0).await.ok();
        let jobs = lease(&client, &args.server, node_id, args.capacity)
            .await
            .unwrap_or_default();
        if jobs.is_empty() {
            tokio::time::sleep(Duration::from_secs(args.poll_secs)).await;
            continue;
        }
        for job in jobs {
            let permit = sem.clone().acquire_owned().await?;
            let host_sem = host_locks
                .entry(job.host_id)
                .or_insert_with(|| Arc::new(Semaphore::new(1)))
                .clone();
            let host_permit = host_sem.acquire_owned().await?;

            let client = client.clone();
            let server = args.server.clone();
            let fixture = args.fixture.clone();
            let fixture_mode = args.fixture_mode;
            let probe = args.probe.clone();
            let loader = args.loader.clone();
            let probe_dir = args.probe_dir.clone();
            let identity = args.identity.clone();
            let ssh_user = args.ssh_user.clone();
            let checks = args.checks.clone();
            let tofu = args.tofu;
            let cred_key = cred_key.clone();

            tokio::spawn(async move {
                let _permit = permit;
                let _host_permit = host_permit;
                let result = if fixture_mode {
                    run_fixture_job(&client, &server, node_id, &job, &fixture).await
                } else {
                    live_scan::run_live_job(
                        &client,
                        &server,
                        node_id,
                        &job,
                        live_scan::LiveOpts {
                            probe,
                            loader,
                            probe_dir,
                            identity,
                            ssh_user,
                            checks,
                            tofu,
                            cred_key,
                        },
                    )
                    .await
                };
                match result {
                    Ok(()) => tracing::info!(scan_id = %job.id, "job complete"),
                    Err(e) => {
                        tracing::error!(error = %e, scan_id = %job.id, "job failed");
                        let _ = post_job_failure(&client, &server, node_id, job.id, job.host_id, &e).await;
                    }
                }
            });
        }
    }
}

#[derive(Debug, serde::Deserialize)]
pub(crate) struct LeaseJob {
    id: Uuid,
    host_id: Uuid,
    check_set: String,
    #[serde(default)]
    primary_addr: Option<String>,
    #[serde(default)]
    ssh_port: Option<u16>,
    #[serde(default)]
    host_key_fingerprint: Option<String>,
    #[serde(default)]
    host_key_type: Option<String>,
    #[serde(default)]
    ssh_connect_timeout_secs: Option<u64>,
    #[serde(default)]
    ssh_auth_timeout_secs: Option<u64>,
    #[serde(default)]
    ssh_cmd_timeout_secs: Option<u64>,
    #[serde(default)]
    ssh_inactivity_timeout_secs: Option<u64>,
    #[serde(default)]
    ssh_delivery_timeout_secs: Option<u64>,
    #[serde(default)]
    ssh_connect_delay_ms: Option<u64>,
    #[serde(default)]
    scan_timeout_secs: Option<u64>,
    #[serde(default = "default_jitter")]
    ssh_timeout_jitter_pct: u8,
    #[serde(default)]
    ssh_user: Option<String>,
    #[serde(default)]
    ssh_auth: Option<String>,
    #[serde(default)]
    ssh_identity: Option<String>,
    /// Vault-unsealed PEM delivered over TLS lease (preferred).
    #[serde(default)]
    ssh_identity_pem: Option<String>,
    /// Node-sealed identity ciphertext (base64 RMBOX1) — decrypt with cred private key.
    #[serde(default)]
    ssh_identity_box: Option<String>,
    #[serde(default)]
    ssh_password_file: Option<String>,
    /// Vault-unsealed password delivered over TLS lease (preferred).
    #[serde(default)]
    ssh_password: Option<String>,
    /// Node-sealed password ciphertext (base64 RMBOX1).
    #[serde(default)]
    ssh_password_box: Option<String>,
    /// When true, run the agentless probe via sudo for root visibility.
    #[serde(default)]
    ssh_sudo: Option<bool>,
    /// `nopasswd` | `password` | `ssh_password` (reuse SSH password file).
    #[serde(default)]
    ssh_sudo_mode: Option<String>,
    #[serde(default)]
    ssh_sudo_password_file: Option<String>,
    #[serde(default)]
    ssh_sudo_password: Option<String>,
    #[serde(default)]
    ssh_sudo_password_box: Option<String>,
    /// Host scan preference: `ssh_commands` forces Method D (no probe binary).
    #[serde(default)]
    scan_mode: Option<String>,
    /// Host agent kind from the control plane (`ssh` | `agentlite` | `virtual`).
    #[serde(default)]
    agent_kind: Option<String>,
    /// Extra absolute paths for AgentLite file inventory (`collect_paths` host label).
    #[serde(default)]
    collect_paths: Option<String>,
    /// Collector IDs resolved from the configured check-set plan (server).
    #[serde(default)]
    collectors: Vec<String>,
    /// Check IDs enabled for this scan's check set (server).
    #[serde(default)]
    check_ids: Vec<String>,
    /// Probe resource envelope from the server (memory / CPU / bandwidth / caps).
    #[serde(default)]
    probe_limits: Option<rustmite_proto::Limits>,
}

fn default_jitter() -> u8 {
    10
}


async fn post_job_failure(
    client: &reqwest::Client,
    server: &str,
    node_id: Uuid,
    scan_id: Uuid,
    host_id: Uuid,
    err: &anyhow::Error,
) -> Result<()> {
    let report = rustmite_node::classify_job_error(err);
    let _ = client
        .post(format!("{}/v1/nodes/progress", server.trim_end_matches('/')))
        .json(&serde_json::json!({
            "scan_id": scan_id,
            "node_id": node_id,
            "stage": report.stage,
            "pct": 100,
            "state": "failed",
            "message": report.message,
        }))
        .send()
        .await;
    let url = format!("{}/v1/nodes/results", server.trim_end_matches('/'));
    client
        .post(&url)
        .json(&serde_json::json!({
            "scan_id": scan_id,
            "host_id": host_id,
            "node_id": node_id,
            "outcome": report.outcome,
            "findings": [],
            "observations": [],
            "probe_version": "",
            "signature": "",
            "meta": {
                "scan_id": scan_id,
                "host_id": host_id,
                "node_id": node_id,
                "outcome": report.scan_outcome,
                "delivery": {
                    "method": "tmpfs",
                    "encoder": "none",
                    "bytes_transferred": 0,
                    "cleanup_ok": true,
                    "cleanup_forced": false,
                    "fallback_reason": serde_json::Value::Null,
                },
                "probe_version": "",
                "arch": "unknown",
                "kernel": "",
                "boot_id": "",
                "caps": {},
                "collectors": [],
                "applicable_checks": 0,
                "fired": 0,
                "not_applicable": 0,
                "started_at": "",
                "finished_at": "",
                "duration_ms": 0,
                "bytes_from_probe": 0,
                "observation_count": 0,
                "node_signature": "",
            },
        }))
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

async fn register(
    client: &reqwest::Client,
    server: &str,
    node_id: Uuid,
    capacity: usize,
    cred_pubkey_hex: &str,
) -> Result<()> {
    let url = format!("{}/v1/nodes/register", server.trim_end_matches('/'));
    client
        .post(&url)
        .json(&serde_json::json!({
            "id": node_id,
            "name": format!("node-{node_id}"),
            "capacity": capacity as i32,
            "version": env!("CARGO_PKG_VERSION"),
            "cred_pubkey": cred_pubkey_hex,
        }))
        .send()
        .await
        .context("register")?
        .error_for_status()
        .context("register status")?;
    Ok(())
}

async fn lease(
    client: &reqwest::Client,
    server: &str,
    node_id: Uuid,
    capacity: usize,
) -> Result<Vec<LeaseJob>> {
    let url = format!("{}/v1/nodes/lease", server.trim_end_matches('/'));
    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "node_id": node_id,
            "capacity": capacity,
        }))
        .send()
        .await
        .context("lease")?;
    let jobs = resp.error_for_status()?.json().await?;
    Ok(jobs)
}

async fn heartbeat(
    client: &reqwest::Client,
    server: &str,
    node_id: Uuid,
    in_flight: i32,
) -> Result<()> {
    let url = format!("{}/v1/nodes/heartbeat", server.trim_end_matches('/'));
    client
        .post(&url)
        .json(&serde_json::json!({
            "node_id": node_id,
            "in_flight": in_flight,
        }))
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

async fn run_fixture_job(
    client: &reqwest::Client,
    server: &str,
    node_id: Uuid,
    job: &LeaseJob,
    fixture: &PathBuf,
) -> Result<()> {
    let result = fixture_scan::scan_fixture_for(
        fixture,
        rustmite_proto::ScanId(job.id),
        rustmite_proto::HostId(job.host_id),
    )?;
    let signature = sign::sign_payload(&serde_json::to_vec(&result.findings)?);
    let url = format!("{}/v1/nodes/results", server.trim_end_matches('/'));
    client
        .post(&url)
        .json(&serde_json::json!({
            "scan_id": job.id,
            "host_id": job.host_id,
            "node_id": node_id,
            "outcome": "complete",
            "observations": result.observations,
            "findings": result.findings,
            "meta": {
                "scan_id": job.id,
                "host_id": job.host_id,
                "node_id": node_id,
                "outcome": { "kind": "complete" },
                "delivery": {
                    "method": "pure_command",
                    "encoder": null,
                    "bytes_transferred": 0,
                    "cleanup_ok": true,
                    "cleanup_forced": false,
                    "fallback_reason": "fixture_mode"
                },
                "probe_version": "fixture",
                "arch": "unknown",
                "kernel": "",
                "boot_id": "",
                "caps": {
                    "memfd_create": false,
                    "statx": false,
                    "sock_diag": false,
                    "bpf_prog_iter": false,
                    "map_files": false,
                    "cgroup_v2": false,
                    "kallsyms_readable": false,
                    "tracefs_readable": false,
                    "proc_sched_debug": false,
                    "audit_netlink": false,
                    "proc_exe_readable": false
                },
                "collectors": [],
                "applicable_checks": 1,
                "fired": result.findings.len(),
                "not_applicable": 0,
                "started_at": "",
                "finished_at": "",
                "duration_ms": 0,
                "bytes_from_probe": 0,
                "observation_count": result.observations.len(),
                "node_signature": signature,
            }
        }))
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}
