//! Control-plane binary: operator API (:8080) and node API (:8443).
#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context};
use clap::Parser;
use rustmite_notify::WebhookSink;
use rustmite_server::{
    default_checks_dir, ensure_dev_certs, node_router, operator_router, seed_demo, serve_plain,
    serve_tls, spawn_host_health_checker, spawn_scan_scheduler, spawn_scan_simulator, AppState,
    CheckCatalog, MetricsHub,
    RuntimeSettings, TlsPaths,
    DEFAULT_SEED_HOSTS, DEFAULT_TLS_DIR,
};
use rustmite_store::{InMemoryStore, Store};
use rustmite_transport::{identity_fingerprint, NoiseKeypair};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(name = "rustmite-server", about = "RustMite control plane")]
struct Args {
    #[arg(long, default_value = "0.0.0.0:8080", env = "RUSTMITE_LISTEN")]
    listen: SocketAddr,

    #[arg(long, default_value = "0.0.0.0:8443", env = "RUSTMITE_NODE_LISTEN")]
    node_listen: SocketAddr,

    /// Enable TLS 1.3 (default on). When no cert/key are given, auto-generates a
    /// self-signed pair under `--tls-dir` (like ismyphonepwned / mimic-rs).
    #[arg(long, default_value_t = true, env = "RUSTMITE_TLS")]
    tls: bool,

    /// Disable TLS on the operator console only (cleartext HTTP). The node/agent
    /// listener always uses TLS 1.3 — secrets and scan traffic stay encrypted.
    #[arg(long, default_value_t = false, env = "RUSTMITE_NO_TLS")]
    no_tls: bool,

    /// Fleet credential encryption *public* key (hex file). Private key stays on nodes.
    /// Defaults to `.dev/vault/cred.pub` (written when a node registers / generates keys).
    #[arg(long, default_value = rustmite_crypto::DEFAULT_CRED_PUB_PATH, env = "RUSTMITE_CRED_PUBKEY")]
    cred_pubkey: PathBuf,

    /// Deprecated: shared vault master key is no longer used for SSH credentials
    /// (Sandfly-style node-only boxes). Kept for CLI compatibility.
    #[arg(long, default_value = rustmite_crypto::DEFAULT_MASTER_KEY_PATH, env = "RUSTMITE_VAULT_KEY_FILE")]
    vault_key_file: PathBuf,

    /// Directory for auto-generated `cert.pem` / `key.pem` when TLS is on and no
    /// explicit `--tls-cert`/`--tls-key` are provided.
    #[arg(long, default_value = DEFAULT_TLS_DIR, env = "RUSTMITE_TLS_DIR")]
    tls_dir: PathBuf,

    /// PEM certificate chain for the operator (and node, unless overridden) listener.
    #[arg(long, env = "RUSTMITE_TLS_CERT")]
    tls_cert: Option<PathBuf>,

    /// PEM private key for the operator (and node, unless overridden) listener.
    #[arg(long, env = "RUSTMITE_TLS_KEY")]
    tls_key: Option<PathBuf>,

    /// Optional PEM cert for the node listener (defaults to `--tls-cert` / auto).
    #[arg(long, env = "RUSTMITE_NODE_TLS_CERT")]
    node_tls_cert: Option<PathBuf>,

    /// Optional PEM key for the node listener (defaults to `--tls-key` / auto).
    #[arg(long, env = "RUSTMITE_NODE_TLS_KEY")]
    node_tls_key: Option<PathBuf>,

    /// PEM CA bundle; when set, the node listener requires client certs (mTLS).
    #[arg(long, env = "RUSTMITE_NODE_TLS_CLIENT_CA")]
    node_tls_client_ca: Option<PathBuf>,

    #[arg(long, default_value = "checks", env = "RUSTMITE_CHECKS")]
    checks: PathBuf,

    #[arg(long, env = "RUSTMITE_WEBHOOK_URL")]
    webhook_url: Option<String>,

    #[arg(long, env = "RUSTMITE_WEBHOOK_SECRET", default_value = "rustmite-dev-secret")]
    webhook_secret: String,

    #[arg(long, env = "RUSTMITE_SEED_DEMO", default_value_t = false)]
    seed_demo: bool,

    #[arg(long, env = "RUSTMITE_SEED_HOSTS", default_value_t = DEFAULT_SEED_HOSTS)]
    seed_hosts: usize,

    #[arg(long, env = "RUSTMITE_SCAN_SIM", default_value_t = true)]
    scan_sim: bool,

    #[arg(long, default_value = "standard", env = "RUSTMITE_DEFAULT_CHECK_SET")]
    default_check_set: String,

    #[arg(long, default_value = "1h", env = "RUSTMITE_SCAN_INTERVAL")]
    scan_interval: String,

    #[arg(long, default_value_t = 20, env = "RUSTMITE_SCAN_JITTER_PCT")]
    scan_jitter_pct: u8,

    #[arg(long, default_value_t = 32, env = "RUSTMITE_MAX_CONCURRENT_SCANS")]
    max_concurrent_scans: usize,

    #[arg(long, default_value_t = 120, env = "RUSTMITE_SCAN_TIMEOUT_SECS")]
    scan_timeout_secs: u64,

    /// Finished scans retained per host (newest kept).
    #[arg(long, default_value_t = 3, env = "RUSTMITE_SCAN_HISTORY_PER_HOST")]
    scan_history_per_host: usize,

    #[arg(long, default_value_t = 10, env = "RUSTMITE_SSH_CONNECT_TIMEOUT_SECS")]
    ssh_connect_timeout_secs: u64,

    #[arg(long, default_value_t = 20, env = "RUSTMITE_SSH_AUTH_TIMEOUT_SECS")]
    ssh_auth_timeout_secs: u64,

    #[arg(long, default_value_t = 60, env = "RUSTMITE_SSH_CMD_TIMEOUT_SECS")]
    ssh_cmd_timeout_secs: u64,

    #[arg(long, default_value_t = 90, env = "RUSTMITE_SSH_INACTIVITY_TIMEOUT_SECS")]
    ssh_inactivity_timeout_secs: u64,

    #[arg(long, default_value_t = 30, env = "RUSTMITE_SSH_DELIVERY_TIMEOUT_SECS")]
    ssh_delivery_timeout_secs: u64,

    #[arg(long, default_value_t = 10, env = "RUSTMITE_SSH_FINGERPRINT_TIMEOUT_SECS")]
    ssh_fingerprint_timeout_secs: u64,

    #[arg(long, default_value_t = 0, env = "RUSTMITE_SSH_CONNECT_DELAY_MS")]
    ssh_connect_delay_ms: u64,

    #[arg(long, default_value_t = 10, env = "RUSTMITE_SSH_TIMEOUT_JITTER_PCT")]
    ssh_timeout_jitter_pct: u8,

    #[arg(long, env = "RUSTMITE_CLICKHOUSE_URL")]
    clickhouse_url: Option<String>,

    #[arg(long, default_value_t = 30, env = "RUSTMITE_CLICKHOUSE_TIMEOUT_SECS")]
    clickhouse_timeout_secs: u64,

    #[arg(long, default_value_t = true, env = "RUSTMITE_NOISE_XX")]
    noise_xx: bool,

    /// JSON snapshot of hosts, findings, scans, and observations (survives restart).
    #[arg(long, default_value = ".dev/store.json", env = "RUSTMITE_STORE")]
    store: PathBuf,

    /// Ignore any existing snapshot and start with an empty control-plane store.
    #[arg(long, default_value_t = false, env = "RUSTMITE_RESET_STORE")]
    reset_store: bool,
}

fn resolve_tls(
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    client_ca: Option<PathBuf>,
    label: &str,
) -> anyhow::Result<Option<TlsPaths>> {
    match (cert, key) {
        (None, None) => {
            if client_ca.is_some() {
                bail!("{label}: --node-tls-client-ca requires TLS cert/key");
            }
            Ok(None)
        }
        (Some(cert), Some(key)) => {
            let mut paths = TlsPaths::new(cert, key);
            if let Some(ca) = client_ca {
                paths = paths.with_client_ca(ca);
            }
            Ok(Some(paths))
        }
        (Some(_), None) => bail!("{label}: TLS cert set but key missing"),
        (None, Some(_)) => bail!("{label}: TLS key set but cert missing"),
    }
}

fn resolve_operator_and_node_tls(args: &Args) -> anyhow::Result<(Option<TlsPaths>, Option<TlsPaths>)> {
    let tls_wanted = args.tls && !args.no_tls;
    let explicit = args.tls_cert.is_some() || args.tls_key.is_some();

    // Node ↔ agent channel is always TLS 1.3. Operator console may be cleartext for local
    // lab use (`--no-tls`), but the node listener still gets a cert (shared or auto).
    let operator = if let (Some(cert), Some(key)) = (&args.tls_cert, &args.tls_key) {
        Some(TlsPaths::new(cert.clone(), key.clone()))
    } else if tls_wanted || explicit {
        if explicit {
            resolve_tls(args.tls_cert.clone(), args.tls_key.clone(), None, "operator")?
        } else {
            Some(ensure_dev_certs(&args.tls_dir)?)
        }
    } else {
        None
    };

    let shared_cert = operator.as_ref().map(|p| p.cert.clone());
    let shared_key = operator.as_ref().map(|p| p.key.clone());
    let node_cert = args.node_tls_cert.clone().or(shared_cert);
    let node_key = args.node_tls_key.clone().or(shared_key);
    let mut node = match resolve_tls(
        node_cert,
        node_key,
        args.node_tls_client_ca.clone(),
        "node",
    )? {
        Some(paths) => Some(paths),
        None => {
            // Always encrypt the node API — generate/reuse certs under tls_dir.
            Some(ensure_dev_certs(&args.tls_dir)?)
        }
    };
    if let (Some(op), Some(ref mut n)) = (&operator, &mut node) {
        if n.cert == op.cert && n.key == op.key {
            n.auto_generated = op.auto_generated;
        }
    }
    if node.is_none() {
        bail!("node TLS is required for agent communication");
    }
    Ok((operator, node))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // axum-server may pull aws-lc-rs while the workspace prefers ring — pick explicitly.
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("install rustls CryptoProvider (ring)"))?;

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let args = Args::parse();
    let (operator_tls, node_tls) = resolve_operator_and_node_tls(&args)?;
    if let Some(ref tls) = operator_tls {
        if tls.auto_generated {
            tracing::warn!(
                cert = %tls.cert.display(),
                "TLS using auto-generated self-signed certificate (dev only; browsers will warn)"
            );
        }
    }

    let checks_dir = if args.checks.as_os_str() == "checks" && !args.checks.is_dir() {
        default_checks_dir()
    } else {
        args.checks.clone()
    };
    let checks = CheckCatalog::open(&checks_dir)
        .with_context(|| format!("load checks from {}", checks_dir.display()))?;
    tracing::info!(count = checks.len().await, path = %checks_dir.display(), "checks loaded");

    let webhook = args
        .webhook_url
        .as_ref()
        .map(|url| Arc::new(WebhookSink::new(url.clone(), args.webhook_secret.as_bytes())));

    let noise_kp = NoiseKeypair::generate().context("generate Noise XX server key")?;
    let noise_fp = identity_fingerprint(&noise_kp.public);
    if args.noise_xx {
        tracing::info!(fingerprint = %noise_fp, pattern = "Noise_XX_25519_ChaChaPoly_BLAKE2s", "Noise XX identity enabled");
    }

    let cred_pubkey = if args.cred_pubkey.is_file() {
        match rustmite_crypto::CredPublicKey::load_file(&args.cred_pubkey) {
            Ok(pk) => {
                tracing::info!(
                    path = %args.cred_pubkey.display(),
                    fingerprint = %pk.to_hex(),
                    "credential encryption public key loaded (node-only decrypt)"
                );
                Some(pk)
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    path = %args.cred_pubkey.display(),
                    "failed to load cred pubkey — waiting for scanner node register"
                );
                None
            }
        }
    } else {
        tracing::info!(
            path = %args.cred_pubkey.display(),
            "no credential public key yet — start rustmite-node to publish one before uploading SSH secrets"
        );
        None
    };
    let cred_pubkey = Arc::new(tokio::sync::RwLock::new(cred_pubkey));
    let _ = &args.vault_key_file; // deprecated for SSH creds

    // Propagate ClickHouse URL into env for ClickHouseClient::from_env if passed via flag.
    if let Some(ref url) = args.clickhouse_url {
        std::env::set_var("RUSTMITE_CLICKHOUSE_URL", url);
    }
    std::env::set_var(
        "RUSTMITE_CLICKHOUSE_TIMEOUT_SECS",
        args.clickhouse_timeout_secs.to_string(),
    );

    // Connect ClickHouse first — it is the durable control-plane backend.
    let clickhouse = rustmite_server::clickhouse::ClickHouseClient::from_env();
    let mut clickhouse_url_effective = args.clickhouse_url.clone();
    let clickhouse = if let Some(ch) = clickhouse {
        clickhouse_url_effective = Some(ch.base_url().to_string());
        match ch
            .wait_ready(30, std::time::Duration::from_millis(500))
            .await
        {
            Ok(()) => {
                tracing::info!(url = ch.base_url(), db = ch.database(), "ClickHouse connected");
                if let Err(e) = ch.ensure_control_plane_schema().await {
                    tracing::warn!(error = %e, "ClickHouse control-plane schema ensure failed");
                }
                if args.seed_demo {
                    match ch.seed_demo_events(args.seed_hosts.min(40)).await {
                        Ok(0) => tracing::info!("ClickHouse already has events — skip seed"),
                        Ok(n) => tracing::info!(rows = n, "ClickHouse demo events seeded"),
                        Err(e) => tracing::warn!(error = %e, "ClickHouse demo seed failed"),
                    }
                }
                Some(ch)
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    url = ch.base_url(),
                    "ClickHouse not reachable — falling back to local JSON store (.dev/store.json)"
                );
                None
            }
        }
    } else {
        tracing::info!("ClickHouse disabled (RUSTMITE_CLICKHOUSE=0) — using local JSON store");
        None
    };

    if args.reset_store {
        if let Some(ref ch) = clickhouse {
            ch.reset_control_plane()
                .await
                .context("reset ClickHouse control-plane store")?;
            tracing::warn!("ClickHouse control-plane store reset (cp_entities truncated)");
        }
        if args.store.exists() {
            std::fs::remove_file(&args.store)
                .with_context(|| format!("remove store {}", args.store.display()))?;
            tracing::warn!(path = %args.store.display(), "local JSON store reset");
        }
    }

    // Working set is always in-memory; durable backend is ClickHouse when available.
    let (store, clickhouse_arc) = if let Some(ch) = clickhouse {
        let ch = Arc::new(ch);
        let store = Arc::new(InMemoryStore::new());

        match ch.load_control_plane().await {
            Ok(Some(snap)) => {
                let hosts = snap.hosts.len();
                let findings = snap.findings.len();
                store
                    .import_snapshot(snap)
                    .context("import ClickHouse control-plane snapshot")?;
                tracing::info!(
                    hosts,
                    findings,
                    db = ch.database(),
                    "control-plane store loaded from ClickHouse"
                );
                // One-shot cleanup: old modules.lkm compared every /sys/module entry
                // (including built-ins like 8250) and flooded RM-KERN-0001. Only purge when
                // the store still looks like that flood (>10 hits); real alerts stay.
                let stale_kern = store
                    .list_findings(rustmite_store::FindingFilter {
                        host_id: None,
                        severity: None,
                        check_id: Some("RM-KERN-0001".into()),
                        limit: 50,
                    })
                    .await
                    .map(|v| v.len())
                    .unwrap_or(0);
                if stale_kern > 10 {
                    match store.clear_findings_by_checks(&["RM-KERN-0001"]).await {
                        Ok(n) => tracing::info!(
                            purged = n,
                            check = "RM-KERN-0001",
                            "purged stale hidden-module findings (built-in /sys/module FPs)"
                        ),
                        Err(e) => tracing::warn!(
                            error = %e,
                            "failed to purge stale RM-KERN-0001 findings"
                        ),
                    }
                }
                // Non-root fd walks left every listener "unowned" → RM-NET-0002 flood.
                let stale_net = store
                    .list_findings(rustmite_store::FindingFilter {
                        host_id: None,
                        severity: None,
                        check_id: Some("RM-NET-0002".into()),
                        limit: 50,
                    })
                    .await
                    .map(|v| v.len())
                    .unwrap_or(0);
                if stale_net > 10 {
                    match store.clear_findings_by_checks(&["RM-NET-0002"]).await {
                        Ok(n) => tracing::info!(
                            purged = n,
                            check = "RM-NET-0002",
                            "purged stale orphan-listener findings (non-root fd-walk FPs)"
                        ),
                        Err(e) => tracing::warn!(
                            error = %e,
                            "failed to purge stale RM-NET-0002 findings"
                        ),
                    }
                }
                // RM-NET-0003 / RM-USER-0008 / RM-CRED-0005(v1) flooded without baselines
                // (every :22 listener, every authorized_key, every ssh-rsa type name).
                match store
                    .clear_findings_by_checks(&[
                        "RM-NET-0003",
                        "RM-USER-0008",
                        "RM-CRED-0005",
                    ])
                    .await
                {
                    Ok(n) if n > 0 => tracing::info!(
                        purged = n,
                        "purged baseline-less listener/SSH-key false positives"
                    ),
                    Ok(_) => {}
                    Err(e) => tracing::warn!(
                        error = %e,
                        "failed to purge baseline-less finding FPs"
                    ),
                }
                // RM-PROC-0006 v1 treated TASK_COMM_LEN truncation as masquerade;
                // RM-PROC-0010/0011 alerted on normal JIT RWX and every root daemon.
                match store
                    .clear_findings_by_checks(&[
                        "RM-PROC-0006",
                        "RM-PROC-0010",
                        "RM-PROC-0011",
                    ])
                    .await
                {
                    Ok(n) if n > 0 => tracing::info!(
                        purged = n,
                        "purged process masquerade / RWX / root-listener false positives"
                    ),
                    Ok(_) => {}
                    Err(e) => tracing::warn!(
                        error = %e,
                        "failed to purge process-check false positives"
                    ),
                }
            }
            Ok(None) => {
                if args.store.exists() {
                    if let Ok(legacy) = InMemoryStore::open(&args.store) {
                        if !legacy.is_empty() {
                            let snap = legacy
                                .export_snapshot()
                                .context("export legacy JSON store")?;
                            let hosts = snap.hosts.len();
                            let findings = snap.findings.len();
                            store
                                .import_snapshot(snap.clone())
                                .context("import legacy JSON into memory")?;
                            match ch.save_control_plane(&snap).await {
                                Ok(n) => {
                                    tracing::info!(
                                        hosts,
                                        findings,
                                        rows = n,
                                        path = %args.store.display(),
                                        "migrated legacy JSON store into ClickHouse"
                                    );
                                    store.clear_dirty();
                                }
                                Err(e) => tracing::warn!(
                                    error = %e,
                                    "ClickHouse migration failed — state kept in memory until flush"
                                ),
                            }
                        } else {
                            tracing::info!("ClickHouse control-plane empty — starting fresh");
                        }
                    } else {
                        tracing::info!("ClickHouse control-plane empty — starting fresh");
                    }
                } else {
                    tracing::info!("ClickHouse control-plane empty — starting fresh");
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "ClickHouse load failed — starting with empty in-memory store"
                );
            }
        }

        tracing::info!(
            backend = "clickhouse",
            hosts = store.host_count(),
            findings = store.finding_count(),
            "control-plane store ready"
        );

        // If RPL `events` is empty but we already have process observations in the
        // control-plane store, backfill once so hunts work without a rescan.
        if let Err(e) = backfill_events_from_store(&ch, store.as_ref()).await {
            tracing::warn!(error = %e, "ClickHouse events backfill skipped");
        }

        (store, Some(ch))
    } else {
        let store = Arc::new(
            InMemoryStore::open(&args.store)
                .with_context(|| format!("open store {}", args.store.display()))?,
        );
        tracing::info!(
            backend = "json",
            path = %args.store.display(),
            hosts = store.host_count(),
            findings = store.finding_count(),
            "control-plane store ready (ClickHouse unavailable)"
        );
        (store, None)
    };

    {
        let mut keep = args.scan_history_per_host;
        if let Ok(raw) = std::fs::read_to_string(".dev/scan-history-per-host") {
            if let Ok(n) = raw.trim().parse::<usize>() {
                keep = n.min(200);
            }
        }
        store.set_scan_history_per_host(keep);
        match store.prune_scan_history(None, keep).await {
            Ok(n) if n > 0 => {
                tracing::info!(keep, pruned = n, "pruned finished scans to history limit");
                store.mark_dirty_public();
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "scan history prune failed"),
        }
        tracing::info!(keep, "scan history per host");
    }

    if args.seed_demo {
        if store.host_count() > 0 {
            tracing::info!(
                hosts = store.host_count(),
                "skipping demo seed — restored hosts from store (pass --reset-store to wipe)"
            );
        } else {
            seed_demo(&store, checks.snapshot().await.as_ref(), args.seed_hosts)
                .await
                .context("seed demo data")?;
            tracing::info!(hosts = args.seed_hosts, "demo fleet seeded for operator console");
            store.mark_dirty_public();
        }
    }
    spawn_store_flusher(store.clone(), clickhouse_arc.clone());

    if let Some(ch) = clickhouse_arc.clone() {
        // Push on-disk virtual ingest / sift platform into ClickHouse.
        let _ = rustmite_server::platform_ch::restore_sift_db(ch.as_ref()).await;
        if let Ok(hosts) = store.list_hosts().await {
            for h in hosts {
                let is_v = h.agent_kind.eq_ignore_ascii_case("virtual")
                    || h.auth_status
                        .as_deref()
                        .map(|s| s.eq_ignore_ascii_case("virtual"))
                        .unwrap_or(false);
                if is_v {
                    let _ = rustmite_server::platform_ch::restore_virtual_host(ch.as_ref(), h.id.0)
                        .await;
                    let _ =
                        rustmite_server::platform_ch::sync_virtual_host(ch.as_ref(), h.id.0).await;
                }
            }
        }
        rustmite_server::platform_ch::sync_sift_db(ch.as_ref()).await;
    }

    {
        let now = rustmite_server::sys_metrics::utc_now_rfc3339();
        match rustmite_server::ssh_hunter::backfill_from_store(store.as_ref(), 50_000, &now).await {
            Ok(n) if n > 0 => {
                tracing::info!(placements = n, "SSH Hunter backfilled from observations on startup");
                store.mark_dirty_public();
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "SSH Hunter startup backfill failed"),
        }
        match rustmite_server::ssh_hunter::ensure_default_zones(store.as_ref()).await {
            Ok(n) if n > 0 => {
                tracing::info!(zones = n, "SSH Hunter default zones seeded");
                store.mark_dirty_public();
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "SSH Hunter zones seed failed"),
        }
    }

    let host_health = Arc::new(tokio::sync::RwLock::new(
        rustmite_server::host_health::load_host_health_config(),
    ));
    spawn_host_health_checker(store.clone(), host_health.clone());

    if args.scan_sim {
        spawn_scan_simulator(store.clone());
        tracing::info!("scan progress simulator enabled");
    }

    let check_engine = checks.snapshot().await;
    let check_sets = rustmite_server::check_sets::CheckSetStore::open(
        PathBuf::from(".dev/check-sets.json"),
        check_engine.as_ref(),
    );
    tracing::info!(
        path = %check_sets.path().display(),
        "check-set plans ready"
    );

    let api_token = std::env::var("RUSTMITE_API_TOKEN").ok();
    let require_auth = rustmite_server::operator_auth::require_auth_from_env();
    let operator_auth = Arc::new(
        rustmite_server::operator_auth::OperatorAuth::open(
            rustmite_server::operator_auth::OperatorAuth::default_path(),
            require_auth,
        )
        .expect("open operator auth store"),
    );
    let (admin_user, admin_pass) = rustmite_server::operator_auth::bootstrap_admin_from_env();
    if let Err(e) = operator_auth
        .ensure_bootstrap_admin(&admin_user, &admin_pass)
        .await
    {
        tracing::warn!(error = %e, "bootstrap admin failed");
    } else if require_auth {
        tracing::info!(
            require_auth,
            path = %operator_auth.path().display(),
            "operator auth enabled (default admin user if store was empty)"
        );
    } else {
        tracing::warn!("operator auth DISABLED (RUSTMITE_REQUIRE_AUTH=0) — console is open");
    }
    let settings = Arc::new(RuntimeSettings {
        listen: args.listen,
        node_listen: args.node_listen,
        checks_path: checks_dir.clone(),
        checks_count: checks.len().await,
        webhook_url: args.webhook_url.clone(),
        webhook_secret_set: !args.webhook_secret.is_empty(),
        seed_demo: args.seed_demo,
        seed_hosts: args.seed_hosts,
        scan_sim: args.scan_sim,
        api_token_required: api_token.is_some(),
        default_check_set: args.default_check_set,
        scan_interval: args.scan_interval,
        scan_jitter_pct: args.scan_jitter_pct,
        max_concurrent_scans: args.max_concurrent_scans,
        scan_timeout_secs: args.scan_timeout_secs,
        scan_history_per_host: args.scan_history_per_host,
        clickhouse_url: clickhouse_url_effective,
        noise_xx_enabled: args.noise_xx,
        noise_xx_server_fingerprint: Some(noise_fp),
        tls_enabled: operator_tls.is_some(),
        tls_cert: operator_tls.as_ref().map(|p| p.cert.clone()),
        tls_auto_generated: operator_tls
            .as_ref()
            .map(|p| p.auto_generated)
            .unwrap_or(false),
        node_tls_enabled: node_tls.is_some(),
        node_tls_cert: node_tls.as_ref().map(|p| p.cert.clone()),
        node_tls_client_ca: args.node_tls_client_ca.clone(),
        ssh_connect_timeout_secs: args.ssh_connect_timeout_secs,
        ssh_auth_timeout_secs: args.ssh_auth_timeout_secs,
        ssh_cmd_timeout_secs: args.ssh_cmd_timeout_secs,
        ssh_inactivity_timeout_secs: args.ssh_inactivity_timeout_secs,
        ssh_delivery_timeout_secs: args.ssh_delivery_timeout_secs,
        ssh_fingerprint_timeout_secs: args.ssh_fingerprint_timeout_secs,
        ssh_connect_delay_ms: args.ssh_connect_delay_ms,
        ssh_timeout_jitter_pct: args.ssh_timeout_jitter_pct,
        clickhouse_timeout_secs: args.clickhouse_timeout_secs,
        probe_limits: rustmite_proto::Limits::default(),
    });
    spawn_scan_scheduler(store.clone(), settings.clone());
    let probe_limits = {
        let path = PathBuf::from(".dev/probe-limits.json");
        let limits = if path.is_file() {
            std::fs::read_to_string(&path)
                .ok()
                .and_then(|raw| serde_json::from_str(&raw).ok())
                .unwrap_or_default()
        } else {
            rustmite_proto::Limits::default()
        };
        Arc::new(tokio::sync::RwLock::new(limits))
    };
    let state = AppState {
        store: store.clone(),
        api_token: api_token.clone(),
        checks: checks.clone(),
        check_sets,
        webhook,
        metrics: Arc::new(MetricsHub::new()),
        settings,
        clickhouse: clickhouse_arc.clone(),
        noise_keypair: Arc::new(noise_kp),
        noise_xx_enabled: args.noise_xx,
        cred_pubkey,
        probe_limits,
        host_health,
        sift_platform: rustmite_server::sift_platform::SiftPlatform::default(),
        virtual_agents: rustmite_server::virtual_agents::VirtualAgentStore::load_or_create(
            ".dev/virtual-agents.json",
        ),
        operator_auth,
    };

    let _ = rustmite_server::credentials::import_filesystem_credentials(&state).await;

    let op = operator_router(state.clone());
    let node = node_router(state);

    let op_scheme = if operator_tls.is_some() { "https" } else { "http" };
    let node_scheme = if node_tls.is_some() { "https" } else { "http" };
    tracing::info!(%args.listen, scheme = op_scheme, "operator API + console listening (open /)");
    tracing::info!(
        %args.node_listen,
        scheme = node_scheme,
        mtls = args.node_tls_client_ca.is_some(),
        "node API listening"
    );

    let op_fut = async {
        if let Some(ref tls) = operator_tls {
            serve_tls(args.listen, op, tls).await
        } else {
            serve_plain(args.listen, op).await
        }
    };
    let node_fut = async {
        if let Some(ref tls) = node_tls {
            serve_tls(args.node_listen, node, tls).await
        } else {
            serve_plain(args.node_listen, node).await
        }
    };

    tokio::select! {
        res = async { tokio::try_join!(op_fut, node_fut) } => {
            res?;
        }
        _ = shutdown_signal() => {
            tracing::info!("shutdown signal — persisting control-plane store");
        }
    }
    if let Err(e) = persist_store(&store, clickhouse_arc.as_ref()).await {
        tracing::error!(error = %e, "failed to persist store on shutdown");
    }
    Ok(())
}

async fn backfill_events_from_store(
    ch: &rustmite_server::clickhouse::ClickHouseClient,
    store: &InMemoryStore,
) -> anyhow::Result<()> {
    let existing = ch
        .query_raw("SELECT count() FROM events")
        .await
        .map_err(|e| anyhow::anyhow!(e))?
        .trim()
        .parse::<u64>()
        .unwrap_or(0);
    if existing > 0 {
        return Ok(());
    }
    let obs = store
        .list_observations(None, 50_000)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    if obs.is_empty() {
        return Ok(());
    }

    // Group by (scan_id, host_id) so host_name / collector stay coherent.
    use std::collections::HashMap;
    let mut by_scan: HashMap<(Uuid, Uuid), Vec<rustmite_proto::Observation>> = HashMap::new();
    let mut collectors: HashMap<(Uuid, Uuid), String> = HashMap::new();
    for row in obs {
        let key = (row.scan_id.0, row.host_id.0);
        collectors
            .entry(key)
            .or_insert_with(|| row.collector.clone());
        by_scan.entry(key).or_default().push(row.data);
    }

    let mut total = 0usize;
    let now = rustmite_server::sys_metrics::utc_now_rfc3339();
    for ((scan_id, host_id), observations) in by_scan {
        let host_name = store
            .get_host(rustmite_proto::HostId(host_id))
            .await
            .map(|h| h.display_name)
            .unwrap_or_else(|_| host_id.to_string());
        let collector = collectors
            .get(&(scan_id, host_id))
            .map(|s| s.as_str())
            .unwrap_or("probe");
        let ctx = rustmite_server::events_ingest::EventContext {
            host_id,
            host_name: &host_name,
            scan_id,
            collector,
            timestamp: &now,
        };
        let rows = rustmite_server::events_ingest::observations_to_events(&ctx, &observations);
        for chunk in rows.chunks(500) {
            total += ch
                .insert_json_each_row("events", chunk)
                .await
                .map_err(|e| anyhow::anyhow!(e))?;
        }
    }
    tracing::info!(rows = total, "ClickHouse events backfilled from control-plane observations");
    Ok(())
}

async fn persist_store(
    store: &InMemoryStore,
    ch: Option<&Arc<rustmite_server::clickhouse::ClickHouseClient>>,
) -> anyhow::Result<()> {
    if !store.is_dirty() && ch.is_some() {
        // Still force-save on shutdown so a clean restart sees the latest snapshot.
    }
    if let Some(ch) = ch {
        let snap = store.export_snapshot()?;
        ch.save_control_plane(&snap)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        store.clear_dirty();
        return Ok(());
    }
    store.save()?;
    Ok(())
}

fn spawn_store_flusher(
    store: Arc<InMemoryStore>,
    ch: Option<Arc<rustmite_server::clickhouse::ClickHouseClient>>,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            if !store.is_dirty() {
                continue;
            }
            // Capture dirtiness generation so a concurrent mutation during the
            // await keeps the store dirty for the next flush.
            let gen = store.dirty_generation();
            if let Some(ref ch) = ch {
                match store.export_snapshot() {
                    Ok(snap) => match ch.save_control_plane(&snap).await {
                        Ok(n) => {
                            store.clear_dirty_if(gen);
                            tracing::debug!(rows = n, "control-plane store flushed to ClickHouse");
                        }
                        Err(e) => tracing::warn!(error = %e, "ClickHouse control-plane persist failed"),
                    },
                    Err(e) => tracing::warn!(error = %e, "export store snapshot failed"),
                }
            } else {
                match store.save_if_dirty() {
                    Ok(true) => tracing::debug!("control-plane store snapshot written to JSON"),
                    Ok(false) => {}
                    Err(e) => tracing::warn!(error = %e, "JSON store persist failed"),
                }
            }
        }
    });
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut term = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            Ok(s) => s,
            Err(_) => {
                let _ = ctrl_c.await;
                return;
            }
        };
        tokio::select! {
            _ = ctrl_c => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
    }
}
