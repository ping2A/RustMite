//! Periodic lightweight host reachability checks (TCP + SSH banner).
//!
//! Updates each host's `auth_status` / `auth_detail` / `auth_checked_at` so the
//! operator console can show Active / Offline without waiting for a full scan.
//! Cadence and concurrency are live-editable via the Settings panel.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustmite_store::{ActivityEvent, HostRecord, InMemoryStore, Store, UpdateHost};
use rustmite_transport::{test_host_connectivity, ConnectivityTestOpts, SshTimeouts};
use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, Semaphore};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::sys_metrics;

/// Default cadence between fleet-wide health passes.
pub const DEFAULT_INTERVAL_SECS: u64 = 60;
/// Cap concurrent TCP probes so large fleets do not stampede.
pub const DEFAULT_CONCURRENCY: usize = 8;
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 3;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostHealthConfig {
    /// When false, the background loop sleeps without probing.
    pub enabled: bool,
    /// Seconds between fleet-wide passes (minimum 15).
    pub interval_secs: u64,
    /// Max concurrent TCP/SSH banner probes.
    pub concurrency: usize,
    /// Per-host TCP connect timeout.
    pub connect_timeout_secs: u64,
}

impl Default for HostHealthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: DEFAULT_INTERVAL_SECS,
            concurrency: DEFAULT_CONCURRENCY,
            connect_timeout_secs: DEFAULT_CONNECT_TIMEOUT_SECS,
        }
    }
}

impl HostHealthConfig {
    pub fn sanitized(mut self) -> Self {
        self.interval_secs = self.interval_secs.clamp(15, 3600);
        self.concurrency = self.concurrency.clamp(1, 64);
        self.connect_timeout_secs = self.connect_timeout_secs.clamp(1, 30);
        self
    }
}

fn config_path() -> PathBuf {
    PathBuf::from(".dev/host-health.json")
}

pub fn load_host_health_config() -> HostHealthConfig {
    let path = config_path();
    if path.is_file() {
        if let Ok(raw) = std::fs::read_to_string(&path) {
            if let Ok(cfg) = serde_json::from_str::<HostHealthConfig>(&raw) {
                return cfg.sanitized();
            }
        }
    }
    HostHealthConfig::default()
}

pub fn save_host_health_config(cfg: &HostHealthConfig) {
    let path = config_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(raw) = serde_json::to_string_pretty(cfg) {
        let _ = std::fs::write(path, raw);
    }
}

pub fn spawn_host_health_checker(
    store: Arc<InMemoryStore>,
    config: Arc<RwLock<HostHealthConfig>>,
) {
    info!("host health checker started (live settings)");

    tokio::spawn(async move {
        // Stagger first pass slightly so startup I/O settles.
        tokio::time::sleep(Duration::from_secs(5)).await;
        let mut last_interval = Duration::from_secs(DEFAULT_INTERVAL_SECS);
        let mut ticker = tokio::time::interval(last_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let cfg = config.read().await.clone().sanitized();
            let want = Duration::from_secs(cfg.interval_secs);
            if want != last_interval {
                last_interval = want;
                ticker = tokio::time::interval(want);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                // Consume the immediate tick so we wait a full new interval.
                ticker.tick().await;
            }
            if !cfg.enabled {
                debug!("host health pass skipped (disabled in settings)");
                continue;
            }
            let n = check_all_hosts(
                store.clone(),
                cfg.concurrency,
                Duration::from_secs(cfg.connect_timeout_secs),
            )
            .await;
            if n > 0 {
                debug!(updated = n, "host health pass complete");
            }
        }
    });
}

/// One health pass over all hosts that have a primary address.
/// Returns how many host records were written.
pub async fn check_all_hosts(
    store: Arc<InMemoryStore>,
    concurrency: usize,
    connect_timeout: Duration,
) -> usize {
    let hosts = match store.list_hosts().await {
        Ok(h) => h,
        Err(e) => {
            warn!(error = %e, "host health: list_hosts failed");
            return 0;
        }
    };
    let targets: Vec<_> = hosts
        .into_iter()
        .filter(|h| {
            if h.agent_kind.eq_ignore_ascii_case("virtual") {
                return false;
            }
            h.primary_addr
                .as_deref()
                .map(str::trim)
                .is_some_and(|s| !s.is_empty())
        })
        .collect();
    if targets.is_empty() {
        return 0;
    }

    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut set = tokio::task::JoinSet::new();
    for host in targets {
        let store = store.clone();
        let permit = match sem.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => break,
        };
        set.spawn(async move {
            let _permit = permit;
            check_one(&store, &host, connect_timeout).await
        });
    }

    let mut changed = 0usize;
    while let Some(res) = set.join_next().await {
        match res {
            Ok(true) => changed += 1,
            Ok(false) => {}
            Err(e) => warn!(error = %e, "host health task join failed"),
        }
    }
    changed
}

async fn check_one(store: &InMemoryStore, host: &HostRecord, connect_timeout: Duration) -> bool {
    let addr = match host
        .primary_addr
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(a) => a,
        None => return false,
    };
    let port = if host.ssh_port == 0 { 22 } else { host.ssh_port };

    let mut timeouts = SshTimeouts::default();
    timeouts.connect = connect_timeout;
    timeouts.auth = connect_timeout
        .saturating_mul(2)
        .max(Duration::from_secs(5));
    timeouts.command = Duration::from_secs(5);

    let report = match test_host_connectivity(ConnectivityTestOpts {
        host: addr,
        port,
        username: None,
        identity: None,
        identity_pem: None,
        password: None,
        timeouts,
        require_auth: false,
    })
    .await
    {
        Ok(r) => r,
        Err(e) => {
            debug!(host = %host.display_name, error = %e, "host health probe error");
            return persist(store, host, "unreachable", Some(e.to_string())).await;
        }
    };

    // Reachability-only: promote TCP+banner success to `ok` so the console shows
    // Active without needing a decryptable credential on the control plane.
    let reachable = matches!(
        report.auth_status.as_str(),
        "partial" | "no_credential" | "ok"
    );
    let (status, detail) = if reachable {
        ("ok", Some(format!("SSH reachable on {addr}:{port}")))
    } else {
        let detail = report
            .stages
            .iter()
            .rev()
            .find(|s| !s.ok)
            .map(|s| s.detail.clone())
            .or_else(|| report.stages.last().map(|s| s.detail.clone()));
        (report.auth_status.as_str(), detail)
    };

    persist(store, host, status, detail).await
}

async fn persist(
    store: &InMemoryStore,
    host: &HostRecord,
    status: &str,
    detail: Option<String>,
) -> bool {
    let prev = host.auth_status.as_deref().unwrap_or("");
    let detail_changed = host.auth_detail.as_deref() != detail.as_deref();
    let status_changed = prev != status;

    if let Err(e) = store
        .update_host(
            host.id,
            UpdateHost {
                auth_status: Some(status.into()),
                auth_detail: detail.clone(),
                auth_checked_at: Some(sys_metrics::utc_now_rfc3339()),
                ..Default::default()
            },
        )
        .await
    {
        warn!(host = %host.display_name, error = %e, "host health update failed");
        return false;
    }

    if status_changed {
        let level = if status == "ok" { "info" } else { "warn" };
        let _ = store
            .push_activity(ActivityEvent {
                id: Uuid::nil(),
                ts: String::new(),
                level: level.into(),
                kind: "host.health".into(),
                message: format!(
                    "Host {} health {} → {}{}",
                    host.display_name,
                    if prev.is_empty() { "unknown" } else { prev },
                    status,
                    detail
                        .as_deref()
                        .map(|d| format!(" ({d})"))
                        .unwrap_or_default()
                ),
                scan_id: None,
                host_id: Some(host.id),
                node_id: None,
                detail: Some(serde_json::json!({
                    "from": prev,
                    "to": status,
                    "detail": detail,
                })),
            })
            .await;
        info!(
            host = %host.display_name,
            from = prev,
            to = status,
            "host health changed"
        );
    }

    status_changed || detail_changed || host.auth_checked_at.is_none()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmite_store::UpsertHost;
    use std::collections::BTreeMap;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn spawn_fake_sshd() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let _ = sock.write_all(b"SSH-2.0-FakeTest\r\n").await;
                let mut buf = [0u8; 64];
                let _ = sock.read(&mut buf).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn health_marks_listening_host_ok() {
        let addr = spawn_fake_sshd().await;
        let store = Arc::new(InMemoryStore::new());
        let host = store
            .upsert_host(UpsertHost {
                id: None,
                tenant_id: Uuid::nil(),
                display_name: "local-fake".into(),
                primary_addr: Some(addr.ip().to_string()),
                ssh_port: Some(addr.port()),
                labels: BTreeMap::new(),
                timeouts: Default::default(),
                agent_kind: None,
                ingest_token: None,
            })
            .await
            .unwrap();

        let n = check_all_hosts(store.clone(), 2, Duration::from_secs(2)).await;
        assert_eq!(n, 1);
        let updated = store.get_host(host.id).await.unwrap();
        assert_eq!(updated.auth_status.as_deref(), Some("ok"));
        assert!(updated.auth_checked_at.is_some());
    }

    #[tokio::test]
    async fn health_marks_closed_port_unreachable() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let store = Arc::new(InMemoryStore::new());
        let host = store
            .upsert_host(UpsertHost {
                id: None,
                tenant_id: Uuid::nil(),
                display_name: "down".into(),
                primary_addr: Some(addr.ip().to_string()),
                ssh_port: Some(addr.port()),
                labels: BTreeMap::new(),
                timeouts: Default::default(),
                agent_kind: None,
                ingest_token: None,
            })
            .await
            .unwrap();

        let _ = check_all_hosts(store.clone(), 2, Duration::from_secs(1)).await;
        let updated = store.get_host(host.id).await.unwrap();
        assert_eq!(updated.auth_status.as_deref(), Some("unreachable"));
        assert!(updated.auth_checked_at.is_some());
    }

    #[test]
    fn config_sanitizes_bounds() {
        let cfg = HostHealthConfig {
            enabled: true,
            interval_secs: 1,
            concurrency: 999,
            connect_timeout_secs: 0,
        }
        .sanitized();
        assert_eq!(cfg.interval_secs, 15);
        assert_eq!(cfg.concurrency, 64);
        assert_eq!(cfg.connect_timeout_secs, 1);
    }
}
