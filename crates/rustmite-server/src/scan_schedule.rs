//! Opt-in automatic scan scheduling.
//!
//! Hosts default to **manual** collection (`labels.scan_interval = "manual"`).
//! Only hosts with a concrete duration interval are enqueued by this loop.
//! Operators still use **Scan now** for on-demand collection.

use std::sync::Arc;
use std::time::Duration;

use rustmite_proto::HostId;
use rustmite_store::{EnqueueScan, InMemoryStore, Store};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::settings::RuntimeSettings;

const TICK_SECS: u64 = 30;
const MAX_ENQUEUE_PER_TICK: usize = 8;

/// Background loop: enqueue due scans for hosts that opted into automatic collection.
pub fn spawn_scan_scheduler(store: Arc<InMemoryStore>, settings: Arc<RuntimeSettings>) {
    info!("scan scheduler started (opt-in; manual hosts skipped)");
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(8)).await;
        let mut ticker = tokio::time::interval(Duration::from_secs(TICK_SECS));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            if let Err(e) = schedule_tick(&store, &settings).await {
                warn!(error = %e, "scan scheduler tick failed");
            }
        }
    });
}

async fn schedule_tick(
    store: &InMemoryStore,
    settings: &RuntimeSettings,
) -> anyhow::Result<()> {
    let hosts = store.list_hosts().await?;
    let snap = store.queue_snapshot().await?;
    let active_hosts: std::collections::HashSet<Uuid> = snap
        .active
        .iter()
        .filter(|j| matches!(j.state.as_str(), "queued" | "leased" | "running"))
        .map(|j| j.host_id.0)
        .collect();

    let fleet_check = settings.default_check_set.clone();
    let jitter_pct = settings.scan_jitter_pct.min(50);
    let now = OffsetDateTime::now_utc();
    let mut enqueued = 0usize;

    for h in hosts {
        if enqueued >= MAX_ENQUEUE_PER_TICK {
            break;
        }
        if h.agent_kind.eq_ignore_ascii_case("virtual") {
            continue;
        }
        if active_hosts.contains(&h.id.0) {
            continue;
        }
        let Some(interval_secs) = host_auto_interval_secs(&h) else {
            continue;
        };
        if !host_can_scan(&h) {
            continue;
        }
        if !host_is_due(&h, interval_secs, jitter_pct, now) {
            continue;
        }
        let check_set = h
            .labels
            .get("check_set")
            .or_else(|| h.labels.get("default_check_set"))
            .cloned()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| fleet_check.clone());
        let interval_label = h
            .labels
            .get("scan_interval")
            .cloned()
            .unwrap_or_else(|| format!("{interval_secs}s"));
        match store
            .enqueue_scan(EnqueueScan {
                host_id: h.id,
                check_set,
                priority: 80,
            })
            .await
        {
            Ok(job) => {
                enqueued += 1;
                let _ = store
                    .push_activity(rustmite_store::ActivityEvent {
                        id: Uuid::nil(),
                        ts: String::new(),
                        level: "info".into(),
                        kind: "scan.scheduled".into(),
                        message: format!(
                            "Automatic collection queued for {} ({})",
                            h.display_name, interval_label
                        ),
                        scan_id: Some(job.id),
                        host_id: Some(h.id),
                        node_id: None,
                        detail: Some(serde_json::json!({
                            "scan_interval": interval_label,
                            "source": "scheduler",
                        })),
                    })
                    .await;
            }
            Err(rustmite_store::StoreError::Conflict(_)) => {}
            Err(e) => {
                debug!(host = %h.display_name, error = %e, "schedule enqueue skipped");
            }
        }
    }
    if enqueued > 0 {
        debug!(enqueued, "scan scheduler enqueued jobs");
    }
    Ok(())
}

/// Concrete duration ⇒ automatic collection enabled. `manual` / missing ⇒ off.
fn host_auto_interval_secs(h: &rustmite_store::HostRecord) -> Option<u64> {
    let raw = h.labels.get("scan_interval")?.trim();
    if is_manual_interval(raw) {
        return None;
    }
    parse_interval_secs(raw).filter(|s| *s > 0)
}

fn is_manual_interval(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "" | "manual" | "off" | "none" | "disabled" | "0"
    )
}

fn host_can_scan(h: &rustmite_store::HostRecord) -> bool {
    let labels = &h.labels;
    let has_cred = labels.contains_key("ssh_password_file")
        || labels.contains_key("ssh_identity")
        || labels.contains_key("credential")
        || labels
            .get("ssh_auth")
            .map(|v| v == "password" || v == "publickey")
            .unwrap_or(false);
    if !has_cred {
        return false;
    }
    match h.auth_status.as_deref() {
        Some("no_credential") | Some("unreachable") | Some("no_sshd") => false,
        _ => true,
    }
}

fn host_is_due(
    h: &rustmite_store::HostRecord,
    interval_secs: u64,
    jitter_pct: u8,
    now: OffsetDateTime,
) -> bool {
    let jitter = if jitter_pct == 0 {
        0i64
    } else {
        let span = (interval_secs as i64 * i64::from(jitter_pct)) / 100;
        let hash = fnv1a_host(h.id);
        (hash % (2 * span.max(1) as u64)) as i64 - span
    };
    let period_secs = ((interval_secs as i64) + jitter).max(60) as u64;
    match h.last_scan_at.as_deref().and_then(parse_ts) {
        None => true, // never scanned — due once automatic collection is enabled
        Some(last) => {
            let elapsed = now - last;
            elapsed >= time::Duration::seconds(period_secs as i64)
        }
    }
}

fn parse_interval_secs(raw: &str) -> Option<u64> {
    let s = raw.trim().to_ascii_lowercase();
    if s.is_empty() || is_manual_interval(&s) {
        return None;
    }
    let (num, unit) = if let Some(i) = s.find(|c: char| c.is_ascii_alphabetic()) {
        (&s[..i], &s[i..])
    } else {
        return s.parse().ok();
    };
    let n: u64 = num.parse().ok()?;
    let mul = match unit {
        "s" | "sec" | "secs" | "second" | "seconds" => 1,
        "m" | "min" | "mins" | "minute" | "minutes" => 60,
        "h" | "hr" | "hrs" | "hour" | "hours" => 3600,
        "d" | "day" | "days" => 86400,
        _ => return None,
    };
    Some(n.saturating_mul(mul))
}

fn parse_ts(raw: &str) -> Option<OffsetDateTime> {
    let t = raw.trim();
    if let Ok(dt) = OffsetDateTime::parse(t, &Rfc3339) {
        return Some(dt);
    }
    // `OffsetDateTime::to_string()` style used by the store for last_scan_at.
    let fmt = time::format_description::parse(
        "[year]-[month]-[day] [hour]:[minute]:[second].[subsecond] [offset_hour \
         sign:mandatory]:[offset_minute]:[offset_second]",
    )
    .ok()?;
    OffsetDateTime::parse(t, &fmt).ok()
}

fn fnv1a_host(id: HostId) -> u64 {
    let bytes = id.0.as_bytes();
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in bytes {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmite_store::HostRecord;
    use std::collections::BTreeMap;
    use uuid::Uuid;

    #[test]
    fn manual_intervals_are_off() {
        assert!(is_manual_interval("manual"));
        assert!(is_manual_interval("OFF"));
        assert!(is_manual_interval(""));
        assert_eq!(parse_interval_secs("manual"), None);
        assert_eq!(parse_interval_secs("1h"), Some(3600));
        assert_eq!(parse_interval_secs("15m"), Some(900));
        assert_eq!(parse_interval_secs("7d"), Some(7 * 86400));
        assert_eq!(parse_interval_secs("2h"), Some(7200));
    }

    fn host_with(interval: Option<&str>, auth: Option<&str>) -> HostRecord {
        let mut labels = BTreeMap::new();
        if let Some(v) = interval {
            labels.insert("scan_interval".into(), v.into());
        }
        labels.insert("ssh_identity".into(), "id_ed25519".into());
        HostRecord {
            id: HostId::new_v4(),
            tenant_id: Uuid::nil(),
            display_name: "h".into(),
            primary_addr: Some("10.0.0.1".into()),
            ssh_port: 22,
            arch: None,
            kernel: None,
            os: None,
            os_id: None,
            os_version: None,
            agent_kind: "ssh".into(),
            ingest_token: None,
            labels,
            last_scan_at: None,
            last_outcome: None,
            timeouts: Default::default(),
            auth_status: auth.map(|s| s.into()),
            auth_detail: None,
            auth_checked_at: None,
        }
    }

    #[test]
    fn auto_interval_requires_concrete_duration() {
        assert_eq!(host_auto_interval_secs(&host_with(None, Some("ok"))), None);
        assert_eq!(
            host_auto_interval_secs(&host_with(Some("manual"), Some("ok"))),
            None
        );
        assert_eq!(
            host_auto_interval_secs(&host_with(Some("off"), Some("ok"))),
            None
        );
        assert_eq!(
            host_auto_interval_secs(&host_with(Some("1h"), Some("ok"))),
            Some(3600)
        );
        assert_eq!(
            host_auto_interval_secs(&host_with(Some("30m"), Some("ok"))),
            Some(1800)
        );
    }

    #[test]
    fn host_can_scan_requires_cred_and_reachable_auth() {
        let ok = host_with(Some("1h"), Some("ok"));
        assert!(host_can_scan(&ok));

        let mut no_cred = ok.clone();
        no_cred.labels.remove("ssh_identity");
        assert!(!host_can_scan(&no_cred));

        let mut unreachable = ok.clone();
        unreachable.auth_status = Some("unreachable".into());
        assert!(!host_can_scan(&unreachable));

        let mut no_cred_status = ok.clone();
        no_cred_status.auth_status = Some("no_credential".into());
        assert!(!host_can_scan(&no_cred_status));
    }

    #[test]
    fn never_scanned_auto_host_is_due() {
        let h = host_with(Some("1h"), Some("ok"));
        let now = OffsetDateTime::now_utc();
        assert!(host_is_due(&h, 3600, 0, now));
    }

    #[test]
    fn recently_scanned_host_is_not_due() {
        let mut h = host_with(Some("1h"), Some("ok"));
        let now = OffsetDateTime::now_utc();
        h.last_scan_at = Some(now.to_string());
        assert!(!host_is_due(&h, 3600, 0, now));
    }

    #[test]
    fn virtual_agent_kind_skipped_by_interval_helper_still_parses() {
        let mut h = host_with(Some("1h"), Some("ok"));
        h.agent_kind = "virtual".into();
        // Interval helper is kind-agnostic; scheduler loop skips virtuals separately.
        assert_eq!(host_auto_interval_secs(&h), Some(3600));
    }
}
