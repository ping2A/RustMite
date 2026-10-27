//! Optional ClickHouse client for RPL hunts + observation ingest (mobipwn-style).

use std::time::Duration;

use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClickHouseError {
    #[error("clickhouse http: {0}")]
    Http(String),
    #[error("clickhouse: {0}")]
    Msg(String),
}

#[derive(Clone, Debug)]
pub struct ClickHouseClient {
    base: String,
    user: String,
    password: String,
    database: String,
    http: reqwest::Client,
}

/// Per-table on-disk footprint from `system.parts` (active parts only).
#[derive(Clone, Debug, serde::Serialize)]
pub struct ClickHouseTableSize {
    pub table: String,
    pub bytes: u64,
    pub rows: u64,
}

fn json_u64(v: Option<&Value>) -> u64 {
    let Some(v) = v else {
        return 0;
    };
    v.as_u64()
        .or_else(|| v.as_i64().map(|n| n.max(0) as u64))
        .or_else(|| v.as_f64().map(|n| n.max(0.0) as u64))
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        .unwrap_or(0)
}

fn env_flag_disabled(name: &str) -> bool {
    matches!(
        std::env::var(name).ok().as_deref(),
        Some("0") | Some("false") | Some("off") | Some("no")
    )
}

impl ClickHouseClient {
    /// Build from env. Auto-enables `http://127.0.0.1:8123` unless
    /// `RUSTMITE_CLICKHOUSE=0` / `RUSTMITE_NO_CLICKHOUSE=1`.
    pub fn from_env() -> Option<Self> {
        if env_flag_disabled("RUSTMITE_CLICKHOUSE") || env_flag_disabled("RUSTMITE_NO_CLICKHOUSE") {
            return None;
        }
        let url = std::env::var("RUSTMITE_CLICKHOUSE_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "http://127.0.0.1:8123".into());
        Self::new(
            url,
            std::env::var("RUSTMITE_CLICKHOUSE_USER").unwrap_or_else(|_| "rustmite".into()),
            std::env::var("RUSTMITE_CLICKHOUSE_PASSWORD").unwrap_or_else(|_| "rustmite".into()),
            std::env::var("RUSTMITE_CLICKHOUSE_DB").unwrap_or_else(|_| "rustmite".into()),
            std::env::var("RUSTMITE_CLICKHOUSE_TIMEOUT_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(30),
        )
        .ok()
    }

    pub fn new(
        url: impl Into<String>,
        user: impl Into<String>,
        password: impl Into<String>,
        database: impl Into<String>,
        timeout_secs: u64,
    ) -> Result<Self, ClickHouseError> {
        let timeout = Duration::from_secs(timeout_secs.max(1));
        let http = reqwest::Client::builder()
            .connect_timeout(timeout.min(Duration::from_secs(10)))
            .timeout(timeout)
            .pool_idle_timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| ClickHouseError::Http(e.to_string()))?;
        Ok(Self {
            base: url.into().trim_end_matches('/').to_string(),
            user: user.into(),
            password: password.into(),
            database: database.into(),
            http,
        })
    }

    pub fn database(&self) -> &str {
        self.database.as_str()
    }

    pub fn base_url(&self) -> &str {
        self.base.as_str()
    }

    /// Retry ping until ready (docker compose often needs a few seconds).
    pub async fn wait_ready(&self, attempts: u32, delay: Duration) -> Result<(), ClickHouseError> {
        let mut last = ClickHouseError::Msg("not attempted".into());
        for i in 0..attempts.max(1) {
            match self.ping().await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    last = e;
                    if i + 1 < attempts {
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }
        Err(last)
    }

    pub async fn ping(&self) -> Result<(), ClickHouseError> {
        let _ = self.query_raw("SELECT 1").await?;
        Ok(())
    }

    pub async fn query_json_each_row(&self, sql: &str) -> Result<Vec<Value>, ClickHouseError> {
        let body = self
            .query_raw(&format!("{sql} FORMAT JSONEachRow"))
            .await?;
        let mut rows = Vec::new();
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            rows.push(
                serde_json::from_str(line)
                    .map_err(|e| ClickHouseError::Msg(format!("json row: {e}")))?,
            );
        }
        Ok(rows)
    }

    pub async fn insert_json_each_row(
        &self,
        table: &str,
        rows: &[Value],
    ) -> Result<usize, ClickHouseError> {
        if rows.is_empty() {
            return Ok(0);
        }
        let mut body = String::new();
        for row in rows {
            body.push_str(
                &serde_json::to_string(row)
                    .map_err(|e| ClickHouseError::Msg(format!("encode row: {e}")))?,
            );
            body.push('\n');
        }
        let sql = format!("INSERT INTO {table} FORMAT JSONEachRow");
        let res = self
            .http
            .post(format!("{}/", self.base))
            .basic_auth(&self.user, Some(&self.password))
            .query(&[("database", self.database.as_str()), ("query", sql.as_str())])
            .body(body)
            .send()
            .await
            .map_err(|e| ClickHouseError::Http(e.to_string()))?;
        if !res.status().is_success() {
            let status = res.status();
            let text = res.text().await.unwrap_or_default();
            return Err(ClickHouseError::Http(format!("{status}: {text}")));
        }
        Ok(rows.len())
    }

    /// Insert a small demo corpus so RPL hunts return rows without live ingest.
    pub async fn seed_demo_events(&self, host_count: usize) -> Result<usize, ClickHouseError> {
        let n = host_count.clamp(2, 40) as u32;
        // Idempotent-ish: only seed when the table is empty.
        let existing = self
            .query_raw("SELECT count() FROM events")
            .await?
            .trim()
            .parse::<u64>()
            .unwrap_or(1);
        if existing > 0 {
            return Ok(0);
        }

        let samples: &[(&str, &str, &str, u8, &str, &str)] = &[
            (
                "process",
                "decloak.process",
                "sshd",
                0,
                "info",
                "ssh daemon observed",
            ),
            (
                "process",
                "decloak.process",
                "cron",
                0,
                "info",
                "scheduler observed",
            ),
            (
                "hidden_process",
                "decloak.process",
                "kworker/0:2",
                0,
                "high",
                "suspicious process name",
            ),
            (
                "process",
                "decloak.process",
                "memfd:rustmite",
                1,
                "critical",
                "memfd-backed executable",
            ),
            (
                "authorized_key",
                "ssh.keys",
                "sshd",
                0,
                "medium",
                "new authorized_keys entry",
            ),
            (
                "file_entropy",
                "entropy",
                "ls",
                0,
                "high",
                "entropy spike on /usr/bin/ls",
            ),
            (
                "integrity_mismatch",
                "file.integrity",
                "login",
                0,
                "critical",
                "hash drift on /bin/login",
            ),
            (
                "socket",
                "net.sockets",
                "sshd",
                0,
                "info",
                "listener on :22",
            ),
        ];

        let mut rows = Vec::with_capacity(n as usize);
        for i in 0..n {
            let (kind, collector, proc, memfd, sev, msg) = samples[(i as usize) % samples.len()];
            let host = format!("demo-host-{:04}", i + 1);
            rows.push(serde_json::json!({
                "timestamp": format!("now64(6) - INTERVAL {} SECOND", i * 97),
                "message": msg,
                "source_type": "rustmite_probe",
                "source": "seed-demo",
                "platform": "linux",
                "host_id": host,
                "host_name": host,
                "scan_id": format!("seed-scan-{i}"),
                "collector": collector,
                "kind": kind,
                "check_id": "",
                "data_type": kind,
                "process_name": proc,
                "process_id": 1000 + i,
                "user": if proc == "sshd" { "root" } else { "app" },
                "path": "",
                "src_ip": "",
                "dest_ip": "",
                "file_hash": "",
                "severity": sev,
                "exe_memfd": memfd,
                "ext": "{}"
            }));
        }

        // JSONEachRow cannot evaluate expressions — use SQL VALUES with now64().
        let mut sql = String::from(
            "INSERT INTO events \
             (timestamp, message, source_type, source, platform, host_id, host_name, scan_id, \
              collector, kind, data_type, process_name, process_id, user, severity, exe_memfd) VALUES ",
        );
        for (i, row) in rows.iter().enumerate() {
            if i > 0 {
                sql.push(',');
            }
            sql.push_str(&format!(
                "(now64(6) - INTERVAL {ago} SECOND, '{msg}', 'rustmite_probe', 'seed-demo', 'linux', \
                 '{host}', '{host}', '{scan}', '{collector}', '{kind}', '{kind}', '{proc}', {pid}, \
                 '{user}', '{sev}', {memfd})",
                ago = i * 97,
                msg = esc(row["message"].as_str().unwrap_or("")),
                host = esc(row["host_id"].as_str().unwrap_or("")),
                scan = esc(row["scan_id"].as_str().unwrap_or("")),
                collector = esc(row["collector"].as_str().unwrap_or("")),
                kind = esc(row["kind"].as_str().unwrap_or("")),
                proc = esc(row["process_name"].as_str().unwrap_or("")),
                pid = row["process_id"].as_u64().unwrap_or(0),
                user = esc(row["user"].as_str().unwrap_or("")),
                sev = esc(row["severity"].as_str().unwrap_or("info")),
                memfd = row["exe_memfd"].as_u64().unwrap_or(0),
            ));
        }
        let _ = self.query_raw(&sql).await?;
        Ok(n as usize)
    }

    pub async fn events_count(&self) -> Result<u64, ClickHouseError> {
        let raw = self.query_raw("SELECT count() FROM events").await?;
        Ok(raw.trim().parse().unwrap_or(0))
    }

    /// On-disk size of each table in this client's database (`system.parts`).
    pub async fn database_table_sizes(&self) -> Result<Vec<ClickHouseTableSize>, ClickHouseError> {
        let db = self.database.replace('\'', "\\'");
        let sql = format!(
            "SELECT table AS name, \
                    sum(bytes_on_disk) AS bytes, \
                    sum(rows) AS rows \
             FROM system.parts \
             WHERE active AND database = '{db}' \
             GROUP BY table \
             ORDER BY bytes DESC"
        );
        let rows = self.query_json_each_row(&sql).await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let name = row
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if name.is_empty() {
                continue;
            }
            out.push(ClickHouseTableSize {
                table: name,
                bytes: json_u64(row.get("bytes")),
                rows: json_u64(row.get("rows")),
            });
        }
        Ok(out)
    }

    /// Live (non-deleted) platform blob rows across all kinds.
    pub async fn platform_blobs_live_count(&self) -> Result<u64, ClickHouseError> {
        self.ensure_platform_blobs_schema().await?;
        let raw = self
            .query_raw(
                "SELECT count() FROM rm_platform_blobs FINAL WHERE deleted = 0",
            )
            .await?;
        Ok(raw.trim().parse().unwrap_or(0))
    }

    /// Wipe RPL / hunt event rows (ingested observations).
    pub async fn clear_events(&self) -> Result<(), ClickHouseError> {
        self.query_raw("TRUNCATE TABLE IF EXISTS events").await?;
        let _ = self
            .query_raw("TRUNCATE TABLE IF EXISTS detection_signals")
            .await;
        Ok(())
    }

    /// Ensure RPL hunt `events` (+ detection_signals) exist — same DDL as
    /// `docker/clickhouse/init.sql`, so a missing initdb step cannot leave Hunt broken.
    pub async fn ensure_events_schema(&self) -> Result<(), ClickHouseError> {
        self.query_raw(
            "CREATE TABLE IF NOT EXISTS events \
             ( \
               id UUID DEFAULT generateUUIDv7(), \
               timestamp DateTime64(6, 'UTC'), \
               message String, \
               source_type LowCardinality(String) DEFAULT 'rustmite_probe', \
               source LowCardinality(String) DEFAULT '', \
               ingest_time DateTime64(6, 'UTC') DEFAULT now64(6), \
               platform LowCardinality(String) DEFAULT 'linux', \
               host_id String DEFAULT '', \
               host_name String DEFAULT '', \
               scan_id String DEFAULT '', \
               collector LowCardinality(String) DEFAULT '', \
               kind LowCardinality(String) DEFAULT '', \
               check_id LowCardinality(String) DEFAULT '', \
               data_type LowCardinality(String) DEFAULT '', \
               process_name LowCardinality(String) DEFAULT '', \
               process_id UInt32 DEFAULT 0, \
               user LowCardinality(String) DEFAULT '', \
               path String DEFAULT '', \
               args String DEFAULT '', \
               cmdline String DEFAULT '', \
               src_ip String DEFAULT '', \
               dest_ip String DEFAULT '', \
               file_hash String DEFAULT '', \
               severity LowCardinality(String) DEFAULT 'info', \
               exe_memfd UInt8 DEFAULT 0, \
               ext String DEFAULT '{}' \
             ) \
             ENGINE = MergeTree \
             PARTITION BY toYYYYMMDD(timestamp) \
             ORDER BY (platform, host_id, timestamp, id) \
             TTL toDateTime(timestamp) + INTERVAL 90 DAY \
             SETTINGS index_granularity = 8192",
        )
        .await?;
        // Existing deployments created before args/cmdline — add columns if missing.
        let _ = self
            .query_raw("ALTER TABLE events ADD COLUMN IF NOT EXISTS args String DEFAULT ''")
            .await;
        let _ = self
            .query_raw("ALTER TABLE events ADD COLUMN IF NOT EXISTS cmdline String DEFAULT ''")
            .await;
        let _ = self
            .query_raw(
                "CREATE TABLE IF NOT EXISTS detection_signals \
                 ( \
                   rule_id UUID, \
                   rule_name String, \
                   matched_at DateTime64(6, 'UTC') DEFAULT now64(6), \
                   event_id UUID, \
                   host_id String, \
                   dedup_key String, \
                   prevalence Float64 DEFAULT 0, \
                   payload String \
                 ) \
                 ENGINE = MergeTree \
                 PARTITION BY toYYYYMMDD(matched_at) \
                 ORDER BY (rule_id, matched_at) \
                 TTL toDateTime(matched_at) + INTERVAL 90 DAY",
            )
            .await;
        Ok(())
    }

    /// Ensure control-plane tables exist (safe to call on every start).
    pub async fn ensure_control_plane_schema(&self) -> Result<(), ClickHouseError> {
        self.query_raw(
            "CREATE TABLE IF NOT EXISTS cp_entities \
             ( \
               entity LowCardinality(String), \
               id String, \
               updated_at DateTime64(6, 'UTC') DEFAULT now64(6), \
               deleted UInt8 DEFAULT 0, \
               payload String \
             ) \
             ENGINE = ReplacingMergeTree(updated_at) \
             ORDER BY (entity, id) \
             SETTINGS index_granularity = 8192",
        )
        .await?;
        self.ensure_platform_blobs_schema().await?;
        self.ensure_events_schema().await?;
        Ok(())
    }

    /// Durable blobs outside the control-plane snapshot (AnoMark models, virtual JSONL ingest).
    /// Kept separate so `save_control_plane` truncates do not wipe them.
    pub async fn ensure_platform_blobs_schema(&self) -> Result<(), ClickHouseError> {
        self.query_raw(
            "CREATE TABLE IF NOT EXISTS rm_platform_blobs \
             ( \
               kind LowCardinality(String), \
               id String, \
               updated_at DateTime64(6, 'UTC') DEFAULT now64(6), \
               deleted UInt8 DEFAULT 0, \
               meta String, \
               payload String \
             ) \
             ENGINE = ReplacingMergeTree(updated_at) \
             ORDER BY (kind, id) \
             SETTINGS index_granularity = 8192",
        )
        .await?;
        Ok(())
    }

    pub async fn upsert_platform_blob(
        &self,
        kind: &str,
        id: &str,
        meta: &serde_json::Value,
        payload: &str,
    ) -> Result<(), ClickHouseError> {
        self.ensure_platform_blobs_schema().await?;
        let meta_s = serde_json::to_string(meta)
            .map_err(|e| ClickHouseError::Msg(format!("encode meta: {e}")))?;
        let row = serde_json::json!({
            "kind": kind,
            "id": id,
            "updated_at": clickhouse_ts(""),
            "deleted": 0,
            "meta": meta_s,
            "payload": payload,
        });
        self.insert_json_each_row("rm_platform_blobs", &[row]).await?;
        Ok(())
    }

    pub async fn get_platform_blob(
        &self,
        kind: &str,
        id: &str,
    ) -> Result<Option<(serde_json::Value, String)>, ClickHouseError> {
        self.ensure_platform_blobs_schema().await?;
        let kind_esc = kind.replace('\'', "\\'");
        let id_esc = id.replace('\'', "\\'");
        let sql = format!(
            "SELECT meta, payload, deleted \
             FROM rm_platform_blobs FINAL \
             WHERE kind = '{kind_esc}' AND id = '{id_esc}' \
             LIMIT 1"
        );
        let rows = self.query_json_each_row(&sql).await?;
        let Some(row) = rows.into_iter().next() else {
            return Ok(None);
        };
        if row.get("deleted").and_then(|v| v.as_u64()).unwrap_or(0) != 0 {
            return Ok(None);
        }
        let meta = row
            .get("meta")
            .and_then(|v| v.as_str())
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_else(|| serde_json::json!({}));
        let payload = row
            .get("payload")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        Ok(Some((meta, payload)))
    }

    pub async fn list_platform_blob_ids(&self, kind: &str) -> Result<Vec<String>, ClickHouseError> {
        self.ensure_platform_blobs_schema().await?;
        let kind_esc = kind.replace('\'', "\\'");
        let sql = format!(
            "SELECT id FROM rm_platform_blobs FINAL \
             WHERE kind = '{kind_esc}' AND deleted = 0"
        );
        let rows = self.query_json_each_row(&sql).await?;
        Ok(rows
            .into_iter()
            .filter_map(|r| r.get("id").and_then(|v| v.as_str()).map(str::to_string))
            .collect())
    }

    /// List live platform blobs for one id (host UUID), without loading payloads.
    pub async fn list_platform_blobs_for_id(
        &self,
        id: &str,
    ) -> Result<Vec<serde_json::Value>, ClickHouseError> {
        self.ensure_platform_blobs_schema().await?;
        let id_esc = id.replace('\'', "\\'");
        let sql = format!(
            "SELECT kind, id, meta, length(payload) AS bytes, updated_at \
             FROM rm_platform_blobs FINAL \
             WHERE id = '{id_esc}' AND deleted = 0 \
             ORDER BY kind"
        );
        self.query_json_each_row(&sql).await
    }

    /// Summarize virtual ingest blobs: distinct host ids + total payload bytes.
    pub async fn virtual_ingest_blob_stats(&self) -> Result<(usize, u64), ClickHouseError> {
        self.ensure_platform_blobs_schema().await?;
        let sql = "SELECT \
             uniqExact(id) AS hosts, \
             sum(length(payload)) AS bytes \
           FROM rm_platform_blobs FINAL \
           WHERE deleted = 0 \
             AND kind IN ('virtual_processes', 'virtual_files', 'virtual_provenance')";
        let rows = self.query_json_each_row(sql).await?;
        let Some(row) = rows.into_iter().next() else {
            return Ok((0, 0));
        };
        Ok((json_u64(row.get("hosts")) as usize, json_u64(row.get("bytes"))))
    }

    pub async fn delete_platform_blob(&self, kind: &str, id: &str) -> Result<(), ClickHouseError> {
        self.ensure_platform_blobs_schema().await?;
        let row = serde_json::json!({
            "kind": kind,
            "id": id,
            "updated_at": clickhouse_ts(""),
            "deleted": 1,
            "meta": "{}",
            "payload": "",
        });
        self.insert_json_each_row("rm_platform_blobs", &[row]).await?;
        Ok(())
    }

    /// Hard-remove virtual ingest platform blobs and reclaim disk (`OPTIMIZE FINAL`).
    /// Soft-deletes alone leave payload bytes in `system.parts` until merges run.
    pub async fn clear_virtual_ingest_blobs(&self) -> Result<(), ClickHouseError> {
        self.ensure_platform_blobs_schema().await?;
        self.query_raw(
            "ALTER TABLE rm_platform_blobs DELETE WHERE kind IN \
             ('virtual_processes','virtual_files','virtual_provenance')",
        )
        .await?;
        // Force mutations/merges so Data tab `bytes_on_disk` drops immediately.
        let _ = self
            .query_raw("OPTIMIZE TABLE rm_platform_blobs FINAL")
            .await;
        Ok(())
    }

    /// Compact `rm_platform_blobs` after soft-deletes (best-effort).
    pub async fn optimize_platform_blobs(&self) -> Result<(), ClickHouseError> {
        self.ensure_platform_blobs_schema().await?;
        self.query_raw("OPTIMIZE TABLE rm_platform_blobs FINAL")
            .await?;
        Ok(())
    }

    /// Best-effort remove hunt events for a host.
    /// Matches `events.host_id` (UUID string) — callers may also pass display_name
    /// when events were keyed by machine_id.
    pub async fn delete_events_for_host(&self, host_id: &str) -> Result<(), ClickHouseError> {
        let hid = host_id.replace('\\', "\\\\").replace('\'', "\\'");
        // Mutation is async in ClickHouse; fire-and-forget is fine for host cleanup.
        let sql = format!(
            "ALTER TABLE events DELETE WHERE host_id = '{hid}' OR host_name = '{hid}'"
        );
        match self.query_raw(&sql).await {
            Ok(_) => Ok(()),
            Err(e) => {
                // Table may not exist yet in fresh installs.
                let msg = e.to_string();
                if msg.contains("UNKNOWN_TABLE") || msg.contains("doesn't exist") {
                    Ok(())
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Remove only virtual-ingest hunt rows for a host (keeps real probe scan events).
    pub async fn delete_virtual_events_for_host(&self, host_id: &str) -> Result<(), ClickHouseError> {
        let hid = host_id.replace('\\', "\\\\").replace('\'', "\\'");
        let sql = format!(
            "ALTER TABLE events DELETE WHERE (host_id = '{hid}' OR host_name = '{hid}') \
             AND source = 'virtual_ingest'"
        );
        match self.query_raw(&sql).await {
            Ok(_) => Ok(()),
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("UNKNOWN_TABLE") || msg.contains("doesn't exist") {
                    Ok(())
                } else {
                    Err(e)
                }
            }
        }
    }

    pub async fn control_plane_entity_count(&self) -> Result<u64, ClickHouseError> {
        let raw = self
            .query_raw("SELECT count() FROM cp_entities FINAL WHERE deleted = 0")
            .await?;
        Ok(raw.trim().parse().unwrap_or(0))
    }

    /// Count live `host` rows only (zones/activity must not block an empty-fleet flush).
    pub async fn control_plane_host_count(&self) -> Result<u64, ClickHouseError> {
        let raw = self
            .query_raw(
                "SELECT count() FROM cp_entities FINAL \
                 WHERE deleted = 0 AND entity = 'host'",
            )
            .await?;
        Ok(raw.trim().parse().unwrap_or(0))
    }

    /// Wipe control-plane tables (used by --reset-store / --fresh-store).
    pub async fn reset_control_plane(&self) -> Result<(), ClickHouseError> {
        self.ensure_control_plane_schema().await?;
        self.query_raw("TRUNCATE TABLE IF EXISTS cp_entities").await?;
        Ok(())
    }

    /// Load the latest control-plane snapshot from ClickHouse.
    pub async fn load_control_plane(
        &self,
    ) -> Result<Option<rustmite_store::StoreSnapshot>, ClickHouseError> {
        self.ensure_control_plane_schema().await?;
        let rows = self
            .query_json_each_row(
                "SELECT entity, id, deleted, payload \
                 FROM cp_entities FINAL \
                 WHERE deleted = 0",
            )
            .await?;
        if rows.is_empty() {
            return Ok(None);
        }

        let mut snap = rustmite_store::StoreSnapshot {
            schema_version: 1,
            saved_at: crate::sys_metrics::utc_now_rfc3339(),
            hosts: Vec::new(),
            jobs: Vec::new(),
            metas: Vec::new(),
            observations: Vec::new(),
            findings: Vec::new(),
            host_keys: Vec::new(),
            baselines: Vec::new(),
            activity: Vec::new(),
            ssh_keys: Vec::new(),
            ssh_placements: Vec::new(),
            ssh_zones: Vec::new(),
            credentials: Vec::new(),
        };

        for row in rows {
            let entity = row.get("entity").and_then(|v| v.as_str()).unwrap_or("");
            let payload = row.get("payload").and_then(|v| v.as_str()).unwrap_or("{}");
            match entity {
                "host" => {
                    if let Ok(v) = serde_json::from_str(payload) {
                        snap.hosts.push(v);
                    }
                }
                "scan_job" => {
                    if let Ok(v) = serde_json::from_str(payload) {
                        snap.jobs.push(v);
                    }
                }
                "scan_meta" => {
                    if let Ok(v) = serde_json::from_str(payload) {
                        snap.metas.push(v);
                    }
                }
                "observation" => {
                    if let Ok(v) = serde_json::from_str(payload) {
                        snap.observations.push(v);
                    }
                }
                "finding" => {
                    if let Ok(v) = serde_json::from_str(payload) {
                        snap.findings.push(v);
                    }
                }
                "host_key" => {
                    if let Ok(v) = serde_json::from_str(payload) {
                        snap.host_keys.push(v);
                    }
                }
                "baseline" => {
                    if let Ok(v) = serde_json::from_str(payload) {
                        snap.baselines.push(v);
                    }
                }
                "activity" => {
                    if let Ok(v) = serde_json::from_str(payload) {
                        snap.activity.push(v);
                    }
                }
                "ssh_key" => {
                    if let Ok(v) = serde_json::from_str(payload) {
                        snap.ssh_keys.push(v);
                    }
                }
                "ssh_placement" => {
                    if let Ok(v) = serde_json::from_str(payload) {
                        snap.ssh_placements.push(v);
                    }
                }
                "ssh_zone" => {
                    if let Ok(v) = serde_json::from_str(payload) {
                        snap.ssh_zones.push(v);
                    }
                }
                "credential" => {
                    if let Ok(v) = serde_json::from_str(payload) {
                        snap.credentials.push(v);
                    }
                }
                _ => {}
            }
        }
        Ok(Some(snap))
    }

    /// Persist a full control-plane snapshot (ReplacingMergeTree keeps latest per id).
    ///
    /// Writes into `cp_entities__next` first, then atomically `EXCHANGE TABLES` so a
    /// failed / timed-out insert cannot leave an empty control plane after TRUNCATE.
    pub async fn save_control_plane(
        &self,
        snap: &rustmite_store::StoreSnapshot,
    ) -> Result<usize, ClickHouseError> {
        self.save_control_plane_ex(snap, false).await
    }

    /// Like [`Self::save_control_plane`], but `force_empty` allows wiping a non-empty
    /// fleet (used by Data → Clear all / clear hosts).
    pub async fn save_control_plane_ex(
        &self,
        snap: &rustmite_store::StoreSnapshot,
        force_empty: bool,
    ) -> Result<usize, ClickHouseError> {
        self.ensure_control_plane_schema().await?;
        self.ensure_control_plane_swap_schema().await?;

        // Safety: never replace a populated *fleet* with an empty in-memory snapshot
        // unless the operator explicitly cleared data (`force_empty`).
        let existing_hosts = self.control_plane_host_count().await.unwrap_or(0);
        if !force_empty && snap.hosts.is_empty() && existing_hosts > 0 {
            return Err(ClickHouseError::Msg(format!(
                "refusing to overwrite non-empty control plane ({existing_hosts} hosts) with 0 hosts — \
                 check ClickHouse connectivity / volume mounts; use Data → Clear or --reset-store to wipe deliberately"
            )));
        }

        let mut rows: Vec<serde_json::Value> = Vec::new();
        let ts = snap.saved_at.clone();

        for h in &snap.hosts {
            rows.push(entity_row("host", &h.id.to_string(), &ts, h)?);
        }
        for j in &snap.jobs {
            rows.push(entity_row("scan_job", &j.id.to_string(), &ts, j)?);
        }
        for m in &snap.metas {
            rows.push(entity_row("scan_meta", &m.scan_id.to_string(), &ts, m)?);
        }
        for o in &snap.observations {
            let id = format!("{}:{}", o.scan_id, o.seq);
            rows.push(entity_row("observation", &id, &ts, o)?);
        }
        for f in &snap.findings {
            rows.push(entity_row("finding", &f.id.to_string(), &ts, f)?);
        }
        for k in &snap.host_keys {
            rows.push(entity_row("host_key", &k.host_id.to_string(), &ts, k)?);
        }
        for b in &snap.baselines {
            let id = format!("{}:{}", b.host_id, b.name);
            rows.push(entity_row("baseline", &id, &ts, b)?);
        }
        for a in &snap.activity {
            rows.push(entity_row("activity", &a.id.to_string(), &ts, a)?);
        }
        for k in &snap.ssh_keys {
            rows.push(entity_row("ssh_key", &k.fingerprint, &ts, k)?);
        }
        for (i, p) in snap.ssh_placements.iter().enumerate() {
            let id = format!(
                "{}:{}:{}:{}:{}",
                p.fingerprint, p.host_id, p.username, p.role, i
            );
            rows.push(entity_row("ssh_placement", &id, &ts, p)?);
        }
        for z in &snap.ssh_zones {
            rows.push(entity_row("ssh_zone", &z.id.to_string(), &ts, z)?);
        }
        for c in &snap.credentials {
            rows.push(entity_row("credential", &c.id, &ts, c)?);
        }

        // Build + insert into the swap table first. Live `cp_entities` stays intact
        // until EXCHANGE, so a timeout mid-insert cannot wipe the fleet.
        self.query_raw("TRUNCATE TABLE cp_entities__next").await?;
        const CHUNK: usize = 400;
        let mut n = 0usize;
        for chunk in rows.chunks(CHUNK) {
            n += self.insert_json_each_row("cp_entities__next", chunk).await?;
        }
        self.query_raw("EXCHANGE TABLES cp_entities AND cp_entities__next")
            .await?;
        // Old live data now sits in __next — drop it so the next flush starts clean.
        let _ = self.query_raw("TRUNCATE TABLE cp_entities__next").await;
        Ok(n)
    }

    async fn ensure_control_plane_swap_schema(&self) -> Result<(), ClickHouseError> {
        self.query_raw(
            "CREATE TABLE IF NOT EXISTS cp_entities__next \
             ( \
               entity LowCardinality(String), \
               id String, \
               updated_at DateTime64(6, 'UTC') DEFAULT now64(6), \
               deleted UInt8 DEFAULT 0, \
               payload String \
             ) \
             ENGINE = ReplacingMergeTree(updated_at) \
             ORDER BY (entity, id) \
             SETTINGS index_granularity = 8192",
        )
        .await?;
        Ok(())
    }

    pub async fn query_raw(&self, sql: &str) -> Result<String, ClickHouseError> {
        let res = self
            .http
            .post(format!("{}/", self.base))
            .basic_auth(&self.user, Some(&self.password))
            .query(&[("database", self.database.as_str())])
            .body(sql.to_string())
            .send()
            .await
            .map_err(|e| ClickHouseError::Http(e.to_string()))?;
        if !res.status().is_success() {
            let status = res.status();
            let text = res.text().await.unwrap_or_default();
            return Err(ClickHouseError::Http(format!("{status}: {text}")));
        }
        res.text()
            .await
            .map_err(|e| ClickHouseError::Http(e.to_string()))
    }
}

fn entity_row<T: serde::Serialize>(
    entity: &str,
    id: &str,
    updated_at: &str,
    payload: &T,
) -> Result<serde_json::Value, ClickHouseError> {
    let payload = serde_json::to_string(payload)
        .map_err(|e| ClickHouseError::Msg(format!("encode {entity}: {e}")))?;
    Ok(serde_json::json!({
        "entity": entity,
        "id": id,
        "updated_at": clickhouse_ts(updated_at),
        "deleted": 0,
        "payload": payload,
    }))
}

/// ClickHouse JSONEachRow DateTime64 prefers `YYYY-MM-DD HH:MM:SS[.ffffff]`.
fn clickhouse_ts(raw: &str) -> String {
    let s = raw.trim();
    if s.is_empty() || s.eq_ignore_ascii_case("now") {
        return crate::sys_metrics::utc_now_rfc3339()
            .replace('T', " ")
            .trim_end_matches('Z')
            .replace('Z', "")
            .chars()
            .take(26)
            .collect::<String>()
            .trim_end_matches('+')
            .to_string();
    }
    let mut out = s.replace('T', " ");
    if let Some(i) = out.find('Z') {
        out.truncate(i);
    }
    if let Some(i) = out.find('+') {
        // Drop timezone offset if present after the time.
        if i > 10 {
            out.truncate(i);
        }
    }
    out.trim().to_string()
}

fn esc(s: &str) -> String {
    s.replace('\'', "''")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmite_proto::HostId;
    use rustmite_store::{HostRecord, StoreSnapshot};
    use std::collections::BTreeMap;
    use uuid::Uuid;

    #[tokio::test]
    async fn control_plane_round_trip() {
        let Some(ch) = ClickHouseClient::from_env() else {
            eprintln!("skip: ClickHouse disabled");
            return;
        };
        if ch.wait_ready(3, Duration::from_millis(200)).await.is_err() {
            eprintln!("skip: ClickHouse not reachable");
            return;
        }
        ch.ensure_control_plane_schema().await.expect("schema");
        // Use a dedicated namespace via truncate — lab-only.
        ch.reset_control_plane().await.expect("reset");

        let host_id = HostId::new_v7();
        let snap = StoreSnapshot {
            schema_version: 1,
            saved_at: "2026-01-01 00:00:00.000000".into(),
            hosts: vec![HostRecord {
                id: host_id,
                tenant_id: Uuid::nil(),
                display_name: "ch-persist-host".into(),
                primary_addr: Some("10.9.9.9".into()),
                ssh_port: 22,
                arch: None,
                kernel: None,
                os: None,
                os_id: None,
                os_version: None,
                agent_kind: "ssh".into(),
                ingest_token: None,
                labels: BTreeMap::new(),
                last_scan_at: None,
                last_outcome: None,
                timeouts: Default::default(),
                auth_status: Some("ok".into()),
                auth_detail: None,
                auth_checked_at: None,
            }],
            jobs: vec![],
            metas: vec![],
            observations: vec![],
            findings: vec![],
            host_keys: vec![],
            baselines: vec![],
            activity: vec![],
            ssh_keys: vec![],
            ssh_placements: vec![],
            ssh_zones: vec![],
            credentials: vec![],
        };
        let n = ch.save_control_plane(&snap).await.expect("save");
        assert_eq!(n, 1);
        let loaded = ch.load_control_plane().await.expect("load").expect("snap");
        assert_eq!(loaded.hosts.len(), 1);
        assert_eq!(loaded.hosts[0].display_name, "ch-persist-host");
        assert_eq!(loaded.hosts[0].id, host_id);
    }
}
