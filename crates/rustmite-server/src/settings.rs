//! Effective control-plane settings catalog + runtime snapshot (secrets redacted).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// One tunable the operator can change via CLI flag / env.
#[derive(Clone, Debug, Serialize)]
pub struct SettingDescriptor {
    pub key: &'static str,
    pub flag: &'static str,
    pub env: &'static str,
    pub value_type: &'static str,
    pub default: &'static str,
    pub description: &'static str,
    pub requires_restart: bool,
    pub secret: bool,
    /// Optional enumerated choices for the console.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<&'static [&'static str]>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EffectiveSettings {
    pub listen: String,
    pub node_listen: String,
    pub checks_path: String,
    pub checks_count: usize,
    pub webhook_configured: bool,
    pub webhook_url: Option<String>,
    pub webhook_secret_configured: bool,
    pub seed_demo: bool,
    pub seed_hosts: usize,
    pub scan_sim: bool,
    pub api_token_required: bool,
    pub rust_log: Option<String>,
    pub version: String,
    pub default_check_set: String,
    pub scan_interval: String,
    pub scan_jitter_pct: u8,
    pub max_concurrent_scans: usize,
    pub scan_timeout_secs: u64,
    pub scan_history_per_host: usize,
    pub clickhouse_url: Option<String>,
    pub clickhouse_configured: bool,
    pub clickhouse_db: Option<String>,
    /// Absolute path to the server log file (`.dev/server.log`).
    pub server_log_path: String,
    /// Absolute path to the local config override file (`.dev/config.env`).
    pub config_path: String,
    /// Directory where uploaded SSH identity keys are stored.
    pub ssh_identities_dir: String,
    /// Directory where stored SSH passwords are kept (mode 600 files).
    pub ssh_secrets_dir: String,
    pub noise_xx_enabled: bool,
    pub noise_xx_server_fingerprint: Option<String>,
    pub tls_enabled: bool,
    pub tls_cert: Option<String>,
    pub tls_auto_generated: bool,
    pub node_tls_enabled: bool,
    pub node_tls_cert: Option<String>,
    pub node_tls_mtls: bool,
    pub node_tls_client_ca: Option<String>,
    pub ssh_connect_timeout_secs: u64,
    pub ssh_auth_timeout_secs: u64,
    pub ssh_cmd_timeout_secs: u64,
    pub ssh_inactivity_timeout_secs: u64,
    pub ssh_delivery_timeout_secs: u64,
    pub ssh_fingerprint_timeout_secs: u64,
    pub ssh_connect_delay_ms: u64,
    pub ssh_timeout_jitter_pct: u8,
    pub clickhouse_timeout_secs: u64,
    /// Probe agent resource envelope (docs/03 Limits).
    pub probe_max_rss_bytes: u64,
    pub probe_max_observations: u32,
    pub probe_max_output_bytes: u64,
    pub probe_max_files_examined: u32,
    pub probe_max_bytes_hashed: u64,
    pub probe_nice: i8,
    pub probe_io_idle: bool,
    pub probe_max_transfer_bps: u64,
    pub probe_max_cpu_pct: u8,
    pub probe_max_open_files: u32,
    /// Fleet host reachability checker (Settings panel — not CLI/env).
    pub host_health_enabled: bool,
    pub host_health_interval_secs: u64,
    pub host_health_concurrency: usize,
    pub host_health_connect_timeout_secs: u64,
    /// WebAuthn RP advertised to the browser (empty = use request Origin/Host).
    pub webauthn_origin: Option<String>,
    pub webauthn_rp_id: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SettingsExport {
    pub schema_version: u32,
    pub exported_at: String,
    pub catalog: Vec<SettingDescriptor>,
    pub effective: EffectiveSettings,
    /// Non-secret overrides currently persisted (secrets listed separately).
    pub overrides: BTreeMap<String, String>,
    /// Secret keys that have a persisted override (values never exported).
    pub secret_overrides: Vec<String>,
    /// Path of the on-disk overrides file.
    pub settings_file: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct SettingsPatchResult {
    pub applied: Vec<String>,
    pub pending_restart: Vec<String>,
    pub cleared: Vec<String>,
    pub export: SettingsExport,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SettingsPatchRequest {
    /// Map of catalog key → string value. Empty string clears optional settings.
    pub values: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SettingsFile {
    schema_version: u32,
    values: BTreeMap<String, String>,
}

pub const SETTINGS_CATALOG: &[SettingDescriptor] = &[
    SettingDescriptor {
        key: "listen",
        flag: "--listen",
        env: "RUSTMITE_LISTEN",
        value_type: "socket_addr",
        default: "0.0.0.0:8080",
        description: "Operator API + console listen address",
        requires_restart: true,
        secret: false,
        options: None,
    },
    SettingDescriptor {
        key: "node_listen",
        flag: "--node-listen",
        env: "RUSTMITE_NODE_LISTEN",
        value_type: "socket_addr",
        default: "0.0.0.0:8443",
        description: "Node ingest / lease API listen address",
        requires_restart: true,
        secret: false,
        options: None,
    },
    SettingDescriptor {
        key: "checks",
        flag: "--checks",
        env: "RUSTMITE_CHECKS",
        value_type: "path",
        default: "checks",
        description: "Directory of check TOML manifests loaded at startup",
        requires_restart: true,
        secret: false,
        options: None,
    },
    SettingDescriptor {
        key: "default_check_set",
        flag: "--default-check-set",
        env: "RUSTMITE_DEFAULT_CHECK_SET",
        value_type: "enum",
        default: "standard",
        description: "Default check set applied when enqueueing scheduled / manual scans",
        requires_restart: false,
        secret: false,
        options: Some(&["pulse", "standard", "deep", "incident"]),
    },
    SettingDescriptor {
        key: "scan_interval",
        flag: "--scan-interval",
        env: "RUSTMITE_SCAN_INTERVAL",
        value_type: "duration",
        default: "1h",
        description: "Fleet cadence used when a host enables automatic collection (hosts default to manual)",
        requires_restart: false,
        secret: false,
        options: Some(&["5m", "15m", "30m", "1h", "6h", "12h", "24h", "7d"]),
    },
    SettingDescriptor {
        key: "scan_jitter_pct",
        flag: "--scan-jitter-pct",
        env: "RUSTMITE_SCAN_JITTER_PCT",
        value_type: "u8",
        default: "20",
        description: "Randomise schedule by ±N% so fleets do not thundering-herd",
        requires_restart: false,
        secret: false,
        options: Some(&["0", "10", "20", "30", "50"]),
    },
    SettingDescriptor {
        key: "max_concurrent_scans",
        flag: "--max-concurrent-scans",
        env: "RUSTMITE_MAX_CONCURRENT_SCANS",
        value_type: "usize",
        default: "32",
        description: "Global cap on simultaneously running scans across all nodes",
        requires_restart: false,
        secret: false,
        options: Some(&["8", "16", "32", "64", "128"]),
    },
    SettingDescriptor {
        key: "scan_timeout_secs",
        flag: "--scan-timeout-secs",
        env: "RUSTMITE_SCAN_TIMEOUT_SECS",
        value_type: "u64",
        default: "120",
        description: "Per-host scan wall-clock timeout before the job is marked failed",
        requires_restart: false,
        secret: false,
        options: Some(&["60", "90", "120", "180", "300"]),
    },
    SettingDescriptor {
        key: "scan_history_per_host",
        flag: "--scan-history-per-host",
        env: "RUSTMITE_SCAN_HISTORY_PER_HOST",
        value_type: "usize",
        default: "3",
        description: "Finished scans retained per host (newest kept; active jobs always retained). Hosts may override via label scan_history",
        requires_restart: false,
        secret: false,
        options: Some(&["1", "3", "5", "10", "20", "50"]),
    },
    SettingDescriptor {
        key: "ssh_connect_timeout_secs",
        flag: "--ssh-connect-timeout-secs",
        env: "RUSTMITE_SSH_CONNECT_TIMEOUT_SECS",
        value_type: "u64",
        default: "10",
        description: "Per-host TCP/SSH connect timeout (docs/04 §8)",
        requires_restart: false,
        secret: false,
        options: Some(&["5", "10", "15", "30"]),
    },
    SettingDescriptor {
        key: "ssh_auth_timeout_secs",
        flag: "--ssh-auth-timeout-secs",
        env: "RUSTMITE_SSH_AUTH_TIMEOUT_SECS",
        value_type: "u64",
        default: "20",
        description: "Per-host SSH public-key auth timeout",
        requires_restart: false,
        secret: false,
        options: Some(&["10", "20", "30", "60"]),
    },
    SettingDescriptor {
        key: "ssh_cmd_timeout_secs",
        flag: "--ssh-cmd-timeout-secs",
        env: "RUSTMITE_SSH_CMD_TIMEOUT_SECS",
        value_type: "u64",
        default: "60",
        description: "Per-host remote command / fingerprint exec timeout",
        requires_restart: false,
        secret: false,
        options: Some(&["30", "60", "90", "120"]),
    },
    SettingDescriptor {
        key: "ssh_inactivity_timeout_secs",
        flag: "--ssh-inactivity-timeout-secs",
        env: "RUSTMITE_SSH_INACTIVITY_TIMEOUT_SECS",
        value_type: "u64",
        default: "90",
        description: "Per-host SSH channel inactivity timeout",
        requires_restart: false,
        secret: false,
        options: Some(&["30", "60", "90", "180"]),
    },
    SettingDescriptor {
        key: "ssh_delivery_timeout_secs",
        flag: "--ssh-delivery-timeout-secs",
        env: "RUSTMITE_SSH_DELIVERY_TIMEOUT_SECS",
        value_type: "u64",
        default: "30",
        description: "Per-host probe delivery timeout",
        requires_restart: false,
        secret: false,
        options: Some(&["15", "30", "60"]),
    },
    SettingDescriptor {
        key: "ssh_fingerprint_timeout_secs",
        flag: "--ssh-fingerprint-timeout-secs",
        env: "RUSTMITE_SSH_FINGERPRINT_TIMEOUT_SECS",
        value_type: "u64",
        default: "10",
        description: "Per-host capability/fingerprint probe timeout",
        requires_restart: false,
        secret: false,
        options: Some(&["5", "10", "20"]),
    },
    SettingDescriptor {
        key: "ssh_connect_delay_ms",
        flag: "--ssh-connect-delay-ms",
        env: "RUSTMITE_SSH_CONNECT_DELAY_MS",
        value_type: "u64",
        default: "0",
        description: "Per-host delay before opening TCP (stagger / rate-limit)",
        requires_restart: false,
        secret: false,
        options: Some(&["0", "50", "100", "250", "500", "1000"]),
    },
    SettingDescriptor {
        key: "ssh_timeout_jitter_pct",
        flag: "--ssh-timeout-jitter-pct",
        env: "RUSTMITE_SSH_TIMEOUT_JITTER_PCT",
        value_type: "u8",
        default: "10",
        description: "Jitter ±N% applied to per-host SSH timeouts (docs/04 §8)",
        requires_restart: false,
        secret: false,
        options: Some(&["0", "5", "10", "20"]),
    },
    SettingDescriptor {
        key: "clickhouse_timeout_secs",
        flag: "--clickhouse-timeout-secs",
        env: "RUSTMITE_CLICKHOUSE_TIMEOUT_SECS",
        value_type: "u64",
        default: "30",
        description: "ClickHouse HTTP connect/request timeout for RPL hunts",
        requires_restart: false,
        secret: false,
        options: Some(&["10", "30", "60", "120"]),
    },
    SettingDescriptor {
        key: "webhook_url",
        flag: "--webhook-url",
        env: "RUSTMITE_WEBHOOK_URL",
        value_type: "url",
        default: "(unset)",
        description: "Optional webhook sink for findings / alerts",
        requires_restart: true,
        secret: false,
        options: None,
    },
    SettingDescriptor {
        key: "webhook_secret",
        flag: "--webhook-secret",
        env: "RUSTMITE_WEBHOOK_SECRET",
        value_type: "secret",
        default: "rustmite-dev-secret",
        description: "HMAC secret for webhook signatures (value never exported)",
        requires_restart: true,
        secret: true,
        options: None,
    },
    SettingDescriptor {
        key: "seed_demo",
        flag: "--seed-demo",
        env: "RUSTMITE_SEED_DEMO",
        value_type: "bool",
        default: "false",
        description: "Seed a multi-profile demo fleet for the operator console",
        requires_restart: true,
        secret: false,
        options: Some(&["true", "false"]),
    },
    SettingDescriptor {
        key: "seed_hosts",
        flag: "--seed-hosts",
        env: "RUSTMITE_SEED_HOSTS",
        value_type: "usize",
        default: "3000",
        description: "Host count when demo seeding is enabled",
        requires_restart: true,
        secret: false,
        options: None,
    },
    SettingDescriptor {
        key: "scan_sim",
        flag: "--scan-sim",
        env: "RUSTMITE_SCAN_SIM",
        value_type: "bool",
        default: "true",
        description: "Background simulator that advances queued scans and emits stage logs",
        requires_restart: true,
        secret: false,
        options: Some(&["true", "false"]),
    },
    SettingDescriptor {
        key: "clickhouse_url",
        flag: "--clickhouse-url",
        env: "RUSTMITE_CLICKHOUSE_URL",
        value_type: "url",
        default: "(unset)",
        description: "ClickHouse HTTP endpoint for RPL hunts (auto http://127.0.0.1:8123 unless RUSTMITE_CLICKHOUSE=0)",
        requires_restart: true,
        secret: false,
        options: None,
    },
    SettingDescriptor {
        key: "clickhouse_user",
        flag: "(none)",
        env: "RUSTMITE_CLICKHOUSE_USER",
        value_type: "string",
        default: "rustmite",
        description: "ClickHouse username",
        requires_restart: true,
        secret: false,
        options: None,
    },
    SettingDescriptor {
        key: "clickhouse_password",
        flag: "(none)",
        env: "RUSTMITE_CLICKHOUSE_PASSWORD",
        value_type: "secret",
        default: "rustmite",
        description: "ClickHouse password (never exported)",
        requires_restart: true,
        secret: true,
        options: None,
    },
    SettingDescriptor {
        key: "noise_xx",
        flag: "--noise-xx",
        env: "RUSTMITE_NOISE_XX",
        value_type: "bool",
        default: "true",
        description: "Require Noise XX (Noise_XX_25519_ChaChaPoly_BLAKE2s) for node↔server identity",
        requires_restart: true,
        secret: false,
        options: Some(&["true", "false"]),
    },
    SettingDescriptor {
        key: "tls",
        flag: "--tls / --no-tls",
        env: "RUSTMITE_TLS / RUSTMITE_NO_TLS",
        value_type: "bool",
        default: "true",
        description: "Enable TLS 1.3; when on without cert/key, auto-generates self-signed PEMs under --tls-dir",
        requires_restart: true,
        secret: false,
        options: Some(&["true", "false"]),
    },
    SettingDescriptor {
        key: "tls_dir",
        flag: "--tls-dir",
        env: "RUSTMITE_TLS_DIR",
        value_type: "path",
        default: ".dev/tls",
        description: "Directory for auto-generated cert.pem / key.pem",
        requires_restart: true,
        secret: false,
        options: None,
    },
    SettingDescriptor {
        key: "tls_cert",
        flag: "--tls-cert",
        env: "RUSTMITE_TLS_CERT",
        value_type: "path",
        default: "(auto under tls_dir)",
        description: "PEM certificate chain; omit to auto-generate a self-signed cert for local/dev",
        requires_restart: true,
        secret: false,
        options: None,
    },
    SettingDescriptor {
        key: "tls_key",
        flag: "--tls-key",
        env: "RUSTMITE_TLS_KEY",
        value_type: "path",
        default: "(auto under tls_dir)",
        description: "PEM private key paired with --tls-cert (never exported)",
        requires_restart: true,
        secret: true,
        options: None,
    },
    SettingDescriptor {
        key: "node_tls_cert",
        flag: "--node-tls-cert",
        env: "RUSTMITE_NODE_TLS_CERT",
        value_type: "path",
        default: "(falls back to tls_cert)",
        description: "Optional PEM cert for the node listener (defaults to operator TLS cert)",
        requires_restart: true,
        secret: false,
        options: None,
    },
    SettingDescriptor {
        key: "node_tls_key",
        flag: "--node-tls-key",
        env: "RUSTMITE_NODE_TLS_KEY",
        value_type: "path",
        default: "(falls back to tls_key)",
        description: "Optional PEM key for the node listener (never exported)",
        requires_restart: true,
        secret: true,
        options: None,
    },
    SettingDescriptor {
        key: "node_tls_client_ca",
        flag: "--node-tls-client-ca",
        env: "RUSTMITE_NODE_TLS_CLIENT_CA",
        value_type: "path",
        default: "(unset)",
        description: "PEM CA bundle; when set, node listener requires client certificates (mTLS)",
        requires_restart: true,
        secret: false,
        options: None,
    },
    SettingDescriptor {
        key: "webauthn_origin",
        flag: "--webauthn-origin",
        env: "(none)",
        value_type: "url",
        default: "(request Origin)",
        description: "WebAuthn origin advertised to YubiKeys (e.g. https://console.example). Empty uses the browser Origin header.",
        requires_restart: false,
        secret: false,
        options: None,
    },
    SettingDescriptor {
        key: "webauthn_rp_id",
        flag: "--webauthn-rp-id",
        env: "(none)",
        value_type: "string",
        default: "(hostname of origin)",
        description: "WebAuthn relying-party ID (hostname). Empty uses the hostname of the origin.",
        requires_restart: false,
        secret: false,
        options: None,
    },
    SettingDescriptor {
        key: "api_token",
        flag: "(none)",
        env: "RUSTMITE_API_TOKEN",
        value_type: "secret",
        default: "(unset)",
        description: "If set, operator /v1/* routes require Authorization: Bearer <token>",
        requires_restart: true,
        secret: true,
        options: None,
    },
    SettingDescriptor {
        key: "rust_log",
        flag: "(none)",
        env: "RUST_LOG",
        value_type: "string",
        default: "info",
        description: "tracing-subscriber env filter (e.g. rustmite_server=debug)",
        requires_restart: true,
        secret: false,
        options: None,
    },
];

#[derive(Clone, Debug)]
pub struct RuntimeSettings {
    pub listen: SocketAddr,
    pub node_listen: SocketAddr,
    pub checks_path: PathBuf,
    pub checks_count: usize,
    pub webhook_url: Option<String>,
    pub webhook_secret_set: bool,
    pub seed_demo: bool,
    pub seed_hosts: usize,
    pub scan_sim: bool,
    pub api_token_required: bool,
    pub default_check_set: String,
    pub scan_interval: String,
    pub scan_jitter_pct: u8,
    pub max_concurrent_scans: usize,
    pub scan_timeout_secs: u64,
    pub scan_history_per_host: usize,
    pub clickhouse_url: Option<String>,
    pub noise_xx_enabled: bool,
    pub noise_xx_server_fingerprint: Option<String>,
    pub tls_enabled: bool,
    pub tls_cert: Option<PathBuf>,
    pub tls_auto_generated: bool,
    pub node_tls_enabled: bool,
    pub node_tls_cert: Option<PathBuf>,
    pub node_tls_client_ca: Option<PathBuf>,
    pub ssh_connect_timeout_secs: u64,
    pub ssh_auth_timeout_secs: u64,
    pub ssh_cmd_timeout_secs: u64,
    pub ssh_inactivity_timeout_secs: u64,
    pub ssh_delivery_timeout_secs: u64,
    pub ssh_fingerprint_timeout_secs: u64,
    pub ssh_connect_delay_ms: u64,
    pub ssh_timeout_jitter_pct: u8,
    pub clickhouse_timeout_secs: u64,
    /// Envelope pushed into every ScanRequest (memory / CPU / I/O / bandwidth / counts).
    pub probe_limits: rustmite_proto::Limits,
}

impl RuntimeSettings {
    /// Backward-compatible export used until the UI settings manager is wired.
    pub fn export(&self) -> SettingsExport {
        SettingsExport {
            schema_version: 6,
            exported_at: crate::sys_metrics::utc_now_rfc3339(),
            catalog: SETTINGS_CATALOG.to_vec(),
            effective: self.export_effective(),
            overrides: BTreeMap::new(),
            secret_overrides: Vec::new(),
            settings_file: SettingsManager::default_path().display().to_string(),
        }
    }

    pub fn export_effective(&self) -> EffectiveSettings {
        EffectiveSettings {
            listen: self.listen.to_string(),
            node_listen: self.node_listen.to_string(),
            checks_path: self.checks_path.display().to_string(),
            checks_count: self.checks_count,
            webhook_configured: self.webhook_url.is_some(),
            webhook_url: self.webhook_url.clone(),
            webhook_secret_configured: self.webhook_secret_set,
            seed_demo: self.seed_demo,
            seed_hosts: self.seed_hosts,
            scan_sim: self.scan_sim,
            api_token_required: self.api_token_required,
            rust_log: std::env::var("RUST_LOG").ok(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            default_check_set: self.default_check_set.clone(),
            scan_interval: self.scan_interval.clone(),
            scan_jitter_pct: self.scan_jitter_pct,
            max_concurrent_scans: self.max_concurrent_scans,
            scan_timeout_secs: self.scan_timeout_secs,
            scan_history_per_host: self.scan_history_per_host,
            clickhouse_url: self.clickhouse_url.clone(),
            clickhouse_configured: self.clickhouse_url.is_some(),
            clickhouse_db: std::env::var("RUSTMITE_CLICKHOUSE_DB")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .or_else(|| {
                    if self.clickhouse_url.is_some() {
                        Some("rustmite".into())
                    } else {
                        None
                    }
                }),
            server_log_path: resolve_local_path(&[".dev/server.log"]),
            config_path: resolve_local_path(&[".dev/config.env"]),
            ssh_identities_dir: resolve_local_path(&[".dev/ssh-identities"]),
            ssh_secrets_dir: resolve_local_path(&[".dev/ssh-secrets"]),
            noise_xx_enabled: self.noise_xx_enabled,
            noise_xx_server_fingerprint: self.noise_xx_server_fingerprint.clone(),
            tls_enabled: self.tls_enabled,
            tls_cert: self.tls_cert.as_ref().map(|p| p.display().to_string()),
            tls_auto_generated: self.tls_auto_generated,
            node_tls_enabled: self.node_tls_enabled,
            node_tls_cert: self
                .node_tls_cert
                .as_ref()
                .map(|p| p.display().to_string()),
            node_tls_mtls: self.node_tls_client_ca.is_some(),
            node_tls_client_ca: self
                .node_tls_client_ca
                .as_ref()
                .map(|p| p.display().to_string()),
            ssh_connect_timeout_secs: self.ssh_connect_timeout_secs,
            ssh_auth_timeout_secs: self.ssh_auth_timeout_secs,
            ssh_cmd_timeout_secs: self.ssh_cmd_timeout_secs,
            ssh_inactivity_timeout_secs: self.ssh_inactivity_timeout_secs,
            ssh_delivery_timeout_secs: self.ssh_delivery_timeout_secs,
            ssh_fingerprint_timeout_secs: self.ssh_fingerprint_timeout_secs,
            ssh_connect_delay_ms: self.ssh_connect_delay_ms,
            ssh_timeout_jitter_pct: self.ssh_timeout_jitter_pct,
            clickhouse_timeout_secs: self.clickhouse_timeout_secs,
            probe_max_rss_bytes: self.probe_limits.max_rss_bytes,
            probe_max_observations: self.probe_limits.max_observations,
            probe_max_output_bytes: self.probe_limits.max_output_bytes,
            probe_max_files_examined: self.probe_limits.max_files_examined,
            probe_max_bytes_hashed: self.probe_limits.max_bytes_hashed,
            probe_nice: self.probe_limits.nice,
            probe_io_idle: self.probe_limits.io_idle,
            probe_max_transfer_bps: self.probe_limits.max_transfer_bps,
            probe_max_cpu_pct: self.probe_limits.max_cpu_pct,
            probe_max_open_files: self.probe_limits.max_open_files,
            host_health_enabled: true,
            host_health_interval_secs: crate::host_health::DEFAULT_INTERVAL_SECS,
            host_health_concurrency: crate::host_health::DEFAULT_CONCURRENCY,
            host_health_connect_timeout_secs: 3,
            webauthn_origin: None,
            webauthn_rp_id: None,
        }
    }
}

fn resolve_local_path(defaults: &[&str]) -> String {
    for d in defaults {
        let p = std::path::PathBuf::from(d);
        if let Ok(abs) = std::fs::canonicalize(&p) {
            return abs.display().to_string();
        }
        if let Ok(cwd) = std::env::current_dir() {
            return cwd.join(p).display().to_string();
        }
        return p.display().to_string();
    }
    String::new()
}

fn catalog_by_key(key: &str) -> Option<&'static SettingDescriptor> {
    SETTINGS_CATALOG.iter().find(|d| d.key == key)
}

fn parse_bool(raw: &str) -> Result<bool, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => Err(format!("expected bool, got {other:?}")),
    }
}

fn optional_string(raw: &str) -> Option<String> {
    let t = raw.trim();
    if t.is_empty() || t == "(unset)" {
        None
    } else {
        Some(t.to_string())
    }
}

fn optional_path(raw: &str) -> Option<PathBuf> {
    optional_string(raw).map(PathBuf::from)
}

/// Mutable settings store: live runtime values + persisted overrides.
#[derive(Clone)]
pub struct SettingsManager {
    inner: Arc<RwLock<SettingsInner>>,
}

struct SettingsInner {
    runtime: RuntimeSettings,
    overrides: BTreeMap<String, String>,
    path: PathBuf,
}

impl SettingsManager {
    pub fn new(runtime: RuntimeSettings, path: PathBuf) -> Self {
        Self {
            inner: Arc::new(RwLock::new(SettingsInner {
                runtime,
                overrides: BTreeMap::new(),
                path,
            })),
        }
    }

    pub fn default_path() -> PathBuf {
        std::env::var_os("RUSTMITE_SETTINGS_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(".dev/settings-overrides.json"))
    }

    /// Load overrides from disk (if present) and apply them onto the runtime snapshot.
    pub async fn load_overrides(&self) -> anyhow::Result<usize> {
        let mut guard = self.inner.write().await;
        let path = guard.path.clone();
        if !path.exists() {
            return Ok(0);
        }
        let raw = std::fs::read_to_string(&path)?;
        let file: SettingsFile = serde_json::from_str(&raw)?;
        let mut count = 0;
        for (key, value) in file.values {
            if catalog_by_key(&key).is_none() {
                tracing::warn!(%key, "ignoring unknown settings override");
                continue;
            }
            if let Err(e) = guard.apply_one(&key, &value) {
                tracing::warn!(%key, error = %e, "failed to apply settings override");
                continue;
            }
            guard.overrides.insert(key, value);
            count += 1;
        }
        Ok(count)
    }

    pub async fn export(&self) -> SettingsExport {
        self.inner.read().await.export()
    }

    pub async fn snapshot(&self) -> RuntimeSettings {
        self.inner.read().await.runtime.clone()
    }

    pub async fn patch(&self, req: SettingsPatchRequest) -> Result<SettingsPatchResult, String> {
        let mut guard = self.inner.write().await;
        let mut applied = Vec::new();
        let mut pending_restart = Vec::new();
        let mut cleared = Vec::new();

        for (key, value) in &req.values {
            let desc = catalog_by_key(key).ok_or_else(|| format!("unknown setting: {key}"))?;
            let trimmed = value.trim();
            // Secrets: empty means "leave unchanged"
            if desc.secret && trimmed.is_empty() {
                continue;
            }
            // Optional clears
            let clearing = !desc.secret
                && matches!(
                    desc.value_type,
                    "url" | "path" | "secret" | "string" | "socket_addr"
                )
                && (trimmed.is_empty() || trimmed == "(unset)");

            if clearing {
                guard.apply_clear(key)?;
                guard.overrides.remove(key);
                cleared.push(key.clone());
                if desc.requires_restart {
                    pending_restart.push(key.clone());
                } else {
                    applied.push(key.clone());
                }
                continue;
            }

            guard.apply_one(key, trimmed)?;
            if desc.secret {
                // Persist marker only in overrides; keep real value in overrides for restart
                // but never export it.
                guard.overrides.insert(key.clone(), trimmed.to_string());
            } else {
                guard.overrides.insert(key.clone(), trimmed.to_string());
            }
            if desc.requires_restart {
                pending_restart.push(key.clone());
            } else {
                applied.push(key.clone());
            }
        }

        guard.persist().map_err(|e| e.to_string())?;
        Ok(SettingsPatchResult {
            applied,
            pending_restart,
            cleared,
            export: guard.export(),
        })
    }
}

impl SettingsInner {
    fn export(&self) -> SettingsExport {
        let mut public_overrides = BTreeMap::new();
        let mut secret_overrides = Vec::new();
        for (k, v) in &self.overrides {
            if catalog_by_key(k).map(|d| d.secret).unwrap_or(false) {
                secret_overrides.push(k.clone());
            } else {
                public_overrides.insert(k.clone(), v.clone());
            }
        }
        secret_overrides.sort();
        SettingsExport {
            schema_version: 6,
            exported_at: crate::sys_metrics::utc_now_rfc3339(),
            catalog: SETTINGS_CATALOG.to_vec(),
            effective: self.runtime.export_effective(),
            overrides: public_overrides,
            secret_overrides,
            settings_file: self.path.display().to_string(),
        }
    }

    fn persist(&self) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = SettingsFile {
            schema_version: 1,
            values: self.overrides.clone(),
        };
        let raw = serde_json::to_string_pretty(&file)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, raw)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    fn apply_clear(&mut self, key: &str) -> Result<(), String> {
        match key {
            "webhook_url" => self.runtime.webhook_url = None,
            "webhook_secret" => self.runtime.webhook_secret_set = false,
            "clickhouse_url" => self.runtime.clickhouse_url = None,
            "clickhouse_password" => {}
            "api_token" => self.runtime.api_token_required = false,
            "tls_cert" => self.runtime.tls_cert = None,
            "tls_key" => {}
            "node_tls_cert" => self.runtime.node_tls_cert = None,
            "node_tls_key" => {}
            "node_tls_client_ca" => self.runtime.node_tls_client_ca = None,
            "webauthn_origin" => {}
            "webauthn_rp_id" => {}
            "rust_log" => {
                std::env::remove_var("RUST_LOG");
            }
            other => return Err(format!("{other} cannot be cleared")),
        }
        Ok(())
    }

    fn apply_one(&mut self, key: &str, raw: &str) -> Result<(), String> {
        let desc = catalog_by_key(key).ok_or_else(|| format!("unknown setting: {key}"))?;
        if let Some(opts) = desc.options {
            let ok = opts.iter().any(|o| *o == raw)
                || matches!(desc.value_type, "bool" | "u8" | "u64" | "usize" | "string" | "url" | "path" | "socket_addr" | "duration" | "secret" | "enum");
            // For enumerated options, enforce membership when options are present and value_type is enum/u8/u64/usize
            if matches!(desc.value_type, "enum" | "u8" | "u64" | "usize")
                && desc.options.is_some()
                && !opts.iter().any(|o| *o == raw)
            {
                // still allow free numeric if type is numeric but not in list? For UX allow any parseable number for numeric types
                if matches!(desc.value_type, "enum") {
                    return Err(format!(
                        "{key}: {raw:?} not in {:?}",
                        opts
                    ));
                }
            }
            let _ = ok;
        }

        match key {
            "listen" => {
                self.runtime.listen = raw
                    .parse::<SocketAddr>()
                    .map_err(|e| format!("listen: {e}"))?;
            }
            "node_listen" => {
                self.runtime.node_listen = raw
                    .parse::<SocketAddr>()
                    .map_err(|e| format!("node_listen: {e}"))?;
            }
            "checks" => {
                self.runtime.checks_path = PathBuf::from(raw);
            }
            "default_check_set" => {
                self.runtime.default_check_set = raw.to_string();
            }
            "scan_interval" => {
                self.runtime.scan_interval = raw.to_string();
            }
            "scan_jitter_pct" => {
                self.runtime.scan_jitter_pct = raw
                    .parse()
                    .map_err(|e| format!("scan_jitter_pct: {e}"))?;
            }
            "max_concurrent_scans" => {
                self.runtime.max_concurrent_scans = raw
                    .parse()
                    .map_err(|e| format!("max_concurrent_scans: {e}"))?;
            }
            "scan_timeout_secs" => {
                self.runtime.scan_timeout_secs = raw
                    .parse()
                    .map_err(|e| format!("scan_timeout_secs: {e}"))?;
            }
            "scan_history_per_host" => {
                let n: usize = raw
                    .parse()
                    .map_err(|e| format!("scan_history_per_host: {e}"))?;
                if n > 200 {
                    return Err("scan_history_per_host must be <= 200".into());
                }
                self.runtime.scan_history_per_host = n;
            }
            "ssh_connect_timeout_secs" => {
                self.runtime.ssh_connect_timeout_secs = raw
                    .parse()
                    .map_err(|e| format!("ssh_connect_timeout_secs: {e}"))?;
            }
            "ssh_auth_timeout_secs" => {
                self.runtime.ssh_auth_timeout_secs = raw
                    .parse()
                    .map_err(|e| format!("ssh_auth_timeout_secs: {e}"))?;
            }
            "ssh_cmd_timeout_secs" => {
                self.runtime.ssh_cmd_timeout_secs = raw
                    .parse()
                    .map_err(|e| format!("ssh_cmd_timeout_secs: {e}"))?;
            }
            "ssh_inactivity_timeout_secs" => {
                self.runtime.ssh_inactivity_timeout_secs = raw
                    .parse()
                    .map_err(|e| format!("ssh_inactivity_timeout_secs: {e}"))?;
            }
            "ssh_delivery_timeout_secs" => {
                self.runtime.ssh_delivery_timeout_secs = raw
                    .parse()
                    .map_err(|e| format!("ssh_delivery_timeout_secs: {e}"))?;
            }
            "ssh_fingerprint_timeout_secs" => {
                self.runtime.ssh_fingerprint_timeout_secs = raw
                    .parse()
                    .map_err(|e| format!("ssh_fingerprint_timeout_secs: {e}"))?;
            }
            "ssh_connect_delay_ms" => {
                self.runtime.ssh_connect_delay_ms = raw
                    .parse()
                    .map_err(|e| format!("ssh_connect_delay_ms: {e}"))?;
            }
            "ssh_timeout_jitter_pct" => {
                self.runtime.ssh_timeout_jitter_pct = raw
                    .parse()
                    .map_err(|e| format!("ssh_timeout_jitter_pct: {e}"))?;
            }
            "clickhouse_timeout_secs" => {
                self.runtime.clickhouse_timeout_secs = raw
                    .parse()
                    .map_err(|e| format!("clickhouse_timeout_secs: {e}"))?;
                std::env::set_var("RUSTMITE_CLICKHOUSE_TIMEOUT_SECS", raw);
            }
            "webhook_url" => {
                self.runtime.webhook_url = optional_string(raw);
            }
            "webhook_secret" => {
                self.runtime.webhook_secret_set = !raw.is_empty();
            }
            "seed_demo" => {
                self.runtime.seed_demo = parse_bool(raw)?;
            }
            "seed_hosts" => {
                self.runtime.seed_hosts =
                    raw.parse().map_err(|e| format!("seed_hosts: {e}"))?;
            }
            "scan_sim" => {
                self.runtime.scan_sim = parse_bool(raw)?;
            }
            "clickhouse_url" => {
                self.runtime.clickhouse_url = optional_string(raw);
                if let Some(ref url) = self.runtime.clickhouse_url {
                    std::env::set_var("RUSTMITE_CLICKHOUSE_URL", url);
                }
            }
            "clickhouse_user" => {
                std::env::set_var("RUSTMITE_CLICKHOUSE_USER", raw);
            }
            "clickhouse_password" => {
                std::env::set_var("RUSTMITE_CLICKHOUSE_PASSWORD", raw);
            }
            "noise_xx" => {
                self.runtime.noise_xx_enabled = parse_bool(raw)?;
            }
            "tls" => {
                self.runtime.tls_enabled = parse_bool(raw)?;
            }
            "tls_dir" => {
                // display-only until restart; keep override for next boot
            }
            "tls_cert" => {
                self.runtime.tls_cert = optional_path(raw);
            }
            "tls_key" => {}
            "node_tls_cert" => {
                self.runtime.node_tls_cert = optional_path(raw);
            }
            "node_tls_key" => {}
            "node_tls_client_ca" => {
                self.runtime.node_tls_client_ca = optional_path(raw);
            }
            "webauthn_origin" | "webauthn_rp_id" => {
                // Live values live in AppState.webauthn_rp (Settings PUT / CLI).
            }
            "api_token" => {
                self.runtime.api_token_required = !raw.is_empty();
                if raw.is_empty() {
                    std::env::remove_var("RUSTMITE_API_TOKEN");
                } else {
                    std::env::set_var("RUSTMITE_API_TOKEN", raw);
                }
            }
            "rust_log" => {
                std::env::set_var("RUST_LOG", raw);
            }
            other => return Err(format!("setting {other} is not writable")),
        }
        Ok(())
    }
}

/// Editable string shown in the console for a catalog key.
pub fn editor_value(key: &str, eff: &EffectiveSettings, overrides: &BTreeMap<String, String>) -> String {
    if let Some(v) = overrides.get(key) {
        return v.clone();
    }
    match key {
        "listen" => eff.listen.clone(),
        "node_listen" => eff.node_listen.clone(),
        "checks" => eff.checks_path.clone(),
        "default_check_set" => eff.default_check_set.clone(),
        "scan_interval" => eff.scan_interval.clone(),
        "scan_jitter_pct" => eff.scan_jitter_pct.to_string(),
        "max_concurrent_scans" => eff.max_concurrent_scans.to_string(),
        "scan_timeout_secs" => eff.scan_timeout_secs.to_string(),
        "scan_history_per_host" => eff.scan_history_per_host.to_string(),
        "ssh_connect_timeout_secs" => eff.ssh_connect_timeout_secs.to_string(),
        "ssh_auth_timeout_secs" => eff.ssh_auth_timeout_secs.to_string(),
        "ssh_cmd_timeout_secs" => eff.ssh_cmd_timeout_secs.to_string(),
        "ssh_inactivity_timeout_secs" => eff.ssh_inactivity_timeout_secs.to_string(),
        "ssh_delivery_timeout_secs" => eff.ssh_delivery_timeout_secs.to_string(),
        "ssh_fingerprint_timeout_secs" => eff.ssh_fingerprint_timeout_secs.to_string(),
        "ssh_connect_delay_ms" => eff.ssh_connect_delay_ms.to_string(),
        "ssh_timeout_jitter_pct" => eff.ssh_timeout_jitter_pct.to_string(),
        "clickhouse_timeout_secs" => eff.clickhouse_timeout_secs.to_string(),
        "webhook_url" => eff.webhook_url.clone().unwrap_or_default(),
        "webhook_secret" => String::new(),
        "seed_demo" => eff.seed_demo.to_string(),
        "seed_hosts" => eff.seed_hosts.to_string(),
        "scan_sim" => eff.scan_sim.to_string(),
        "clickhouse_url" => eff.clickhouse_url.clone().unwrap_or_default(),
        "clickhouse_user" => std::env::var("RUSTMITE_CLICKHOUSE_USER").unwrap_or_default(),
        "clickhouse_password" => String::new(),
        "noise_xx" => eff.noise_xx_enabled.to_string(),
        "tls" => eff.tls_enabled.to_string(),
        "tls_dir" => std::env::var("RUSTMITE_TLS_DIR").unwrap_or_else(|_| ".dev/tls".into()),
        "tls_cert" => eff.tls_cert.clone().unwrap_or_default(),
        "tls_key" => String::new(),
        "node_tls_cert" => eff.node_tls_cert.clone().unwrap_or_default(),
        "node_tls_key" => String::new(),
        "node_tls_client_ca" => eff.node_tls_client_ca.clone().unwrap_or_default(),
        "webauthn_origin" => eff.webauthn_origin.clone().unwrap_or_default(),
        "webauthn_rp_id" => eff.webauthn_rp_id.clone().unwrap_or_default(),
        "api_token" => String::new(),
        "rust_log" => eff.rust_log.clone().unwrap_or_else(|| "info".into()),
        _ => String::new(),
    }
}
