//! RustMite control-plane library surface for tests/embedding.
#![forbid(unsafe_code)]
#![recursion_limit = "512"]

pub mod anomark_api;
pub mod auth;
pub mod check_catalog;
pub mod check_sets;
pub mod clickhouse;
pub mod credentials;
pub mod platform_ch;
pub mod events_ingest;
pub mod host_health;
pub mod ingest_map;
pub mod ingest_tree;
pub mod ingest_virtual;
pub mod openapi;
pub mod routes;
pub mod scan_sim;
pub mod seed;
pub mod settings;
pub mod sift_api;
pub mod sift_platform;
pub mod ssh_hunter;
pub mod sys_metrics;
pub mod tls;
pub mod ui;
pub mod version_info;
pub mod virtual_agents;

pub use check_catalog::CheckCatalog;
pub use host_health::{spawn_host_health_checker, HostHealthConfig};
pub use routes::{default_checks_dir, node_router, operator_router, AppState};
pub use scan_sim::spawn_scan_simulator;
pub use seed::{seed_demo, DEFAULT_SEED_HOSTS};
pub use settings::{RuntimeSettings, SettingsExport, SETTINGS_CATALOG};
pub use sys_metrics::MetricsHub;
pub use tls::{ensure_dev_certs, serve_plain, serve_tls, TlsPaths, DEFAULT_TLS_DIR};
