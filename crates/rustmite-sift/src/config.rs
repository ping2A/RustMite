//! Detection configuration and defaults.

use std::error::Error;
use std::fs;
use std::fs::File;
use log;
use serde::{Deserialize, Serialize};

/// **File analysis:** tunables for “mtime close to access” (`FileSignature.recently_modified`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FileRecentMtimeConfig {
    /// Treat `mtime` up to this many minutes **after** access as clock skew (still eligible).
    pub clock_skew_minutes: i64,
    /// Max hours between `mtime` and access for credential/boot–heavy paths (shadow, sudoers, …).
    pub max_hours_critical_paths: u32,
    /// Max hours for system dirs (`/etc`, `/usr/bin`, …) when access is elevated or risky.
    pub max_hours_system_elevated: u32,
    /// Max hours for paths that match suspicious patterns only (non-system).
    pub max_hours_suspicious_only: u32,
    /// Path prefixes where recent-mtime is never flagged (logs, caches, ephemeral dirs).
    pub volatile_path_prefixes: Vec<String>,
}

impl Default for FileRecentMtimeConfig {
    fn default() -> Self {
        Self {
            clock_skew_minutes: 5,
            max_hours_critical_paths: 12,
            max_hours_system_elevated: 6,
            max_hours_suspicious_only: 3,
            volatile_path_prefixes: vec![
                "/var/log/".to_string(),
                "/var/cache/".to_string(),
                "/var/lib/dpkg/".to_string(),
                "/var/lib/apt/".to_string(),
                "/var/tmp/".to_string(),
                "/tmp/".to_string(),
                "/run/".to_string(),
                "/proc/".to_string(),
                "/sys/".to_string(),
                "/dev/".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    // NOTE: persisted in SQLite (`events.db`, table `detection_configs`) with a mirror in `.ironsift-platform/db.json` `run_config`.
    // This must be backwards-compatible: older/partial objects must still deserialize.
    // `#[serde(default)]` for scalars/Vecs uses type default (0.0, empty) — wrong for us — so fields
    // that must match `DetectionConfig::default()` use `default = "def_..."` helpers.

    /// Shannon entropy threshold for detecting obfuscated commands
    #[serde(default = "def_entropy_threshold")]
    pub entropy_threshold: f64,

    /// Ratio below which a cluster is considered a minority (e.g., 0.10 = 10%)
    #[serde(default = "def_minority_cluster_ratio")]
    pub minority_cluster_ratio: f64,

    /// DBSCAN tolerance (epsilon) - lower is stricter
    #[serde(default = "def_dbscan_tolerance")]
    pub dbscan_tolerance: f64,

    /// Minimum samples for DBSCAN core point
    #[serde(default = "def_dbscan_min_samples")]
    pub dbscan_min_samples: usize,

    /// Enable L2 normalization of feature vectors
    #[serde(default = "def_normalize_features")]
    pub normalize_features: bool,

    /// Suspicious path patterns (regex)
    #[serde(default = "def_suspicious_path_patterns")]
    pub suspicious_path_patterns: Vec<String>,

    /// Exclude Linux kernel threads (names starting with '[' and ending with ']')
    #[serde(default = "def_exclude_kernel_threads")]
    pub exclude_kernel_threads: bool,

    /// Common system processes that legitimately run as root (UID 0)
    #[serde(default = "def_common_root_processes")]
    pub common_root_processes: Vec<String>,

    /// Penalize root processes that are NOT in common_root_processes list
    #[serde(default = "def_flag_unexpected_root")]
    pub flag_unexpected_root: bool,

    /// Enable debug output for detailed process information
    #[serde(default = "def_debug_display")]
    pub debug_display: bool,

    /// Exclude processes that are direct children of init/systemd (PPID = 1)
    #[serde(default = "def_exclude_init_children")]
    pub exclude_init_children: bool,

    /// Path whitelist patterns (glob-style wildcards: * and ?). Compiled once per load/run (not
    /// per row).
    #[serde(default = "def_whitelisted_path_patterns")]
    pub whitelisted_path_patterns: Vec<String>,

    /// **File analysis only:** Rust regex patterns matched against the full file path. Matching
    /// rows are **never** merged into `MachineFileProfile` (counts, mtimes, TF-IDF, etc.); use
    /// patterns such as `^/proc/` or `^/var/cache/` to drop whole directory trees.
    #[serde(default)]
    pub file_excluded_path_regexes: Vec<String>,

    /// **File analysis only:** Rust regex patterns matched against the basename (last `/` segment
    /// only). Matching rows are **never** merged into file profiles.
    #[serde(default)]
    pub file_excluded_filename_regexes: Vec<String>,

    /// When true, suppress progress and verbose output (for use by scripts/pipelines)
    #[serde(default)]
    pub quiet: bool,

    /// **File analysis:** recent modification vs access-time heuristic (`recently_modified` flag).
    #[serde(default)]
    pub file_recent_mtime: FileRecentMtimeConfig,

    /// When **false** (default), `size` is ignored for fleet **equivalence** (rare-file counting and
    /// TF‑IDF / DBSCAN feature keys). Reduces false splits from log noise.
    #[serde(default)]
    pub file_rare_signature_includes_size: bool,

    /// When **false** (default), `permissions`, `owner`, `group`, and writable flags are ignored for
    /// fleet equivalence (same as [`Self::file_rare_signature_includes_size`] scope).
    #[serde(default)]
    pub file_rare_signature_includes_metadata: bool,

    /// When **false** (default), `recently_modified` is cleared for fleet equivalence so different
    /// access timestamps across hosts do not split the same path+uid into separate features.
    #[serde(default)]
    pub file_rare_signature_includes_recent_mtime: bool,

    /// **File analysis only:** when **true** (default), a “rare file access” reason is emitted only
    /// for paths that also carry a risk indicator (suspicious path, world/group writable, root UID
    /// outside `/proc /sys /dev`, recent mtime, or system-administered directory like `/etc /bin
    /// /sbin /usr/bin /usr/sbin /root /boot /var/spool/cron`). Set to `false` to restore the
    /// previous "every fleet-unique file is rare" behavior. Massive endpoint inventories (40k+
    /// files per host) generate many uninteresting unique entries; this gate keeps the signal high.
    #[serde(default = "def_file_rare_requires_risk")]
    pub file_rare_requires_risk: bool,

    /// **File analysis only:** maximum number of `Rare file access:` rows added to a single host's
    /// `anomalous_features` per analysis. The most interesting (highest-risk, then highest-count)
    /// entries are kept; the rest are summarized as `(+N more rare files not shown)`. Default 20.
    #[serde(default = "def_file_max_rare_examples_per_host")]
    pub file_max_rare_examples_per_host: usize,

    /// **File analysis only:** maximum number of distinct file signatures to keep as columns in the
    /// fleet TF-IDF / DBSCAN matrix. When exceeded, the rarest middle-frequency signatures are
    /// kept (drop universal features and fleet-unique features which are reported separately as
    /// "Rare file access"). Default 8000. Helps endpoints with very large file inventories
    /// (40k+ unique paths per host) stay responsive without losing fleet-relative signals.
    #[serde(default = "def_file_max_unique_features")]
    pub file_max_unique_features: usize,

    /// **File fleet only:** when **true**, inventory rows that share the same fingerprint (path +
    /// uid + permissions + owner + group + size + optional mtime bucket) on at least
    /// [`Self::file_fleet_baseline_min_host_fraction`] of hosts are treated as fleet **baseline**
    /// and excluded from rare-file doc-frequency counting and TF-IDF middle-frequency features.
    /// Reduces noise when every endpoint has the same copies of common packages. **Off by default**
    /// because centrally deployed malware could match on every host — pair with
    /// [`Self::file_fleet_baseline_exclude_suspicious_paths`] (default true) so suspicious-path
    /// rows never become baseline.
    #[serde(default)]
    pub file_fleet_baseline_fingerprint_enabled: bool,

    /// Minimum fraction of hosts (0.0–1.0) that must exhibit the same fingerprint for it to count
    /// as baseline. `1.0` means every host in the run (default).
    #[serde(default = "def_file_fleet_baseline_min_host_fraction")]
    pub file_fleet_baseline_min_host_fraction: f64,

    /// Bucket width in seconds for mtime when hashing fingerprints (`mtime.timestamp / bucket`).
    /// `0` disables mtime in the fingerprint (path/metadata/size only). Default 86400 (one day).
    #[serde(default = "def_file_fleet_baseline_mtime_bucket_secs")]
    pub file_fleet_baseline_mtime_bucket_secs: u64,

    /// When building baseline fingerprints, skip rows whose `FileSignature` has
    /// `is_suspicious_path: true` so universal `/tmp` or dot-bin paths are never dropped from
    /// anomaly logic via the baseline rule.
    #[serde(default = "def_file_fleet_baseline_exclude_suspicious_paths")]
    pub file_fleet_baseline_exclude_suspicious_paths: bool,

    /// **SQLite file runs only:** when **true** (default), loading file inventory for a detection run
    /// skips rows whose `inv_checksum` (basename + permissions `mode` only, set at ingest) is
    /// **common across the run’s selected file datasets**: on a single dataset, excluded if every
    /// machine has that checksum; with multiple file datasets, excluded if the checksum appears in
    /// **all** of them.
    #[serde(default = "def_file_exclude_common_inventory_sql")]
    pub file_exclude_common_inventory_sql: bool,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            entropy_threshold: 4.5,
            minority_cluster_ratio: 0.10,
            dbscan_tolerance: 0.35,
            dbscan_min_samples: 2,
            normalize_features: true,
            suspicious_path_patterns: vec![
                r"/tmp/".to_string(),
                r"/dev/shm/".to_string(),
                r"/var/tmp/".to_string(),
                r"/home/[^/]+/\.[^/]+".to_string(),
                r"^\./".to_string(),
                // Hidden files in system paths (e.g. /bin/.rootme, /usr/sbin/.hidden)
                r"/(?:bin|sbin|usr/bin|usr/sbin)/\.[^/]+".to_string(),
            ],
            exclude_kernel_threads: true,
            common_root_processes: vec![
                "systemd".to_string(),
                "init".to_string(),
                "sshd".to_string(),
                "cron".to_string(),
                "crond".to_string(),
                "rsyslogd".to_string(),
                "dockerd".to_string(),
                "containerd".to_string(),
                "kubelet".to_string(),
                "networkd".to_string(),
                "systemd-networkd".to_string(),
                "systemd-resolved".to_string(),
                "systemd-journald".to_string(),
                "systemd-logind".to_string(),
                "systemd-udevd".to_string(),
                "dbus-daemon".to_string(),
                "polkitd".to_string(),
                "snapd".to_string(),
                "unattended-upgr".to_string(),
                "accounts-daemon".to_string(),
                "rtkit-daemon".to_string(),
                "cups-browsed".to_string(),
                "cupsd".to_string(),
                "avahi-daemon".to_string(),
            ],
            flag_unexpected_root: true,
            debug_display: false,
            exclude_init_children: false,
            whitelisted_path_patterns: vec![],
            file_excluded_path_regexes: vec![],
            file_excluded_filename_regexes: vec![],
            quiet: false,
            file_recent_mtime: FileRecentMtimeConfig::default(),
            file_rare_signature_includes_size: false,
            file_rare_signature_includes_metadata: false,
            file_rare_signature_includes_recent_mtime: false,
            file_rare_requires_risk: true,
            file_max_rare_examples_per_host: 20,
            file_max_unique_features: 8000,
            file_fleet_baseline_fingerprint_enabled: false,
            file_fleet_baseline_min_host_fraction: 1.0,
            file_fleet_baseline_mtime_bucket_secs: 86_400,
            file_fleet_baseline_exclude_suspicious_paths: true,
            file_exclude_common_inventory_sql: true,
        }
    }
}

// Serde per-field defaults for partial persisted configs.
// These must match `DetectionConfig::default()` to avoid surprise behavior.
fn def_entropy_threshold() -> f64 {
    DetectionConfig::default().entropy_threshold
}

fn def_minority_cluster_ratio() -> f64 {
    DetectionConfig::default().minority_cluster_ratio
}

fn def_dbscan_tolerance() -> f64 {
    DetectionConfig::default().dbscan_tolerance
}

fn def_dbscan_min_samples() -> usize {
    DetectionConfig::default().dbscan_min_samples
}

fn def_normalize_features() -> bool {
    DetectionConfig::default().normalize_features
}

fn def_suspicious_path_patterns() -> Vec<String> {
    DetectionConfig::default().suspicious_path_patterns
}

fn def_exclude_kernel_threads() -> bool {
    DetectionConfig::default().exclude_kernel_threads
}

fn def_common_root_processes() -> Vec<String> {
    DetectionConfig::default().common_root_processes
}

fn def_flag_unexpected_root() -> bool {
    DetectionConfig::default().flag_unexpected_root
}

fn def_debug_display() -> bool {
    DetectionConfig::default().debug_display
}

fn def_exclude_init_children() -> bool {
    DetectionConfig::default().exclude_init_children
}

fn def_whitelisted_path_patterns() -> Vec<String> {
    DetectionConfig::default().whitelisted_path_patterns
}

fn def_file_rare_requires_risk() -> bool {
    DetectionConfig::default().file_rare_requires_risk
}

fn def_file_max_rare_examples_per_host() -> usize {
    DetectionConfig::default().file_max_rare_examples_per_host
}

fn def_file_max_unique_features() -> usize {
    DetectionConfig::default().file_max_unique_features
}

fn def_file_fleet_baseline_min_host_fraction() -> f64 {
    DetectionConfig::default().file_fleet_baseline_min_host_fraction
}

fn def_file_fleet_baseline_mtime_bucket_secs() -> u64 {
    DetectionConfig::default().file_fleet_baseline_mtime_bucket_secs
}

fn def_file_fleet_baseline_exclude_suspicious_paths() -> bool {
    DetectionConfig::default().file_fleet_baseline_exclude_suspicious_paths
}

fn def_file_exclude_common_inventory_sql() -> bool {
    DetectionConfig::default().file_exclude_common_inventory_sql
}

impl DetectionConfig {
    /// Load config from JSON file
    pub fn from_file(path: &str) -> Result<Self, Box<dyn Error>> {
        let contents = fs::read_to_string(path)?;
        let config: Self = serde_json::from_str(&contents)?;
        Ok(config)
    }

    /// Save config to JSON file
    pub fn to_file(&self, path: &str) -> Result<(), Box<dyn Error>> {
        let file = File::create(path)?;
        serde_json::to_writer_pretty(file, self)?;
        Ok(())
    }

    /// Print comprehensive configuration display (no-op when quiet)
    pub fn print(&self) {
        if self.quiet {
            return;
        }
        log::info!(
            "Configuration: entropy_threshold={:.2}, dbscan_tolerance={:.3}, min_samples={}, minority_ratio={:.1}%, normalize={}",
            self.entropy_threshold,
            self.dbscan_tolerance,
            self.dbscan_min_samples,
            self.minority_cluster_ratio * 100.0,
            self.normalize_features
        );
        log::info!(
            "Filtering: exclude_kernel_threads={}, exclude_init_children={}, flag_unexpected_root={}, debug_display={}",
            self.exclude_kernel_threads,
            self.exclude_init_children,
            self.flag_unexpected_root,
            self.debug_display
        );
        if !self.suspicious_path_patterns.is_empty() {
            log::info!("Suspicious path patterns: {} configured", self.suspicious_path_patterns.len());
        }
        if !self.whitelisted_path_patterns.is_empty() {
            log::info!("Whitelisted path patterns: {} configured", self.whitelisted_path_patterns.len());
        }
        if !self.file_excluded_path_regexes.is_empty() {
            log::info!(
                "File analysis: {} excluded-path regex(es)",
                self.file_excluded_path_regexes.len()
            );
        }
        if !self.file_excluded_filename_regexes.is_empty() {
            log::info!(
                "File analysis: {} excluded-filename regex(es)",
                self.file_excluded_filename_regexes.len()
            );
        }
        if !self.common_root_processes.is_empty() {
            log::info!("Common root processes: {} listed", self.common_root_processes.len());
        }
        log::info!(
            "File recent-mtime: skew={}m, max_h (critical/system/suspicious)={}/{}/{}, volatile_prefixes={}",
            self.file_recent_mtime.clock_skew_minutes,
            self.file_recent_mtime.max_hours_critical_paths,
            self.file_recent_mtime.max_hours_system_elevated,
            self.file_recent_mtime.max_hours_suspicious_only,
            self.file_recent_mtime.volatile_path_prefixes.len()
        );
        log::info!(
            "File fleet signature equivalence includes: size={}, metadata={}, recent_mtime={}",
            self.file_rare_signature_includes_size,
            self.file_rare_signature_includes_metadata,
            self.file_rare_signature_includes_recent_mtime
        );
        log::info!(
            "File rare-access gating: requires_risk={}, max_examples_per_host={}, max_unique_features={}",
            self.file_rare_requires_risk,
            self.file_max_rare_examples_per_host,
            self.file_max_unique_features
        );
        log::info!(
            "File fleet baseline fingerprint: enabled={}, min_host_fraction={:.2}, mtime_bucket_secs={}, exclude_suspicious_paths={}",
            self.file_fleet_baseline_fingerprint_enabled,
            self.file_fleet_baseline_min_host_fraction,
            self.file_fleet_baseline_mtime_bucket_secs,
            self.file_fleet_baseline_exclude_suspicious_paths
        );
        log::info!(
            "File SQLite load filter (exclude run-scope common inv_checksum): {}",
            self.file_exclude_common_inventory_sql
        );
    }

    /// Row-level filters used only by [`crate::loaders`] when building in-memory profiles from disk
    /// (kernel threads, PPID=1, path whitelist, file path regex exclusions).
    ///
    /// **SQLite ingestion** ([`crate::event_db::EventDb::ingest_dataset`]) does **not** use
    /// [`DetectionConfig`] at all — every parsed line is stored.
    ///
    /// Use this when reloading the same source files for analysis helpers that should match what
    /// was ingested (e.g. AnoMark training text built from datasets).
    pub fn unfiltered_row_loading() -> Self {
        let mut c = Self::default();
        c.exclude_kernel_threads = false;
        c.exclude_init_children = false;
        c.whitelisted_path_patterns.clear();
        c.file_excluded_path_regexes.clear();
        c.file_excluded_filename_regexes.clear();
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unfiltered_row_loading_disables_filters_and_exclusions() {
        let u = DetectionConfig::unfiltered_row_loading();
        assert!(!u.exclude_kernel_threads);
        assert!(!u.exclude_init_children);
        assert!(u.whitelisted_path_patterns.is_empty());
        assert!(u.file_excluded_path_regexes.is_empty());
        assert!(u.file_excluded_filename_regexes.is_empty());
    }

    #[test]
    fn detection_config_deserialize_empty_json_fills_defaults() {
        let c: DetectionConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(c.dbscan_tolerance, DetectionConfig::default().dbscan_tolerance);
        assert_eq!(c.entropy_threshold, DetectionConfig::default().entropy_threshold);
    }

    #[test]
    fn file_recent_mtime_config_default_has_volatile_prefixes() {
        let f = FileRecentMtimeConfig::default();
        assert!(f.volatile_path_prefixes.iter().any(|p| p.contains("/tmp/")));
    }
}
