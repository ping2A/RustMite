//! API/Web platform state and orchestration for ingestion and runs.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ahash::AHashMap;
use rustmite_anomark::{
    load_char_training_data, load_csv_with_columns, load_jsonl_with_columns, train_parallel,
    validate_train_file_kinds, LoadedCharTrainingData, ModelHandler, TrainFileKind, resolve_column_name,
};

use chrono::Utc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::event_db::{
    DetectionConfigProfileMeta, EventDb, IngestSummary, DELETE_DATASET_EVENTS_MAX_IDS,
};

fn dataset_kind_from_ingest_summary(summary: &IngestSummary) -> DatasetKind {
    match summary.kind.as_str() {
        "mixed" => DatasetKind::Mixed,
        "file" => DatasetKind::File,
        _ => DatasetKind::Process,
    }
}

use crate::analysis::analyze_fleet;
use crate::config::DetectionConfig;
use crate::file_analysis::analyze_files_fleet;
use crate::json_parse::{default_machine_fallback_for_source_file, parse_json_logs};
use crate::builder::build_profiles;
use crate::file_analysis::build_file_profiles_from_grouped;
use crate::loaders::{
    load_csv_data, load_files_csv_data, load_files_json_data, load_files_jsonl_data, load_json_data,
    load_jsonl_data,
};
use crate::report::{AnomalyLevel, AnalysisType};
use crate::types::{MachineFileProfile, MachineProfile, ProcessSignature, RawLogEntry};
use crate::event_db::DatasetInspection;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DatasetKind {
    Process,
    File,
    /// NDJSON (or sniffed JSON) contains both process and file-inventory rows; ingest fills both tables.
    Mixed,
}

/// Which detection arms to run for [`DatasetKind::Mixed`] datasets in a [`CreateRunRequest`].
/// Pure process / file datasets always use their matching arm only.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RunDetectionFocus {
    /// Mixed datasets feed both process and file analysis (legacy behavior).
    #[default]
    Auto,
    /// Mixed datasets feed **process** analysis only for this run (skip file arm for mixed).
    ProcessOnly,
    /// Mixed datasets feed **file** analysis only for this run (skip process arm for mixed).
    FileOnly,
}

/// Whether to run IronSift fleet clustering, AnoMark command scoring, or both.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RunDetectorMode {
    /// Fleet TF-IDF / DBSCAN (and file fleet) plus optional AnoMark when `enable_anomark` is true.
    #[default]
    Both,
    /// IronSift process + file detection only; never runs AnoMark for this request.
    IronsiftOnly,
    /// AnoMark suspicious-command ratios only; skips `analyze_fleet` / `analyze_files_fleet`.
    /// Requires process-capable datasets and a readable model (or chosen training).
    AnomarkOnly,
}

#[inline]
fn run_fleet_detection(mode: RunDetectorMode) -> bool {
    matches!(
        mode,
        RunDetectorMode::Both | RunDetectorMode::IronsiftOnly
    )
}

#[inline]
fn run_anomark_detection(mode: RunDetectorMode, enable_anomark: bool) -> bool {
    match mode {
        RunDetectorMode::IronsiftOnly => false,
        RunDetectorMode::AnomarkOnly => true,
        RunDetectorMode::Both => enable_anomark,
    }
}

/// Suspect threshold (% of ln prior) for fleet AnoMark and quick score; lower = more sensitive.
#[inline]
fn clamp_anomark_suspect_percent(pct: f64) -> f64 {
    if pct.is_finite() && pct > 0.0 {
        pct.clamp(55.0, 99.999)
    } else {
        95.0
    }
}

fn default_anomark_run_suspect_percent() -> f64 {
    95.0
}

/// Returns `(use_process_arm, use_file_arm)` for this dataset kind and run focus.
fn run_detection_arms(kind: DatasetKind, focus: RunDetectionFocus) -> (bool, bool) {
    let process = match focus {
        RunDetectionFocus::Auto | RunDetectionFocus::ProcessOnly => {
            matches!(kind, DatasetKind::Process | DatasetKind::Mixed)
        }
        RunDetectionFocus::FileOnly => matches!(kind, DatasetKind::Process),
    };
    let file = match focus {
        RunDetectionFocus::Auto | RunDetectionFocus::FileOnly => {
            matches!(kind, DatasetKind::File | DatasetKind::Mixed)
        }
        RunDetectionFocus::ProcessOnly => matches!(kind, DatasetKind::File),
    };
    (process, file)
}

fn dataset_tag_map_for_run(
    datasets: &[DatasetRecord],
    run_dataset_ids: &[String],
) -> HashMap<String, Vec<String>> {
    run_dataset_ids
        .iter()
        .filter_map(|rid| {
            datasets
                .iter()
                .find(|d| &d.id == rid)
                .map(|d| (d.id.clone(), d.tags.clone()))
        })
        .collect()
}

fn union_dataset_tags_for_ids(ids: &[String], ds_tags: &HashMap<String, Vec<String>>) -> Vec<String> {
    let mut out: Vec<String> = ids
        .iter()
        .filter_map(|id| ds_tags.get(id))
        .flatten()
        .cloned()
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Dataset ingestion tags for a machine id in this run (`dataset_id/host` when multi-dataset).
fn resolve_machine_dataset_tags_for_run(
    machine_id: &str,
    run_dataset_ids: &[String],
    focus: RunDetectionFocus,
    datasets: &[DatasetRecord],
) -> Vec<String> {
    let ds_tags = dataset_tag_map_for_run(datasets, run_dataset_ids);
    if let Some((prefix, _rest)) = machine_id.split_once('/') {
        if run_dataset_ids.iter().any(|id| id == prefix) {
            return ds_tags.get(prefix).cloned().unwrap_or_default();
        }
    }
    let process_ds_ids: Vec<&String> = run_dataset_ids
        .iter()
        .filter(|id| {
            datasets
                .iter()
                .find(|d| &d.id == *id)
                .map(|d| run_detection_arms(d.kind, focus).0)
                .unwrap_or(false)
        })
        .collect();
    let file_ds_ids: Vec<&String> = run_dataset_ids
        .iter()
        .filter(|id| {
            datasets
                .iter()
                .find(|d| &d.id == *id)
                .map(|d| run_detection_arms(d.kind, focus).1)
                .unwrap_or(false)
        })
        .collect();

    let picked: Vec<String> = if process_ds_ids.len() == 1 {
        vec![process_ds_ids[0].clone()]
    } else if process_ds_ids.is_empty() && file_ds_ids.len() == 1 {
        vec![file_ds_ids[0].clone()]
    } else if run_dataset_ids.len() == 1 {
        vec![run_dataset_ids[0].clone()]
    } else {
        return union_dataset_tags_for_ids(run_dataset_ids, &ds_tags);
    };
    union_dataset_tags_for_ids(&picked, &ds_tags)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetRecord {
    pub id: String,
    pub name: String,
    pub source_path: String,
    pub format: String,
    pub kind: DatasetKind,
    pub tags: Vec<String>,
    pub schema_profile: String,
    pub imported_at: String,
    /// When set, JSONL/JSON rows without host fields use this instead of the source file stem
    /// (e.g. parent-folder segment from `ironsift --ingest-parent-tag-field`).
    #[serde(default)]
    pub ingest_default_machine_id: Option<String>,
}

/// Group of reasons attributed to a single detector (e.g. `ironsift-process`, `anomark-rs`,
/// `ironsift-file`). Lets the UI render reasons grouped by where they came from instead of one
/// flat sorted blob.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DetectorReasons {
    pub detector: String,
    pub reasons: Vec<String>,
}

/// Analyst triage verdict for a single reason line or a host-level decision.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TriageVerdict {
    #[default]
    Unset,
    FalsePositive,
    Malicious,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasonTriageEntry {
    pub detector: String,
    pub reason: String,
    #[serde(default)]
    pub verdict: TriageVerdict,
    /// When an analyst last set a non-[`TriageVerdict::Unset`] verdict for this line (RFC 3339).
    /// Cleared when verdict is unset; omitted for fleet auto-merge until someone saves triage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineTriageEntry {
    pub machine_id: String,
    #[serde(default)]
    pub reason_decisions: Vec<ReasonTriageEntry>,
    #[serde(default)]
    pub final_verdict: TriageVerdict,
}

/// Saved analyst review for a detection run (per machine, per reason + final call).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RunUserTriage {
    #[serde(default)]
    pub machines: Vec<MachineTriageEntry>,
}

/// One per-reason verdict from an **older** detection run (newest matching run wins). Used to show
/// which past analyst decisions feed fleet-wide triage memory for the current run’s reason lines.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistoricalReasonVerdict {
    pub detector: String,
    pub reason: String,
    pub verdict: TriageVerdict,
    pub source_run_id: String,
    pub source_run_created_at: String,
    /// Host on [`DetectionRunRecord::user_triage`] that contributed this precedent (audit / edit).
    #[serde(default)]
    pub source_machine_id: String,
    /// When that verdict was last reviewed on the source run (`ReasonTriageEntry::reviewed_at`), if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_reviewed_at: Option<String>,
}

/// `(detector, reason)` pair stored on a run to **suppress** fleet triage memory for that line on
/// this run only (stops auto-merge and clears saved per-reason rows for that key).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ReasonPrecedentKey {
    pub detector: String,
    pub reason: String,
}

/// Fleet-wide triage memory persisted **independently of** [`PlatformDb::runs`], so precedents
/// survive `delete_all_runs` and remain available for new runs and the global fleet memory API.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FleetTriagePrecedentEntry {
    pub detector: String,
    pub reason: String,
    pub verdict: TriageVerdict,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_reviewed_at: Option<String>,
    #[serde(default)]
    pub source_run_id: String,
    #[serde(default)]
    pub source_run_created_at: String,
    #[serde(default)]
    pub source_machine_id: String,
    /// When this row was last updated in the fleet store (RFC 3339).
    pub updated_at: String,
}

/// Active past verdicts plus those hidden by [`DetectionRunRecord::triage_precedent_ignore`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriagePrecedentBundle {
    pub entries: Vec<HistoricalReasonVerdict>,
    pub suppressed: Vec<HistoricalReasonVerdict>,
}

fn reason_excluded_from_per_reason_triage(reason: &str) -> bool {
    reason.trim_start().starts_with("Process row:")
}

impl RunUserTriage {
    /// Removes per-reason rows that are not meaningful to triage (e.g. raw `Process row: …` context).
    pub fn without_excluded_reason_decisions(&self) -> RunUserTriage {
        RunUserTriage {
            machines: self
                .machines
                .iter()
                .map(|m| MachineTriageEntry {
                    machine_id: m.machine_id.clone(),
                    reason_decisions: m
                        .reason_decisions
                        .iter()
                        .filter(|e| !reason_excluded_from_per_reason_triage(&e.reason))
                        .cloned()
                        .collect(),
                    final_verdict: m.final_verdict,
                })
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionFinding {
    pub machine_id: String,
    pub severity: String,
    pub score: f64,
    /// Flat list of every reason from every detector (sorted/deduped). Kept for backwards
    /// compatibility with older runs in `db.json` and external consumers; new UIs should prefer
    /// [`Self::reasons_by_detector`] for grouped rendering.
    pub reasons: Vec<String>,
    pub detectors: Vec<String>,
    /// Dataset ingestion tags for the host’s source dataset(s) at run time (empty if unknown / legacy runs).
    #[serde(default)]
    pub dataset_tags: Vec<String>,
    /// Reasons grouped per detector in the order they were emitted (within each bucket reasons are
    /// deduped while preserving insertion order so high-level summaries stay above details).
    /// Empty on legacy runs that pre-date this field; UIs should fall back to prefix heuristics on
    /// [`Self::reasons`] in that case.
    #[serde(default)]
    pub reasons_by_detector: Vec<DetectorReasons>,
    /// Full Sigma (sigmazero) rule-match JSON per host when stable Sigma ran on this detection.
    /// One entry per engine match (order follows emission before reason-string deduplication).
    /// Empty for hosts with no Sigma hits or legacy runs.
    #[serde(default)]
    pub sigma_matches: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRunRecord {
    pub id: String,
    pub created_at: String,
    pub dataset_ids: Vec<String>,
    pub baseline_tags: Vec<String>,
    pub candidate_tags: Vec<String>,
    pub findings: Vec<DetectionFinding>,
    #[serde(default)]
    pub baseline_finding_count: usize,
    #[serde(default)]
    pub candidate_finding_count: usize,
    pub summary: String,
    /// SQLite [`DetectionConfig`] profile id used for this run (if known).
    #[serde(default)]
    pub detection_config_id: Option<String>,
    /// Profile display name at run time (if known).
    #[serde(default)]
    pub detection_config_name: Option<String>,
    /// How mixed datasets were analyzed for this run (`auto` if omitted in older saved runs).
    #[serde(default)]
    pub detection_focus: RunDetectionFocus,
    /// Fleet vs AnoMark vs both (`both` if omitted in older saved runs).
    #[serde(default)]
    pub detector_mode: RunDetectorMode,
    /// AnoMark suspect threshold actually used for this run (`95` if omitted in older saved runs).
    #[serde(default = "default_anomark_run_suspect_percent")]
    pub anomark_suspect_percent: f64,
    /// Full run request parameters as sent to the server (empty on runs saved before this field existed).
    #[serde(default)]
    pub request: DetectionRunRequestSnapshot,
    /// Analyst triage (false positive / malicious) per reason and final decision per machine.
    #[serde(default)]
    pub user_triage: RunUserTriage,
    /// Per-run suppressions: fleet-wide precedent is **not** applied for these `(detector, reason)`
    /// keys, and matching per-reason triage rows are removed from this run.
    #[serde(default)]
    pub triage_precedent_ignore: Vec<ReasonPrecedentKey>,
    /// Sigma (stable) engine summary when this run evaluated Sigma (`None` if disabled or legacy).
    #[serde(default)]
    pub sigma_stable_stats: Option<DetectionRunSigmaStats>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct PlatformDb {
    pub datasets: Vec<DatasetRecord>,
    pub runs: Vec<DetectionRunRecord>,
    pub anomark: AnoMarkSettings,
    /// [sigmazero](https://github.com/ping2A/sigmazero) (`sigma_zero` crate) for Sigma rules on process JSONL.
    #[serde(default)]
    pub sigma_zero: SigmaZeroSettings,
    pub run_config: DetectionConfig,
    /// Each successful AnoMark `train` run: persisted model + input and request snapshot.
    #[serde(default)]
    pub anomark_trainings: Vec<AnoMarkTrainRecord>,
    /// `(detector, reason)` pairs excluded from fleet triage memory: not listed in the global
    /// precedent view and not merged into new runs from historical verdicts.
    #[serde(default)]
    pub fleet_triage_precedent_drops: Vec<ReasonPrecedentKey>,
    /// Canonical fleet triage memory (survives deletion of all runs).
    #[serde(default)]
    pub fleet_triage_precedent_entries: Vec<FleetTriagePrecedentEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneycombCell {
    pub name: String,
    pub value: f64,
    pub severity: String,
    /// False when the host is in the run’s ingested data but has no finding (fleet “green”).
    #[serde(default = "honey_infected_default")]
    pub infected: bool,
    /// When `min_score` / `severity` query params are set, `false` means the finding is outside the filter (UI may dim; host still shown).
    #[serde(default = "honey_matches_default")]
    pub matches_filter: bool,
    /// Populated when [`Self::infected`]; for detail panel in the web UI.
    #[serde(default)]
    pub reasons: Vec<String>,
    #[serde(default)]
    pub detectors: Vec<String>,
    #[serde(default)]
    pub dataset_tags: Vec<String>,
}

fn honey_infected_default() -> bool {
    true
}

fn honey_matches_default() -> bool {
    true
}

fn finding_passes_scores(
    score: f64,
    severity: &str,
    min_score: Option<f64>,
    severity_filter: Option<&str>,
) -> bool {
    if let Some(m) = min_score {
        if score < m {
            return false;
        }
    }
    if let Some(s) = severity_filter {
        if !severity.eq_ignore_ascii_case(s) {
            return false;
        }
    }
    true
}

#[derive(Clone)]
pub struct PlatformStore {
    db_path: String,
    sql_path: String,
    db: Arc<RwLock<PlatformDb>>,
}

/// When ingesting JSONL under a tree, add an automatic tag per file from the **immediate parent**
/// directory name: split by `delimiter`, take the `field`-th segment (**1-based**, e.g. `4` for the
/// fourth `-`-separated part of `RemoteAccess-…-HOSTEXAMPLE01-…`). The same segment is stored as
/// [`DatasetRecord::ingest_default_machine_id`] so host-less log lines use it as `machine_id`.
#[derive(Clone, Debug)]
pub struct ParentDirTagRule {
    pub field: usize,
    pub delimiter: char,
}

/// Returns the `field`-th segment (1-based) of `parent_dir_name` split by `delimiter`, trimmed.
pub fn parent_dir_segment_tag(parent_dir_name: &str, field: usize, delimiter: char) -> Option<String> {
    if field < 1 {
        return None;
    }
    let idx = field - 1;
    let parts: Vec<&str> = parent_dir_name.split(delimiter).collect();
    parts
        .get(idx)
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn parent_dir_tag_from_path(path: &Path, rule: &ParentDirTagRule) -> Option<String> {
    let parent = path.parent()?;
    let name = parent.file_name()?.to_str()?;
    parent_dir_segment_tag(name, rule.field, rule.delimiter)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDatasetRequest {
    pub name: String,
    pub source_path: String,
    pub kind: DatasetKind,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "default_schema_profile")]
    pub schema_profile: String,
    #[serde(default)]
    pub ingest_default_machine_id: Option<String>,
}

/// Remove ingested SQLite rows from inspect (`DELETE` by primary key, scoped to dataset).
#[derive(Debug, Clone, Deserialize)]
pub struct DeleteDatasetEventsRequest {
    #[serde(default)]
    pub process_ids: Vec<i64>,
    #[serde(default)]
    pub file_ids: Vec<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRunRequest {
    pub dataset_ids: Vec<String>,
    #[serde(default)]
    pub baseline_tags: Vec<String>,
    #[serde(default)]
    pub candidate_tags: Vec<String>,
    #[serde(default)]
    pub enable_anomark: bool,
    /// When set, score with this training job’s `model.bin` instead of `anomark.model_path`.
    #[serde(default)]
    pub anomark_train_id: Option<String>,
    /// Suspect threshold as percent of ln(prior) for fleet AnoMark (55–99.999); lower = more sensitive.
    #[serde(default = "default_anomark_run_suspect_percent")]
    pub anomark_suspect_percent: f64,
    /// Optional IronSift detection profile id (`events.db`); when omitted, uses the platform-selected profile.
    #[serde(default)]
    pub detection_config_id: Option<String>,
    /// When datasets are [`DatasetKind::Mixed`], restrict this run to process-only or file-only analysis.
    #[serde(default)]
    pub detection_focus: RunDetectionFocus,
    #[serde(default)]
    pub detector_mode: RunDetectorMode,
    /// Run in-process Sigma (sigmazero) after fleet engines, using only rules with `status: stable`.
    #[serde(default)]
    pub enable_sigma_stable: bool,
}

/// Snapshot of the request body used to start a detection run (persisted for history / reproducibility).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct DetectionRunRequestSnapshot {
    pub dataset_ids: Vec<String>,
    pub baseline_tags: Vec<String>,
    pub candidate_tags: Vec<String>,
    pub enable_anomark: bool,
    pub anomark_train_id: Option<String>,
    #[serde(default = "default_anomark_run_suspect_percent")]
    pub anomark_suspect_percent: f64,
    pub detection_config_id: Option<String>,
    pub detection_focus: RunDetectionFocus,
    pub detector_mode: RunDetectorMode,
    #[serde(default)]
    pub enable_sigma_stable: bool,
}

/// Create a named detection configuration profile in SQLite.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDetectionConfigRequest {
    pub name: String,
    pub config: DetectionConfig,
}

/// Update a stored detection profile (name and/or JSON body).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateDetectionConfigRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub config: Option<DetectionConfig>,
}

/// Set which profile is used for new runs when `detection_config_id` is not passed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectDetectionConfigRequest {
    pub id: String,
}

/// Which AnoMark model files exist on disk (for the Runs & Findings UI).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnoMarkTrainingAvailability {
    pub id: String,
    pub created_at: String,
    #[serde(default)]
    pub name: String,
    /// Absolute path the server will use.
    pub model_path: String,
    pub available: bool,
    #[serde(default)]
    pub favorite: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnoMarkAvailability {
    pub config_path: String,
    pub config_available: bool,
    pub trainings: Vec<AnoMarkTrainingAvailability>,
    pub any_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnoMarkSettings {
    /// Ignored; AnoMark runs in-process via the `anomark` crate. Kept for older `db.json` files.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub bin_path: String,
    pub model_path: String,
    /// JSON/CSV column name for the full command line per row (default `cmdline`, matching osquery `processes.cmdline`).
    pub column: String,
    pub machine_field: String,
}

impl Default for AnoMarkSettings {
    fn default() -> Self {
        Self {
            bin_path: String::new(),
            model_path: String::new(),
            column: "cmdline".to_string(),
            machine_field: "machine_id".to_string(),
        }
    }
}

fn sigma_rule_enabled_default() -> bool {
    true
}

/// One Sigma rule stored in the platform database (`sigma_zero.rules_inline` in `db.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaRuleInline {
    /// Stable id for the UI (e.g. uuid).
    pub id: String,
    /// Optional short label in the UI (does not affect evaluation).
    #[serde(default)]
    pub title: String,
    /// Full YAML for a single Sigma rule document.
    pub yaml: String,
    /// When false, the rule is kept on disk but not loaded for Sigma checks.
    #[serde(default = "sigma_rule_enabled_default")]
    pub enabled: bool,
    /// UI / library tags; merged into the parsed rule’s `tags` for Sigma (and `filter_tags` on check).
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Legacy Sigma settings kept for `db.json` compatibility. Evaluation is disabled in RustMite.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaZeroSettings {
    /// Ignored. Kept for older `db.json` files.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub bin_path: String,
    /// Directory of Sigma rule YAML files (used when no entry in [`Self::rules_inline`] is enabled with non-empty YAML, or `rules_inline` is empty).
    #[serde(default)]
    pub rules_dir: String,
    /// Optional default `--field-map` (e.g. `ImagePath:process_name,CommandLine:command_line` for Windows rules).
    #[serde(default)]
    pub field_map: String,
    /// Optional default parallel worker count (`-w`).
    #[serde(default)]
    pub workers: Option<usize>,
    /// Stored rules (enabled entries with YAML win over [`Self::rules_dir`]).
    #[serde(default)]
    pub rules_inline: Vec<SigmaRuleInline>,
}

impl Default for SigmaZeroSettings {
    fn default() -> Self {
        Self {
            bin_path: String::new(),
            rules_dir: String::new(),
            field_map: String::new(),
            workers: None,
            rules_inline: Vec::new(),
        }
    }
}

/// Run Sigma evaluation on a log file path or on selected process datasets.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SigmaZeroCheckRequest {
    /// If set, use this file as the log (JSON/JSONL). Ignores dataset selection.
    #[serde(default)]
    pub log_path: String,
    #[serde(default)]
    pub dataset_ids: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Override `SigmaZeroSettings.rules_dir`.
    #[serde(default)]
    pub rules_dir: Option<String>,
    /// Per-request `--field-map` (wins over settings default if non-empty).
    #[serde(default)]
    pub field_map: Option<String>,
    #[serde(default)]
    pub filter_tags: Vec<String>,
    #[serde(default)]
    pub filter_levels: Vec<String>,
    #[serde(default)]
    pub filter_rule_ids: Vec<String>,
    /// When using stored `rules_inline`, restrict evaluation to these `SigmaRuleInline.id` values (non-empty = subset).
    #[serde(default)]
    pub inline_rule_ids: Vec<String>,
    #[serde(default)]
    pub workers: Option<usize>,
    /// Keep only rules whose YAML `status` is `stable` (case-insensitive). Used for detection runs.
    #[serde(default)]
    pub stable_rules_only: bool,
}

/// Sigma rule identity for UI hints (`GET /api/sigma-zero/stable-rules`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaStableRuleRef {
    pub id: String,
    pub title: String,
}

/// Throughput and timing for one Sigma check (helps validate that evaluation ran; Rust/Rayon can be very fast).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SigmaZeroEvaluationStats {
    /// Rules after filters, compiled into the engine.
    pub rules_compiled: usize,
    /// JSONL lines successfully parsed as [`sigma_zero::models::LogEntry`].
    pub log_entries_evaluated: usize,
    /// Approximate scalar work: `rules_compiled × log_entries_evaluated` (sigmazero evaluates per rule × log in parallel for typical detections).
    pub approx_scalar_checks: u64,
    #[serde(default)]
    pub engine_build_ms: u64,
    #[serde(default)]
    pub jsonl_parse_ms: u64,
    #[serde(default)]
    pub evaluate_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaZeroCheckResult {
    pub status: String,
    pub line_count: u64,
    pub source_dataset_ids: Vec<String>,
    /// Directory path when rules were loaded from disk; empty when using [`Self::rules_source`] `database`.
    #[serde(default)]
    pub rules_dir: String,
    /// `database` | `directory` | `embedded-defaults` (bundled demo when nothing is saved).
    #[serde(default)]
    pub rules_source: String,
    pub rules_match_count: usize,
    /// Serialized [`sigma_zero::models::RuleMatch`] (one per detection).
    pub matches: Vec<serde_json::Value>,
    #[serde(default)]
    /// Reserved; in-process engine does not use stderr. Empty string.
    pub stderr: String,
    /// For dataset-based checks: `ingested` (SQLite `processes`), `source_files` (original upload), or empty if `log_path` was used.
    #[serde(default)]
    pub process_log_source: String,
    /// For dataset-based checks: same semantics as [`Self::process_log_source`] but for SQLite `"file"` / file inventory export.
    #[serde(default)]
    pub file_log_source: String,
    #[serde(default)]
    pub evaluation: SigmaZeroEvaluationStats,
}

/// Sigma (stable rules) evaluation summary persisted on a [`DetectionRunRecord`] when the run
/// included Sigma. Lets the UI show engine output even when no host-level findings were raised.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct DetectionRunSigmaStats {
    pub status: String,
    pub rules_match_count: usize,
    pub rules_compiled: usize,
    pub log_entries_evaluated: usize,
    #[serde(default)]
    pub approx_scalar_checks: u64,
    #[serde(default)]
    pub evaluate_ms: u64,
    #[serde(default)]
    pub engine_build_ms: u64,
    #[serde(default)]
    pub jsonl_parse_ms: u64,
    #[serde(default)]
    pub line_count: u64,
    #[serde(default)]
    pub rules_source: String,
    #[serde(default)]
    pub process_log_source: String,
    #[serde(default)]
    pub file_log_source: String,
}



#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnoMarkTrainRequest {
    /// Optional human-readable name for the model (shown in UI / pickers).
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub training_path: String,
    #[serde(default)]
    pub dataset_ids: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "default_anomark_column")]
    pub column: String,
    #[serde(default = "default_anomark_order")]
    pub order: u8,
    /// Optional extra output path. If empty, the model is written only to
    /// `{platform}/anomark-trains/{train_id}/model.bin` and can be downloaded from the API.
    #[serde(default)]
    pub output_model_path: String,
}

/// Stored in [`PlatformDb::anomark_trainings`] and on disk under `{platform_data_dir}/anomark-trains/{id}/`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnoMarkTrainRecord {
    pub id: String,
    pub created_at: String,
    /// Display name (copied from request at train time).
    #[serde(default)]
    pub name: String,
    /// Exact request. `output_model_path` may be empty (model only in platform storage).
    pub request: AnoMarkTrainRequest,
    /// If training came from built-in dataset selection, these process dataset ids were used.
    #[serde(default)]
    pub source_dataset_ids: Vec<String>,
    /// `true` when `training_path` in the request pointed at an on-disk file; input was a copy of that file.
    #[serde(default)]
    pub from_user_file: bool,
    /// Relative to the platform data directory, e.g. `anomark-trains/{uuid}/model.bin`.
    pub rel_model_path: String,
    pub rel_training_data_path: String,
    pub training_line_count: u64,
    pub bin_path_used: String,
    /// User-pinned trainings sort first in list and model pickers.
    #[serde(default)]
    pub favorite: bool,
}

fn cmp_anomark_train_record_display(a: &AnoMarkTrainRecord, b: &AnoMarkTrainRecord) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    match (a.favorite, b.favorite) {
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        _ => b.created_at.cmp(&a.created_at),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnoMarkTrainResult {
    pub status: String,
    pub model_path: String,
    /// Id for [`AnoMarkTrainRecord`] and download API.
    pub train_id: String,
    /// Persisted copy paths and metadata.
    pub record: AnoMarkTrainRecord,
}

/// Loaded Markov model stats plus optional provenance when the file came from an IronSift training job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnoMarkModelInspection {
    pub model_path: String,
    pub file_size_bytes: u64,
    pub order: usize,
    pub is_trained: bool,
    pub prior: f64,
    pub num_contexts: usize,
    pub num_transitions: usize,
    pub alphabet_len: usize,
    pub raw_markov_entries: usize,
    /// Same rule as detection runs: suspect if command score is below this (95% of prior ln).
    pub suspect_threshold_ln: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub where_generated: Option<AnoMarkWhereGenerated>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub config_origin_note: String,
}

/// CLI-friendly summary returned by [`PlatformStore::test_anomark_cli`].
#[derive(Debug, Clone, Serialize)]
pub struct AnoMarkTestResult {
    pub model_path: String,
    /// `"platform"`, `"training"`, or `"explicit-path"` depending on how the model was resolved.
    pub model_source: String,
    pub model_order: usize,
    pub model_prior_ln: f64,
    /// Percent of `ln(prior)` actually used as suspect threshold (clamped to AnoMark range).
    pub suspect_percent_used: f64,
    pub suspect_threshold_ln: f64,
    /// Present when the caller asked to score one command line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_score: Option<AnoMarkCommandScore>,
    /// Per-dataset suspect-command ratios for the selected ingested process datasets.
    #[serde(default)]
    pub datasets: Vec<AnoMarkTestDatasetSummary>,
    /// Datasets that matched ids/tags but were skipped (e.g. `kind=file`).
    #[serde(default)]
    pub datasets_skipped: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnoMarkTestDatasetSummary {
    pub dataset_id: String,
    pub dataset_name: String,
    pub commands_scored: u64,
    pub suspect_commands: u64,
    pub host_stats: Vec<AnoMarkTestDatasetHostStat>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnoMarkTestDatasetHostStat {
    pub host: String,
    pub commands: u64,
    pub suspect: u64,
    pub ratio: f64,
}

fn score_one_command_against_model(
    model_path: &Path,
    source: &str,
    train_id: Option<String>,
    command: &str,
    machine_name: Option<&str>,
    suspect_percent: f64,
) -> Result<AnoMarkCommandScore, Box<dyn Error>> {
    let scores = score_commands_against_model(
        model_path,
        source,
        train_id,
        &[(machine_name, command)],
        suspect_percent,
    )?;
    scores
        .into_iter()
        .next()
        .ok_or_else(|| "no score returned".into())
}

/// Load the model once and score many `(machine, command)` pairs. Empty commands are skipped.
fn score_commands_against_model(
    model_path: &Path,
    source: &str,
    train_id: Option<String>,
    commands: &[(Option<&str>, &str)],
    suspect_percent: f64,
) -> Result<Vec<AnoMarkCommandScore>, Box<dyn Error>> {
    const MAX_CMD: usize = 32 * 1024;
    if !model_path.is_file() {
        return Err(format!("model file not found: {}", model_path.display()).into());
    }
    let path_str = model_path
        .to_str()
        .ok_or("model path is not valid UTF-8")?;
    let mut model =
        ModelHandler::load_model(path_str).map_err(|e: anyhow::Error| e.to_string())?;
    if !model.is_trained() {
        model.normalize_model_and_compute_prior();
    }
    let pct = clamp_anomark_suspect_percent(suspect_percent);
    let threshold_ln = ModelHandler::compute_threshold(&model, pct);
    let canonical = model_path
        .canonicalize()
        .unwrap_or_else(|_| model_path.to_path_buf())
        .to_string_lossy()
        .into_owned();
    let order = model.order;
    let pad = "~".repeat(order);

    let mut out = Vec::with_capacity(commands.len());
    for &(machine_name, command) in commands {
        if command.len() > MAX_CMD {
            return Err(format!("command exceeds {} characters", MAX_CMD).into());
        }
        let trimmed = command.trim();
        let machine_trim = machine_name
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("");
        let scored_line = anomark_score_line(machine_trim, trimmed);
        if scored_line.is_empty() {
            continue;
        }
        if scored_line.len() > MAX_CMD {
            return Err(format!("scored line exceeds {} characters", MAX_CMD).into());
        }
        let padded = format!("{}{}", pad, scored_line);
        let log_likelihood = model.log_likelihood(&padded);
        let is_suspect = ModelHandler::is_suspect_command(log_likelihood, threshold_ln);
        let margin_ln = log_likelihood - threshold_ln;
        out.push(AnoMarkCommandScore {
            model_path: canonical.clone(),
            source: source.to_string(),
            train_id: train_id.clone(),
            order,
            log_likelihood,
            suspect_threshold_ln: threshold_ln,
            is_suspect,
            margin_ln,
            suspect_percent_used: pct,
            line_scored: scored_line,
        });
    }
    Ok(out)
}

/// Score a single command line against an AnoMark model (same suspect rule as fleet scoring).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnoMarkCommandScore {
    pub model_path: String,
    /// `"platform"` = path from settings; `"training"` = saved training `model.bin`.
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub train_id: Option<String>,
    pub order: usize,
    pub log_likelihood: f64,
    pub suspect_threshold_ln: f64,
    pub is_suspect: bool,
    /// `log_likelihood - suspect_threshold_ln` — negative means flagged at [`Self::suspect_percent_used`].
    pub margin_ln: f64,
    /// Percent of `ln(prior)` used as threshold (same semantics as [`ModelHandler::compute_threshold`]).
    pub suspect_percent_used: f64,
    /// Exact UTF-8 string scored by the Markov model (`machine cmd…` when host is known).
    #[serde(default)]
    pub line_scored: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnoMarkWhereGenerated {
    pub train_id: String,
    pub generated_at: String,
    pub generation_engine: String,
    /// Absolute path to the platform data directory (contains `anomark-trains/`).
    pub platform_data_directory: String,
    pub model_file_relative: String,
    pub training_input_relative: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub optional_output_copy_path: String,
    /// Short human summary of training input (file path vs dataset ids).
    pub source_label: String,
    pub training_line_count: u64,
    pub request: AnoMarkTrainRequest,
    pub source_dataset_ids: Vec<String>,
    pub from_user_file: bool,
}

struct AnoMarkTrainingInputMeta {
    from_user_file: bool,
    source_dataset_ids: Vec<String>,
    /// `true` when the path was a generated file under the OS temp directory (delete after copy).
    remove_source: bool,
}

fn default_anomark_column() -> String {
    "cmdline".to_string()
}

fn default_anomark_order() -> u8 {
    4
}

fn default_schema_profile() -> String {
    "osquery-5.22.1".to_string()
}

impl PlatformStore {
    pub fn load_or_create(db_path: &str) -> Result<Self, Box<dyn Error>> {
        let db_file = Path::new(db_path);
        let parent = db_file.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let sql_path = parent.join("events.db").to_string_lossy().into_owned();
        let mut db = if db_file.exists() {
            let content = fs::read_to_string(db_path)?;
            serde_json::from_str::<PlatformDb>(&content)?
        } else {
            PlatformDb::default()
        };
        let event_db = EventDb::new(&sql_path)?;
        let legacy = db_file.exists().then(|| db.run_config.clone());
        event_db.ensure_detection_configs_initialized(legacy)?;
        if let Ok(Some(cfg)) = event_db.get_selected_detection_config() {
            db.run_config = cfg;
        }
        let seeded = seed_fleet_triage_precedents_from_runs_if_empty(&mut db);
        let store = Self {
            db_path: db_path.to_string(),
            sql_path,
            db: Arc::new(RwLock::new(db)),
        };
        if seeded {
            store.save()?;
        }
        Ok(store)
    }

    /// Path to the platform metadata JSON (e.g. `db.json`).
    pub fn db_json_path(&self) -> &str {
        &self.db_path
    }

    /// Path to the SQLite database for ingested events (`events.db`, alongside `db.json`).
    pub fn events_sqlite_path(&self) -> &str {
        &self.sql_path
    }

    fn save(&self) -> Result<(), Box<dyn Error>> {
        let parent = Path::new(&self.db_path)
            .parent()
            .ok_or("invalid db path")?;
        fs::create_dir_all(parent)?;
        let db = self.db.read();
        fs::write(&self.db_path, serde_json::to_vec_pretty(&*db)?)?;
        Ok(())
    }

    pub fn list_datasets(&self) -> Vec<DatasetRecord> {
        self.db.read().datasets.clone()
    }

    pub fn list_runs(&self) -> Vec<DetectionRunRecord> {
        let mut v = self.db.read().runs.clone();
        v.sort_by(|a, b| {
            let by_time = b.created_at.cmp(&a.created_at);
            if by_time != std::cmp::Ordering::Equal {
                return by_time;
            }
            b.id.cmp(&a.id)
        });
        v
    }

    pub fn get_anomark_settings(&self) -> AnoMarkSettings {
        self.db.read().anomark.clone()
    }

    /// Discover config + saved training models on disk (for UI: enable AnoMark when any exist).
    pub fn anomark_availability(&self) -> AnoMarkAvailability {
        let cfg = self.get_anomark_settings();
        let config_path = cfg.model_path.trim().to_string();
        let config_available = !config_path.is_empty() && Path::new(&config_path).is_file();
        let mut list = self.list_anomark_trainings();
        list.sort_by(cmp_anomark_train_record_display);
        let mut trainings: Vec<AnoMarkTrainingAvailability> = Vec::new();
        for t in list {
            let model_path = self
                .anomark_train_stored_model_path(&t.id)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            let available = !model_path.is_empty() && Path::new(&model_path).is_file();
            let favorite = t.favorite;
            trainings.push(AnoMarkTrainingAvailability {
                id: t.id,
                created_at: t.created_at,
                name: t.name,
                model_path,
                available,
                favorite,
            });
        }
        let any_available = config_available || trainings.iter().any(|x| x.available);
        AnoMarkAvailability {
            config_path,
            config_available,
            trainings,
            any_available,
        }
    }

    /// Resolve a configured model path: absolute file, or relative to the platform data directory.
    fn resolve_anomark_model_path(&self, trimmed: &str) -> Option<PathBuf> {
        let path = Path::new(trimmed);
        if path.is_file() {
            return Some(path.to_path_buf());
        }
        let root = self.platform_root().ok()?;
        let joined = root.join(trimmed);
        if joined.is_file() {
            Some(joined)
        } else {
            None
        }
    }

    /// Settings to use for a detection run, or `None` if AnoMark should be skipped.
    fn resolve_anomark_settings_for_run(
        &self,
        req: &CreateRunRequest,
    ) -> Option<AnoMarkSettings> {
        let mut s = self.get_anomark_settings();
        if let Some(tid) = &req.anomark_train_id {
            let t = tid.trim();
            if !t.is_empty() {
                if let Some(p) = self.anomark_train_stored_model_path(t) {
                    if p.is_file() {
                        s.model_path = p.to_string_lossy().to_string();
                    } else {
                        log::warn!(
                            "AnoMark: training '{}' model file missing at {:?}; using platform model path",
                            t,
                            p
                        );
                    }
                } else {
                    log::warn!(
                        "AnoMark: unknown training id '{}'; using platform model path",
                        t
                    );
                }
            }
        }
        let p = s.model_path.trim();
        if p.is_empty() {
            return None;
        }
        let resolved = self.resolve_anomark_model_path(p)?;
        s.model_path = resolved.to_string_lossy().to_string();
        Some(s)
    }

    pub fn get_run_config(&self) -> DetectionConfig {
        EventDb::new(&self.sql_path)
            .ok()
            .and_then(|edb| edb.get_selected_detection_config().ok().flatten())
            .unwrap_or_else(|| self.db.read().run_config.clone())
    }

    /// Selected profile JSON, profile list, and selected id (SQLite-backed).
    pub fn run_config_with_profiles(
        &self,
    ) -> Result<(DetectionConfig, Vec<DetectionConfigProfileMeta>, Option<String>), Box<dyn Error>>
    {
        let edb = EventDb::new(&self.sql_path)?;
        edb.ensure_detection_configs_initialized(None)?;
        let profiles = edb.list_detection_config_profiles()?;
        let selected_id = edb.get_selected_detection_config_id()?;
        let cfg = edb
            .get_selected_detection_config()?
            .unwrap_or_else(|| self.db.read().run_config.clone());
        Ok((cfg, profiles, selected_id))
    }

    pub fn get_detection_config_profile_detail(
        &self,
        id: &str,
    ) -> Result<(DetectionConfigProfileMeta, DetectionConfig), Box<dyn Error>> {
        let edb = EventDb::new(&self.sql_path)?;
        let profiles = edb.list_detection_config_profiles()?;
        let meta = profiles
            .into_iter()
            .find(|m| m.id == id)
            .ok_or_else(|| -> Box<dyn Error> { "detection config not found".into() })?;
        let cfg = edb
            .get_detection_config_by_id(id)?
            .ok_or_else(|| -> Box<dyn Error> { "detection config not found".into() })?;
        Ok((meta, cfg))
    }

    pub fn create_detection_config_profile(
        &self,
        req: CreateDetectionConfigRequest,
    ) -> Result<(String, DetectionConfigProfileMeta), Box<dyn Error>> {
        let edb = EventDb::new(&self.sql_path)?;
        edb.ensure_detection_configs_initialized(None)?;
        let name = req.name.trim();
        if name.is_empty() {
            return Err("profile name is required".into());
        }
        let id = edb.insert_detection_config(name, &req.config)?;
        let profiles = edb.list_detection_config_profiles()?;
        let meta = profiles
            .into_iter()
            .find(|m| m.id == id)
            .ok_or_else(|| -> Box<dyn Error> { "failed to load new profile".into() })?;
        Ok((id, meta))
    }

    pub fn update_detection_config_profile(
        &self,
        id: &str,
        req: UpdateDetectionConfigRequest,
    ) -> Result<(), Box<dyn Error>> {
        let edb = EventDb::new(&self.sql_path)?;
        if let Some(ref n) = req.name {
            if n.trim().is_empty() {
                return Err("profile name cannot be empty".into());
            }
        }
        let name = req.name.as_ref().map(|s| s.trim().as_ref());
        if req.name.is_none() && req.config.is_none() {
            return Err("nothing to update (provide name and/or config)".into());
        }
        edb.update_detection_config_row(id, name, req.config.as_ref())?;
        if edb.get_selected_detection_config_id()?.as_deref() == Some(id) {
            if let Some(cfg) = edb.get_selected_detection_config()? {
                self.db.write().run_config = cfg;
                self.save()?;
            }
        }
        Ok(())
    }

    pub fn delete_detection_config_profile(&self, id: &str) -> Result<(), Box<dyn Error>> {
        let edb = EventDb::new(&self.sql_path)?;
        edb.delete_detection_config_row(id)?;
        if let Ok(Some(cfg)) = edb.get_selected_detection_config() {
            self.db.write().run_config = cfg;
            self.save()?;
        }
        Ok(())
    }

    pub fn select_detection_config_profile(&self, id: &str) -> Result<(), Box<dyn Error>> {
        let edb = EventDb::new(&self.sql_path)?;
        edb.set_selected_detection_config_id(id)?;
        if let Some(cfg) = edb.get_selected_detection_config()? {
            self.db.write().run_config = cfg;
            self.save()?;
        }
        Ok(())
    }

    pub fn set_run_config(&self, cfg: DetectionConfig) -> Result<DetectionConfig, Box<dyn Error>> {
        let edb = EventDb::new(&self.sql_path)?;
        edb.ensure_detection_configs_initialized(Some(cfg.clone()))?;
        edb.update_selected_detection_config_json(&cfg)?;
        self.db.write().run_config = cfg.clone();
        self.save()?;
        Ok(cfg)
    }

    fn resolve_detection_config_for_run(
        &self,
        req: &CreateRunRequest,
    ) -> Result<(DetectionConfig, Option<String>, Option<String>), Box<dyn Error>> {
        let edb = EventDb::new(&self.sql_path)?;
        let tid = req
            .detection_config_id
            .as_ref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty());
        if let Some(id) = tid {
            return match edb.get_detection_config_by_id(id)? {
                Some(cfg) => {
                    let name = edb.get_detection_config_name(id)?;
                    Ok((cfg, Some(id.to_string()), name))
                }
                None => Err(format!("detection config not found: {}", id).into()),
            };
        }
        let cfg = edb
            .get_selected_detection_config()?
            .unwrap_or_else(|| self.db.read().run_config.clone());
        let sid = edb.get_selected_detection_config_id()?;
        let name = sid
            .as_ref()
            .and_then(|i| edb.get_detection_config_name(i).ok().flatten());
        Ok((cfg, sid, name))
    }

    pub fn set_anomark_settings(
        &self,
        settings: AnoMarkSettings,
    ) -> Result<AnoMarkSettings, Box<dyn Error>> {
        self.db.write().anomark = settings.clone();
        self.save()?;
        Ok(settings)
    }

    pub fn get_sigma_zero_settings(&self) -> SigmaZeroSettings {
        self.db.read().sigma_zero.clone()
    }

    pub fn set_sigma_zero_settings(
        &self,
        settings: SigmaZeroSettings,
    ) -> Result<SigmaZeroSettings, Box<dyn Error>> {
        self.db.write().sigma_zero = settings.clone();
        self.save()?;
        Ok(settings)
    }

    /// Sigma templates are unused in RustMite (use rustmite-checks / RPL rules instead).
    pub fn default_sigma_rule_templates() -> Vec<SigmaRuleInline> {
        Vec::new()
    }

    /// Sigma stable-rule listing is disabled — prefer RustMite detection rules.
    pub fn list_sigma_stable_rules(&self) -> Result<Vec<SigmaStableRuleRef>, Box<dyn Error>> {
        Ok(Vec::new())
    }

    /// Sigma evaluation is not wired in RustMite. Use fleet clustering, AnoMark, or RustMite rules.
    pub fn check_sigma_zero(
        &self,
        _req: SigmaZeroCheckRequest,
    ) -> Result<SigmaZeroCheckResult, Box<dyn Error>> {
        Err(
            "Sigma/sigmazero is not enabled in RustMite — use rustmite-checks or RPL for rules"
                .into(),
        )
    }

    pub fn train_anomark(
        &self,
        req: AnoMarkTrainRequest,
    ) -> Result<AnoMarkTrainResult, Box<dyn Error>> {
        let (source_training_path, meta) = self.resolve_anomark_training_input(&req)?;
        let settings = self.get_anomark_settings();
        let train_id = Uuid::new_v4().to_string();
        let root = self.platform_root()?;
        let out_dir = root.join("anomark-trains").join(&train_id);
        fs::create_dir_all(&out_dir)?;
        let ext = source_training_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("jsonl");
        let stored_basename = format!("training_input.{}", ext);
        let stored_input = out_dir.join(&stored_basename);
        let stored_model = out_dir.join("model.bin");
        fs::copy(&source_training_path, &stored_input)?;
        if meta.remove_source {
            let _ = fs::remove_file(&source_training_path);
        }
        let line_count = Self::count_file_lines(&stored_input)?;

        let user_path = req.output_model_path.trim();
        let (anomark_out, also_copy_to_platform): (PathBuf, bool) = if user_path.is_empty() {
            (stored_model.clone(), false)
        } else {
            let p = Path::new(user_path).to_path_buf();
            if let Some(parent) = p.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)?;
                }
            }
            (p, true)
        };

        let order = req.order as usize;
        let kind = match ext.to_ascii_lowercase().as_str() {
            "csv" => TrainFileKind::Csv,
            "txt" => TrainFileKind::Txt,
            _ => TrainFileKind::Jsonl,
        };
        let files = vec![(stored_input.clone(), kind)];
        validate_train_file_kinds(&files).map_err(|e: anyhow::Error| e.to_string())?;
        let col = resolve_column_name(
            &files,
            if req.column.is_empty() {
                None
            } else {
                Some(req.column.as_str())
            },
        )
        .map_err(|e: anyhow::Error| e.to_string())?;
        let loaded = load_char_training_data(&files, col.as_deref(), None, None, None)
            .map_err(|e: anyhow::Error| e.to_string())?;

        let mut model = match loaded {
            LoadedCharTrainingData::Lines { ref lines, .. } if lines.is_empty() => {
                let _ = fs::remove_dir_all(&out_dir);
                return Err("no training lines in input".into());
            }
            LoadedCharTrainingData::Lines { lines, counts } => {
                if lines.len() > 2_000 {
                    train_parallel(&lines, order, counts.as_deref(), None)
                } else {
                    ModelHandler::train_from_csv(&lines, order, counts.as_deref(), None)
                }
            }
            .map_err(|e: anyhow::Error| e.to_string())?,
            LoadedCharTrainingData::Corpus { text } => {
                ModelHandler::train_from_txt(&text, order, None)
                    .map_err(|e: anyhow::Error| e.to_string())?
            }
        };
        model.normalize_model_and_compute_prior();
        let out_s = anomark_out
            .to_str()
            .ok_or("output model path is not valid UTF-8")?;
        ModelHandler::save_model(&model, Some(out_s)).map_err(|e: anyhow::Error| e.to_string())?;

        if !anomark_out.is_file() {
            let _ = fs::remove_dir_all(&out_dir);
            return Err("model file not found after anomark train (save failed)".into());
        }
        if also_copy_to_platform {
            if anomark_out != stored_model {
                fs::copy(&anomark_out, &stored_model)?;
            }
        }
        let rel = format!("anomark-trains/{}", train_id);
        let canonical_path = stored_model;
        let record = AnoMarkTrainRecord {
            id: train_id.clone(),
            created_at: Utc::now().to_rfc3339(),
            name: req.name.trim().to_string(),
            request: req.clone(),
            source_dataset_ids: meta.source_dataset_ids,
            from_user_file: meta.from_user_file,
            rel_model_path: format!("{}/model.bin", rel),
            rel_training_data_path: format!("{}/{}", rel, stored_basename),
            training_line_count: line_count,
            bin_path_used: "anomark (in-process library)".to_string(),
            favorite: false,
        };
        self.db.write().anomark_trainings.push(record.clone());
        self.save()?;
        let mut updated = settings;
        updated.model_path = canonical_path.to_string_lossy().to_string();
        updated.column = req.column.clone();
        self.set_anomark_settings(updated)?;
        Ok(AnoMarkTrainResult {
            status: "ok".to_string(),
            model_path: canonical_path.to_string_lossy().to_string(),
            train_id: train_id.clone(),
            record,
        })
    }

    fn platform_root(&self) -> Result<PathBuf, Box<dyn Error>> {
        Path::new(&self.db_path)
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| "invalid platform database path (no parent directory)".into())
    }

    fn count_file_lines(path: &Path) -> Result<u64, Box<dyn Error>> {
        let f = fs::File::open(path)?;
        let n = BufReader::new(f).lines().count() as u64;
        Ok(n)
    }

    /// Returns path to a JSONL training file and metadata (dataset source vs external file).
    fn resolve_anomark_training_input(
        &self,
        req: &AnoMarkTrainRequest,
    ) -> Result<(PathBuf, AnoMarkTrainingInputMeta), Box<dyn Error>> {
        if !req.training_path.trim().is_empty() {
            let p = Path::new(&req.training_path);
            if !p.exists() {
                return Err(format!("training_path does not exist: {}", req.training_path).into());
            }
            return Ok((
                p.to_path_buf(),
                AnoMarkTrainingInputMeta {
                    from_user_file: true,
                    source_dataset_ids: vec![],
                    remove_source: false,
                },
            ));
        }

        let db = self.db.read();
        let mut selected: Vec<DatasetRecord> = db.datasets.clone();
        if !req.dataset_ids.is_empty() {
            selected.retain(|d| req.dataset_ids.iter().any(|id| id == &d.id));
        }
        if !req.tags.is_empty() {
            selected.retain(|d| d.tags.iter().any(|t| req.tags.iter().any(|rt| rt == t)));
        }
        selected.retain(|d| {
            matches!(
                d.kind,
                DatasetKind::Process | DatasetKind::Mixed
            )
        });
        if selected.is_empty() {
            return Err(
                "no process datasets selected for training (provide training_path or dataset_ids/tags)"
                    .into(),
            );
        }
        // Source file is only required as a fallback; if SQLite has rows for the dataset
        // (the normal post-ingest state) we train from there so test rows added via
        // Inspect → Append also feed the model.
        let edb = EventDb::new(&self.sql_path)?;
        for ds in &selected {
            let n_sql = edb.process_entries_for_dataset(&ds.id)?.len();
            if n_sql == 0 {
                let p = Path::new(&ds.source_path);
                if !p.is_file() {
                    return Err(format!(
                        "dataset {} has no SQLite process rows and the source file is missing or not a file: {}",
                        ds.id, ds.source_path
                    )
                    .into());
                }
            }
        }
        let source_ids: Vec<String> = selected.iter().map(|d| d.id.clone()).collect();
        drop(db);

        let tmp_name = format!("anomark-train-{}.jsonl", Uuid::new_v4());
        let tmp_path = std::env::temp_dir().join(&tmp_name);
        let mut out = String::new();
        for ds in selected {
            let profiles = load_process_profiles_sqlite_first(
                &self.sql_path,
                &ds,
                &DetectionConfig::unfiltered_row_loading(),
            )?;
            for p in profiles {
                for (sig, count) in p.counts {
                    let proc_cmd = format!("{} {}", sig.path, sig.name);
                    let cmd_for_markov = anomark_score_line(&p.id, &proc_cmd);
                    for _ in 0..count {
                        out.push_str(
                            &serde_json::json!({
                                "machine_id": p.id,
                                "cmdline": cmd_for_markov,
                                "command": cmd_for_markov,
                            })
                            .to_string(),
                        );
                        out.push('\n');
                    }
                }
            }
        }
        if out.trim().is_empty() {
            return Err("selected datasets produced no trainable commands".into());
        }
        fs::write(&tmp_path, &out)?;
        Ok((
            tmp_path,
            AnoMarkTrainingInputMeta {
                from_user_file: false,
                source_dataset_ids: source_ids,
                remove_source: true,
            },
        ))
    }

    /// List training jobs newest last (or reverse in UI from API).
    pub fn list_anomark_trainings(&self) -> Vec<AnoMarkTrainRecord> {
        self.db.read().anomark_trainings.clone()
    }

    /// Favorites first, then newest by [`AnoMarkTrainRecord::created_at`].
    pub fn list_anomark_trainings_for_display(&self) -> Vec<AnoMarkTrainRecord> {
        let mut v = self.list_anomark_trainings();
        v.sort_by(cmp_anomark_train_record_display);
        v
    }

    pub fn set_anomark_training_favorite(
        &self,
        train_id: &str,
        favorite: bool,
    ) -> Result<(), Box<dyn Error>> {
        let id = train_id.trim();
        if id.is_empty() {
            return Err("empty training id".into());
        }
        {
            let mut w = self.db.write();
            let rec = w
                .anomark_trainings
                .iter_mut()
                .find(|r| r.id == id)
                .ok_or_else(|| format!("AnoMark training not found: {}", id))?;
            rec.favorite = favorite;
        }
        self.save()?;
        Ok(())
    }

    /// Insert a training record restored from durable storage (ClickHouse) if missing.
    pub fn import_anomark_training_record(
        &self,
        record: AnoMarkTrainRecord,
    ) -> Result<(), Box<dyn Error>> {
        {
            let mut w = self.db.write();
            if w.anomark_trainings.iter().any(|t| t.id == record.id) {
                return Ok(());
            }
            w.anomark_trainings.push(record);
        }
        self.save()?;
        Ok(())
    }

    /// Path to a persisted `model.bin` for download, or `None` if missing.
    pub fn anomark_train_stored_model_path(&self, train_id: &str) -> Option<PathBuf> {
        let rec = self
            .db
            .read()
            .anomark_trainings
            .iter()
            .find(|r| r.id == train_id)
            .cloned()?;
        let root = self.platform_root().ok()?;
        let p = root.join(&rec.rel_model_path);
        if p.is_file() {
            Some(p)
        } else {
            None
        }
    }

    /// Path to a persisted `training_input.jsonl`, or `None` if missing.
    pub fn anomark_train_stored_training_data_path(&self, train_id: &str) -> Option<PathBuf> {
        let rec = self
            .db
            .read()
            .anomark_trainings
            .iter()
            .find(|r| r.id == train_id)
            .cloned()?;
        let root = self.platform_root().ok()?;
        let p = root.join(&rec.rel_training_data_path);
        if p.is_file() {
            Some(p)
        } else {
            None
        }
    }

    fn anomark_where_generated(&self, rec: &AnoMarkTrainRecord) -> Result<AnoMarkWhereGenerated, Box<dyn Error>> {
        let root = self.platform_root()?;
        let source_label = if rec.from_user_file {
            let p = rec.request.training_path.trim();
            if p.is_empty() {
                "Training file (path not recorded in request)".to_string()
            } else {
                format!("Training file: {}", p)
            }
        } else if !rec.source_dataset_ids.is_empty() {
            format!("Process datasets: {}", rec.source_dataset_ids.join(", "))
        } else {
            "Process datasets (from tags / filters in request)".to_string()
        };
        let optional = rec.request.output_model_path.trim().to_string();
        Ok(AnoMarkWhereGenerated {
            train_id: rec.id.clone(),
            generated_at: rec.created_at.clone(),
            generation_engine: rec.bin_path_used.clone(),
            platform_data_directory: root.to_string_lossy().to_string(),
            model_file_relative: rec.rel_model_path.clone(),
            training_input_relative: rec.rel_training_data_path.clone(),
            optional_output_copy_path: optional,
            source_label,
            training_line_count: rec.training_line_count,
            request: rec.request.clone(),
            source_dataset_ids: rec.source_dataset_ids.clone(),
            from_user_file: rec.from_user_file,
        })
    }

    /// Load the saved `model.bin` for a training job and return Markov stats plus where it was produced.
    pub fn inspect_anomark_training_model(&self, train_id: &str) -> Result<AnoMarkModelInspection, Box<dyn Error>> {
        let rec = self
            .db
            .read()
            .anomark_trainings
            .iter()
            .find(|r| r.id == train_id)
            .cloned()
            .ok_or_else(|| format!("unknown training id: {}", train_id))?;
        let path = self
            .anomark_train_stored_model_path(train_id)
            .ok_or_else(|| "model file missing for this training".to_string())?;
        let wg = self.anomark_where_generated(&rec)?;
        Self::inspect_anomark_model_file(&path, Some(wg), "")
    }

    /// Inspect the model file currently set in AnoMark settings (may be external to saved trainings).
    pub fn inspect_anomark_configured_model(&self) -> Result<AnoMarkModelInspection, Box<dyn Error>> {
        let cfg = self.get_anomark_settings();
        let p = cfg.model_path.trim();
        if p.is_empty() {
            return Err("AnoMark model path is not set (enter a path on the AnoMark tab and save)".into());
        }
        let path = Path::new(p);
        let note = "This path is the current AnoMark model in settings. It may have been copied from anywhere; use Inspect on a saved training row for a model that IronSift generated on this server, with full provenance.";
        Self::inspect_anomark_model_file(path, None, note)
    }

    fn inspect_anomark_model_file(
        path: &Path,
        where_generated: Option<AnoMarkWhereGenerated>,
        config_origin_note: &str,
    ) -> Result<AnoMarkModelInspection, Box<dyn Error>> {
        if !path.is_file() {
            return Err(format!("model file not found: {}", path.display()).into());
        }
        let path_str = path
            .to_str()
            .ok_or("model path is not valid UTF-8")?;
        let mut model =
            ModelHandler::load_model(path_str).map_err(|e: anyhow::Error| e.to_string())?;
        if !model.is_trained() {
            model.normalize_model_and_compute_prior();
        }
        let threshold = ModelHandler::compute_threshold(&model, 95.0);
        let meta = fs::metadata(path)?;
        let model_path = path
            .canonicalize()
            .unwrap_or_else(|_| path.to_path_buf())
            .to_string_lossy()
            .to_string();
        Ok(AnoMarkModelInspection {
            model_path,
            file_size_bytes: meta.len(),
            order: model.order,
            is_trained: model.is_trained(),
            prior: model.prior,
            num_contexts: model.num_contexts(),
            num_transitions: model.num_transitions(),
            alphabet_len: model.alphabet_len(),
            raw_markov_entries: model.raw_markov_entries(),
            suspect_threshold_ln: threshold,
            where_generated,
            config_origin_note: config_origin_note.to_string(),
        })
    }

    /// Run the same logic as [`Self::test_anomark_cli`] for a single command line; useful when
    /// the caller does not need dataset-wide scoring. `explicit_model_path` wins over `train_id`,
    /// which wins over the platform settings model path.
    pub fn score_anomark_command_with_model_file(
        &self,
        explicit_model_path: Option<&Path>,
        command: &str,
        machine_name: Option<&str>,
        train_id: Option<&str>,
        suspect_percent: f64,
    ) -> Result<AnoMarkCommandScore, Box<dyn Error>> {
        let (path, source, stored_id) = self.resolve_anomark_model_for_test(
            explicit_model_path,
            train_id,
        )?;
        score_one_command_against_model(&path, &source, stored_id, command, machine_name, suspect_percent)
    }

    /// Test an AnoMark model from the CLI: optionally score a single command, and/or compute
    /// suspect-command ratios across selected ingested process datasets (the same way runs do).
    /// Datasets are filtered by ids and/or tags; only `Process` and `Mixed` kinds are scored.
    /// Reads ingested rows from `events.db` (so test rows added via Inspect → Append are scored).
    pub fn test_anomark_cli(
        &self,
        explicit_model_path: Option<&Path>,
        train_id: Option<&str>,
        command: Option<&str>,
        machine_name: Option<&str>,
        dataset_ids: &[String],
        tags: &[String],
        suspect_percent: f64,
    ) -> Result<AnoMarkTestResult, Box<dyn Error>> {
        let (model_path, model_source, stored_id) =
            self.resolve_anomark_model_for_test(explicit_model_path, train_id)?;
        let path_str = model_path
            .to_str()
            .ok_or("model path is not valid UTF-8")?;
        let mut model =
            ModelHandler::load_model(path_str).map_err(|e: anyhow::Error| e.to_string())?;
        if !model.is_trained() {
            model.normalize_model_and_compute_prior();
        }
        let pct = clamp_anomark_suspect_percent(suspect_percent);
        let threshold_ln = ModelHandler::compute_threshold(&model, pct);

        let command_score = match command.map(str::trim).filter(|s| !s.is_empty()) {
            Some(cmd) => Some(score_one_command_against_model(
                &model_path,
                &model_source,
                stored_id.clone(),
                cmd,
                machine_name,
                suspect_percent,
            )?),
            None => None,
        };

        let mut datasets_summaries: Vec<AnoMarkTestDatasetSummary> = Vec::new();
        let mut datasets_skipped: Vec<String> = Vec::new();
        let any_filter = !dataset_ids.is_empty() || !tags.is_empty();
        if any_filter {
            let all_datasets = self.db.read().datasets.clone();
            let mut selected: Vec<DatasetRecord> = all_datasets;
            if !dataset_ids.is_empty() {
                selected.retain(|d| dataset_ids.iter().any(|id| id == &d.id));
            }
            if !tags.is_empty() {
                selected.retain(|d| d.tags.iter().any(|t| tags.iter().any(|rt| rt == t)));
            }
            for d in &selected {
                if !matches!(d.kind, DatasetKind::Process | DatasetKind::Mixed) {
                    datasets_skipped.push(format!("{} ({}, kind={:?})", d.id, d.name, d.kind));
                    continue;
                }
            }
            selected.retain(|d| matches!(d.kind, DatasetKind::Process | DatasetKind::Mixed));

            let edb = EventDb::new(&self.sql_path)?;
            for ds in selected {
                let entries = edb.process_entries_for_dataset(&ds.id)?;
                let mut totals: HashMap<String, (u64, u64)> = HashMap::new();
                let mut commands_scored: u64 = 0;
                let mut suspect_commands: u64 = 0;
                for e in &entries {
                    let row = raw_log_entry_to_anomark_row(e);
                    let cmd = row_command_for_anomark(&row, "cmdline");
                    let host_raw = row_machine_for_anomark(&row, "machine_id");
                    let scored = anomark_score_line(&host_raw, &cmd);
                    if scored.is_empty() {
                        continue;
                    }
                    let padded = format!("{}{}", "~".repeat(model.order), scored);
                    let ll = model.log_likelihood(&padded);
                    let suspect = ModelHandler::is_suspect_command(ll, threshold_ln);
                    commands_scored += 1;
                    let slot = totals.entry(host_raw.clone()).or_insert((0, 0));
                    slot.0 += 1;
                    if suspect {
                        slot.1 += 1;
                        suspect_commands += 1;
                    }
                }
                let mut host_stats: Vec<AnoMarkTestDatasetHostStat> = totals
                    .into_iter()
                    .map(|(host, (commands, suspect))| AnoMarkTestDatasetHostStat {
                        host,
                        commands,
                        suspect,
                        ratio: if commands == 0 {
                            0.0
                        } else {
                            suspect as f64 / commands as f64
                        },
                    })
                    .collect();
                host_stats.sort_by(|a, b| b.ratio.partial_cmp(&a.ratio).unwrap_or(std::cmp::Ordering::Equal).then_with(|| a.host.cmp(&b.host)));
                datasets_summaries.push(AnoMarkTestDatasetSummary {
                    dataset_id: ds.id.clone(),
                    dataset_name: ds.name.clone(),
                    commands_scored,
                    suspect_commands,
                    host_stats,
                });
            }
        }

        Ok(AnoMarkTestResult {
            model_path: model_path.to_string_lossy().into_owned(),
            model_source,
            model_order: model.order,
            model_prior_ln: model.prior,
            suspect_percent_used: pct,
            suspect_threshold_ln: threshold_ln,
            command_score,
            datasets: datasets_summaries,
            datasets_skipped,
        })
    }

    fn resolve_anomark_model_for_test(
        &self,
        explicit_model_path: Option<&Path>,
        train_id: Option<&str>,
    ) -> Result<(PathBuf, String, Option<String>), Box<dyn Error>> {
        if let Some(p) = explicit_model_path {
            if !p.is_file() {
                return Err(format!("AnoMark model file not found: {}", p.display()).into());
            }
            return Ok((p.to_path_buf(), "explicit-path".to_string(), None));
        }
        if let Some(tid) = train_id.map(str::trim).filter(|s| !s.is_empty()) {
            let p = self.anomark_train_stored_model_path(tid).ok_or_else(|| {
                format!(
                    "no model file for training {} (refresh the list or train again)",
                    tid
                )
            })?;
            return Ok((p, "training".to_string(), Some(tid.to_string())));
        }
        let cfg = self.get_anomark_settings();
        let p = cfg.model_path.trim();
        if p.is_empty() {
            return Err(
                "AnoMark model path is empty — pass --anomark-model, --anomark-train-id, or set the platform settings"
                    .into(),
            );
        }
        let path = self.resolve_anomark_model_path(p).ok_or_else(|| {
            format!(
                "AnoMark model file not found for settings path {:?} (use an absolute path or one relative to the platform directory next to db.json)",
                p
            )
        })?;
        Ok((path, "platform".to_string(), None))
    }

    /// Score one command with the platform model path or a saved training's `model.bin`.
    /// `suspect_percent` is clamped to **55.0–99.999** (same scale as [`ModelHandler::compute_threshold`]); lower = more sensitive (more commands flagged).
    pub fn score_anomark_command(
        &self,
        command: &str,
        machine_name: Option<&str>,
        train_id: Option<&str>,
        suspect_percent: f64,
    ) -> Result<AnoMarkCommandScore, Box<dyn Error>> {
        let mut scores = self.score_anomark_commands(
            &[(machine_name, command)],
            train_id,
            suspect_percent,
        )?;
        scores
            .pop()
            .ok_or_else(|| "command is empty".into())
    }

    /// Score many commands against one model load (much faster than calling
    /// [`Self::score_anomark_command`] per line). Each pair is `(optional machine label, command)`.
    /// Empty commands are skipped.
    pub fn score_anomark_commands(
        &self,
        commands: &[(Option<&str>, &str)],
        train_id: Option<&str>,
        suspect_percent: f64,
    ) -> Result<Vec<AnoMarkCommandScore>, Box<dyn Error>> {
        if commands.is_empty() {
            return Ok(Vec::new());
        }
        let (path, source, stored_id) = self.resolve_anomark_model_for_test(None, train_id)?;
        score_commands_against_model(
            &path,
            &source,
            stored_id,
            commands,
            suspect_percent,
        )
    }

    pub fn get_run(&self, id: &str) -> Option<DetectionRunRecord> {
        self.db.read().runs.iter().find(|r| r.id == id).cloned()
    }

    /// Findings for `GET .../detections`: syncs triage from history, ensures `dataset_tags`, and returns
    /// **effective** score/severity from raw detector scores plus per-reason triage.
    pub fn findings_for_run_detections_api(&self, run_id: &str) -> Option<Vec<DetectionFinding>> {
        if let Err(e) = self.sync_run_triage_from_history(run_id) {
            log::warn!(
                "sync_run_triage_from_history failed for run {}: {}; serving findings without merge",
                run_id,
                e
            );
        }
        let r = self.get_run(run_id)?;
        let db = self.db.read();
        let datasets = db.datasets.as_slice();
        let triage = &r.user_triage;
        let mut out: Vec<DetectionFinding> = r
            .findings
            .iter()
            .map(|f| {
                let mut ff = f.clone();
                if ff.dataset_tags.is_empty() {
                    ff.dataset_tags = resolve_machine_dataset_tags_for_run(
                        &ff.machine_id,
                        &r.dataset_ids,
                        r.detection_focus,
                        datasets,
                    );
                }
                let (eff_score, eff_sev) = effective_score_and_severity(f, triage);
                ff.score = eff_score;
                ff.severity = eff_sev;
                ff
            })
            .collect();
        sort_findings_by_review_priority(&mut out);
        Some(out)
    }

    /// Past analyst per-reason verdicts for this run’s detection lines: **`entries`** are active
    /// precedents (fleet memory may apply); **`suppressed`** are blocked by
    /// [`DetectionRunRecord::triage_precedent_ignore`] but still shown for management.
    pub fn triage_precedent_for_run(&self, run_id: &str) -> Option<TriagePrecedentBundle> {
        let _ = self.sync_run_triage_from_history(run_id);
        let r = self.get_run(run_id)?;
        let keys = reason_keys_in_findings(&r.findings);
        let ignore = precedent_ignore_set(&r);
        let fleet_drops = self.fleet_precedent_drop_set_snapshot();
        let (runs_sorted, persistent) = {
            let db = self.db.read();
            let mut v = db.runs.clone();
            v.sort_by(|a, b| b.created_at.cmp(&a.created_at));
            (v, db.fleet_triage_precedent_entries.clone())
        };
        let prov = build_reason_verdict_provenance_combined(
            &runs_sorted,
            Some(run_id),
            &fleet_drops,
            &persistent,
        );
        let mut entries = Vec::new();
        let mut suppressed = Vec::new();
        for (k, v) in prov {
            if !keys.contains(&k) {
                continue;
            }
            if ignore.contains(&k) {
                suppressed.push(v);
            } else {
                entries.push(v);
            }
        }
        let sort_fn = |a: &HistoricalReasonVerdict, b: &HistoricalReasonVerdict| {
            a.detector
                .cmp(&b.detector)
                .then_with(|| a.reason.cmp(&b.reason))
        };
        entries.sort_by(sort_fn);
        suppressed.sort_by(sort_fn);
        Some(TriagePrecedentBundle { entries, suppressed })
    }

    /// Latest saved per-reason verdict for each `(detector, reason)` in **persisted fleet memory**
    /// (survives deleting all runs). Keys in [`PlatformDb::fleet_triage_precedent_drops`] are omitted.
    /// Per-run “suppress precedent” still lives on each [`DetectionRunRecord`].
    pub fn triage_precedent_fleet_global(&self) -> Vec<HistoricalReasonVerdict> {
        let fleet_drops = self.fleet_precedent_drop_set_snapshot();
        let persistent = self.db.read().fleet_triage_precedent_entries.clone();
        let mut entries: Vec<_> = persistent
            .iter()
            .filter(|e| !fleet_drops.contains(&(e.detector.clone(), e.reason.clone())))
            .filter(|e| !reason_excluded_from_per_reason_triage(&e.reason))
            .filter(|e| !matches!(e.verdict, TriageVerdict::Unset))
            .map(fleet_precedent_entry_to_historical)
            .collect();
        entries.sort_by(|a, b| {
            a.detector
                .cmp(&b.detector)
                .then_with(|| a.reason.cmp(&b.reason))
        });
        entries
    }

    fn fleet_precedent_drop_set_snapshot(&self) -> HashSet<(String, String)> {
        self.db
            .read()
            .fleet_triage_precedent_drops
            .iter()
            .map(|k| (k.detector.clone(), k.reason.clone()))
            .collect()
    }

    /// Keys removed from fleet triage memory (see [`PlatformDb::fleet_triage_precedent_drops`]).
    pub fn fleet_triage_precedent_drops(&self) -> Vec<ReasonPrecedentKey> {
        self.db.read().fleet_triage_precedent_drops.clone()
    }

    /// Exclude this `(detector, reason)` from fleet precedent listing and from merge-into-new-runs.
    pub fn add_fleet_triage_precedent_drop(&self, key: ReasonPrecedentKey) -> Result<(), Box<dyn Error>> {
        let det = key.detector.trim();
        if det.is_empty() {
            return Err("detector must not be empty".into());
        }
        let key = ReasonPrecedentKey {
            detector: det.to_string(),
            reason: key.reason,
        };
        let mut db = self.db.write();
        let dup = db
            .fleet_triage_precedent_drops
            .iter()
            .any(|k| k.detector == key.detector && k.reason == key.reason);
        if !dup {
            db.fleet_triage_precedent_drops.push(key);
        }
        drop(db);
        self.save()?;
        Ok(())
    }

    /// Put a pair back into fleet triage memory (undo [`Self::add_fleet_triage_precedent_drop`]).
    pub fn remove_fleet_triage_precedent_drop(
        &self,
        key: &ReasonPrecedentKey,
    ) -> Result<bool, Box<dyn Error>> {
        let mut db = self.db.write();
        let n = db.fleet_triage_precedent_drops.len();
        db.fleet_triage_precedent_drops.retain(|k| {
            !(k.detector == key.detector && k.reason == key.reason)
        });
        let changed = db.fleet_triage_precedent_drops.len() != n;
        drop(db);
        if changed {
            self.save()?;
        }
        Ok(changed)
    }

    /// Permanently remove this `(detector, reason)` from persisted fleet triage memory
    /// ([`PlatformDb::fleet_triage_precedent_entries`]) and from [`PlatformDb::fleet_triage_precedent_drops`]
    /// if present. The pair can reappear later if triage on a saved run upserts it again.
    pub fn delete_fleet_triage_precedent_entry(
        &self,
        key: ReasonPrecedentKey,
    ) -> Result<bool, Box<dyn Error>> {
        let det = key.detector.trim();
        if det.is_empty() {
            return Err("detector must not be empty".into());
        }
        let reason = key.reason;
        let mut db = self.db.write();
        let n_entries = db.fleet_triage_precedent_entries.len();
        db.fleet_triage_precedent_entries.retain(|e| {
            !(e.detector.trim() == det && e.reason == reason)
        });
        let removed_entry = db.fleet_triage_precedent_entries.len() != n_entries;
        let n_drops = db.fleet_triage_precedent_drops.len();
        db.fleet_triage_precedent_drops.retain(|k| {
            !(k.detector.trim() == det && k.reason == reason)
        });
        let removed_drop = db.fleet_triage_precedent_drops.len() != n_drops;
        let changed = removed_entry || removed_drop;
        drop(db);
        if changed {
            self.save()?;
        }
        Ok(changed)
    }

    /// Stop using fleet precedent for one `(detector, reason)` on this run: add to ignore list and
    /// remove matching per-reason triage rows (so effective severity recomputes).
    pub fn add_triage_precedent_ignore(
        &self,
        run_id: &str,
        key: ReasonPrecedentKey,
    ) -> Result<(), Box<dyn Error>> {
        let keys_in_run = {
            let db = self.db.read();
            let rec = db
                .runs
                .iter()
                .find(|r| r.id == run_id)
                .ok_or_else(|| format!("run not found: {}", run_id))?;
            reason_keys_in_findings(&rec.findings)
        };
        let pair = (key.detector.clone(), key.reason.clone());
        if !keys_in_run.contains(&pair) {
            return Err("reason key does not appear in this run's findings".into());
        }
        let mut db = self.db.write();
        let rec = db
            .runs
            .iter_mut()
            .find(|r| r.id == run_id)
            .ok_or_else(|| format!("run not found: {}", run_id))?;
        if !rec
            .triage_precedent_ignore
            .iter()
            .any(|k| k.detector == key.detector && k.reason == key.reason)
        {
            rec.triage_precedent_ignore.push(key.clone());
        }
        strip_reason_decisions_for_key(&mut rec.user_triage, &key.detector, &key.reason);
        drop(db);
        self.save()?;
        Ok(())
    }

    /// Allow fleet precedent again for this `(detector, reason)` on this run; then re-sync merge.
    pub fn remove_triage_precedent_ignore(
        &self,
        run_id: &str,
        key: &ReasonPrecedentKey,
    ) -> Result<(), Box<dyn Error>> {
        let mut db = self.db.write();
        let rec = db
            .runs
            .iter_mut()
            .find(|r| r.id == run_id)
            .ok_or_else(|| format!("run not found: {}", run_id))?;
        let n = rec.triage_precedent_ignore.len();
        rec.triage_precedent_ignore.retain(|k| {
            !(k.detector == key.detector && k.reason == key.reason)
        });
        if rec.triage_precedent_ignore.len() == n {
            drop(db);
            return Ok(());
        }
        drop(db);
        self.save()?;
        let _ = self.sync_run_triage_from_history(run_id);
        Ok(())
    }

    /// Remove a single saved detection run from `db.json` (ingested datasets are unchanged).
    pub fn delete_run(&self, run_id: &str) -> Result<(), Box<dyn Error>> {
        {
            let mut w = self.db.write();
            let n = w.runs.len();
            w.runs.retain(|r| r.id != run_id);
            if w.runs.len() == n {
                return Err(format!("run not found: {}", run_id).into());
            }
        }
        self.save()?;
        Ok(())
    }

    /// Replace saved analyst triage for a run. Every `machine_id` must appear in that run's findings.
    pub fn update_run_user_triage(
        &self,
        run_id: &str,
        triage: RunUserTriage,
    ) -> Result<(), Box<dyn Error>> {
        let valid_hosts: HashSet<String> = {
            let db = self.db.read();
            let rec = db
                .runs
                .iter()
                .find(|r| r.id == run_id)
                .ok_or_else(|| format!("run not found: {}", run_id))?;
            rec.findings.iter().map(|f| f.machine_id.clone()).collect()
        };
        let mut seen_m = HashSet::new();
        let triage = triage.without_excluded_reason_decisions();
        for m in &triage.machines {
            if !seen_m.insert(m.machine_id.clone()) {
                return Err(format!("duplicate machine_id in triage: {}", m.machine_id).into());
            }
            if !valid_hosts.contains(&m.machine_id) {
                return Err(format!(
                    "unknown machine_id in triage: {} (not in this run's findings)",
                    m.machine_id
                )
                .into());
            }
        }
        let mut db = self.db.write();
        {
            let rec = db
                .runs
                .iter_mut()
                .find(|r| r.id == run_id)
                .ok_or_else(|| format!("run not found: {}", run_id))?;
            let old_triage = rec.user_triage.clone();
            let mut triage = triage;
            stamp_reason_review_times_on_triage_put(&old_triage, &mut triage);
            rec.user_triage = triage;
            let _ = normalize_triage_groups_and_auto_final_for_run(rec);
            align_reviewed_at_for_normalized_reason_groups(rec);
        }
        let lifted = {
            let rec = db
                .runs
                .iter()
                .find(|r| r.id == run_id)
                .ok_or_else(|| format!("run not found: {}", run_id))?;
            non_unset_triage_reason_keys(&rec.user_triage)
        };
        if !lifted.is_empty() {
            db.fleet_triage_precedent_drops.retain(|k| {
                !lifted.contains(&(k.detector.clone(), k.reason.clone()))
            });
        }
        let rec_snapshot = db
            .runs
            .iter()
            .find(|r| r.id == run_id)
            .ok_or_else(|| format!("run not found: {}", run_id))?
            .clone();
        upsert_fleet_precedents_from_run(&mut db.fleet_triage_precedent_entries, &rec_snapshot);
        drop(db);
        self.save()?;
        Ok(())
    }

    /// Copy per-reason triage from older runs when the same `(detector, reason)` was already judged
    /// (latest verdict wins). Persists only when something changes. Does not alter raw finding scores.
    pub fn sync_run_triage_from_history(&self, run_id: &str) -> Result<bool, Box<dyn Error>> {
        let fleet_drops = self.fleet_precedent_drop_set_snapshot();
        let (runs_sorted, persistent) = {
            let db = self.db.read();
            let mut v = db.runs.clone();
            v.sort_by(|a, b| b.created_at.cmp(&a.created_at));
            (v, db.fleet_triage_precedent_entries.clone())
        };
        let history = build_reason_verdict_history_from_runs(
            &runs_sorted,
            run_id,
            &fleet_drops,
            &persistent,
        );
        let mut db = self.db.write();
        let (merge_changed, norm_changed) = {
            let rec = db
                .runs
                .iter_mut()
                .find(|r| r.id == run_id)
                .ok_or_else(|| format!("run not found: {}", run_id))?;
            let ignore = precedent_ignore_set(rec);
            let (merged, merge_changed) = merge_history_into_user_triage(
                &rec.findings,
                &rec.user_triage,
                &history,
                &ignore,
            );
            if merge_changed {
                rec.user_triage = merged;
            }
            let norm_changed = normalize_triage_groups_and_auto_final_for_run(rec);
            (merge_changed, norm_changed)
        };
        if !merge_changed && !norm_changed {
            return Ok(false);
        }
        let rec_snapshot = db
            .runs
            .iter()
            .find(|r| r.id == run_id)
            .ok_or_else(|| format!("run not found: {}", run_id))?
            .clone();
        upsert_fleet_precedents_from_run(&mut db.fleet_triage_precedent_entries, &rec_snapshot);
        drop(db);
        self.save()?;
        Ok(true)
    }

    /// Remove all detection runs (same storage as `delete_all_datasets` — only the run list in `db.json`).
    pub fn delete_all_runs(&self) -> Result<(), Box<dyn Error>> {
        self.db.write().runs.clear();
        self.save()?;
        Ok(())
    }

    /// Absolute path to the on-disk model file `train_anomark` would have written for this id, if
    /// the platform root is resolvable. Used to compare against `AnoMarkSettings::model_path` so we
    /// can clear stale references when a training is deleted.
    fn anomark_train_canonical_model_path(&self, train_id: &str) -> Option<PathBuf> {
        let rec = self
            .db
            .read()
            .anomark_trainings
            .iter()
            .find(|r| r.id == train_id)
            .cloned()?;
        let root = self.platform_root().ok()?;
        Some(root.join(&rec.rel_model_path))
    }

    /// `true` when the configured platform `model_path` points at this training's stored model.
    /// Compares both the absolute expected path (`{platform_root}/anomark-trains/{id}/model.bin`)
    /// and a relative-suffix match, so manually-edited settings still get cleaned up on delete.
    fn settings_points_at_training(&self, train_id: &str, expected_abs: &Path) -> bool {
        let cfg = self.get_anomark_settings();
        let mp = cfg.model_path.trim();
        if mp.is_empty() {
            return false;
        }
        let exp = expected_abs.to_string_lossy();
        if mp == exp {
            return true;
        }
        let suffix_unix = format!("anomark-trains/{}/model.bin", train_id);
        let mp_norm = mp.replace('\\', "/");
        if mp_norm.ends_with(&suffix_unix) {
            return true;
        }
        false
    }

    /// Delete a single AnoMark training: remove its `db.json` record, best-effort wipe of
    /// `{platform_root}/anomark-trains/{id}/`, and clear `anomark.model_path` if it pointed at the
    /// deleted training. Existing detection runs that referenced this training are kept (their
    /// findings are already baked in); rerunning a finding that needs the deleted model will
    /// surface the usual "model not readable" error.
    pub fn delete_anomark_training(&self, train_id: &str) -> Result<(), Box<dyn Error>> {
        let id = train_id.trim();
        if id.is_empty() {
            return Err("anomark training id is required".into());
        }
        let canonical = self.anomark_train_canonical_model_path(id);
        let dir = canonical.as_ref().and_then(|p| p.parent().map(Path::to_path_buf));
        {
            let mut w = self.db.write();
            let n = w.anomark_trainings.len();
            w.anomark_trainings.retain(|r| r.id != id);
            if w.anomark_trainings.len() == n {
                return Err(format!("anomark training not found: {}", id).into());
            }
        }
        if let Some(d) = &dir {
            if d.is_dir() {
                if let Err(e) = fs::remove_dir_all(d) {
                    log::warn!(
                        "delete_anomark_training: failed to remove {}: {} (db.json record was removed)",
                        d.display(),
                        e
                    );
                }
            }
        }
        if let Some(canon) = canonical {
            if self.settings_points_at_training(id, &canon) {
                let mut updated = self.get_anomark_settings();
                updated.model_path = String::new();
                let _ = self.set_anomark_settings(updated);
            }
        }
        self.save()?;
        Ok(())
    }

    /// Delete every saved AnoMark training (records + on-disk dirs). Returns the number of
    /// records removed. Clears `anomark.model_path` when it pointed at any deleted training.
    pub fn delete_all_anomark_trainings(&self) -> Result<usize, Box<dyn Error>> {
        let trainings = self.list_anomark_trainings();
        if trainings.is_empty() {
            return Ok(0);
        }
        let root = self.platform_root().ok();
        let cfg_path = self.get_anomark_settings().model_path.trim().to_string();
        let mut should_clear_settings = false;
        for t in &trainings {
            if let Some(rt) = &root {
                let abs = rt.join(&t.rel_model_path);
                if !cfg_path.is_empty() && self.settings_points_at_training(&t.id, &abs) {
                    should_clear_settings = true;
                }
                if let Some(dir) = abs.parent() {
                    if dir.is_dir() {
                        if let Err(e) = fs::remove_dir_all(dir) {
                            log::warn!(
                                "delete_all_anomark_trainings: failed to remove {}: {}",
                                dir.display(),
                                e
                            );
                        }
                    }
                }
            }
        }
        let removed = {
            let mut w = self.db.write();
            let n = w.anomark_trainings.len();
            w.anomark_trainings.clear();
            n
        };
        if should_clear_settings {
            let mut updated = self.get_anomark_settings();
            updated.model_path = String::new();
            let _ = self.set_anomark_settings(updated);
        }
        self.save()?;
        Ok(removed)
    }

    pub fn inspect_dataset(
        &self,
        dataset_id: &str,
        process_limit: u32,
        file_limit: u32,
    ) -> Result<DatasetInspection, Box<dyn Error>> {
        EventDb::new(&self.sql_path)?.inspect_dataset(dataset_id, process_limit, file_limit)
    }

    /// Append NDJSON lines to the SQLite event store for this dataset (testing / manual injection).
    /// Does not replace data re-ingested from the dataset source file on full `ingest_dataset`.
    pub fn append_dataset_test_ndjson(
        &self,
        dataset_id: &str,
        ndjson: &str,
    ) -> Result<crate::event_db::AppendTestSummary, Box<dyn Error>> {
        let (source_path, ingest_mid) = {
            let g = self.db.read();
            let ds = g
                .datasets
                .iter()
                .find(|d| d.id == dataset_id)
                .ok_or("dataset not found")?;
            (ds.source_path.clone(), ds.ingest_default_machine_id.clone())
        };
        let default_mid =
            default_machine_fallback_for_source_file(&source_path, ingest_mid.as_deref());
        EventDb::new(&self.sql_path)?.append_test_ndjson(dataset_id, &default_mid, ndjson)
    }

    /// Delete ingested process/file rows by SQLite `id` (inspect samples include these keys).
    pub fn delete_dataset_events(
        &self,
        dataset_id: &str,
        req: DeleteDatasetEventsRequest,
    ) -> Result<(usize, usize), Box<dyn Error>> {
        let n_req = req.process_ids.len() + req.file_ids.len();
        if n_req == 0 {
            return Err("no row ids provided".into());
        }
        if n_req > DELETE_DATASET_EVENTS_MAX_IDS {
            return Err(format!(
                "too many row ids in one request (max {})",
                DELETE_DATASET_EVENTS_MAX_IDS
            )
            .into());
        }
        {
            let db = self.db.read();
            if !db.datasets.iter().any(|d| d.id == dataset_id) {
                return Err("dataset not found".into());
            }
        }
        let edb = EventDb::new(&self.sql_path)?;
        let dp = edb.delete_process_events_by_ids(dataset_id, &req.process_ids)?;
        let df = edb.delete_file_events_by_ids(dataset_id, &req.file_ids)?;
        Ok((dp, df))
    }

    pub fn delete_all_datasets(&self) -> Result<(), Box<dyn Error>> {
        EventDb::new(&self.sql_path)?.delete_all_datasets()?;
        self.db.write().datasets.clear();
        self.save()?;
        Ok(())
    }

    pub fn create_dataset(
        &self,
        req: CreateDatasetRequest,
    ) -> Result<(DatasetRecord, IngestSummary), Box<dyn Error>> {
        if !Path::new(&req.source_path).exists() {
            return Err(format!("source_path does not exist: {}", req.source_path).into());
        }
        let format = match Path::new(&req.source_path).extension().and_then(|e| e.to_str()) {
            Some(ext) => ext.to_lowercase(),
            None => "unknown".to_string(),
        };
        let mut rec = DatasetRecord {
            id: Uuid::new_v4().to_string(),
            name: req.name,
            source_path: req.source_path,
            format,
            kind: req.kind,
            tags: req.tags,
            schema_profile: req.schema_profile,
            imported_at: Utc::now().to_rfc3339(),
            ingest_default_machine_id: req.ingest_default_machine_id,
        };
        let summary = EventDb::new(&self.sql_path)?.ingest_dataset(&rec)?;
        rec.kind = dataset_kind_from_ingest_summary(&summary);
        self.db.write().datasets.push(rec.clone());
        self.save()?;
        Ok((rec, summary))
    }

    pub fn import_file_auto(
        &self,
        source_path: &str,
        name: Option<String>,
        tags: Vec<String>,
        ingest_default_machine_id: Option<String>,
        kind_override: Option<DatasetKind>,
    ) -> Result<(DatasetRecord, IngestSummary), Box<dyn Error>> {
        let path = Path::new(source_path);
        if !path.exists() {
            return Err(format!("source_path does not exist: {}", source_path).into());
        }
        let kind = match kind_override {
            Some(k) => k,
            None => detect_kind(path)?,
        };
        let dataset_name = name.unwrap_or_else(|| {
            path.file_name()
                .and_then(|x| x.to_str())
                .unwrap_or("dataset")
                .to_string()
        });
        self.create_dataset(CreateDatasetRequest {
            name: dataset_name,
            source_path: source_path.to_string(),
            kind,
            tags,
            schema_profile: default_schema_profile(),
            ingest_default_machine_id,
        })
    }

    /// Recursively find every `.jsonl` file under `root_dir` and import each as its own dataset.
    /// Dataset names are the path relative to `root_dir` (POSIX slashes) so nested files stay distinct.
    ///
    /// `parent_tag` adds one tag per file from the **parent folder’s name**: split by the rule’s
    /// delimiter and take the 1-based `field` segment (see [`ParentDirTagRule`]). Merged with
    /// `tags` without duplicates.
    /// `kind_override`: when `Some`, dataset **metadata** uses that kind before ingest; the stored kind
    /// is still derived from row counts (NDJSON with both process and file lines becomes `mixed`).
    /// Prefer `None` so [`detect_kind`] can return [`DatasetKind::Mixed`] for mixed logs.
    pub fn import_jsonl_recursive(
        &self,
        root_dir: &Path,
        tags: Vec<String>,
        parent_tag: Option<ParentDirTagRule>,
        kind_override: Option<DatasetKind>,
    ) -> Result<Vec<(DatasetRecord, IngestSummary)>, Box<dyn Error>> {
        if !root_dir.is_dir() {
            return Err(format!("not a directory: {}", root_dir.display()).into());
        }
        let root_norm = fs::canonicalize(root_dir)?;
        let mut paths: Vec<PathBuf> = Vec::new();
        collect_jsonl_paths(&root_norm, &mut paths)?;
        paths.sort();
        let mut out: Vec<(DatasetRecord, IngestSummary)> = Vec::new();
        for p in paths {
            let p_norm = fs::canonicalize(&p)?;
            let source = p_norm.to_string_lossy().to_string();
            let rel = p_norm.strip_prefix(&root_norm).unwrap_or(p_norm.as_path());
            let name = {
                let s = rel.to_string_lossy().replace('\\', "/");
                let s = s.trim_start_matches('/').trim();
                if s.is_empty() {
                    p_norm
                        .file_name()
                        .and_then(|x| x.to_str())
                        .unwrap_or("dataset")
                        .to_string()
                } else {
                    s.to_string()
                }
            };
            let parent_machine = parent_tag
                .as_ref()
                .and_then(|rule| parent_dir_tag_from_path(&p_norm, rule));
            let mut merged = tags.clone();
            if let Some(ref extra) = parent_machine {
                if !merged.iter().any(|x| x == extra) {
                    merged.push(extra.clone());
                }
            } else if let Some(rule) = parent_tag.as_ref() {
                log::debug!(
                    "ingest: no parent-dir tag for {} (parent name segment {} / {:?})",
                    p_norm.display(),
                    rule.field,
                    rule.delimiter
                );
            }
            out.push(self.import_file_auto(
                &source,
                Some(name),
                merged,
                parent_machine,
                kind_override,
            )?);
        }
        if out.is_empty() {
            return Err(format!(
                "no .jsonl files found under {}",
                root_dir.display()
            )
            .into());
        }
        Ok(out)
    }

    pub fn add_dataset_tags(
        &self,
        dataset_id: &str,
        tags: &[String],
    ) -> Result<(DatasetRecord, IngestSummary), Box<dyn Error>> {
        let mut db = self.db.write();
        let rec = db
            .datasets
            .iter_mut()
            .find(|d| d.id == dataset_id)
            .ok_or("dataset not found")?;
        for t in tags {
            if !rec.tags.iter().any(|x| x == t) {
                rec.tags.push(t.clone());
            }
        }
        let out = rec.clone();
        drop(db);
        let summary = EventDb::new(&self.sql_path)?.ingest_dataset(&out)?;
        let kind = dataset_kind_from_ingest_summary(&summary);
        {
            let mut db = self.db.write();
            if let Some(r) = db.datasets.iter_mut().find(|d| d.id == dataset_id) {
                r.kind = kind;
            }
        }
        self.save()?;
        let updated = self
            .db
            .read()
            .datasets
            .iter()
            .find(|d| d.id == dataset_id)
            .cloned()
            .ok_or("dataset not found")?;
        Ok((updated, summary))
    }

    pub fn remove_dataset_tags(
        &self,
        dataset_id: &str,
        tags: &[String],
    ) -> Result<(DatasetRecord, IngestSummary), Box<dyn Error>> {
        if tags.is_empty() {
            return Err("no tags to remove".into());
        }
        let mut db = self.db.write();
        let rec = db
            .datasets
            .iter_mut()
            .find(|d| d.id == dataset_id)
            .ok_or("dataset not found")?;
        rec.tags.retain(|t| !tags.iter().any(|rm| rm == t));
        let out = rec.clone();
        drop(db);
        let summary = EventDb::new(&self.sql_path)?.ingest_dataset(&out)?;
        let kind = dataset_kind_from_ingest_summary(&summary);
        {
            let mut db = self.db.write();
            if let Some(r) = db.datasets.iter_mut().find(|d| d.id == dataset_id) {
                r.kind = kind;
            }
        }
        self.save()?;
        let updated = self
            .db
            .read()
            .datasets
            .iter()
            .find(|d| d.id == dataset_id)
            .cloned()
            .ok_or("dataset not found")?;
        Ok((updated, summary))
    }

    /// Append one reason to a finding while keeping the per-detector bucket
    /// ([`DetectionFinding::reasons_by_detector`]) and the flat list
    /// ([`DetectionFinding::reasons`]) in sync. The flat list is what older clients (and saved
    /// runs) read; the bucket is what the new UI uses to render reasons grouped per detector.
    fn push_detector_reason(f: &mut DetectionFinding, detector: &str, reason: String) {
        f.reasons.push(reason.clone());
        match f.reasons_by_detector.iter_mut().find(|b| b.detector == detector) {
            Some(b) => b.reasons.push(reason),
            None => f.reasons_by_detector.push(DetectorReasons {
                detector: detector.to_string(),
                reasons: vec![reason],
            }),
        }
    }

    #[inline]
    /// Bulk version of [`Self::push_detector_reason`] for cases that already build a `Vec`
    /// (e.g. `analyze_*_fleet` returning `anomalous_features`).
    fn extend_detector_reasons<I: IntoIterator<Item = String>>(
        f: &mut DetectionFinding,
        detector: &str,
        reasons: I,
    ) {
        for r in reasons {
            Self::push_detector_reason(f, detector, r);
        }
    }

    pub fn run_detection(&self, req: CreateRunRequest) -> Result<DetectionRunRecord, Box<dyn Error>> {
        let datasets = self.selected_datasets(&req)?;
        let (config, dc_id, dc_name) = self.resolve_detection_config_for_run(&req)?;

        let mut process_sets = Vec::new();
        let mut file_sets = Vec::new();
        for d in &datasets {
            let (use_p, use_f) = run_detection_arms(d.kind, req.detection_focus);
            if use_p {
                process_sets.push(d.clone());
            }
            if use_f {
                file_sets.push(d.clone());
            }
        }

        let mut finding_by_host: HashMap<String, DetectionFinding> = HashMap::new();

        let run_fleet = run_fleet_detection(req.detector_mode);
        let run_anomark = run_anomark_detection(req.detector_mode, req.enable_anomark);
        let anomark_suspect_percent = clamp_anomark_suspect_percent(req.anomark_suspect_percent);

        if matches!(req.detector_mode, RunDetectorMode::AnomarkOnly) && process_sets.is_empty() {
            return Err(
                "AnoMark-only run needs at least one dataset that contributes process rows (kind process or mixed, given detection scope)."
                    .into(),
            );
        }

        if !process_sets.is_empty() {
            let multi_process = process_sets.len() > 1;
            let mut all = Vec::<MachineProfile>::new();
            for d in &process_sets {
                let mut profiles =
                    load_process_profiles_sqlite_first(&self.sql_path, d, &config)?;
                if multi_process {
                    for p in &mut profiles {
                        p.id = namespace_run_machine_id(&d.id, &p.id, true);
                    }
                }
                all.extend(profiles);
            }
            let merged = merge_process_profiles(&all);
            if run_fleet {
                let report = analyze_fleet(&merged, &config)?;
                let process_dataset_ids: Vec<String> =
                    process_sets.iter().map(|d| d.id.clone()).collect();
                let edb_examples = EventDb::new(&self.sql_path)?;
                for an in report.anomalies {
                    let sev_score = match an.severity {
                        AnomalyLevel::Critical => 1.0,
                        AnomalyLevel::High => 0.75,
                        AnomalyLevel::Medium => 0.5,
                        AnomalyLevel::Low => 0.25,
                    };
                    let e = finding_by_host
                        .entry(an.machine_id.clone())
                        .or_insert_with(|| DetectionFinding {
                            machine_id: an.machine_id.clone(),
                            severity: "LOW".to_string(),
                            score: 0.0,
                            reasons: Vec::new(),
                            detectors: Vec::new(),
                            dataset_tags: Vec::new(),
                            reasons_by_detector: Vec::new(),
                            sigma_matches: Vec::new(),
                        });
                    e.score = e.score.max(sev_score);
                    Self::extend_detector_reasons(e, "ironsift-process", an.anomalous_features);
                    e.detectors.push("ironsift-process".to_string());

                    if let Some(profile) = merged.iter().find(|p| p.id == an.machine_id) {
                        let (lookup_datasets, logical_machine) = if multi_process {
                            split_namespaced_machine_id(&an.machine_id)
                                .map(|(ds, host)| (vec![ds], host))
                                .unwrap_or_else(|| {
                                    (process_dataset_ids.clone(), an.machine_id.clone())
                                })
                        } else {
                            (process_dataset_ids.clone(), an.machine_id.clone())
                        };
                        let mut examples_added = 0usize;
                        let mut risky: Vec<(&ProcessSignature, u32)> = profile
                            .counts
                            .iter()
                            .filter(|(sig, _)| {
                                let common =
                                    config.common_root_processes.iter().any(|p| sig.name.contains(p));
                                let behavioral = sig.is_high_entropy || sig.is_suspicious_path;
                                let unexpected_root = sig.uid == 0 && !common;
                                behavioral || unexpected_root
                            })
                            .map(|(s, c)| (s, *c))
                            .collect();
                        risky.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.name.cmp(&b.0.name)));
                        for (sig, _count) in risky {
                            if examples_added >= PROCESS_RISK_EXAMPLES_PER_HOST {
                                break;
                            }
                            match edb_examples.find_process_row_example(
                                &lookup_datasets,
                                &logical_machine,
                                sig.name.as_ref(),
                                sig.path.as_ref(),
                            ) {
                                Ok(Some(row)) => {
                                    Self::push_detector_reason(
                                        e,
                                        "ironsift-process",
                                        format!(
                                            "Process row: dataset={} machine_id={} pid={} parent={} uid={} name={} path={} cmdline={} start_time={}",
                                            row.dataset_id,
                                            row.machine_id,
                                            row.pid,
                                            row.parent,
                                            row.uid,
                                            row.name,
                                            row.path,
                                            truncate_for_reason(&row.cmdline),
                                            row.start_time
                                                .map(|s| s.to_string())
                                                .unwrap_or_else(|| "(none)".to_string()),
                                        ),
                                    );
                                    examples_added += 1;
                                }
                                Ok(None) => {}
                                Err(err) => {
                                    log::debug!(
                                        "process row lookup failed (dataset={:?}, machine={}, name={}, path={}): {}",
                                        lookup_datasets,
                                        logical_machine,
                                        sig.name,
                                        sig.path,
                                        err
                                    );
                                }
                            }
                        }
                    }
                }
            }
            if run_anomark {
                if let Some(amo) = self.resolve_anomark_settings_for_run(&req) {
                    let an_scores = score_with_anomark(
                        &self.sql_path,
                        &process_sets,
                        &amo,
                        multi_process,
                        anomark_suspect_percent,
                    )?;
                    for (host, host_score) in an_scores {
                        let ratio = finite_f64(host_score.ratio);
                        if host_score.suspects.is_empty() && ratio <= 0.0 {
                            continue;
                        }
                        let e = finding_by_host.entry(host.clone()).or_insert_with(|| DetectionFinding {
                            machine_id: host,
                            severity: "LOW".to_string(),
                            score: 0.0,
                            reasons: Vec::new(),
                            detectors: Vec::new(),
                            dataset_tags: Vec::new(),
                            reasons_by_detector: Vec::new(),
                            sigma_matches: Vec::new(),
                        });
                        e.score = e
                            .score
                            .max(finite_f64((e.score * 0.7) + (ratio * 0.3)));
                        Self::push_detector_reason(
                            e,
                            "anomark-rs",
                            format!(
                                "AnoMark suspicious command ratio {:.2} (suspect {:.1}%)",
                                ratio, anomark_suspect_percent
                            ),
                        );
                        for ex in &host_score.suspects {
                            Self::push_detector_reason(
                                e,
                                "anomark-rs",
                                format!(
                                    "AnoMark suspect: {} (ll={:.2}, margin={:.2})",
                                    truncate_for_reason(&ex.command),
                                    ex.log_likelihood,
                                    ex.margin_ln
                                ),
                            );
                        }
                        e.detectors.push("anomark-rs".to_string());
                    }
                } else if matches!(req.detector_mode, RunDetectorMode::AnomarkOnly) {
                    return Err(
                        "AnoMark-only run requires a readable model (configure AnoMark in settings or choose a saved training)."
                            .into(),
                    );
                } else {
                    log::warn!(
                        "AnoMark was enabled for this run but skipped: no readable model file (configure AnoMark in settings or pick a valid saved training)"
                    );
                }
            }
        }

        if !file_sets.is_empty() && run_fleet {
            let multi_file = file_sets.len() > 1;
            let run_file_dataset_ids: Vec<String> = file_sets
                .iter()
                .map(|d| d.id.clone())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();
            let mut all = Vec::<MachineFileProfile>::new();
            for d in &file_sets {
                let mut profiles = load_file_profiles_sqlite_first(
                    &self.sql_path,
                    d,
                    &config,
                    &run_file_dataset_ids,
                )?;
                if multi_file {
                    for p in &mut profiles {
                        p.id = namespace_run_machine_id(&d.id, &p.id, true);
                    }
                }
                all.extend(profiles);
            }
            let merged = merge_file_profiles(&all);
            let report = analyze_files_fleet(&merged, &config)?;
            for an in report.anomalies {
                let sev_score = match an.severity {
                    AnomalyLevel::Critical => 1.0,
                    AnomalyLevel::High => 0.75,
                    AnomalyLevel::Medium => 0.5,
                    AnomalyLevel::Low => 0.25,
                };
                let e = finding_by_host
                    .entry(an.machine_id.clone())
                    .or_insert_with(|| DetectionFinding {
                        machine_id: an.machine_id.clone(),
                        severity: "LOW".to_string(),
                        score: 0.0,
                        reasons: Vec::new(),
                        detectors: Vec::new(),
                        dataset_tags: Vec::new(),
                        reasons_by_detector: Vec::new(),
                        sigma_matches: Vec::new(),
                    });
                e.score = e.score.max(sev_score);
                Self::extend_detector_reasons(e, "ironsift-file", an.anomalous_features);
                e.detectors.push("ironsift-file".to_string());
            }
        }

        // Sigma/sigmazero is not used in RustMite (rules live in rustmite-checks / RPL).
        let sigma_stable_stats: Option<DetectionRunSigmaStats> = None;
        let _ = req.enable_sigma_stable;

        let mut findings: Vec<_> = finding_by_host
            .into_values()
            .map(|mut f| {
                f.score = finite_f64(f.score);
                f.severity = severity_from_score(f.score).to_string();
                f.reasons.sort();
                f.reasons.dedup();
                f.detectors.sort();
                f.detectors.dedup();
                // Within each per-detector bucket, dedup while preserving insertion order so
                // high-level summaries stay above details (e.g. AnoMark ratio before suspects).
                for bucket in f.reasons_by_detector.iter_mut() {
                    let mut seen: HashSet<String> = HashSet::new();
                    bucket.reasons.retain(|r| seen.insert(r.clone()));
                }
                // Stable canonical order across buckets so the UI groups appear consistently.
                fn detector_rank(d: &str) -> u8 {
                    match d {
                        "ironsift-process" => 0,
                        "anomark-rs" => 1,
                        "sigma-zero" => 2,
                        "ironsift-file" => 3,
                        _ => 4,
                    }
                }
                f.reasons_by_detector.sort_by(|a, b| {
                    detector_rank(&a.detector)
                        .cmp(&detector_rank(&b.detector))
                        .then_with(|| a.detector.cmp(&b.detector))
                });
                f
            })
            .collect();
        let selected_ids: Vec<String> = datasets.iter().map(|d| d.id.clone()).collect();
        for f in &mut findings {
            f.dataset_tags = resolve_machine_dataset_tags_for_run(
                &f.machine_id,
                &selected_ids,
                req.detection_focus,
                &datasets,
            );
        }
        findings.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        let request = DetectionRunRequestSnapshot {
            dataset_ids: selected_ids.clone(),
            baseline_tags: req.baseline_tags.clone(),
            candidate_tags: req.candidate_tags.clone(),
            enable_anomark: req.enable_anomark,
            anomark_train_id: req.anomark_train_id.clone(),
            anomark_suspect_percent,
            detection_config_id: dc_id.clone(),
            detection_focus: req.detection_focus,
            detector_mode: req.detector_mode,
            enable_sigma_stable: req.enable_sigma_stable,
        };
        let mut rec = DetectionRunRecord {
            id: Uuid::new_v4().to_string(),
            created_at: Utc::now().to_rfc3339(),
            dataset_ids: selected_ids,
            baseline_tags: req.baseline_tags,
            candidate_tags: req.candidate_tags,
            baseline_finding_count: 0,
            candidate_finding_count: findings.len(),
            summary: format!("{} findings", findings.len()),
            findings,
            detection_config_id: dc_id,
            detection_config_name: dc_name,
            detection_focus: req.detection_focus,
            detector_mode: req.detector_mode,
            anomark_suspect_percent,
            request,
            user_triage: RunUserTriage::default(),
            triage_precedent_ignore: vec![],
            sigma_stable_stats,
        };
        let fleet_drops = self.fleet_precedent_drop_set_snapshot();
        let (runs_sorted, persistent) = {
            let db = self.db.read();
            let mut v = db.runs.clone();
            v.sort_by(|a, b| b.created_at.cmp(&a.created_at));
            (v, db.fleet_triage_precedent_entries.clone())
        };
        let history = build_reason_verdict_history_from_runs(
            &runs_sorted,
            &rec.id,
            &fleet_drops,
            &persistent,
        );
        let ignore = precedent_ignore_set(&rec);
        let (merged, _) = merge_history_into_user_triage(
            &rec.findings,
            &rec.user_triage,
            &history,
            &ignore,
        );
        rec.user_triage = merged;
        let mut db = self.db.write();
        db.runs.push(rec.clone());
        upsert_fleet_precedents_from_run(&mut db.fleet_triage_precedent_entries, &rec);
        drop(db);
        self.save()?;
        Ok(rec)
    }

    pub fn honeycomb_for_run(&self, run_id: &str) -> Option<Vec<HoneycombCell>> {
        self.honeycomb_for_run_filtered(run_id, None, None)
    }

    /// One cell per host in the run: every machine seen in ingested datasets (SQLite) **plus** any
    /// host in findings. Clean machines are green; infected use score/severity from the run.
    /// Filter query params do not drop cells; they set [`HoneycombCell::matches_filter`].
    pub fn honeycomb_for_run_filtered(
        &self,
        run_id: &str,
        min_score: Option<f64>,
        severity: Option<&str>,
    ) -> Option<Vec<HoneycombCell>> {
        if let Err(e) = self.sync_run_triage_from_history(run_id) {
            log::warn!(
                "sync_run_triage_from_history failed before honeycomb (run {}): {}",
                run_id,
                e
            );
        }
        let r = self.get_run(run_id)?;
        let from_db: Vec<String> = EventDb::new(&self.sql_path)
            .and_then(|db| db.distinct_machine_ids_for_datasets(&r.dataset_ids))
            .unwrap_or_default();
        let mut ids: BTreeSet<String> = from_db.into_iter().collect();
        for f in &r.findings {
            ids.insert(f.machine_id.clone());
        }
        let mut all: Vec<String> = ids.into_iter().collect();
        all.sort();

        let by_machine: HashMap<String, &DetectionFinding> = r
            .findings
            .iter()
            .map(|f| (f.machine_id.clone(), f))
            .collect();

        let db = self.db.read();
        let datasets_slice = db.datasets.as_slice();

        let cells: Vec<HoneycombCell> = all
            .into_iter()
            .map(|name| {
                let dataset_tags = match by_machine.get(&name) {
                    Some(f) if !f.dataset_tags.is_empty() => f.dataset_tags.clone(),
                    Some(_) | None => resolve_machine_dataset_tags_for_run(
                        &name,
                        &r.dataset_ids,
                        r.detection_focus,
                        datasets_slice,
                    ),
                };
                if let Some(f) = by_machine.get(&name) {
                    let (eff_score, eff_sev) = effective_score_and_severity(f, &r.user_triage);
                    let matches_filter =
                        finding_passes_scores(eff_score, &eff_sev, min_score, severity);
                    HoneycombCell {
                        name,
                        value: eff_score,
                        severity: eff_sev,
                        infected: true,
                        matches_filter,
                        reasons: f.reasons.clone(),
                        detectors: f.detectors.clone(),
                        dataset_tags,
                    }
                } else {
                    HoneycombCell {
                        name,
                        value: 0.0,
                        severity: "CLEAN".to_string(),
                        infected: false,
                        matches_filter: true,
                        reasons: vec![],
                        detectors: vec![],
                        dataset_tags,
                    }
                }
            })
            .collect();
        Some(cells)
    }

    fn selected_datasets(&self, req: &CreateRunRequest) -> Result<Vec<DatasetRecord>, Box<dyn Error>> {
        let db = self.db.read();
        if db.datasets.is_empty() {
            return Err(
                "no datasets: import on Ingestion first, or check .ironsift-platform/db.json."
                    .into(),
            );
        }
        let mut selected: Vec<DatasetRecord> = db.datasets.clone();
        if !req.dataset_ids.is_empty() {
            selected.retain(|d| req.dataset_ids.iter().any(|id| id == &d.id));
        }
        let mut tag_filter: Vec<String> = req.baseline_tags.clone();
        tag_filter.extend(req.candidate_tags.clone());
        if !tag_filter.is_empty() {
            selected.retain(|d| d.tags.iter().any(|t| tag_filter.contains(t)));
        }
        if selected.is_empty() {
            return Err(
                "no datasets match the request: check dataset id(s) (comma field + checkboxes), and tags in baseline or candidate fields; tags must match dataset tags exactly."
                    .into(),
            );
        }
        Ok(selected)
    }
}

/// JSON and many JSON serializers reject NaN/±∞; keep scores in-range for the API and `db.json`.
fn finite_f64(x: f64) -> f64 {
    if x.is_finite() { x } else { 0.0 }
}

fn severity_from_score(score: f64) -> &'static str {
    let score = finite_f64(score);
    if score >= 0.9 {
        "CRITICAL"
    } else if score >= 0.7 {
        "HIGH"
    } else if score >= 0.4 {
        "MEDIUM"
    } else {
        "LOW"
    }
}

/// Same prefix rules as the findings UI (`classifyLegacyReason`) when `reasons_by_detector` is empty.
fn classify_legacy_reason_line(reason: &str) -> &'static str {
    let s = reason.trim_start();
    if s.starts_with("Sigma match:") {
        return "sigma-zero";
    }
    if s.starts_with("AnoMark suspect:")
        || s.starts_with("AnoMark suspicious command ratio")
    {
        return "anomark-rs";
    }
    if s.starts_with("RISK DETECTED:")
        || s.starts_with("Process row:")
        || s.starts_with("Rare process:")
    {
        return "ironsift-process";
    }
    if s.starts_with("Rare file access:")
        || s.starts_with("MTIME ANOMALY")
        || s.starts_with("METADATA ANOMALY")
        || s.starts_with("FLEET OUTLIER")
        || s.starts_with("(+")
        || s.contains("more rare files matched")
    {
        return "ironsift-file";
    }
    "other"
}

/// `(detector, reason)` rows in UI order for triage and history lookup.
fn finding_detector_reason_pairs(f: &DetectionFinding) -> Vec<(String, String)> {
    let mut out = Vec::new();
    const GROUP_ORDER: &[&str] = &["ironsift-process", "anomark-rs", "sigma-zero", "ironsift-file", "other"];
    if !f.reasons_by_detector.is_empty() {
        let mut by_det: HashMap<String, Vec<String>> = HashMap::new();
        for b in &f.reasons_by_detector {
            if b.reasons.is_empty() {
                continue;
            }
            by_det
                .entry(b.detector.clone())
                .or_default()
                .extend(b.reasons.iter().cloned());
        }
        for det in GROUP_ORDER {
            if let Some(list) = by_det.remove(*det) {
                for reason in list {
                    out.push(((*det).to_string(), reason));
                }
            }
        }
        let mut rest: Vec<_> = by_det.into_iter().collect();
        rest.sort_by(|a, b| a.0.cmp(&b.0));
        for (det, list) in rest {
            for reason in list {
                out.push((det.clone(), reason));
            }
        }
    } else {
        for reason in &f.reasons {
            let det = classify_legacy_reason_line(reason).to_string();
            out.push((det, reason.clone()));
        }
    }
    out
}

/// Primary process `name=` token for grouping related `ironsift-process` lines (RISK, Rare process,
/// Process row) into one triage decision in the UI and for effective severity.
fn extract_ironsift_process_primary_name(reason: &str) -> Option<String> {
    let s = reason.trim_start();
    if s.starts_with("RISK DETECTED:") {
        let after = s["RISK DETECTED:".len()..].trim_start();
        for tok in after.split_whitespace() {
            if let Some(v) = tok.strip_prefix("name=") {
                let v = v.trim_end_matches(',').trim();
                if !v.is_empty() {
                    return Some(v.to_ascii_lowercase());
                }
            }
        }
        return None;
    }
    if s.starts_with("Rare process:") {
        let rest = s["Rare process:".len()..].trim();
        let name = rest
            .split(|c: char| c == ' ' || c == '(' || c == '\t')
            .next()
            .unwrap_or("")
            .trim();
        return if name.is_empty() {
            None
        } else {
            Some(name.to_ascii_lowercase())
        };
    }
    if s.starts_with("Process row:") {
        for tok in s.split_whitespace() {
            if let Some(v) = tok.strip_prefix("name=") {
                let v = v.trim_end_matches(',').trim();
                if !v.is_empty() {
                    return Some(v.to_ascii_lowercase());
                }
            }
        }
    }
    None
}

/// Stable key: same for all `ironsift-process` lines that describe the same primary process name.
fn triage_group_key(detector: &str, reason: &str) -> String {
    if detector == "ironsift-process" {
        if let Some(n) = extract_ironsift_process_primary_name(reason) {
            return format!("ironsift-process::g::{n}");
        }
    }
    format!("{detector}::{reason}")
}

fn aggregate_verdicts_for_group(vers: &[TriageVerdict]) -> TriageVerdict {
    if vers.is_empty() {
        return TriageVerdict::Unset;
    }
    if vers
        .iter()
        .any(|v| matches!(v, TriageVerdict::Malicious))
    {
        return TriageVerdict::Malicious;
    }
    if vers.iter().any(|v| matches!(v, TriageVerdict::Unset)) {
        return TriageVerdict::Unset;
    }
    TriageVerdict::FalsePositive
}

fn upsert_reason_verdict(m: &mut MachineTriageEntry, detector: &str, reason: &str, verdict: TriageVerdict) {
    if let Some(rd) = m
        .reason_decisions
        .iter_mut()
        .find(|e| e.detector == detector && e.reason == reason)
    {
        rd.verdict = verdict;
        if matches!(verdict, TriageVerdict::Unset) {
            rd.reviewed_at = None;
        }
    } else {
        m.reason_decisions.push(ReasonTriageEntry {
            detector: detector.to_string(),
            reason: reason.to_string(),
            verdict,
            reviewed_at: None,
        });
    }
}

/// Unique actionable `(detector, triage_group_key)` pairs for a finding (Process row excluded).
fn actionable_triage_group_slots(f: &DetectionFinding) -> Vec<(String, String)> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for (det, reason) in finding_detector_reason_pairs(f) {
        if reason_excluded_from_per_reason_triage(&reason) {
            continue;
        }
        let gk = triage_group_key(&det, &reason);
        let slot = (det.clone(), gk.clone());
        if seen.insert(slot.clone()) {
            out.push(slot);
        }
    }
    out
}

fn history_verdict_for_line_or_process_group(
    detector: &str,
    reason: &str,
    history: &HashMap<(String, String), TriageVerdict>,
) -> Option<TriageVerdict> {
    if let Some(v) = history.get(&(detector.to_string(), reason.to_string())) {
        return Some(*v);
    }
    if detector != "ironsift-process" {
        return None;
    }
    let gk = triage_group_key(detector, reason);
    let mut collected = Vec::new();
    for ((d, r), v) in history {
        if d != detector {
            continue;
        }
        if triage_group_key(d, r) == gk {
            collected.push(*v);
        }
    }
    if collected.is_empty() {
        None
    } else {
        Some(aggregate_verdicts_for_group(&collected))
    }
}

/// Unify per-line verdicts within each triage group, then set `final_verdict` when exactly one
/// actionable group exists on the host.
fn normalize_triage_groups_and_auto_final_for_run(rec: &mut DetectionRunRecord) -> bool {
    let mut changed = false;
    for f in &rec.findings {
        let mid = f.machine_id.clone();
        let mut buckets: HashMap<(String, String), Vec<String>> = HashMap::new();
        for (det, reason) in finding_detector_reason_pairs(f) {
            if reason_excluded_from_per_reason_triage(&reason) {
                continue;
            }
            let gk = triage_group_key(&det, &reason);
            buckets
                .entry((det.clone(), gk))
                .or_default()
                .push(reason.clone());
        }
        for ((det, _gk), reasons) in buckets {
            let vers: Vec<TriageVerdict> = reasons
                .iter()
                .map(|r| verdict_for_reason_on_machine(&rec.user_triage, &mid, &det, r))
                .collect();
            let agg = aggregate_verdicts_for_group(&vers);
            for r in &reasons {
                let cur = verdict_for_reason_on_machine(&rec.user_triage, &mid, &det, r);
                if cur != agg {
                    changed = true;
                }
            }
            if let Some(m) = rec
                .user_triage
                .machines
                .iter_mut()
                .find(|x| x.machine_id == mid)
            {
                for r in &reasons {
                    upsert_reason_verdict(m, &det, r, agg);
                }
            }
        }
    }
    for f in &rec.findings {
        let mid = f.machine_id.as_str();
        let slots = actionable_triage_group_slots(f);
        if slots.len() != 1 {
            continue;
        }
        let (det, gk) = &slots[0];
        let reasons: Vec<String> = finding_detector_reason_pairs(f)
            .into_iter()
            .filter(|(_, r)| !reason_excluded_from_per_reason_triage(r))
            .filter(|(d, r)| d == det && triage_group_key(d, r) == *gk)
            .map(|(_, r)| r)
            .collect();
        if reasons.is_empty() {
            continue;
        }
        let vers: Vec<TriageVerdict> = reasons
            .iter()
            .map(|r| verdict_for_reason_on_machine(&rec.user_triage, mid, det, r))
            .collect();
        let agg = aggregate_verdicts_for_group(&vers);
        if let Some(m) = rec
            .user_triage
            .machines
            .iter_mut()
            .find(|x| x.machine_id.as_str() == mid)
        {
            if m.final_verdict != agg {
                m.final_verdict = agg;
                changed = true;
            }
        }
    }
    changed
}

fn fleet_precedent_entry_to_historical(e: &FleetTriagePrecedentEntry) -> HistoricalReasonVerdict {
    HistoricalReasonVerdict {
        detector: e.detector.clone(),
        reason: e.reason.clone(),
        verdict: e.verdict,
        source_run_id: e.source_run_id.clone(),
        source_run_created_at: e.source_run_created_at.clone(),
        source_machine_id: e.source_machine_id.clone(),
        source_reviewed_at: e.source_reviewed_at.clone(),
    }
}

/// Overwrites existing keys: **newest runs first** in the slice should be passed so the first
/// contributing run wins (same as legacy `or_insert` scan order).
fn merge_run_precedents_into_provenance_map(
    map: &mut HashMap<(String, String), HistoricalReasonVerdict>,
    runs_newest_first: &[DetectionRunRecord],
    exclude_run_id: Option<&str>,
    fleet_drops: &HashSet<(String, String)>,
) {
    for run in runs_newest_first {
        if exclude_run_id == Some(run.id.as_str()) {
            continue;
        }
        for m in &run.user_triage.machines {
            for e in &m.reason_decisions {
                if matches!(e.verdict, TriageVerdict::Unset) {
                    continue;
                }
                if reason_excluded_from_per_reason_triage(&e.reason) {
                    continue;
                }
                let key = (e.detector.clone(), e.reason.clone());
                if fleet_drops.contains(&key) {
                    continue;
                }
                map.entry(key).or_insert_with(|| HistoricalReasonVerdict {
                    detector: e.detector.clone(),
                    reason: e.reason.clone(),
                    verdict: e.verdict,
                    source_run_id: run.id.clone(),
                    source_run_created_at: run.created_at.clone(),
                    source_machine_id: m.machine_id.clone(),
                    source_reviewed_at: e.reviewed_at.clone(),
                });
            }
        }
    }
}

/// Latest non-unset verdict per `(detector, reason)` from **runs only** (newest contributing run wins).
#[cfg(test)]
fn build_reason_verdict_provenance_from_runs(
    runs_newest_first: &[DetectionRunRecord],
    exclude_run_id: Option<&str>,
    fleet_drops: &HashSet<(String, String)>,
) -> HashMap<(String, String), HistoricalReasonVerdict> {
    let mut map = HashMap::new();
    merge_run_precedents_into_provenance_map(&mut map, runs_newest_first, exclude_run_id, fleet_drops);
    map
}

/// Persisted fleet memory plus other runs; **runs override** the store for the same `(detector, reason)`.
fn build_reason_verdict_provenance_combined(
    runs_newest_first: &[DetectionRunRecord],
    exclude_run_id: Option<&str>,
    fleet_drops: &HashSet<(String, String)>,
    persistent: &[FleetTriagePrecedentEntry],
) -> HashMap<(String, String), HistoricalReasonVerdict> {
    let mut run_map = HashMap::new();
    merge_run_precedents_into_provenance_map(
        &mut run_map,
        runs_newest_first,
        exclude_run_id,
        fleet_drops,
    );
    let mut out = HashMap::new();
    for e in persistent {
        if fleet_drops.contains(&(e.detector.clone(), e.reason.clone())) {
            continue;
        }
        if reason_excluded_from_per_reason_triage(&e.reason) {
            continue;
        }
        if matches!(e.verdict, TriageVerdict::Unset) {
            continue;
        }
        out.insert(
            (e.detector.clone(), e.reason.clone()),
            fleet_precedent_entry_to_historical(e),
        );
    }
    for (k, v) in run_map {
        out.insert(k, v);
    }
    out
}

/// Verdict map for merging into a run: persisted fleet memory plus other runs (runs override store).
fn build_reason_verdict_history_from_runs(
    runs_newest_first: &[DetectionRunRecord],
    exclude_run_id: &str,
    fleet_drops: &HashSet<(String, String)>,
    persistent: &[FleetTriagePrecedentEntry],
) -> HashMap<(String, String), TriageVerdict> {
    build_reason_verdict_provenance_combined(
        runs_newest_first,
        Some(exclude_run_id),
        fleet_drops,
        persistent,
    )
    .into_iter()
    .map(|(k, v)| (k, v.verdict))
    .collect()
}

fn upsert_fleet_precedents_from_run(entries: &mut Vec<FleetTriagePrecedentEntry>, run: &DetectionRunRecord) {
    let now = Utc::now().to_rfc3339();
    for m in &run.user_triage.machines {
        for e in &m.reason_decisions {
            if matches!(e.verdict, TriageVerdict::Unset) {
                continue;
            }
            if reason_excluded_from_per_reason_triage(&e.reason) {
                continue;
            }
            let det = e.detector.trim();
            if det.is_empty() {
                continue;
            }
            let reason = e.reason.clone();
            if let Some(existing) = entries
                .iter_mut()
                .find(|x| x.detector == det && x.reason == reason)
            {
                existing.verdict = e.verdict;
                existing.source_reviewed_at = e.reviewed_at.clone();
                existing.source_run_id = run.id.clone();
                existing.source_run_created_at = run.created_at.clone();
                existing.source_machine_id = m.machine_id.clone();
                existing.updated_at = now.clone();
            } else {
                entries.push(FleetTriagePrecedentEntry {
                    detector: det.to_string(),
                    reason,
                    verdict: e.verdict,
                    source_reviewed_at: e.reviewed_at.clone(),
                    source_run_id: run.id.clone(),
                    source_run_created_at: run.created_at.clone(),
                    source_machine_id: m.machine_id.clone(),
                    updated_at: now.clone(),
                });
            }
        }
    }
}

fn seed_fleet_triage_precedents_from_runs_if_empty(db: &mut PlatformDb) -> bool {
    if !db.fleet_triage_precedent_entries.is_empty() {
        return false;
    }
    if db.runs.is_empty() {
        return false;
    }
    let drops: HashSet<(String, String)> = db
        .fleet_triage_precedent_drops
        .iter()
        .map(|k| (k.detector.clone(), k.reason.clone()))
        .collect();
    let mut runs = db.runs.clone();
    runs.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    let now = Utc::now().to_rfc3339();
    let mut map: HashMap<(String, String), HistoricalReasonVerdict> = HashMap::new();
    merge_run_precedents_into_provenance_map(&mut map, &runs, None, &drops);
    if map.is_empty() {
        return false;
    }
    db.fleet_triage_precedent_entries = map
        .into_values()
        .map(|h| FleetTriagePrecedentEntry {
            detector: h.detector,
            reason: h.reason,
            verdict: h.verdict,
            source_reviewed_at: h.source_reviewed_at,
            source_run_id: h.source_run_id,
            source_run_created_at: h.source_run_created_at,
            source_machine_id: h.source_machine_id,
            updated_at: now.clone(),
        })
        .collect();
    true
}

fn reason_keys_in_findings(findings: &[DetectionFinding]) -> HashSet<(String, String)> {
    let mut keys = HashSet::new();
    for f in findings {
        for (det, reason) in finding_detector_reason_pairs(f) {
            if reason_excluded_from_per_reason_triage(&reason) {
                continue;
            }
            keys.insert((det, reason));
        }
    }
    keys
}

fn precedent_ignore_set(rec: &DetectionRunRecord) -> HashSet<(String, String)> {
    rec.triage_precedent_ignore
        .iter()
        .map(|k| (k.detector.clone(), k.reason.clone()))
        .collect()
}

fn strip_reason_decisions_for_key(triage: &mut RunUserTriage, detector: &str, reason: &str) {
    for m in &mut triage.machines {
        m.reason_decisions
            .retain(|e| !(e.detector == detector && e.reason == reason));
    }
}

/// `(detector, reason)` pairs with a non-[`TriageVerdict::Unset`] verdict in this triage snapshot.
/// Used to clear matching [`PlatformDb::fleet_triage_precedent_drops`] when an analyst explicitly
/// saves triage again after removing a pair from fleet memory.
fn non_unset_triage_reason_keys(triage: &RunUserTriage) -> HashSet<(String, String)> {
    let mut keys = HashSet::new();
    for m in &triage.machines {
        for e in &m.reason_decisions {
            if matches!(e.verdict, TriageVerdict::Unset) {
                continue;
            }
            if reason_excluded_from_per_reason_triage(&e.reason) {
                continue;
            }
            keys.insert((e.detector.clone(), e.reason.clone()));
        }
    }
    keys
}

/// Set `reviewed_at` when an analyst changes a per-reason verdict; preserve prior timestamps when unchanged.
fn stamp_reason_review_times_on_triage_put(old: &RunUserTriage, incoming: &mut RunUserTriage) {
    let now = Utc::now().to_rfc3339();
    for m in &mut incoming.machines {
        let old_m = old.machines.iter().find(|x| x.machine_id == m.machine_id);
        for e in &mut m.reason_decisions {
            if matches!(e.verdict, TriageVerdict::Unset) {
                e.reviewed_at = None;
                continue;
            }
            let old_e = old_m.and_then(|om| {
                om.reason_decisions
                    .iter()
                    .find(|r| r.detector == e.detector && r.reason == e.reason)
            });
            let unchanged = old_e.map(|o| o.verdict == e.verdict).unwrap_or(false);
            e.reviewed_at = if unchanged {
                old_e.and_then(|o| o.reviewed_at.clone())
            } else {
                Some(now.clone())
            };
        }
    }
}

/// After group normalization, use one timestamp per triage group (latest RFC 3339) when any line was reviewed.
fn align_reviewed_at_for_normalized_reason_groups(rec: &mut DetectionRunRecord) {
    for f in &rec.findings {
        let mid = f.machine_id.clone();
        let Some(m_entry) = rec
            .user_triage
            .machines
            .iter_mut()
            .find(|x| x.machine_id == mid)
        else {
            continue;
        };
        let mut buckets: HashMap<(String, String), Vec<usize>> = HashMap::new();
        for (i, e) in m_entry.reason_decisions.iter().enumerate() {
            if reason_excluded_from_per_reason_triage(&e.reason) {
                continue;
            }
            if matches!(e.verdict, TriageVerdict::Unset) {
                continue;
            }
            let gk = triage_group_key(&e.detector, &e.reason);
            buckets
                .entry((e.detector.clone(), gk))
                .or_default()
                .push(i);
        }
        for indices in buckets.into_values() {
            let mut best: Option<String> = None;
            for &i in &indices {
                if let Some(ref t) = m_entry.reason_decisions[i].reviewed_at {
                    best = Some(match &best {
                        None => t.clone(),
                        Some(b) if t > b => t.clone(),
                        Some(b) => b.clone(),
                    });
                }
            }
            if let Some(unified) = best {
                for i in indices {
                    m_entry.reason_decisions[i].reviewed_at = Some(unified.clone());
                }
            }
        }
    }
}

/// Fills per-reason `Unset` slots from fleet-wide history. Never overwrites an analyst choice on this run.
fn merge_history_into_user_triage(
    findings: &[DetectionFinding],
    current: &RunUserTriage,
    history: &HashMap<(String, String), TriageVerdict>,
    precedent_ignore: &HashSet<(String, String)>,
) -> (RunUserTriage, bool) {
    let mut changed = false;
    let mut machines: HashMap<String, MachineTriageEntry> = HashMap::new();
    // Keep every machine row from the saved triage first. Previously we only overlaid `current`
    // onto hosts that appeared in `findings`, which dropped orphan rows (e.g. legacy data,
    // hand-edited db, or findings that no longer list every host that still has saved verdicts).
    // That made fleet-wide precedent appear to vanish after routine sync (e.g. post-ingest changes).
    for m in &current.machines {
        machines.insert(m.machine_id.clone(), m.clone());
    }
    for f in findings {
        machines
            .entry(f.machine_id.clone())
            .or_insert_with(|| MachineTriageEntry {
                machine_id: f.machine_id.clone(),
                reason_decisions: vec![],
                final_verdict: TriageVerdict::Unset,
            });
    }
    for f in findings {
        let entry = machines
            .get_mut(&f.machine_id)
            .expect("machine from findings");
        for (det, reason) in finding_detector_reason_pairs(f) {
            if reason_excluded_from_per_reason_triage(&reason) {
                continue;
            }
            let key = (det.clone(), reason.clone());
            if precedent_ignore.contains(&key) {
                continue;
            }
            let cur_v = entry
                .reason_decisions
                .iter()
                .find(|e| e.detector == det && e.reason == reason)
                .map(|e| e.verdict)
                .unwrap_or(TriageVerdict::Unset);
            if !matches!(cur_v, TriageVerdict::Unset) {
                continue;
            }
            let Some(hv) = history_verdict_for_line_or_process_group(&det, &reason, history) else {
                continue;
            };
            if let Some(rd) = entry
                .reason_decisions
                .iter_mut()
                .find(|e| e.detector == det && e.reason == reason)
            {
                rd.verdict = hv;
                rd.reviewed_at = None;
            } else {
                entry.reason_decisions.push(ReasonTriageEntry {
                    detector: det,
                    reason,
                    verdict: hv,
                    reviewed_at: None,
                });
            }
            changed = true;
        }
    }
    let mut list: Vec<_> = machines.into_values().collect();
    list.sort_by(|a, b| a.machine_id.cmp(&b.machine_id));
    (RunUserTriage { machines: list }, changed)
}

fn verdict_for_reason_on_machine(
    triage: &RunUserTriage,
    machine_id: &str,
    detector: &str,
    reason: &str,
) -> TriageVerdict {
    triage
        .machines
        .iter()
        .find(|m| m.machine_id == machine_id)
        .and_then(|m| {
            m.reason_decisions
                .iter()
                .find(|e| e.detector == detector && e.reason == reason)
        })
        .map(|e| e.verdict)
        .unwrap_or(TriageVerdict::Unset)
}

/// Uses the **stored** detector fusion score on the finding and per-reason triage: all actionable
/// groups marked false positive → score 0 / LOW; any malicious → keep the raw score; if **any** group
/// is still unset, keep the full raw score (analysts have not yet decided to downgrade other lines on
/// this host, so the detector severity must not be diluted by unrelated FP groups).
fn effective_score_and_severity(f: &DetectionFinding, triage: &RunUserTriage) -> (f64, String) {
    let raw = finite_f64(f.score);
    let slots = actionable_triage_group_slots(f);
    if slots.is_empty() {
        return (raw, f.severity.clone());
    }
    let mid = f.machine_id.as_str();
    let mut n_mal = 0usize;
    let mut n_fp = 0usize;
    for (det, gk) in &slots {
        let reasons: Vec<String> = finding_detector_reason_pairs(f)
            .into_iter()
            .filter(|(_, r)| !reason_excluded_from_per_reason_triage(r))
            .filter(|(d, r)| d == det && triage_group_key(d, r) == *gk)
            .map(|(_, r)| r)
            .collect();
        let vers: Vec<TriageVerdict> = reasons
            .iter()
            .map(|r| verdict_for_reason_on_machine(triage, mid, det, r))
            .collect();
        match aggregate_verdicts_for_group(&vers) {
            TriageVerdict::Malicious => n_mal += 1,
            TriageVerdict::FalsePositive => n_fp += 1,
            TriageVerdict::Unset => {}
        }
    }
    let n_act = slots.len();
    let new_score = if n_mal > 0 {
        raw
    } else if n_fp == n_act {
        0.0
    } else {
        raw
    };
    let sev = severity_from_score(new_score).to_string();
    (new_score, sev)
}

#[inline]
fn severity_bucket_for_sort(sev: &str) -> u8 {
    match sev.to_ascii_uppercase().as_str() {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        _ => 1,
    }
}

/// Order hosts for analyst review: highest **effective** risk first (score after triage), then
/// severity label, then stable machine id.
fn sort_findings_by_review_priority(findings: &mut [DetectionFinding]) {
    findings.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| {
                severity_bucket_for_sort(&b.severity).cmp(&severity_bucket_for_sort(&a.severity))
            })
            .then_with(|| a.machine_id.cmp(&b.machine_id))
    });
}

fn collect_jsonl_paths(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), Box<dyn Error>> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_jsonl_paths(&path, out)?;
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("jsonl"))
        {
            out.push(path);
        }
    }
    Ok(())
}

fn load_process_profiles(
    dataset: &DatasetRecord,
    cfg: &DetectionConfig,
) -> Result<Vec<MachineProfile>, Box<dyn Error>> {
    let mid = dataset.ingest_default_machine_id.as_deref();
    match dataset.format.as_str() {
        "jsonl" => load_jsonl_data(&dataset.source_path, cfg, mid),
        "json" => load_json_data(&dataset.source_path, cfg),
        "csv" => load_csv_data(&dataset.source_path, cfg),
        _ => Err(format!("unsupported process dataset format: {}", dataset.format).into()),
    }
}

/// Prefer ingested SQLite rows so test rows (Inspect → Append) are evaluated by detection runs;
/// fall back to the source file when SQLite has no rows for this dataset (e.g. ingest is stale).
fn load_process_profiles_sqlite_first(
    sql_path: &str,
    dataset: &DatasetRecord,
    cfg: &DetectionConfig,
) -> Result<Vec<MachineProfile>, Box<dyn Error>> {
    let edb = EventDb::new(sql_path)?;
    let entries = edb.process_entries_for_dataset(&dataset.id)?;
    if !entries.is_empty() {
        log::info!(
            "Run: loaded {} process rows from event_db for dataset {} (includes any test rows)",
            entries.len(),
            dataset.id
        );
        return Ok(build_profiles(entries, cfg));
    }
    log::info!(
        "Run: dataset {} has no SQLite process rows; falling back to source file {}",
        dataset.id,
        dataset.source_path
    );
    load_process_profiles(dataset, cfg)
}

fn detect_kind(path: &Path) -> Result<DatasetKind, Box<dyn Error>> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or_default();
    if ext == "csv" {
        let mut rdr = csv::Reader::from_path(path)?;
        let headers = rdr.headers()?.clone();
        let h = headers
            .iter()
            .map(|x| x.to_ascii_lowercase())
            .collect::<Vec<_>>();
        let has_pid = h.iter().any(|x| x == "pid");
        let has_name = h.iter().any(|x| x == "name");
        let has_args = h.iter().any(|x| x == "args");
        if has_pid || has_name || has_args {
            Ok(DatasetKind::Process)
        } else {
            Ok(DatasetKind::File)
        }
    } else if ext == "json" || ext == "jsonl" {
        match crate::json_parse::sniff_json_or_jsonl_dataset_kind(path) {
            Ok(crate::json_parse::JsonSniffDatasetKind::Process) => Ok(DatasetKind::Process),
            Ok(crate::json_parse::JsonSniffDatasetKind::File) => Ok(DatasetKind::File),
            Ok(crate::json_parse::JsonSniffDatasetKind::Mixed) => Ok(DatasetKind::Mixed),
            Err(e) => {
                log::warn!(
                    "could not sniff JSON/JSONL kind for {} ({}); falling back to filename heuristic",
                    path.display(),
                    e
                );
                let n = path
                    .file_name()
                    .and_then(|x| x.to_str())
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                Ok(if n.contains("file") {
                    DatasetKind::File
                } else {
                    DatasetKind::Process
                })
            }
        }
    } else {
        Err("unsupported format for auto detection".into())
    }
}

fn load_file_profiles(
    dataset: &DatasetRecord,
    cfg: &DetectionConfig,
) -> Result<Vec<MachineFileProfile>, Box<dyn Error>> {
    let mid = dataset.ingest_default_machine_id.as_deref();
    match dataset.format.as_str() {
        "jsonl" => load_files_jsonl_data(&dataset.source_path, cfg, mid),
        "json" => load_files_json_data(&dataset.source_path, cfg, mid),
        "csv" => load_files_csv_data(&dataset.source_path, cfg),
        _ => Err(format!("unsupported file dataset format: {}", dataset.format).into()),
    }
}

fn load_file_profiles_sqlite_first(
    sql_path: &str,
    dataset: &DatasetRecord,
    cfg: &DetectionConfig,
    run_file_dataset_ids: &[String],
) -> Result<Vec<MachineFileProfile>, Box<dyn Error>> {
    let edb = EventDb::new(sql_path)?;
    // Stream rows from SQLite directly into per-machine groups: with a 20 × 40k file fleet this
    // skips a 200+ MB intermediate `Vec<RawFileEntry>` that would otherwise stay alive while
    // the per-machine vectors were also being built.
    let grouped = edb.group_file_entries_by_machine_for_run(
        &dataset.id,
        run_file_dataset_ids,
        cfg.file_exclude_common_inventory_sql,
    )?;
    if !grouped.is_empty() {
        let machines_after_sql = grouped.len();
        let after_sql: usize = grouped.values().map(|v| v.len()).sum();
        let profiles = build_file_profiles_from_grouped(grouped, cfg);
        let ingested: usize = profiles.iter().map(|p| p.total_logs as usize).sum();
        if cfg.file_exclude_common_inventory_sql && !run_file_dataset_ids.is_empty() {
            let stored = edb.count_file_rows_for_dataset(&dataset.id)? as usize;
            log::info!(
                "Run: file dataset {} — {} row(s) in event_db, {} retained after inv_checksum exclusion (common across all {} file dataset(s) in this run, or universal across hosts when a single file dataset), {} ingested into profiles after path/filename filters (final rows used for detection); {} machine(s) after SQL filter, streamed by machine; includes test rows",
                dataset.id,
                stored,
                after_sql,
                run_file_dataset_ids.len(),
                ingested,
                machines_after_sql,
            );
        } else {
            log::info!(
                "Run: loaded {} file row(s) from event_db for dataset {} across {} machine(s), {} ingested into profiles after path/filename filters (final rows used for detection; streamed by machine; includes test rows)",
                after_sql,
                dataset.id,
                machines_after_sql,
                ingested,
            );
        }
        return Ok(profiles);
    }
    log::info!(
        "Run: dataset {} has no SQLite file rows; falling back to source file {}",
        dataset.id,
        dataset.source_path
    );
    load_file_profiles(dataset, cfg)
}

fn merge_process_profiles(input: &[MachineProfile]) -> Vec<MachineProfile> {
    let mut map: HashMap<String, MachineProfile> = HashMap::new();
    for p in input {
        let slot = map.entry(p.id.clone()).or_insert_with(|| MachineProfile::new(&p.id));
        slot.total_logs += p.total_logs;
        for (sig, count) in &p.counts {
            *slot.counts.entry(sig.clone()).or_insert(0) += *count;
        }
    }
    map.into_values().collect()
}

/// When multiple datasets are in one run, the same logical `machine_id` in two files must not be
/// merged—they are different collection windows. Prefix with `dataset_id/` so fleet analysis and
/// findings stay distinct (single-dataset runs keep plain host ids for stable UI labels).
fn namespace_run_machine_id(dataset_id: &str, logical_host: &str, multi_dataset: bool) -> String {
    if multi_dataset {
        format!("{}/{}", dataset_id, logical_host)
    } else {
        logical_host.to_string()
    }
}

/// Inverse of [`namespace_run_machine_id`] when `multi_dataset` was true: split the `dataset_id/host`
/// pair so callers can scope a SQLite lookup to that dataset. Returns `None` when there is no `/`.
fn split_namespaced_machine_id(namespaced: &str) -> Option<(String, String)> {
    namespaced
        .split_once('/')
        .map(|(ds, host)| (ds.to_string(), host.to_string()))
}

fn merge_file_profiles(input: &[MachineFileProfile]) -> Vec<MachineFileProfile> {
    let mut map: HashMap<String, MachineFileProfile> = HashMap::new();
    for p in input {
        let slot = map.entry(p.id.clone()).or_insert_with(|| MachineFileProfile::new(&p.id));
        slot.total_logs += p.total_logs;
        for (sig, count) in &p.counts {
            *slot.counts.entry(sig.clone()).or_insert(0) += *count;
        }
        for (path, mt) in &p.file_mtimes {
            slot.file_mtimes.insert(path.clone(), *mt);
        }
        for (k, v) in &p.file_path_owner {
            slot.file_path_owner.insert(k.clone(), v.clone());
        }
        for (k, v) in &p.file_path_group {
            slot.file_path_group.insert(k.clone(), v.clone());
        }
        for (k, v) in &p.file_path_size {
            slot.file_path_size.insert(k.clone(), *v);
        }
    }
    map.into_values().collect()
}

/// Max risky-process example rows surfaced per host in fleet findings (one row per signature).
const PROCESS_RISK_EXAMPLES_PER_HOST: usize = 5;

/// Max suspect command examples kept per host (ascending by `log_likelihood`, i.e. worst-first).
const ANOMARK_SUSPECT_EXAMPLES_PER_HOST: usize = 5;

/// Max characters of a suspect command preserved in finding reasons (longer cmdlines get truncated with `…`).
const ANOMARK_SUSPECT_EXAMPLE_MAX_CHARS: usize = 240;

#[derive(Debug, Clone)]
struct AnomarkSuspectExample {
    command: String,
    log_likelihood: f64,
    margin_ln: f64,
}

#[derive(Debug, Clone, Default)]
struct AnomarkHostScore {
    ratio: f64,
    /// Worst-first (lowest log_likelihood = most surprising); bounded by [`ANOMARK_SUSPECT_EXAMPLES_PER_HOST`].
    suspects: Vec<AnomarkSuspectExample>,
}

fn truncate_for_reason(s: &str) -> String {
    if s.chars().count() <= ANOMARK_SUSPECT_EXAMPLE_MAX_CHARS {
        return s.to_string();
    }
    let truncated: String = s.chars().take(ANOMARK_SUSPECT_EXAMPLE_MAX_CHARS).collect();
    format!("{}…", truncated)
}

fn score_with_anomark(
    sql_path: &str,
    process_datasets: &[DatasetRecord],
    settings: &AnoMarkSettings,
    namespace_by_dataset: bool,
    suspect_percent: f64,
) -> Result<HashMap<String, AnomarkHostScore>, Box<dyn Error>> {
    if settings.model_path.is_empty() {
        return Ok(HashMap::new());
    }
    let model_path = settings.model_path.as_str();
    let column = if settings.column.is_empty() {
        "cmdline"
    } else {
        settings.column.as_str()
    };
    let machine_field = if settings.machine_field.is_empty() {
        "machine_id"
    } else {
        settings.machine_field.as_str()
    };

    let mut model = ModelHandler::load_model(model_path).map_err(|e: anyhow::Error| e.to_string())?;
    if !model.is_trained() {
        model.normalize_model_and_compute_prior();
    }
    let pct = clamp_anomark_suspect_percent(suspect_percent);
    let threshold_ln = ModelHandler::compute_threshold(&model, pct);

    let mut totals: HashMap<String, (u32, u32)> = HashMap::new();
    let mut suspects_per_host: HashMap<String, Vec<AnomarkSuspectExample>> = HashMap::new();
    let edb = EventDb::new(sql_path)?;

    for ds in process_datasets {
        // Prefer ingested SQLite rows so test rows added via Inspect → Append are scored.
        // Fall back to the source file only when SQLite has no rows (e.g. ingest is stale).
        let sqlite_entries = edb.process_entries_for_dataset(&ds.id)?;
        let rows: Vec<AHashMap<String, String>> = if !sqlite_entries.is_empty() {
            sqlite_entries
                .iter()
                .map(raw_log_entry_to_anomark_row)
                .collect()
        } else {
            // `anomark::load_jsonl_with_columns` is for newline-delimited JSON, not a single JSON array file.
            // `json` process datasets are loaded elsewhere via `parse_json_logs` — match that here.
            match ds.format.as_str() {
                "json" => {
                    let content = fs::read_to_string(&ds.source_path)
                        .map_err(|e: std::io::Error| e.to_string())?;
                    let entries = parse_json_logs(&content).map_err(|e| e.to_string())?;
                    if entries.is_empty() {
                        log::warn!(
                            "AnoMark: no parseable process rows in json dataset at {}",
                            ds.source_path
                        );
                    }
                    entries.iter().map(raw_log_entry_to_anomark_row).collect()
                }
                "jsonl" => load_jsonl_with_columns(&ds.source_path)
                    .map_err(|e: anyhow::Error| e.to_string())?,
                "csv" => load_csv_with_columns(&ds.source_path)
                    .map_err(|e: anyhow::Error| e.to_string())?,
                _ => {
                    return Err(format!(
                        "unsupported dataset format for anomark scoring: {} (use csv, json, or jsonl)",
                        ds.format
                    )
                    .into())
                }
            }
        };
        for row in rows {
            let cmd = row_command_for_anomark(&row, column);
            let host_raw = row_machine_for_anomark(&row, machine_field);
            let host = namespace_run_machine_id(&ds.id, &host_raw, namespace_by_dataset);
            let scored = anomark_score_line(&host_raw, &cmd);
            if scored.is_empty() {
                continue;
            }
            let padded = format!("{}{}", "~".repeat(model.order), scored);
            let score = model.log_likelihood(&padded);
            let suspect = ModelHandler::is_suspect_command(score, threshold_ln);
            {
                let entry = totals.entry(host.clone()).or_insert((0, 0));
                entry.0 += 1;
                if suspect {
                    entry.1 += 1;
                }
            }
            if suspect && !cmd.trim().is_empty() {
                let bucket = suspects_per_host.entry(host).or_default();
                let example = AnomarkSuspectExample {
                    command: cmd,
                    log_likelihood: finite_f64(score),
                    margin_ln: finite_f64(score - threshold_ln),
                };
                if bucket.len() < ANOMARK_SUSPECT_EXAMPLES_PER_HOST {
                    bucket.push(example);
                    bucket.sort_by(|a, b| {
                        a.log_likelihood
                            .partial_cmp(&b.log_likelihood)
                            .unwrap_or(std::cmp::Ordering::Equal)
                    });
                } else if let Some(worst_kept) = bucket.last() {
                    // Keep the N most surprising commands (lowest log_likelihood = "most unusual").
                    if example.log_likelihood < worst_kept.log_likelihood {
                        bucket.pop();
                        bucket.push(example);
                        bucket.sort_by(|a, b| {
                            a.log_likelihood
                                .partial_cmp(&b.log_likelihood)
                                .unwrap_or(std::cmp::Ordering::Equal)
                        });
                    }
                }
            }
        }
    }

    let mut scores = HashMap::new();
    for (host, (all, suspect)) in totals {
        if all > 0 {
            let ratio = suspect as f64 / all as f64;
            let suspects = suspects_per_host.remove(&host).unwrap_or_default();
            scores.insert(host, AnomarkHostScore { ratio, suspects });
        }
    }
    Ok(scores)
}


/// Common command field names when the configured AnoMark column is empty (e.g. JSONL uses `command` vs `cmdline`).
const ANOMARK_CMD_FALLBACK_KEYS: &[&str] = &[
    "cmdline",
    "command",
    "cmd",
    "CommandLine",
    "command_line",
    "ProcessCommandLine",
    "Image",
];

/// Host / machine columns used when [`AnoMarkSettings::machine_field`] is missing on a row.
const ANOMARK_MACHINE_FALLBACK_KEYS: &[&str] = &[
    "machine_id",
    "hostname",
    "host_identifier",
    "host",
    "node",
];

/// Text scored by AnoMark: `"{machine} {cmd}"` when `machine_label` is non-empty (matches training snapshots).
fn anomark_score_line(machine_label: &str, cmd: &str) -> String {
    let m = machine_label.trim();
    let c = cmd.trim();
    if c.is_empty() {
        return String::new();
    }
    if m.is_empty() {
        return c.to_string();
    }
    format!("{} {}", m, c)
}

fn row_machine_for_anomark(row: &AHashMap<String, String>, primary: &str) -> String {
    let primary_lc = primary.to_ascii_lowercase();
    let mut h = row_key_lookup(row, primary);
    if !h.is_empty() {
        return h;
    }
    for key in ANOMARK_MACHINE_FALLBACK_KEYS {
        if key.to_ascii_lowercase() == primary_lc {
            continue;
        }
        h = row_key_lookup(row, key);
        if !h.is_empty() {
            return h;
        }
    }
    String::new()
}

fn row_command_for_anomark(row: &AHashMap<String, String>, primary: &str) -> String {
    let primary_lc = primary.to_ascii_lowercase();
    let mut cmd = row_key_lookup(row, primary);
    if !cmd.is_empty() {
        return cmd;
    }
    for key in ANOMARK_CMD_FALLBACK_KEYS {
        if key.to_ascii_lowercase() == primary_lc {
            continue;
        }
        cmd = row_key_lookup(row, key);
        if !cmd.is_empty() {
            return cmd;
        }
    }
    String::new()
}

/// Case-insensitive single-value lookup in a training row.
/// String rows for AnoMark, aligned with `parse_json_logs` / `load_json_data` (not line-oriented JSONL helpers).
fn raw_log_entry_to_anomark_row(e: &RawLogEntry) -> AHashMap<String, String> {
    let mut m = AHashMap::new();
    m.insert("machine_id".to_string(), e.machine_id.clone());
    m.insert("hostname".to_string(), e.machine_id.clone());
    m.insert("host".to_string(), e.machine_id.clone());
    let command = if !e.path.is_empty() {
        if e.args.is_empty() {
            e.path.clone()
        } else {
            format!("{} {}", e.path, e.args)
        }
    } else {
        e.name.clone()
    };
    m.insert("cmdline".to_string(), command.clone());
    m.insert("command".to_string(), command);
    m
}

fn row_key_lookup(row: &AHashMap<String, String>, col: &str) -> String {
    if let Some(v) = row.get(col) {
        return v.clone();
    }
    let want = col.to_ascii_lowercase();
    for (k, v) in row {
        if k.to_ascii_lowercase() == want {
            return v.clone();
        }
    }
    String::new()
}

#[allow(dead_code)]
fn _analysis_type_name(t: AnalysisType) -> &'static str {
    match t {
        AnalysisType::Process => "process",
        AnalysisType::File => "file",
    }
}

#[cfg(test)]
mod json_kind_sniff_tests {
    use crate::json_parse::{classify_json_line_shape, JsonLineShape};
    use serde_json::json;

    #[test]
    fn file_information_inventory_row_is_file() {
        let v = json!({
            "timestamp": "2026-04-27T00:10:05",
            "date": "2026-04-17T20:34:00",
            "event_type": "file_information",
            "permissions": "-rw-r-----.",
            "owner": "root",
            "group": "root",
            "size": 221295,
            "file_path": "/data/var/dlogs/config_rest_server.log"
        });
        assert_eq!(classify_json_line_shape(&v), JsonLineShape::File);
    }

    #[test]
    fn cmdline_pid_row_is_process() {
        let v = json!({"cmdline": "/bin/sh -c id", "pid": 401, "parent": 1});
        assert_eq!(classify_json_line_shape(&v), JsonLineShape::Process);
    }
}

#[cfg(test)]
mod parent_dir_tag_tests {
    use super::parent_dir_segment_tag;

    #[test]
    fn example_folder_name_field_4_is_host() {
        let n = "RemoteAccess-Periodicsnapshot-standalone-HOSTEXAMPLE01-20260330-0012";
        assert_eq!(
            parent_dir_segment_tag(n, 4, '-').as_deref(),
            Some("HOSTEXAMPLE01")
        );
    }

    #[test]
    fn out_of_range_returns_none() {
        assert!(parent_dir_segment_tag("a-b", 9, '-').is_none());
    }
}

#[cfg(test)]
mod anomark_score_line_tests {
    use super::anomark_score_line;

    #[test]
    fn prefixes_machine_when_non_empty() {
        assert_eq!(
            anomark_score_line("web-01", "/bin/bash -c ls"),
            "web-01 /bin/bash -c ls"
        );
    }

    #[test]
    fn command_only_when_machine_missing() {
        assert_eq!(anomark_score_line("", "echo hi"), "echo hi");
        assert_eq!(anomark_score_line("   ", "echo hi"), "echo hi");
    }

    #[test]
    fn empty_when_command_empty() {
        assert!(anomark_score_line("host", "").is_empty());
        assert!(anomark_score_line("host", "  ").is_empty());
    }
}

#[cfg(test)]
mod anomark_row_command_tests {
    use super::{row_command_for_anomark, AHashMap};

    #[test]
    fn falls_back_from_cmdline_to_command() {
        let mut row = AHashMap::default();
        row.insert("command".to_string(), "C:\\\\Windows\\\\cmd.exe /c whoami".to_string());
        assert_eq!(
            row_command_for_anomark(&row, "cmdline"),
            "C:\\\\Windows\\\\cmd.exe /c whoami"
        );
    }

    #[test]
    fn primary_column_wins_when_present() {
        let mut row = AHashMap::default();
        row.insert("cmdline".to_string(), "primary".to_string());
        row.insert("command".to_string(), "other".to_string());
        assert_eq!(row_command_for_anomark(&row, "cmdline"), "primary");
    }
}

#[cfg(test)]
mod run_detector_mode_tests {
    use super::{run_anomark_detection, run_fleet_detection, RunDetectorMode};

    #[test]
    fn fleet_and_anomark_flags_by_mode() {
        assert!(run_fleet_detection(RunDetectorMode::Both));
        assert!(run_fleet_detection(RunDetectorMode::IronsiftOnly));
        assert!(!run_fleet_detection(RunDetectorMode::AnomarkOnly));

        assert!(run_anomark_detection(RunDetectorMode::AnomarkOnly, false));
        assert!(!run_anomark_detection(RunDetectorMode::IronsiftOnly, true));
        assert!(run_anomark_detection(RunDetectorMode::Both, true));
        assert!(!run_anomark_detection(RunDetectorMode::Both, false));
    }
}

#[cfg(test)]
mod run_detection_focus_tests {
    use super::{run_detection_arms, DatasetKind, RunDetectionFocus};

    #[test]
    fn auto_mixed_in_both_arms() {
        assert_eq!(
            run_detection_arms(DatasetKind::Mixed, RunDetectionFocus::Auto),
            (true, true)
        );
    }

    #[test]
    fn process_only_mixed_process_arm_only() {
        assert_eq!(
            run_detection_arms(DatasetKind::Mixed, RunDetectionFocus::ProcessOnly),
            (true, false)
        );
    }

    #[test]
    fn file_only_mixed_file_arm_only() {
        assert_eq!(
            run_detection_arms(DatasetKind::Mixed, RunDetectionFocus::FileOnly),
            (false, true)
        );
    }

    #[test]
    fn pure_process_and_file_unaffected_by_focus_arms() {
        assert_eq!(
            run_detection_arms(DatasetKind::Process, RunDetectionFocus::ProcessOnly),
            (true, false)
        );
        assert_eq!(
            run_detection_arms(DatasetKind::File, RunDetectionFocus::FileOnly),
            (false, true)
        );
    }
}

#[cfg(test)]
mod run_namespace_tests {
    use super::namespace_run_machine_id;

    #[test]
    fn single_dataset_run_keeps_plain_host_id() {
        assert_eq!(namespace_run_machine_id("ds-1", "web-01", false), "web-01");
    }

    #[test]
    fn multi_dataset_run_prefixes_dataset_id() {
        assert_eq!(
            namespace_run_machine_id("817cbabb-2a33-483f-a70e-dc952263d9fa", "web-01", true),
            "817cbabb-2a33-483f-a70e-dc952263d9fa/web-01"
        );
    }
}

#[cfg(test)]
mod dataset_tags_resolve_tests {
    use super::{
        resolve_machine_dataset_tags_for_run, DatasetKind, DatasetRecord, RunDetectionFocus,
    };

    fn ds(id: &str, kind: DatasetKind, tags: &[&str]) -> DatasetRecord {
        DatasetRecord {
            id: id.to_string(),
            name: id.to_string(),
            source_path: String::new(),
            format: "jsonl".to_string(),
            kind,
            tags: tags.iter().map(|s| (*s).to_string()).collect(),
            schema_profile: String::new(),
            imported_at: String::new(),
            ingest_default_machine_id: None,
        }
    }

    #[test]
    fn prefixed_machine_uses_that_dataset_tags() {
        let datasets = vec![
            ds("ds-a", DatasetKind::Process, &["prod"]),
            ds("ds-b", DatasetKind::Process, &["staging"]),
        ];
        let run_ids = vec!["ds-a".to_string(), "ds-b".to_string()];
        let t = resolve_machine_dataset_tags_for_run(
            "ds-a/host1",
            &run_ids,
            RunDetectionFocus::Auto,
            &datasets,
        );
        assert_eq!(t, vec!["prod".to_string()]);
    }

    #[test]
    fn single_process_dataset_unprefixed_gets_sorted_tags() {
        let datasets = vec![ds("only", DatasetKind::Process, &["win", "srv"])];
        let run_ids = vec!["only".to_string()];
        let t = resolve_machine_dataset_tags_for_run(
            "host",
            &run_ids,
            RunDetectionFocus::Auto,
            &datasets,
        );
        assert_eq!(t, vec!["srv".to_string(), "win".to_string()]);
    }
}

#[cfg(test)]
mod anomark_training_delete_tests {
    use super::{
        AnoMarkSettings, AnoMarkTrainRecord, AnoMarkTrainRequest, PlatformStore,
    };
    use std::fs;
    use std::path::Path;
    use tempfile::tempdir;

    /// Seed a [`PlatformStore`] with a fake AnoMark training record on disk so we can verify the
    /// delete paths without spinning up the (slow) real `train_anomark` pipeline.
    fn seed_training(store: &PlatformStore, id: &str) -> std::path::PathBuf {
        let root = store.platform_root().expect("platform root resolves");
        let dir = root.join("anomark-trains").join(id);
        fs::create_dir_all(&dir).expect("training dir");
        fs::write(dir.join("model.bin"), b"fake-model").expect("model.bin");
        fs::write(dir.join("training_input.jsonl"), b"{\"cmdline\":\"ls -la\"}\n")
            .expect("training input");
        let rel_dir = format!("anomark-trains/{}", id);
        let req = AnoMarkTrainRequest {
            name: String::new(),
            training_path: String::new(),
            dataset_ids: Vec::new(),
            tags: Vec::new(),
            column: "cmdline".to_string(),
            order: 4,
            output_model_path: String::new(),
        };
        let rec = AnoMarkTrainRecord {
            id: id.to_string(),
            created_at: "1970-01-01T00:00:00Z".to_string(),
            name: String::new(),
            request: req,
            source_dataset_ids: Vec::new(),
            from_user_file: false,
            rel_model_path: format!("{}/model.bin", rel_dir),
            rel_training_data_path: format!("{}/training_input.jsonl", rel_dir),
            training_line_count: 1,
            bin_path_used: "test".to_string(),
            favorite: false,
        };
        store.db.write().anomark_trainings.push(rec);
        store.save().expect("save db");
        dir
    }

    fn point_settings_at(store: &PlatformStore, model_path: &Path) {
        let mut s = AnoMarkSettings::default();
        s.model_path = model_path.to_string_lossy().to_string();
        store
            .set_anomark_settings(s)
            .expect("settings update succeeds");
    }

    #[test]
    fn delete_anomark_training_removes_record_and_files() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("db.json");
        let store = PlatformStore::load_or_create(db_path.to_str().unwrap()).expect("store");
        let train_dir = seed_training(&store, "train-aaa");
        let model_file = train_dir.join("model.bin");
        point_settings_at(&store, &model_file);

        store
            .delete_anomark_training("train-aaa")
            .expect("delete succeeds");

        assert!(store.list_anomark_trainings().is_empty());
        assert!(!train_dir.exists(), "training dir should be wiped");
        let cfg = store.get_anomark_settings();
        assert!(
            cfg.model_path.trim().is_empty(),
            "model_path should be cleared when it pointed at the deleted training: {}",
            cfg.model_path
        );
    }

    #[test]
    fn delete_anomark_training_keeps_unrelated_settings_path() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("db.json");
        let store = PlatformStore::load_or_create(db_path.to_str().unwrap()).expect("store");
        seed_training(&store, "train-aaa");
        // External path that is *not* the deleted training's stored model.
        let unrelated = dir.path().join("external-model.bin");
        fs::write(&unrelated, b"fake").expect("write external");
        point_settings_at(&store, &unrelated);

        store
            .delete_anomark_training("train-aaa")
            .expect("delete succeeds");

        let cfg = store.get_anomark_settings();
        assert_eq!(
            cfg.model_path,
            unrelated.to_string_lossy().to_string(),
            "external model_path must be preserved on training delete"
        );
    }

    #[test]
    fn delete_anomark_training_unknown_id_is_error() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("db.json");
        let store = PlatformStore::load_or_create(db_path.to_str().unwrap()).expect("store");
        seed_training(&store, "train-aaa");
        let err = store
            .delete_anomark_training("does-not-exist")
            .expect_err("deleting unknown id must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("not found"),
            "error should mention not-found: {}",
            msg
        );
        assert_eq!(
            store.list_anomark_trainings().len(),
            1,
            "valid trainings must remain untouched"
        );
    }

    #[test]
    fn delete_all_anomark_trainings_clears_records_and_dirs() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("db.json");
        let store = PlatformStore::load_or_create(db_path.to_str().unwrap()).expect("store");
        let d1 = seed_training(&store, "train-aaa");
        let d2 = seed_training(&store, "train-bbb");
        let model_file = d2.join("model.bin");
        point_settings_at(&store, &model_file);

        let removed = store
            .delete_all_anomark_trainings()
            .expect("purge succeeds");

        assert_eq!(removed, 2);
        assert!(store.list_anomark_trainings().is_empty());
        assert!(!d1.exists());
        assert!(!d2.exists());
        let cfg = store.get_anomark_settings();
        assert!(
            cfg.model_path.trim().is_empty(),
            "purge should clear model_path that referenced any deleted training"
        );
    }

    #[test]
    fn delete_all_anomark_trainings_no_op_when_empty() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("db.json");
        let store = PlatformStore::load_or_create(db_path.to_str().unwrap()).expect("store");
        let removed = store
            .delete_all_anomark_trainings()
            .expect("purge succeeds even when empty");
        assert_eq!(removed, 0);
    }

    #[test]
    fn set_anomark_training_favorite_persists() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("db.json");
        let store = PlatformStore::load_or_create(db_path.to_str().unwrap()).expect("store");
        seed_training(&store, "train-aaa");
        store
            .set_anomark_training_favorite("train-aaa", true)
            .expect("set favorite");
        assert!(store.list_anomark_trainings()[0].favorite);
        store
            .set_anomark_training_favorite("train-aaa", false)
            .expect("unset favorite");
        assert!(!store.list_anomark_trainings()[0].favorite);
    }

    #[test]
    fn set_anomark_training_favorite_unknown_id_errors() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("db.json");
        let store = PlatformStore::load_or_create(db_path.to_str().unwrap()).expect("store");
        seed_training(&store, "train-aaa");
        let err = store
            .set_anomark_training_favorite("missing", true)
            .expect_err("unknown id");
        assert!(
            err.to_string().contains("not found"),
            "unexpected: {}",
            err
        );
        assert!(!store.list_anomark_trainings()[0].favorite);
    }
}

#[cfg(test)]
mod detector_reason_helpers_tests {
    use super::{DetectionFinding, PlatformStore};

    fn empty_finding(machine_id: &str) -> DetectionFinding {
        DetectionFinding {
            machine_id: machine_id.to_string(),
            severity: "LOW".to_string(),
            score: 0.0,
            reasons: Vec::new(),
            detectors: Vec::new(),
            dataset_tags: Vec::new(),
            reasons_by_detector: Vec::new(),
            sigma_matches: Vec::new(),
        }
    }

    #[test]
    fn push_detector_reason_keeps_flat_and_bucket_in_sync() {
        let mut f = empty_finding("h1");
        PlatformStore::push_detector_reason(
            &mut f,
            "anomark-rs",
            "AnoMark suspicious command ratio 0.01 (suspect 95.0%)".to_string(),
        );
        PlatformStore::push_detector_reason(
            &mut f,
            "anomark-rs",
            "AnoMark suspect: /bin/ps (ll=-11.29, margin=-0.22)".to_string(),
        );
        PlatformStore::push_detector_reason(
            &mut f,
            "ironsift-process",
            "RISK DETECTED: name=sh path=sh".to_string(),
        );

        assert_eq!(f.reasons.len(), 3);
        assert_eq!(f.reasons_by_detector.len(), 2);
        let an = f
            .reasons_by_detector
            .iter()
            .find(|b| b.detector == "anomark-rs")
            .expect("anomark bucket");
        assert_eq!(an.reasons.len(), 2);
        assert!(an.reasons[0].contains("ratio"));
        assert!(an.reasons[1].contains("AnoMark suspect"));
        let isp = f
            .reasons_by_detector
            .iter()
            .find(|b| b.detector == "ironsift-process")
            .expect("ironsift-process bucket");
        assert_eq!(isp.reasons.len(), 1);
    }

    #[test]
    fn extend_detector_reasons_preserves_input_order() {
        let mut f = empty_finding("h1");
        PlatformStore::extend_detector_reasons(
            &mut f,
            "ironsift-file",
            vec![
                "MTIME ANOMALY: /etc/passwd modified 48h NEWER than fleet baseline".to_string(),
                "Rare file access: /tmp/.x/agent [suspicious_path]".to_string(),
                "(+5 more rare files matched the same gate, not shown)".to_string(),
            ],
        );
        assert_eq!(f.reasons.len(), 3);
        let bucket = &f.reasons_by_detector[0];
        assert_eq!(bucket.detector, "ironsift-file");
        assert_eq!(bucket.reasons[0].starts_with("MTIME ANOMALY"), true);
        assert_eq!(bucket.reasons[1].starts_with("Rare file access"), true);
        assert_eq!(bucket.reasons[2].starts_with("(+5"), true);
    }

    #[test]
    fn duplicate_reasons_are_handled_per_bucket() {
        let mut f = empty_finding("h1");
        PlatformStore::push_detector_reason(&mut f, "anomark-rs", "dup".to_string());
        PlatformStore::push_detector_reason(&mut f, "anomark-rs", "dup".to_string());
        // Pre-finalization both copies are present (dedup happens at the end of run_detection
        // alongside flat reasons sort/dedup). What matters here is that the bucket is only
        // created once and sequential pushes target it.
        assert_eq!(f.reasons_by_detector.len(), 1);
        assert_eq!(f.reasons_by_detector[0].reasons, vec!["dup", "dup"]);
    }
}

#[cfg(test)]
mod run_user_triage_filter_tests {
    use super::{MachineTriageEntry, ReasonTriageEntry, RunUserTriage, TriageVerdict};

    #[test]
    fn without_excluded_reason_decisions_drops_process_row() {
        let t = RunUserTriage {
            machines: vec![MachineTriageEntry {
                machine_id: "h1".into(),
                reason_decisions: vec![
                    ReasonTriageEntry {
                        detector: "ironsift-process".into(),
                        reason: "Process row: dataset=x pid=1".into(),
                        verdict: TriageVerdict::Malicious,
                        reviewed_at: None,
                    },
                    ReasonTriageEntry {
                        detector: "ironsift-process".into(),
                        reason: "RISK DETECTED: uid=0".into(),
                        verdict: TriageVerdict::FalsePositive,
                        reviewed_at: None,
                    },
                ],
                final_verdict: TriageVerdict::Unset,
            }],
        };
        let f = t.without_excluded_reason_decisions();
        assert_eq!(f.machines[0].reason_decisions.len(), 1);
        assert!(f.machines[0].reason_decisions[0].reason.starts_with("RISK"));
    }
}

#[cfg(test)]
mod reason_history_triage_tests {
    use super::{
        effective_score_and_severity, merge_history_into_user_triage, DetectionFinding,
        DetectorReasons, MachineTriageEntry, PlatformStore, ReasonTriageEntry, RunUserTriage,
        TriageVerdict,
    };
    use std::collections::{HashMap, HashSet};

    fn sample_finding() -> DetectionFinding {
        DetectionFinding {
            machine_id: "host-a".into(),
            severity: "HIGH".into(),
            score: 0.75,
            reasons: vec![],
            detectors: vec!["anomark-rs".into()],
            dataset_tags: vec![],
            reasons_by_detector: vec![DetectorReasons {
                detector: "anomark-rs".into(),
                reasons: vec!["AnoMark suspect: /bin/touch (ll=-1.0, margin=0.1)".into()],
            }],
            sigma_matches: vec![],
        }
    }

    #[test]
    fn history_fills_unset_reason_verdict() {
        let f = sample_finding();
        let current = RunUserTriage::default();
        let mut hist = HashMap::new();
        hist.insert(
            (
                "anomark-rs".into(),
                "AnoMark suspect: /bin/touch (ll=-1.0, margin=0.1)".into(),
            ),
            TriageVerdict::FalsePositive,
        );
        let empty_ignore = HashSet::new();
        let (merged, changed) =
            merge_history_into_user_triage(&[f.clone()], &current, &hist, &empty_ignore);
        assert!(changed);
        let m = merged.machines.iter().find(|x| x.machine_id == "host-a").unwrap();
        assert_eq!(m.reason_decisions.len(), 1);
        assert_eq!(m.reason_decisions[0].verdict, TriageVerdict::FalsePositive);
        assert!(
            m.reason_decisions[0].reviewed_at.is_none(),
            "fleet merge must not set human review time"
        );
    }

    #[test]
    fn history_does_not_override_existing_verdict() {
        let f = sample_finding();
        let current = RunUserTriage {
            machines: vec![MachineTriageEntry {
                machine_id: "host-a".into(),
                reason_decisions: vec![ReasonTriageEntry {
                    detector: "anomark-rs".into(),
                    reason: "AnoMark suspect: /bin/touch (ll=-1.0, margin=0.1)".into(),
                    verdict: TriageVerdict::Malicious,
                    reviewed_at: None,
                }],
                final_verdict: TriageVerdict::Unset,
            }],
        };
        let mut hist = HashMap::new();
        hist.insert(
            (
                "anomark-rs".into(),
                "AnoMark suspect: /bin/touch (ll=-1.0, margin=0.1)".into(),
            ),
            TriageVerdict::FalsePositive,
        );
        let empty_ignore = HashSet::new();
        let (merged, changed) = merge_history_into_user_triage(&[f], &current, &hist, &empty_ignore);
        assert!(!changed);
        assert_eq!(
            merged.machines[0].reason_decisions[0].verdict,
            TriageVerdict::Malicious
        );
    }

    /// Saved triage for a host must survive merge even if that host is missing from the current
    /// `findings` slice (fleet precedent is derived from all `user_triage` rows).
    #[test]
    fn merge_preserves_triage_for_machines_not_in_findings() {
        let f = sample_finding();
        let current = RunUserTriage {
            machines: vec![
                MachineTriageEntry {
                    machine_id: "host-a".into(),
                    reason_decisions: vec![],
                    final_verdict: TriageVerdict::Unset,
                },
                MachineTriageEntry {
                    machine_id: "host-orphan".into(),
                    reason_decisions: vec![ReasonTriageEntry {
                        detector: "anomark-rs".into(),
                        reason: "AnoMark suspect: /bin/legacy (ll=-2.0, margin=0.2)".into(),
                        verdict: TriageVerdict::FalsePositive,
                        reviewed_at: None,
                    }],
                    final_verdict: TriageVerdict::Unset,
                },
            ],
        };
        let empty_hist = HashMap::new();
        let empty_ignore = HashSet::new();
        let (merged, changed) =
            merge_history_into_user_triage(&[f], &current, &empty_hist, &empty_ignore);
        assert!(!changed);
        let ids: Vec<_> = merged.machines.iter().map(|m| m.machine_id.as_str()).collect();
        assert!(ids.contains(&"host-a"));
        assert!(ids.contains(&"host-orphan"));
        let orphan = merged
            .machines
            .iter()
            .find(|m| m.machine_id == "host-orphan")
            .unwrap();
        assert_eq!(orphan.reason_decisions.len(), 1);
        assert_eq!(orphan.reason_decisions[0].verdict, TriageVerdict::FalsePositive);
    }

    #[test]
    fn effective_score_zero_when_all_actionable_reasons_fp() {
        let f = sample_finding();
        let triage = RunUserTriage {
            machines: vec![MachineTriageEntry {
                machine_id: "host-a".into(),
                reason_decisions: vec![ReasonTriageEntry {
                    detector: "anomark-rs".into(),
                    reason: "AnoMark suspect: /bin/touch (ll=-1.0, margin=0.1)".into(),
                    verdict: TriageVerdict::FalsePositive,
                    reviewed_at: None,
                }],
                final_verdict: TriageVerdict::Unset,
            }],
        };
        let (s, sev) = effective_score_and_severity(&f, &triage);
        assert_eq!(s, 0.0);
        assert_eq!(sev, "LOW");
    }

    #[test]
    fn effective_score_keeps_raw_when_any_malicious() {
        let f = sample_finding();
        let triage = RunUserTriage {
            machines: vec![MachineTriageEntry {
                machine_id: "host-a".into(),
                reason_decisions: vec![
                    ReasonTriageEntry {
                        detector: "anomark-rs".into(),
                        reason: "AnoMark suspect: /bin/touch (ll=-1.0, margin=0.1)".into(),
                        verdict: TriageVerdict::Malicious,
                        reviewed_at: None,
                    },
                    ReasonTriageEntry {
                        detector: "anomark-rs".into(),
                        reason: "AnoMark suspicious command ratio 0.50 (suspect 95.0%)".into(),
                        verdict: TriageVerdict::FalsePositive,
                        reviewed_at: None,
                    },
                ],
                final_verdict: TriageVerdict::Unset,
            }],
        };
        let mut f2 = f;
        PlatformStore::push_detector_reason(
            &mut f2,
            "anomark-rs",
            "AnoMark suspicious command ratio 0.50 (suspect 95.0%)".into(),
        );
        let (s, _) = effective_score_and_severity(&f2, &triage);
        assert_eq!(s, 0.75);
    }

    /// Unset triage on one actionable group must not dilute severity because another group is FP
    /// (e.g. `RISK DETECTED: sh …` still open while "cluster outlier" was marked false positive).
    #[test]
    fn effective_score_keeps_raw_when_mixed_fp_and_unset_groups() {
        let mut f = DetectionFinding {
            machine_id: "host-a".into(),
            severity: "HIGH".into(),
            score: 0.75,
            reasons: vec![],
            detectors: vec!["ironsift-process".into()],
            dataset_tags: vec![],
            reasons_by_detector: vec![],
            sigma_matches: vec![],
        };
        let risk =
            "RISK DETECTED: name=sh path=sh parent=dscockpitd uid=0 count=1 reasons=root_no_whitelist,high_entropy_args"
                .to_string();
        let cluster = "Process mix differs from fleet majority cluster (no behavioral/root/rare-process flags)."
            .to_string();
        PlatformStore::push_detector_reason(&mut f, "ironsift-process", risk.clone());
        PlatformStore::push_detector_reason(&mut f, "ironsift-process", cluster.clone());
        let triage = RunUserTriage {
            machines: vec![MachineTriageEntry {
                machine_id: "host-a".into(),
                reason_decisions: vec![ReasonTriageEntry {
                    detector: "ironsift-process".into(),
                    reason: cluster,
                    verdict: TriageVerdict::FalsePositive,
                    reviewed_at: None,
                }],
                final_verdict: TriageVerdict::Unset,
            }],
        };
        let (s, sev) = effective_score_and_severity(&f, &triage);
        assert_eq!(s, 0.75);
        assert_eq!(sev, "HIGH");
    }

    #[test]
    fn merge_skips_keys_in_precedent_ignore_set() {
        let f = sample_finding();
        let current = RunUserTriage::default();
        let mut hist = HashMap::new();
        hist.insert(
            (
                "anomark-rs".into(),
                "AnoMark suspect: /bin/touch (ll=-1.0, margin=0.1)".into(),
            ),
            TriageVerdict::FalsePositive,
        );
        let mut ign = HashSet::new();
        ign.insert((
            "anomark-rs".into(),
            "AnoMark suspect: /bin/touch (ll=-1.0, margin=0.1)".into(),
        ));
        let (merged, changed) = merge_history_into_user_triage(&[f], &current, &hist, &ign);
        assert!(!changed);
        let m = merged.machines.iter().find(|x| x.machine_id == "host-a").unwrap();
        assert!(m.reason_decisions.is_empty());
    }

    #[test]
    fn effective_score_ironsift_process_counts_one_slot_per_process_name() {
        let mut f = DetectionFinding {
            machine_id: "host-a".into(),
            severity: "HIGH".into(),
            score: 0.9,
            reasons: vec![],
            detectors: vec!["ironsift-process".into()],
            dataset_tags: vec![],
            reasons_by_detector: vec![],
            sigma_matches: vec![],
        };
        let risk = "RISK DETECTED:name=lsof path=/usr/sbin/lsof parent=lsof uid=0 count=1 reasons=root_no_whitelist".to_string();
        let rare = "Rare process:lsof (explanation)".to_string();
        PlatformStore::push_detector_reason(&mut f, "ironsift-process", risk.clone());
        PlatformStore::push_detector_reason(&mut f, "ironsift-process", rare.clone());
        let triage = RunUserTriage {
            machines: vec![MachineTriageEntry {
                machine_id: "host-a".into(),
                reason_decisions: vec![
                    ReasonTriageEntry {
                        detector: "ironsift-process".into(),
                        reason: risk,
                        verdict: TriageVerdict::FalsePositive,
                        reviewed_at: None,
                    },
                    ReasonTriageEntry {
                        detector: "ironsift-process".into(),
                        reason: rare,
                        verdict: TriageVerdict::FalsePositive,
                        reviewed_at: None,
                    },
                ],
                final_verdict: TriageVerdict::Unset,
            }],
        };
        let (s, sev) = effective_score_and_severity(&f, &triage);
        assert_eq!(s, 0.0);
        assert_eq!(sev, "LOW");
    }

    #[test]
    fn history_fills_risk_line_from_rare_process_line_same_group() {
        let mut f = DetectionFinding {
            machine_id: "host-a".into(),
            severity: "HIGH".into(),
            score: 0.9,
            reasons: vec![],
            detectors: vec!["ironsift-process".into()],
            dataset_tags: vec![],
            reasons_by_detector: vec![],
            sigma_matches: vec![],
        };
        let risk = "RISK DETECTED:name=lsof path=/usr/sbin/lsof parent=lsof uid=0 count=1 reasons=root_no_whitelist".to_string();
        let rare = "Rare process:lsof (explanation)".to_string();
        PlatformStore::push_detector_reason(&mut f, "ironsift-process", risk.clone());
        PlatformStore::push_detector_reason(&mut f, "ironsift-process", rare.clone());
        let current = RunUserTriage::default();
        let mut hist = HashMap::new();
        hist.insert(
            ("ironsift-process".into(), rare.clone()),
            TriageVerdict::FalsePositive,
        );
        let empty_ignore = HashSet::new();
        let (merged, changed) =
            merge_history_into_user_triage(&[f], &current, &hist, &empty_ignore);
        assert!(changed);
        let m = merged.machines.iter().find(|x| x.machine_id == "host-a").unwrap();
        let v_risk = m
            .reason_decisions
            .iter()
            .find(|e| e.reason == risk)
            .map(|e| e.verdict);
        let v_rare = m
            .reason_decisions
            .iter()
            .find(|e| e.reason == rare)
            .map(|e| e.verdict);
        assert_eq!(v_risk, Some(TriageVerdict::FalsePositive));
        assert_eq!(v_rare, Some(TriageVerdict::FalsePositive));
    }
}

#[cfg(test)]
mod fleet_triage_precedent_drop_tests {
    use super::{
        build_reason_verdict_provenance_from_runs, DetectionFinding, DetectionRunRecord,
        MachineTriageEntry, PlatformStore, ReasonPrecedentKey, ReasonTriageEntry,
        RunDetectionFocus, RunDetectorMode, RunUserTriage, TriageVerdict,
    };
    use std::collections::HashSet;
    use tempfile::tempdir;

    fn run_with_reason(det: &str, reason: &str, verdict: TriageVerdict) -> DetectionRunRecord {
        DetectionRunRecord {
            id: "run-test-1".into(),
            created_at: "2026-01-02T12:00:00Z".into(),
            dataset_ids: vec![],
            baseline_tags: vec![],
            candidate_tags: vec![],
            baseline_finding_count: 0,
            candidate_finding_count: 0,
            findings: vec![],
            summary: "test".into(),
            detection_config_id: None,
            detection_config_name: None,
            detection_focus: RunDetectionFocus::Auto,
            detector_mode: RunDetectorMode::Both,
            anomark_suspect_percent: 95.0,
            request: Default::default(),
            user_triage: RunUserTriage {
                machines: vec![MachineTriageEntry {
                    machine_id: "host-1".into(),
                    reason_decisions: vec![ReasonTriageEntry {
                        detector: det.into(),
                        reason: reason.into(),
                        verdict,
                        reviewed_at: None,
                    }],
                    final_verdict: TriageVerdict::Unset,
                }],
            },
            triage_precedent_ignore: vec![],
            sigma_stable_stats: None,
        }
    }

    #[test]
    fn fleet_drop_set_hides_pair_from_provenance() {
        let runs = [run_with_reason("sigma-zero", "Suspicious: foo", TriageVerdict::Malicious)];
        let mut drops = HashSet::new();
        drops.insert(("sigma-zero".into(), "Suspicious: foo".into()));
        let m = build_reason_verdict_provenance_from_runs(&runs, None, &drops);
        assert!(m.is_empty());
        let m2 = build_reason_verdict_provenance_from_runs(&runs, None, &HashSet::new());
        assert_eq!(m2.len(), 1);
    }

    #[test]
    fn saving_triage_clears_fleet_drop_for_that_reason_key() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("db.json");
        let store = PlatformStore::load_or_create(db_path.to_str().unwrap()).expect("store");
        let run_id = "run-fleet-drop-lift".to_string();
        let mut rec = run_with_reason("sigma-zero", "line a", TriageVerdict::Malicious);
        rec.id = run_id.clone();
        rec.candidate_finding_count = 1;
        rec.findings = vec![DetectionFinding {
            machine_id: "host-1".into(),
            severity: "HIGH".into(),
            score: 0.9,
            reasons: vec![],
            detectors: vec!["sigma-zero".into()],
            dataset_tags: vec![],
            reasons_by_detector: vec![],
            sigma_matches: vec![],
        }];
        {
            let mut db = store.db.write();
            db.runs.push(rec);
        }
        store.save().expect("save");
        store
            .add_fleet_triage_precedent_drop(ReasonPrecedentKey {
                detector: "sigma-zero".into(),
                reason: "line a".into(),
            })
            .expect("drop");
        assert!(store.triage_precedent_fleet_global().is_empty());
        let triage = RunUserTriage {
            machines: vec![MachineTriageEntry {
                machine_id: "host-1".into(),
                reason_decisions: vec![ReasonTriageEntry {
                    detector: "sigma-zero".into(),
                    reason: "line a".into(),
                    verdict: TriageVerdict::FalsePositive,
                    reviewed_at: None,
                }],
                final_verdict: TriageVerdict::Unset,
            }],
        };
        store
            .update_run_user_triage(&run_id, triage)
            .expect("update triage");
        let global = store.triage_precedent_fleet_global();
        assert_eq!(global.len(), 1);
        assert_eq!(global[0].verdict, TriageVerdict::FalsePositive);
        assert_eq!(global[0].source_run_id, run_id);
        assert!(
            global[0].source_reviewed_at.is_some(),
            "fleet precedent should carry review time after save"
        );
    }

    #[test]
    fn fleet_memory_survives_delete_all_runs() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("db.json");
        let store = PlatformStore::load_or_create(db_path.to_str().unwrap()).expect("store");
        let run_id = "run-fleet-persist".to_string();
        let mut rec = run_with_reason("sigma-zero", "line persist", TriageVerdict::FalsePositive);
        rec.id = run_id.clone();
        rec.candidate_finding_count = 1;
        rec.findings = vec![DetectionFinding {
            machine_id: "host-1".into(),
            severity: "HIGH".into(),
            score: 0.9,
            reasons: vec![],
            detectors: vec!["sigma-zero".into()],
            dataset_tags: vec![],
            reasons_by_detector: vec![],
            sigma_matches: vec![],
        }];
        store.db.write().runs.push(rec);
        store.save().expect("save");
        store
            .update_run_user_triage(
                &run_id,
                RunUserTriage {
                    machines: vec![MachineTriageEntry {
                        machine_id: "host-1".into(),
                        reason_decisions: vec![ReasonTriageEntry {
                            detector: "sigma-zero".into(),
                            reason: "line persist".into(),
                            verdict: TriageVerdict::FalsePositive,
                            reviewed_at: None,
                        }],
                        final_verdict: TriageVerdict::Unset,
                    }],
                },
            )
            .expect("triage");
        assert_eq!(store.triage_precedent_fleet_global().len(), 1);
        store.delete_all_runs().expect("delete all");
        assert!(store.db.read().runs.is_empty());
        let global = store.triage_precedent_fleet_global();
        assert_eq!(global.len(), 1);
        assert_eq!(global[0].verdict, TriageVerdict::FalsePositive);
        assert_eq!(global[0].reason, "line persist");
    }

    #[test]
    fn delete_fleet_triage_precedent_entry_clears_store_and_drop_list() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("db.json");
        let store = PlatformStore::load_or_create(db_path.to_str().unwrap()).expect("store");
        let run_id = "run-del-fleet".to_string();
        let mut rec = run_with_reason("sigma-zero", "unique-reason-line", TriageVerdict::Malicious);
        rec.id = run_id.clone();
        rec.candidate_finding_count = 1;
        rec.findings = vec![DetectionFinding {
            machine_id: "host-1".into(),
            severity: "HIGH".into(),
            score: 0.9,
            reasons: vec![],
            detectors: vec!["sigma-zero".into()],
            dataset_tags: vec![],
            reasons_by_detector: vec![],
            sigma_matches: vec![],
        }];
        store.db.write().runs.push(rec);
        store.save().expect("save");
        store
            .update_run_user_triage(
                &run_id,
                RunUserTriage {
                    machines: vec![MachineTriageEntry {
                        machine_id: "host-1".into(),
                        reason_decisions: vec![ReasonTriageEntry {
                            detector: "sigma-zero".into(),
                            reason: "unique-reason-line".into(),
                            verdict: TriageVerdict::Malicious,
                            reviewed_at: None,
                        }],
                        final_verdict: TriageVerdict::Unset,
                    }],
                },
            )
            .expect("triage");
        assert_eq!(store.triage_precedent_fleet_global().len(), 1);
        store
            .add_fleet_triage_precedent_drop(ReasonPrecedentKey {
                detector: "sigma-zero".into(),
                reason: "unique-reason-line".into(),
            })
            .expect("drop");
        assert!(store.triage_precedent_fleet_global().is_empty());
        assert_eq!(store.fleet_triage_precedent_drops().len(), 1);
        let changed = store
            .delete_fleet_triage_precedent_entry(ReasonPrecedentKey {
                detector: "sigma-zero".into(),
                reason: "unique-reason-line".into(),
            })
            .expect("delete");
        assert!(changed);
        assert!(store.db.read().fleet_triage_precedent_entries.is_empty());
        assert!(store.db.read().fleet_triage_precedent_drops.is_empty());
        assert!(store.triage_precedent_fleet_global().is_empty());
    }
}

#[cfg(test)]
mod triage_review_time_tests {
    use super::{
        DetectionFinding, DetectionRunRecord, MachineTriageEntry, PlatformStore, ReasonTriageEntry,
        RunDetectionFocus, RunDetectorMode, RunUserTriage, TriageVerdict,
    };
    use tempfile::tempdir;

    fn finding(mid: &str) -> DetectionFinding {
        DetectionFinding {
            machine_id: mid.into(),
            severity: "HIGH".into(),
            score: 0.9,
            reasons: vec![],
            detectors: vec!["sigma-zero".into()],
            dataset_tags: vec![],
            reasons_by_detector: vec![],
            sigma_matches: vec![],
        }
    }

    fn run_record(run_id: &str) -> DetectionRunRecord {
        DetectionRunRecord {
            id: run_id.into(),
            created_at: "2026-01-02T12:00:00Z".into(),
            dataset_ids: vec![],
            baseline_tags: vec![],
            candidate_tags: vec![],
            baseline_finding_count: 0,
            candidate_finding_count: 1,
            findings: vec![finding("host-1")],
            summary: "test".into(),
            detection_config_id: None,
            detection_config_name: None,
            detection_focus: RunDetectionFocus::Auto,
            detector_mode: RunDetectorMode::Both,
            anomark_suspect_percent: 95.0,
            request: Default::default(),
            user_triage: RunUserTriage::default(),
            triage_precedent_ignore: vec![],
            sigma_stable_stats: None,
        }
    }

    #[test]
    fn triage_put_stamps_reviewed_at_on_new_verdict() {
        let dir = tempdir().expect("tempdir");
        let store =
            PlatformStore::load_or_create(dir.path().join("db.json").to_str().unwrap()).expect("store");
        let run_id = "r-review-1".to_string();
        let mut rec = run_record(&run_id);
        rec.user_triage = RunUserTriage {
            machines: vec![MachineTriageEntry {
                machine_id: "host-1".into(),
                reason_decisions: vec![],
                final_verdict: TriageVerdict::Unset,
            }],
        };
        store.db.write().runs.push(rec);
        store.save().expect("save");
        let triage = RunUserTriage {
            machines: vec![MachineTriageEntry {
                machine_id: "host-1".into(),
                reason_decisions: vec![ReasonTriageEntry {
                    detector: "sigma-zero".into(),
                    reason: "hit".into(),
                    verdict: TriageVerdict::FalsePositive,
                    reviewed_at: None,
                }],
                final_verdict: TriageVerdict::Unset,
            }],
        };
        store.update_run_user_triage(&run_id, triage).expect("put");
        let r = store.get_run(&run_id).expect("run");
        let e = r.user_triage.machines[0]
            .reason_decisions
            .iter()
            .find(|x| x.reason == "hit")
            .expect("row");
        assert!(
            e.reviewed_at.as_deref().unwrap_or("").len() >= 10,
            "expected RFC3339 reviewed_at"
        );
    }

    #[test]
    fn triage_put_preserves_reviewed_at_when_verdict_unchanged() {
        let dir = tempdir().expect("tempdir");
        let store =
            PlatformStore::load_or_create(dir.path().join("db.json").to_str().unwrap()).expect("store");
        let run_id = "r-review-2".to_string();
        let mut rec = run_record(&run_id);
        rec.user_triage = RunUserTriage {
            machines: vec![MachineTriageEntry {
                machine_id: "host-1".into(),
                reason_decisions: vec![ReasonTriageEntry {
                    detector: "sigma-zero".into(),
                    reason: "hit".into(),
                    verdict: TriageVerdict::FalsePositive,
                    reviewed_at: Some("2026-03-01T10:00:00Z".into()),
                }],
                final_verdict: TriageVerdict::Unset,
            }],
        };
        store.db.write().runs.push(rec);
        store.save().expect("save");
        let triage = RunUserTriage {
            machines: vec![MachineTriageEntry {
                machine_id: "host-1".into(),
                reason_decisions: vec![ReasonTriageEntry {
                    detector: "sigma-zero".into(),
                    reason: "hit".into(),
                    verdict: TriageVerdict::FalsePositive,
                    reviewed_at: None,
                }],
                final_verdict: TriageVerdict::Unset,
            }],
        };
        store.update_run_user_triage(&run_id, triage).expect("put");
        let r = store.get_run(&run_id).expect("run");
        let e = &r.user_triage.machines[0].reason_decisions[0];
        assert_eq!(e.reviewed_at.as_deref(), Some("2026-03-01T10:00:00Z"));
    }
}

#[cfg(test)]
mod findings_priority_sort_tests {
    use super::{sort_findings_by_review_priority, DetectionFinding};

    fn row(mid: &str, score: f64, severity: &str) -> DetectionFinding {
        DetectionFinding {
            machine_id: mid.into(),
            severity: severity.into(),
            score,
            reasons: vec![],
            detectors: vec![],
            dataset_tags: vec![],
            reasons_by_detector: vec![],
            sigma_matches: vec![],
        }
    }

    #[test]
    fn sorts_by_effective_score_most_severe_first() {
        let mut v = vec![
            row("low-host", 0.1, "LOW"),
            row("crit-host", 0.95, "CRITICAL"),
            row("mid-host", 0.45, "MEDIUM"),
        ];
        sort_findings_by_review_priority(&mut v);
        assert_eq!(
            v.iter().map(|f| f.machine_id.as_str()).collect::<Vec<_>>(),
            vec!["crit-host", "mid-host", "low-host"]
        );
    }

    #[test]
    fn tie_breaker_machine_id_when_score_equal() {
        let mut v = vec![row("zebra", 0.5, "MEDIUM"), row("alpha", 0.5, "MEDIUM")];
        sort_findings_by_review_priority(&mut v);
        assert_eq!(v[0].machine_id, "alpha");
        assert_eq!(v[1].machine_id, "zebra");
    }
}
