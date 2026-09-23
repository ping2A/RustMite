//! IronSift: fleet-wide anomaly detection for process and file access logs.
//!
//! Vendored from [ping2A/IronSift](https://github.com/ping2A/IronSift) into RustMite
//! as `rustmite-sift` (TF-IDF + DBSCAN fleet clustering, file mode, temporal diffs).
//! Command-line Markov scoring uses [`rustmite_anomark`]. RustMite detection rules
//! (checks / RPL) replace IronSift's Sigma path.

mod config;
mod interner;
mod utils;
mod types;
mod report;
mod json_parse;
mod builder;
mod analysis;
mod file_analysis;
mod temporal;
mod loaders;
mod osquery;
mod platform;
mod sigma_log_export;
mod event_db;
mod osquery_event_ddl;
pub mod adapters;

// Re-export public API
pub use config::{DetectionConfig, FileRecentMtimeConfig};
pub use interner::SharedInterner;
pub use types::{
    FileSignature, MachineFileProfile, MachineProfile, ProcessEntry, ProcessSignature,
    RawConnectionEntry, RawFileEntry, RawLogEntry,
};
pub use report::{
    AnalysisReport, AnalysisType, AnomalyDetails, AnomalyLevel,
};
pub use utils::{
    calculate_shannon_entropy, compile_regex_list, compile_wildcard_list,
    file_path_matches_exclusion, is_path_suspicious, is_path_suspicious_compiled,
    is_path_whitelisted, is_path_whitelisted_compiled, looks_like_kernel_thread_name,
    matches_wildcard, parse_command_line, parse_log_datetime, unix_permission_flags,
};
pub use json_parse::{
    classify_json_line_shape, default_machine_fallback_for_source_file, parse_files_json_logs,
    parse_json_log, parse_json_logs, parse_jsonl_logs, parse_jsonl_process_line,
    sniff_json_or_jsonl_dataset_kind, JsonLineShape, JsonSniffDatasetKind,
};
pub use builder::{build_profiles, resolve_parent_names, ProcessBuilder};
pub use analysis::{analyze_fleet, analyze_fleet2};
pub use file_analysis::{
    analyze_files_fleet, build_file_profiles, build_file_profiles_from_grouped,
    should_ingest_file_entry,
};
pub use temporal::{
    build_machine_snapshot, compare_temporal, compare_temporal_series,
    MachineSnapshot, TemporalDiff,
};
pub use loaders::{
    build_profiles_simple, generate_mock_data, load_csv_data, load_files_csv_data,
    load_files_json_data, load_files_jsonl_data, load_json_data, load_jsonl_data,
};
pub use osquery::{normalize_osquery_file_row, normalize_osquery_process_row};
pub use platform::{
    AnoMarkAvailability, AnoMarkCommandScore, AnoMarkModelInspection, AnoMarkSettings,
    AnoMarkTestDatasetHostStat, AnoMarkTestDatasetSummary, AnoMarkTestResult,
    AnoMarkTrainRecord,
    AnoMarkTrainRequest, AnoMarkTrainResult, AnoMarkTrainingAvailability, AnoMarkWhereGenerated,
    CreateDatasetRequest, CreateDetectionConfigRequest, CreateRunRequest, DatasetKind,
    DeleteDatasetEventsRequest,
    RunDetectionFocus, RunDetectorMode,
    DatasetRecord, DetectionFinding, DetectionRunRecord, DetectionRunRequestSnapshot,
    DetectionRunSigmaStats,
    DetectorReasons, FleetTriagePrecedentEntry, HistoricalReasonVerdict, HoneycombCell,
    MachineTriageEntry,
    ReasonPrecedentKey, ReasonTriageEntry, RunUserTriage, TriagePrecedentBundle, TriageVerdict,
    ParentDirTagRule,
    PlatformStore, SelectDetectionConfigRequest, SigmaRuleInline, SigmaStableRuleRef,
    SigmaZeroCheckRequest, SigmaZeroCheckResult, SigmaZeroEvaluationStats, SigmaZeroSettings,
    UpdateDetectionConfigRequest,
    parent_dir_segment_tag,
};
pub use event_db::DetectionConfigProfileMeta;
pub use event_db::DATASET_INSPECT_MAX_SAMPLE;
pub use event_db::DELETE_DATASET_EVENTS_MAX_IDS;
pub use event_db::DatasetInspection;
pub use event_db::EventDb;
pub use event_db::IngestSummary;
pub use adapters::rustmite::{
    observations_to_connections, observations_to_file_logs, observations_to_process_logs,
    process_obs_to_raw,
};

#[cfg(test)]
mod tests;
