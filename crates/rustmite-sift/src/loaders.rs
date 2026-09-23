//! Data loaders: CSV/JSON and mock data.
//!
//! CSV and JSONL inputs use **streaming** (two-pass for process logs so PID→name is complete,
//! single-pass for file logs) to scale to millions of rows without holding the full dataset in RAM.

use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use log;

use crate::builder::{
    build_profiles, merge_log_into_profile, process_entry_passes_filters, ProcessBuilder,
};
use crate::config::DetectionConfig;
use crate::interner::{merge_pid_map_entry, SharedInterner};
use crate::file_analysis::{
    build_file_profiles, merge_file_log_into_profile, should_ingest_file_entry,
};
use crate::json_parse::{
    default_machine_fallback_for_source_file, parse_files_json_logs, parse_json_logs,
    parse_jsonl_process_line,
};
use crate::types::{MachineFileProfile, MachineProfile, RawFileEntry, RawLogEntry};
use crate::utils::{compile_regex_list, compile_wildcard_list, looks_like_kernel_thread_name};

pub fn load_csv_data(
    path: &str,
    config: &DetectionConfig,
) -> Result<Vec<MachineProfile>, Box<dyn Error>> {
    if !Path::new(path).exists() {
        return Err(format!("Input file not found: '{}'", path).into());
    }
    let metadata = fs::metadata(path)?;
    if metadata.len() == 0 {
        return Err(format!("Input file is empty: '{}'", path).into());
    }

    let interner = SharedInterner::default();
    let mut pid_to_name: HashMap<(Arc<str>, u32), Arc<str>> = HashMap::new();
    {
        let mut rdr = csv::Reader::from_path(path)?;
        for result in rdr.deserialize::<RawLogEntry>() {
            let entry = result?;
            merge_pid_map_entry(&interner, &mut pid_to_name, &entry);
        }
    }

    let whitelist_res = compile_wildcard_list(&config.whitelisted_path_patterns);
    let suspicious_path_res = compile_regex_list(&config.suspicious_path_patterns);
    let mut machine_profiles: HashMap<String, MachineProfile> = HashMap::new();
    let mut debug_keys: HashMap<String, HashMap<String, u32>> = HashMap::new();
    let mut row_count: u64 = 0;
    {
        let mut rdr = csv::Reader::from_path(path)?;
        for result in rdr.deserialize::<RawLogEntry>() {
            let entry = result?;
            row_count += 1;
            if !process_entry_passes_filters(&entry, config, &whitelist_res) {
                continue;
            }
            let mid = entry.machine_id.clone();
            let profile = machine_profiles
                .entry(mid.clone())
                .or_insert_with(|| MachineProfile::new(&mid));
            let pc = if config.debug_display {
                Some(debug_keys.entry(mid).or_default())
            } else {
                None
            };
            merge_log_into_profile(profile, &entry, &pid_to_name, config, &interner, pc, &suspicious_path_res);
        }
    }

    if machine_profiles.is_empty() {
        return Err(format!("No valid machine logs found in '{}'.", path).into());
    }

    log::info!(
        "Loaded {} CSV process rows into {} machine profiles (streaming)",
        row_count,
        machine_profiles.len()
    );

    let mut profiles: Vec<MachineProfile> = machine_profiles.into_values().collect();
    profiles.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(profiles)
}

pub fn load_json_data(
    path: &str,
    config: &DetectionConfig,
) -> Result<Vec<MachineProfile>, Box<dyn Error>> {
    if !Path::new(path).exists() {
        return Err(format!("Input file not found: '{}'", path).into());
    }
    let metadata = fs::metadata(path)?;
    if metadata.len() == 0 {
        return Err(format!("Input file is empty: '{}'", path).into());
    }
    let content = fs::read_to_string(path)?;
    let entries = parse_json_logs(&content)?;
    if entries.is_empty() {
        return Err(format!("No valid machine logs found in '{}'.", path).into());
    }
    log::info!("Loaded {} process entries from JSON", entries.len());
    Ok(build_profiles(entries, config))
}

/// Load process data from a JSONL file (one JSON object per line).
/// Format: `{"timestamp": "...", "event_type": "process", "user": "0", "command": "...", "pid": 1, "ppid": 0}`
/// Optional per-line: `machine_id`, `hostname`, `host`. If absent, uses `ingest_default_machine_id`
/// when set (dataset metadata / CLI parent-folder segment), otherwise the file stem.
pub fn load_jsonl_data(
    path: &str,
    config: &DetectionConfig,
    ingest_default_machine_id: Option<&str>,
) -> Result<Vec<MachineProfile>, Box<dyn Error>> {
    if !Path::new(path).exists() {
        return Err(format!("Input file not found: '{}'", path).into());
    }
    let metadata = fs::metadata(path)?;
    if metadata.len() == 0 {
        return Err(format!("Input file is empty: '{}'", path).into());
    }
    let default_machine_id =
        default_machine_fallback_for_source_file(path, ingest_default_machine_id);

    let interner = SharedInterner::default();
    let mut pid_to_name: HashMap<(Arc<str>, u32), Arc<str>> = HashMap::new();
    {
        let f = File::open(path)?;
        for line in BufReader::new(f).lines() {
            let line = line?;
            let t = line.trim();
            if t.is_empty() || t.starts_with("//") || t.starts_with('#') {
                continue;
            }
            match parse_jsonl_process_line(t, &default_machine_id) {
                Ok(entry) => merge_pid_map_entry(&interner, &mut pid_to_name, &entry),
                Err(e) => log::debug!("JSONL pid-map pass skipped line: {}", e),
            }
        }
    }

    let whitelist_res = compile_wildcard_list(&config.whitelisted_path_patterns);
    let suspicious_path_res = compile_regex_list(&config.suspicious_path_patterns);
    let mut machine_profiles: HashMap<String, MachineProfile> = HashMap::new();
    let mut debug_keys: HashMap<String, HashMap<String, u32>> = HashMap::new();
    let mut row_count: u64 = 0;
    let mut skipped_kernel_threads: u64 = 0;
    {
        let f = File::open(path)?;
        for line in BufReader::new(f).lines() {
            let line = line?;
            let t = line.trim();
            if t.is_empty() || t.starts_with("//") || t.starts_with('#') {
                continue;
            }
            let entry = match parse_jsonl_process_line(t, &default_machine_id) {
                Ok(e) => e,
                Err(e) => {
                    log::debug!("JSONL profile pass skipped line: {}", e);
                    continue;
                }
            };
            row_count += 1;
            if !process_entry_passes_filters(&entry, config, &whitelist_res) {
                if config.exclude_kernel_threads && looks_like_kernel_thread_name(&entry.name) {
                    skipped_kernel_threads += 1;
                }
                continue;
            }
            let mid = entry.machine_id.clone();
            let profile = machine_profiles
                .entry(mid.clone())
                .or_insert_with(|| MachineProfile::new(&mid));
            let pc = if config.debug_display {
                Some(debug_keys.entry(mid).or_default())
            } else {
                None
            };
            merge_log_into_profile(profile, &entry, &pid_to_name, config, &interner, pc, &suspicious_path_res);
        }
    }

    if machine_profiles.is_empty() {
        if row_count == 0 {
            return Err(format!(
                "No valid process lines found in '{}'. \
                 NDJSON rows need cmdline/command/Image/path, or name/ProcessName, or executable path (same rules as JSON batch). \
                 Run with RUST_LOG=debug to see per-line parse errors.",
                path
            )
            .into());
        }
        let kernel_hint = if skipped_kernel_threads > 0 {
            format!(
                " {} of those line(s) look like Linux kernel threads (names in [brackets], e.g. [kworker/0:0H]) and were skipped because exclude_kernel_threads is true (default). \
                 Re-run with --include-kernel-threads or set \"exclude_kernel_threads\": false in your config JSON.",
                skipped_kernel_threads
            )
        } else {
            String::new()
        };
        return Err(format!(
            "Parsed {} process line(s) from '{}' but none were kept for analysis.{} \
             Other reasons: exclude_init_children, or path whitelist filters.",
            row_count, path, kernel_hint
        )
        .into());
    }

    log::info!(
        "Loaded {} JSONL process rows into {} machine profiles (streaming, default machine_id: {})",
        row_count,
        machine_profiles.len(),
        default_machine_id
    );

    let mut profiles: Vec<MachineProfile> = machine_profiles.into_values().collect();
    profiles.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(profiles)
}

pub fn load_files_csv_data(
    path: &str,
    config: &DetectionConfig,
) -> Result<Vec<MachineFileProfile>, Box<dyn Error>> {
    if !Path::new(path).exists() {
        return Err(format!("Input file not found: '{}'", path).into());
    }
    let metadata = fs::metadata(path)?;
    if metadata.len() == 0 {
        return Err(format!("Input file is empty: '{}'", path).into());
    }

    let whitelist_res = compile_wildcard_list(&config.whitelisted_path_patterns);
    let path_exclude_res = compile_regex_list(&config.file_excluded_path_regexes);
    let filename_exclude_res = compile_regex_list(&config.file_excluded_filename_regexes);
    let suspicious_path_res = compile_regex_list(&config.suspicious_path_patterns);
    let interner = SharedInterner::default();

    let mut machine_profiles: HashMap<String, MachineFileProfile> = HashMap::new();
    let mut debug_keys: HashMap<String, HashMap<String, u32>> = HashMap::new();
    let mut row_count: u64 = 0;
    let mut rdr = csv::Reader::from_path(path)?;
    for result in rdr.deserialize::<RawFileEntry>() {
        let entry = result?;
        row_count += 1;
        if !should_ingest_file_entry(
            &entry,
            &path_exclude_res,
            &filename_exclude_res,
            &whitelist_res,
        ) {
            continue;
        }
        let mid = entry.machine_id.clone();
        let profile = machine_profiles
            .entry(mid.clone())
            .or_insert_with(|| MachineFileProfile::new(&mid));
        let fc = if config.debug_display {
            Some(debug_keys.entry(mid).or_default())
        } else {
            None
        };
        merge_file_log_into_profile(
            profile,
            &entry,
            config,
            &interner,
            fc,
            &path_exclude_res,
            &filename_exclude_res,
            &suspicious_path_res,
            &whitelist_res,
        );
    }

    machine_profiles.retain(|_, p| p.total_logs > 0);
    if machine_profiles.is_empty() {
        return Err(format!("No valid file access logs found in '{}'.", path).into());
    }

    log::info!(
        "Loaded {} CSV file rows into {} machine profiles (streaming)",
        row_count,
        machine_profiles.len()
    );

    let mut profiles: Vec<MachineFileProfile> = machine_profiles.into_values().collect();
    profiles.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(profiles)
}

pub fn load_files_json_data(
    path: &str,
    config: &DetectionConfig,
    ingest_default_machine_id: Option<&str>,
) -> Result<Vec<MachineFileProfile>, Box<dyn Error>> {
    if !Path::new(path).exists() {
        return Err(format!("Input file not found: '{}'", path).into());
    }
    let metadata = fs::metadata(path)?;
    if metadata.len() == 0 {
        return Err(format!("Input file is empty: '{}'", path).into());
    }
    let default_machine_id =
        default_machine_fallback_for_source_file(path, ingest_default_machine_id);
    let content = fs::read_to_string(path)?;
    let entries = parse_files_json_logs(&content, &default_machine_id)?;
    if entries.is_empty() {
        return Err(format!("No valid file access logs found in '{}'.", path).into());
    }
    log::info!("Loaded {} file access entries from JSON", entries.len());
    Ok(build_file_profiles(entries, config))
}

/// Load file access logs from JSONL (one JSON object per line). Same schema as JSON; `machine_id`
/// defaults to the file stem or `ingest_default_machine_id` when set.
pub fn load_files_jsonl_data(
    path: &str,
    config: &DetectionConfig,
    ingest_default_machine_id: Option<&str>,
) -> Result<Vec<MachineFileProfile>, Box<dyn Error>> {
    if !Path::new(path).exists() {
        return Err(format!("Input file not found: '{}'", path).into());
    }
    let metadata = fs::metadata(path)?;
    if metadata.len() == 0 {
        return Err(format!("Input file is empty: '{}'", path).into());
    }
    let default_machine_id =
        default_machine_fallback_for_source_file(path, ingest_default_machine_id);

    let whitelist_res = compile_wildcard_list(&config.whitelisted_path_patterns);
    let path_exclude_res = compile_regex_list(&config.file_excluded_path_regexes);
    let filename_exclude_res = compile_regex_list(&config.file_excluded_filename_regexes);
    let suspicious_path_res = compile_regex_list(&config.suspicious_path_patterns);
    let interner = SharedInterner::default();

    let mut machine_profiles: HashMap<String, MachineFileProfile> = HashMap::new();
    let mut debug_keys: HashMap<String, HashMap<String, u32>> = HashMap::new();
    let mut row_count: u64 = 0;
    let f = File::open(path)?;
    for line in BufReader::new(f).lines() {
        let line = line?;
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        let mut entry: RawFileEntry = match serde_json::from_str(t) {
            Ok(e) => e,
            Err(e) => {
                log::debug!("JSONL file line skipped: {}", e);
                continue;
            }
        };
        if entry.machine_id.is_empty() {
            entry.machine_id = default_machine_id.to_string();
        }
        row_count += 1;
        if !should_ingest_file_entry(
            &entry,
            &path_exclude_res,
            &filename_exclude_res,
            &whitelist_res,
        ) {
            continue;
        }
        let mid = entry.machine_id.clone();
        let profile = machine_profiles
            .entry(mid.clone())
            .or_insert_with(|| MachineFileProfile::new(&mid));
        let fc = if config.debug_display {
            Some(debug_keys.entry(mid).or_default())
        } else {
            None
        };
        merge_file_log_into_profile(
            profile,
            &entry,
            config,
            &interner,
            fc,
            &path_exclude_res,
            &filename_exclude_res,
            &suspicious_path_res,
            &whitelist_res,
        );
    }

    machine_profiles.retain(|_, p| p.total_logs > 0);
    if machine_profiles.is_empty() {
        return Err(format!("No valid file access lines found in '{}'.", path).into());
    }

    log::info!(
        "Loaded {} JSONL file rows into {} machine profiles (streaming, default machine_id: {})",
        row_count,
        machine_profiles.len(),
        default_machine_id
    );

    let mut profiles: Vec<MachineFileProfile> = machine_profiles.into_values().collect();
    profiles.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(profiles)
}

pub fn generate_mock_data(config: &DetectionConfig) -> Vec<MachineProfile> {
    let entries: Vec<RawLogEntry> = (0..50)
        .flat_map(|i| {
            let machine_id = format!("machine_{:02}", i);
            let mut logs = Vec::new();
            for j in 0..100 {
                logs.push(RawLogEntry {
                    machine_id: machine_id.clone(),
                    pid: 1000 + j,
                    ppid: 1,
                    name: "nginx".to_string(),
                    uid: 33,
                    path: "/usr/sbin/nginx".to_string(),
                    args: "-c /etc/nginx.conf".to_string(),
                    timestamp: None,
                });
            }
            if i == 13 {
                for j in 0..50 {
                    logs.push(RawLogEntry {
                        machine_id: machine_id.clone(),
                        pid: 2000 + j,
                        ppid: 1,
                        name: "kworker".to_string(),
                        uid: 0,
                        path: "/tmp/.hidden/miner".to_string(),
                        args: "XkzL1^s09f87aH@9#".to_string(),
                        timestamp: None,
                    });
                }
            }
            logs.push(RawLogEntry {
                machine_id: machine_id.clone(),
                pid: 1,
                ppid: 0,
                name: "systemd".to_string(),
                uid: 0,
                path: "/usr/lib/systemd/systemd".to_string(),
                args: "--system".to_string(),
                timestamp: None,
            });
            logs
        })
        .collect();
    build_profiles(entries, config)
}

pub fn build_profiles_simple(
    machine_processes: Vec<(String, String, String)>,
    config: &DetectionConfig,
) -> Vec<MachineProfile> {
    let mut builder = ProcessBuilder::new();
    for (machine_id, name, parent) in machine_processes {
        builder.add_process(&machine_id, &name, &parent);
    }
    let raw_entries = builder.build();
    build_profiles(raw_entries, config)
}
