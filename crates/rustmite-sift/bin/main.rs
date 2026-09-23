use std::error::Error;
use std::path::{Path, PathBuf};
use std::env;
use std::fs;

use env_logger::Env;
use log;

use rustmite_sift::{
    load_csv_data, load_json_data, load_jsonl_data, generate_mock_data, analyze_fleet,
    load_files_csv_data, load_files_json_data, load_files_jsonl_data, analyze_files_fleet,
    AnoMarkTestResult, DatasetKind, DetectionConfig, ParentDirTagRule, PlatformStore,
};

const DEFAULT_INPUT_CSV: &str = "test_dataset.csv";
const DEFAULT_INPUT_JSON: &str = "test_dataset.json";
const DEFAULT_INPUT_FILES_CSV: &str = "test_files_dataset.csv";
const DEFAULT_INPUT_FILES_JSON: &str = "test_files_dataset.json";
const CONFIG_FILE: &str = "ironsift_config.json";
const REPORT_OUTPUT: &str = "forensic_report.json";

fn print_usage() {
    println!("Usage: ironsift [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --input <file>        Input file (can be repeated); each JSONL file = one machine");
    println!("  --files               Analyze file access logs (instead of process logs)");
    println!("  --config <file>       Load configuration from JSON file");
    println!("  --export-json [path]  Export forensic report as JSON (default: forensic_report.json)");
    println!("                        Use '-' to write JSON to stdout (script-friendly)");
    println!("  -q, --quiet           Minimal output: one-line summary only (for pipelines)");
    println!("  --include-kernel-threads  Do not drop Linux kernel thread names like [kworker/0:0H]");
    println!("                        (default: exclude them; set exclude_kernel_threads=false)");
    println!("  --tolerance <value>   Override DBSCAN tolerance (default: from config, 0.35)");
    println!("  --help                Show this help message");
    println!();
    println!("Platform ingestion (web UI datasets / SQLite events):");
    println!("  --ingest-jsonl-dir <dir>  Recursively import every .jsonl file as a dataset");
    println!("  --platform-db <path>    Platform db.json (default: .ironsift-platform/db.json)");
    println!("  --tag <name>            Tag applied to every imported file (repeat for multiple)");
    println!("  --tags <a,b,c>          Comma-separated tags (same effect as repeated --tag)");
    println!("  --ingest-parent-tag-field <n>  Also tag each file from parent folder name: n-th");
    println!("                        segment (1-based) after splitting by delimiter (default -)");
    println!("  --ingest-parent-tag-delimiter <c>  Single character split (default: -); requires");
    println!("                        --ingest-parent-tag-field");
    println!("  --ingest-kind auto|process|file|mixed  Override per-file kind for --ingest-jsonl-dir");
    println!("                        (default auto: sniff uses the same parsers as ingest)");
    println!();
    println!("AnoMark test (score one command and/or ingested datasets against a model):");
    println!("  --anomark-test                 Run AnoMark in test mode and exit (no fleet analysis)");
    println!("  --anomark-command <text>       Command line to score (use quotes for full argv)");
    println!("  --anomark-machine <name>       Hostname/machine_id prefix for the scored line (matches fleet runs)");
    println!("  --anomark-model <path>         Explicit AnoMark .bin model file (wins over training/platform)");
    println!("  --anomark-train-id <uuid>      Score against a saved training model.bin (under .ironsift-platform/anomark-trains/<id>/)");
    println!("  --anomark-dataset <id>         Add an ingested dataset to score (repeatable)");
    println!("  --anomark-tags <a,b,c>         Pick datasets by tag (comma-separated)");
    println!("  --anomark-suspect-percent <p>  Suspect threshold percent of ln(prior) (55–99.999, default 95)");
    println!("  --anomark-json                 Print result as JSON instead of human-readable text");
    println!();
    println!("Supported Input Formats:");
    println!("  • CSV files (.csv)    - Process logs (RawLogEntry) or file logs (RawFileEntry)");
    println!("  • JSON files (.json)  - Process logs, or file logs (array / NDJSON / single object)");
    println!("  • JSONL files (.jsonl) - Process logs, or with --files: one JSON object per line (file_path, date, permissions, …)");
    println!();
    println!("Examples:");
    println!("  ironsift                           # Run with defaults (auto-detect input)");
    println!("  ironsift --input logs.json         # Process JSON log file");
    println!("  ironsift --input events.jsonl      # Process JSONL (one machine = one file)");
    println!("  ironsift --input a.jsonl --input b.jsonl  # Multiple JSONL = multiple machines");
    println!("  ironsift --files --input files.csv # Analyze file access logs");
    println!("  ironsift -q                        # Quiet: one-line summary only (script-friendly)");
    println!("  ironsift --export-json -           # Write JSON report to stdout (for piping)");
    println!("  ironsift --export-json report.json # Write JSON report to file");
    println!("  ironsift --tolerance 0.08          # Run with custom tolerance");
    println!("  ironsift --config custom.json      # Run with custom config");
    println!("  ironsift --ingest-jsonl-dir ./logs --tag baseline --tag jan2026");
    println!("  ironsift --ingest-jsonl-dir ./root --ingest-parent-tag-field 4 --tag baseline");
    println!("  ironsift --anomark-test --anomark-command \"/bin/bash -c id\" --anomark-machine web-01");
    println!("  ironsift --anomark-test --anomark-model models/baseline.bin --anomark-dataset <ds-id>");
    println!("  ironsift --anomark-test --anomark-tags baseline --anomark-suspect-percent 90 --anomark-json");
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    
    // Set log level to ERROR when quiet so progress is suppressed (must be before init)
    let quiet = args.iter().any(|a| a == "-q" || a == "--quiet")
        || args.windows(2).any(|w| {
            let a0 = w.get(0).and_then(|s| Some(s.as_str()));
            let a1 = w.get(1).and_then(|s| Some(s.as_str()));
            a0 == Some("--export-json") && a1 == Some("-")
        });
    if quiet {
        env::set_var("RUST_LOG", "error");
    }
    env_logger::Builder::from_env(Env::default().filter_or("RUST_LOG", if quiet { "error" } else { "info" }))
        .format_timestamp_secs()
        .format_target(false)
        .try_init()
        .ok();
    
    // Parse arguments
    let mut export_json_path: Option<String> = None; // None = don't export, Some(path) = export to path
    let mut analyze_files = false;
    let mut config = DetectionConfig::default();
    let mut config_path: Option<String> = None;
    let mut input_files: Vec<String> = Vec::new();
    let mut ingest_jsonl_dir: Option<String> = None;
    let mut platform_db: Option<String> = None;
    let mut ingest_tags: Vec<String> = Vec::new();
    let mut ingest_parent_tag_field: Option<usize> = None;
    let mut ingest_parent_tag_delimiter: Option<char> = None;
    let mut include_kernel_threads_cli = false;
    let mut ingest_kind_override: Option<DatasetKind> = None;

    let mut anomark_test = false;
    let mut anomark_command: Option<String> = None;
    let mut anomark_machine: Option<String> = None;
    let mut anomark_model_path: Option<String> = None;
    let mut anomark_train_id: Option<String> = None;
    let mut anomark_dataset_ids: Vec<String> = Vec::new();
    let mut anomark_tags: Vec<String> = Vec::new();
    let mut anomark_suspect_percent: f64 = 95.0;
    let mut anomark_json = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--help" => {
                print_usage();
                return Ok(());
            }
            "-q" | "--quiet" => {
                config.quiet = true;
            }
            "--include-kernel-threads" => {
                include_kernel_threads_cli = true;
            }
            "--export-json" => {
                i += 1;
                if i < args.len() && (args[i] == "-" || !args[i].starts_with('-')) {
                    export_json_path = Some(args[i].clone());
                } else {
                    if i < args.len() {
                        i -= 1;
                    }
                    export_json_path = Some(REPORT_OUTPUT.to_string());
                }
            }
            "--files" => {
                analyze_files = true;
            }
            "--input" => {
                i += 1;
                if i >= args.len() {
                    log::error!("--input requires a file path");
                    return Err("Missing input file path".into());
                }
                input_files.push(args[i].clone());
            }
            "--tolerance" => {
                i += 1;
                if i >= args.len() {
                    log::error!("--tolerance requires a value");
                    return Err("Missing tolerance value".into());
                }
                config.dbscan_tolerance = args[i].parse()
                    .map_err(|_| "Invalid tolerance value")?;
            }
            "--config" => {
                i += 1;
                if i >= args.len() {
                    log::error!("--config requires a file path");
                    return Err("Missing config file path".into());
                }
                config_path = Some(args[i].clone());
            }
            "--ingest-jsonl-dir" => {
                i += 1;
                if i >= args.len() {
                    log::error!("--ingest-jsonl-dir requires a directory path");
                    return Err("Missing directory path".into());
                }
                ingest_jsonl_dir = Some(args[i].clone());
            }
            "--platform-db" => {
                i += 1;
                if i >= args.len() {
                    log::error!("--platform-db requires a file path");
                    return Err("Missing platform db path".into());
                }
                platform_db = Some(args[i].clone());
            }
            "--tag" => {
                i += 1;
                if i >= args.len() {
                    log::error!("--tag requires a value");
                    return Err("Missing tag value".into());
                }
                ingest_tags.push(args[i].clone());
            }
            "--tags" => {
                i += 1;
                if i >= args.len() {
                    log::error!("--tags requires a value");
                    return Err("Missing tags value".into());
                }
                for part in args[i].split(',') {
                    let t = part.trim();
                    if !t.is_empty() {
                        ingest_tags.push(t.to_string());
                    }
                }
            }
            "--ingest-parent-tag-field" => {
                i += 1;
                if i >= args.len() {
                    log::error!("--ingest-parent-tag-field requires a positive integer (1 = first segment)");
                    return Err("Missing segment index".into());
                }
                let n: usize = args[i]
                    .parse()
                    .map_err(|_| "Invalid --ingest-parent-tag-field (use a positive integer, e.g. 4)")?;
                if n < 1 {
                    return Err("--ingest-parent-tag-field must be >= 1 (1 = first segment)".into());
                }
                ingest_parent_tag_field = Some(n);
            }
            "--ingest-parent-tag-delimiter" => {
                i += 1;
                if i >= args.len() {
                    log::error!("--ingest-parent-tag-delimiter requires one character");
                    return Err("Missing delimiter".into());
                }
                let s = args[i].as_str();
                let mut it = s.chars();
                let c = it.next().ok_or("Delimiter must not be empty")?;
                if it.next().is_some() {
                    return Err("--ingest-parent-tag-delimiter must be a single character".into());
                }
                ingest_parent_tag_delimiter = Some(c);
            }
            "--anomark-test" => {
                anomark_test = true;
            }
            "--anomark-command" => {
                i += 1;
                if i >= args.len() {
                    return Err("--anomark-command requires a value".into());
                }
                anomark_command = Some(args[i].clone());
            }
            "--anomark-machine" => {
                i += 1;
                if i >= args.len() {
                    return Err("--anomark-machine requires a value".into());
                }
                anomark_machine = Some(args[i].clone());
            }
            "--anomark-model" => {
                i += 1;
                if i >= args.len() {
                    return Err("--anomark-model requires a path".into());
                }
                anomark_model_path = Some(args[i].clone());
            }
            "--anomark-train-id" => {
                i += 1;
                if i >= args.len() {
                    return Err("--anomark-train-id requires a uuid".into());
                }
                anomark_train_id = Some(args[i].clone());
            }
            "--anomark-dataset" => {
                i += 1;
                if i >= args.len() {
                    return Err("--anomark-dataset requires a dataset id".into());
                }
                anomark_dataset_ids.push(args[i].clone());
            }
            "--anomark-tags" => {
                i += 1;
                if i >= args.len() {
                    return Err("--anomark-tags requires a comma-separated value".into());
                }
                for part in args[i].split(',') {
                    let t = part.trim();
                    if !t.is_empty() {
                        anomark_tags.push(t.to_string());
                    }
                }
            }
            "--anomark-suspect-percent" => {
                i += 1;
                if i >= args.len() {
                    return Err("--anomark-suspect-percent requires a value".into());
                }
                anomark_suspect_percent = args[i]
                    .parse()
                    .map_err(|_| "Invalid --anomark-suspect-percent (use a number, e.g. 95)")?;
            }
            "--anomark-json" => {
                anomark_json = true;
            }
            "--ingest-kind" => {
                i += 1;
                if i >= args.len() {
                    log::error!("--ingest-kind requires auto, process, file, or mixed");
                    return Err("Missing --ingest-kind value".into());
                }
                ingest_kind_override = match args[i].to_ascii_lowercase().as_str() {
                    "auto" => None,
                    "process" => Some(DatasetKind::Process),
                    "file" => Some(DatasetKind::File),
                    "mixed" => Some(DatasetKind::Mixed),
                    other => {
                        log::error!("--ingest-kind must be auto, process, file, or mixed (got {})", other);
                        return Err("Invalid --ingest-kind".into());
                    }
                };
            }
            other => {
                log::error!("Unknown option: {}", other);
                print_usage();
                return Err("Invalid argument".into());
            }
        }
        i += 1;
    }

    if ingest_jsonl_dir.is_some() && !input_files.is_empty() {
        return Err("--ingest-jsonl-dir cannot be combined with --input".into());
    }
    if ingest_jsonl_dir.is_some() && analyze_files {
        return Err("--ingest-jsonl-dir cannot be combined with --files".into());
    }
    if ingest_parent_tag_field.is_some() && ingest_jsonl_dir.is_none() {
        return Err("--ingest-parent-tag-field requires --ingest-jsonl-dir".into());
    }
    if ingest_parent_tag_delimiter.is_some() && ingest_parent_tag_field.is_none() {
        return Err("--ingest-parent-tag-delimiter requires --ingest-parent-tag-field".into());
    }

    let anomark_explicitly_used = anomark_command.is_some()
        || anomark_model_path.is_some()
        || anomark_train_id.is_some()
        || !anomark_dataset_ids.is_empty()
        || !anomark_tags.is_empty();
    if anomark_test || anomark_explicitly_used {
        if !anomark_test {
            log::info!("AnoMark flags supplied without --anomark-test; running test mode");
        }
        if anomark_command.is_none()
            && anomark_dataset_ids.is_empty()
            && anomark_tags.is_empty()
        {
            return Err(
                "--anomark-test needs at least one of --anomark-command, --anomark-dataset, or --anomark-tags"
                    .into(),
            );
        }
        let db_path = platform_db
            .clone()
            .unwrap_or_else(|| ".ironsift-platform/db.json".to_string());
        return run_anomark_test(
            &db_path,
            anomark_command.as_deref(),
            anomark_machine.as_deref(),
            anomark_model_path.as_deref(),
            anomark_train_id.as_deref(),
            &anomark_dataset_ids,
            &anomark_tags,
            anomark_suspect_percent,
            anomark_json,
            config.quiet,
        );
    }

    if let Some(dir) = ingest_jsonl_dir {
        let db = platform_db.unwrap_or_else(|| ".ironsift-platform/db.json".to_string());
        let store = PlatformStore::load_or_create(&db)?;
        let path = std::path::Path::new(&dir);
        if !path.is_dir() {
            return Err(format!("Not a directory: {}", dir).into());
        }
        let mut seen = std::collections::HashSet::<String>::new();
        ingest_tags.retain(|t| seen.insert(t.clone()));
        let parent_rule = ingest_parent_tag_field.map(|field| ParentDirTagRule {
            field,
            delimiter: ingest_parent_tag_delimiter.unwrap_or('-'),
        });
        let imported = store.import_jsonl_recursive(path, ingest_tags, parent_rule, ingest_kind_override)?;
        if !config.quiet {
            println!(
                "Imported {} dataset(s) into {}",
                imported.len(),
                db
            );
            for (d, s) in &imported {
                println!(
                    "  {}  {}  kind={}  processes={}  files={}  {:?}",
                    d.id,
                    d.name,
                    s.kind,
                    s.process_event_count,
                    s.file_event_count,
                    d.tags
                );
            }
        } else {
            for (d, _) in &imported {
                println!("{}", d.id);
            }
        }
        return Ok(());
    }
    
    // When writing JSON to stdout, suppress all other stdout so pipes get only JSON
    if export_json_path.as_deref() == Some("-") {
        config.quiet = true;
    }
    
    // Load config from file if specified
    if let Some(path) = config_path {
        log::info!("Loading configuration from: {}", path);
        config = DetectionConfig::from_file(&path)?;
    }
    if include_kernel_threads_cli {
        config.exclude_kernel_threads = false;
    }
    
    if !config.quiet {
        println!("{:=^60}", " IRONSIFT SECURITY ANALYZER ");
        println!();
        config.print();
        println!();
    }

    if analyze_files {
        // FILE-BASED ANALYSIS
        if !config.quiet {
            println!("📄 Analyzing FILE ACCESS logs");
            println!();
        }
        
        // 1. Ingest File Data - Support single/multiple CSV and JSON
        let file_profiles = if !input_files.is_empty() {
            let mut all: Vec<rustmite_sift::MachineFileProfile> = Vec::new();
            for input in &input_files {
                if !Path::new(input).exists() {
                    return Err(format!("Input file not found: {}", input).into());
                }
                log::info!("Loading file data from: {}", input);
                if input.ends_with(".json") {
                    all.extend(load_files_json_data(input, &config, None)?);
                } else if input.ends_with(".jsonl") {
                    all.extend(load_files_jsonl_data(input, &config, None)?);
                } else if input.ends_with(".csv") {
                    all.extend(load_files_csv_data(input, &config)?);
                } else {
                    return Err(format!(
                        "Unsupported file format for file analysis: {}. Use .csv, .json, or .jsonl",
                        input
                    )
                    .into());
                }
            }
            all
        } else {
            // Auto-detect default files
            if Path::new(DEFAULT_INPUT_FILES_JSON).exists() {
                log::info!("Loading file data from: {}", DEFAULT_INPUT_FILES_JSON);
                load_files_json_data(DEFAULT_INPUT_FILES_JSON, &config, None)?
            } else if Path::new(DEFAULT_INPUT_FILES_CSV).exists() {
                log::info!("Loading file data from: {}", DEFAULT_INPUT_FILES_CSV);
                load_files_csv_data(DEFAULT_INPUT_FILES_CSV, &config)?
            } else {
                return Err("No file dataset found. Use --input to specify a file, or generate one with: cargo run --bin generator -- --files".into());
            }
        };

        log::info!("Loaded {} machine file profiles", file_profiles.len());
        log::info!("Running DBSCAN clustering analysis on file access patterns");
        let report = analyze_files_fleet(&file_profiles, &config)?;
        
        // 3. Display Results (skip when writing JSON to stdout so pipe gets only JSON)
        if export_json_path.as_deref() != Some("-") {
            report.print_detailed(None);
        }

        // 4. Export JSON if requested (file analysis: not yet supported)
        if export_json_path.is_some() {
            log::warn!("JSON export for file analysis is not yet fully supported");
        }
    } else {
        // PROCESS-BASED ANALYSIS (original code)
        // Auto-detect file vs process data if CSV
        if !config.quiet {
            println!("🔍 Analyzing PROCESS logs");
            println!();
        }
        
        // 1. Ingest Data - Support single/multiple CSV, JSON, JSONL
        let profiles = if !input_files.is_empty() {
            // User specified input file(s) — each JSONL file = one machine when multiple files
            let mut all_profiles: Vec<rustmite_sift::MachineProfile> = Vec::new();
            for input in &input_files {
                if !Path::new(input).exists() {
                    return Err(format!("Input file not found: {}", input).into());
                }
                log::info!("Loading data from: {}", input);
                if input.ends_with(".jsonl") {
                    let file_profiles = load_jsonl_data(input, &config, None)?;
                    all_profiles.extend(file_profiles);
                } else if input.ends_with(".json") {
                    match load_json_data(input, &config) {
                        Ok(file_profiles) => all_profiles.extend(file_profiles),
                        Err(_) => {
                            log::info!("Detected file access data in JSON");
                            let file_profiles = load_files_json_data(input, &config, None)?;
                            log::info!("Loaded {} machine file profiles", file_profiles.len());
                            log::info!("Running DBSCAN clustering analysis on file access patterns");
                            let report = analyze_files_fleet(&file_profiles, &config)?;
                            if export_json_path.as_deref() != Some("-") {
                                report.print_detailed(None);
                            }
                            if export_json_path.is_some() {
                                log::warn!("JSON export for file analysis is not yet fully supported");
                            }
                            return Ok(());
                        }
                    }
                } else if input.ends_with(".csv") {
                    match detect_csv_type(input) {
                        Ok(true) => {
                            log::info!("Detected file access data in CSV");
                            let file_profiles = load_files_csv_data(input, &config)?;
                            log::info!("Loaded {} machine file profiles", file_profiles.len());
                            log::info!("Running DBSCAN clustering analysis on file access patterns");
                            let report = analyze_files_fleet(&file_profiles, &config)?;
                            if export_json_path.as_deref() != Some("-") {
                                report.print_detailed(None);
                            }
                            if export_json_path.is_some() {
                                log::warn!("JSON export for file analysis is not yet fully supported");
                            }
                            return Ok(());
                        }
                        Ok(false) => all_profiles.extend(load_csv_data(input, &config)?),
                        Err(e) => {
                            log::warn!("Could not detect CSV type, assuming process data: {}", e);
                            all_profiles.extend(load_csv_data(input, &config)?)
                        }
                    }
                } else {
                    return Err(format!("Unsupported file format: {}. Use .csv, .json, or .jsonl", input).into());
                }
            }
            if all_profiles.is_empty() {
                return Err("No valid machine profiles loaded from any input file".into());
            }
            all_profiles
        } else {
            // Auto-detect default files
            if Path::new(DEFAULT_INPUT_FILES_JSON).exists() {
                log::info!("Detected file access data: {}", DEFAULT_INPUT_FILES_JSON);
                let file_profiles = load_files_json_data(DEFAULT_INPUT_FILES_JSON, &config, None)?;
                log::info!("Loaded {} machine file profiles", file_profiles.len());
                log::info!("Running DBSCAN clustering analysis on file access patterns");
                let report = analyze_files_fleet(&file_profiles, &config)?;
                if export_json_path.as_deref() != Some("-") {
                    report.print_detailed(None);
                }
                if export_json_path.is_some() {
                    log::warn!("JSON export for file analysis is not yet fully supported");
                }
                return Ok(());
            } else if Path::new(DEFAULT_INPUT_FILES_CSV).exists() {
                log::info!("Detected file access data: {}", DEFAULT_INPUT_FILES_CSV);
                let file_profiles = load_files_csv_data(DEFAULT_INPUT_FILES_CSV, &config)?;
                log::info!("Loaded {} machine file profiles", file_profiles.len());
                log::info!("Running DBSCAN clustering analysis on file access patterns");
                let report = analyze_files_fleet(&file_profiles, &config)?;
                if export_json_path.as_deref() != Some("-") {
                    report.print_detailed(None);
                }
                if export_json_path.is_some() {
                    log::warn!("JSON export for file analysis is not yet fully supported");
                }
                return Ok(());
            } else if Path::new(DEFAULT_INPUT_JSON).exists() {
                log::info!("Loading data from: {}", DEFAULT_INPUT_JSON);
                load_json_data(DEFAULT_INPUT_JSON, &config)?
            } else if Path::new(DEFAULT_INPUT_CSV).exists() {
                log::info!("Loading data from: {}", DEFAULT_INPUT_CSV);
                match detect_csv_type(DEFAULT_INPUT_CSV) {
                    Ok(true) => {
                        log::info!("Detected file access data in CSV");
                        let file_profiles = load_files_csv_data(DEFAULT_INPUT_CSV, &config)?;
                        log::info!("Loaded {} machine file profiles", file_profiles.len());
                        log::info!("Running DBSCAN clustering analysis on file access patterns");
                        let report = analyze_files_fleet(&file_profiles, &config)?;
                        if export_json_path.as_deref() != Some("-") {
                            report.print_detailed(None);
                        }
                        if export_json_path.is_some() {
                            log::warn!("JSON export for file analysis is not yet fully supported");
                        }
                        return Ok(());
                    }
                    _ => load_csv_data(DEFAULT_INPUT_CSV, &config)?,
                }
            } else {
                log::info!("No dataset found, generating mock data");
                generate_mock_data(&config)
            }
        };

        log::info!("Loaded {} machine profiles", profiles.len());
        log::info!("Running DBSCAN clustering analysis");
        let report = analyze_fleet(&profiles, &config)?;
        
        if export_json_path.as_deref() != Some("-") {
            report.print_detailed(Some(&profiles));
        }
        if let Some(path) = &export_json_path {
            report.export_json(&profiles, path)?;
        }
    }

    if !Path::new(CONFIG_FILE).exists() {
        config.to_file(CONFIG_FILE)?;
        log::info!("Configuration saved to: {} (edit to customize detection parameters)", CONFIG_FILE);
    }

    Ok(())
}

fn run_anomark_test(
    platform_db: &str,
    command: Option<&str>,
    machine: Option<&str>,
    model_path: Option<&str>,
    train_id: Option<&str>,
    dataset_ids: &[String],
    tags: &[String],
    suspect_percent: f64,
    as_json: bool,
    quiet: bool,
) -> Result<(), Box<dyn Error>> {
    let store = PlatformStore::load_or_create(platform_db)?;
    let explicit = model_path.map(PathBuf::from);
    let result = store.test_anomark_cli(
        explicit.as_deref(),
        train_id,
        command,
        machine,
        dataset_ids,
        tags,
        suspect_percent,
    )?;
    if as_json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        print_anomark_test_human(&result, quiet);
    }
    Ok(())
}

fn print_anomark_test_human(r: &AnoMarkTestResult, quiet: bool) {
    if !quiet {
        println!("{:=^60}", " ANOMARK TEST ");
    }
    println!("Model:                {}", r.model_path);
    println!("Source:               {}", r.model_source);
    println!(
        "Order / prior_ln:     {} / {:.6}",
        r.model_order, r.model_prior_ln
    );
    println!(
        "Suspect % (used):     {:.3}    threshold_ln: {:.6}",
        r.suspect_percent_used, r.suspect_threshold_ln
    );
    if let Some(cs) = &r.command_score {
        println!();
        println!("--- Command score ---");
        println!("Scored line:          {}", cs.line_scored);
        println!("log_likelihood:       {:.6}", cs.log_likelihood);
        println!(
            "margin_ln:            {:.6}   ({} threshold)",
            cs.margin_ln,
            if cs.margin_ln >= 0.0 { ">=" } else { "<" }
        );
        println!(
            "Verdict:              {}",
            if cs.is_suspect {
                "SUSPECT"
            } else {
                "not suspect"
            }
        );
    }
    if !r.datasets.is_empty() || !r.datasets_skipped.is_empty() {
        println!();
        println!("--- Datasets ---");
    }
    for d in &r.datasets {
        let global_ratio = if d.commands_scored == 0 {
            0.0
        } else {
            d.suspect_commands as f64 / d.commands_scored as f64
        };
        println!(
            "{}  ({})    cmds={}    suspect={}    ratio={:.3}",
            d.dataset_id, d.dataset_name, d.commands_scored, d.suspect_commands, global_ratio
        );
        for hs in &d.host_stats {
            println!(
                "    host={:<32}  cmds={:>7}  suspect={:>7}  ratio={:.3}",
                hs.host, hs.commands, hs.suspect, hs.ratio
            );
        }
    }
    if !r.datasets_skipped.is_empty() {
        println!();
        println!(
            "Skipped {} non-process dataset(s):",
            r.datasets_skipped.len()
        );
        for s in &r.datasets_skipped {
            println!("  - {}", s);
        }
    }
}

/// Detect if a CSV file contains file entries or process entries by checking the header
fn detect_csv_type(path: &str) -> Result<bool, Box<dyn Error>> {
    use std::io::BufRead;
    use std::io::BufReader;
    
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut first_line = String::new();
    reader.read_line(&mut first_line)?;
    
    let header = first_line.trim().to_lowercase();
    
    // File entries have: machine_id,path,uid,timestamp (no pid, ppid, name, args)
    // Process entries have: machine_id,pid,ppid,name,uid,path,args,timestamp
    if header.contains("path") && !header.contains("pid") && !header.contains("name") && !header.contains("args") {
        Ok(true)  // File data
    } else if header.contains("pid") || header.contains("name") || header.contains("args") {
        Ok(false)  // Process data
    } else {
        // Default to process data for backward compatibility
        Ok(false)
    }
}