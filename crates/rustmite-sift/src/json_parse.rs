//! JSON log parsing for process and file entries.

use std::error::Error;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;
use log;

use crate::types::{RawFileEntry, RawLogEntry};
use crate::utils::parse_command_line;

/// Process- vs file-inventory-like JSON shape (auto dataset kind + guarding file ingest).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonLineShape {
    Process,
    File,
}

/// Outcome of [`sniff_json_or_jsonl_dataset_kind`] when parser-backed sampling is applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonSniffDatasetKind {
    Process,
    File,
    /// At least one line parsed as process NDJSON and at least one as file inventory.
    Mixed,
}

/// Heuristic classification of one JSON value (osquery-style process vs file rows, vendor fields).
pub fn classify_json_line_shape(v: &serde_json::Value) -> JsonLineShape {
    let Some(obj) = v.as_object() else {
        return JsonLineShape::Process;
    };
    if obj.contains_key("cmdline")
        || obj.contains_key("command")
        || obj.contains_key("CommandLine")
        || obj.contains_key("ProcessCommandLine")
        || obj.contains_key("ParentCommandLine")
        || obj.contains_key("Image")
    {
        return JsonLineShape::Process;
    }
    if obj.contains_key("pid")
        || obj.contains_key("ppid")
        || obj.contains_key("parent")
    {
        return JsonLineShape::Process;
    }
    if let Some(et) = obj.get("event_type").and_then(|x| x.as_str()) {
        let el = et.to_ascii_lowercase();
        if el.contains("process") {
            return JsonLineShape::Process;
        }
        if el.contains("file") {
            return JsonLineShape::File;
        }
    }
    if obj.contains_key("file_path") {
        return JsonLineShape::File;
    }
    // `date` is omitted here: many process exports include a generic `date`/`timestamp` field; pairing
    // it with `path` (exe path) must not classify the row as file inventory.
    let has_pathish = obj.contains_key("path")
        || obj.contains_key("file_path")
        || (obj.contains_key("directory") && obj.contains_key("filename"));
    let has_file_meta = obj.contains_key("permissions")
        || obj.contains_key("mode")
        || obj.contains_key("size")
        || obj.contains_key("mtime");
    if has_pathish && has_file_meta {
        return JsonLineShape::File;
    }
    JsonLineShape::Process
}

const SNIFF_MAX_SMALL_FILE_BYTES: u64 = 16 * 1024 * 1024;
const SNIFF_MAX_LINES: usize = 2000;
const SNIFF_MAX_BYTES: u64 = 2 * 1024 * 1024;

fn decide_dataset_shape(proc: u32, file: u32) -> JsonLineShape {
    // Mixed NDJSON (both inventory and process-shaped rows): prefer process so Sigma/detection
    // use `processes`; file-only rows are skipped by the process parser.
    if proc > 0 && file > 0 {
        return JsonLineShape::Process;
    }
    if proc == 0 && file == 0 {
        return JsonLineShape::Process;
    }
    if proc > file {
        return JsonLineShape::Process;
    }
    if file > proc {
        return JsonLineShape::File;
    }
    JsonLineShape::Process
}

fn tally_shape(v: &serde_json::Value, proc: &mut u32, file: &mut u32) {
    if let Some(arr) = v.as_array() {
        for item in arr.iter().take(SNIFF_MAX_LINES) {
            match classify_json_line_shape(item) {
                JsonLineShape::Process => *proc += 1,
                JsonLineShape::File => *file += 1,
            }
        }
        return;
    }
    match classify_json_line_shape(v) {
        JsonLineShape::Process => *proc += 1,
        JsonLineShape::File => *file += 1,
    }
}

/// Host placeholder for [`parse_jsonl_process_line`] during sniff only.
const SNIFF_DEFAULT_MACHINE: &str = "__ironsift_sniff__";

/// Try the same parsers used at ingest: process NDJSON vs file inventory row.
fn sniff_one_line_for_kind(
    line: &str,
    proc_parse: &mut u32,
    file_parse: &mut u32,
    proc_shape: &mut u32,
    file_shape: &mut u32,
) {
    let t = line.trim();
    if t.is_empty() {
        return;
    }
    if parse_jsonl_process_line(t, SNIFF_DEFAULT_MACHINE).is_ok() {
        *proc_parse += 1;
        return;
    }
    if serde_json::from_str::<RawFileEntry>(t)
        .map(|e| !e.path.trim().is_empty())
        .unwrap_or(false)
    {
        *file_parse += 1;
        return;
    }
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(t) {
        tally_shape(&v, proc_shape, file_shape);
    }
}

fn finalize_sniff(
    proc_parse: u32,
    file_parse: u32,
    proc_shape: u32,
    file_shape: u32,
) -> JsonSniffDatasetKind {
    if proc_parse > 0 && file_parse > 0 {
        return JsonSniffDatasetKind::Mixed;
    }
    if proc_parse > 0 {
        return JsonSniffDatasetKind::Process;
    }
    if file_parse > 0 {
        return JsonSniffDatasetKind::File;
    }
    match decide_dataset_shape(proc_shape, file_shape) {
        JsonLineShape::Process => JsonSniffDatasetKind::Process,
        JsonLineShape::File => JsonSniffDatasetKind::File,
    }
}

/// Sample up to [`SNIFF_MAX_LINES`] lines / [`SNIFF_MAX_BYTES`] of a `.json` / `.jsonl` file.
/// Uses **the same parsers as ingestion** (`parse_jsonl_process_line`, `RawFileEntry`) when possible;
/// falls back to shape heuristics only for lines that match neither.
pub fn sniff_json_or_jsonl_dataset_kind(path: &Path) -> Result<JsonSniffDatasetKind, Box<dyn Error>> {
    let len = fs::metadata(path)?.len();
    if len <= SNIFF_MAX_SMALL_FILE_BYTES {
        let s = fs::read_to_string(path)?;
        let t = s.trim();
        if t.is_empty() {
            return Ok(JsonSniffDatasetKind::Process);
        }
        let mut proc_parse = 0u32;
        let mut file_parse = 0u32;
        let mut proc_shape = 0u32;
        let mut file_shape = 0u32;

        if let Ok(v) = serde_json::from_str::<serde_json::Value>(t) {
            if let Some(arr) = v.as_array() {
                for item in arr.iter().take(SNIFF_MAX_LINES) {
                    let line = serde_json::to_string(item)?;
                    sniff_one_line_for_kind(
                        &line,
                        &mut proc_parse,
                        &mut file_parse,
                        &mut proc_shape,
                        &mut file_shape,
                    );
                }
            } else {
                sniff_one_line_for_kind(
                    t,
                    &mut proc_parse,
                    &mut file_parse,
                    &mut proc_shape,
                    &mut file_shape,
                );
            }
            return Ok(finalize_sniff(
                proc_parse,
                file_parse,
                proc_shape,
                file_shape,
            ));
        }

        let mut scanned_lines = 0usize;
        let mut scanned_bytes: u64 = 0;
        for line in s.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("//") || line.starts_with('#') {
                continue;
            }
            scanned_lines += 1;
            scanned_bytes = scanned_bytes.saturating_add(line.len() as u64).saturating_add(1);
            if scanned_lines > SNIFF_MAX_LINES || scanned_bytes > SNIFF_MAX_BYTES {
                break;
            }
            sniff_one_line_for_kind(
                line,
                &mut proc_parse,
                &mut file_parse,
                &mut proc_shape,
                &mut file_shape,
            );
        }
        return Ok(finalize_sniff(
            proc_parse,
            file_parse,
            proc_shape,
            file_shape,
        ));
    }
    let f = File::open(path)?;
    let reader = BufReader::new(f);
    let mut proc_parse = 0u32;
    let mut file_parse = 0u32;
    let mut proc_shape = 0u32;
    let mut file_shape = 0u32;
    let mut scanned_lines = 0usize;
    let mut scanned_bytes: u64 = 0;
    for line in reader.lines() {
        let line = line?;
        let t = line.trim();
        if t.is_empty() || t.starts_with("//") || t.starts_with('#') {
            continue;
        }
        scanned_lines += 1;
        scanned_bytes = scanned_bytes.saturating_add(t.len() as u64).saturating_add(1);
        if scanned_lines > SNIFF_MAX_LINES || scanned_bytes > SNIFF_MAX_BYTES {
            break;
        }
        sniff_one_line_for_kind(
            t,
            &mut proc_parse,
            &mut file_parse,
            &mut proc_shape,
            &mut file_shape,
        );
    }
    Ok(finalize_sniff(
        proc_parse,
        file_parse,
        proc_shape,
        file_shape,
    ))
}

/// Default host label when a row has no `machine_id` / hostname fields: use `ingest_default_machine_id`
/// when non-empty (e.g. parent-folder segment from `ironsift --ingest-parent-tag-field`), otherwise the
/// source file stem.
pub fn default_machine_fallback_for_source_file(
    source_path: &str,
    ingest_default_machine_id: Option<&str>,
) -> String {
    let stem = Path::new(source_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("default");
    match ingest_default_machine_id.map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => s.to_string(),
        None => stem.to_string(),
    }
}

fn extract_string_field(data: &serde_json::Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(value) = data.get(key) {
            if let Some(s) = value.as_str() {
                return Some(s.to_string());
            }
        }
    }
    None
}

/// Command / executable string for JSONL process lines (flexible vendor keys).
fn extract_jsonl_command_string(data: &serde_json::Value) -> Option<String> {
    extract_string_field(
        data,
        &[
            "command",
            "cmd",
            "cmdline",
            "commandline",
            "CommandLine",
            "command_line",
            "ProcessCommandLine",
            "process_command_line",
            "ParentCommandLine",
            "parent_command_line",
            "Image",
            "image",
            "ImagePath",
            "exe",
            "executable",
            "path",
        ],
    )
}

/// Shared field resolution for process NDJSON and batch JSON (CLI + ingestion).
/// Unlike [`parse_json_log`], this does not require `machine_id` — callers supply a default for JSONL.
fn process_argv_from_vendor_json(data: &serde_json::Value) -> Result<(String, String, String), Box<dyn Error>> {
    let name_opt = extract_string_field(
        data,
        &["name", "process", "process_name", "comm", "ProcessName"],
    );
    let path_opt = extract_string_field(
        data,
        &["path", "exe", "executable", "Image", "image", "ImagePath"],
    );
    let args_opt = extract_string_field(data, &["args", "arguments", "params"]);
    if let (Some(n), Some(p), Some(a)) = (name_opt, path_opt, args_opt) {
        return Ok((n, p, a));
    }
    if let Some(command) = extract_jsonl_command_string(data) {
        return Ok(parse_command_line(&command));
    }
    if let Some(n) = extract_string_field(
        data,
        &["name", "process", "process_name", "comm", "ProcessName"],
    ) {
        return Ok((n.clone(), n, String::new()));
    }
    if let Some(p) = extract_string_field(
        data,
        &["path", "exe", "executable", "Image", "image", "ImagePath"],
    ) {
        let stem = Path::new(&p)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(p.as_str())
            .to_string();
        return Ok((stem, p, String::new()));
    }
    Err(
        "Missing process fields: need command/cmdline/CommandLine/Image/path, or name/ProcessName, or executable path"
            .into(),
    )
}

fn extract_u32_field(data: &serde_json::Value, keys: &[&str]) -> Option<u32> {
    for key in keys {
        if let Some(value) = data.get(key) {
            if let Some(num) = value.as_u64() {
                return Some(num as u32);
            }
            if let Some(s) = value.as_str() {
                if let Ok(num) = s.parse::<u32>() {
                    return Some(num);
                }
            }
        }
    }
    None
}

/// Parse process information from JSON string.
pub fn parse_json_log(json: &str) -> Result<RawLogEntry, Box<dyn Error>> {
    let data: serde_json::Value = serde_json::from_str(json)?;

    let machine_id = extract_string_field(
        &data,
        &["machine_id", "hostname", "host", "server", "node", "container", "pod"],
    )
    .ok_or("Missing machine identifier (need: machine_id, hostname, host, server, node, container, or pod)")?;

    let pid = extract_u32_field(&data, &["pid", "process_id"]).unwrap_or(0);
    let ppid = extract_u32_field(&data, &["ppid", "parent_pid", "parent"]).unwrap_or(0);

    let (name, path, args) = process_argv_from_vendor_json(&data)?;

    let uid = extract_u32_field(&data, &["uid", "user_id", "userid"]).unwrap_or(1000);
    let timestamp = extract_string_field(&data, &["timestamp", "time", "datetime", "start_time"]);

    Ok(RawLogEntry {
        machine_id,
        pid,
        ppid,
        name,
        uid,
        path,
        args,
        timestamp,
    })
}

/// Parse a batch of JSON log entries (NDJSON or JSON array).
pub fn parse_json_logs(json: &str) -> Result<Vec<RawLogEntry>, Box<dyn Error>> {
    let json = json.trim();
    if json.is_empty() {
        return Ok(Vec::new());
    }
    if json.starts_with('[') {
        let array: Vec<serde_json::Value> = serde_json::from_str(json)?;
        let mut entries = Vec::new();
        for value in array {
            let json_str = serde_json::to_string(&value)?;
            match parse_json_log(&json_str) {
                Ok(entry) => entries.push(entry),
                Err(e) => log::warn!("Failed to parse JSON entry: {}", e),
            }
        }
        return Ok(entries);
    }
    let mut entries = Vec::new();
    for line in json.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") || line.starts_with('#') {
            continue;
        }
        match parse_json_log(line) {
            Ok(entry) => entries.push(entry),
            Err(e) => log::warn!("Failed to parse JSON line: {}", e),
        }
    }
    Ok(entries)
}

/// Parse one line of JSONL process format:
/// `{"timestamp": "...", "event_type": "process", "user": "0", "command": "/sbin/init", "pid": 1, "ppid": 0}`
/// Optional per-line: `machine_id`, `hostname`, `host` (overrides default_machine_id).
pub fn parse_jsonl_process_line(
    line: &str,
    default_machine_id: &str,
) -> Result<RawLogEntry, Box<dyn Error>> {
    let data: serde_json::Value = serde_json::from_str(line.trim())?;
    let machine_id = extract_string_field(
        &data,
        &["machine_id", "hostname", "host", "server", "node"],
    )
    .unwrap_or_else(|| default_machine_id.to_string());

    let pid = extract_u32_field(&data, &["pid", "process_id"]).unwrap_or(0);
    let ppid = extract_u32_field(&data, &["ppid", "parent_pid", "parent"]).unwrap_or(0);
    let (name, path, args) = process_argv_from_vendor_json(&data)?;
    let uid = extract_u32_field(&data, &["uid", "user_id", "userid", "user"])
        .or_else(|| data.get("user").and_then(|v| v.as_str()).and_then(|s| s.parse::<u32>().ok()))
        .unwrap_or(1000);
    let timestamp = extract_string_field(&data, &["timestamp", "time", "datetime", "start_time"]);

    Ok(RawLogEntry {
        machine_id,
        pid,
        ppid,
        name,
        uid,
        path,
        args,
        timestamp,
    })
}

/// Parse JSONL content (one JSON object per line, process format).
/// Uses default_machine_id for lines that don't have machine_id/hostname/host.
pub fn parse_jsonl_logs(
    content: &str,
    default_machine_id: &str,
) -> Result<Vec<RawLogEntry>, Box<dyn Error>> {
    let mut entries = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") || line.starts_with('#') {
            continue;
        }
        match parse_jsonl_process_line(line, default_machine_id) {
            Ok(entry) => entries.push(entry),
            Err(e) => log::warn!("Failed to parse JSONL line: {} - {}", line, e),
        }
    }
    Ok(entries)
}

fn normalize_raw_file_entry(mut entry: RawFileEntry, default_machine_id: &str) -> RawFileEntry {
    if entry.machine_id.is_empty() {
        entry.machine_id = default_machine_id.to_string();
    }
    entry
}

/// Parse file access logs from JSON (array, single object, or NDJSON).
/// Lines without `machine_id` use `default_machine_id` (typically the input file stem).
pub fn parse_files_json_logs(
    content: &str,
    default_machine_id: &str,
) -> Result<Vec<RawFileEntry>, Box<dyn Error>> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    if let Ok(entries) = serde_json::from_str::<Vec<RawFileEntry>>(trimmed) {
        return Ok(entries
            .into_iter()
            .map(|e| normalize_raw_file_entry(e, default_machine_id))
            .collect());
    }
    if let Ok(entry) = serde_json::from_str::<RawFileEntry>(trimmed) {
        return Ok(vec![normalize_raw_file_entry(entry, default_machine_id)]);
    }
    let mut entries = Vec::new();
    for line in trimmed.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("Failed to parse JSON line: {} - {}", line, e);
                continue;
            }
        };
        if classify_json_line_shape(&v) == JsonLineShape::Process {
            log::debug!("Skipping process-shaped line in file JSONL batch");
            continue;
        }
        match serde_json::from_value::<RawFileEntry>(v) {
            Ok(entry) => entries.push(normalize_raw_file_entry(entry, default_machine_id)),
            Err(e) => log::warn!("Failed to parse JSON line: {} - {}", line, e),
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod shape_tests {
    use super::{
        classify_json_line_shape, parse_jsonl_process_line, sniff_json_or_jsonl_dataset_kind,
        JsonLineShape, JsonSniffDatasetKind,
    };
    use serde_json::json;
    use std::io::Write;

    #[test]
    fn event_type_process_is_process() {
        let v = json!({"event_type": "process_start", "pid": 4});
        assert_eq!(classify_json_line_shape(&v), JsonLineShape::Process);
    }

    #[test]
    fn jsonl_name_only_parses_like_batch_json() {
        let line = r#"{"pid":42,"parent":1,"name":"sshd"}"#;
        let e = parse_jsonl_process_line(line, "host-a").expect("name-only process line");
        assert_eq!(e.name, "sshd");
        assert_eq!(e.path, "sshd");
    }

    #[test]
    fn jsonl_image_only_parses() {
        let line = r#"{"pid":1,"Image":"C:\\Windows\\System32\\services.exe"}"#;
        let e = parse_jsonl_process_line(line, "host-a").expect("image-only");
        assert!(e.path.contains("services.exe"));
    }

    #[test]
    fn jsonl_linux_kworker_command_parses() {
        let line = r#"{"timestamp": "2026-04-27T00:10:05", "event_type": "process", "user": "0", "command": "[kworker/0:0H]", "pid": 5, "ppid": 2}"#;
        let e = parse_jsonl_process_line(line, "host-a").expect("kworker line");
        assert_eq!(e.pid, 5);
        assert_eq!(e.ppid, 2);
        assert_eq!(e.name, "[kworker/0:0H]");
        assert_eq!(e.uid, 0);
    }

    #[test]
    fn sniff_mixed_file_and_process_lines_is_mixed() {
        let mut tmp = tempfile::NamedTempFile::with_suffix(".jsonl").unwrap();
        writeln!(
            tmp,
            r#"{{"file_path":"/tmp/x","size":1,"permissions":"0644"}}"#
        )
        .unwrap();
        writeln!(tmp, r#"{{"cmdline":"/bin/sh","pid":1,"parent":0}}"#).unwrap();
        tmp.flush().unwrap();
        let k = sniff_json_or_jsonl_dataset_kind(tmp.path()).unwrap();
        assert_eq!(k, JsonSniffDatasetKind::Mixed);
    }

    #[test]
    fn sniff_pure_file_stays_file() {
        let mut tmp = tempfile::NamedTempFile::with_suffix(".jsonl").unwrap();
        for _ in 0..3 {
            writeln!(
                tmp,
                r#"{{"file_path":"/var/log/a.log","size":100,"permissions":"0644"}}"#
            )
            .unwrap();
        }
        tmp.flush().unwrap();
        let k = sniff_json_or_jsonl_dataset_kind(tmp.path()).unwrap();
        assert_eq!(k, JsonSniffDatasetKind::File);
    }

    #[test]
    fn sniff_process_and_file_inventory_is_mixed_even_if_file_lines_dominate() {
        let mut tmp = tempfile::NamedTempFile::with_suffix(".jsonl").unwrap();
        for i in 0..5 {
            writeln!(
                tmp,
                r#"{{"file_path":"/var/log/{}.log","size":100,"permissions":"0644"}}"#,
                i
            )
            .unwrap();
        }
        writeln!(tmp, r#"{{"command":"/usr/bin/whoami","pid":999,"ppid":1}}"#).unwrap();
        tmp.flush().unwrap();
        let k = sniff_json_or_jsonl_dataset_kind(tmp.path()).unwrap();
        assert_eq!(k, JsonSniffDatasetKind::Mixed);
    }
}
