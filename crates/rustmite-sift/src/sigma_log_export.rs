//! Convert IronSift process dataset files to JSONL for the [sigmazero](https://github.com/ping2A/sigmazero) engine
//! (`LogEntry` / `evaluate_log_line`). Each line includes Sigma-friendly names (`process_name`, `command_line`)
//! and **osquery 5.22.1 `processes`-aligned** aliases (`name`, `path`, `cmdline`, `parent`, `pid`, …) so rules
//! can match the same field names as SQLite ingestion / `processes` in the event DB.

use std::error::Error;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};

use log;
use crate::json_parse::{
    classify_json_line_shape, default_machine_fallback_for_source_file, parse_files_json_logs,
    parse_json_log, parse_jsonl_process_line, JsonLineShape,
};
use crate::types::{RawFileEntry, RawLogEntry};

/// Same flexibility as ingestion: accept full `parse_json_log` rows, or JSONL process lines
/// (`command` + optional host) with a default `machine_id` derived from the source file path
/// when host is missing — otherwise Sigma export drops every line that ingested successfully.
fn parse_line_for_sigma_export(source_path: &str, line: &str) -> Result<RawLogEntry, Box<dyn Error>> {
    let fb = default_machine_fallback_for_source_file(source_path, None);
    parse_json_log(line).or_else(|_| parse_jsonl_process_line(line, &fb))
}

fn command_line_str(e: &RawLogEntry) -> String {
    if !e.path.is_empty() {
        if e.args.is_empty() {
            e.path.clone()
        } else {
            format!("{} {}", e.path, e.args)
        }
    } else {
        e.name.clone()
    }
}

/// Same shape as [`raw_to_sigma_json`], from a row in the ingested `processes` SQLite table (`cmdline` stored verbatim).
///
/// `dataset_id` is emitted as `ironsift_dataset_id` so Sigma matches can be merged into the same
/// namespaced host keys as multi-dataset detection runs (`dataset_id/logical_host`).
pub fn sigma_json_from_ingested_sql_row(
    dataset_id: &str,
    machine_id: &str,
    pid: i64,
    name: &str,
    path: &str,
    cmdline: &str,
    uid: i64,
    parent: i64,
    start_time: Option<i64>,
) -> serde_json::Value {
    let pid_u = pid.max(0) as u64;
    let uid_u = uid.max(0) as u32;
    let ppid_u = parent.max(0) as u32;
    let timestamp = start_time.map(|e| e.to_string());
    let mut v = serde_json::json!({
        "machine_id": machine_id,
        "event_type": "process_creation",
        "process_name": name,
        "command_line": cmdline,
        "cmdline": cmdline,
        "name": name,
        "path": path,
        "pid": pid_u,
        "parent": ppid_u,
        "ppid": ppid_u,
        "uid": uid_u,
        "timestamp": timestamp,
    });
    let ds = dataset_id.trim();
    if !ds.is_empty() {
        v.as_object_mut()
            .expect("object")
            .insert("ironsift_dataset_id".into(), serde_json::json!(ds));
    }
    v
}

/// One JSON line per **file inventory** row (`RawFileEntry` / SQLite `file` table): Sigma-friendly and
/// osquery **`file` table-aligned** field names so rules can target `file_path`, `path`,
/// `TargetFilename`, `permissions`, `mode`, etc.
pub fn sigma_json_from_ingested_file_sql_row(
    machine_id: &str,
    path: &str,
    directory: Option<&str>,
    filename: Option<&str>,
    uid: i64,
    mode: Option<&str>,
    size: Option<i64>,
    mtime: Option<i64>,
    atime: Option<i64>,
    ironsift_dataset_id: Option<&str>,
) -> serde_json::Value {
    let uid_u = uid.max(0) as u64;
    let dir_s = directory.unwrap_or("");
    let name_s = filename.unwrap_or("");
    let mode_s = mode.unwrap_or("");
    let mut v = serde_json::json!({
        "machine_id": machine_id,
        "event_type": "file_information",
        "file_path": path,
        "path": path,
        "TargetFilename": path,
        "directory": dir_s,
        "filename": name_s,
        "uid": uid_u,
        "permissions": mode_s,
        "mode": mode_s,
    });
    let obj = v.as_object_mut().expect("object");
    if let Some(sz) = size {
        if sz >= 0 {
            obj.insert("size".into(), serde_json::json!(sz));
        }
    }
    if let Some(mt) = mtime {
        obj.insert("mtime".into(), serde_json::json!(mt));
    }
    if let Some(at) = atime {
        obj.insert("atime".into(), serde_json::json!(at));
    }
    if let Some(ds) = ironsift_dataset_id.map(str::trim).filter(|s| !s.is_empty()) {
        obj.insert("ironsift_dataset_id".into(), serde_json::json!(ds));
    }
    v
}

pub fn raw_file_to_sigma_json(e: &RawFileEntry, ironsift_dataset_id: Option<&str>) -> serde_json::Value {
    let path = e.path.as_str();
    let derived_dir = std::path::Path::new(path)
        .parent()
        .and_then(|p| p.to_str())
        .unwrap_or("");
    let derived_name = std::path::Path::new(path)
        .file_name()
        .and_then(|p| p.to_str())
        .unwrap_or("");
    let dir_s = if derived_dir.is_empty() {
        None
    } else {
        Some(derived_dir)
    };
    let name_s = if derived_name.is_empty() {
        None
    } else {
        Some(derived_name)
    };
    let mut v = sigma_json_from_ingested_file_sql_row(
        &e.machine_id,
        path,
        dir_s,
        name_s,
        i64::from(e.uid),
        e.permissions.as_deref(),
        e.size.map(|s| s as i64),
        None,
        None,
        ironsift_dataset_id,
    );
    if let Some(obj) = v.as_object_mut() {
        if let Some(ref m) = e.mtime {
            let t = m.trim();
            if !t.is_empty() {
                obj.insert("mtime".into(), serde_json::json!(t));
            }
        }
        if let Some(ref a) = e.timestamp {
            let t = a.trim();
            if !t.is_empty() {
                obj.insert("atime".into(), serde_json::json!(t));
            }
        }
    }
    v
}

/// One JSON line per process event: Sigma synonyms plus osquery `processes` column names where they overlap.
pub fn raw_to_sigma_json(e: &RawLogEntry, ironsift_dataset_id: Option<&str>) -> serde_json::Value {
    let cmd = command_line_str(e);
    let mut v = serde_json::json!({
        "machine_id": e.machine_id,
        "event_type": "process_creation",
        "process_name": e.name,
        "command_line": cmd,
        "cmdline": cmd,
        "name": e.name,
        "path": e.path,
        "pid": e.pid,
        "parent": e.ppid,
        "ppid": e.ppid,
        "uid": e.uid,
        "timestamp": e.timestamp,
    });
    if let Some(ds) = ironsift_dataset_id.map(str::trim).filter(|s| !s.is_empty()) {
        v.as_object_mut()
            .expect("object")
            .insert("ironsift_dataset_id".into(), serde_json::json!(ds));
    }
    v
}

/// Export process log files to a single JSONL file. Each `sources` entry is `(source_path, format)` where
/// `format` is a lowercase file extension, e.g. `jsonl`, `json`, `csv`.
///
/// Prefer [`export_process_sources_to_sigma_jsonl_writer`] when appending into an existing export stream.
#[allow(dead_code)] // Convenience API + unit tests; merged Sigma checks use the `_writer` helper.
pub fn export_process_sources_to_sigma_jsonl(
    sources: &[(String, String)],
    out_path: &std::path::Path,
) -> Result<u64, Box<dyn Error>> {
    let mut out = File::create(out_path)?;
    export_process_sources_to_sigma_jsonl_writer(sources, &mut out, None)
}

/// Append Sigma JSONL from on-disk process logs into an existing writer (used to merge SQLite + file exports per dataset).
pub fn export_process_sources_to_sigma_jsonl_writer<W: Write>(
    sources: &[(String, String)],
    w: &mut W,
    ironsift_dataset_id: Option<&str>,
) -> Result<u64, Box<dyn Error>> {
    let mut total: u64 = 0;
    for (path, ext) in sources {
        let n = match ext.as_str() {
            "csv" => write_csv(path, w, ironsift_dataset_id)?,
            "json" => write_json_file(path, w, ironsift_dataset_id)?,
            "jsonl" => write_jsonl(path, w, ironsift_dataset_id)?,
            other => {
                return Err(format!(
                    "unsupported format for Sigma export: {} (path {})",
                    other, path
                )
                .into());
            }
        };
        total += n;
    }
    Ok(total)
}

/// Append Sigma JSONL from on-disk **file inventory** logs ([`RawFileEntry`] / osquery `file`-like NDJSON).
pub fn export_file_sources_to_sigma_jsonl_writer<W: Write>(
    sources: &[(String, String)],
    w: &mut W,
    ironsift_dataset_id: Option<&str>,
) -> Result<u64, Box<dyn Error>> {
    let mut total: u64 = 0;
    for (path, ext) in sources {
        let n = match ext.as_str() {
            "csv" => write_file_csv(path, w, ironsift_dataset_id)?,
            "json" => write_file_json_file(path, w, ironsift_dataset_id)?,
            "jsonl" => write_file_jsonl(path, w, ironsift_dataset_id)?,
            other => {
                return Err(format!(
                    "unsupported format for Sigma file export: {} (path {})",
                    other, path
                )
                .into());
            }
        };
        total += n;
    }
    Ok(total)
}

fn normalize_file_machine(mut e: RawFileEntry, default_mid: &str) -> RawFileEntry {
    if e.machine_id.is_empty() {
        e.machine_id = default_mid.to_string();
    }
    e
}

fn write_file_line<W: Write>(
    w: &mut W,
    e: &RawFileEntry,
    ironsift_dataset_id: Option<&str>,
) -> std::io::Result<()> {
    let s = serde_json::to_string(&raw_file_to_sigma_json(e, ironsift_dataset_id)).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
    })?;
    writeln!(w, "{}", s)
}

fn write_file_jsonl<W: Write>(
    path: &str,
    w: &mut W,
    ironsift_dataset_id: Option<&str>,
) -> Result<u64, Box<dyn Error>> {
    let fb = default_machine_fallback_for_source_file(path, None);
    let f = File::open(path)?;
    let mut reader = BufReader::with_capacity(1024 * 1024, f);
    let mut n: u64 = 0;
    let mut line = String::new();
    loop {
        line.clear();
        let bytes = reader.read_line(&mut line)?;
        if bytes == 0 {
            break;
        }
        let t = line.trim();
        if t.is_empty() || t.starts_with("//") || t.starts_with('#') {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(t) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("Sigma file export skipped line in {}: {}", path, e);
                continue;
            }
        };
        if classify_json_line_shape(&v) == JsonLineShape::Process {
            continue;
        }
        match serde_json::from_value::<RawFileEntry>(v) {
            Ok(e) => {
                let e = normalize_file_machine(e, &fb);
                if e.path.is_empty() {
                    continue;
                }
                write_file_line(w, &e, ironsift_dataset_id)?;
                n += 1;
            }
            Err(e) => log::warn!("Sigma file export skipped line in {}: {}", path, e),
        }
    }
    Ok(n)
}

fn write_file_json_file<W: Write>(
    path: &str,
    w: &mut W,
    ironsift_dataset_id: Option<&str>,
) -> Result<u64, Box<dyn Error>> {
    let fb = default_machine_fallback_for_source_file(path, None);
    let content = fs::read_to_string(path)?;
    let entries = parse_files_json_logs(content.trim(), &fb)?;
    let mut n: u64 = 0;
    for e in entries {
        if e.path.is_empty() {
            continue;
        }
        write_file_line(w, &e, ironsift_dataset_id)?;
        n += 1;
    }
    Ok(n)
}

fn write_file_csv<W: Write>(
    path: &str,
    w: &mut W,
    ironsift_dataset_id: Option<&str>,
) -> Result<u64, Box<dyn Error>> {
    use csv::Reader;
    let mut n: u64 = 0;
    let mut rdr = Reader::from_path(path)?;
    for result in rdr.deserialize::<RawFileEntry>() {
        let e = result?;
        if e.path.is_empty() {
            continue;
        }
        write_file_line(w, &e, ironsift_dataset_id)?;
        n += 1;
    }
    Ok(n)
}

fn write_line<W: Write>(
    w: &mut W,
    e: &RawLogEntry,
    ironsift_dataset_id: Option<&str>,
) -> std::io::Result<()> {
    let s = serde_json::to_string(&raw_to_sigma_json(e, ironsift_dataset_id)).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
    })?;
    writeln!(w, "{}", s)
}

fn write_jsonl<W: Write>(
    path: &str,
    w: &mut W,
    ironsift_dataset_id: Option<&str>,
) -> Result<u64, Box<dyn Error>> {
    let f = File::open(path)?;
    let mut reader = BufReader::with_capacity(1024 * 1024, f);
    let mut n: u64 = 0;
    let mut line = String::new();
    loop {
        line.clear();
        let bytes = reader.read_line(&mut line)?;
        if bytes == 0 {
            break;
        }
        let t = line.trim();
        if t.is_empty() || t.starts_with("//") || t.starts_with('#') {
            continue;
        }
        match parse_line_for_sigma_export(path, t) {
            Ok(e) => {
                write_line(w, &e, ironsift_dataset_id)?;
                n += 1;
            }
            Err(e) => {
                log::warn!("Sigma export skipped line in {}: {}", path, e);
            }
        }
    }
    Ok(n)
}

fn write_json_file<W: Write>(
    path: &str,
    w: &mut W,
    ironsift_dataset_id: Option<&str>,
) -> Result<u64, Box<dyn Error>> {
    let content = fs::read_to_string(path)?;
    let json = content.trim();
    if json.is_empty() {
        return Ok(0);
    }
    let mut n: u64 = 0;
    if json.starts_with('[') {
        let array: Vec<serde_json::Value> = serde_json::from_str(json)?;
        for value in array {
            let line = serde_json::to_string(&value)?;
            match parse_line_for_sigma_export(path, &line) {
                Ok(e) => {
                    write_line(w, &e, ironsift_dataset_id)?;
                    n += 1;
                }
                Err(e) => log::warn!("Sigma export skipped JSON entry in {}: {}", path, e),
            }
        }
        return Ok(n);
    }
    for line in json.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") || line.starts_with('#') {
            continue;
        }
        match parse_line_for_sigma_export(path, line) {
            Ok(e) => {
                write_line(w, &e, ironsift_dataset_id)?;
                n += 1;
            }
            Err(e) => log::warn!("Sigma export skipped line in {}: {}", path, e),
        }
    }
    Ok(n)
}

fn write_csv<W: Write>(
    path: &str,
    w: &mut W,
    ironsift_dataset_id: Option<&str>,
) -> Result<u64, Box<dyn Error>> {
    use csv::Reader;
    let mut n: u64 = 0;
    let mut rdr = Reader::from_path(path)?;
    for result in rdr.deserialize::<RawLogEntry>() {
        let e = result?;
        write_line(w, &e, ironsift_dataset_id)?;
        n += 1;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempfile::NamedTempFile;

    /// Ingest-style JSONL (no machine_id) must export for Sigma, same as ingestion.
    #[test]
    fn export_jsonl_ingest_style_without_host_counts_lines() {
        let mut f = NamedTempFile::new().unwrap();
        let p = f.path().to_str().unwrap().to_string();
        writeln!(
            f,
            r#"{{"timestamp": "2026-03-16T00:10:05", "event_type": "process", "user": "0", "command": "/sbin/init", "pid": 1, "ppid": 0}}"#
        )
        .unwrap();
        f.flush().unwrap();

        let out = tempfile::tempdir().unwrap();
        let out_path = out.path().join("sigma.jsonl");
        let n = export_process_sources_to_sigma_jsonl(&[(p, "jsonl".to_string())], &out_path).unwrap();
        assert_eq!(n, 1, "expected one Sigma line from ingest-style JSONL");

        let mut s = String::new();
        std::fs::File::open(&out_path)
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        assert!(s.contains("process_name"));
        assert!(s.contains("command_line"));
        assert!(s.contains("\"cmdline\""));
    }

    #[test]
    fn ingested_sql_sigma_json_carries_ironsift_dataset_id() {
        let v = sigma_json_from_ingested_sql_row(
            "dataset-uuid",
            "host1",
            1,
            "sh",
            "/bin/sh",
            "sh -c id",
            0,
            0,
            None,
        );
        assert_eq!(
            v.get("ironsift_dataset_id").and_then(|x| x.as_str()),
            Some("dataset-uuid")
        );
    }
}
