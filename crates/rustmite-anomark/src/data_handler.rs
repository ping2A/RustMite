use ahash::AHashMap;
use anyhow::{Context, Result};
use csv::ReaderBuilder;
use regex::Regex;
use serde::Deserialize;
use serde_json::Value;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
pub struct DataRow {
    #[serde(flatten)]
    pub fields: AHashMap<String, String>,  // Now works with serde feature enabled
}

/// Replace SID patterns with placeholder
pub fn replace_sid(text: &str, placeholder: &str) -> String {
    let re = Regex::new(r"S[-–]1[-–]([0-9]+[-–])+[0-9]+").unwrap();
    re.replace_all(text, placeholder).to_string()
}

/// Replace GUID patterns with placeholder
pub fn replace_guid(text: &str, placeholder: &str) -> String {
    let re = Regex::new(r"\{?[0-9A-Fa-f]{8}[-–]([0-9A-Fa-f]{4}[-–]){3}[0-9A-Fa-f]{12}\}?").unwrap();
    re.replace_all(text, placeholder).to_string()
}

/// Replace user path patterns with placeholder
pub fn replace_user(text: &str, placeholder: &str) -> String {
    let re = Regex::new(r"(?i)(C:\\Users)\\[^\\]*\\").unwrap();
    re.replace_all(text, format!(r"$1\{}\", placeholder))
        .to_string()
}

/// Replace hash patterns with placeholder
pub fn replace_hash(text: &str, placeholder: &str) -> String {
    let re = Regex::new(r"\b(?:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32}|[A-Fa-f0-9]{20})\b").unwrap();
    re.replace_all(text, placeholder).to_string()
}

/// Replace filepath patterns with placeholder
pub fn replace_filepath(text: &str, placeholder: &str) -> String {
    // Simplified version of the complex filepath regex from Python
    let re = Regex::new(
        r#"(?x)
        (?P<opening>
            \b(?P<montage>[a-zA-Z]:[/\\])
            |[/\\][/\\](?<!http://)(?<!https://)
            |%\w+%[/\\]
        )
        (?:[^/\\<>:"|?\n\r ,'][^/\\<>:"|?\n\r]*[/\\])*
        (?:[^/\\<>:"'|?\n\r;, ][^/\\<>:"|?\n\r;, .]*)?
        (?:\.\w+)*
        "#
    ).unwrap();
    
    re.replace_all(text, format!("$opening{}", placeholder))
        .to_string()
}

/// Apply all placeholder transformations
pub fn apply_all_placeholders(text: &str, apply_filepath: bool) -> String {
    let mut result = text.to_string();
    result = replace_sid(&result, "<SID>");
    result = replace_guid(&result, "<GUID>");
    result = replace_hash(&result, "<HASH>");
    result = replace_user(&result, "<USER>");
    
    if apply_filepath {
        result = replace_filepath(&result, "<FILEPATH>");
    }
    
    result
}

/// Expand paths to a list of data files. Each path can be a file or a directory.
/// - File: included if its extension matches `extension` (e.g. `"csv"`).
/// - Directory: all non-directory files in it whose extension matches; if `recursive`, descend into subdirs.
/// Returns sorted, deduplicated paths for stable ordering.
pub fn expand_data_paths(
    paths: &[impl AsRef<Path>],
    extension: &str,
    recursive: bool,
) -> Result<Vec<PathBuf>> {
    let ext_lower = extension.to_lowercase();
    let mut out: Vec<PathBuf> = Vec::new();

    fn collect(
        path: &Path,
        ext: &str,
        recursive: bool,
        out: &mut Vec<PathBuf>,
    ) -> Result<()> {
        if path.is_file() {
            if path
                .extension()
                .map(|e| e.to_string_lossy().to_lowercase())
                .as_deref()
                == Some(ext)
            {
                out.push(path.to_path_buf());
            }
            return Ok(());
        }
        if path.is_dir() {
            for e in std::fs::read_dir(path).context("Failed to read directory")? {
                let e = e?;
                let p = e.path();
                if p.is_file() {
                    if p.extension()
                        .map(|e| e.to_string_lossy().to_lowercase())
                        .as_deref()
                        == Some(ext)
                    {
                        out.push(p);
                    }
                } else if recursive && p.is_dir() {
                    collect(&p, ext, true, out)?;
                }
            }
        }
        Ok(())
    }

    for path in paths {
        let path = path.as_ref();
        if path.is_file() {
            if path.extension().map(|e| e.to_string_lossy().to_lowercase()).as_deref() == Some(ext_lower.as_str()) {
                out.push(path.to_path_buf());
            }
        } else if path.is_dir() {
            collect(path, &ext_lower, recursive, &mut out)?;
        }
    }

    out.sort();
    out.dedup();
    Ok(out)
}

/// Load data from CSV file
pub fn load_csv(path: &str, column_name: &str) -> Result<Vec<String>> {
    let mut reader = ReaderBuilder::new()
        .has_headers(true)
        .from_path(path)?;

    let mut data = Vec::new();
    
    for result in reader.deserialize() {
        let record: DataRow = result?;
        if let Some(value) = record.fields.get(column_name) {
            data.push(value.clone());
        }
    }

    Ok(data)
}

/// Load data from CSV with all columns
pub fn load_csv_with_columns(path: &str) -> Result<Vec<AHashMap<String, String>>> {
    let mut reader = ReaderBuilder::new()
        .has_headers(true)
        .from_path(path)?;

    let mut data = Vec::new();
    
    for result in reader.deserialize() {
        let record: DataRow = result?;
        data.push(record.fields);
    }

    Ok(data)
}

/// Load data from TXT file
pub fn load_txt(path: &str) -> Result<String> {
    Ok(std::fs::read_to_string(path)?)
}

/// Convert a JSON value to string for storage in row maps
fn json_value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        Value::Array(arr) => serde_json::to_string(arr).unwrap_or_default(),
        Value::Object(obj) => serde_json::to_string(obj).unwrap_or_default(),
    }
}

/// Load data from JSONL file, extracting one field (e.g. "command") per line
pub fn load_jsonl(path: &str, column_name: &str) -> Result<Vec<String>> {
    load_jsonl_filtered(path, column_name, None, None)
}

/// Load JSONL with optional filter: only include lines where `filter_field == filter_value` (e.g. event_type -> "process").
pub fn load_jsonl_filtered(
    path: &str,
    column_name: &str,
    filter_field: Option<&str>,
    filter_value: Option<&str>,
) -> Result<Vec<String>> {
    let file = File::open(path).context("Failed to open JSONL file")?;
    let reader = BufReader::new(file);
    let mut data = Vec::new();

    for (line_num, line) in reader.lines().enumerate() {
        let line = line.context("Failed to read line")?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(line)
            .with_context(|| format!("Invalid JSON at line {}", line_num + 1))?;
        let obj = value.as_object().context("Each line must be a JSON object")?;
        if let (Some(ff), Some(fv)) = (filter_field, filter_value) {
            if obj.get(ff).map(|v| json_value_to_string(v) != fv).unwrap_or(true) {
                continue;
            }
        }
        if let Some(v) = obj.get(column_name) {
            data.push(json_value_to_string(v));
        }
    }

    Ok(data)
}

/// Load JSONL file with all fields as string key-value pairs (for detection output)
pub fn load_jsonl_with_columns(path: &str) -> Result<Vec<AHashMap<String, String>>> {
    let file = File::open(path).context("Failed to open JSONL file")?;
    let reader = BufReader::new(file);
    let mut data = Vec::new();

    for (line_num, line) in reader.lines().enumerate() {
        let line = line.context("Failed to read line")?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(line)
            .with_context(|| format!("Invalid JSON at line {}", line_num + 1))?;
        let obj = value.as_object().context("Each line must be a JSON object")?;
        let mut row = AHashMap::new();
        for (k, v) in obj {
            row.insert(k.clone(), json_value_to_string(v));
        }
        data.push(row);
    }

    Ok(data)
}

/// Process dataframe-like data with slicing options
pub fn process_data(
    data: Vec<String>,
    n_lines: Option<usize>,
    percentage: Option<f64>,
    from_end: bool,
    randomize: bool,
) -> Vec<String> {
    let mut result = data;

    if randomize {
        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        result.shuffle(&mut rng);
    }

    if let Some(n) = n_lines {
        if from_end && result.len() > n {
            let skip_amount = result.len() - n;  // Calculate before moving
            result = result.into_iter().skip(skip_amount).collect();
        } else {
            result.truncate(n);
        }
    } else if let Some(pct) = percentage {
        let count = ((result.len() as f64 * pct) / 100.0) as usize;
        if from_end && result.len() > count {
            let skip_amount = result.len() - count;  // Calculate before moving
            result = result.into_iter().skip(skip_amount).collect();
        } else {
            result.truncate(count);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replace_sid() {
        let text = "my_S-1-0-0";
        assert_eq!(replace_sid(text, "<SID>"), "my_<SID>");

        let text2 = "other SID here: S-1-5-21-4242424242-424242-4242442-4242 should be replaced";
        assert_eq!(
            replace_sid(text2, "<placeholder>"),
            "other SID here: <placeholder> should be replaced"
        );
    }

    #[test]
    fn test_replace_user() {
        let text = r"C:\Users\some_user\some_folder";
        assert_eq!(
            replace_user(text, "<USER>"),
            r"C:\Users\<USER>\some_folder"
        );
    }

    #[test]
    fn test_replace_guid() {
        let text = r"Here is some {12345678-1234-1234-1234-123456789012}";
        assert_eq!(replace_guid(text, "<GUID>"), r"Here is some <GUID>");
    }

    #[test]
    fn test_replace_hash() {
        // SHA256
        let text = r"Here is some e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(replace_hash(text, "<HASH>"), r"Here is some <HASH>");

        // MD5
        let text2 = r"Here is some d41d8cd98f00b204e9800998ecf8427e";
        assert_eq!(replace_hash(text2, "<HASH>"), r"Here is some <HASH>");
    }

    #[test]
    fn test_csv_with_ahashmap_serde() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Create temp CSV file
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "col1,col2").unwrap();
        writeln!(temp_file, "value1,value2").unwrap();
        writeln!(temp_file, "value3,value4").unwrap();
        temp_file.flush().unwrap();

        // Load CSV directly into AHashMap (tests serde feature)
        let result = load_csv_with_columns(temp_file.path().to_str().unwrap()).unwrap();
        
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].get("col1"), Some(&"value1".to_string()));
        assert_eq!(result[0].get("col2"), Some(&"value2".to_string()));
        assert_eq!(result[1].get("col1"), Some(&"value3".to_string()));
        assert_eq!(result[1].get("col2"), Some(&"value4".to_string()));
        
        // Verify it's actually an AHashMap (type check at compile time)
        let _: &AHashMap<String, String> = &result[0];
    }

    #[test]
    fn test_process_data_from_end() {
        let data = vec![
            "line1".to_string(),
            "line2".to_string(),
            "line3".to_string(),
            "line4".to_string(),
            "line5".to_string(),
        ];

        // Test taking last 2 lines
        let result = process_data(data.clone(), Some(2), None, true, false);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], "line4");
        assert_eq!(result[1], "line5");

        // Test taking last 50%
        let result = process_data(data, None, Some(40.0), true, false);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], "line4");
        assert_eq!(result[1], "line5");
    }

    #[test]
    fn test_load_jsonl() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, r#"{{"timestamp":"2026-03-09T00:10:06","event_type":"process","user":"0","command":"/sbin/init","pid":1,"ppid":0}}"#).unwrap();
        writeln!(f, r#"{{"timestamp":"2026-03-09T00:10:06","event_type":"process","user":"0","command":"[kthreadd]","pid":2,"ppid":0}}"#).unwrap();
        f.flush().unwrap();

        let commands = load_jsonl(f.path().to_str().unwrap(), "command").unwrap();
        assert_eq!(commands.len(), 2);
        assert_eq!(commands[0], "/sbin/init");
        assert_eq!(commands[1], "[kthreadd]");
    }

    #[test]
    fn test_load_jsonl_with_columns() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, r#"{{"timestamp":"2026-03-09T00:10:06","event_type":"process","user":"0","command":"/sbin/init","pid":1,"ppid":0}}"#).unwrap();
        f.flush().unwrap();

        let rows = load_jsonl_with_columns(f.path().to_str().unwrap()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("command"), Some(&"/sbin/init".to_string()));
        assert_eq!(rows[0].get("pid"), Some(&"1".to_string()));
        assert_eq!(rows[0].get("event_type"), Some(&"process".to_string()));
    }

    #[test]
    fn test_load_jsonl_filtered() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, r#"{{"event_type":"process","command":"/sbin/init"}}"#).unwrap();
        writeln!(f, r#"{{"event_type":"network","command":"curl x"}}"#).unwrap();
        writeln!(f, r#"{{"event_type":"process","command":"[kthreadd]"}}"#).unwrap();
        f.flush().unwrap();

        let all = load_jsonl_filtered(f.path().to_str().unwrap(), "command", None, None).unwrap();
        assert_eq!(all.len(), 3);
        let process_only = load_jsonl_filtered(f.path().to_str().unwrap(), "command", Some("event_type"), Some("process")).unwrap();
        assert_eq!(process_only.len(), 2);
        assert_eq!(process_only[0], "/sbin/init");
        assert_eq!(process_only[1], "[kthreadd]");
    }

    #[test]
    fn test_expand_data_paths() {
        use tempfile::{NamedTempFile, TempDir};

        // Single file
        let f = NamedTempFile::new().unwrap();
        let p = f.path().to_path_buf();
        std::fs::rename(f.path(), p.with_extension("csv")).unwrap();
        let csv_path = p.with_extension("csv");
        let files = expand_data_paths(&[csv_path.as_path()], "csv", false).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0], csv_path);

        // Directory with matching extension
        let dir = TempDir::new().unwrap();
        let d = dir.path();
        let f1 = d.join("a.csv");
        let f2 = d.join("b.csv");
        let f3 = d.join("ignore.txt");
        std::fs::write(&f1, "x").unwrap();
        std::fs::write(&f2, "y").unwrap();
        std::fs::write(&f3, "z").unwrap();
        let files = expand_data_paths(&[d], "csv", false).unwrap();
        assert_eq!(files.len(), 2);
        assert!(files.iter().any(|p| p.file_name().unwrap() == "a.csv"));
        assert!(files.iter().any(|p| p.file_name().unwrap() == "b.csv"));
    }
}