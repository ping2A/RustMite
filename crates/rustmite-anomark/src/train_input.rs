//! Resolve training file lists (CSV / JSONL / TXT) for the unified `train` CLI.

use anyhow::{Context, Result};
use clap::ValueEnum;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::data_handler::{load_csv, load_jsonl_filtered, load_txt};

/// Discriminant for each training file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrainFileKind {
    Csv,
    Jsonl,
    Txt,
}

/// How to interpret input paths (`auto` = infer from extension per file).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum TrainFormatArg {
    #[default]
    Auto,
    Csv,
    Jsonl,
    Txt,
}

fn kind_from_ext(path: &Path) -> Option<TrainFileKind> {
    let ext = path.extension()?.to_str()?.to_ascii_lowercase();
    match ext.as_str() {
        "csv" => Some(TrainFileKind::Csv),
        "jsonl" => Some(TrainFileKind::Jsonl),
        "txt" => Some(TrainFileKind::Txt),
        _ => None,
    }
}

fn collect_dir_by_ext(
    dir: &Path,
    ext: &str,
    recursive: bool,
    kind: TrainFileKind,
    out: &mut Vec<(PathBuf, TrainFileKind)>,
) -> Result<()> {
    let ext_lower = ext.to_lowercase();
    fn walk(
        dir: &Path,
        ext: &str,
        kind: TrainFileKind,
        recursive: bool,
        out: &mut Vec<(PathBuf, TrainFileKind)>,
    ) -> Result<()> {
        for e in std::fs::read_dir(dir).with_context(|| format!("Failed to read {}", dir.display()))? {
            let e = e?;
            let p = e.path();
            if p.is_file() {
                if p.extension()
                    .map(|x| x.to_string_lossy().to_ascii_lowercase())
                    .as_deref()
                    == Some(ext)
                {
                    out.push((p, kind));
                }
            } else if recursive && p.is_dir() {
                walk(&p, ext, kind, true, out)?;
            }
        }
        Ok(())
    }
    walk(dir, &ext_lower, kind, recursive, out)?;
    Ok(())
}

/// Collect all `.csv` / `.jsonl` / `.txt` under `dir` (for `auto`).
fn collect_dir_auto(
    dir: &Path,
    recursive: bool,
    out: &mut Vec<(PathBuf, TrainFileKind)>,
) -> Result<()> {
    fn walk(dir: &Path, recursive: bool, out: &mut Vec<(PathBuf, TrainFileKind)>) -> Result<()> {
        for e in std::fs::read_dir(dir).with_context(|| format!("Failed to read {}", dir.display()))? {
            let e = e?;
            let p = e.path();
            if p.is_file() {
                if let Some(k) = kind_from_ext(&p) {
                    out.push((p, k));
                }
            } else if recursive && p.is_dir() {
                walk(&p, true, out)?;
            }
        }
        Ok(())
    }
    walk(dir, recursive, out)?;
    Ok(())
}

/// Expand user path list into concrete files with kinds. With a forced format, extension may differ (e.g. `foo.log` + `--format jsonl`).
pub fn expand_train_files(
    paths: &[String],
    recursive: bool,
    format: TrainFormatArg,
) -> Result<Vec<(PathBuf, TrainFileKind)>> {
    let mut out = Vec::new();

    for s in paths {
        let p = Path::new(s);
        if !p.exists() {
            anyhow::bail!("Path does not exist: {}", p.display());
        }

        match format {
            TrainFormatArg::Csv => {
                if p.is_file() {
                    out.push((p.to_path_buf(), TrainFileKind::Csv));
                } else if p.is_dir() {
                    collect_dir_by_ext(p, "csv", recursive, TrainFileKind::Csv, &mut out)?;
                }
            }
            TrainFormatArg::Jsonl => {
                if p.is_file() {
                    out.push((p.to_path_buf(), TrainFileKind::Jsonl));
                } else if p.is_dir() {
                    collect_dir_by_ext(p, "jsonl", recursive, TrainFileKind::Jsonl, &mut out)?;
                }
            }
            TrainFormatArg::Txt => {
                if p.is_file() {
                    out.push((p.to_path_buf(), TrainFileKind::Txt));
                } else if p.is_dir() {
                    collect_dir_by_ext(p, "txt", recursive, TrainFileKind::Txt, &mut out)?;
                }
            }
            TrainFormatArg::Auto => {
                if p.is_file() {
                    let k = kind_from_ext(p).ok_or_else(|| {
                        anyhow::anyhow!(
                            "Cannot infer format from '{}'; use --format csv|jsonl|txt",
                            p.display()
                        )
                    })?;
                    out.push((p.to_path_buf(), k));
                } else if p.is_dir() {
                    collect_dir_auto(p, recursive, &mut out)?;
                }
            }
        }
    }

    out.sort_by(|a, b| a.0.cmp(&b.0));
    out.dedup_by(|a, b| a.0 == b.0);
    Ok(out)
}

/// Ensure we do not mix plain-text corpus files with row-oriented CSV/JSONL.
pub fn validate_train_file_kinds(files: &[(PathBuf, TrainFileKind)]) -> Result<()> {
    let kinds: HashSet<TrainFileKind> = files.iter().map(|(_, k)| *k).collect();
    let has_txt = kinds.contains(&TrainFileKind::Txt);
    let has_structured = kinds.contains(&TrainFileKind::Csv) || kinds.contains(&TrainFileKind::Jsonl);
    if has_txt && has_structured {
        anyhow::bail!(
            "Cannot mix .txt files with CSV/JSONL in one run: train text separately, or use only CSV/JSONL."
        );
    }
    Ok(())
}

/// Column for CSV/JSONL: required for CSV / mixed; optional for JSONL-only (defaults to `command`).
pub fn resolve_column_name(
    files: &[(PathBuf, TrainFileKind)],
    column_cli: Option<&str>,
) -> Result<Option<String>> {
    let structured = files
        .iter()
        .any(|(_, k)| *k == TrainFileKind::Csv || *k == TrainFileKind::Jsonl);
    if !structured {
        return Ok(None);
    }
    if let Some(c) = column_cli {
        if c.trim().is_empty() {
            anyhow::bail!("--column must not be empty");
        }
        return Ok(Some(c.to_string()));
    }
    let all_jsonl = files
        .iter()
        .all(|(_, k)| *k == TrainFileKind::Jsonl);
    if all_jsonl {
        return Ok(Some("command".to_string()));
    }
    anyhow::bail!(
        "--column / -c is required for CSV (or mixed CSV/JSONL) input (e.g. CommandLine)"
    );
}

/// Loaded data for character-level training: either many padded lines or one TXT corpus.
#[derive(Debug)]
pub enum LoadedCharTrainingData {
    Lines {
        lines: Vec<String>,
        counts: Option<Vec<usize>>,
    },
    Corpus {
        text: String,
    },
}

/// Load all files in order (sorted paths) into one training payload.
pub fn load_char_training_data(
    files: &[(PathBuf, TrainFileKind)],
    column: Option<&str>,
    filter_field: Option<&str>,
    filter_value: Option<&str>,
    count_column: Option<&str>,
) -> Result<LoadedCharTrainingData> {
    if files.is_empty() {
        anyhow::bail!("No input files to load");
    }

    if files[0].1 == TrainFileKind::Txt {
        let mut corpus = String::new();
        for (path, _) in files {
            let p = path.to_string_lossy();
            corpus.push_str(&load_txt(p.as_ref())?);
            corpus.push('\n');
        }
        return Ok(LoadedCharTrainingData::Corpus { text: corpus });
    }

    let col = column
        .ok_or_else(|| anyhow::anyhow!("internal: column missing for structured load"))?;

    let use_counts = count_column.is_some();
    let mut lines = Vec::new();
    let mut counts_build: Vec<usize> = Vec::new();

    for (path, kind) in files {
        let p = path.to_string_lossy();
        match kind {
            TrainFileKind::Txt => unreachable!("validated: no txt mix"),
            TrainFileKind::Csv => {
                let rows = load_csv(p.as_ref(), col)?;
                let n = rows.len();
                lines.extend(rows);
                if use_counts {
                    let cc = count_column.expect("count column");
                    let c: Vec<usize> = load_csv(p.as_ref(), cc)?
                        .into_iter()
                        .filter_map(|s| s.parse::<usize>().ok())
                        .collect();
                    if c.len() != n {
                        anyhow::bail!(
                            "Count column '{}' length {} does not match column '{}' length {} in {}",
                            cc,
                            c.len(),
                            col,
                            n,
                            path.display()
                        );
                    }
                    counts_build.extend(c);
                }
            }
            TrainFileKind::Jsonl => {
                let rows =
                    load_jsonl_filtered(p.as_ref(), col, filter_field, filter_value)?;
                let n = rows.len();
                lines.extend(rows);
                if use_counts {
                    counts_build.extend(std::iter::repeat(1usize).take(n));
                }
            }
        }
    }

    let counts = if use_counts {
        if counts_build.len() != lines.len() {
            anyhow::bail!("internal: counts length mismatch");
        }
        if counts_build.is_empty() {
            None
        } else {
            Some(counts_build)
        }
    } else {
        None
    };

    Ok(LoadedCharTrainingData::Lines { lines, counts })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_rejects_txt_plus_csv() {
        let files = vec![
            (PathBuf::from("a.txt"), TrainFileKind::Txt),
            (PathBuf::from("b.csv"), TrainFileKind::Csv),
        ];
        assert!(validate_train_file_kinds(&files).is_err());
    }

    #[test]
    fn resolve_column_jsonl_only_default() {
        let files = vec![(PathBuf::from("x.jsonl"), TrainFileKind::Jsonl)];
        assert_eq!(
            resolve_column_name(&files, None).unwrap(),
            Some("command".to_string())
        );
    }

    #[test]
    fn resolve_column_csv_requires_flag() {
        let files = vec![(PathBuf::from("x.csv"), TrainFileKind::Csv)];
        assert!(resolve_column_name(&files, None).is_err());
        assert_eq!(
            resolve_column_name(&files, Some("Cmd")).unwrap(),
            Some("Cmd".to_string())
        );
    }
}
