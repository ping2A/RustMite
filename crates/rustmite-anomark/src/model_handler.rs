use crate::data_handler::apply_all_placeholders;
use crate::model::MarkovModel;
use crate::token_model::TokenMarkovModel;
use crate::train_filter::TrainLineFilter;
use ahash::AHashMap;
use anyhow::{Context, Result};
use chrono::Local;
use csv::Writer;
use indicatif::{ProgressBar, ProgressStyle};
use std::fs::File;
use std::io::{BufReader, BufWriter};

const MARKOV_SCORE: &str = "markovScore";

pub struct ModelHandler;

impl ModelHandler {
    /// Resolve a CSV column or JSON field name: exact match, then ASCII case-insensitive.
    /// Returns the actual key present in the row (for consistent lookups on all rows).
    fn resolve_field_key(row: &AHashMap<String, String>, col_name: &str) -> Result<String> {
        let want = col_name.trim();
        if want.is_empty() {
            anyhow::bail!("Column/field name is empty");
        }
        if let Some(k) = row.keys().find(|k| k.as_str() == want) {
            return Ok(k.clone());
        }
        let want_lower = want.to_ascii_lowercase();
        if let Some(k) = row
            .keys()
            .find(|k| k.to_ascii_lowercase() == want_lower)
        {
            return Ok(k.clone());
        }
        let mut keys: Vec<_> = row.keys().map(|s| s.as_str()).collect();
        keys.sort();
        anyhow::bail!(
            "Column/field '{}' not found. Available fields: {}",
            want,
            keys.join(", ")
        );
    }

    /// Resolve field key by scanning rows until one contains the column (for JSONL with varying fields per line).
    /// Rows that don't have the column (e.g. other event types) should be skipped by the caller.
    fn resolve_field_key_from_data(
        data: &[AHashMap<String, String>],
        col_name: &str,
    ) -> Result<String> {
        for row in data {
            if let Ok(k) = Self::resolve_field_key(row, col_name) {
                return Ok(k);
            }
        }
        let sample = data
            .first()
            .map(|r| {
                let mut keys: Vec<_> = r.keys().map(|s| s.as_str()).collect();
                keys.sort();
                keys.join(", ")
            })
            .unwrap_or_else(|| "no rows".to_string());
        anyhow::bail!(
            "Column/field '{}' not found in any row (JSONL may have different fields per line). In first row, available: {}",
            col_name.trim(),
            sample
        );
    }

    /// Train a model from text data
    pub fn train_from_txt(
        training_data: &str,
        model_order: usize,
        model: Option<MarkovModel>,
    ) -> Result<MarkovModel> {
        let mut model = model.unwrap_or_else(|| MarkovModel::new(model_order));
        
        println!("Training model...");
        let start = std::time::Instant::now();
        
        model.train(training_data, 1);
        
        println!("Training took {:.2} minutes", start.elapsed().as_secs_f64() / 60.0);
        
        Ok(model)
    }

    /// Train a model from CSV data
    pub fn train_from_csv(
        data: &[String],
        model_order: usize,
        count_data: Option<&[usize]>,
        model: Option<MarkovModel>,
    ) -> Result<MarkovModel> {
        let mut model = model.unwrap_or_else(|| MarkovModel::new(model_order));
        
        println!("Training model...");
        let start = std::time::Instant::now();
        
        let pb = ProgressBar::new(data.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
                .unwrap()
                .progress_chars("#>-"),
        );

        for (i, text) in data.iter().enumerate() {
            let padded = format!("{}{}{}", "~".repeat(model_order), text, "~".repeat(model_order));
            let count = count_data.map(|c| c[i]).unwrap_or(1);
            model.train(&padded, count);
            pb.inc(1);
        }

        pb.finish_with_message("Training complete");
        println!("Training took {:.2} minutes", start.elapsed().as_secs_f64() / 60.0);
        
        Ok(model)
    }

    /// Save a model to disk
    pub fn save_model(model: &MarkovModel, save_path: Option<&str>) -> Result<String> {
        println!("Saving model...");
        
        let path = if let Some(p) = save_path {
            p.to_string()
        } else {
            let now = Local::now();
            format!(
                "./models/{}_modelLetters_{}grams.bin",
                now.format("%Y%m%d_%Hh%M"),
                model.order
            )
        };

        std::fs::create_dir_all("./models")?;

        let file = File::create(&path)?;
        let writer = BufWriter::new(file);
        bincode::serialize_into(writer, model)
            .context("Failed to serialize model")?;

        println!("Successfully saved model in: {}", path);
        Ok(path)
    }

    /// Load a model from disk
    pub fn load_model(path: &str) -> Result<MarkovModel> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let model: MarkovModel = bincode::deserialize_from(reader)
            .context("Failed to deserialize model")?;
        Ok(model)
    }

    /// Save a token model to disk
    pub fn save_token_model(model: &TokenMarkovModel, save_path: Option<&str>) -> Result<String> {
        println!("Saving token model...");
        let path = if let Some(p) = save_path {
            p.to_string()
        } else {
            let now = Local::now();
            format!(
                "./models/{}_token_model_{}grams.bin",
                now.format("%Y%m%d_%Hh%M"),
                model.order
            )
        };
        std::fs::create_dir_all("./models")?;
        let file = File::create(&path)?;
        let writer = BufWriter::new(file);
        bincode::serialize_into(writer, model).context("Failed to serialize token model")?;
        println!("Successfully saved token model in: {}", path);
        Ok(path)
    }

    /// Load a token model from disk
    pub fn load_token_model(path: &str) -> Result<TokenMarkovModel> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        bincode::deserialize_from(reader).context("Failed to deserialize token model")
    }

    /// Execute token model on dataset. Threshold for explain = 95% of prior log.
    /// If `exclude_filter` is set, rows whose command matches (e.g. kernel threads) are skipped and not scored.
    /// If `machine_override` or `machine_field` is set, each result gets a machine label for filtering.
    pub fn execute_on_data_token(
        model: &TokenMarkovModel,
        data: Vec<AHashMap<String, String>>,
        col_name: &str,
        apply_placeholder: bool,
        apply_filepath: bool,
        with_explain: bool,
        exclude_filter: Option<&TrainLineFilter>,
        machine_field: Option<&str>,
        machine_override: Option<&str>,
    ) -> Result<Vec<ScoredResult>> {
        let threshold = model.prior.ln() * 0.95;
        println!("Applying token model to data...");
        let pb = ProgressBar::new(data.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
                .unwrap()
                .progress_chars("#>-"),
        );
        let mut grouped: AHashMap<String, ScoredResult> = AHashMap::new();

        if data.is_empty() {
            pb.finish_with_message("No rows to process");
            return Ok(vec![]);
        }
        let field_key = Self::resolve_field_key_from_data(&data, col_name)?;
        let machine_field_key = machine_field
            .and_then(|f| Self::resolve_field_key_from_data(&data, f).ok());
        let mut skipped = 0usize;
        let mut skipped_excluded = 0usize;

        for row in data {
            let Some(mut text) = row.get(&field_key).cloned() else {
                skipped += 1;
                pb.inc(1);
                continue;
            };
            if let Some(filter) = exclude_filter {
                if filter.should_exclude(&text) {
                    skipped_excluded += 1;
                    pb.inc(1);
                    continue;
                }
            }
            let row_machine = machine_override
                .map(String::from)
                .or_else(|| machine_field_key.as_ref().and_then(|k| row.get(k).cloned()));
            if apply_placeholder {
                text = apply_all_placeholders(&text, apply_filepath);
            }
            let (score, unusual) = if with_explain {
                let (s, u) = model.explain(&text, threshold);
                (s, Some(u.into_iter().map(|(ng, lp)| UnusualNgram { ngram: ng, log_prob: lp }).collect()))
            } else {
                (model.log_likelihood(&text), None)
            };

            let entry = grouped.entry(text.clone()).or_insert_with(|| ScoredResult {
                command_line: text.clone(),
                score,
                machine: row_machine.clone(),
                other_fields: AHashMap::new(),
                unusual_ngrams: unusual.clone(),
            });
            if let Some(ref m) = row_machine {
                if let Some(ref mut em) = entry.machine {
                    if !em.contains(m) {
                        entry.machine = Some(format!("{},{}", em, m));
                    }
                } else {
                    entry.machine = Some(m.clone());
                }
            }
            for (key, value) in row {
                if key != field_key {
                    entry.other_fields.entry(key).or_insert_with(Vec::new).push(value);
                }
            }
            if score < entry.score {
                entry.score = score;
                entry.unusual_ngrams = unusual;
            }
            pb.inc(1);
        }
        pb.finish_with_message("Execution complete");
        if skipped > 0 {
            println!("Skipped {} rows missing field '{}' (e.g. other event types)", skipped, field_key);
        }
        if skipped_excluded > 0 {
            println!("Skipped {} rows excluded by filter (e.g. kernel threads)", skipped_excluded);
        }
        let mut results: Vec<ScoredResult> = grouped.into_values().collect();
        results.sort_by(|a, b| a.score.partial_cmp(&b.score).unwrap_or(std::cmp::Ordering::Equal));
        Ok(results)
    }

    /// Execute model on dataset and return scored results.
    /// If `with_explain` is true, populates `unusual_ngrams` using `explain_threshold_percent` (default 95).
    /// If `exclude_filter` is set, rows whose command matches (e.g. kernel threads) are skipped and not scored.
    /// If `machine_override` is set, every row gets that label; else if `machine_field` is set, the value is taken from that column.
    pub fn execute_on_data(
        model: &mut MarkovModel,
        data: Vec<AHashMap<String, String>>,
        col_name: &str,
        apply_placeholder: bool,
        apply_filepath: bool,
        with_explain: bool,
        explain_threshold_percent: f64,
        exclude_filter: Option<&TrainLineFilter>,
        machine_field: Option<&str>,
        machine_override: Option<&str>,
    ) -> Result<Vec<ScoredResult>> {
        if !model.is_trained() {
            model.normalize_model_and_compute_prior();
        }

        println!("Applying model to data...");
        let threshold = Self::compute_threshold(model, explain_threshold_percent);

        let pb = ProgressBar::new(data.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
                .unwrap()
                .progress_chars("#>-"),
        );

        let mut grouped: AHashMap<String, ScoredResult> = AHashMap::new();

        if data.is_empty() {
            pb.finish_with_message("No rows to process");
            return Ok(vec![]);
        }
        let field_key = Self::resolve_field_key_from_data(&data, col_name)?;
        let machine_field_key = machine_field
            .and_then(|f| Self::resolve_field_key_from_data(&data, f).ok());
        let mut skipped = 0usize;
        let mut skipped_excluded = 0usize;

        for row in data {
            let Some(mut text) = row.get(&field_key).cloned() else {
                skipped += 1;
                pb.inc(1);
                continue;
            };

            if let Some(filter) = exclude_filter {
                if filter.should_exclude(&text) {
                    skipped_excluded += 1;
                    pb.inc(1);
                    continue;
                }
            }

            let row_machine = machine_override
                .map(String::from)
                .or_else(|| machine_field_key.as_ref().and_then(|k| row.get(k).cloned()));

            if apply_placeholder {
                text = apply_all_placeholders(&text, apply_filepath);
            }

            let padded = format!("{}{}", "~".repeat(model.order), text);
            let (score, unusual) = if with_explain {
                let (s, u) = model.explain(&padded, threshold);
                (s, Some(u.into_iter().map(|(ng, lp)| UnusualNgram { ngram: ng, log_prob: lp }).collect()))
            } else {
                (model.log_likelihood(&padded), None)
            };

            let entry = grouped.entry(text.clone()).or_insert_with(|| ScoredResult {
                command_line: text.clone(),
                score,
                machine: row_machine.clone(),
                other_fields: AHashMap::new(),
                unusual_ngrams: unusual.clone(),
            });

            if let Some(ref m) = row_machine {
                if let Some(ref mut em) = entry.machine {
                    if !em.contains(m) {
                        entry.machine = Some(format!("{},{}", em, m));
                    }
                } else {
                    entry.machine = Some(m.clone());
                }
            }

            for (key, value) in row {
                if key != field_key {
                    entry.other_fields
                        .entry(key)
                        .or_insert_with(Vec::new)
                        .push(value);
                }
            }

            if score < entry.score {
                entry.score = score;
                entry.unusual_ngrams = unusual;
            }

            pb.inc(1);
        }

        pb.finish_with_message("Execution complete");
        if skipped > 0 {
            println!("Skipped {} rows missing field '{}' (e.g. other event types)", skipped, field_key);
        }
        if skipped_excluded > 0 {
            println!("Skipped {} rows excluded by filter (e.g. kernel threads)", skipped_excluded);
        }

        let mut results: Vec<ScoredResult> = grouped.into_values().collect();
        results.sort_by(|a, b| {
            a.score.partial_cmp(&b.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        Ok(results)
    }

    /// Compute threshold as percentage of model prior
    pub fn compute_threshold(model: &MarkovModel, percent: f64) -> f64 {
        model.prior.ln() * percent / 100.0
    }

    /// True when the line score is below the baseline (more anomalous than typical training).
    pub fn is_suspect_command(score: f64, suspect_threshold_ln: f64) -> bool {
        score < suspect_threshold_ln
    }

    /// Add colored output to a command line
    pub fn colored_results(text: &str, model: &MarkovModel, threshold: f64) -> String {
        let padded = format!("{}{}", "~".repeat(model.order), text);
        let chars: Vec<char> = padded.chars().collect();
        let mut result = String::new();

        for k in model.order..chars.len() {
            let ngram: String = chars[k.saturating_sub(model.order)..=k].iter().collect();
            let score = model.log_likelihood(&ngram);
            
            if score < threshold {
                result.push_str(&format!("\x1b[91m{}\x1b[0m", chars[k]));
            } else {
                result.push(chars[k]);
            }
        }

        result.replace("\x1b[0m\x1b[91m", "")
    }

    /// Display top results in terminal.
    /// `suspect_threshold_ln`: if `Some(t)`, mark each line SUSPECT when `score < t` (e.g. `prior.ln() * 0.95`).
    pub fn display_top(
        results: &[ScoredResult],
        model: &MarkovModel,
        nb_lines: usize,
        color: bool,
        show_percentage: bool,
        show_explain: bool,
        suspect_threshold_ln: Option<f64>,
    ) {
        println!("_______");
        println!("Displaying top {} (sorted: most unusual first)", nb_lines);

        let threshold = Self::compute_threshold(model, 95.0);

        if let Some(t) = suspect_threshold_ln {
            println!(
                "SUSPECT = markovScore below baseline ({:.4}); lower score = more unusual vs training.",
                t
            );
        }

        for (i, result) in results.iter().take(nb_lines).enumerate() {
            println!("_______");
            let rank = i + 1;
            if let Some(t) = suspect_threshold_ln {
                let suspect = Self::is_suspect_command(result.score, t);
                println!(
                    "#{} — {} | markovScore={:.6}",
                    rank,
                    if suspect {
                        "SUSPECT (this command is flagged as unusual)"
                    } else {
                        "not flagged (score at or above baseline)"
                    },
                    result.score
                );
            } else {
                println!("#{} | markovScore={:.6}", i + 1, result.score);
            }

            if let Some(ref m) = result.machine {
                println!("Machine: {}", m);
            }
            if color {
                println!("{}", Self::colored_results(&result.command_line, model, threshold));
            } else {
                println!("Command: {}", result.command_line);
            }

            if show_percentage {
                let percentage = (result.score / model.prior.ln() * 100.0).round();
                println!("{}%", percentage);
            }

            if show_explain {
                if let Some(ref un) = result.unusual_ngrams {
                    if !un.is_empty() {
                        println!("  unusual n-grams: {}", un.iter()
                            .map(|u| format!("{:?}({:.2})", u.ngram, u.log_prob))
                            .collect::<Vec<_>>()
                            .join(", "));
                    }
                }
            }
        }
        println!("_______");
    }

    /// Save results to CSV file.
    /// `suspect_threshold_ln`: if `Some(t)`, add column `Suspect` = `yes` when `score < t`.
    pub fn save_results(
        results: &[ScoredResult],
        output: Option<&str>,
        model: &MarkovModel,
        color: bool,
        show_percentage: bool,
        show_explain: bool,
        suspect_threshold_ln: Option<f64>,
    ) -> Result<String> {
        println!("Saving results...");
        
        let path = if let Some(p) = output {
            p.to_string()
        } else {
            let now = Local::now();
            format!("./results/{}_export.csv", now.format("%Y%m%d_%Hh%M"))
        };

        std::fs::create_dir_all("./results")?;

        let mut wtr = Writer::from_path(&path)?;

        let mut other_keys: Vec<String> = results
            .first()
            .map(|r| r.other_fields.keys().cloned().collect())
            .unwrap_or_default();
        other_keys.sort();

        let has_machine = results.iter().any(|r| r.machine.is_some());
        let mut headers = vec!["CommandLine".to_string(), MARKOV_SCORE.to_string()];
        if suspect_threshold_ln.is_some() {
            headers.push("Suspect".to_string());
        }
        if has_machine {
            headers.push("Machine".to_string());
        }
        for key in &other_keys {
            headers.push(format!("List of all {}", key));
        }
        if color {
            headers.push("Colored CommandLine".to_string());
        }
        if show_percentage {
            headers.push("Percentage".to_string());
        }
        if show_explain {
            headers.push("UnusualNgrams".to_string());
        }
        wtr.write_record(&headers)?;

        let threshold = Self::compute_threshold(model, 95.0);

        // Write data
        for result in results {
            let mut record = vec![
                result.command_line.clone(),
                result.score.to_string(),
            ];
            if let Some(t) = suspect_threshold_ln {
                let s = if Self::is_suspect_command(result.score, t) {
                    "yes"
                } else {
                    "no"
                };
                record.push(s.to_string());
            }
            if has_machine {
                record.push(result.machine.as_deref().unwrap_or("").to_string());
            }
            for original_key in &other_keys {
                if let Some(values) = result.other_fields.get(original_key) {
                    let unique: Vec<String> = values
                        .iter()
                        .map(|s| s.to_string())
                        .collect::<std::collections::HashSet<_>>()
                        .into_iter()
                        .collect();
                    record.push(unique.join(" - "));
                } else {
                    record.push(String::new());
                }
            }

            if color {
                record.push(Self::colored_results(&result.command_line, model, threshold));
            }

            if show_percentage {
                let percentage = (result.score / model.prior.ln() * 100.0).round();
                record.push(format!("{}%", percentage));
            }

            if show_explain {
                let reason = result.unusual_ngrams.as_ref()
                    .map(|un| un.iter()
                        .map(|u| format!("{} ({:.2})", u.ngram, u.log_prob))
                        .collect::<Vec<_>>()
                        .join("; "))
                    .unwrap_or_default();
                record.push(reason);
            }

            wtr.write_record(&record)?;
        }

        wtr.flush()?;
        println!("Successfully saved results in: {}", path);
        Ok(path)
    }
}

/// One unusual n-gram contributing to a low score (explainability).
#[derive(Debug, Clone)]
pub struct UnusualNgram {
    pub ngram: String,
    pub log_prob: f64,
}

#[derive(Debug, Clone)]
pub struct ScoredResult {
    pub command_line: String,
    pub score: f64,
    /// Optional machine/host identifier for filtering (from --machine or --machine-field).
    pub machine: Option<String>,
    pub other_fields: AHashMap<String, Vec<String>>,
    /// When explainability is enabled: n-grams with log_prob below threshold
    pub unusual_ngrams: Option<Vec<UnusualNgram>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_field_key_exact_and_case_insensitive() {
        let row = AHashMap::from([
            ("command".to_string(), "x".to_string()),
            ("event_type".to_string(), "process".to_string()),
        ]);
        assert_eq!(
            ModelHandler::resolve_field_key(&row, "command").unwrap(),
            "command"
        );
        assert_eq!(
            ModelHandler::resolve_field_key(&row, "COMMAND").unwrap(),
            "command"
        );
        assert_eq!(
            ModelHandler::resolve_field_key(&row, "  command  ").unwrap(),
            "command"
        );
    }
}
