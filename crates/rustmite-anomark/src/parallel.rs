use crate::model::MarkovModel;
use crate::model_handler::ScoredResult;
use ahash::AHashMap;
use anyhow::Result;
use rayon::prelude::*;
use std::sync::{Arc, Mutex};

/// Parallel training using Rayon
pub fn train_parallel(
    data: &[String],
    order: usize,
    count_data: Option<&[usize]>,
    existing_model: Option<MarkovModel>,
) -> Result<MarkovModel> {
    println!("Training model (parallel mode)...");
    let start = std::time::Instant::now();

    // Create thread-safe model (use existing or create new)
    let model = Arc::new(Mutex::new(
        existing_model.unwrap_or_else(|| MarkovModel::new(order))
    ));

    // Process data in parallel chunks
    data.par_iter()
        .enumerate()
        .for_each(|(i, text)| {
            let padded = format!("{}{}{}", "~".repeat(order), text, "~".repeat(order));
            let count = count_data.map(|c| c[i]).unwrap_or(1);
            
            let mut model_lock = model.lock().unwrap();
            model_lock.train(&padded, count);
        });

    let model = Arc::try_unwrap(model)
        .expect("Arc should have only one reference")
        .into_inner()
        .unwrap();

    println!(
        "Parallel training took {:.2} minutes",
        start.elapsed().as_secs_f64() / 60.0
    );

    Ok(model)
}

/// Parallel execution on data
pub fn execute_parallel(
    model: &MarkovModel,
    data: Vec<AHashMap<String, String>>,
    col_name: &str,
) -> Result<Vec<(String, f64, AHashMap<String, String>)>> {
    println!("Applying model to data (parallel mode)...");

    // Process rows in parallel
    let results: Vec<_> = data
        .par_iter()
        .filter_map(|row| {
            row.get(col_name).map(|text| {
                let padded = format!("{}{}", "~".repeat(model.order), text);
                let score = model.log_likelihood(&padded);
                (text.clone(), score, row.clone())
            })
        })
        .collect();

    Ok(results)
}

/// Group results after parallel execution
pub fn group_results(
    results: Vec<(String, f64, AHashMap<String, String>)>,
    col_name: &str,
) -> Vec<ScoredResult> {
    let mut grouped: AHashMap<String, ScoredResult> = AHashMap::new();

    for (text, score, row) in results {
        let entry = grouped.entry(text.clone()).or_insert_with(|| ScoredResult {
            command_line: text,
            score,
            machine: None,
            other_fields: AHashMap::new(),
            unusual_ngrams: None,
        });

        for (key, value) in row {
            if key != col_name {
                entry
                    .other_fields
                    .entry(key)
                    .or_insert_with(Vec::new)
                    .push(value);
            }
        }

        if score < entry.score {
            entry.score = score;
        }
    }

    let mut final_results: Vec<_> = grouped.into_values().collect();
    final_results.sort_by(|a, b| {
        a.score
            .partial_cmp(&b.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    final_results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parallel_training() {
        let data = vec![
            "hello world".to_string(),
            "hello rust".to_string(),
            "world of rust".to_string(),
        ];

        let model = train_parallel(&data, 3, None, None).unwrap();
        assert_eq!(model.order, 3);
        assert!(!model.is_trained()); // Not normalized yet
    }

    #[test]
    fn test_parallel_execution() {
        let data = vec![
            "hello world".to_string(),
            "test data".to_string(),
        ];

        let mut model = train_parallel(&data, 2, None, None).unwrap();
        model.normalize_model_and_compute_prior();

        let test_data = vec![
            AHashMap::from([
                ("cmd".to_string(), "hello".to_string()),
                ("user".to_string(), "alice".to_string()),
            ]),
            AHashMap::from([
                ("cmd".to_string(), "test".to_string()),
                ("user".to_string(), "bob".to_string()),
            ]),
        ];

        let results = execute_parallel(&model, test_data, "cmd").unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_parallel_vs_serial_consistency() {
        let data: Vec<String> = (0..100)
            .map(|i| format!("command number {}", i))
            .collect();

        // Serial training
        let mut serial_model = MarkovModel::new(3);
        for text in &data {
            let padded = format!("~~~{}~~~", text);
            serial_model.train(&padded, 1);
        }

        // Parallel training
        let parallel_model = train_parallel(&data, 3, None, None).unwrap();

        // Both should have the same order
        assert_eq!(serial_model.order, parallel_model.order);
    }

    #[test]
    fn test_group_results() {
        let results = vec![
            (
                "cmd1".to_string(),
                -5.0,
                AHashMap::from([
                    ("cmd".to_string(), "cmd1".to_string()),
                    ("user".to_string(), "alice".to_string()),
                ]),
            ),
            (
                "cmd1".to_string(),
                -6.0,
                AHashMap::from([
                    ("cmd".to_string(), "cmd1".to_string()),
                    ("user".to_string(), "bob".to_string()),
                ]),
            ),
            (
                "cmd2".to_string(),
                -3.0,
                AHashMap::from([
                    ("cmd".to_string(), "cmd2".to_string()),
                    ("user".to_string(), "charlie".to_string()),
                ]),
            ),
        ];

        let grouped = group_results(results, "cmd");

        assert_eq!(grouped.len(), 2);
        // Sorted by score ascending (worst first): cmd1 (-6.0) then cmd2 (-3.0)
        assert_eq!(grouped[0].command_line, "cmd1");
        assert_eq!(grouped[0].score, -6.0);
        assert_eq!(grouped[1].command_line, "cmd2");
        assert_eq!(grouped[1].score, -3.0);
    }
}
