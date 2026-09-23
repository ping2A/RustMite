use rustmite_anomark::{ModelHandler, MarkovModel};
use ahash::AHashMap;
use tempfile::tempdir;

#[test]
fn test_train_from_txt() {
    let training_text = "This is some data~~~~This is some data~~~~This is some data~~~~Some new is data";
    let model = ModelHandler::train_from_txt(training_text, 4, None).unwrap();
    
    assert_eq!(model.order, 4);
    assert!(!model.is_trained()); // Not normalized yet
}

#[test]
fn test_train_and_normalize() {
    let training_text = "hello world hello world";
    let mut model = ModelHandler::train_from_txt(training_text, 2, None).unwrap();
    model.normalize_model_and_compute_prior();
    
    assert!(model.is_trained());
    assert!(model.prior > 0.0);
}

#[test]
fn test_train_from_csv() {
    let data = vec![
        "This is some data".to_string(),
        "Some new is data".to_string(),
        "word".to_string(),
    ];
    let counts = vec![10, 3, 1];
    
    let model = ModelHandler::train_from_csv(&data, 4, Some(&counts), None).unwrap();
    
    assert_eq!(model.order, 4);
}

#[test]
fn test_save_and_load_model() {
    let dir = tempdir().unwrap();
    let model_path = dir.path().join("test_model.bin");
    
    let training_text = "test data for serialization";
    let mut model = ModelHandler::train_from_txt(training_text, 3, None).unwrap();
    model.normalize_model_and_compute_prior();
    
    // Save
    ModelHandler::save_model(&model, Some(model_path.to_str().unwrap())).unwrap();
    
    // Load
    let loaded_model = ModelHandler::load_model(model_path.to_str().unwrap()).unwrap();
    
    assert_eq!(model.order, loaded_model.order);
    assert_eq!(model.prior, loaded_model.prior);
}

#[test]
fn test_log_likelihood() {
    let training_text = "hello hello hello";
    let mut model = ModelHandler::train_from_txt(training_text, 2, None).unwrap();
    model.normalize_model_and_compute_prior();
    
    let score1 = model.log_likelihood("~~hello");
    let score2 = model.log_likelihood("~~goodbye");
    
    // "hello" should have better (less negative) score than "goodbye"
    assert!(score1 > score2);
}

#[test]
fn test_execute_on_data() {
    let training_text = "normal command line normal command line";
    let mut model = ModelHandler::train_from_txt(training_text, 3, None).unwrap();
    model.normalize_model_and_compute_prior();
    
    let test_data = vec![
        AHashMap::from([
            ("CommandLine".to_string(), "normal command".to_string()),
            ("User".to_string(), "alice".to_string()),
        ]),
        AHashMap::from([
            ("CommandLine".to_string(), "unusual pattern".to_string()),
            ("User".to_string(), "bob".to_string()),
        ]),
    ];
    
    let results = ModelHandler::execute_on_data(
        &mut model,
        test_data,
        "CommandLine",
        false,
        false,
        false,
        95.0,
        None,
        None,
        None,
    ).unwrap();
    
    assert_eq!(results.len(), 2);
    assert!(results.iter().any(|r| r.command_line.contains("normal")));
    assert!(results.iter().any(|r| r.command_line.contains("unusual")));
}

#[test]
fn test_threshold_computation() {
    let mut model = MarkovModel::new(2);
    model.prior = 0.001;
    
    let threshold = ModelHandler::compute_threshold(&model, 95.0);
    
    // threshold should be 95% of log(prior)
    assert!((threshold - (model.prior.ln() * 0.95)).abs() < 0.0001);
}

// New tests for optimizations

#[test]
fn test_ahash_map_performance() {
    // Test that AHashMap works correctly
    let mut map: AHashMap<String, i32> = AHashMap::new();
    map.insert("key1".to_string(), 1);
    map.insert("key2".to_string(), 2);
    
    assert_eq!(map.get("key1"), Some(&1));
    assert_eq!(map.get("key2"), Some(&2));
    assert_eq!(map.len(), 2);
}

#[test]
fn test_parallel_training() {
    use rustmite_anomark::train_parallel;
    
    let data = vec![
        "hello world".to_string(),
        "hello rust".to_string(),
        "world of rust".to_string(),
    ];
    
    let model = train_parallel(&data, 3, None, None).unwrap();
    assert_eq!(model.order, 3);
}

#[test]
fn test_streaming_trainer() {
    use rustmite_anomark::StreamingTrainer;
    use std::io::Cursor;
    
    let data = "hello world\nhello rust\nworld of rust\n";
    let cursor = Cursor::new(data.as_bytes());
    
    let mut trainer = StreamingTrainer::new(3, 10);
    trainer.train_stream(cursor).unwrap();
    
    assert_eq!(trainer.lines_processed(), 3);
    assert_eq!(trainer.model().order, 3);
}

#[test]
fn test_streaming_scorer() {
    use rustmite_anomark::{StreamingTrainer, StreamingScorer};
    use std::io::Cursor;
    
    // Train
    let train_data = "hello world\nhello rust\n";
    let cursor = Cursor::new(train_data.as_bytes());
    let mut trainer = StreamingTrainer::new(3, 10);
    trainer.train_stream(cursor).unwrap();
    
    let mut model = trainer.into_model();
    model.normalize_model_and_compute_prior();
    
    // Score
    let test_data = "hello world\nunusual data\n";
    let cursor = Cursor::new(test_data.as_bytes());
    let scorer = StreamingScorer::new(model);
    
    let mut results = Vec::new();
    scorer.score_stream(cursor, |line, score| {
        results.push((line.to_string(), score));
    }).unwrap();
    
    assert_eq!(results.len(), 2);
}

#[test]
fn test_mmap_training() {
    use rustmite_anomark::train_from_mmap;
    use std::io::Write;
    use tempfile::NamedTempFile;
    
    let mut temp_file = NamedTempFile::new().unwrap();
    writeln!(temp_file, "hello world").unwrap();
    writeln!(temp_file, "hello rust").unwrap();
    temp_file.flush().unwrap();
    
    let path = temp_file.path().to_str().unwrap();
    let model = train_from_mmap(path, 3).unwrap();
    
    assert_eq!(model.order, 3);
}

#[test]
fn test_mmap_scoring() {
    use rustmite_anomark::{train_from_mmap, score_from_mmap};
    use std::io::Write;
    use tempfile::NamedTempFile;
    
    // Train
    let mut train_file = NamedTempFile::new().unwrap();
    writeln!(train_file, "normal command").unwrap();
    writeln!(train_file, "normal execution").unwrap();
    train_file.flush().unwrap();
    
    let mut model = train_from_mmap(train_file.path().to_str().unwrap(), 3).unwrap();
    model.normalize_model_and_compute_prior();
    
    // Score
    let mut test_file = NamedTempFile::new().unwrap();
    writeln!(test_file, "normal command").unwrap();
    writeln!(test_file, "unusual anomaly").unwrap();
    test_file.flush().unwrap();
    
    let results = score_from_mmap(&model, test_file.path().to_str().unwrap()).unwrap();
    assert_eq!(results.len(), 2);
}

#[test]
fn test_parallel_vs_serial_consistency() {
    use rustmite_anomark::train_parallel;
    
    let data: Vec<String> = (0..100)
        .map(|i| format!("command number {}", i))
        .collect();
    
    // Serial
    let mut serial_model = MarkovModel::new(3);
    for text in &data {
        let padded = format!("~~~{}~~~", text);
        serial_model.train(&padded, 1);
    }
    
    // Parallel
    let parallel_model = train_parallel(&data, 3, None, None).unwrap();
    
    assert_eq!(serial_model.order, parallel_model.order);
}

#[test]
fn test_large_dataset_streaming() {
    use rustmite_anomark::StreamingTrainer;
    use std::io::Cursor;
    
    // Simulate large dataset
    let mut large_data = String::new();
    for i in 0..10000 {
        large_data.push_str(&format!("command line number {}\n", i));
    }
    
    let cursor = Cursor::new(large_data.as_bytes());
    let mut trainer = StreamingTrainer::new(4, 100);
    trainer.train_stream(cursor).unwrap();
    
    assert_eq!(trainer.lines_processed(), 10000);
}

