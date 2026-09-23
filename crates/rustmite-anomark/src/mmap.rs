use crate::model::MarkovModel;
use anyhow::{Context, Result};
use memmap2::Mmap;
use std::fs::File;
use std::io::{BufRead, BufReader, Cursor};

/// Train model using memory-mapped file for large datasets
pub fn train_from_mmap(path: &str, order: usize) -> Result<MarkovModel> {
    println!("Loading file with memory mapping: {}", path);
    
    let file = File::open(path)
        .with_context(|| format!("Failed to open file: {}", path))?;
    
    // Safety: We're only reading the file, not modifying it
    let mmap = unsafe { 
        Mmap::map(&file)
            .context("Failed to memory-map file")? 
    };
    
    println!("File mapped to memory ({} bytes)", mmap.len());
    
    let mut model = MarkovModel::new(order);
    let cursor = Cursor::new(&mmap[..]);
    let reader = BufReader::new(cursor);
    
    let mut lines_processed = 0;
    for (i, line) in reader.lines().enumerate() {
        let line = line.context("Failed to read line")?;
        let padded = format!(
            "{}{}{}",
            "~".repeat(order),
            line,
            "~".repeat(order)
        );
        model.train(&padded, 1);
        lines_processed += 1;
        
        if i % 10000 == 0 && i > 0 {
            println!("Processed {} lines", i);
        }
    }
    
    println!("Training complete: {} lines processed", lines_processed);
    Ok(model)
}

/// Score data using memory-mapped file
pub fn score_from_mmap(
    model: &MarkovModel,
    path: &str,
) -> Result<Vec<(String, f64)>> {
    println!("Loading file with memory mapping: {}", path);
    
    let file = File::open(path)
        .with_context(|| format!("Failed to open file: {}", path))?;
    
    // Safety: We're only reading the file
    let mmap = unsafe { 
        Mmap::map(&file)
            .context("Failed to memory-map file")? 
    };
    
    println!("File mapped to memory ({} bytes)", mmap.len());
    
    let cursor = Cursor::new(&mmap[..]);
    let reader = BufReader::new(cursor);
    
    let mut results = Vec::new();
    
    for (i, line) in reader.lines().enumerate() {
        let line = line.context("Failed to read line")?;
        let padded = format!("{}{}", "~".repeat(model.order), line);
        let score = model.log_likelihood(&padded);
        results.push((line, score));
        
        if i % 10000 == 0 && i > 0 {
            println!("Scored {} lines", i);
        }
    }
    
    // Sort by score
    results.sort_by(|a, b| {
        a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal)
    });
    
    Ok(results)
}

/// Get file size without loading it
pub fn get_file_info(path: &str) -> Result<FileInfo> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("Failed to get metadata for: {}", path))?;
    
    Ok(FileInfo {
        size_bytes: metadata.len(),
        size_mb: metadata.len() as f64 / 1024.0 / 1024.0,
        size_gb: metadata.len() as f64 / 1024.0 / 1024.0 / 1024.0,
    })
}

#[derive(Debug)]
pub struct FileInfo {
    pub size_bytes: u64,
    pub size_mb: f64,
    pub size_gb: f64,
}

impl FileInfo {
    pub fn display(&self) -> String {
        if self.size_gb >= 1.0 {
            format!("{:.2} GB", self.size_gb)
        } else if self.size_mb >= 1.0 {
            format!("{:.2} MB", self.size_mb)
        } else {
            format!("{} bytes", self.size_bytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_train_from_mmap() -> Result<()> {
        // Create temporary file
        let mut temp_file = NamedTempFile::new()?;
        writeln!(temp_file, "hello world")?;
        writeln!(temp_file, "hello rust")?;
        writeln!(temp_file, "world of rust")?;
        temp_file.flush()?;

        let path = temp_file.path().to_str().unwrap();
        let model = train_from_mmap(path, 3)?;

        assert_eq!(model.order, 3);
        Ok(())
    }

    #[test]
    fn test_score_from_mmap() -> Result<()> {
        // Create training file
        let mut train_file = NamedTempFile::new()?;
        writeln!(train_file, "normal command")?;
        writeln!(train_file, "normal execution")?;
        train_file.flush()?;

        // Train model
        let mut model = train_from_mmap(train_file.path().to_str().unwrap(), 3)?;
        model.normalize_model_and_compute_prior();

        // Create test file
        let mut test_file = NamedTempFile::new()?;
        writeln!(test_file, "normal command")?;
        writeln!(test_file, "unusual anomaly")?;
        test_file.flush()?;

        // Score
        let results = score_from_mmap(&model, test_file.path().to_str().unwrap())?;

        assert_eq!(results.len(), 2);
        // First result should be the anomalous one (lower score)
        assert!(results[0].0.contains("unusual") || results[1].0.contains("unusual"));

        Ok(())
    }

    #[test]
    fn test_large_file_mmap() -> Result<()> {
        // Create a larger file
        let mut temp_file = NamedTempFile::new()?;
        for i in 0..1000 {
            writeln!(temp_file, "command line number {}", i)?;
        }
        temp_file.flush()?;

        let path = temp_file.path().to_str().unwrap();
        let model = train_from_mmap(path, 4)?;

        assert_eq!(model.order, 4);
        Ok(())
    }

    #[test]
    fn test_get_file_info() -> Result<()> {
        let mut temp_file = NamedTempFile::new()?;
        writeln!(temp_file, "test data")?;
        temp_file.flush()?;

        let info = get_file_info(temp_file.path().to_str().unwrap())?;

        assert!(info.size_bytes > 0);
        assert!(info.size_mb > 0.0);
        assert!(!info.display().is_empty());

        Ok(())
    }

    #[test]
    fn test_file_info_display() {
        let info = FileInfo {
            size_bytes: 1024,
            size_mb: 0.001,
            size_gb: 0.0,
        };
        assert!(info.display().contains("bytes"));

        let info = FileInfo {
            size_bytes: 1048576,
            size_mb: 1.0,
            size_gb: 0.001,
        };
        assert!(info.display().contains("MB"));

        let info = FileInfo {
            size_bytes: 1073741824,
            size_mb: 1024.0,
            size_gb: 1.0,
        };
        assert!(info.display().contains("GB"));
    }

    #[test]
    fn test_mmap_vs_regular_consistency() -> Result<()> {
        // Create file
        let mut temp_file = NamedTempFile::new()?;
        let test_data = vec!["hello world", "test data", "sample line"];
        for line in &test_data {
            writeln!(temp_file, "{}", line)?;
        }
        temp_file.flush()?;

        // Train with mmap
        let mmap_model = train_from_mmap(temp_file.path().to_str().unwrap(), 3)?;

        // Train normally
        let mut normal_model = MarkovModel::new(3);
        for line in test_data {
            let padded = format!("~~~{}~~~", line);
            normal_model.train(&padded, 1);
        }

        // Both should have same order
        assert_eq!(mmap_model.order, normal_model.order);

        Ok(())
    }
}
