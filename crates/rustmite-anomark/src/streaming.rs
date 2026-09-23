use crate::model::MarkovModel;
use anyhow::Result;
use std::io::{BufRead, BufReader, Read};

/// Streaming training - processes data line by line without loading everything into memory
pub struct StreamingTrainer {
    model: MarkovModel,
    lines_processed: usize,
    chunk_size: usize,
}

impl StreamingTrainer {
    pub fn new(order: usize, chunk_size: usize) -> Self {
        Self {
            model: MarkovModel::new(order),
            lines_processed: 0,
            chunk_size,
        }
    }

    /// Train on a stream of data
    pub fn train_stream<R: Read>(&mut self, reader: R) -> Result<()> {
        let buf_reader = BufReader::new(reader);
        let mut buffer = Vec::new();

        for line in buf_reader.lines() {
            let line = line?;
            buffer.push(line);

            // Process in chunks to maintain some efficiency
            if buffer.len() >= self.chunk_size {
                self.process_chunk(&buffer);
                buffer.clear();
            }
        }

        // Process remaining lines
        if !buffer.is_empty() {
            self.process_chunk(&buffer);
        }

        Ok(())
    }

    fn process_chunk(&mut self, lines: &[String]) {
        for line in lines {
            let padded = format!(
                "{}{}{}",
                "~".repeat(self.model.order),
                line,
                "~".repeat(self.model.order)
            );
            self.model.train(&padded, 1);
            self.lines_processed += 1;

            if self.lines_processed % 10000 == 0 {
                println!("Processed {} lines", self.lines_processed);
            }
        }
    }

    /// Get the trained model
    pub fn into_model(self) -> MarkovModel {
        self.model
    }

    /// Get reference to the model
    pub fn model(&self) -> &MarkovModel {
        &self.model
    }

    /// Get mutable reference to the model
    pub fn model_mut(&mut self) -> &mut MarkovModel {
        &mut self.model
    }

    /// Get number of lines processed
    pub fn lines_processed(&self) -> usize {
        self.lines_processed
    }
}

/// Streaming scorer - scores data line by line without loading everything
pub struct StreamingScorer {
    model: MarkovModel,
}

impl StreamingScorer {
    pub fn new(model: MarkovModel) -> Self {
        Self { model }
    }

    /// Score a stream of data and return results as they're processed
    pub fn score_stream<R: Read, F>(&self, reader: R, mut callback: F) -> Result<()>
    where
        F: FnMut(&str, f64),
    {
        let buf_reader = BufReader::new(reader);

        for (i, line) in buf_reader.lines().enumerate() {
            let line = line?;
            let padded = format!("{}{}", "~".repeat(self.model.order), line);
            let score = self.model.log_likelihood(&padded);

            callback(&line, score);

            if i % 10000 == 0 && i > 0 {
                println!("Scored {} lines", i);
            }
        }

        Ok(())
    }

    /// Score a stream and collect only anomalies (below threshold)
    pub fn score_stream_filter<R: Read>(
        &self,
        reader: R,
        threshold: f64,
    ) -> Result<Vec<(String, f64)>> {
        let mut anomalies = Vec::new();
        let buf_reader = BufReader::new(reader);

        for line in buf_reader.lines() {
            let line = line?;
            let padded = format!("{}{}", "~".repeat(self.model.order), line);
            let score = self.model.log_likelihood(&padded);

            if score < threshold {
                anomalies.push((line, score));
            }
        }

        // Sort by score (most anomalous first)
        anomalies.sort_by(|a, b| {
            a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal)
        });

        Ok(anomalies)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_streaming_trainer() {
        let data = "hello world\nhello rust\nworld of rust\n";
        let cursor = Cursor::new(data.as_bytes());

        let mut trainer = StreamingTrainer::new(3, 10);
        trainer.train_stream(cursor).unwrap();

        assert_eq!(trainer.lines_processed(), 3);
        assert_eq!(trainer.model().order, 3);
    }

    #[test]
    fn test_streaming_trainer_with_chunks() {
        let data = (0..100).map(|i| format!("line {}\n", i)).collect::<String>();
        let cursor = Cursor::new(data.as_bytes());

        let mut trainer = StreamingTrainer::new(2, 5);
        trainer.train_stream(cursor).unwrap();

        assert_eq!(trainer.lines_processed(), 100);
    }

    #[test]
    fn test_streaming_scorer() {
        // Train model
        let train_data = "hello world\nhello rust\n";
        let cursor = Cursor::new(train_data.as_bytes());

        let mut trainer = StreamingTrainer::new(3, 10);
        trainer.train_stream(cursor).unwrap();

        let mut model = trainer.into_model();
        model.normalize_model_and_compute_prior();

        // Score new data
        let test_data = "hello world\nunusual data\n";
        let cursor = Cursor::new(test_data.as_bytes());

        let scorer = StreamingScorer::new(model);
        let mut results = Vec::new();

        scorer
            .score_stream(cursor, |line, score| {
                results.push((line.to_string(), score));
            })
            .unwrap();

        assert_eq!(results.len(), 2);
        // "hello world" should have better score than "unusual data"
        assert!(results[0].1 > results[1].1);
    }

    #[test]
    fn test_streaming_scorer_filter() {
        // Train model
        let train_data = "normal command\nnormal execution\n";
        let cursor = Cursor::new(train_data.as_bytes());

        let mut trainer = StreamingTrainer::new(3, 10);
        trainer.train_stream(cursor).unwrap();

        let mut model = trainer.into_model();
        model.normalize_model_and_compute_prior();

        // Score and filter
        let test_data = "normal command\nvery unusual anomaly\nnormal execution\n";
        let cursor = Cursor::new(test_data.as_bytes());

        let threshold = model.prior.ln() * 0.95;
        let scorer = StreamingScorer::new(model);
        let anomalies = scorer.score_stream_filter(cursor, threshold).unwrap();

        // Should detect the unusual line
        assert!(!anomalies.is_empty());
        assert!(anomalies
            .iter()
            .any(|(line, _)| line.contains("unusual")));
    }

    #[test]
    fn test_large_stream() {
        // Simulate processing a large file
        let mut large_data = String::new();
        for i in 0..10000 {
            large_data.push_str(&format!("command line number {}\n", i));
        }

        let cursor = Cursor::new(large_data.as_bytes());
        let mut trainer = StreamingTrainer::new(4, 100);
        trainer.train_stream(cursor).unwrap();

        assert_eq!(trainer.lines_processed(), 10000);
    }

    #[test]
    fn test_empty_stream() {
        let data = "";
        let cursor = Cursor::new(data.as_bytes());

        let mut trainer = StreamingTrainer::new(3, 10);
        let result = trainer.train_stream(cursor);

        assert!(result.is_ok());
        assert_eq!(trainer.lines_processed(), 0);
    }
}
