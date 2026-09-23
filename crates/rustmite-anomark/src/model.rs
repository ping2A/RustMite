use ahash::AHashMap;
use anyhow::{Context, Result};
use rand::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarkovModel {
    pub order: usize,
    markov_chain: AHashMap<String, AHashMap<char, usize>>,
    normed_chain: AHashMap<String, AHashMap<char, f64>>,
    pub prior: f64,
    alphabet: Vec<char>,
}

impl MarkovModel {
    pub fn new(order: usize) -> Self {
        Self {
            order,
            markov_chain: AHashMap::new(),
            normed_chain: AHashMap::new(),
            prior: 0.001,
            alphabet: Vec::new(),
        }
    }

    /// Train the model on input data
    pub fn train(&mut self, training_data: &str, count: usize) {
        let chars: Vec<char> = training_data.chars().collect();
        
        for i in 0..chars.len().saturating_sub(self.order) {
            let current_ngram: String = chars[i..i + self.order].iter().collect();
            let next_letter = chars[i + self.order];

            self.markov_chain
                .entry(current_ngram)
                .or_insert_with(AHashMap::new)
                .entry(next_letter)
                .and_modify(|c| *c += count)
                .or_insert(count);

            if !self.alphabet.contains(&next_letter) {
                self.alphabet.push(next_letter);
            }
        }
    }

    /// Normalize the transition matrix and compute prior
    pub fn normalize_model_and_compute_prior(&mut self) {
        // Normalize transition matrix
        for (ngram, transitions) in &self.markov_chain {
            let total: usize = transitions.values().sum();
            let normalized: AHashMap<char, f64> = transitions
                .iter()
                .map(|(k, v)| (*k, *v as f64 / total as f64))
                .collect();
            self.normed_chain.insert(ngram.clone(), normalized);
        }

        // Sort alphabet
        self.alphabet.sort();

        // Compute minimum probability as prior
        let probabilities: Vec<f64> = self
            .normed_chain
            .values()
            .flat_map(|d| d.values())
            .copied()
            .collect();

        if let Some(&min_prob) = probabilities.iter().min_by(|a, b| {
            a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal)
        }) {
            self.prior = 0.01 * min_prob;
        }
    }

    /// Generate a simulated sequence from the model
    pub fn simulate(&self, length: usize, start: Option<&str>) -> Result<String> {
        self.check_if_trained()?;

        let mut rng = thread_rng();
        let mut simulation = if let Some(start_str) = start {
            start_str.to_string()
        } else {
            self.normed_chain
                .keys()
                .choose(&mut rng)
                .context("No n-grams in model")?
                .clone()
        };

        let target_length = length.max(simulation.len());
        let chars_to_generate = target_length.saturating_sub(simulation.len());

        for _ in 0..chars_to_generate {
            let ngram = if simulation.len() >= self.order {
                &simulation[simulation.len() - self.order..]
            } else {
                &simulation
            };
            let next_char = self.generate_letter(ngram)?;
            simulation.push(next_char);
        }

        Ok(simulation)
    }

    /// Generate a random letter from an n-gram
    fn generate_letter(&self, ngram: &str) -> Result<char> {
        let mut rng = thread_rng();

        if let Some(distribution) = self.normed_chain.get(ngram) {
            let mut r: f64 = rng.gen();
            for (key, prob) in distribution {
                r -= prob;
                if r <= 0.0 {
                    return Ok(*key);
                }
            }
        }

        self.alphabet
            .choose(&mut rng)
            .copied()
            .context("Empty alphabet")
    }

    /// Compute the log likelihood of a sequence
    pub fn log_likelihood(&self, sequence: &str) -> f64 {
        let ngrams = self.log_likelihood_ngrams(sequence);
        if ngrams.is_empty() {
            return self.prior.ln();
        }
        let sum: f64 = ngrams.iter().map(|(_, lp)| lp).sum();
        sum / ngrams.len() as f64
    }

    /// Per-(order+1)-gram log probabilities. Each element is (ngram_string, log_prob).
    /// Used for explainability: which n-grams contributed to a low score.
    pub fn log_likelihood_ngrams(&self, sequence: &str) -> Vec<(String, f64)> {
        if self.normed_chain.is_empty() {
            return Vec::new();
        }
        let chars: Vec<char> = sequence.chars().collect();
        let mut out = Vec::with_capacity(chars.len().saturating_sub(self.order));

        for i in 0..chars.len().saturating_sub(self.order) {
            let ngram: String = chars[i..i + self.order].iter().collect();
            let next_letter = chars[i + self.order];
            let full_ngram: String = chars[i..=i + self.order].iter().collect();

            let probability = self
                .normed_chain
                .get(&ngram)
                .and_then(|d| d.get(&next_letter))
                .copied()
                .unwrap_or(self.prior);

            out.push((full_ngram, probability.ln()));
        }
        out
    }

    /// Explain a sequence: overall score and list of unusual n-grams (log_prob below threshold).
    /// Unusual n-grams are those contributing most to anomaly.
    pub fn explain(&self, sequence: &str, threshold: f64) -> (f64, Vec<(String, f64)>) {
        let ngrams = self.log_likelihood_ngrams(sequence);
        let score = if ngrams.is_empty() {
            self.prior.ln()
        } else {
            ngrams.iter().map(|(_, lp)| lp).sum::<f64>() / ngrams.len() as f64
        };
        let unusual: Vec<(String, f64)> = ngrams
            .into_iter()
            .filter(|(_, lp)| *lp < threshold)
            .collect();
        (score, unusual)
    }

    fn check_if_trained(&self) -> Result<()> {
        if self.normed_chain.is_empty() {
            anyhow::bail!("Must train model before simulating new sequences");
        }
        Ok(())
    }

    /// Check if the model is trained
    pub fn is_trained(&self) -> bool {
        !self.normed_chain.is_empty()
    }

    /// Number of distinct context n-grams (states) in the normalized chain.
    pub fn num_contexts(&self) -> usize {
        self.normed_chain.len()
    }

    /// Total number of outgoing transitions (sum over contexts of distinct next characters).
    pub fn num_transitions(&self) -> usize {
        self.normed_chain.values().map(|m| m.len()).sum()
    }

    /// Size of the character alphabet seen during training.
    pub fn alphabet_len(&self) -> usize {
        self.alphabet.len()
    }

    /// Raw count entries in the unnormalized chain (before normalize; 0 if only normalized in memory).
    pub fn raw_markov_entries(&self) -> usize {
        self.markov_chain.values().map(|m| m.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_training() {
        let mut model = MarkovModel::new(2);
        model.train("hello world", 1);
        assert!(!model.markov_chain.is_empty());
    }

    #[test]
    fn test_log_likelihood() {
        let mut model = MarkovModel::new(2);
        model.train("hello hello hello", 1);
        model.normalize_model_and_compute_prior();
        
        let score = model.log_likelihood("hello");
        assert!(score.is_finite());
    }

    #[test]
    fn test_simulate() {
        let mut model = MarkovModel::new(2);
        model.train("abcabcabc", 1);
        model.normalize_model_and_compute_prior();
        
        let result = model.simulate(10, None);
        assert!(result.is_ok());
        assert!(result.unwrap().len() >= 2);
    }

    #[test]
    fn test_explain_returns_unusual_ngrams() {
        let mut model = MarkovModel::new(2);
        model.train("hello world hello world", 1);
        model.normalize_model_and_compute_prior();
        let threshold = model.prior.ln() * 0.95;
        let (score_normal, unusual_normal) = model.explain("~~hello~~", threshold);
        let (score_weird, unusual_weird) = model.explain("~~xyzq~~", threshold);
        assert!(score_weird < score_normal);
        assert!(unusual_weird.len() > unusual_normal.len());
    }

    #[test]
    fn test_log_likelihood_ngrams() {
        let mut model = MarkovModel::new(2);
        // Train on a sequence long enough for order 2 (need at least 3 chars per n-gram)
        model.train("~~ab~~", 1);
        model.normalize_model_and_compute_prior();
        let ngrams = model.log_likelihood_ngrams("~~ab~~");
        assert!(!ngrams.is_empty());
        let avg: f64 = ngrams.iter().map(|(_, lp)| lp).sum::<f64>() / ngrams.len() as f64;
        assert!((avg - model.log_likelihood("~~ab~~")).abs() < 1e-10);
    }

    #[test]
    fn test_model_statistics() {
        let m = MarkovModel::new(3);
        assert_eq!(m.num_contexts(), 0);
        assert_eq!(m.num_transitions(), 0);
        let mut m2 = MarkovModel::new(2);
        m2.train("abc", 1);
        m2.normalize_model_and_compute_prior();
        assert!(m2.num_contexts() > 0);
        assert!(m2.num_transitions() > 0);
    }
}