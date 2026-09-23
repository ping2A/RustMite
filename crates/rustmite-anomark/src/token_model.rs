//! Token-level Markov model: n-gram transitions over tokens (e.g. words, path segments).

use ahash::AHashMap;
use serde::{Deserialize, Serialize};

use crate::tokenizer::Tokenizer;

const PAD_TOKEN: &str = "~";
const SEP: &str = "\x01";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenMarkovModel {
    pub order: usize,
    pub tokenizer: Tokenizer,
    chain: AHashMap<String, AHashMap<String, usize>>,
    normed_chain: AHashMap<String, AHashMap<String, f64>>,
    pub prior: f64,
}

impl TokenMarkovModel {
    pub fn new(order: usize, tokenizer: Tokenizer) -> Self {
        Self {
            order,
            tokenizer,
            chain: AHashMap::new(),
            normed_chain: AHashMap::new(),
            prior: 0.001,
        }
    }

    fn context_key(tokens: &[String]) -> String {
        tokens.join(SEP)
    }

    /// Train on a sequence of tokens (e.g. from one command line).
    pub fn train_tokens(&mut self, tokens: &[String], count: usize) {
        if tokens.is_empty() {
            return;
        }
        let pad: Vec<String> = (0..self.order).map(|_| PAD_TOKEN.to_string()).collect();
        let padded: Vec<String> = pad
            .iter()
            .cloned()
            .chain(tokens.iter().cloned())
            .chain(pad.iter().cloned())
            .collect();

        for i in 0..padded.len().saturating_sub(self.order) {
            let context = Self::context_key(&padded[i..i + self.order]);
            let next = padded[i + self.order].clone();
            self.chain
                .entry(context)
                .or_insert_with(AHashMap::new)
                .entry(next)
                .and_modify(|c| *c += count)
                .or_insert(count);
        }
    }

    /// Train from a raw string (tokenize with the model's tokenizer).
    pub fn train(&mut self, s: &str, count: usize) {
        let tokens = self.tokenizer.tokenize(s);
        self.train_tokens(&tokens, count);
    }

    /// Normalize and compute prior. Call before scoring.
    pub fn normalize_model_and_compute_prior(&mut self) {
        for (ctx, next_counts) in &self.chain {
            let total: usize = next_counts.values().sum();
            let normed: AHashMap<String, f64> = next_counts
                .iter()
                .map(|(k, v)| (k.clone(), *v as f64 / total as f64))
                .collect();
            self.normed_chain.insert(ctx.clone(), normed);
        }

        let probs: Vec<f64> = self
            .normed_chain
            .values()
            .flat_map(|m| m.values().copied())
            .collect();
        if let Some(&min_p) = probs.iter().min_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal)) {
            self.prior = 0.01 * min_p;
        }
    }

    pub fn is_trained(&self) -> bool {
        !self.normed_chain.is_empty()
    }

    /// Number of distinct token contexts in the normalized chain.
    pub fn num_contexts(&self) -> usize {
        self.normed_chain.len()
    }

    /// Total number of distinct next-token transitions (sum over contexts).
    pub fn num_transitions(&self) -> usize {
        self.normed_chain.values().map(|m| m.len()).sum()
    }

    /// Log likelihood of a token sequence (average log prob per transition).
    pub fn log_likelihood_tokens(&self, tokens: &[String]) -> f64 {
        if self.normed_chain.is_empty() {
            return self.prior.ln();
        }
        let pad: Vec<String> = (0..self.order).map(|_| PAD_TOKEN.to_string()).collect();
        let padded: Vec<String> = pad
            .iter()
            .cloned()
            .chain(tokens.iter().cloned())
            .chain(pad.iter().cloned())
            .collect();

        let mut sum = 0.0;
        let mut n = 0usize;
        for i in 0..padded.len().saturating_sub(self.order) {
            let context = Self::context_key(&padded[i..i + self.order]);
            let next = &padded[i + self.order];
            let prob = self
                .normed_chain
                .get(&context)
                .and_then(|m| m.get(next))
                .copied()
                .unwrap_or(self.prior);
            sum += prob.ln();
            n += 1;
        }
        if n == 0 {
            self.prior.ln()
        } else {
            sum / n as f64
        }
    }

    /// Log likelihood of a raw string (tokenize then score).
    pub fn log_likelihood(&self, s: &str) -> f64 {
        let tokens = self.tokenizer.tokenize(s);
        self.log_likelihood_tokens(&tokens)
    }

    /// Per-transition log probs: (context_and_next as string, log_prob). For explainability.
    pub fn log_likelihood_ngrams(&self, s: &str) -> Vec<(String, f64)> {
        if self.normed_chain.is_empty() {
            return Vec::new();
        }
        let tokens = self.tokenizer.tokenize(s);
        let pad: Vec<String> = (0..self.order).map(|_| PAD_TOKEN.to_string()).collect();
        let padded: Vec<String> = pad
            .iter()
            .cloned()
            .chain(tokens.iter().cloned())
            .chain(pad.iter().cloned())
            .collect();

        let mut out = Vec::new();
        for i in 0..padded.len().saturating_sub(self.order) {
            let context = Self::context_key(&padded[i..i + self.order]);
            let next = &padded[i + self.order];
            let prob = self
                .normed_chain
                .get(&context)
                .and_then(|m| m.get(next))
                .copied()
                .unwrap_or(self.prior);
            let ngram_display = format!("{} -> {}", context.replace('\x01', " "), next);
            out.push((ngram_display, prob.ln()));
        }
        out
    }

    /// Explain: overall score and unusual token transitions (below threshold).
    pub fn explain(&self, s: &str, threshold: f64) -> (f64, Vec<(String, f64)>) {
        let ngrams = self.log_likelihood_ngrams(s);
        let score = if ngrams.is_empty() {
            self.prior.ln()
        } else {
            ngrams.iter().map(|(_, lp)| lp).sum::<f64>() / ngrams.len() as f64
        };
        let unusual = ngrams
            .into_iter()
            .filter(|(_, lp)| *lp < threshold)
            .collect();
        (score, unusual)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_model_train_and_score() {
        let mut m = TokenMarkovModel::new(2, Tokenizer::Whitespace);
        m.train("curl http://example.com", 1);
        m.train("curl http://other.com", 1);
        m.train("wget http://example.com", 1);
        m.normalize_model_and_compute_prior();
        let score_curl = m.log_likelihood("curl http://example.com");
        let score_weird = m.log_likelihood("xyz random junk");
        assert!(score_curl > score_weird);
    }

    #[test]
    fn test_token_model_explain() {
        let mut m = TokenMarkovModel::new(1, Tokenizer::Whitespace);
        m.train("a b c", 1);
        m.train("a b d", 1);
        m.normalize_model_and_compute_prior();
        let (_score, unusual) = m.explain("a b z", -10.0); // threshold very low so nothing unusual
        assert!(unusual.is_empty());
        let (_, unusual2) = m.explain("a b z", 0.0); // threshold 0, so low-prob transitions count
        assert!(!unusual2.is_empty());
    }
}
