//! Tokenization strategies for token-level Markov models.

use serde::{Deserialize, Serialize};

/// Tokenizer strategy: how to split a string into tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Tokenizer {
    /// Split on whitespace (one or more spaces, tabs, newlines)
    Whitespace,
    /// Split on path separators (/ and \), keeping the separators as tokens
    PathSegments,
    /// Split on whitespace and also on / and \ (path-like tokens)
    WhitespaceAndPath,
}

impl Tokenizer {
    /// Tokenize a string into a sequence of tokens.
    pub fn tokenize(&self, s: &str) -> Vec<String> {
        match self {
            Tokenizer::Whitespace => s
                .split_whitespace()
                .map(|t| t.to_string())
                .filter(|t| !t.is_empty())
                .collect(),
            Tokenizer::PathSegments => split_path_segments(s),
            Tokenizer::WhitespaceAndPath => {
                let path_tokens = split_path_segments(s);
                let mut out = Vec::new();
                for t in path_tokens {
                    if t == "/" || t == "\\" {
                        out.push(t);
                    } else {
                        for w in t.split_whitespace() {
                            if !w.is_empty() {
                                out.push(w.to_string());
                            }
                        }
                    }
                }
                out
            }
        }
    }
}

fn split_path_segments(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for c in s.chars() {
        if c == '/' || c == '\\' {
            if !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
            out.push(c.to_string());
        } else {
            current.push(c);
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

impl Default for Tokenizer {
    fn default() -> Self {
        Tokenizer::Whitespace
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_whitespace() {
        let t = Tokenizer::Whitespace;
        assert_eq!(t.tokenize("a b  c"), vec!["a", "b", "c"]);
        assert_eq!(t.tokenize("/usr/bin/curl"), vec!["/usr/bin/curl"]);
    }

    #[test]
    fn test_path_segments() {
        let t = Tokenizer::PathSegments;
        let out = t.tokenize("/usr/bin/curl");
        assert_eq!(out, vec!["/", "usr", "/", "bin", "/", "curl"]);
        let out2 = t.tokenize("C:\\Windows\\System32");
        assert!(out2.iter().any(|s| s == "Windows"));
        assert!(out2.iter().any(|s| s == "System32"));
    }

    #[test]
    fn test_whitespace_and_path() {
        let t = Tokenizer::WhitespaceAndPath;
        let out = t.tokenize("/usr/bin/curl -s http://x");
        assert!(out.iter().any(|s| s == "/"));
        assert!(out.iter().any(|s| s == "usr"));
        assert!(out.iter().any(|s| s == "curl"));
        assert!(out.iter().any(|s| s == "-s"));
    }
}
