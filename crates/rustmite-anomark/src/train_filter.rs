//! Optional filters to drop command lines before training (e.g. Linux kernel threads).

use anyhow::{Context, Result};
use regex::Regex;

/// True when `s` looks like a Linux kernel thread name: entire string is `[name]`, e.g. `[nvme-wq]`, `[kthreadd]`.
pub fn is_linux_kernel_thread_command(s: &str) -> bool {
    let t = s.trim();
    if t.len() < 3 || !t.starts_with('[') || !t.ends_with(']') {
        return false;
    }
    let inner = &t[1..t.len() - 1];
    !inner.is_empty() && !inner.contains('[') && !inner.contains(']')
}

/// Compiled rules for excluding lines from training corpora.
#[derive(Debug)]
pub struct TrainLineFilter {
    exclude_kernel_threads: bool,
    exclude_regexes: Vec<Regex>,
}

impl TrainLineFilter {
    /// Build a filter. `exclude_regex_patterns` are matched against the **full** command string (not trimmed), unless the pattern uses anchors.
    pub fn new(exclude_kernel_threads: bool, exclude_regex_patterns: &[String]) -> Result<Self> {
        let mut exclude_regexes = Vec::with_capacity(exclude_regex_patterns.len());
        for p in exclude_regex_patterns {
            exclude_regexes.push(
                Regex::new(p).with_context(|| format!("Invalid --exclude-regex pattern: {p}"))?,
            );
        }
        Ok(Self {
            exclude_kernel_threads,
            exclude_regexes,
        })
    }

    /// `true` if this command should be **dropped** from training.
    pub fn should_exclude(&self, cmd: &str) -> bool {
        if self.exclude_kernel_threads && is_linux_kernel_thread_command(cmd) {
            return true;
        }
        self.exclude_regexes.iter().any(|re| re.is_match(cmd))
    }
}

/// Drop excluded commands; keeps `counts` aligned when provided.
pub fn filter_training_lines(
    data: Vec<String>,
    counts: Option<Vec<usize>>,
    filter: &TrainLineFilter,
) -> (Vec<String>, Option<Vec<usize>>, usize) {
    let mut excluded = 0;
    match counts {
        Some(c) if c.len() == data.len() => {
            let mut nd = Vec::with_capacity(data.len());
            let mut nc = Vec::with_capacity(data.len());
            for (d, ct) in data.into_iter().zip(c.into_iter()) {
                if filter.should_exclude(&d) {
                    excluded += 1;
                } else {
                    nd.push(d);
                    nc.push(ct);
                }
            }
            (nd, Some(nc), excluded)
        }
        _ => {
            let mut nd = Vec::with_capacity(data.len());
            for d in data {
                if filter.should_exclude(&d) {
                    excluded += 1;
                } else {
                    nd.push(d);
                }
            }
            (nd, None, excluded)
        }
    }
}

/// Apply exclusion rules when any are enabled; otherwise returns inputs unchanged.
pub fn maybe_filter_training_lines(
    data: Vec<String>,
    counts: Option<Vec<usize>>,
    exclude_kernel_threads: bool,
    exclude_regex_patterns: &[String],
) -> Result<(Vec<String>, Option<Vec<usize>>, usize)> {
    if !exclude_kernel_threads && exclude_regex_patterns.is_empty() {
        return Ok((data, counts, 0));
    }
    let f = TrainLineFilter::new(exclude_kernel_threads, exclude_regex_patterns)?;
    let (d, c, ex) = filter_training_lines(data, counts, &f);
    Ok((d, c, ex))
}

/// Filter whole TXT training body by line when any rule is enabled.
pub fn maybe_filter_txt_training_body(
    text: String,
    exclude_kernel_threads: bool,
    exclude_regex_patterns: &[String],
) -> Result<(String, usize)> {
    if !exclude_kernel_threads && exclude_regex_patterns.is_empty() {
        return Ok((text, 0));
    }
    let f = TrainLineFilter::new(exclude_kernel_threads, exclude_regex_patterns)?;
    let (out, ex) = filter_txt_training_body(&text, &f);
    Ok((out, ex))
}

/// For plain-text training: keep only lines that are not excluded, preserve newlines between kept lines.
pub fn filter_txt_training_body(text: &str, filter: &TrainLineFilter) -> (String, usize) {
    let mut excluded = 0;
    let mut out = String::new();
    for line in text.lines() {
        if filter.should_exclude(line) {
            excluded += 1;
        } else {
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(line);
        }
    }
    (out, excluded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_thread_detection() {
        assert!(is_linux_kernel_thread_command("[nvme-wq]"));
        assert!(is_linux_kernel_thread_command("  [kthreadd]  "));
        assert!(is_linux_kernel_thread_command("[rcu_sched]"));
        assert!(!is_linux_kernel_thread_command("/usr/bin/bash"));
        assert!(!is_linux_kernel_thread_command("[not closed"));
        assert!(!is_linux_kernel_thread_command("a [b] c"));
    }

    #[test]
    fn filter_regex() {
        let f = TrainLineFilter::new(false, &[r"^systemd$".to_string()]).unwrap();
        assert!(f.should_exclude("systemd"));
        assert!(!f.should_exclude("/usr/lib/systemd/systemd"));
    }

    #[test]
    fn filter_kernel_and_counts() {
        let f = TrainLineFilter::new(true, &[]).unwrap();
        let data = vec![
            "[kthreadd]".to_string(),
            "/bin/ls".to_string(),
            "[nvme-wq]".to_string(),
        ];
        let counts = vec![1usize, 2, 3];
        let (d, c, ex) = filter_training_lines(data, Some(counts), &f);
        assert_eq!(ex, 2);
        assert_eq!(d, vec!["/bin/ls".to_string()]);
        assert_eq!(c, Some(vec![2]));
    }
}
