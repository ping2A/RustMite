//! Utility functions: entropy, path matching, command-line parsing.

use std::collections::HashMap;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use log;
use regex::Regex;

pub fn calculate_shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let normalized = s
        .replace('/', " ")
        .replace('.', " ")
        .replace('-', " ")
        .replace('_', " ");

    let mut counts = HashMap::new();
    for c in normalized.chars() {
        if !c.is_whitespace() {
            *counts.entry(c).or_insert(0) += 1;
        }
    }

    if counts.is_empty() {
        return 0.0;
    }

    let len = normalized.chars().filter(|c| !c.is_whitespace()).count() as f64;
    if len == 0.0 {
        return 0.0;
    }

    let entropy = counts.values().fold(0.0, |acc, &count| {
        let p = count as f64 / len;
        acc - p * p.log2()
    });

    entropy
}

/// Convert one glob-style whitelist pattern (`*`, `?`) into a full-match regex (anchored).
pub fn glob_wildcard_to_regex(pattern: &str) -> Result<Regex, regex::Error> {
    let mut regex_pattern = String::new();
    regex_pattern.push('^');
    for ch in pattern.chars() {
        match ch {
            '*' => regex_pattern.push_str(".*"),
            '?' => regex_pattern.push('.'),
            '.' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|' | '\\' => {
                regex_pattern.push('\\');
                regex_pattern.push(ch);
            }
            _ => regex_pattern.push(ch),
        }
    }
    regex_pattern.push('$');
    Regex::new(&regex_pattern)
}

/// Compile path whitelist globs once for hot loops (process/file loaders over large NDJSON).
///
/// Invalid patterns are skipped with a warning (same spirit as [`compile_regex_list`]).
pub fn compile_wildcard_list(patterns: &[String]) -> Vec<Regex> {
    patterns
        .iter()
        .filter_map(|p| match glob_wildcard_to_regex(p) {
            Ok(re) => Some(re),
            Err(e) => {
                log::warn!("Invalid whitelist glob {:?}: {}", p, e);
                None
            }
        })
        .collect()
}

/// True if `path` matches any precompiled whitelist glob.
#[inline]
pub fn is_path_whitelisted_compiled(path: &str, compiled: &[Regex]) -> bool {
    compiled.iter().any(|re| re.is_match(path))
}

/// Check if a path matches a glob-style pattern with wildcards (* and ?).
///
/// **Performance:** compiles a regex on every call; in loaders use [`compile_wildcard_list`] and
/// [`is_path_whitelisted_compiled`] instead.
pub fn matches_wildcard(path: &str, pattern: &str) -> bool {
    glob_wildcard_to_regex(pattern)
        .map(|re| re.is_match(path))
        .unwrap_or(false)
}

/// Check if path matches any whitelisted pattern (slow: recompiles each glob every time).
pub fn is_path_whitelisted(path: &str, whitelist: &[String]) -> bool {
    whitelist.iter().any(|pattern| matches_wildcard(path, pattern))
}

/// Check suspicious-path regexes against `path`.
///
/// **Performance:** compiles each pattern with [`Regex::new`] on every call. Fine for tests and
/// one-off checks; on hot paths (file/process builders over tens of thousands of rows) compile
/// once with [`compile_regex_list`] and use [`is_path_suspicious_compiled`] instead.
pub fn is_path_suspicious(path: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|pattern| {
        Regex::new(pattern)
            .map(|re| re.is_match(path))
            .unwrap_or(false)
    })
}

/// Precompiled variant of [`is_path_suspicious`]; pass the output of [`compile_regex_list`].
#[inline]
pub fn is_path_suspicious_compiled(path: &str, compiled: &[Regex]) -> bool {
    compiled.iter().any(|re| re.is_match(path))
}

/// Compile regex strings for repeated matching; invalid patterns are skipped with a warning.
pub fn compile_regex_list(patterns: &[String]) -> Vec<Regex> {
    patterns
        .iter()
        .filter_map(|p| match Regex::new(p) {
            Ok(re) => Some(re),
            Err(e) => {
                log::warn!("Invalid regex pattern {:?}: {}", p, e);
                None
            }
        })
        .collect()
}

/// True if `path` matches any full-path regex, or its basename matches any filename regex.
pub fn file_path_matches_exclusion(path: &str, path_res: &[Regex], filename_res: &[Regex]) -> bool {
    if path_res.iter().any(|r| r.is_match(path)) {
        return true;
    }
    let basename = path
        .rsplit(|c| c == '/' || c == '\\')
        .next()
        .unwrap_or(path);
    filename_res.iter().any(|r| r.is_match(basename))
}

/// Parse timestamps from RFC3339 or common `T`/space-separated naive datetimes (e.g. `date` / `timestamp` in JSONL).
pub fn parse_log_datetime(s: &str) -> Option<DateTime<Utc>> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    for fmt in [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S",
    ] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(Utc.from_utc_datetime(&naive));
        }
    }
    None
}

/// Interpret `ls -l` style permission strings (e.g. `-rw-------.`) for group / world write bits.
pub fn unix_permission_flags(ls_perm: &str) -> (bool, bool) {
    let p = ls_perm.trim().trim_end_matches('.');
    let b = p.as_bytes();
    if b.len() < 10 {
        return (false, false);
    }
    let group_writable = b[5] == b'w';
    let world_writable = b[8] == b'w';
    (world_writable, group_writable)
}

/// Linux-style kernel thread task name as shown in `ps` / `/proc` (e.g. `[kworker/0:0H]`).
#[inline]
pub fn looks_like_kernel_thread_name(name: &str) -> bool {
    name.starts_with('[') && name.ends_with(']')
}

/// Parse a command line into (name, path, args)
pub fn parse_command_line(command: &str) -> (String, String, String) {
    let command = command.trim();

    if command.is_empty() {
        return (String::new(), String::new(), String::new());
    }

    if command.starts_with('[') && command.ends_with(']') {
        return (command.to_string(), command.to_string(), String::new());
    }

    let parts = parse_command_parts(command);

    if parts.is_empty() {
        return (String::new(), String::new(), String::new());
    }

    let path = parts[0].clone();
    let args = if parts.len() > 1 {
        parts[1..].join(" ")
    } else {
        String::new()
    };

    let name = if let Some(pos) = path.rfind('/') {
        path[pos + 1..].to_string()
    } else {
        path.clone()
    };

    (name, path, args)
}

/// Parse command line respecting quotes
pub(crate) fn parse_command_parts(command: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = command.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '"' | '\'' => in_quotes = !in_quotes,
            ' ' if !in_quotes => {
                if !current.is_empty() {
                    parts.push(current.clone());
                    current.clear();
                }
            }
            _ => current.push(ch),
        }
    }

    if !current.is_empty() {
        parts.push(current);
    }

    parts
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;

    #[test]
    fn entropy_empty_is_zero() {
        assert_eq!(calculate_shannon_entropy(""), 0.0);
    }

    #[test]
    fn wildcard_star_and_question() {
        assert!(matches_wildcard("/var/log/app.log", "/var/log/*.log"));
        assert!(matches_wildcard("/tmp/a1", "/tmp/a?"));
        assert!(!matches_wildcard("/tmp/b", "/tmp/a?"));
    }

    #[test]
    fn whitelist_any_pattern() {
        let wl = vec!["/usr/bin/*".to_string()];
        assert!(is_path_whitelisted("/usr/bin/python3", &wl));
        assert!(!is_path_whitelisted("/bin/sh", &wl));
    }

    #[test]
    fn compile_wildcard_list_matches_is_path_whitelisted() {
        let patterns = vec![
            "/opt/conda/*".to_string(),
            "/home/*/venv/*".to_string(),
        ];
        let compiled = compile_wildcard_list(&patterns);
        for path in ["/opt/conda/bin/python", "/home/u/venv/lib/x", "/etc/passwd"] {
            assert_eq!(
                is_path_whitelisted(path, &patterns),
                is_path_whitelisted_compiled(path, &compiled),
                "path={path}"
            );
        }
    }

    #[test]
    fn suspicious_path_matches_regex() {
        let pats = vec![r"/tmp/".to_string()];
        assert!(is_path_suspicious("/tmp/x", &pats));
        assert!(!is_path_suspicious("/etc/passwd", &pats));
    }

    #[test]
    fn compile_regex_list_skips_invalid() {
        let pats = vec![r"^\d+$".to_string(), "[".to_string()];
        let res = compile_regex_list(&pats);
        assert_eq!(res.len(), 1);
        assert!(res[0].is_match("42"));
    }

    #[test]
    fn file_path_matches_exclusion_path_or_basename() {
        let path_re = vec![Regex::new("^/proc").unwrap()];
        let name_re = vec![Regex::new("^\\.cache$").unwrap()];
        assert!(file_path_matches_exclusion("/proc/1/cmdline", &path_re, &name_re));
        assert!(file_path_matches_exclusion("/home/u/.cache", &path_re, &name_re));
        assert!(!file_path_matches_exclusion("/home/u/file", &path_re, &name_re));
    }

    #[test]
    fn parse_log_datetime_rfc3339_and_naive() {
        assert!(parse_log_datetime("2024-01-02T03:04:05Z").is_some());
        assert!(parse_log_datetime("2024-01-02T03:04:05+00:00").is_some());
        assert!(parse_log_datetime("2024-01-02 03:04:05").is_some());
        assert!(parse_log_datetime("").is_none());
    }

    #[test]
    fn unix_permission_world_and_group_write() {
        let (world, group) = unix_permission_flags("-rw-rw-rw-.");
        assert!(world);
        assert!(group);
        let (world2, group2) = unix_permission_flags("-rw-r--r--.");
        assert!(!world2);
        assert!(!group2);
    }

    #[test]
    fn unix_permission_short_string() {
        let (w, g) = unix_permission_flags("-rw");
        assert!(!w);
        assert!(!g);
    }

    #[test]
    fn kernel_thread_brackets() {
        assert!(looks_like_kernel_thread_name("[kworker/0:0H]"));
        assert!(!looks_like_kernel_thread_name("kworker"));
    }

    #[test]
    fn parse_command_line_basic_and_bracket() {
        let (n, p, a) = parse_command_line("/bin/bash -c \"echo hi\"");
        assert_eq!(n, "bash");
        assert_eq!(p, "/bin/bash");
        assert_eq!(a, "-c echo hi"); // quoted segments are stripped by parse_command_parts
        let (n2, p2, a2) = parse_command_line("[kworker/0:0H]");
        assert_eq!(n2, "[kworker/0:0H]");
        assert_eq!(p2, "[kworker/0:0H]");
        assert!(a2.is_empty());
    }

    #[test]
    fn parse_command_parts_respects_quotes() {
        let parts = parse_command_parts(r#"one "two three" four"#);
        assert_eq!(parts, vec!["one", "two three", "four"]);
    }
}
