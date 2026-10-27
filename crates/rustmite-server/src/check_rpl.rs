//! Best-effort translation of check-engine `where` expressions into Hunt RPL.
//!
//! Check predicates use typed fields (`process.exe`, `file_meta.path`, `matches`,
//! `path_under`, …). Hunt RPL uses flat event fields (`path`, `process_name`) and
//! globs. This is an analyst aid — not a lossless compiler.

use uuid::Uuid;

/// Build a Hunt RPL query approximating a check's `match` + `where`, scoped to hosts.
pub fn check_to_hunt_rpl(
    match_on: &str,
    where_expr: &str,
    host_ids: &[Uuid],
    host_names: &[String],
) -> String {
    let kind = match_kind(match_on);
    let mut parts: Vec<String> = Vec::new();

    if !host_ids.is_empty() {
        if host_ids.len() == 1 {
            parts.push(format!("host_id=\"{}\"", host_ids[0]));
        } else if host_ids.len() <= 8 {
            let list = host_ids
                .iter()
                .map(|id| format!("\"{id}\""))
                .collect::<Vec<_>>()
                .join(", ");
            parts.push(format!("host_id IN ({list})"));
        } else if !host_names.is_empty() && host_names.len() <= 8 {
            let list = host_names
                .iter()
                .map(|n| format!("\"{}\"", escape_rpl_str(n)))
                .collect::<Vec<_>>()
                .join(", ");
            parts.push(format!("host_name IN ({list})"));
        } else {
            parts.push(format!("host_id=\"{}\"", host_ids[0]));
            parts.push(format!("/* +{} more hosts — refine in Hunt */", host_ids.len() - 1));
        }
    }

    if let Some(k) = kind {
        parts.push(format!("kind=\"{k}\""));
    }

    let body = translate_where(where_expr);
    if !body.trim().is_empty() {
        parts.push(format!("({body})"));
    }

    let search = if parts.is_empty() {
        "*".to_string()
    } else {
        parts.join(" ")
    };

    let fields = default_fields(match_on);
    format!("{search} | fields {fields} | sort -timestamp | head 200")
}

fn match_kind(match_on: &str) -> Option<&'static str> {
    match match_on {
        "process" => Some("process"),
        "hidden_process" => Some("hidden_process"),
        "file_meta" => Some("file_meta"),
        "file_entropy" => Some("file_entropy"),
        "elf_info" => Some("elf_info"),
        "socket" => Some("socket"),
        "hidden_socket" => Some("hidden_socket"),
        "ioc_hit" => Some("ioc_hit"),
        "preload" => Some("preload"),
        "account" => Some("account"),
        "module" => Some("module"),
        "authorized_key" => Some("authorized_key"),
        "scheduled_task" => Some("scheduled_task"),
        "service" => Some("service"),
        "log_integrity" => Some("log_integrity"),
        "utmp_session" => Some("utmp_session"),
        "integrity_mismatch" => Some("integrity_mismatch"),
        "dir_anomaly" => Some("dir_anomaly"),
        _ => None,
    }
}

fn default_fields(match_on: &str) -> &'static str {
    match match_on {
        "process" | "hidden_process" => {
            "timestamp, host_name, kind, process_name, process_id, user, path, message"
        }
        "file_meta" | "file_entropy" | "elf_info" | "ioc_hit" | "integrity_mismatch"
        | "dir_anomaly" => "timestamp, host_name, kind, path, file_hash, user, message",
        "socket" | "hidden_socket" => {
            "timestamp, host_name, kind, process_name, src_ip, dest_ip, path, message"
        }
        _ => "timestamp, host_name, kind, process_name, path, message",
    }
}

fn translate_where(where_expr: &str) -> String {
    let mut s = where_expr.to_string();
    // Drop line comments.
    s = s
        .lines()
        .map(|line| {
            let t = line.trim();
            if t.starts_with("//") || t.starts_with('#') {
                ""
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    s = s.replace('\n', " ");
    while s.contains("  ") {
        s = s.replace("  ", " ");
    }
    s = s.trim().to_string();

    // Method / infix rewrites before field renames.
    s = rewrite_path_under(&s);
    s = rewrite_contains(&s);
    s = rewrite_starts_with(&s);
    s = rewrite_ends_with(&s);
    s = rewrite_matches(&s);
    s = rewrite_null_checks(&s);

    // Field map: typed check fields → Hunt columns.
    for (from, to) in FIELD_MAP {
        s = s.replace(from, to);
    }

    // Operators / keywords.
    s = s.replace("==", "=");
    s = replace_word(&s, "and", "AND");
    s = replace_word(&s, "or", "OR");
    s = replace_word(&s, "not", "NOT");
    // Compact `path = "x"` → `path="x"` (does not touch `!=`).
    s = regex_lite(r#"\s*=\s*"#).replace_all(&s, "=").into_owned();

    collapse_ws(&s)
}

const FIELD_MAP: &[(&str, &str)] = &[
    ("file_meta.path", "path"),
    ("file_entropy.path", "path"),
    ("ioc_hit.path", "path"),
    ("integrity_mismatch.path", "path"),
    ("dir_anomaly.path", "path"),
    ("elf_info.path", "path"),
    ("process.exe", "path"),
    ("process.comm", "process_name"),
    ("process.cmdline", "message"),
    ("process.pid", "process_id"),
    ("process.ppid", "ppid"),
    ("process.cwd", "path"),
    ("process.uid", "user"),
    ("process.euid", "user"),
    ("account.name", "user"),
    ("account.shell", "path"),
    ("socket.local_addr", "src_ip"),
    ("socket.remote_addr", "dest_ip"),
];

fn rewrite_path_under(s: &str) -> String {
    // field.path_under("/prefix")  OR  path_under(field, "/prefix")
    let mut out = s.to_string();
    // receiver.path_under("...")
    let re = regex_lite(r#"([A-Za-z0-9_.]+)\.path_under\(\s*"([^"]*)"\s*\)"#);
    out = re
        .replace_all(&out, |caps: &regex::Captures| {
            let field = &caps[1];
            let prefix = &caps[2];
            let hunt = map_field_name(field);
            format!("{hunt}=\"{}*\"", escape_rpl_str(prefix))
        })
        .into_owned();
    out
}

fn rewrite_contains(s: &str) -> String {
    let mut out = s.to_string();
    // field contains "x"
    let re = regex_lite(r#"([A-Za-z0-9_.]+)\s+contains\s+"([^"]*)""#);
    out = re
        .replace_all(&out, |caps: &regex::Captures| {
            let field = map_field_name(&caps[1]);
            let needle = escape_rpl_str(&caps[2]);
            format!("{field}=\"*{needle}*\"")
        })
        .into_owned();
    // field.contains("x")
    let re2 = regex_lite(r#"([A-Za-z0-9_.]+)\.contains\(\s*"([^"]*)"\s*\)"#);
    out = re2
        .replace_all(&out, |caps: &regex::Captures| {
            let field = map_field_name(&caps[1]);
            let needle = escape_rpl_str(&caps[2]);
            format!("{field}=\"*{needle}*\"")
        })
        .into_owned();
    out
}

fn rewrite_starts_with(s: &str) -> String {
    let re = regex_lite(r#"([A-Za-z0-9_.]+)\s+starts_with\s+"([^"]*)""#);
    re.replace_all(s, |caps: &regex::Captures| {
        let field = map_field_name(&caps[1]);
        format!("{field}=\"{}*\"", escape_rpl_str(&caps[2]))
    })
    .into_owned()
}

fn rewrite_ends_with(s: &str) -> String {
    let re = regex_lite(r#"([A-Za-z0-9_.]+)\s+ends_with\s+"([^"]*)""#);
    re.replace_all(s, |caps: &regex::Captures| {
        let field = map_field_name(&caps[1]);
        format!("{field}=\"*{}\"", escape_rpl_str(&caps[2]))
    })
    .into_owned()
}

fn rewrite_matches(s: &str) -> String {
    // field matches "regex" → best-effort glob / OR of literals
    let re = regex_lite(r#"([A-Za-z0-9_.]+)\s+matches\s+"((?:\\.|[^"\\])*)""#);
    re.replace_all(s, |caps: &regex::Captures| {
        let field = map_field_name(&caps[1]);
        let pat = unescape_quoted(&caps[2]);
        regex_to_rpl_clause(&field, &pat)
    })
    .into_owned()
}

fn rewrite_null_checks(s: &str) -> String {
    let mut out = s.to_string();
    let re_ne = regex_lite(r#"([A-Za-z0-9_.]+)\s*!=\s*null"#);
    out = re_ne
        .replace_all(&out, |caps: &regex::Captures| {
            format!("{}=*", map_field_name(&caps[1]))
        })
        .into_owned();
    let re_eq = regex_lite(r#"([A-Za-z0-9_.]+)\s*==\s*null"#);
    out = re_eq
        .replace_all(&out, |caps: &regex::Captures| {
            format!("NOT {}=*", map_field_name(&caps[1]))
        })
        .into_owned();
    out
}

fn regex_to_rpl_clause(field: &str, pat: &str) -> String {
    // Strip anchors and common escapes for a glob-ish approximation.
    let mut p = pat.trim().to_string();
    if p.starts_with('^') {
        p = p[1..].to_string();
    }
    if p.ends_with('$') {
        p.pop();
    }
    // Alternation of simple literals: a|b|c
    if let Some(alts) = simple_regex_alts(&p) {
        if alts.len() == 1 {
            return format!("{field}=\"{}\"", escape_rpl_str(&alts[0]));
        }
        let inner = alts
            .iter()
            .map(|a| format!("{field}=\"{}\"", escape_rpl_str(a)))
            .collect::<Vec<_>>()
            .join(" OR ");
        return format!("({inner})");
    }
    // Fallback: pull longest literal run as substring glob.
    if let Some(lit) = longest_literal_run(&p) {
        if lit.len() >= 3 {
            return format!("{field}=\"*{}\"", escape_rpl_str(&lit));
        }
    }
    format!("{field}=* /* regex was: {} */", escape_rpl_str(pat))
}

fn simple_regex_alts(pat: &str) -> Option<Vec<String>> {
    // Only handle patterns like /tmp/(a|b)\.py or plain a|b without nested groups beyond one ().
    let mut p = pat.to_string();
    p = p.replace("\\.", ".");
    p = p.replace("\\/", "/");
    // Expand single group: prefix(a|b|c)suffix
    if let Some((pre, rest)) = p.split_once('(') {
        let (alts, post) = rest.split_once(')')?;
        if alts.contains('(') || post.contains('(') {
            return None;
        }
        if alts.chars().any(|c| matches!(c, '*' | '+' | '?' | '[' | ']' | '{' | '}' | '\\')) {
            return None;
        }
        let post = post.replace("\\.", ".");
        let out: Vec<String> = alts
            .split('|')
            .map(|a| format!("{pre}{a}{post}"))
            .map(|s| globify_regex_crumbs(&s))
            .collect();
        if out.iter().all(|s| !s.is_empty()) {
            return Some(out);
        }
        return None;
    }
    if p.contains('|')
        && !p.contains('(')
        && p.chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-|".contains(c))
    {
        return Some(p.split('|').map(|s| s.to_string()).collect());
    }
    // Single literal-ish path
    if p.chars()
        .all(|c| c.is_ascii_alphanumeric() || "/._-".contains(c))
    {
        return Some(vec![p]);
    }
    None
}

fn globify_regex_crumbs(s: &str) -> String {
    s.replace(".*", "*").replace(".+", "*")
}

fn longest_literal_run(pat: &str) -> Option<String> {
    let mut best = String::new();
    let mut cur = String::new();
    let mut chars = pat.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(n) = chars.next() {
                if n.is_ascii_alphanumeric() || "/._-".contains(n) {
                    cur.push(n);
                } else {
                    if cur.len() > best.len() {
                        best = cur.clone();
                    }
                    cur.clear();
                }
            }
            continue;
        }
        if c.is_ascii_alphanumeric() || "/._-".contains(c) {
            cur.push(c);
        } else {
            if cur.len() > best.len() {
                best = cur.clone();
            }
            cur.clear();
        }
    }
    if cur.len() > best.len() {
        best = cur;
    }
    if best.is_empty() {
        None
    } else {
        Some(best)
    }
}

fn map_field_name(field: &str) -> String {
    for (from, to) in FIELD_MAP {
        if field == *from {
            return (*to).to_string();
        }
    }
    // Strip known prefixes: process.foo → try foo
    if let Some(rest) = field.strip_prefix("process.") {
        return match rest {
            "exe" => "path".into(),
            "comm" => "process_name".into(),
            "cmdline" => "message".into(),
            "pid" => "process_id".into(),
            other => other.to_string(),
        };
    }
    if let Some(rest) = field.split('.').next_back() {
        if matches!(rest, "path" | "comm" | "exe") {
            return if rest == "comm" {
                "process_name".into()
            } else if rest == "exe" {
                "path".into()
            } else {
                "path".into()
            };
        }
    }
    field.to_string()
}

fn escape_rpl_str(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn unescape_quoted(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(n) = chars.next() {
                out.push(n);
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn replace_word(hay: &str, word: &str, with: &str) -> String {
    let re = regex_lite(&format!(r"(?i)\b{}\b", regex::escape(word)));
    re.replace_all(hay, with).into_owned()
}

fn collapse_ws(s: &str) -> String {
    let mut out = s.to_string();
    while out.contains("  ") {
        out = out.replace("  ", " ");
    }
    out.trim().to_string()
}

fn regex_lite(pat: &str) -> regex::Regex {
    regex::Regex::new(pat).expect("static rewrite regex")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translates_ics_file_rule() {
        let where_expr = r#"
          file_meta.path != null
          and (
            file_meta.path == "/tmp/ml.py"
            or file_meta.path ends_with "/sp_run.py"
            or file_meta.path.path_under("/data/.icscap")
          )
        "#;
        let rpl = check_to_hunt_rpl("file_meta", where_expr, &[], &[]);
        assert!(rpl.contains("kind=\"file_meta\""), "{rpl}");
        assert!(rpl.contains("path=\"/tmp/ml.py\""), "{rpl}");
        assert!(rpl.contains("path=\"*/sp_run.py\""), "{rpl}");
        assert!(rpl.contains("path=\"/data/.icscap*\""), "{rpl}");
        assert!(rpl.contains("| fields"), "{rpl}");
    }

    #[test]
    fn scopes_single_host() {
        let id = Uuid::nil();
        let rpl = check_to_hunt_rpl("process", "process.comm == \"sshd\"", &[id], &[]);
        assert!(rpl.contains(&format!("host_id=\"{id}\"")), "{rpl}");
        assert!(rpl.contains("process_name=\"sshd\""), "{rpl}");
    }
}
