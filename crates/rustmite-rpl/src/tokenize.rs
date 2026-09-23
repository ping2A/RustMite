//! Bloom-filter-aware tokenization for full-text style bare tokens.

/// Split a bare search token into sub-tokens suitable for `splitByNonAlpha` indexes.
pub fn tokenize_for_bloom(token: &str) -> Vec<String> {
    let lower = token.to_lowercase();
    let parts: Vec<String> = lower
        .split(|c: char| !c.is_alphanumeric())
        .filter(|p| p.len() >= 2)
        .map(|p| p.to_string())
        .collect();
    if parts.is_empty() && !lower.is_empty() {
        vec![lower]
    } else {
        parts
    }
}

/// Build a ClickHouse condition that uses token index columns when available.
pub fn bloom_token_condition(column: &str, token: &str) -> String {
    let parts = tokenize_for_bloom(token);
    if parts.is_empty() {
        return format!("positionCaseInsensitive({column}, '{token}') > 0");
    }
    let checks: Vec<String> = parts
        .iter()
        .map(|p| format!("hasToken({column}, '{p}')"))
        .collect();
    format!("({})", checks.join(" AND "))
}
