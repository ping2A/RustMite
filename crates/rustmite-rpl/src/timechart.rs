//! Timechart semantics (nano / Splunk / OpenSearch PPL alignment).
//!
//! Reference: [OpenSearch `timechart`](https://docs.opensearch.org/latest/sql-and-ppl/ppl/commands/timechart/)
//! - `limit` caps distinct `by` values chosen by **total volume across all buckets**
//! - Default `limit` is **10** when `by` is set and the user omits `limit=`
//! - `limit=0` means unlimited series
//! - Remaining split-by values roll into **`Other`** when `useother=true` (default)
//! - A **global row `LIMIT` on `(bucket, series)` rows** is wrong: with
//!   `ORDER BY bucket ASC, c DESC LIMIT N` you keep the top counts from the earliest
//!   buckets only, which collapses charts to a single dominant series (e.g. only Package).

use crate::rpl::{RplCommand, RplQuery};
use std::collections::HashMap;

/// Effective series cap for SQL generation.
pub fn effective_timechart_series_limit(by: &Option<String>, limit: Option<u32>) -> Option<u32> {
    if by.is_none() {
        return None;
    }
    match limit {
        None => Some(10),
        Some(0) => None,
        Some(n) => Some(n),
    }
}

pub const OTHER_SERIES_LABEL: &str = "Other";

/// OpenSearch `useother` — default true when a series limit is in effect.
pub fn timechart_use_other(useother: Option<bool>) -> bool {
    useother.unwrap_or(true)
}

/// Whether [`apply_row_limit`] must not run (timechart carries its own series cap).
pub fn should_skip_row_limit (rpl: &RplQuery) -> bool {
    rpl.commands
        .iter()
        .any(|c| matches!(c, RplCommand::Timechart { .. }))
}

/// Pre-fix bug: global row cap on the bucket×series grid.
pub fn legacy_row_cap_rows(rows: &[(u32, String, u32)], cap: usize) -> Vec<(u32, String, u32)> {
    let mut sorted = rows.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(&b.0).then(b.2.cmp(&a.2)));
    sorted.truncate(cap);
    sorted
}

/// Top N series by total count, all buckets kept (`useother=false`).
pub fn top_series_rows(rows: &[(u32, String, u32)], cap: usize) -> Vec<(u32, String, u32)> {
    top_series_rows_with_other(rows, cap, false)
}

/// Top N series plus optional `Other` rollup (`useother=true`, OpenSearch default).
pub fn top_series_rows_with_other(
    rows: &[(u32, String, u32)],
    cap: usize,
    use_other: bool,
) -> Vec<(u32, String, u32)> {
    let mut totals: HashMap<&str, u32> = HashMap::new();
    for (_, series, c) in rows {
        *totals.entry(series.as_str()).or_insert(0) += c;
    }
    let mut ranked: Vec<_> = totals.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1));
    let keep: std::collections::HashSet<_> = ranked
        .iter()
        .take(cap)
        .map(|(s, _)| (*s).to_string())
        .collect();
    let has_tail = ranked.len() > cap;

    let mut bucket_map: HashMap<u32, HashMap<String, u32>> = HashMap::new();
    for (bucket, series, c) in rows {
        let label = if keep.contains(series) {
            series.clone()
        } else if use_other && has_tail {
            OTHER_SERIES_LABEL.to_string()
        } else {
            continue;
        };
        *bucket_map
            .entry(*bucket)
            .or_default()
            .entry(label)
            .or_insert(0) += c;
    }

    let mut out = Vec::new();
    for (bucket, series_map) in bucket_map {
        for (series, c) in series_map {
            out.push((bucket, series, c));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0).then(b.2.cmp(&a.2)));
    out
}

pub fn distinct_series(rows: &[(u32, String, u32)]) -> Vec<String> {
    let mut keys: Vec<_> = rows
        .iter()
        .map(|(_, s, _)| s.clone())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    keys.sort_unstable();
    keys
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 24 hourly buckets × 3 parsers; Package wins every hour.
    fn mobile_parser_grid() -> Vec<(u32, String, u32)> {
        (0..24)
            .flat_map(|b| {
                [
                    (b, "Package".to_string(), 100_u32),
                    (b, "Network".to_string(), 50),
                    (b, "Process".to_string(), 10),
                ]
            })
            .collect()
    }

    #[test]
    fn legacy_global_limit_truncates_time_range() {
        let grid = mobile_parser_grid();
        let legacy = legacy_row_cap_rows(&grid, 8);
        // Bug: global row LIMIT keeps only the first 8 (bucket, series) pairs — ~2–3 hours
        // of a 24h chart instead of all buckets for the top parsers.
        assert_eq!(legacy.len(), 8);
        let max_bucket = legacy.iter().map(|(b, _, _)| *b).max().unwrap_or(0);
        assert!(
            max_bucket < 3,
            "legacy cap should not reach later buckets (max={max_bucket}): {legacy:?}"
        );
    }

    #[test]
    fn top_series_keeps_multiple_parsers_across_all_buckets() {
        let grid = mobile_parser_grid();
        let fixed = top_series_rows(&grid, 8);
        let series = distinct_series(&fixed);
        assert_eq!(
            series,
            vec![
                "Network".to_string(),
                "Package".to_string(),
                "Process".to_string()
            ]
        );
        assert_eq!(fixed.len(), 24 * 3);
        assert!(fixed.iter().any(|(b, s, _)| *b == 23 && s == "Process"));
    }

    #[test]
    fn useother_rolls_tail_parsers_into_other() {
        let grid: Vec<(u32, String, u32)> = (0..2)
            .flat_map(|b| {
                [
                    (b, "Package".to_string(), 100),
                    (b, "Network".to_string(), 50),
                    (b, "Process".to_string(), 10),
                    (b, "Crash".to_string(), 5),
                ]
            })
            .collect();
        let with_other = top_series_rows_with_other(&grid, 2, true);
        let series = distinct_series(&with_other);
        assert_eq!(series.len(), 3);
        assert!(series.contains(&OTHER_SERIES_LABEL.to_string()));
        assert!(series.contains(&"Package".to_string()));
        assert!(series.contains(&"Network".to_string()));
        let other_total: u32 = with_other
            .iter()
            .filter(|(_, s, _)| s == OTHER_SERIES_LABEL)
            .map(|(_, _, c)| c)
            .sum();
        assert_eq!(other_total, 2 * (10 + 5));
    }

    #[test]
    fn useother_false_drops_tail_series() {
        let grid: Vec<(u32, String, u32)> = (0..1)
            .flat_map(|b| {
                [
                    (b, "Package".to_string(), 100),
                    (b, "Network".to_string(), 50),
                    (b, "Process".to_string(), 10),
                ]
            })
            .collect();
        let out = top_series_rows_with_other(&grid, 2, false);
        assert_eq!(distinct_series(&out), vec!["Network".to_string(), "Package".to_string()]);
    }

    #[test]
    fn effective_limit_defaults_to_ten_like_opensearch() {
        assert_eq!(
            effective_timechart_series_limit(&Some("parser".into()), None),
            Some(10)
        );
        assert_eq!(
            effective_timechart_series_limit(&Some("parser".into()), Some(0)),
            None
        );
        assert_eq!(
            effective_timechart_series_limit(&Some("parser".into()), Some(8)),
            Some(8)
        );
        assert_eq!(effective_timechart_series_limit(&None, None), None);
    }

}
