use crate::rpl::{CompareOp, JoinType, RplCommand, RplQuery, SearchExpr};
use crate::timechart::{
    effective_timechart_series_limit, timechart_use_other, OTHER_SERIES_LABEL,
};
use crate::tokenize::bloom_token_condition;
use crate::fields::clickhouse_ip_indicator_key;
use crate::fields::{
    field_has_value_sql, is_numeric_field, resolve_field_sql, tag_contains_sql, SEARCHABLE_FIELDS,
};
use regex::Regex;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SqlGenError {
    #[error(
        "Real-time rules only support the search filter (field=value, AND/OR, time modifiers like last 24h). \
         Pipe commands are not evaluated on each incoming event. \
         Unsupported: {pipe_summary}. \
         Switch to scheduled mode, or remove pipes and keep the filter only \
         (e.g. platform=\"android\" last 24h)."
    )]
    RealtimePipesNotAllowed { pipe_summary: String },
    #[error("invalid rex field name: {0}")]
    InvalidRexField(String),
    #[error("lookup unsupported for field: {0}")]
    UnsupportedLookupField(String),
}

/// Generate ClickHouse SQL for an RPL query against `rustmite.events`.
pub fn generate_clickhouse_sql(
    query: &RplQuery,
    database: &str,
    time_from: Option<&str>,
    time_to: Option<&str>,
) -> Result<String, SqlGenError> {
    let mut where_parts = vec![search_expr_sql(&query.search)?];
    if let Some(f) = time_from {
        where_parts.push(format!("timestamp >= parseDateTime64BestEffort('{f}')"));
    }
    if let Some(t) = time_to {
        where_parts.push(format!("timestamp <= parseDateTime64BestEffort('{t}')"));
    }

    let mut sql = format!(
        "SELECT * FROM {database}.events WHERE {}",
        where_parts.join(" AND ")
    );

    let mut pending_fields: Option<Vec<String>> = None;
    // After `| stats …`, `| sort -count` must target the `stat` alias (not ext.count).
    let mut stats_output_aliases: Option<Vec<String>> = None;
    for cmd in &query.commands {
        if let RplCommand::Fields { names } = cmd {
            if fields_include_timestamp(names) {
                sql = flush_pending_fields(sql, &mut pending_fields)?;
                sql = apply_fields_projection(sql, names)?;
            } else {
                sql = flush_pending_fields(sql, &mut pending_fields)?;
                pending_fields = Some(names.clone());
            }
            stats_output_aliases = None;
            continue;
        }
        if !matches!(cmd, RplCommand::Head { .. } | RplCommand::Sort { .. }) {
            sql = flush_pending_fields(sql, &mut pending_fields)?;
        }
        match cmd {
            RplCommand::Stats { by, .. } => {
                sql = apply_command(sql, cmd, database, time_from, time_to)?;
                let mut aliases = by.clone();
                aliases.push("stat".into());
                aliases.push("count".into());
                stats_output_aliases = Some(aliases);
            }
            RplCommand::Sort { field, desc } => {
                sql = apply_sort(sql, field, *desc, stats_output_aliases.as_deref())?;
            }
            other => {
                sql = apply_command(sql, other, database, time_from, time_to)?;
                if !matches!(
                    other,
                    RplCommand::Head { .. } | RplCommand::Sort { .. }
                ) {
                    stats_output_aliases = None;
                }
            }
        }
    }
    sql = flush_pending_fields(sql, &mut pending_fields)?;

    Ok(sql)
}

fn events_search_where_parts(
    query: &RplQuery,
    time_from: Option<&str>,
    time_to: Option<&str>,
) -> Result<Vec<String>, SqlGenError> {
    let mut where_parts = vec![search_expr_sql(&query.search)?];
    if let Some(f) = time_from {
        where_parts.push(format!("timestamp >= parseDateTime64BestEffort('{f}')"));
    }
    if let Some(t) = time_to {
        where_parts.push(format!("timestamp <= parseDateTime64BestEffort('{t}')"));
    }
    Ok(where_parts)
}

/// WHERE predicate for realtime MVs (search clause only, no pipes).
pub fn generate_events_where_clause(
    query: &RplQuery,
    time_from: Option<&str>,
    time_to: Option<&str>,
) -> Result<String, SqlGenError> {
    if !query.commands.is_empty() {
        return Err(SqlGenError::RealtimePipesNotAllowed {
            pipe_summary: query.pipe_summary(),
        });
    }
    Ok(events_search_where_parts(query, time_from, time_to)?.join(" AND "))
}

/// Base `events` filter SELECT for validate UI (search + time; ignores pipe commands).
pub fn generate_events_filter_sql(
    query: &RplQuery,
    database: &str,
    time_from: Option<&str>,
    time_to: Option<&str>,
) -> Result<String, SqlGenError> {
    let where_clause = events_search_where_parts(query, time_from, time_to)?.join(" AND ");
    Ok(format!(
        "SELECT * FROM {database}.events WHERE {where_clause}"
    ))
}

/// Cap rows for search/detection without producing invalid `LIMIT … LIMIT …` SQL.
pub fn apply_row_limit(sql: String, max: u32) -> String {
    if sql.to_ascii_uppercase().contains(" LIMIT ") {
        format!("SELECT * FROM ({sql}) LIMIT {max}")
    } else {
        format!("{sql} LIMIT {max}")
    }
}

/// `| head` on raw events sorts by time; on stats/sort output keep existing order.
fn apply_head(sql: String, limit: u32) -> String {
    if sql_has_group_by(&sql) || sql_has_order_by(&sql) {
        format!("SELECT * FROM ({sql}) LIMIT {limit}")
    } else {
        format!("SELECT * FROM ({sql}) ORDER BY timestamp DESC LIMIT {limit}")
    }
}

fn sql_has_group_by(sql: &str) -> bool {
    sql.to_ascii_uppercase().contains(" GROUP BY ")
}

fn sql_has_order_by(sql: &str) -> bool {
    sql.to_ascii_uppercase().contains(" ORDER BY ")
}

/// Resolve `| sort` against either raw event columns or prior `| stats` aliases.
fn apply_sort(
    sql: String,
    field: &str,
    desc: bool,
    stats_aliases: Option<&[String]>,
) -> Result<String, SqlGenError> {
    let dir = if desc { "DESC" } else { "ASC" };
    let col = resolve_sort_column(field, stats_aliases);
    Ok(format!("SELECT * FROM ({sql}) ORDER BY {col} {dir}"))
}

fn resolve_sort_column(field: &str, stats_aliases: Option<&[String]>) -> String {
    let normalized = match field {
        "sourcetype" => "source_type",
        "count" => "stat",
        other => other,
    };
    if let Some(aliases) = stats_aliases {
        if aliases.iter().any(|a| a == normalized || a == field) {
            let alias = if normalized == "stat" || field == "count" {
                "stat"
            } else {
                normalized
            };
            return format!("`{}`", alias.replace('`', ""));
        }
    }
    if is_enrichment_output_column(normalized) {
        return format!("`{}`", normalized.replace('`', ""));
    }
    resolve_column(normalized)
}

fn apply_command(
    sql: String,
    cmd: &RplCommand,
    database: &str,
    time_from: Option<&str>,
    time_to: Option<&str>,
) -> Result<String, SqlGenError> {
    Ok(match cmd {
        RplCommand::Where(expr) => {
            format!("{sql} AND {}", search_expr_sql(expr)?)
        }
        RplCommand::Head { limit } => apply_head(sql, *limit),
        RplCommand::Sort { field, desc } => apply_sort(sql, field, *desc, None)?,
        RplCommand::Stats { agg, field, by } => {
            let agg_expr = stats_agg_expr(agg, field.as_deref());
            if by.is_empty() {
                return Ok(format!(
                    "SELECT {agg_expr} AS stat FROM ({sql}) ORDER BY stat DESC"
                ));
            }
            let group_cols: Vec<String> = by.iter().map(|f| stats_group_column(f)).collect();
            let group = group_cols.join(", ");
            // Group keys must appear bare in SELECT (not `any(col)` — CH rejects that with GROUP BY col).
            let select_group: Vec<String> = by
                .iter()
                .zip(group_cols.iter())
                .map(|(f, col)| format!("{col} AS `{f}`"))
                .collect();
            format!(
                "SELECT {}, {agg_expr} AS stat FROM ({sql}) GROUP BY {group} ORDER BY stat DESC",
                select_group.join(", ")
            )
        }
        RplCommand::Eval { field, expr } => {
            let alias = safe_sql_identifier(field)?;
            let body = eval_expression_sql(expr);
            format!("SELECT *, {body} AS {alias} FROM ({sql})")
        }
        RplCommand::Rename { old, new } => {
            let old_c = resolve_column(old);
            let new_id = safe_sql_identifier(new)?;
            format!(
                "SELECT {old_c} AS `{new_id}`, * EXCEPT ({old_c}) FROM ({sql})"
            )
        }
        RplCommand::Lookup { field, prefix } => {
            let col = resolve_column(field);
            let p = safe_sql_identifier(prefix)?;
            let extras = lookup_dict_columns(field, &col, &p, database)?;
            format!(
                "SELECT *, {} FROM ({sql})",
                extras.join(", ")
            )
        }
        RplCommand::Dedup { field } => {
            let col = resolve_column(field);
            format!(
                "SELECT * FROM (SELECT *, row_number() OVER (PARTITION BY {col} ORDER BY timestamp DESC) AS _rn FROM ({sql})) WHERE _rn = 1"
            )
        }
        RplCommand::Timechart {
            span,
            agg,
            field,
            by,
            limit,
            useother,
        } => {
            let bucket = span_to_clickhouse(span);
            let split = by
                .as_ref()
                .map(|f| resolve_column(f))
                .unwrap_or_else(|| "'all'".into());
            let metric = timechart_metric_expr(agg, field.as_deref());
            let grouped = format!(
                "SELECT toStartOfInterval(timestamp, INTERVAL {bucket}) AS bucket, {split} AS series, {metric} AS c \
                 FROM ({sql}) GROUP BY bucket, series"
            );
            match effective_timechart_series_limit(by, *limit) {
                Some(n) if timechart_use_other(*useother) => format!(
                    "WITH grouped AS ({grouped}), top_series AS ( \
                     SELECT series FROM grouped GROUP BY series ORDER BY sum(c) DESC LIMIT {n} \
                     ), rolled AS ( \
                     SELECT bucket, if(series IN (SELECT series FROM top_series), series, '{other}') AS series, c \
                     FROM grouped \
                     ) \
                     SELECT bucket, series, sum(c) AS c FROM rolled GROUP BY bucket, series \
                     ORDER BY bucket ASC, c DESC",
                    other = OTHER_SERIES_LABEL
                ),
                Some(n) => format!(
                    "WITH grouped AS ({grouped}), top_series AS ( \
                     SELECT series FROM grouped GROUP BY series ORDER BY sum(c) DESC LIMIT {n} \
                     ) \
                     SELECT bucket, series, c FROM grouped \
                     WHERE series IN (SELECT series FROM top_series) \
                     ORDER BY bucket ASC, c DESC"
                ),
                None => format!(
                    "SELECT bucket, series, c FROM ({grouped}) ORDER BY bucket ASC, c DESC"
                ),
            }
        }
        RplCommand::Rex { name, pattern, field } => {
            let col = resolve_column(field);
            let alias = safe_sql_identifier(name)?;
            let escaped = escape_clickhouse_regex(pattern);
            format!(
                "SELECT *, arrayElement(extractGroups({col}, '{escaped}'), 1) AS {alias} FROM ({sql})"
            )
        }
        RplCommand::Join {
            join_type,
            field,
            subquery,
        } => {
            let sub_sql = generate_clickhouse_sql(subquery, database, time_from, time_to)?;
            let col = resolve_column(field);
            let join_kw = match join_type {
                JoinType::Inner => "INNER JOIN",
                JoinType::Left => "LEFT JOIN",
            };
            let nonempty = field_has_value_sql(field)
                .unwrap_or_else(|| format!("{col} != ''"));
            format!(
                "SELECT lhs.* FROM ({sql}) AS lhs {join_kw} ({sub_sql}) AS rhs ON lhs.{col} = rhs.{col} AND {nonempty}"
            )
        }
        RplCommand::Fields { .. } => {
            unreachable!("Fields is handled in generate_clickhouse_sql")
        }
    })
}

fn fields_include_timestamp(names: &[String]) -> bool {
    names.iter().any(|n| n == "timestamp")
}

fn apply_fields_projection(sql: String, names: &[String]) -> Result<String, SqlGenError> {
    let cols: Vec<String> = names
        .iter()
        .map(|f| {
            let c = resolve_column(f);
            format!("{c} AS `{f}`")
        })
        .collect();
    Ok(format!("SELECT {} FROM ({sql})", cols.join(", ")))
}

fn flush_pending_fields(
    sql: String,
    pending: &mut Option<Vec<String>>,
) -> Result<String, SqlGenError> {
    if let Some(names) = pending.take() {
        apply_fields_projection(sql, &names)
    } else {
        Ok(sql)
    }
}

fn safe_sql_identifier(name: &str) -> Result<String, SqlGenError> {
    if name.chars().all(|c| c.is_alphanumeric() || c == '_') && !name.is_empty() {
        Ok(name.to_string())
    } else {
        Err(SqlGenError::InvalidRexField(name.to_string()))
    }
}

fn escape_clickhouse_regex(pattern: &str) -> String {
    pattern.replace('\\', "\\\\").replace('\'', "''")
}

fn stats_agg_expr(agg: &str, field: Option<&str>) -> String {
    match agg {
        "count" => "count()".into(),
        "dc" | "distinct_count" => {
            if let Some(f) = field {
                format!("uniq({})", resolve_column(f))
            } else {
                "uniq(*)".into()
            }
        }
        "values" => {
            if let Some(f) = field {
                format!("groupUniqArray({})", resolve_column(f))
            } else {
                "groupUniqArray(tuple())".into()
            }
        }
        "list" => {
            if let Some(f) = field {
                format!("groupArray({})", resolve_column(f))
            } else {
                "groupArray(tuple())".into()
            }
        }
        other => {
            if let Some(f) = field {
                format!("{other}({})", resolve_column(f))
            } else {
                format!("{other}()")
            }
        }
    }
}

fn timechart_metric_expr(agg: &str, field: Option<&str>) -> String {
    match agg {
        "count" => "count()".into(),
        "avg" | "min" | "max" | "sum" => {
            if let Some(f) = field {
                format!("{agg}({})", resolve_column(f))
            } else {
                "count()".into()
            }
        }
        other => {
            if let Some(f) = field {
                format!("{other}({})", resolve_column(f))
            } else {
                "count()".into()
            }
        }
    }
}

fn lookup_dict_columns(
    field: &str,
    col: &str,
    prefix: &str,
    database: &str,
) -> Result<Vec<String>, SqlGenError> {
    let dict = format!("{database}.ip_enrichment_dict");
    let ioc = format!("{database}.ioc_enrichment_dict");
    let ioc_key = |field: &str, col: &str| -> String {
        if field == "src_ip" || field == "dest_ip" {
            clickhouse_ip_indicator_key(col)
        } else {
            col.to_string()
        }
    };
    let ioc_cols = |pfx: &str, key: &str| {
        vec![
            format!(
                "dictGet('{ioc}', 'malware_family', {key}) AS `{pfx}_malware_family`"
            ),
            format!("dictGet('{ioc}', 'score', {key}) AS `{pfx}_score`"),
        ]
    };

    let vt_stat_cols = |pfx: &str, key: &str| {
        vec![
            format!("dictGet('{ioc}', 'vt_malicious', {key}) AS `{pfx}_malicious`"),
            format!("dictGet('{ioc}', 'vt_harmless', {key}) AS `{pfx}_harmless`"),
            format!("dictGet('{ioc}', 'vt_undetected', {key}) AS `{pfx}_undetected`"),
            format!("dictGet('{ioc}', 'vt_suspicious', {key}) AS `{pfx}_suspicious`"),
            format!("dictGet('{ioc}', 'vt_reputation', {key}) AS `{pfx}_reputation`"),
        ]
    };

    if prefix == "vt" {
        let pfx = format!("vt_{field}");
        let key = ioc_key(field, col);
        return Ok(vt_stat_cols(&pfx, &key));
    }

    if prefix == "play" || (prefix == "lookup" && field == "bundle_id") {
        if field != "bundle_id" {
            return Err(SqlGenError::UnsupportedLookupField(field.to_string()));
        }
        let pfx = if prefix == "play" {
            "play".to_string()
        } else {
            "play".to_string()
        };
        let dict = format!("{database}.package_enrichment_dict");
        return Ok(vec![
            format!("dictGet('{dict}', 'on_play_store', {col}) AS `{pfx}_on_play_store`"),
            format!("dictGet('{dict}', 'play_store_url', {col}) AS `{pfx}_store_url`"),
            format!("dictGet('{dict}', 'app_title', {col}) AS `{pfx}_app_title`"),
        ]);
    }

    Ok(match field {
        "src_ip" | "dest_ip" => {
            let key = clickhouse_ip_indicator_key(col);
            vec![
                format!("dictGet('{dict}', 'country', {key}) AS `{prefix}_country`"),
                format!("dictGet('{dict}', 'city', {key}) AS `{prefix}_city`"),
            ]
        }
        "file_hash" | "destination_domain" => ioc_cols(prefix, &ioc_key(field, col)),
        _ => {
            return Err(SqlGenError::UnsupportedLookupField(field.to_string()));
        }
    })
}

fn eval_expression_sql(expr: &str) -> String {
    let trimmed = expr.trim();
    if (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
    {
        let inner = trimmed.trim_matches(|c| c == '"' || c == '\'');
        return format!("'{}'", inner.replace('\'', "''"));
    }
    if trimmed.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return trimmed.to_string();
    }
    let mut out = translate_eval_identifiers(trimmed);
    if let Ok(re) = Regex::new(r#"="([^"]*)""#) {
        out = re.replace_all(&out, "='$1'").to_string();
    }
    out
}

fn translate_eval_identifiers(expr: &str) -> String {
    let mut names: Vec<&str> = SEARCHABLE_FIELDS.iter().map(|f| f.name).collect();
    names.push("sourcetype");
    names.sort_by_key(|n| std::cmp::Reverse(n.len()));
    let mut out = expr.to_string();
    for name in names {
        let col = if name == "sourcetype" {
            "source_type".to_string()
        } else {
            resolve_column(name)
        };
        let pattern = format!(r"\b{}\b", regex::escape(name));
        if let Ok(re) = Regex::new(&pattern) {
            out = re.replace_all(&out, col.as_str()).to_string();
        }
    }
    out
}

fn span_to_clickhouse(span: &str) -> String {
    if span.ends_with('m') {
        format!("{} MINUTE", span.trim_end_matches('m'))
    } else if span.ends_with('h') {
        format!("{} HOUR", span.trim_end_matches('h'))
    } else if span.ends_with('d') {
        format!("{} DAY", span.trim_end_matches('d'))
    } else {
        "10 MINUTE".into()
    }
}

/// Escape `_` / `%` / `\` so glob `*` / `?` are the only LIKE wildcards.
fn glob_to_like_pattern(pattern: &str) -> String {
    let mut like = String::new();
    for c in pattern.replace('\'', "''").chars() {
        match c {
            '_' | '%' | '\\' => {
                like.push('\\');
                like.push(c);
            }
            '*' => like.push('%'),
            '?' => like.push('_'),
            _ => like.push(c),
        }
    }
    like
}

/// `field=*` means "has a value" (non-empty); numeric columns use `!= 0`, not `!= ''`.
fn field_glob_match_sql(field: &str, col: &str, pattern: &str, negate: bool) -> String {
    let has_literal = pattern.chars().any(|c| c != '*' && c != '?');
    if !has_literal {
        if negate {
            if is_numeric_field(field) {
                format!("{col} = 0")
            } else {
                format!("{col} = ''")
            }
        } else {
            field_has_value_sql(field).unwrap_or_else(|| format!("{col} != ''"))
        }
    } else {
        let expr = if is_numeric_field(field) {
            format!("toString({col})")
        } else {
            col.to_string()
        };
        let like = glob_to_like_pattern(pattern);
        if negate {
            format!("{expr} NOT LIKE '{like}'")
        } else {
            format!("{expr} LIKE '{like}'")
        }
    }
}

const EXT_EVENT_TYPE: &str = "JSONExtractString(ext, 'event_type')";

/// `data_type` hunts also match Sigma `event_type` in `ext` and known Amnesty aliases.
fn data_type_match_sql(pattern: &str, negate: bool) -> String {
    let col = resolve_column("data_type");
    let primary = field_glob_match_sql("data_type", &col, pattern, false);
    let et = field_glob_match_sql("event_type", EXT_EVENT_TYPE, pattern, false);
    let mut parts = vec![primary, et];
    if pattern.contains("tombstone_backtrace") {
        parts.push(format!(
            "({col} LIKE '%tombstone%' AND ({col} LIKE '%frame%' OR {col} LIKE '%backtrace%'))"
        ));
    }
    let positive = format!("({})", parts.join(" OR "));
    if negate {
        format!("NOT {positive}")
    } else {
        positive
    }
}

fn resolve_column(field: &str) -> String {
    let normalized = match field {
        "sourcetype" => "source_type",
        other => other,
    };
    resolve_field_sql(normalized)
        .unwrap_or_else(|| format!("JSONExtractString(ext, '{normalized}')"))
}

/// Columns produced by `| lookup` in the inner subquery — not MUDM / ext fields.
fn is_enrichment_output_column(field: &str) -> bool {
    field == "vt_label"
        || field.starts_with("vt_")
        || field.starts_with("play_")
        || field.starts_with("geo_")
        || field.starts_with("lookup_")
        || field.starts_with("ioc_")
}

fn stats_group_column(field: &str) -> String {
    if is_enrichment_output_column(field) {
        format!("`{}`", field.replace('`', ""))
    } else {
        resolve_column(field)
    }
}

pub fn search_expr_sql(expr: &SearchExpr) -> Result<String, SqlGenError> {
    Ok(match expr {
        SearchExpr::True => "1".into(),
        SearchExpr::And(parts) => {
            let inner: Vec<_> = parts.iter().map(search_expr_sql).collect::<Result<_, _>>()?;
            format!("({})", inner.join(" AND "))
        }
        SearchExpr::Or(parts) => {
            let inner: Vec<_> = parts.iter().map(search_expr_sql).collect::<Result<_, _>>()?;
            format!("({})", inner.join(" OR "))
        }
        SearchExpr::Not(inner) => format!("NOT ({})", search_expr_sql(inner)?),
        SearchExpr::In { field, values, negate } => {
            let col = resolve_column(field);
            let list: Vec<String> = values
                .iter()
                .map(|v| format!("'{}'", v.replace('\'', "''")))
                .collect();
            let op = if *negate { "NOT IN" } else { "IN" };
            format!("{col} {op} ({})", list.join(", "))
        }
        SearchExpr::Field { field, op, value } => {
            let col = resolve_column(field);
            let escaped = value.replace('\'', "''");
            let glob = value.contains('*') || value.contains('?');
            if field == "data_type" {
                return Ok(match op {
                    CompareOp::Eq if glob => data_type_match_sql(value, false),
                    CompareOp::Ne if glob => data_type_match_sql(value, true),
                    CompareOp::Eq => {
                        format!(
                            "({col} = '{escaped}' OR {EXT_EVENT_TYPE} = '{escaped}')"
                        )
                    }
                    CompareOp::Ne => {
                        format!(
                            "({col} != '{escaped}' AND {EXT_EVENT_TYPE} != '{escaped}')"
                        )
                    }
                    CompareOp::Gt => format!("{col} > '{escaped}'"),
                    CompareOp::Lt => format!("{col} < '{escaped}'"),
                    CompareOp::Gte => format!("{col} >= '{escaped}'"),
                    CompareOp::Lte => format!("{col} <= '{escaped}'"),
                });
            }
            if field == "tags" {
                return Ok(match op {
                    CompareOp::Eq if value == "*" => {
                        field_has_value_sql("tags").unwrap_or_else(|| "1".into())
                    }
                    CompareOp::Ne if value == "*" => {
                        format!(
                            "NOT ({})",
                            field_has_value_sql("tags").unwrap_or_else(|| "0".into())
                        )
                    }
                    CompareOp::Eq if glob => field_glob_match_sql(field, &col, value, false),
                    CompareOp::Ne if glob => field_glob_match_sql(field, &col, value, true),
                    CompareOp::Eq => tag_contains_sql(value),
                    CompareOp::Ne => format!("NOT ({})", tag_contains_sql(value)),
                    CompareOp::Gt => format!("{col} > '{escaped}'"),
                    CompareOp::Lt => format!("{col} < '{escaped}'"),
                    CompareOp::Gte => format!("{col} >= '{escaped}'"),
                    CompareOp::Lte => format!("{col} <= '{escaped}'"),
                });
            }
            if matches!(op, CompareOp::Eq | CompareOp::Ne)
                && !glob
                && SEARCHABLE_FIELDS.iter().any(|f| f.name == value)
            {
                let other_col = resolve_column(value);
                return Ok(match op {
                    CompareOp::Eq => format!("{col} = {other_col}"),
                    CompareOp::Ne => format!("{col} != {other_col}"),
                    _ => unreachable!(),
                });
            }
            match op {
                CompareOp::Eq if glob => field_glob_match_sql(field, &col, value, false),
                CompareOp::Ne if glob => field_glob_match_sql(field, &col, value, true),
                CompareOp::Eq => format!("{col} = '{escaped}'"),
                CompareOp::Ne => format!("{col} != '{escaped}'"),
                CompareOp::Gt => format!("{col} > '{escaped}'"),
                CompareOp::Lt => format!("{col} < '{escaped}'"),
                CompareOp::Gte => format!("{col} >= '{escaped}'"),
                CompareOp::Lte => format!("{col} <= '{escaped}'"),
            }
        }
        SearchExpr::BareToken(t) => bloom_token_condition("message", t),
        SearchExpr::Wildcard { field, pattern } => {
            let col = field
                .as_ref()
                .map(|f| resolve_column(f))
                .unwrap_or_else(|| "message".into());
            if let Some(f) = field {
                field_glob_match_sql(f, &col, pattern, false)
            } else {
                let like = glob_to_like_pattern(pattern);
                format!("{col} LIKE '{like}'")
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpl::parse_rpl;

    #[test]
    fn case_panel_logarchive_queries_compile() {
        let queries = [
            r#"source="case-7f71c134" parser="logarchive" action="logarchive_event" | fields timestamp, message, bundle_id, logarchive_decode, logarchive_tool, file_count, action, ext | sort -timestamp | head 40"#,
            r#"source="case-7f71c134" parser="logarchive" action="logarchive_event" | stats count"#,
            r#"source="case-7f71c134" parser="logarchive" action="logarchive_event" | stats count by bundle_id | head 8"#,
            r#"source="case-7f71c134" parser="remotectl_dumpstate" | fields timestamp, parser, message, device_model, os_version, device_id, ext, action | head 8"#,
        ];
        for q in queries {
            let parsed = parse_rpl(q).unwrap_or_else(|e| panic!("parse failed for {q}: {e:?}"));
            let sql = generate_clickhouse_sql(&parsed, "mobipwn", None, None)
                .unwrap_or_else(|e| panic!("sql failed for {q}: {e:?}"));
            assert!(!sql.is_empty(), "empty sql for {q}");
        }
    }

    #[test]
    fn darksword_ios_rules_compile() {
        let queries = [
            r#"platform="ios" (((destination_domain="snapshare.chat" OR dest_ip="snapshare.chat" OR message=*snapshare.chat*) OR (destination_domain="static.cdncounter.net" OR dest_ip="static.cdncounter.net" OR message=*static.cdncounter.net*)) OR (dest_ip="62.72.21.10" OR message=*62.72.21.10*)) | head 500"#,
            r#"platform="ios" parser="logarchive" action="logarchive_event" message=*DarkSword-WIFI-DUMP* | head 100"#,
            r#"platform="ios" parser="crashlogs" message=*mediaplaybackd* | head 200"#,
            r#"platform="ios" (message=*DriverNewThread.js* OR message=*RemoteCall.js* OR message=*InjectJS.js*) | head 100"#,
            r#"platform="ios" ((remote_port=8882 OR message=*:8882*) AND message=*sqwas.shapelie.com*) | head 100"#,
            r#"platform="ios" (message=*TextToSpeech.framework* OR message=*ICMP6_FILTER* OR message=*sandbox_extension_issue_file*) | head 100"#,
            r#"platform="ios" (file_path=*keychain_copy* OR file_path=*PostLogs.txt* OR message=*file_downloader.js*) | head 100"#,
        ];
        for q in queries {
            let parsed = parse_rpl(q).unwrap_or_else(|e| panic!("parse failed for {q}: {e:?}"));
            let sql = generate_clickhouse_sql(&parsed, "mobipwn", None, None)
                .unwrap_or_else(|e| panic!("sql failed for {q}: {e:?}"));
            assert!(!sql.is_empty(), "empty sql for {q}");
        }
    }

    #[test]
    fn tags_filter_uses_has() {
        let q = parse_rpl(r#"tags=baseline"#).unwrap();
        let sql = generate_clickhouse_sql(&q, "mobipwn", None, None).unwrap();
        assert!(sql.contains("has(JSONExtract(ext, 'tags'"));
        assert!(sql.contains("'baseline'"));
    }

    #[test]
    fn field_reference_compare_installer_not_bundle_id() {
        let q = parse_rpl(r#"installer!=bundle_id"#).unwrap();
        let sql = generate_clickhouse_sql(&q, "mobipwn", None, None).unwrap();
        assert!(sql.contains("bundle_id"), "sql should reference bundle_id column: {sql}");
        assert!(
            !sql.contains("'bundle_id'"),
            "bundle_id should be a column ref, not a literal: {sql}"
        );
    }

    #[test]
    fn sideload_package_rule_compiles() {
        let q = parse_rpl(
            r#"parser="Package" platform="android" data_type=*package_metadata* installer=* installer NOT IN ("com.android.vending", "com.google.android.packageinstaller", "com.android.packageinstaller", "null", "com.facebook.system", "com.samsung.android.app.updatecenter", "com.sec.android.app.samsungapps", "com.android.managedprovisioning", "android") !file_path=*/system/* installer!=bundle_id | head 100"#,
        )
        .unwrap();
        let sql = generate_clickhouse_sql(&q, "mobipwn", None, None).unwrap();
        assert!(sql.contains("bundle_id"));
        assert!(!sql.contains("'bundle_id'"));
    }

    #[test]
    fn ios_trollstore_sideload_rule_compiles() {
        let q = parse_rpl(
            r#"platform="ios" (bundle_id="com.opa334.TrollStore" OR bundle_id="com.opa334.TrollStoreLite" OR bundle_id="com.fiore.trolldecrypt" OR bundle_id=*TrollStore* OR bundle_id=*trolldecrypt* OR bundle_id=*altstore* OR process_name=*TrollStore* OR process_name=*TrollDecrypt* OR process_name=*AltStore* OR message=*TrollStore* OR message=*TrollDecrypt* OR message=*com.opa334.TrollStore* OR message=*com.fiore.trolldecrypt* OR message=*AltStore* OR message=*Sideloadly*) | head 100"#,
        )
        .unwrap();
        let sql = generate_clickhouse_sql(&q, "mobipwn", None, None).unwrap();
        assert!(sql.contains("bundle_id"), "sql was: {sql}");
        assert!(sql.contains("TrollStore") || sql.contains("trollstore"), "sql was: {sql}");
    }

    #[test]
    fn fields_projection_includes_tags() {
        let q = parse_rpl(r#"source="case-001" | fields timestamp, source, tags"#).unwrap();
        let sql = generate_clickhouse_sql(&q, "mobipwn", None, None).unwrap();
        assert!(sql.contains("arrayStringConcat(JSONExtract(ext, 'tags'"));
        assert!(sql.contains("AS `tags`"));
    }

    #[test]
    fn fields_projection_uses_ext_column() {
        let q = parse_rpl(r#"source="case-001" | fields action, ext | head 5"#).unwrap();
        let sql = generate_clickhouse_sql(&q, "mobipwn", None, None).unwrap();
        assert!(sql.contains("ext AS `ext`"), "sql was: {sql}");
        assert!(
            !sql.contains("JSONExtractString(ext, 'ext')"),
            "sql was: {sql}"
        );
    }

    #[test]
    fn fields_without_timestamp_then_head_orders_before_projection() {
        let q = parse_rpl(
            r#"source="case-001" parser="Header" | fields device_model, os_version, device_id, message | head 10"#,
        )
        .unwrap();
        let sql = generate_clickhouse_sql(&q, "mobipwn", None, None).unwrap();
        assert!(
            sql.contains("ORDER BY timestamp DESC LIMIT 10"),
            "sql was: {sql}"
        );
        assert!(
            sql.starts_with("SELECT device_model"),
            "projection should be outermost: {sql}"
        );
        assert!(
            !sql.contains("ORDER BY timestamp DESC LIMIT 10 FROM (SELECT device_model"),
            "must not order by timestamp after dropping it: {sql}"
        );
    }

    #[test]
    fn fields_without_timestamp_then_sort_then_head() {
        let q = parse_rpl(
            r#"source="case-001" | fields device_model, message | sort -timestamp | head 5"#,
        )
        .unwrap();
        let sql = generate_clickhouse_sql(&q, "mobipwn", None, None).unwrap();
        assert!(sql.contains("ORDER BY timestamp DESC"), "sql was: {sql}");
        assert!(sql.contains("LIMIT 5"), "sql was: {sql}");
        assert!(
            sql.trim_start().starts_with("SELECT device_model"),
            "sql was: {sql}"
        );
    }

    #[test]
    fn generates_play_lookup() {
        let q = parse_rpl(r#"platform="android" bundle_id=* | lookup play bundle_id"#).unwrap();
        let sql = generate_clickhouse_sql(&q, "mobipwn", None, None).unwrap();
        assert!(sql.contains("package_enrichment_dict"));
        assert!(sql.contains("play_on_play_store"));
        assert!(sql.contains("play_store_url"));
    }

    #[test]
    fn generates_platform_filter() {
        let q = parse_rpl(r#"platform="android""#).unwrap();
        let sql = generate_clickhouse_sql(&q, "mobipwn", None, None).unwrap();
        assert!(sql.contains("platform = 'android'"));
    }

    #[test]
    fn filter_sql_allows_pipe_commands_for_validate_preview() {
        let q = parse_rpl(r#"source="case-001" | head 50"#).unwrap();
        assert!(!q.commands.is_empty());
        let filter = generate_events_filter_sql(&q, "mobipwn", None, None).unwrap();
        assert!(filter.contains("source = 'case-001'"));
        assert!(!filter.contains("LIMIT"));
        let err = generate_events_where_clause(&q, None, None).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Real-time rules only support the search filter"), "msg: {msg}");
        assert!(msg.contains("| head 50"), "msg: {msg}");
    }

    #[test]
    fn field_star_alone_means_non_empty() {
        let q = parse_rpl(r#"bundle_id=*"#).unwrap();
        let sql = generate_clickhouse_sql(&q, "mobipwn", None, None).unwrap();
        assert!(sql.contains("bundle_id != ''"), "sql was: {sql}");
        assert!(!sql.contains("LIKE '%'"), "sql was: {sql}");
    }

    #[test]
    fn process_id_star_uses_numeric_nonempty() {
        let q = parse_rpl(r#"process_id=*"#).unwrap();
        let sql = generate_clickhouse_sql(&q, "mobipwn", None, None).unwrap();
        assert!(sql.contains("process_id != 0"), "sql was: {sql}");
        assert!(!sql.contains("process_id != ''"), "sql was: {sql}");
    }

    #[test]
    fn ext_field_stats_value_uses_json_extract() {
        let q = parse_rpl(r#"function=*crash*"#).unwrap();
        let sql = generate_clickhouse_sql(&q, "mobipwn", None, None).unwrap();
        assert!(
            sql.contains("JSONExtractString(ext, 'function')"),
            "sql was: {sql}"
        );
    }

    #[test]
    fn tombstone_backtrace_amnesty_query() {
        let q = parse_rpl(
            r#"(data_type=*tombstone_backtrace* AND (function=*QuramDngOpcodeScalePerColumn::processArea*)) | head 500"#,
        )
        .unwrap();
        let sql = generate_clickhouse_sql(&q, "mobipwn", None, None).unwrap();
        assert!(
            sql.contains("event_type"),
            "sql was: {sql}"
        );
        assert!(
            sql.contains("tombstone") && sql.contains("frame"),
            "sql was: {sql}"
        );
        assert!(
            sql.contains("JSONExtractString(ext, 'function')"),
            "sql was: {sql}"
        );
        assert!(
            sql.contains("QuramDngOpcodeScalePerColumn"),
            "sql was: {sql}"
        );
    }

    #[test]
    fn field_star_uses_like() {
        let q = parse_rpl(r#"process_name="com.google.android.*""#).unwrap();
        let sql = generate_clickhouse_sql(&q, "mobipwn", None, None).unwrap();
        assert!(
            sql.contains("LIKE 'com.google.android.%'"),
            "sql was: {sql}"
        );
        let q2 = parse_rpl(r#"process_name=*com.google.android.gms*"#).unwrap();
        let sql2 = generate_clickhouse_sql(&q2, "mobipwn", None, None).unwrap();
        assert!(
            sql2.contains("LIKE '%com.google.android.gms%'"),
            "sql2 was: {sql2}"
        );
    }

    #[test]
    fn generates_rex_extract() {
        let q = parse_rpl(r#"platform="android" | rex ip=(\d+) field=message"#).unwrap();
        let sql = generate_clickhouse_sql(&q, "mobipwn", None, None).unwrap();
        assert!(sql.contains("extractGroups"));
        assert!(sql.contains("AS ip"));
    }

    #[test]
    fn generates_join() {
        let q = parse_rpl(
            r#"platform="android" | join device_id [ platform="ios" | head 3 ]"#,
        )
        .unwrap();
        let sql = generate_clickhouse_sql(&q, "mobipwn", None, None).unwrap();
        assert!(sql.contains("INNER JOIN"));
        assert!(sql.contains("device_id"));
    }

    #[test]
    fn head_after_stats_does_not_order_by_timestamp() {
        let q = parse_rpl(
            r#"source="case-001" parser="Process" | stats count by process_name | head 100"#,
        )
        .unwrap();
        let sql = generate_clickhouse_sql(&q, "mobipwn", None, None).unwrap();
        assert!(
            !sql.contains("ORDER BY timestamp"),
            "sql was: {sql}"
        );
        assert!(sql.contains("LIMIT 100"));
        assert!(
            sql.contains("process_name AS `process_name`"),
            "sql was: {sql}"
        );
        assert!(
            !sql.contains("any(process_name)"),
            "sql was: {sql}"
        );
    }

    #[test]
    fn sort_count_after_stats_uses_stat_alias_not_ext() {
        let q = parse_rpl(
            r#"source="case-001" | stats count by parser | sort -count | head 200"#,
        )
        .unwrap();
        let sql = generate_clickhouse_sql(&q, "mobipwn", None, None).unwrap();
        assert!(
            sql.contains("ORDER BY `stat` DESC") || sql.contains("ORDER BY stat DESC"),
            "expected sort by stat alias, got: {sql}"
        );
        assert!(
            !sql.contains("JSONExtractString(ext, 'count')"),
            "must not treat count as ext field: {sql}"
        );
    }

    #[test]
    fn generates_in_clause() {
        let q = parse_rpl(r#"parser IN ("Network", "Process")"#).unwrap();
        let sql = generate_clickhouse_sql(&q, "mobipwn", None, None).unwrap();
        assert!(sql.contains("IN ('Network', 'Process')"), "sql: {sql}");
    }

    #[test]
    fn generates_lookup_dictget() {
        let q = parse_rpl(r#"dest_ip=* | lookup geo dest_ip"#).unwrap();
        let sql = generate_clickhouse_sql(&q, "mobipwn", None, None).unwrap();
        assert!(sql.contains("ip_enrichment_dict"));
        assert!(sql.contains("geo_country"));
    }

    #[test]
    fn generates_vt_lookup_with_normalized_ip_key() {
        let q = parse_rpl(r#"dest_ip=* | lookup vt dest_ip"#).unwrap();
        let sql = generate_clickhouse_sql(&q, "mobipwn", None, None).unwrap();
        assert!(sql.contains("ioc_enrichment_dict"));
        assert!(sql.contains("vt_dest_ip_malicious"));
        assert!(sql.contains("vt_dest_ip_harmless"));
        assert!(sql.contains("dictGet('mobipwn.ioc_enrichment_dict', 'vt_malicious'"));
        assert!(sql.contains("replaceRegexpOne"));
    }

    #[test]
    fn stats_by_enrichment_columns_use_lookup_output_not_ext() {
        let q = parse_rpl(
            r#"dest_ip=* | lookup vt dest_ip | stats count by src_ip, dest_ip, vt_dest_ip_malicious | head 10"#,
        )
        .unwrap();
        let sql = generate_clickhouse_sql(&q, "mobipwn", None, None).unwrap();
        assert!(
            !sql.contains("JSONExtractString(ext, 'vt_dest_ip_malicious')"),
            "must reference lookup column, not ext: {sql}"
        );
        assert!(sql.contains("`vt_dest_ip_malicious`"));
        assert!(sql.contains("dictGet('mobipwn.ioc_enrichment_dict'"));
    }

    #[test]
    fn generates_eval_if() {
        let q = parse_rpl(r#"platform="android" | eval flag=if(platform="android",1,0)"#).unwrap();
        let sql = generate_clickhouse_sql(&q, "mobipwn", None, None).unwrap();
        assert!(sql.contains("if(platform"));
        assert!(sql.contains("AS flag"));
    }

    #[test]
    fn generates_stats_values() {
        let q = parse_rpl(r#"source="case-001" | stats values bundle_id by parser"#).unwrap();
        let sql = generate_clickhouse_sql(&q, "mobipwn", None, None).unwrap();
        assert!(sql.contains("groupUniqArray(bundle_id)"));
    }

    #[test]
    fn timechart_limit_keeps_top_series_across_buckets() {
        let q = parse_rpl(r#"platform="android" | timechart span=1h count by parser limit=8"#).unwrap();
        let sql = generate_clickhouse_sql(&q, "mobipwn", None, None).unwrap();
        assert!(sql.contains("top_series"), "sql: {sql}");
        assert!(sql.contains("ORDER BY sum(c) DESC LIMIT 8"), "sql: {sql}");
        assert!(sql.contains("rolled AS"), "sql: {sql}");
        assert!(sql.contains("'Other'"), "sql: {sql}");
        assert!(
            !sql.ends_with("ORDER BY bucket ASC, c DESC LIMIT 8"),
            "sql: {sql}"
        );
    }

    #[test]
    fn timechart_useother_false_omits_other_bucket() {
        let q = parse_rpl(
            r#"platform="android" | timechart span=1h count by parser limit=8 useother=false"#,
        )
        .unwrap();
        let sql = generate_clickhouse_sql(&q, "mobipwn", None, None).unwrap();
        assert!(sql.contains("WHERE series IN (SELECT series FROM top_series)"), "sql: {sql}");
        assert!(!sql.contains("rolled AS"), "sql: {sql}");
        assert!(!sql.contains("'Other'"), "sql: {sql}");
    }

    #[test]
    fn timechart_without_limit_defaults_to_ten_series() {
        let q = parse_rpl(r#"platform="android" | timechart span=1h count by parser"#).unwrap();
        match &q.commands[0] {
            crate::rpl::RplCommand::Timechart { limit, .. } => assert!(limit.is_none()),
            _ => panic!("expected timechart"),
        }
        let sql = generate_clickhouse_sql(&q, "mobipwn", None, None).unwrap();
        assert!(sql.contains("top_series"), "sql: {sql}");
        assert!(sql.contains("ORDER BY sum(c) DESC LIMIT 10"), "sql: {sql}");
    }

    #[test]
    fn timechart_limit_zero_returns_all_series() {
        let q =
            parse_rpl(r#"platform="android" | timechart span=1h count by parser limit=0"#).unwrap();
        let sql = generate_clickhouse_sql(&q, "mobipwn", None, None).unwrap();
        assert!(!sql.contains("top_series"), "sql: {sql}");
        assert!(!sql.contains(" LIMIT "), "sql: {sql}");
    }

    #[test]
    fn apply_row_limit_with_head_does_not_double_limit() {
        let q = parse_rpl(r#"process_name="com.google.android.gms" | head 200"#).unwrap();
        let sql = generate_clickhouse_sql(&q, "mobipwn", None, None).unwrap();
        let capped = apply_row_limit(sql, 100);
        assert!(
            !capped.to_ascii_uppercase().contains("LIMIT 200 LIMIT"),
            "capped sql: {capped}"
        );
        assert!(capped.contains(") LIMIT 100"));
    }
}
