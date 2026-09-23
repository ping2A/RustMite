use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RplQuery {
    /// `last 24h` style modifier parsed from the search bar prefix.
    pub time_range: Option<TimeRange>,
    pub search: SearchExpr,
    pub commands: Vec<RplCommand>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimeUnit {
    Minutes,
    Hours,
    Days,
    Weeks,
}

/// `last 24h` vs `now-7d` — both resolve to [now - duration, now] in admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum TimeAnchor {
    #[default]
    Last,
    NowMinus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeRange {
    pub amount: u32,
    pub unit: TimeUnit,
    #[serde(default)]
    pub anchor: TimeAnchor,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SearchExpr {
    And(Vec<SearchExpr>),
    Or(Vec<SearchExpr>),
    Not(Box<SearchExpr>),
    Field { field: String, op: CompareOp, value: String },
    In {
        field: String,
        values: Vec<String>,
        negate: bool,
    },
    BareToken(String),
    Wildcard { field: Option<String>, pattern: String },
    True,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompareOp {
    Eq,
    Ne,
    Gt,
    Lt,
    Gte,
    Lte,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JoinType {
    Inner,
    Left,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RplCommand {
    Where(SearchExpr),
    Stats {
        agg: String,
        field: Option<String>,
        by: Vec<String>,
    },
    Head { limit: u32 },
    Sort { field: String, desc: bool },
    Timechart {
        span: String,
        agg: String,
        /// Field for `avg`/`min`/`max`/`sum` (unused for `count`).
        field: Option<String>,
        by: Option<String>,
        /// Top N split-by values; `None` = all series.
        limit: Option<u32>,
        /// Roll remaining split-by values into `Other` (OpenSearch `useother`, default true).
        useother: Option<bool>,
    },
    /// `eval field=expr` — literal, `if()`, or simple arithmetic on fields.
    Eval { field: String, expr: String },
    /// `rename old AS new`
    Rename { old: String, new: String },
    /// `lookup [prefix] field` — dictGet enrichment columns (IP / file_hash).
    Lookup {
        field: String,
        prefix: String,
    },
    Dedup { field: String },
    /// `rex name=(pattern) field=message` — extract capture group 1 into `name`.
    Rex {
        name: String,
        pattern: String,
        field: String,
    },
    /// `join [ type=inner ] device_id [ subquery ]`
    Join {
        join_type: JoinType,
        field: String,
        subquery: RplQuery,
    },
    /// `fields platform parser message` — column projection.
    Fields { names: Vec<String> },
}

impl RplCommand {
    /// Short label for error messages and validation hints (e.g. `head 50`, `stats count by parser`).
    pub fn pipe_label(&self) -> String {
        match self {
            RplCommand::Where(_) => "where".into(),
            RplCommand::Stats { agg, field, by } => {
                let mut s = format!("stats {agg}");
                if let Some(f) = field {
                    s.push(' ');
                    s.push_str(f);
                }
                if !by.is_empty() {
                    s.push_str(" by ");
                    s.push_str(&by.join(", "));
                }
                s
            }
            RplCommand::Head { limit } => format!("head {limit}"),
            RplCommand::Sort { field, desc } => {
                format!("sort {}{field}", if *desc { "-" } else { "" })
            }
            RplCommand::Timechart {
                span,
                agg,
                field,
                by,
                limit,
                ..
            } => {
                let mut s = format!("timechart span={span} {agg}");
                if let Some(f) = field {
                    s.push(' ');
                    s.push_str(f);
                }
                if let Some(f) = by {
                    s.push_str(" by ");
                    s.push_str(f);
                }
                if let Some(n) = limit {
                    s.push_str(&format!(" limit={n}"));
                }
                s
            }
            RplCommand::Eval { field, .. } => format!("eval {field}=…"),
            RplCommand::Rename { old, new } => format!("rename {old} AS {new}"),
            RplCommand::Lookup { field, prefix } => format!("lookup {prefix} {field}"),
            RplCommand::Dedup { field } => format!("dedup {field}"),
            RplCommand::Rex { name, .. } => format!("rex {name}=…"),
            RplCommand::Join { field, .. } => format!("join {field}"),
            RplCommand::Fields { names } => format!("fields {}", names.join(", ")),
        }
    }
}

impl RplQuery {
    /// Pipe segment summary for errors (e.g. `| head 50 | stats count by parser`).
    pub fn pipe_summary(&self) -> String {
        self.commands
            .iter()
            .map(|c| format!("| {}", c.pipe_label()))
            .collect::<Vec<_>>()
            .join(" ")
    }

    pub fn join_count(&self) -> usize {
        self.commands
            .iter()
            .filter(|c| matches!(c, RplCommand::Join { .. }))
            .count()
            + self
                .commands
                .iter()
                .filter_map(|c| match c {
                    RplCommand::Join { subquery, .. } => Some(subquery.join_count()),
                    _ => None,
                })
                .sum::<usize>()
    }

    pub fn is_broad_search(&self) -> bool {
        is_broad_expr(&self.search)
    }

    /// True when the search clause filters on a named field (e.g. `source="case-001"`).
    pub fn filters_field(&self, field: &str) -> bool {
        expr_filters_field(&self.search, field)
    }

    /// Exact `field=value` literal from the search clause (no globs), if present.
    pub fn literal_field_eq(&self, field: &str) -> Option<String> {
        literal_field_eq_expr(&self.search, field)
    }

    /// Bugreport/sysdiagnose events use device timestamps, not ingest "now" — do not apply
    /// the default `last N hours` wall-clock window unless the user sets `last` or the time picker.
    pub fn skips_default_time_window(&self) -> bool {
        if self.time_range.is_some() {
            return false;
        }
        if self.filters_field("source") || self.filters_investigation_ioc() {
            return true;
        }
        if self.is_broad_search() {
            return false;
        }
        const SCOPED: &[&str] = &["platform", "parser", "device_id", "source_type"];
        SCOPED.iter().any(|f| self.filters_field(f))
    }

    /// IoC-style investigation filters (Amnesty rules) — skip default wall-clock window.
    pub fn filters_investigation_ioc(&self) -> bool {
        const IOC: &[&str] = &[
            "bundle_id",
            "destination_domain",
            "dest_ip",
            "file_hash",
            "file_path",
            "email",
            "function",
            "process_name",
            "event_type",
            "data_type",
        ];
        IOC.iter().any(|f| expr_filters_field(&self.search, f) || expr_filters_wildcard(&self.search, f))
    }
}

fn expr_filters_field(expr: &SearchExpr, field: &str) -> bool {
    match expr {
        SearchExpr::Field { field: f, .. } | SearchExpr::In { field: f, .. } => f == field,
        SearchExpr::And(parts) | SearchExpr::Or(parts) => {
            parts.iter().any(|e| expr_filters_field(e, field))
        }
        SearchExpr::Not(inner) => expr_filters_field(inner, field),
        _ => false,
    }
}

fn literal_field_eq_expr(expr: &SearchExpr, field: &str) -> Option<String> {
    match expr {
        SearchExpr::Field {
            field: f,
            op: CompareOp::Eq,
            value,
        } if f == field && !value.contains('*') && !value.contains('?') => Some(value.clone()),
        SearchExpr::And(parts) | SearchExpr::Or(parts) => {
            parts.iter().find_map(|e| literal_field_eq_expr(e, field))
        }
        _ => None,
    }
}

fn expr_filters_wildcard(expr: &SearchExpr, field: &str) -> bool {
    match expr {
        SearchExpr::Wildcard {
            field: Some(f), ..
        } => f == field,
        SearchExpr::And(parts) | SearchExpr::Or(parts) => {
            parts.iter().any(|e| expr_filters_wildcard(e, field))
        }
        SearchExpr::Not(inner) => expr_filters_wildcard(inner, field),
        _ => false,
    }
}

fn is_broad_expr(expr: &SearchExpr) -> bool {
    match expr {
        SearchExpr::True => true,
        SearchExpr::BareToken(_) | SearchExpr::Wildcard { .. } => true,
        SearchExpr::And(parts) | SearchExpr::Or(parts) => {
            parts.is_empty() || parts.iter().all(is_broad_expr)
        }
        SearchExpr::Not(inner) => is_broad_expr(inner),
        SearchExpr::Field { .. } | SearchExpr::In { .. } => false,
    }
}
