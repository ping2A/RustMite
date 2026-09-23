//! RPL (pipe language) for RustMite hunting — ported from mobipwn-search.
//! Compiles operator queries to ClickHouse SQL against `rustmite.events`.

pub mod fields;
pub mod rpl;
pub mod sql_gen;
pub mod timechart;
pub mod tokenize;

pub use rpl::{parse_rpl, RplQuery};
pub use sql_gen::{
    apply_row_limit, generate_clickhouse_sql, generate_events_filter_sql,
    generate_events_where_clause, SqlGenError,
};
