//! RustMite searchable fields for RPL → ClickHouse (API-compatible with mobipwn MUDM helpers).

#[derive(Clone, Copy, Debug)]
pub struct SearchField {
    pub name: &'static str,
    pub column: &'static str,
}

pub const SEARCHABLE_FIELDS: &[SearchField] = &[
    SearchField { name: "message", column: "message" },
    SearchField { name: "timestamp", column: "timestamp" },
    SearchField { name: "source_type", column: "source_type" },
    SearchField { name: "source", column: "source" },
    SearchField { name: "platform", column: "platform" },
    SearchField { name: "host_id", column: "host_id" },
    SearchField { name: "host_name", column: "host_name" },
    SearchField { name: "scan_id", column: "scan_id" },
    SearchField { name: "collector", column: "collector" },
    SearchField { name: "kind", column: "kind" },
    SearchField { name: "check_id", column: "check_id" },
    SearchField { name: "data_type", column: "data_type" },
    SearchField { name: "process_name", column: "process_name" },
    SearchField { name: "process_id", column: "process_id" },
    SearchField { name: "user", column: "user" },
    SearchField { name: "path", column: "path" },
    SearchField { name: "src_ip", column: "src_ip" },
    SearchField { name: "dest_ip", column: "dest_ip" },
    SearchField { name: "file_hash", column: "file_hash" },
    SearchField { name: "severity", column: "severity" },
    SearchField { name: "exe_memfd", column: "exe_memfd" },
    SearchField { name: "tags", column: "" },
    SearchField { name: "event_type", column: "" },
    SearchField { name: "ext", column: "ext" },
];

pub fn is_numeric_field(name: &str) -> bool {
    matches!(name, "process_id" | "exe_memfd" | "local_port" | "remote_port" | "ppid")
}

pub fn resolve_field_sql(field: &str) -> Option<String> {
    let normalized = match field {
        "sourcetype" => "source_type",
        other => other,
    };
    if !SEARCHABLE_FIELDS.iter().any(|f| f.name == normalized) {
        return None;
    }
    if normalized == "tags" {
        return Some(tags_sql());
    }
    if let Some(f) = SEARCHABLE_FIELDS.iter().find(|f| f.name == normalized) {
        if !f.column.is_empty() {
            return Some(f.column.to_string());
        }
    }
    Some(format!("JSONExtractString(ext, '{normalized}')"))
}

pub fn field_has_value_sql(field: &str) -> Option<String> {
    if field == "tags" {
        return Some("length(JSONExtract(ext, 'tags', 'Array(String)')) > 0".into());
    }
    let col = resolve_field_sql(field)?;
    if is_numeric_field(field) {
        Some(format!("{col} != 0"))
    } else {
        Some(format!("{col} != ''"))
    }
}

pub fn tags_sql() -> String {
    "arrayStringConcat(JSONExtract(ext, 'tags', 'Array(String)'), ',')".to_string()
}

pub fn tag_contains_sql(tag: &str) -> String {
    let escaped = tag.replace('\'', "''");
    format!("has(JSONExtract(ext, 'tags', 'Array(String)'), '{escaped}')")
}

pub fn clickhouse_ip_indicator_key(col: &str) -> String {
    format!(
        "if(isIPv4String({col}), toUInt64(IPv4StringToNum({col})), reinterpretAsUInt128(IPv6StringToNum({col})))"
    )
}
