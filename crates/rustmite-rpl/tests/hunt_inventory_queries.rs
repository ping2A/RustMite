use rustmite_rpl::{apply_row_limit, generate_clickhouse_sql, parse_rpl};

fn compile(q: &str) -> String {
    let parsed = parse_rpl(q).unwrap_or_else(|e| panic!("parse failed for `{q}`: {e}"));
    let sql = generate_clickhouse_sql(&parsed, "rustmite", None, None)
        .unwrap_or_else(|e| panic!("sql failed for `{q}`: {e}"));
    apply_row_limit(sql, 20)
}

#[test]
fn inventory_process_query_compiles() {
    let sql = compile(
        r#"(host_id="01a17cc6-6640-7681-8bc3-8cdb6e373317" OR host_name="CHINAADSGW01") kind="process" | fields timestamp, process_name, process_id, user, path, args, cmdline | sort -timestamp | head 500"#,
    );
    assert!(sql.to_ascii_lowercase().contains("host_id"), "{sql}");
    assert!(sql.to_ascii_lowercase().contains("process"), "{sql}");
    println!("{sql}");
}

#[test]
fn inventory_file_query_compiles() {
    let sql = compile(
        r#"(host_id="01a17cc6-6640-7681-8bc3-8cdb6e373317" OR host_name="CHINAADSGW01") kind="file_meta" | fields timestamp, path, file_hash, user, message | sort path | head 500"#,
    );
    assert!(sql.to_ascii_lowercase().contains("file_meta"), "{sql}");
    println!("{sql}");
}

#[test]
fn inventory_process_filter_or_compiles() {
    let sql = compile(
        r#"(host_id="01a17cc6-6640-7681-8bc3-8cdb6e373317" OR host_name="CHINAADSGW01") kind="process" (process_name="*init*" OR path="*init*" OR cmdline="*init*") | fields timestamp, process_name, path, cmdline | head 50"#,
    );
    assert!(sql.to_ascii_lowercase().contains("like") || sql.contains("init"), "{sql}");
    println!("{sql}");
}

#[test]
fn inventory_file_path_filter_compiles() {
    let sql = compile(
        r#"(host_id="01a17cc6-6640-7681-8bc3-8cdb6e373317" OR host_name="CHINAADSGW01") kind="file_meta" path="*/data*" | fields timestamp, path | head 50"#,
    );
    assert!(sql.to_ascii_lowercase().contains("like"), "{sql}");
    println!("{sql}");
}
