//! SQLite event store for normalized ingested datasets/events.
//!
//! Process and file rows are stored in tables **`processes`** and **`file`** whose columns match
//! [osquery 5.22.1](https://osquery.io/schema/5.22.1/) `processes` and `file`, plus IronSift columns
//! `id`, `dataset_id`, and `machine_id`. See [`crate::osquery_event_ddl`].

use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeSet, HashMap};
use std::error::Error;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use rusqlite::{params, types::Value as SqlValue, Connection};
use serde::{Deserialize, Serialize};
use rusqlite::OptionalExtension;
use uuid::Uuid;

use crate::config::DetectionConfig;
use crate::json_parse::{
    classify_json_line_shape, default_machine_fallback_for_source_file, parse_files_json_logs,
    parse_json_logs, parse_jsonl_process_line, JsonLineShape,
};
use crate::osquery_event_ddl::{CREATE_FILE_TABLE, CREATE_PROCESSES_TABLE};
use crate::sigma_log_export::{
    export_file_sources_to_sigma_jsonl_writer, sigma_json_from_ingested_file_sql_row,
    sigma_json_from_ingested_sql_row,
};
use crate::platform::{DatasetKind, DatasetRecord};
use crate::types::{RawFileEntry, RawLogEntry};

/// Upper bound for `inspect_dataset` sample rows per table (process / file).
pub const DATASET_INSPECT_MAX_SAMPLE: u32 = 2000;

/// Max NDJSON data lines per `append_test_ndjson` request (non-empty, non-comment).
pub const APPEND_TEST_MAX_LINES: usize = 500;
/// Max request body size for test append (bytes).
pub const APPEND_TEST_MAX_BYTES: usize = 1_000_000;
/// Max combined process + file row ids per delete-events request.
pub const DELETE_DATASET_EVENTS_MAX_IDS: usize = 200;
const APPEND_TEST_MAX_ERRORS_RETURNED: usize = 40;

/// SQLite `PRAGMA user_version` — bump when event table semantics require migration.
const EVENT_SCHEMA_VERSION: i32 = 5;
/// Stored `file.inv_checksum` values from DBs below this version used a different formula; those
/// rows must be dropped so hosts re-ingest file inventory.
const MIN_USER_VERSION_INV_CHECKSUM_FILENAME_MODE: i32 = 5;

/// Platform key for which [`DetectionConfig`] profile is active for runs (unless overridden per request).
pub const PLATFORM_SETTING_SELECTED_DETECTION_CONFIG: &str = "selected_detection_config_id";

/// One stored IronSift detection configuration profile (`events.db`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfigProfileMeta {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub is_selected: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AppendTestSummary {
    pub inserted: usize,
    pub skipped_blank_lines: usize,
    pub parse_errors: Vec<String>,
}

pub struct EventDb {
    path: String,
}

/// Row counts in SQLite after a full dataset ingest (`ingest_dataset` replaces prior rows for that id).
#[derive(Debug, Clone, Serialize)]
pub struct IngestSummary {
    pub dataset_id: String,
    /// `process`, `file`, or `mixed` — derived from ingested row counts (NDJSON can populate both tables).
    pub kind: String,
    pub process_event_count: u64,
    pub file_event_count: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DatasetInspection {
    pub dataset_id: String,
    pub schema_profile: String,
    pub kind: String,
    pub process_event_count: u64,
    pub file_event_count: u64,
    pub sample_process_events: Vec<serde_json::Value>,
    pub sample_file_events: Vec<serde_json::Value>,
}

impl EventDb {
    pub fn new(path: &str) -> Result<Self, Box<dyn Error>> {
        let db = Self {
            path: path.to_string(),
        };
        db.init()?;
        Ok(db)
    }

    fn conn(&self) -> Result<Connection, Box<dyn Error>> {
        let conn = Connection::open(&self.path)?;
        // Sane defaults for IronSift’s mixed read/write workload: WAL lets readers run while
        // a long ingest transaction (hundreds of thousands of rows) holds the writer; the
        // 10s busy timeout absorbs short contention instead of returning SQLITE_BUSY to the
        // HTTP handler; synchronous=NORMAL trades a sliver of crash durability for ~10× ingest
        // throughput on rotating disks; temp_store=MEMORY keeps DISTINCT/ORDER BY scratch off disk.
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;\
             PRAGMA synchronous=NORMAL;\
             PRAGMA busy_timeout=10000;\
             PRAGMA temp_store=MEMORY;",
        )?;
        Ok(conn)
    }

    fn init(&self) -> Result<(), Box<dyn Error>> {
        let conn = self.conn()?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS datasets (
              id TEXT PRIMARY KEY,
              name TEXT NOT NULL,
              source_path TEXT NOT NULL,
              format TEXT NOT NULL,
              kind TEXT NOT NULL,
              schema_profile TEXT NOT NULL,
              imported_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS dataset_tags (
              dataset_id TEXT NOT NULL,
              tag TEXT NOT NULL
            );
            "#,
        )?;
        migrate_osquery_event_tables(&conn)?;
        migrate_detection_config_tables(&conn)?;
        Ok(())
    }

    /// Replace SQLite rows for `ds.id` from `ds.source_path`. **Does not consult**
    /// [`crate::config::DetectionConfig`]: parsing succeeds → row is stored (same philosophy as raw
    /// log retention). Run-time filtering applies only in [`crate::loaders`] and detection flows.
    pub fn ingest_dataset(&self, ds: &DatasetRecord) -> Result<IngestSummary, Box<dyn Error>> {
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;

        let initial_kind = match ds.kind {
            DatasetKind::Process => "process",
            DatasetKind::File => "file",
            DatasetKind::Mixed => "mixed",
        };
        tx.execute(
            "INSERT OR REPLACE INTO datasets (id,name,source_path,format,kind,schema_profile,imported_at) VALUES (?,?,?,?,?,?,?)",
            params![
                ds.id,
                ds.name,
                ds.source_path,
                ds.format,
                initial_kind,
                ds.schema_profile,
                ds.imported_at
            ],
        )?;
        tx.execute("DELETE FROM dataset_tags WHERE dataset_id = ?", params![ds.id])?;
        for t in &ds.tags {
            tx.execute(
                "INSERT INTO dataset_tags (dataset_id, tag) VALUES (?,?)",
                params![ds.id, t],
            )?;
        }

        tx.execute("DELETE FROM processes WHERE dataset_id = ?", params![ds.id])?;
        tx.execute(r#"DELETE FROM "file" WHERE dataset_id = ?"#, params![ds.id])?;

        if is_jsonl_ndjson_source(ds) {
            ingest_jsonl_process_and_file_tables(&tx, ds)?;
        } else {
            match ds.kind {
                DatasetKind::Process | DatasetKind::Mixed => {
                    let rows =
                        read_process_rows(&ds.source_path, ds.ingest_default_machine_id.as_deref())?;
                    let mut stmt = tx.prepare(
                    "INSERT INTO processes (dataset_id,machine_id,pid,name,path,cmdline,uid,parent,start_time) VALUES (?,?,?,?,?,?,?,?,?)",
                )?;
                    for r in rows {
                        let cmdline = full_cmdline(&r);
                        let start_time = optional_epoch_seconds(&r.timestamp);
                        stmt.execute(params![
                            ds.id,
                            r.machine_id,
                            i64::from(r.pid),
                            r.name,
                            r.path,
                            cmdline,
                            i64::from(r.uid),
                            i64::from(r.ppid),
                            start_time,
                        ])?;
                    }
                }
                DatasetKind::File => {
                    let rows =
                        read_file_rows(&ds.source_path, ds.ingest_default_machine_id.as_deref())?;
                    let mut stmt = tx.prepare(
                    r#"INSERT INTO "file" (dataset_id,machine_id,path,directory,filename,uid,mode,size,mtime,atime,inv_checksum) VALUES (?,?,?,?,?,?,?,?,?,?,?)"#,
                )?;
                    for r in rows {
                        let (directory, filename) = split_path_directory_filename(&r.path);
                        let mtime = optional_epoch_seconds(&r.mtime);
                        let atime = optional_epoch_seconds(&r.timestamp);
                        let inv =
                            file_inv_checksum_for_row(filename.as_str(), r.permissions.as_deref());
                        stmt.execute(params![
                            ds.id,
                            r.machine_id,
                            r.path,
                            directory,
                            filename,
                            i64::from(r.uid),
                            r.permissions,
                            r.size.map(|u| u as i64),
                            mtime,
                            atime,
                            inv,
                        ])?;
                    }
                }
            }
        }
        tx.commit()?;

        let process_event_count: u64 = conn.query_row(
            "SELECT COUNT(*) FROM processes WHERE dataset_id = ?",
            params![ds.id],
            |r| r.get(0),
        )?;
        let file_event_count: u64 = conn.query_row(
            r#"SELECT COUNT(*) FROM "file" WHERE dataset_id = ?"#,
            params![ds.id],
            |r| r.get(0),
        )?;
        let kind = effective_ingest_kind_str(process_event_count, file_event_count, ds.kind);
        conn.execute(
            "UPDATE datasets SET kind = ?1 WHERE id = ?2",
            params![kind, ds.id],
        )?;
        Ok(IngestSummary {
            dataset_id: ds.id.clone(),
            kind: kind.to_string(),
            process_event_count,
            file_event_count,
        })
    }

    pub fn inspect_dataset(
        &self,
        dataset_id: &str,
        process_limit: u32,
        file_limit: u32,
    ) -> Result<DatasetInspection, Box<dyn Error>> {
        let pl = process_limit.clamp(1, DATASET_INSPECT_MAX_SAMPLE);
        let fl = file_limit.clamp(1, DATASET_INSPECT_MAX_SAMPLE);
        let conn = self.conn()?;
        let (schema_profile, kind): (String, String) = conn.query_row(
            "SELECT schema_profile, kind FROM datasets WHERE id = ? LIMIT 1",
            params![dataset_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;

        let process_event_count: u64 = conn.query_row(
            "SELECT COUNT(*) FROM processes WHERE dataset_id = ?",
            params![dataset_id],
            |r| r.get(0),
        )?;
        let file_event_count: u64 = conn.query_row(
            r#"SELECT COUNT(*) FROM "file" WHERE dataset_id = ?"#,
            params![dataset_id],
            |r| r.get(0),
        )?;

        let sample_process_events =
            query_samples_as_json(&conn, "processes", dataset_id, i64::from(pl))?;
        let sample_file_events = query_samples_as_json(&conn, r#""file""#, dataset_id, i64::from(fl))?;

        Ok(DatasetInspection {
            dataset_id: dataset_id.to_string(),
            schema_profile,
            kind,
            process_event_count,
            file_event_count,
            sample_process_events,
            sample_file_events,
        })
    }

    /// Append stored `processes` rows for one dataset as Sigma JSONL lines (`out` is not truncated).
    pub fn export_dataset_processes_sigma_jsonl_append<W: Write>(
        &self,
        dataset_id: &str,
        out: &mut W,
    ) -> Result<u64, Box<dyn Error>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT machine_id, pid, name, path, cmdline, uid, parent, start_time FROM processes WHERE dataset_id = ?",
        )?;
        let mut rows = stmt.query(params![dataset_id])?;
        let mut total = 0u64;
        while let Some(row) = rows.next()? {
            let machine_id: String = row.get(0)?;
            let pid: i64 = row.get(1)?;
            let name: String = row.get(2)?;
            let path: String = row.get(3)?;
            let cmdline: String = row.get(4)?;
            let uid: i64 = row.get(5)?;
            let parent: i64 = row.get(6)?;
            let start_time: Option<i64> = row.get(7)?;
            let v = sigma_json_from_ingested_sql_row(
                dataset_id,
                &machine_id,
                pid,
                &name,
                &path,
                &cmdline,
                uid,
                parent,
                start_time,
            );
            writeln!(
                out,
                "{}",
                serde_json::to_string(&v).map_err(|e| e.to_string())?
            )?;
            total += 1;
        }
        Ok(total)
    }

    /// Append stored `file` rows for one dataset as Sigma JSONL (`event_type` = file_information).
    pub fn export_dataset_files_sigma_jsonl_append<W: Write>(
        &self,
        dataset_id: &str,
        out: &mut W,
    ) -> Result<u64, Box<dyn Error>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            r#"SELECT machine_id, path, uid, mode, size, mtime, atime, directory, filename FROM "file" WHERE dataset_id = ?"#,
        )?;
        let mut rows = stmt.query(params![dataset_id])?;
        let mut total = 0u64;
        while let Some(row) = rows.next()? {
            let machine_id: String = row.get(0)?;
            let path: String = row.get(1)?;
            let uid: i64 = row.get(2)?;
            let mode: Option<String> = row.get(3)?;
            let size: Option<i64> = row.get(4)?;
            let mtime: Option<i64> = row.get(5)?;
            let atime: Option<i64> = row.get(6)?;
            let directory: Option<String> = row.get(7)?;
            let filename: Option<String> = row.get(8)?;
            let v = sigma_json_from_ingested_file_sql_row(
                &machine_id,
                &path,
                directory.as_deref(),
                filename.as_deref(),
                uid,
                mode.as_deref(),
                size,
                mtime,
                atime,
                Some(dataset_id),
            );
            writeln!(
                out,
                "{}",
                serde_json::to_string(&v).map_err(|e| e.to_string())?
            )?;
            total += 1;
        }
        Ok(total)
    }

    /// Sigma export for file-shaped datasets: SQLite `file` rows first; for **pure file** datasets only,
    /// fall back to parsing `source_path` as file inventory JSON/CSV when the DB has no rows.
    pub fn append_sigma_file_lines_for_dataset<W: Write>(
        &self,
        ds: &DatasetRecord,
        out: &mut W,
    ) -> Result<(u64, bool, bool), Box<dyn Error>> {
        let n_sql = self.export_dataset_files_sigma_jsonl_append(&ds.id, out)?;
        if n_sql > 0 {
            return Ok((n_sql, true, false));
        }
        if ds.kind != DatasetKind::File {
            return Ok((0, false, false));
        }
        let p = Path::new(&ds.source_path);
        if !p.is_file() {
            return Ok((0, false, false));
        }
        let n_file = export_file_sources_to_sigma_jsonl_writer(
            &[(ds.source_path.clone(), ds.format.clone())],
            out,
            Some(&ds.id),
        )?;
        Ok((n_file, false, n_file > 0))
    }

    /// Sigma export for one dataset: ingested SQLite rows (includes append-test-data), else lines parsed from `source_path`.
    pub fn append_sigma_process_lines_for_dataset<W: Write>(
        &self,
        ds: &DatasetRecord,
        out: &mut W,
    ) -> Result<(u64, bool, bool), Box<dyn Error>> {
        if ds.kind == DatasetKind::File {
            return Ok((0, false, false));
        }
        let n_sql = self.export_dataset_processes_sigma_jsonl_append(&ds.id, out)?;
        if n_sql > 0 {
            return Ok((n_sql, true, false));
        }
        let p = Path::new(&ds.source_path);
        if !p.is_file() {
            return Ok((0, false, false));
        }
        let n_file = crate::sigma_log_export::export_process_sources_to_sigma_jsonl_writer(
            &[(ds.source_path.clone(), ds.format.clone())],
            out,
            Some(&ds.id),
        )?;
        Ok((n_file, false, n_file > 0))
    }

    /// Export stored `processes` rows for the given dataset ids to Sigma JSONL (same keys as file-based export).
    pub fn export_process_datasets_to_sigma_jsonl(
        &self,
        dataset_ids: &[String],
        out_path: &Path,
    ) -> Result<u64, Box<dyn Error>> {
        if dataset_ids.is_empty() {
            return Ok(0);
        }
        let mut out = File::create(out_path)?;
        let mut total = 0u64;
        for ds_id in dataset_ids {
            total += self.export_dataset_processes_sigma_jsonl_append(ds_id, &mut out)?;
        }
        Ok(total)
    }

    /// Delete ingested process rows by primary key; only rows belonging to `dataset_id` are removed.
    pub fn delete_process_events_by_ids(
        &self,
        dataset_id: &str,
        ids: &[i64],
    ) -> Result<usize, Box<dyn Error>> {
        if ids.is_empty() {
            return Ok(0);
        }
        let conn = self.conn()?;
        let mut stmt =
            conn.prepare_cached("DELETE FROM processes WHERE id = ? AND dataset_id = ?")?;
        let mut deleted = 0usize;
        for id in ids {
            deleted += stmt.execute(params![id, dataset_id])?;
        }
        Ok(deleted)
    }

    /// Delete ingested file rows by primary key; only rows belonging to `dataset_id` are removed.
    pub fn delete_file_events_by_ids(
        &self,
        dataset_id: &str,
        ids: &[i64],
    ) -> Result<usize, Box<dyn Error>> {
        if ids.is_empty() {
            return Ok(0);
        }
        let conn = self.conn()?;
        let mut stmt =
            conn.prepare_cached(r#"DELETE FROM "file" WHERE id = ? AND dataset_id = ?"#)?;
        let mut deleted = 0usize;
        for id in ids {
            deleted += stmt.execute(params![id, dataset_id])?;
        }
        Ok(deleted)
    }

    pub fn delete_all_datasets(&self) -> Result<(), Box<dyn Error>> {
        let conn = self.conn()?;
        conn.execute("DELETE FROM dataset_tags", [])?;
        conn.execute("DELETE FROM processes", [])?;
        conn.execute(r#"DELETE FROM "file""#, [])?;
        conn.execute("DELETE FROM datasets", [])?;
        Ok(())
    }

    /// Reconstruct ingested process rows as [`RawLogEntry`] for fleet / AnoMark scoring.
    ///
    /// Includes rows added via `append_test_ndjson` so detection runs reflect what the
    /// Inspect UI shows. `cmdline` is split back into `path` + `args` to preserve the
    /// shape produced by `parse_jsonl_process_line` during ingest.
    pub fn process_entries_for_dataset(
        &self,
        dataset_id: &str,
    ) -> Result<Vec<RawLogEntry>, Box<dyn Error>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT machine_id, pid, name, path, cmdline, uid, parent, start_time \
             FROM processes WHERE dataset_id = ?",
        )?;
        let mut rows = stmt.query(params![dataset_id])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let machine_id: String = row.get(0)?;
            let pid: i64 = row.get(1)?;
            let name: String = row.get(2)?;
            let path: String = row.get(3)?;
            let cmdline: String = row.get(4)?;
            let uid: i64 = row.get(5)?;
            let parent: i64 = row.get(6)?;
            let start_time: Option<i64> = row.get(7)?;
            let path_trim = path.trim();
            let args = if !path_trim.is_empty() && cmdline.starts_with(path_trim) {
                cmdline[path_trim.len()..].trim_start().to_string()
            } else if cmdline == name {
                String::new()
            } else {
                cmdline
            };
            out.push(RawLogEntry {
                machine_id,
                pid: clamp_u32_from_i64(pid),
                ppid: clamp_u32_from_i64(parent),
                name,
                uid: clamp_u32_from_i64(uid),
                path,
                args,
                timestamp: start_time.map(|s| s.to_string()),
            });
        }
        Ok(out)
    }

    /// Find one example row in `processes` matching `(machine_id, name, path)` for any of the given datasets.
    /// Returns the dataset id alongside the row so the caller can cite which dataset fed the example.
    /// Empty `datasets` means "search across all datasets".
    pub fn find_process_row_example(
        &self,
        datasets: &[String],
        machine_id: &str,
        name: &str,
        path: &str,
    ) -> Result<Option<ProcessRowExample>, Box<dyn Error>> {
        let conn = self.conn()?;
        if datasets.is_empty() {
            let mut stmt = conn.prepare(
                "SELECT dataset_id, machine_id, pid, parent, uid, name, path, cmdline, start_time \
                 FROM processes \
                 WHERE machine_id = ? AND name = ? AND path = ? LIMIT 1",
            )?;
            return Ok(query_process_row_example_optional(
                &mut stmt,
                params![machine_id, name, path],
            )?);
        }
        let mut stmt = conn.prepare(
            "SELECT dataset_id, machine_id, pid, parent, uid, name, path, cmdline, start_time \
             FROM processes \
             WHERE dataset_id = ? AND machine_id = ? AND name = ? AND path = ? LIMIT 1",
        )?;
        for ds in datasets {
            if let Some(ex) = query_process_row_example_optional(
                &mut stmt,
                params![ds, machine_id, name, path],
            )? {
                return Ok(Some(ex));
            }
        }
        Ok(None)
    }

    /// Reconstruct ingested file rows as [`RawFileEntry`] for fleet runs.
    ///
    /// Includes rows added via `append_test_ndjson`. For large fleets prefer
    /// [`Self::group_file_entries_by_machine`] which avoids a second 800k-element copy.
    pub fn file_entries_for_dataset(
        &self,
        dataset_id: &str,
    ) -> Result<Vec<RawFileEntry>, Box<dyn Error>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            r#"SELECT machine_id, path, uid, mode, size, mtime, atime FROM "file" WHERE dataset_id = ?"#,
        )?;
        let mut rows = stmt.query(params![dataset_id])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let machine_id: String = row.get(0)?;
            let path: String = row.get(1)?;
            let uid: i64 = row.get(2)?;
            let permissions: Option<String> = row.get(3)?;
            let size: Option<i64> = row.get(4)?;
            let mtime: Option<i64> = row.get(5)?;
            let atime: Option<i64> = row.get(6)?;
            out.push(RawFileEntry {
                machine_id,
                path,
                uid: clamp_u32_from_i64(uid),
                timestamp: atime.map(|s| s.to_string()),
                mtime: mtime.map(|s| s.to_string()),
                permissions,
                owner: None,
                group: None,
                size: size.and_then(|s| if s >= 0 { Some(s as u64) } else { None }),
            });
        }
        Ok(out)
    }

    /// Streamed variant of [`Self::file_entries_for_dataset`] that groups rows by machine
    /// while reading them. Avoids materializing one big `Vec<RawFileEntry>` for the whole
    /// dataset (which is 200+ MB on a 20 × 40k file fleet and stays alive through profile
    /// build); per-machine vectors are released as profiles are built. Caller can feed the
    /// result directly to [`crate::file_analysis::build_file_profiles_from_grouped`].
    /// Count file rows stored for a dataset (before run-level `inv_checksum` exclusion).
    pub fn count_file_rows_for_dataset(&self, dataset_id: &str) -> Result<u64, Box<dyn Error>> {
        let conn = self.conn()?;
        let n: i64 = conn.query_row(
            r#"SELECT COUNT(*) FROM "file" WHERE dataset_id = ?"#,
            params![dataset_id],
            |r| r.get(0),
        )?;
        Ok(n.max(0) as u64)
    }

    pub fn group_file_entries_by_machine(
        &self,
        dataset_id: &str,
    ) -> Result<HashMap<String, Vec<RawFileEntry>>, Box<dyn Error>> {
        self.group_file_entries_by_machine_for_run(dataset_id, &[], false)
    }

    /// Like [`Self::group_file_entries_by_machine`], optionally excluding rows whose
    /// `inv_checksum` is universal across the run’s selected file datasets (see
    /// [`crate::config::DetectionConfig::file_exclude_common_inventory_sql`]).
    pub fn group_file_entries_by_machine_for_run(
        &self,
        dataset_id: &str,
        run_file_dataset_ids: &[String],
        exclude_common_inventory: bool,
    ) -> Result<HashMap<String, Vec<RawFileEntry>>, Box<dyn Error>> {
        let conn = self.conn()?;
        if !exclude_common_inventory {
            return query_grouped_file_rows_simple(&conn, dataset_id);
        }
        let mut uniq: Vec<&str> = Vec::new();
        let mut seen = BTreeSet::new();
        for s in run_file_dataset_ids {
            if seen.insert(s.as_str()) {
                uniq.push(s.as_str());
            }
        }
        if uniq.is_empty() {
            return query_grouped_file_rows_simple(&conn, dataset_id);
        }
        if uniq.len() == 1 {
            return query_grouped_file_rows_exclude_universal_one_ds(&conn, dataset_id);
        }
        query_grouped_file_rows_exclude_common_multi(&conn, dataset_id, &uniq)
    }

    /// Append process or file events parsed from NDJSON lines. Does not re-read the dataset source file.
    /// Process lines use [`parse_jsonl_process_line`]; file lines deserialize as [`RawFileEntry`].
    pub fn append_test_ndjson(
        &self,
        dataset_id: &str,
        default_machine: &str,
        raw: &str,
    ) -> Result<AppendTestSummary, Box<dyn Error>> {
        if raw.len() > APPEND_TEST_MAX_BYTES {
            return Err(format!(
                "body exceeds max size ({} bytes)",
                APPEND_TEST_MAX_BYTES
            )
            .into());
        }
        let mut conn = self.conn()?;
        let kind: String = conn
            .query_row(
                "SELECT kind FROM datasets WHERE id = ? LIMIT 1",
                params![dataset_id],
                |r| r.get(0),
            )
            .map_err(|_| "dataset not found")?;
        let route = kind.as_str();

        let mut inserted = 0usize;
        let mut skipped_blank_lines = 0usize;
        let mut parse_errors: Vec<String> = Vec::new();
        let mut data_lines = 0usize;

        let tx = conn.transaction()?;
        for (physical_idx, raw_line) in raw.lines().enumerate() {
            let line_no = physical_idx + 1;
            let t = raw_line.trim();
            if t.is_empty() {
                skipped_blank_lines += 1;
                continue;
            }
            if t.starts_with("//") || t.starts_with('#') {
                continue;
            }
            data_lines += 1;
            if data_lines > APPEND_TEST_MAX_LINES {
                return Err(format!(
                    "too many data lines (max {} non-empty lines)",
                    APPEND_TEST_MAX_LINES
                )
                .into());
            }
            if route == "process" {
                match parse_jsonl_process_line(t, default_machine) {
                    Ok(r) => {
                        let cmdline = full_cmdline(&r);
                        let start_time = optional_epoch_seconds(&r.timestamp);
                        tx.execute(
                            "INSERT INTO processes (dataset_id,machine_id,pid,name,path,cmdline,uid,parent,start_time) VALUES (?,?,?,?,?,?,?,?,?)",
                            params![
                                dataset_id,
                                r.machine_id,
                                i64::from(r.pid),
                                r.name,
                                r.path,
                                cmdline,
                                i64::from(r.uid),
                                i64::from(r.ppid),
                                start_time,
                            ],
                        )?;
                        inserted += 1;
                    }
                    Err(e) => {
                        if parse_errors.len() < APPEND_TEST_MAX_ERRORS_RETURNED {
                            parse_errors.push(format!("line {}: {}", line_no, e));
                        }
                    }
                }
            } else if route == "file" {
                match serde_json::from_str::<RawFileEntry>(t) {
                    Ok(mut r) => {
                        if r.machine_id.is_empty() {
                            r.machine_id = default_machine.to_string();
                        }
                        if r.path.is_empty() {
                            if parse_errors.len() < APPEND_TEST_MAX_ERRORS_RETURNED {
                                parse_errors.push(format!(
                                    "line {}: file row needs a non-empty path",
                                    line_no
                                ));
                            }
                            continue;
                        }
                        let (directory, filename) = split_path_directory_filename(&r.path);
                        let mtime = optional_epoch_seconds(&r.mtime);
                        let atime = optional_epoch_seconds(&r.timestamp);
                        let inv =
                            file_inv_checksum_for_row(filename.as_str(), r.permissions.as_deref());
                        tx.execute(
                            r#"INSERT INTO "file" (dataset_id,machine_id,path,directory,filename,uid,mode,size,mtime,atime,inv_checksum) VALUES (?,?,?,?,?,?,?,?,?,?,?)"#,
                            params![
                                dataset_id,
                                r.machine_id,
                                r.path,
                                directory,
                                filename,
                                i64::from(r.uid),
                                r.permissions,
                                r.size.map(|u| u as i64),
                                mtime,
                                atime,
                                inv,
                            ],
                        )?;
                        inserted += 1;
                    }
                    Err(e) => {
                        if parse_errors.len() < APPEND_TEST_MAX_ERRORS_RETURNED {
                            parse_errors.push(format!("line {}: {}", line_no, e));
                        }
                    }
                }
            } else if route == "mixed" {
                if let Ok(r) = parse_jsonl_process_line(t, default_machine) {
                    let cmdline = full_cmdline(&r);
                    let start_time = optional_epoch_seconds(&r.timestamp);
                    tx.execute(
                        "INSERT INTO processes (dataset_id,machine_id,pid,name,path,cmdline,uid,parent,start_time) VALUES (?,?,?,?,?,?,?,?,?)",
                        params![
                            dataset_id,
                            r.machine_id,
                            i64::from(r.pid),
                            r.name,
                            r.path,
                            cmdline,
                            i64::from(r.uid),
                            i64::from(r.ppid),
                            start_time,
                        ],
                    )?;
                    inserted += 1;
                } else if let Ok(mut r) = serde_json::from_str::<RawFileEntry>(t) {
                    if r.machine_id.is_empty() {
                        r.machine_id = default_machine.to_string();
                    }
                    if r.path.is_empty() {
                        if parse_errors.len() < APPEND_TEST_MAX_ERRORS_RETURNED {
                            parse_errors.push(format!(
                                "line {}: file row needs a non-empty path",
                                line_no
                            ));
                        }
                        continue;
                    }
                    let (directory, filename) = split_path_directory_filename(&r.path);
                    let mtime = optional_epoch_seconds(&r.mtime);
                    let atime = optional_epoch_seconds(&r.timestamp);
                    let inv =
                        file_inv_checksum_for_row(filename.as_str(), r.permissions.as_deref());
                    tx.execute(
                        r#"INSERT INTO "file" (dataset_id,machine_id,path,directory,filename,uid,mode,size,mtime,atime,inv_checksum) VALUES (?,?,?,?,?,?,?,?,?,?,?)"#,
                        params![
                            dataset_id,
                            r.machine_id,
                            r.path,
                            directory,
                            filename,
                            i64::from(r.uid),
                            r.permissions,
                            r.size.map(|u| u as i64),
                            mtime,
                            atime,
                            inv,
                        ],
                    )?;
                    inserted += 1;
                } else if parse_errors.len() < APPEND_TEST_MAX_ERRORS_RETURNED {
                    parse_errors.push(format!(
                        "line {}: not valid process or file inventory JSON",
                        line_no
                    ));
                }
            } else {
                return Err(format!("unsupported dataset kind for test append: {}", kind).into());
            }
        }
        tx.commit()?;
        Ok(AppendTestSummary {
            inserted,
            skipped_blank_lines,
            parse_errors,
        })
    }

    /// Distinct `machine_id` values for the given ingested `dataset_id`s, across process and file events.
    pub fn distinct_machine_ids_for_datasets(
        &self,
        dataset_ids: &[String],
    ) -> Result<Vec<String>, Box<dyn Error>> {
        if dataset_ids.is_empty() {
            return Ok(vec![]);
        }
        let conn = self.conn()?;
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for ds in dataset_ids {
            let mut stmt = conn
                .prepare("SELECT DISTINCT machine_id FROM processes WHERE dataset_id = ?")?;
            for row in stmt.query_map(params![ds], |r| r.get::<_, String>(0))? {
                let mid = row?;
                if !mid.is_empty() {
                    seen.insert(mid);
                }
            }
        }
        for ds in dataset_ids {
            let mut stmt =
                conn.prepare(r#"SELECT DISTINCT machine_id FROM "file" WHERE dataset_id = ?"#)?;
            for row in stmt.query_map(params![ds], |r| r.get::<_, String>(0))? {
                let mid = row?;
                if !mid.is_empty() {
                    seen.insert(mid);
                }
            }
        }
        Ok(seen.into_iter().collect())
    }

    /// Create tables and seed one profile when empty (`legacy_run_config` migrates from `db.json`).
    pub fn ensure_detection_configs_initialized(
        &self,
        legacy_run_config: Option<DetectionConfig>,
    ) -> Result<(), Box<dyn Error>> {
        let conn = self.conn()?;
        migrate_detection_config_tables(&conn)?;
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM detection_configs", [], |r| r.get(0))?;
        if count == 0 {
            let id = Uuid::new_v4().to_string();
            let now = Utc::now().to_rfc3339();
            let cfg = legacy_run_config.unwrap_or_else(DetectionConfig::default);
            let json = serde_json::to_string(&cfg)?;
            conn.execute(
                "INSERT INTO detection_configs (id,name,config_json,created_at,updated_at) VALUES (?,?,?,?,?)",
                params![id, "Default", json, now, now],
            )?;
            conn.execute(
                "INSERT OR REPLACE INTO platform_settings (key,value) VALUES (?,?)",
                params![PLATFORM_SETTING_SELECTED_DETECTION_CONFIG, id],
            )?;
            return Ok(());
        }
        repair_selected_detection_config_pointer(&conn)?;
        Ok(())
    }

    pub fn get_selected_detection_config(&self) -> Result<Option<DetectionConfig>, Box<dyn Error>> {
        let conn = self.conn()?;
        let sel: Option<String> = conn
            .query_row(
                "SELECT value FROM platform_settings WHERE key = ?",
                params![PLATFORM_SETTING_SELECTED_DETECTION_CONFIG],
                |r| r.get(0),
            )
            .optional()?;
        let Some(id) = sel else {
            return Ok(None);
        };
        self.get_detection_config_by_id(&id)
    }

    pub fn get_detection_config_by_id(&self, id: &str) -> Result<Option<DetectionConfig>, Box<dyn Error>> {
        let conn = self.conn()?;
        let row: Option<String> = conn
            .query_row(
                "SELECT config_json FROM detection_configs WHERE id = ?",
                params![id],
                |r| r.get(0),
            )
            .optional()?;
        match row {
            None => Ok(None),
            Some(j) => Ok(Some(serde_json::from_str(&j)?)),
        }
    }

    pub fn get_detection_config_name(&self, id: &str) -> Result<Option<String>, Box<dyn Error>> {
        let conn = self.conn()?;
        let row: Option<String> = conn
            .query_row(
                "SELECT name FROM detection_configs WHERE id = ?",
                params![id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(row)
    }

    pub fn update_selected_detection_config_json(&self, cfg: &DetectionConfig) -> Result<(), Box<dyn Error>> {
        let conn = self.conn()?;
        let sel: String = conn.query_row(
            "SELECT value FROM platform_settings WHERE key = ?",
            params![PLATFORM_SETTING_SELECTED_DETECTION_CONFIG],
            |r| r.get(0),
        )?;
        let json = serde_json::to_string(cfg)?;
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE detection_configs SET config_json = ?, updated_at = ? WHERE id = ?",
            params![json, now, sel],
        )?;
        Ok(())
    }

    pub fn list_detection_config_profiles(&self) -> Result<Vec<DetectionConfigProfileMeta>, Box<dyn Error>> {
        let conn = self.conn()?;
        repair_selected_detection_config_pointer(&conn)?;
        let selected: Option<String> = conn
            .query_row(
                "SELECT value FROM platform_settings WHERE key = ?",
                params![PLATFORM_SETTING_SELECTED_DETECTION_CONFIG],
                |r| r.get(0),
            )
            .optional()?;
        let mut stmt = conn.prepare(
            "SELECT id, name, created_at, updated_at FROM detection_configs ORDER BY datetime(created_at) ASC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(DetectionConfigProfileMeta {
                id: r.get(0)?,
                name: r.get(1)?,
                created_at: r.get(2)?,
                updated_at: r.get(3)?,
                is_selected: false,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            let mut meta = row?;
            meta.is_selected = selected.as_ref().map(|s| s == &meta.id).unwrap_or(false);
            out.push(meta);
        }
        Ok(out)
    }

    pub fn insert_detection_config(&self, name: &str, cfg: &DetectionConfig) -> Result<String, Box<dyn Error>> {
        let conn = self.conn()?;
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        let json = serde_json::to_string(cfg)?;
        conn.execute(
            "INSERT INTO detection_configs (id,name,config_json,created_at,updated_at) VALUES (?,?,?,?,?)",
            params![id, name, json, now, now],
        )?;
        Ok(id)
    }

    pub fn update_detection_config_row(
        &self,
        id: &str,
        name: Option<&str>,
        cfg: Option<&DetectionConfig>,
    ) -> Result<(), Box<dyn Error>> {
        let conn = self.conn()?;
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM detection_configs WHERE id = ?",
            params![id],
            |r| r.get(0),
        )?;
        if n == 0 {
            return Err("detection config not found".into());
        }
        let now = Utc::now().to_rfc3339();
        if let Some(cfg) = cfg {
            let json = serde_json::to_string(cfg)?;
            if let Some(nm) = name {
                conn.execute(
                    "UPDATE detection_configs SET name = ?, config_json = ?, updated_at = ? WHERE id = ?",
                    params![nm, json, now, id],
                )?;
            } else {
                conn.execute(
                    "UPDATE detection_configs SET config_json = ?, updated_at = ? WHERE id = ?",
                    params![json, now, id],
                )?;
            }
        } else if let Some(nm) = name {
            conn.execute(
                "UPDATE detection_configs SET name = ?, updated_at = ? WHERE id = ?",
                params![nm, now, id],
            )?;
        }
        Ok(())
    }

    pub fn delete_detection_config_row(&self, id: &str) -> Result<(), Box<dyn Error>> {
        let conn = self.conn()?;
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM detection_configs", [], |r| r.get(0))?;
        if count <= 1 {
            return Err("cannot delete the last detection configuration".into());
        }
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM detection_configs WHERE id = ?",
            params![id],
            |r| r.get(0),
        )?;
        if n == 0 {
            return Err("detection config not found".into());
        }
        let selected: Option<String> = conn
            .query_row(
                "SELECT value FROM platform_settings WHERE key = ?",
                params![PLATFORM_SETTING_SELECTED_DETECTION_CONFIG],
                |r| r.get(0),
            )
            .optional()?;
        if selected.as_deref() == Some(id) {
            let other: String = conn.query_row(
                "SELECT id FROM detection_configs WHERE id != ? ORDER BY datetime(created_at) ASC LIMIT 1",
                params![id],
                |r| r.get(0),
            )?;
            conn.execute(
                "INSERT OR REPLACE INTO platform_settings (key,value) VALUES (?,?)",
                params![PLATFORM_SETTING_SELECTED_DETECTION_CONFIG, other],
            )?;
        }
        conn.execute("DELETE FROM detection_configs WHERE id = ?", params![id])?;
        Ok(())
    }

    pub fn set_selected_detection_config_id(&self, id: &str) -> Result<(), Box<dyn Error>> {
        let conn = self.conn()?;
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM detection_configs WHERE id = ?",
            params![id],
            |r| r.get(0),
        )?;
        if n == 0 {
            return Err("detection config not found".into());
        }
        conn.execute(
            "INSERT OR REPLACE INTO platform_settings (key,value) VALUES (?,?)",
            params![PLATFORM_SETTING_SELECTED_DETECTION_CONFIG, id],
        )?;
        Ok(())
    }

    pub fn get_selected_detection_config_id(&self) -> Result<Option<String>, Box<dyn Error>> {
        let conn = self.conn()?;
        repair_selected_detection_config_pointer(&conn)?;
        let r: Option<String> = conn
            .query_row(
                "SELECT value FROM platform_settings WHERE key = ?",
                params![PLATFORM_SETTING_SELECTED_DETECTION_CONFIG],
                |r| r.get(0),
            )
            .optional()?;
        Ok(r)
    }
}

fn migrate_detection_config_tables(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS detection_configs (
          id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          config_json TEXT NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS platform_settings (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        );
    "#,
    )?;
    Ok(())
}

fn repair_selected_detection_config_pointer(conn: &Connection) -> Result<(), Box<dyn Error>> {
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM detection_configs", [], |r| r.get(0))?;
    if count == 0 {
        return Ok(());
    }
    let sel: Option<String> = conn
        .query_row(
            "SELECT value FROM platform_settings WHERE key = ?",
            params![PLATFORM_SETTING_SELECTED_DETECTION_CONFIG],
            |r| r.get(0),
        )
        .optional()?;
    let needs_fix = match &sel {
        None => true,
        Some(id) => {
            let n: i64 = conn.query_row(
                "SELECT COUNT(*) FROM detection_configs WHERE id = ?",
                params![id],
                |r| r.get(0),
            )?;
            n == 0
        }
    };
    if !needs_fix {
        return Ok(());
    }
    let fallback: String = conn.query_row(
        "SELECT id FROM detection_configs ORDER BY datetime(created_at) ASC LIMIT 1",
        [],
        |r| r.get(0),
    )?;
    conn.execute(
        "INSERT OR REPLACE INTO platform_settings (key,value) VALUES (?,?)",
        params![PLATFORM_SETTING_SELECTED_DETECTION_CONFIG, fallback],
    )?;
    Ok(())
}

/// Stable inventory fingerprint for SQLite (`file` row): **basename + permissions (`mode`) only**.
/// Omits path, uid, size, and timestamps so the same logical file aligns across datasets when
/// collection metadata differs.
///
/// Stored at ingest as `inv_checksum`; must stay aligned with run-load SQL filtering.
pub(crate) fn file_inv_checksum_for_row(filename: &str, mode: Option<&str>) -> i64 {
    let mut h = DefaultHasher::new();
    filename.hash(&mut h);
    mode.unwrap_or("").hash(&mut h);
    i64::from_ne_bytes(h.finish().to_ne_bytes())
}

fn push_file_row_into_grouped(
    grouped: &mut HashMap<String, Vec<RawFileEntry>>,
    machine_id: String,
    path: String,
    uid: i64,
    permissions: Option<String>,
    size: Option<i64>,
    mtime: Option<i64>,
    atime: Option<i64>,
) {
    let entry = RawFileEntry {
        machine_id: machine_id.clone(),
        path,
        uid: clamp_u32_from_i64(uid),
        timestamp: atime.map(|s| s.to_string()),
        mtime: mtime.map(|s| s.to_string()),
        permissions,
        owner: None,
        group: None,
        size: size.and_then(|s| if s >= 0 { Some(s as u64) } else { None }),
    };
    grouped.entry(machine_id).or_default().push(entry);
}

fn query_grouped_file_rows_simple(
    conn: &Connection,
    dataset_id: &str,
) -> Result<HashMap<String, Vec<RawFileEntry>>, Box<dyn Error>> {
    let mut grouped = HashMap::new();
    let mut stmt = conn.prepare(
        r#"SELECT machine_id, path, uid, mode, size, mtime, atime FROM "file" WHERE dataset_id = ?"#,
    )?;
    let mut rows = stmt.query(params![dataset_id])?;
    while let Some(row) = rows.next()? {
        push_file_row_into_grouped(
            &mut grouped,
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
            row.get(6)?,
        );
    }
    Ok(grouped)
}

fn query_grouped_file_rows_exclude_universal_one_ds(
    conn: &Connection,
    dataset_id: &str,
) -> Result<HashMap<String, Vec<RawFileEntry>>, Box<dyn Error>> {
    let mut grouped = HashMap::new();
    let sql = r#"
SELECT machine_id, path, uid, mode, size, mtime, atime FROM "file"
WHERE dataset_id = ?1
AND inv_checksum NOT IN (
  SELECT inv_checksum FROM "file"
  WHERE dataset_id = ?1
  GROUP BY inv_checksum
  HAVING COUNT(DISTINCT machine_id) = (SELECT COUNT(DISTINCT machine_id) FROM "file" WHERE dataset_id = ?1)
)"#;
    let mut stmt = conn.prepare(sql)?;
    let mut rows = stmt.query(params![dataset_id])?;
    while let Some(row) = rows.next()? {
        push_file_row_into_grouped(
            &mut grouped,
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
            row.get(6)?,
        );
    }
    Ok(grouped)
}

fn query_grouped_file_rows_exclude_common_multi(
    conn: &Connection,
    dataset_id: &str,
    run_ds: &[&str],
) -> Result<HashMap<String, Vec<RawFileEntry>>, Box<dyn Error>> {
    let n_ds = run_ds.len() as i64;
    let ph = run_ds.iter().map(|_| "?").collect::<Vec<_>>().join(",");
    let sql = format!(
        r#"SELECT machine_id, path, uid, mode, size, mtime, atime FROM "file"
WHERE dataset_id = ? AND inv_checksum NOT IN (
  SELECT inv_checksum FROM "file"
  WHERE dataset_id IN ({ph})
  GROUP BY inv_checksum
  HAVING COUNT(DISTINCT dataset_id) = ?
)"#,
        ph = ph
    );
    let mut grouped = HashMap::new();
    let mut stmt = conn.prepare(&sql)?;
    let mut bind: Vec<&dyn rusqlite::ToSql> = Vec::with_capacity(2 + run_ds.len());
    bind.push(&dataset_id);
    for id in run_ds {
        bind.push(id);
    }
    bind.push(&n_ds);
    let mut rows = stmt.query(bind.as_slice())?;
    while let Some(row) = rows.next()? {
        push_file_row_into_grouped(
            &mut grouped,
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
            row.get(6)?,
        );
    }
    Ok(grouped)
}

/// True when `file` exists but predates the required `inv_checksum` column — table is dropped and
/// recreated from [`CREATE_FILE_TABLE`] (file rows must be re-ingested).
fn file_table_missing_inv_checksum(conn: &Connection) -> Result<bool, Box<dyn Error>> {
    let exists: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='file'",
        [],
        |r| r.get(0),
    )?;
    if exists == 0 {
        return Ok(false);
    }
    let col: i64 = conn.query_row(
        r#"SELECT COUNT(*) FROM pragma_table_info('file') WHERE name='inv_checksum'"#,
        [],
        |r| r.get(0),
    )?;
    Ok(col == 0)
}

fn migrate_osquery_event_tables(conn: &Connection) -> Result<(), Box<dyn Error>> {
    let uv: i32 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    conn.execute_batch(CREATE_PROCESSES_TABLE)?;
    conn.execute("DROP TABLE IF EXISTS process_events", [])?;
    conn.execute("DROP TABLE IF EXISTS file_events", [])?;
    if file_table_missing_inv_checksum(conn)? {
        conn.execute(r#"DROP TABLE IF EXISTS "file""#, [])?;
    } else if uv > 0 && uv < MIN_USER_VERSION_INV_CHECKSUM_FILENAME_MODE {
        conn.execute(r#"DROP TABLE IF EXISTS "file""#, [])?;
    }
    conn.execute_batch(CREATE_FILE_TABLE)?;
    conn.execute(
        &format!("PRAGMA user_version = {}", EVENT_SCHEMA_VERSION),
        [],
    )?;
    Ok(())
}

fn query_samples_as_json(
    conn: &Connection,
    table_sql_fragment: &str,
    dataset_id: &str,
    limit: i64,
) -> Result<Vec<serde_json::Value>, Box<dyn Error>> {
    let sql = format!(
        "SELECT * FROM {} WHERE dataset_id = ? LIMIT ?",
        table_sql_fragment
    );
    let mut stmt = conn.prepare(&sql)?;
    let n = stmt.column_count();
    let names: Vec<String> = (0..n)
        .map(|i| {
            stmt.column_name(i)
                .map(|s| s.to_string())
                .map_err(|e| Box::new(e) as Box<dyn Error>)
        })
        .collect::<Result<_, Box<dyn Error>>>()?;
    let mut out = Vec::new();
    let mut rows = stmt.query(params![dataset_id, limit])?;
    while let Some(row) = rows.next()? {
        let mut m = serde_json::Map::new();
        for i in 0..n {
            let v: SqlValue = row.get(i)?;
            m.insert(names[i].clone(), sqlite_value_to_json(v));
        }
        out.push(serde_json::Value::Object(m));
    }
    Ok(out)
}

fn sqlite_value_to_json(v: SqlValue) -> serde_json::Value {
    match v {
        SqlValue::Null => serde_json::Value::Null,
        SqlValue::Integer(i) => serde_json::json!(i),
        SqlValue::Real(f) => serde_json::Number::from_f64(f)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        SqlValue::Text(s) => serde_json::Value::String(s),
        SqlValue::Blob(_) => serde_json::Value::Null,
    }
}

fn full_cmdline(r: &RawLogEntry) -> String {
    let path = r.path.trim();
    let args = r.args.trim();
    if !path.is_empty() {
        if args.is_empty() {
            path.to_string()
        } else {
            format!("{path} {args}")
        }
    } else if !args.is_empty() {
        args.to_string()
    } else {
        r.name.clone()
    }
}

fn split_path_directory_filename(path: &str) -> (String, String) {
    let p = Path::new(path);
    let filename = p
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string();
    let directory = p
        .parent()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string();
    (directory, filename)
}

fn optional_epoch_seconds(ts: &Option<String>) -> Option<i64> {
    ts.as_deref().and_then(epoch_seconds_from_text)
}

/// Single SQLite `processes` row, used to surface the actual ingested process behind a fleet finding.
#[derive(Debug, Clone, Serialize)]
pub struct ProcessRowExample {
    pub dataset_id: String,
    pub machine_id: String,
    pub pid: i64,
    pub parent: i64,
    pub uid: i64,
    pub name: String,
    pub path: String,
    pub cmdline: String,
    /// Epoch seconds when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time: Option<i64>,
}

fn query_process_row_example_optional(
    stmt: &mut rusqlite::Statement<'_>,
    p: impl rusqlite::Params,
) -> Result<Option<ProcessRowExample>, Box<dyn Error>> {
    let mut rows = stmt.query(p)?;
    if let Some(row) = rows.next()? {
        Ok(Some(ProcessRowExample {
            dataset_id: row.get(0)?,
            machine_id: row.get(1)?,
            pid: row.get(2)?,
            parent: row.get(3)?,
            uid: row.get(4)?,
            name: row.get(5)?,
            path: row.get(6)?,
            cmdline: row.get(7)?,
            start_time: row.get(8)?,
        }))
    } else {
        Ok(None)
    }
}

fn clamp_u32_from_i64(v: i64) -> u32 {
    if v < 0 {
        0
    } else if v > u32::MAX as i64 {
        u32::MAX
    } else {
        v as u32
    }
}

fn epoch_seconds_from_text(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Ok(n) = s.parse::<i64>() {
        return Some(if n > 9_999_999_999 { n / 1000 } else { n });
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.timestamp());
    }
    // ISO 8601 local / no explicit offset (common in log exports, e.g. 2026-04-17T20:34:00)
    for fmt in [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S",
    ] {
        if let Ok(na) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(DateTime::<Utc>::from_naive_utc_and_offset(na, Utc).timestamp());
        }
    }
    if let Ok(d) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        if let Some(na) = d.and_hms_opt(0, 0, 0) {
            return Some(DateTime::<Utc>::from_naive_utc_and_offset(na, Utc).timestamp());
        }
    }
    None
}

fn is_jsonl_ndjson_source(ds: &DatasetRecord) -> bool {
    ds.source_path
        .to_ascii_lowercase()
        .ends_with(".jsonl")
        || ds.format.eq_ignore_ascii_case("jsonl")
}

fn effective_ingest_kind_str(
    process_event_count: u64,
    file_event_count: u64,
    declared: DatasetKind,
) -> &'static str {
    match (process_event_count, file_event_count) {
        (p, f) if p > 0 && f > 0 => "mixed",
        (p, _) if p > 0 => "process",
        (_, f) if f > 0 => "file",
        _ => match declared {
            DatasetKind::Process => "process",
            DatasetKind::File => "file",
            DatasetKind::Mixed => "mixed",
        },
    }
}

fn ingest_jsonl_process_and_file_tables(
    tx: &rusqlite::Transaction<'_>,
    ds: &DatasetRecord,
) -> Result<(), Box<dyn Error>> {
    let fallback = default_machine_fallback_for_source_file(
        ds.source_path.as_str(),
        ds.ingest_default_machine_id.as_deref(),
    );
    let mut stmt_p = tx.prepare(
        "INSERT INTO processes (dataset_id,machine_id,pid,name,path,cmdline,uid,parent,start_time) VALUES (?,?,?,?,?,?,?,?,?)",
    )?;
    let mut stmt_f = tx.prepare(
        r#"INSERT INTO "file" (dataset_id,machine_id,path,directory,filename,uid,mode,size,mtime,atime,inv_checksum) VALUES (?,?,?,?,?,?,?,?,?,?,?)"#,
    )?;

    let f = File::open(&ds.source_path)?;
    for line in BufReader::new(f).lines() {
        let line = line?;
        let t = line.trim();
        if t.is_empty() || t.starts_with("//") || t.starts_with('#') {
            continue;
        }
        if let Ok(r) = parse_jsonl_process_line(t, &fallback) {
            let cmdline = full_cmdline(&r);
            let start_time = optional_epoch_seconds(&r.timestamp);
            stmt_p.execute(params![
                ds.id,
                r.machine_id,
                i64::from(r.pid),
                r.name,
                r.path,
                cmdline,
                i64::from(r.uid),
                i64::from(r.ppid),
                start_time,
            ])?;
            continue;
        }
        let mut fe: RawFileEntry = match serde_json::from_str(t) {
            Ok(e) => e,
            Err(_) => continue,
        };
        if fe.machine_id.is_empty() {
            fe.machine_id = fallback.clone();
        }
        if fe.path.trim().is_empty() {
            continue;
        }
        let (directory, filename) = split_path_directory_filename(&fe.path);
        let mtime = optional_epoch_seconds(&fe.mtime);
        let atime = optional_epoch_seconds(&fe.timestamp);
        let inv = file_inv_checksum_for_row(filename.as_str(), fe.permissions.as_deref());
        stmt_f.execute(params![
            ds.id,
            fe.machine_id,
            fe.path,
            directory,
            filename,
            i64::from(fe.uid),
            fe.permissions,
            fe.size.map(|u| u as i64),
            mtime,
            atime,
            inv,
        ])?;
    }
    Ok(())
}

fn read_process_rows(
    path: &str,
    ingest_default_machine_id: Option<&str>,
) -> Result<Vec<RawLogEntry>, Box<dyn Error>> {
    if path.ends_with(".csv") {
        let mut rdr = csv::Reader::from_path(path)?;
        let mut out = Vec::new();
        for row in rdr.deserialize::<RawLogEntry>() {
            out.push(row?);
        }
        return Ok(out);
    }
    if path.ends_with(".json") {
        let s = std::fs::read_to_string(path)?;
        return Ok(parse_json_logs(&s)?);
    }
    if path.ends_with(".jsonl") {
        let fallback = default_machine_fallback_for_source_file(path, ingest_default_machine_id);
        let mut out = Vec::new();
        let f = File::open(path)?;
        for line in BufReader::new(f).lines() {
            let line = line?;
            let t = line.trim();
            if t.is_empty() {
                continue;
            }
            if let Ok(r) = parse_jsonl_process_line(t, &fallback) {
                out.push(r);
            }
        }
        return Ok(out);
    }
    Err("unsupported process format".into())
}

fn read_file_rows(
    path: &str,
    ingest_default_machine_id: Option<&str>,
) -> Result<Vec<RawFileEntry>, Box<dyn Error>> {
    if path.ends_with(".csv") {
        let mut rdr = csv::Reader::from_path(path)?;
        let mut out = Vec::new();
        for row in rdr.deserialize::<RawFileEntry>() {
            out.push(row?);
        }
        return Ok(out);
    }
    if path.ends_with(".json") {
        let s = std::fs::read_to_string(path)?;
        let fallback = default_machine_fallback_for_source_file(path, ingest_default_machine_id);
        return Ok(parse_files_json_logs(&s, &fallback)?);
    }
    if path.ends_with(".jsonl") {
        let fallback = default_machine_fallback_for_source_file(path, ingest_default_machine_id);
        let mut out = Vec::new();
        let f = File::open(path)?;
        for line in BufReader::new(f).lines() {
            let line = line?;
            let t = line.trim();
            if t.is_empty() {
                continue;
            }
            let v: serde_json::Value = match serde_json::from_str(t) {
                Ok(v) => v,
                Err(e) => {
                    log::debug!("JSONL file line skipped: {}", e);
                    continue;
                }
            };
            if classify_json_line_shape(&v) == JsonLineShape::Process {
                log::debug!("JSONL line is process-shaped; not ingesting into file table (use a process dataset or fix mixed logs)");
                continue;
            }
            match serde_json::from_value::<RawFileEntry>(v) {
                Ok(mut e) => {
                    if e.machine_id.is_empty() {
                        e.machine_id = fallback.clone();
                    }
                    out.push(e);
                }
                Err(e) => log::debug!("JSONL file line skipped: {}", e),
            }
        }
        return Ok(out);
    }
    Err("unsupported file format".into())
}

#[cfg(test)]
mod ingest_policy_tests {
    use super::EventDb;
    use crate::platform::{DatasetKind, DatasetRecord};
    use std::io::Write;

    #[test]
    fn ingest_stores_kernel_thread_line_without_detection_config() {
        let mut tmp = tempfile::NamedTempFile::with_suffix(".jsonl").unwrap();
        writeln!(
            tmp,
            r#"{{"timestamp": "2026-04-27T00:10:05", "event_type": "process", "user": "0", "command": "[kworker/0:0H]", "pid": 5, "ppid": 2}}"#
        )
        .unwrap();
        tmp.flush().unwrap();
        let sql = tempfile::NamedTempFile::new().unwrap();
        let db = EventDb::new(sql.path().to_str().unwrap()).unwrap();
        let rec = DatasetRecord {
            id: "ds-ingest-1".to_string(),
            name: "t".to_string(),
            source_path: tmp.path().to_str().unwrap().to_string(),
            format: "jsonl".to_string(),
            kind: DatasetKind::Process,
            tags: vec![],
            schema_profile: "osquery-5.22.1".to_string(),
            imported_at: "2026-01-01T00:00:00Z".to_string(),
            ingest_default_machine_id: None,
        };
        let s = db.ingest_dataset(&rec).unwrap();
        assert_eq!(s.process_event_count, 1);
        assert_eq!(s.file_event_count, 0);
    }

    #[test]
    fn jsonl_mixed_ingest_fills_both_tables_and_summary_kind() {
        let mut tmp = tempfile::NamedTempFile::with_suffix(".jsonl").unwrap();
        writeln!(
            tmp,
            r#"{{"command":"/bin/sh","pid":1,"parent":0,"machine_id":"h1"}}"#
        )
        .unwrap();
        writeln!(
            tmp,
            r#"{{"file_path":"/var/log/a.log","size":10,"permissions":"0644","machine_id":"h1"}}"#
        )
        .unwrap();
        tmp.flush().unwrap();
        let sql = tempfile::NamedTempFile::new().unwrap();
        let db = EventDb::new(sql.path().to_str().unwrap()).unwrap();
        let rec = DatasetRecord {
            id: "ds-mixed-1".to_string(),
            name: "m".to_string(),
            source_path: tmp.path().to_str().unwrap().to_string(),
            format: "jsonl".to_string(),
            kind: DatasetKind::Process,
            tags: vec![],
            schema_profile: "osquery-5.22.1".to_string(),
            imported_at: "2026-01-01T00:00:00Z".to_string(),
            ingest_default_machine_id: None,
        };
        let s = db.ingest_dataset(&rec).unwrap();
        assert_eq!(s.kind, "mixed");
        assert_eq!(s.process_event_count, 1);
        assert_eq!(s.file_event_count, 1);
    }
}

#[cfg(test)]
mod file_ingest_tests {
    use super::epoch_seconds_from_text;
    use crate::types::RawFileEntry;

    #[test]
    fn epoch_parses_iso_local_t_separator() {
        assert!(epoch_seconds_from_text("2026-04-17T20:34:00").is_some());
        assert!(epoch_seconds_from_text("2026-04-27T00:10:05").is_some());
    }

    #[test]
    fn file_json_sample_deserializes_like_ingest() {
        const JSON: &str = r#"{"timestamp": "2026-04-27T00:10:05", "date": "2026-04-17T20:34:00", "event_type": "file_information", "permissions": "-rw-r-----.", "owner": "root", "group": "root", "size": 221295, "file_path": "/data/var/dlogs/config_rest_server.log"}"#;
        let e: RawFileEntry = serde_json::from_str(JSON).expect("raw file row");
        assert_eq!(e.path, "/data/var/dlogs/config_rest_server.log");
        assert_eq!(e.size, Some(221295));
        assert_eq!(e.permissions.as_deref(), Some("-rw-r-----."));
        assert_eq!(e.mtime.as_deref(), Some("2026-04-17T20:34:00"));
        assert_eq!(e.timestamp.as_deref(), Some("2026-04-27T00:10:05"));
    }
}

#[cfg(test)]
mod file_checksum_sql_tests {
    use super::{file_inv_checksum_for_row, EventDb};
    use rusqlite::params;

    fn insert_file_row(
        conn: &rusqlite::Connection,
        ds: &str,
        host: &str,
        path: &str,
        uid: i64,
        mode: &str,
        size: i64,
    ) {
        let (directory, filename) = super::split_path_directory_filename(path);
        let mtime = Option::<i64>::None;
        let atime = Option::<i64>::None;
        let inv = file_inv_checksum_for_row(filename.as_str(), Some(mode));
        conn.execute(
            r#"INSERT INTO "file" (dataset_id,machine_id,path,directory,filename,uid,mode,size,mtime,atime,inv_checksum) VALUES (?,?,?,?,?,?,?,?,?,?,?)"#,
            params![
                ds,
                host,
                path,
                directory,
                filename,
                uid,
                mode,
                size,
                mtime,
                atime,
                inv
            ],
        )
        .unwrap();
    }

    #[test]
    fn universal_checksum_filtered_for_single_file_dataset_run() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("chk.db");
        let ps = p.to_str().unwrap();
        let _edb_init = EventDb::new(ps).unwrap();
        let conn = rusqlite::Connection::open(ps).unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO datasets (id,name,source_path,format,kind,schema_profile,imported_at) VALUES (?,?,?,?,?,?,?)",
            params!["ds1", "n", "x", "csv", "file", "p", "t"],
        )
        .unwrap();

        insert_file_row(&conn, "ds1", "h1", "/etc/same", 0, "-rw-r--r--", 100);
        insert_file_row(&conn, "ds1", "h2", "/etc/same", 0, "-rw-r--r--", 100);
        insert_file_row(&conn, "ds1", "h1", "/home/u/x", 1000, "-rw-r--r--", 200);

        let db = EventDb::new(ps).unwrap();
        let total_all: usize = db
            .group_file_entries_by_machine("ds1")
            .unwrap()
            .values()
            .map(|v| v.len())
            .sum();
        assert_eq!(total_all, 3);

        let filtered = db
            .group_file_entries_by_machine_for_run("ds1", &["ds1".to_string()], true)
            .unwrap();
        let total_f: usize = filtered.values().map(|v| v.len()).sum();
        assert_eq!(total_f, 1);
        assert_eq!(filtered.get("h1").map(|v| v.len()), Some(1));
        assert_eq!(filtered.get("h2").map(|v| v.len()).unwrap_or(0), 0);
    }

    #[test]
    fn checksum_present_in_all_run_file_datasets_is_filtered() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("chk2.db");
        let ps = p.to_str().unwrap();
        let _edb_init = EventDb::new(ps).unwrap();
        let conn = rusqlite::Connection::open(ps).unwrap();
        for (dsid, name) in [("dsA", "a"), ("dsB", "b")] {
            conn.execute(
                "INSERT OR REPLACE INTO datasets (id,name,source_path,format,kind,schema_profile,imported_at) VALUES (?,?,?,?,?,?,?)",
                params![dsid, name, "x", "csv", "file", "p", "t"],
            )
            .unwrap();
        }

        insert_file_row(&conn, "dsA", "h1", "/opt/shared_marker", 0, "-rw-r--r--", 42);
        insert_file_row(&conn, "dsB", "h9", "/opt/shared_marker", 0, "-rw-r--r--", 42);
        insert_file_row(&conn, "dsA", "h1", "/only/on/a", 0, "-rw-r--r--", 99);

        let db = EventDb::new(ps).unwrap();
        let filtered = db
            .group_file_entries_by_machine_for_run(
                "dsA",
                &["dsA".to_string(), "dsB".to_string()],
                true,
            )
            .unwrap();
        let paths: Vec<&str> = filtered
            .values()
            .flat_map(|v| v.iter().map(|e| e.path.as_str()))
            .collect();
        assert!(
            paths.iter().any(|p| *p == "/only/on/a"),
            "dataset-local row kept: {:?}",
            paths
        );
        assert!(
            !paths.iter().any(|p| *p == "/opt/shared_marker"),
            "cross-dataset common checksum dropped: {:?}",
            paths
        );
    }
}
