//! SQLite DDL aligned with osquery **5.22.1** table specs:
//! - [`processes`](https://osquery.io/schema/5.22.1/#processes) — `specs/processes.table` @ tag 5.22.1
//! - [`file`](https://osquery.io/schema/5.22.1/#file) — `specs/utility/file.table` @ tag 5.22.1
//!
//! Each table adds IronSift columns `id`, `dataset_id`, and `machine_id` (not present in osquery) for
//! multi-dataset storage; all osquery-named columns match the upstream schema.

/// Base + platform-extended columns from osquery `processes` (Windows, Darwin, Linux extensions).
pub const CREATE_PROCESSES_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS processes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  dataset_id TEXT NOT NULL,
  machine_id TEXT NOT NULL,
  pid INTEGER,
  name TEXT,
  path TEXT,
  cmdline TEXT,
  state TEXT,
  cwd TEXT,
  root TEXT,
  uid INTEGER,
  gid INTEGER,
  euid INTEGER,
  egid INTEGER,
  suid INTEGER,
  sgid INTEGER,
  on_disk INTEGER,
  wired_size INTEGER,
  resident_size INTEGER,
  total_size INTEGER,
  user_time INTEGER,
  system_time INTEGER,
  disk_bytes_read INTEGER,
  disk_bytes_written INTEGER,
  start_time INTEGER,
  parent INTEGER,
  pgroup INTEGER,
  threads INTEGER,
  nice INTEGER,
  elevated_token INTEGER,
  secure_process INTEGER,
  protection_type TEXT,
  virtual_process INTEGER,
  elapsed_time INTEGER,
  handle_count INTEGER,
  percent_processor_time INTEGER,
  upid INTEGER,
  uppid INTEGER,
  cpu_type INTEGER,
  cpu_subtype INTEGER,
  translated INTEGER,
  cgroup_path TEXT
);
CREATE INDEX IF NOT EXISTS idx_processes_dataset_id ON processes(dataset_id);
"#;

/// Base + platform-extended columns from osquery `file`.
pub const CREATE_FILE_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS "file" (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  dataset_id TEXT NOT NULL,
  machine_id TEXT NOT NULL,
  path TEXT NOT NULL,
  directory TEXT,
  filename TEXT,
  inode INTEGER,
  uid INTEGER,
  gid INTEGER,
  mode TEXT,
  device INTEGER,
  size INTEGER,
  block_size INTEGER,
  atime INTEGER,
  mtime INTEGER,
  ctime INTEGER,
  btime INTEGER,
  hard_links INTEGER,
  symlink INTEGER,
  "type" TEXT,
  symlink_target_path TEXT,
  attributes TEXT,
  volume_serial TEXT,
  file_id TEXT,
  file_version TEXT,
  product_version TEXT,
  original_filename TEXT,
  shortcut_target_path TEXT,
  shortcut_target_type TEXT,
  shortcut_target_location TEXT,
  shortcut_start_in TEXT,
  shortcut_run TEXT,
  shortcut_comment TEXT,
  bsd_flags TEXT,
  pid_with_namespace INTEGER,
  mount_namespace_id TEXT,
  inv_checksum INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_file_dataset_id ON "file"(dataset_id);
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn processes_ddl_has_expected_columns_and_index() {
        assert!(CREATE_PROCESSES_TABLE.contains("CREATE TABLE IF NOT EXISTS processes"));
        assert!(CREATE_PROCESSES_TABLE.contains("cgroup_path"));
        assert!(CREATE_PROCESSES_TABLE.contains("idx_processes_dataset_id"));
    }

    #[test]
    fn file_ddl_has_expected_columns_and_index() {
        assert!(CREATE_FILE_TABLE.contains("CREATE TABLE IF NOT EXISTS \"file\""));
        assert!(CREATE_FILE_TABLE.contains("symlink_target_path"));
        assert!(CREATE_FILE_TABLE.contains("inv_checksum"));
        assert!(CREATE_FILE_TABLE.contains("idx_file_dataset_id"));
    }
}
