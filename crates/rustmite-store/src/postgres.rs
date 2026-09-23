//! Optional PostgreSQL backend (feature = `postgres`).

use async_trait::async_trait;
use rustmite_proto::{Finding, NodeId, ScanId};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use crate::error::{StoreError, StoreResult};
use crate::traits::Store;
use crate::types::{
    CompleteScan, EnqueueScan, FindingFilter, HostRecord, NodeRegistration, ScanJob, ScanStatus,
    StoredObservation, UpsertHost,
};

/// Sqlx-backed store. Migrations live in `crates/rustmite-store/migrations/`.
pub struct SqlxStore {
    pool: PgPool,
}

impl SqlxStore {
    pub async fn connect(database_url: &str) -> StoreResult<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        let store = Self { pool };
        store.migrate().await?;
        Ok(store)
    }

    pub async fn migrate(&self) -> StoreResult<()> {
        let dir = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations"));
        let migrator = sqlx::migrate::Migrator::new(dir)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        migrator
            .run(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(())
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

#[async_trait]
impl Store for SqlxStore {
    async fn upsert_host(&self, _req: UpsertHost) -> StoreResult<HostRecord> {
        Err(StoreError::Backend(
            "SqlxStore::upsert_host not yet implemented — use InMemoryStore or fill in queries"
                .into(),
        ))
    }

    async fn list_hosts(&self) -> StoreResult<Vec<HostRecord>> {
        Err(StoreError::Backend(
            "SqlxStore::list_hosts not yet implemented".into(),
        ))
    }

    async fn enqueue_scan(&self, _req: EnqueueScan) -> StoreResult<ScanJob> {
        Err(StoreError::Backend(
            "SqlxStore::enqueue_scan not yet implemented".into(),
        ))
    }

    async fn lease_jobs(&self, _node_id: NodeId, _capacity: usize) -> StoreResult<Vec<ScanJob>> {
        Err(StoreError::Backend(
            "SqlxStore::lease_jobs not yet implemented (SELECT … FOR UPDATE SKIP LOCKED)"
                .into(),
        ))
    }

    async fn complete_scan(&self, _req: CompleteScan) -> StoreResult<()> {
        Err(StoreError::Backend(
            "SqlxStore::complete_scan not yet implemented".into(),
        ))
    }

    async fn insert_observations(&self, _rows: Vec<StoredObservation>) -> StoreResult<()> {
        Err(StoreError::Backend(
            "SqlxStore::insert_observations not yet implemented".into(),
        ))
    }

    async fn insert_findings(&self, _findings: Vec<Finding>) -> StoreResult<()> {
        Err(StoreError::Backend(
            "SqlxStore::insert_findings not yet implemented".into(),
        ))
    }

    async fn list_findings(&self, _filter: FindingFilter) -> StoreResult<Vec<Finding>> {
        Err(StoreError::Backend(
            "SqlxStore::list_findings not yet implemented".into(),
        ))
    }

    async fn get_scan(&self, _scan_id: ScanId) -> StoreResult<ScanStatus> {
        Err(StoreError::Backend(
            "SqlxStore::get_scan not yet implemented".into(),
        ))
    }

    async fn register_node(&self, _reg: NodeRegistration) -> StoreResult<()> {
        Err(StoreError::Backend(
            "SqlxStore::register_node not yet implemented".into(),
        ))
    }
}
