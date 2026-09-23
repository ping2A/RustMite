//! Persistence layer: in-memory (default) + optional PostgreSQL via sqlx.
#![forbid(unsafe_code)]

pub mod error;
pub mod memory;
pub mod traits;
pub mod types;

#[cfg(feature = "postgres")]
pub mod postgres;

pub use error::{StoreError, StoreResult};
pub use memory::{InMemoryStore, StoreSnapshot};
pub use traits::Store;
pub use types::*;
pub use rustmite_proto::{HostId, NodeId, ScanId};

#[cfg(feature = "postgres")]
pub use postgres::SqlxStore;
