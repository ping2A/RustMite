//! Shared wire types for RustMite. `no_std + alloc` so probe and server share one definition.
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod ids;
pub mod path;
pub mod enums;
pub mod observation;
pub mod envelope;
pub mod scan;
pub mod finding;
pub mod delivery;

pub use ids::*;
pub use path::{BigInt, PathBytes};
pub use enums::*;
pub use observation::*;
pub use envelope::*;
pub use scan::*;
pub use finding::*;
pub use delivery::DeliveryReport;

/// Current wire schema version.
pub const SCHEMA_VERSION: u16 = 1;
