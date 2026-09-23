//! RustMite scanner node library helpers.
#![forbid(unsafe_code)]

pub mod agent_report;

pub use agent_report::{
    classify_job_error, classify_transport, outcome_from_normalised, AgentFailureReport,
};
pub use rustmite_crypto;
