//! Alert notification sinks.
#![forbid(unsafe_code)]

mod router;
mod sinks;

pub use router::SeverityRouter;
pub use sinks::{NdjsonFileSink, NotifyError, NotifySink, SyslogSink, WebhookSink};

use rustmite_proto::{Finding, Severity};
use serde::{Deserialize, Serialize};

/// Generic alert payload forwarded to sinks.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AlertEvent {
    pub severity: Severity,
    pub title: String,
    pub body: serde_json::Value,
    pub finding: Option<Finding>,
}

impl AlertEvent {
    pub fn from_finding(f: &Finding) -> Self {
        Self {
            severity: f.severity,
            title: f.title.clone(),
            body: serde_json::json!({
                "check_id": f.check_id.as_str(),
                "host_id": f.host_id.to_string(),
                "scan_id": f.scan_id.to_string(),
                "confidence": f.confidence,
                "evidence": f.evidence,
            }),
            finding: Some(f.clone()),
        }
    }
}
