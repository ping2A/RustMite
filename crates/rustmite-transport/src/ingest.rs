//! Normalise probe NDJSON into typed observations + meta.

use rustmite_proto::{
    CollectorReport, CollectorStatus, Envelope, Hello, Observation, ScanOutcome, Summary,
};

use crate::error::TransportError;
use crate::framing::{read_ndjson_bounded, FrameLimits};

#[derive(Clone, Debug)]
pub struct NormalisedResult {
    pub hello: Option<Hello>,
    pub observations: Vec<(String, u32, Observation)>,
    pub collector_reports: Vec<CollectorReport>,
    pub summary: Option<Summary>,
    pub outcome: ScanOutcome,
    pub errors: Vec<String>,
}

pub fn normalise_stream(input: &str) -> Result<NormalisedResult, TransportError> {
    let envs = read_ndjson_bounded(input, &FrameLimits::default())?;
    let mut hello = None;
    let mut observations = Vec::new();
    let mut collector_reports = Vec::new();
    let mut summary = None;
    let mut errors = Vec::new();
    let mut failed = Vec::new();

    for env in envs {
        match env {
            Envelope::Hello(h) => hello = Some(h),
            Envelope::Obs { c, n, d } => observations.push((c, n, d)),
            Envelope::CollectorStatus {
                c,
                status,
                reason,
                stats,
            } => {
                if matches!(
                    status,
                    CollectorStatus::Failed
                        | CollectorStatus::Unsupported
                        | CollectorStatus::Truncated
                ) {
                    failed.push(c.clone());
                }
                collector_reports.push(CollectorReport {
                    id: c,
                    status,
                    reason,
                    observations: stats.observations,
                    elapsed_ms: stats.elapsed_ms,
                });
            }
            Envelope::Summary(s) => summary = Some(s),
            Envelope::Error { c, code, msg } => {
                errors.push(format!("{}:{code}:{msg}", c.as_deref().unwrap_or("-")));
            }
        }
    }

    let outcome = if let Some(ref s) = summary {
        let o = s.outcome.to_ascii_lowercase();
        if o.contains("timeout") {
            ScanOutcome::Timeout {
                elapsed_ms: s.elapsed_ms,
            }
        } else if o.contains("partial") || o.contains("truncated") {
            ScanOutcome::Partial {
                failed_collectors: if failed.is_empty() {
                    s.collectors
                        .iter()
                        .filter(|c| {
                            matches!(
                                c.status,
                                CollectorStatus::Failed
                                    | CollectorStatus::Truncated
                                    | CollectorStatus::Unsupported
                                )
                        })
                        .map(|c| c.id.clone())
                        .collect()
                } else {
                    failed
                },
            }
        } else if o.contains("fail") || !errors.is_empty() {
            if failed.is_empty() {
                ScanOutcome::DeliveryFailed {
                    reason: errors.first().cloned().unwrap_or_else(|| s.outcome.clone()),
                }
            } else {
                ScanOutcome::Partial {
                    failed_collectors: failed,
                }
            }
        } else if !failed.is_empty() {
            ScanOutcome::Partial {
                failed_collectors: failed,
            }
        } else {
            ScanOutcome::Complete
        }
    } else if !failed.is_empty() {
        ScanOutcome::Partial {
            failed_collectors: failed,
        }
    } else if hello.is_some() {
        ScanOutcome::Partial {
            failed_collectors: vec!["missing_summary".into()],
        }
    } else {
        ScanOutcome::DeliveryFailed {
            reason: "empty stream".into(),
        }
    };

    Ok(NormalisedResult {
        hello,
        observations,
        collector_reports,
        summary,
        outcome,
        errors,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmite_proto::Stats;

    #[test]
    fn hostile_giant_rejected_at_frame_layer() {
        let line = format!(
            "{{\"kind\":\"error\",\"code\":\"x\",\"msg\":\"{}\"}}",
            "x".repeat(300_000)
        );
        assert!(normalise_stream(&line).is_err());
    }

    #[test]
    fn summary_timeout_outcome() {
        let stream = r#"{"kind":"summary","outcome":"timeout","collectors":[],"observation_count":0,"bytes_out":0,"elapsed_ms":5000}"#;
        let n = normalise_stream(stream).expect("parse");
        assert!(matches!(
            n.outcome,
            ScanOutcome::Timeout { elapsed_ms: 5000 }
        ));
    }

    #[test]
    fn truncated_collector_is_partial() {
        let env = Envelope::CollectorStatus {
            c: "process.inventory".into(),
            status: CollectorStatus::Truncated,
            reason: Some("deadline_ms exceeded".into()),
            stats: Stats {
                observations: 1,
                bytes_read: 10,
                elapsed_ms: 5,
                extra: Default::default(),
            },
        };
        let sum = Envelope::Summary(Summary {
            outcome: "partial".into(),
            collectors: vec![],
            observation_count: 1,
            bytes_out: 10,
            elapsed_ms: 5,
        });
        let stream = format!(
            "{}\n{}\n",
            serde_json::to_string(&env).unwrap(),
            serde_json::to_string(&sum).unwrap()
        );
        let n = normalise_stream(&stream).expect("parse");
        match n.outcome {
            ScanOutcome::Partial { failed_collectors } => {
                assert!(failed_collectors.iter().any(|c| c == "process.inventory"));
            }
            other => panic!("expected partial, got {other:?}"),
        }
    }

    #[test]
    fn empty_stream_is_delivery_failed() {
        let n = normalise_stream("").expect("empty ok");
        assert!(matches!(n.outcome, ScanOutcome::DeliveryFailed { .. }));
    }

    #[test]
    fn error_envelope_surfaces() {
        let env = Envelope::Error {
            c: Some("entropy".into()),
            code: "io".into(),
            msg: "read failed".into(),
        };
        let sum = Envelope::Summary(Summary {
            outcome: "failed".into(),
            collectors: vec![],
            observation_count: 0,
            bytes_out: 0,
            elapsed_ms: 1,
        });
        let stream = format!(
            "{}\n{}\n",
            serde_json::to_string(&env).unwrap(),
            serde_json::to_string(&sum).unwrap()
        );
        let n = normalise_stream(&stream).unwrap();
        assert!(!n.errors.is_empty());
        assert!(matches!(
            n.outcome,
            ScanOutcome::DeliveryFailed { .. } | ScanOutcome::Partial { .. }
        ));
    }
}
