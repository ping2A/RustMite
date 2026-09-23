//! Classify agent/probe/transport failures into server-visible scan outcomes.

use rustmite_proto::ScanOutcome;
use rustmite_transport::TransportError;

/// Structured failure posted to `/v1/nodes/results` + progress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentFailureReport {
    /// Flat outcome string stored on the scan/host (`failed`, `timeout`, …).
    pub outcome: String,
    /// Typed outcome for ScanMeta.
    pub scan_outcome: ScanOutcome,
    /// Human stage/progress message.
    pub stage: String,
    /// Operator-facing detail (also activity message).
    pub message: String,
}

/// Map a job error into a stable outcome the control plane understands.
pub fn classify_job_error(err: &anyhow::Error) -> AgentFailureReport {
    if let Some(te) = err.downcast_ref::<TransportError>() {
        return classify_transport(te);
    }
    let msg = err.to_string();
    let lower = msg.to_ascii_lowercase();
    if lower.contains("deadline") || lower.contains("timeout") || lower.contains("timed out") {
        return AgentFailureReport {
            outcome: "timeout".into(),
            scan_outcome: ScanOutcome::Timeout { elapsed_ms: 0 },
            stage: format!("timeout: {msg}"),
            message: msg,
        };
    }
    if lower.contains("0 observations") || lower.contains("probe returned") {
        return AgentFailureReport {
            outcome: "probe_crashed".into(),
            scan_outcome: ScanOutcome::ProbeCrashed {
                signal: None,
                exit: None,
                stderr_tail: {
                    let s = msg.as_str();
                    if s.len() <= 800 {
                        s.to_string()
                    } else {
                        s[s.len() - 800..].to_string()
                    }
                },
            },
            stage: "probe produced no observations".into(),
            message: msg,
        };
    }
    if lower.contains("budget") || lower.contains("max_observations") || lower.contains("max_output")
    {
        return AgentFailureReport {
            outcome: "partial".into(),
            scan_outcome: ScanOutcome::Partial {
                failed_collectors: vec!["budget".into()],
            },
            stage: format!("budget truncated: {msg}"),
            message: msg,
        };
    }
    AgentFailureReport {
        outcome: "failed".into(),
        scan_outcome: ScanOutcome::DeliveryFailed {
            reason: msg.clone(),
        },
        stage: format!("failed: {msg}"),
        message: msg,
    }
}

pub fn classify_transport(err: &TransportError) -> AgentFailureReport {
    match err {
        TransportError::HostKeyChanged { expected, got } => AgentFailureReport {
            outcome: "host_key_changed".into(),
            scan_outcome: ScanOutcome::HostKeyChanged {
                expected: expected.clone(),
                got: got.clone(),
            },
            stage: "host key changed — abort".into(),
            message: format!("host key changed: expected {expected}, got {got}"),
        },
        TransportError::Auth(reason) => AgentFailureReport {
            outcome: "auth_failed".into(),
            scan_outcome: ScanOutcome::AuthFailed {
                reason: reason.clone(),
            },
            stage: format!("auth failed: {reason}"),
            message: reason.clone(),
        },
        TransportError::Timeout(reason) => AgentFailureReport {
            outcome: "timeout".into(),
            scan_outcome: ScanOutcome::Timeout { elapsed_ms: 0 },
            stage: format!("timeout: {reason}"),
            message: reason.clone(),
        },
        TransportError::Delivery(reason) => AgentFailureReport {
            outcome: "delivery_failed".into(),
            scan_outcome: ScanOutcome::DeliveryFailed {
                reason: reason.clone(),
            },
            stage: format!("delivery failed: {reason}"),
            message: reason.clone(),
        },
        TransportError::Ssh(reason) | TransportError::Ingest(reason) => {
            let unreachable = reason.to_ascii_lowercase().contains("connect")
                || reason.to_ascii_lowercase().contains("refused")
                || reason.to_ascii_lowercase().contains("unreachable")
                || reason.to_ascii_lowercase().contains("network");
            if unreachable {
                AgentFailureReport {
                    outcome: "unreachable".into(),
                    scan_outcome: ScanOutcome::Unreachable {
                        reason: reason.clone(),
                    },
                    stage: format!("unreachable: {reason}"),
                    message: reason.clone(),
                }
            } else {
                AgentFailureReport {
                    outcome: "failed".into(),
                    scan_outcome: ScanOutcome::DeliveryFailed {
                        reason: reason.clone(),
                    },
                    stage: format!("failed: {reason}"),
                    message: reason.clone(),
                }
            }
        }
        TransportError::Io(e) => AgentFailureReport {
            outcome: "failed".into(),
            scan_outcome: ScanOutcome::DeliveryFailed {
                reason: e.to_string(),
            },
            stage: format!("io failed: {e}"),
            message: e.to_string(),
        },
    }
}

/// Derive the flat outcome string + typed ScanOutcome from a successful probe stream.
pub fn outcome_from_normalised(
    outcome: &ScanOutcome,
    observation_count: usize,
) -> (String, ScanOutcome) {
    if observation_count == 0 {
        return (
            "probe_crashed".into(),
            ScanOutcome::ProbeCrashed {
                signal: None,
                exit: Some(0),
                stderr_tail: "probe returned 0 observations".into(),
            },
        );
    }
    let flat = match outcome {
        ScanOutcome::Complete => "complete",
        ScanOutcome::Partial { .. } => "partial",
        ScanOutcome::Timeout { .. } => "timeout",
        ScanOutcome::ProbeCrashed { .. } => "probe_crashed",
        ScanOutcome::DeliveryFailed { .. } => "delivery_failed",
        ScanOutcome::AuthFailed { .. } => "auth_failed",
        ScanOutcome::HostKeyChanged { .. } => "host_key_changed",
        ScanOutcome::Unreachable { .. } => "unreachable",
    };
    (flat.into(), outcome.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;

    #[test]
    fn classifies_transport_variants() {
        let r = classify_transport(&TransportError::Auth("bad key".into()));
        assert_eq!(r.outcome, "auth_failed");
        assert!(matches!(r.scan_outcome, ScanOutcome::AuthFailed { .. }));

        let r = classify_transport(&TransportError::Timeout("cmd".into()));
        assert_eq!(r.outcome, "timeout");

        let r = classify_transport(&TransportError::Delivery("memfd failed".into()));
        assert_eq!(r.outcome, "delivery_failed");

        let r = classify_transport(&TransportError::Ssh("connection refused".into()));
        assert_eq!(r.outcome, "unreachable");

        let r = classify_transport(&TransportError::HostKeyChanged {
            expected: "a".into(),
            got: "b".into(),
        });
        assert_eq!(r.outcome, "host_key_changed");
    }

    #[test]
    fn classifies_anyhow_wrappers() {
        let err = anyhow!(TransportError::Timeout("deadline".into()));
        let r = classify_job_error(&err);
        assert_eq!(r.outcome, "timeout");

        let err = anyhow!("probe returned 0 observations (delivery=tmpfs)");
        let r = classify_job_error(&err);
        assert_eq!(r.outcome, "probe_crashed");

        let err = anyhow!("max_observations exceeded");
        let r = classify_job_error(&err);
        assert_eq!(r.outcome, "partial");
    }

    #[test]
    fn outcome_from_normalised_zero_obs_is_crash() {
        let (flat, typed) = outcome_from_normalised(&ScanOutcome::Complete, 0);
        assert_eq!(flat, "probe_crashed");
        assert!(matches!(typed, ScanOutcome::ProbeCrashed { .. }));
    }
}
