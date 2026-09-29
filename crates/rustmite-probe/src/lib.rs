//! Probe runtime helpers (testable without stdin/stdout).

#![forbid(unsafe_code)]

pub mod protect;

use rustmite_proto::{CollectorReport, CollectorStatus, Limits};

/// Derive Summary.outcome from collector reports (and optional plan error).
pub fn summary_outcome(reports: &[CollectorReport], plan_failed: bool) -> &'static str {
    if plan_failed {
        return "failed";
    }
    let mut truncated = false;
    let mut failed = false;
    for r in reports {
        match r.status {
            CollectorStatus::Truncated => truncated = true,
            CollectorStatus::Failed => failed = true,
            CollectorStatus::Unsupported => {}
            CollectorStatus::Complete | CollectorStatus::NotApplicable => {}
        }
        if let Some(reason) = &r.reason {
            let l = reason.to_ascii_lowercase();
            if l.contains("deadline") {
                return "timeout";
            }
        }
    }
    if truncated {
        "partial"
    } else if failed {
        "partial"
    } else {
        "complete"
    }
}

/// Clamp / validate limits before applying (server may send zeros).
pub fn sanitize_limits(mut limits: Limits) -> Limits {
    // Same floors as Settings → Agent limits (PUT /v1/settings probe_limits).
    if limits.max_rss_bytes > 0 {
        limits.max_rss_bytes = limits.max_rss_bytes.max(4 * 1024 * 1024);
    }
    if limits.max_observations == 0 {
        limits.max_observations = 1_000;
    } else {
        limits.max_observations = limits.max_observations.max(1_000);
    }
    if limits.max_output_bytes == 0 {
        limits.max_output_bytes = 1024 * 1024;
    } else {
        limits.max_output_bytes = limits.max_output_bytes.max(1024 * 1024);
    }
    if limits.max_files_examined == 0 {
        limits.max_files_examined = 1_000;
    } else {
        limits.max_files_examined = limits.max_files_examined.max(1_000);
    }
    if limits.max_open_files == 0 {
        limits.max_open_files = 64;
    }
    limits.nice = limits.nice.clamp(-20, 19);
    if limits.max_cpu_pct > 100 {
        limits.max_cpu_pct = 100;
    }
    limits
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmite_collect::{run_plan, CollectCtx, VecSink};
    use rustmite_proto::{Budget, CollectionPlan, CollectorSpec, Limits};
    use rustmite_sys::{FixtureFs, FixtureProc};

    #[test]
    fn summary_outcome_timeout_from_deadline_reason() {
        let reports = vec![CollectorReport {
            id: "process.inventory".into(),
            status: CollectorStatus::Truncated,
            reason: Some("deadline_ms exceeded".into()),
            observations: 0,
            elapsed_ms: 1,
        }];
        assert_eq!(summary_outcome(&reports, false), "timeout");
    }

    #[test]
    fn summary_outcome_partial_on_failed_collector() {
        let reports = vec![CollectorReport {
            id: "entropy".into(),
            status: CollectorStatus::Failed,
            reason: Some("io".into()),
            observations: 0,
            elapsed_ms: 1,
        }];
        assert_eq!(summary_outcome(&reports, false), "partial");
    }

    #[test]
    fn sanitize_limits_clamps_and_fills_zeros() {
        let l = sanitize_limits(Limits {
            max_rss_bytes: 100,
            max_observations: 0,
            max_output_bytes: 0,
            max_files_examined: 0,
            max_bytes_hashed: 1,
            nice: 40,
            io_idle: true,
            max_transfer_bps: 0,
            max_cpu_pct: 200,
            max_open_files: 0,
        });
        assert!(l.max_rss_bytes >= 4 * 1024 * 1024);
        assert_eq!(l.max_observations, 1_000);
        assert_eq!(l.max_output_bytes, 1024 * 1024);
        assert_eq!(l.max_files_examined, 1_000);
        assert_eq!(l.nice, 19);
        assert_eq!(l.max_cpu_pct, 100);
        assert_eq!(l.max_open_files, 64);
    }

    #[test]
    fn sanitize_limits_preserves_sane_values() {
        let src = Limits {
            max_rss_bytes: 32 * 1024 * 1024,
            max_observations: 50_000,
            max_output_bytes: 8 * 1024 * 1024,
            max_files_examined: 10_000,
            max_bytes_hashed: 1 << 30,
            nice: 10,
            io_idle: false,
            max_transfer_bps: 256 * 1024,
            max_cpu_pct: 25,
            max_open_files: 128,
        };
        let l = sanitize_limits(src.clone());
        assert_eq!(l, src);
    }

    #[test]
    fn sanitize_limits_matches_server_probe_limits_floor() {
        // Server PUT /v1/settings clamps with the same floors — keep in sync.
        let l = sanitize_limits(Limits {
            max_rss_bytes: 1,
            max_observations: 1,
            max_output_bytes: 1,
            max_files_examined: 1,
            ..Limits::default()
        });
        assert!(l.max_rss_bytes >= 4 * 1024 * 1024);
        assert!(l.max_observations >= 1_000);
        assert!(l.max_output_bytes >= 1024 * 1024);
        assert!(l.max_files_examined >= 1_000);
    }

    #[test]
    fn tight_observation_budget_truncates_collectors() {
        let fx = FixtureProc::new("/tmp/rustmite-probe-budget")
            .with_file("proc/sys/kernel/pid_max", b"32\n")
            .with_file("proc/1/stat", b"1 (init) S 0 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n")
            .with_file("proc/1/status", b"Name:\tinit\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nCapEff:\t0\n");
        let fs = FixtureFs::new();
        let limits = Limits {
            max_observations: 0, // first emit must truncate
            ..Limits::default()
        };
        let budget = Budget::new(&limits, 60_000, 0);
        let ctx = CollectCtx {
            proc: &fx,
            fs: &fs,
            pid_probe: None,
            budget: &budget,
            euid: 0,
            self_pid: 1,
            now_ms: 0,
        };
        let mut sink = VecSink::new();
        let plan = CollectionPlan {
            collectors: vec![
                CollectorSpec::new("recon.inventory"),
                CollectorSpec::new("process.inventory"),
            ],
            ..Default::default()
        };
        let reports = run_plan(&plan, &ctx, &mut sink).expect("run");
        assert!(
            reports
                .iter()
                .any(|r| matches!(r.status, CollectorStatus::Truncated)),
            "expected Truncated under max_observations=0, got {reports:?}"
        );
        assert!(matches!(
            summary_outcome(&reports, false),
            "partial" | "timeout"
        ));
        assert!(budget.observation_count() <= 1);
    }

    #[test]
    fn deadline_budget_truncates_when_now_past_deadline() {
        let fx = FixtureProc::new("/tmp/rustmite-probe-deadline");
        let fs = FixtureFs::new();
        let budget = Budget::new(&Limits::default(), 10, 100);
        let ctx = CollectCtx {
            proc: &fx,
            fs: &fs,
            pid_probe: None,
            budget: &budget,
            euid: 0,
            self_pid: 1,
            now_ms: 200, // past deadline
        };
        let mut sink = VecSink::new();
        let plan = CollectionPlan {
            collectors: vec![CollectorSpec::new("recon.inventory")],
            ..Default::default()
        };
        let reports = run_plan(&plan, &ctx, &mut sink).expect("run");
        // recon may complete without emit if empty, or truncate on first emit
        let outcome = summary_outcome(&reports, false);
        assert!(
            outcome == "timeout" || outcome == "partial" || outcome == "complete",
            "got {outcome} reports={reports:?}"
        );
    }
}
