//! Integration-style collector tests.

#[cfg(test)]
mod integration {
    use rustmite_proto::{Budget, CollectionPlan, CollectorSpec, Limits, Observation};
    use rustmite_sys::{FixtureFs, FixtureProc};

    use crate::{run_plan, CollectCtx, VecSink};

    fn make_stat(pid: i32, comm: &str, starttime: u64) -> String {
        format!(
            "{pid} ({comm}) S 0 {pid} {pid} 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 {starttime} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
        )
    }

    #[test]
    fn parse_integration_plan() {
        let fx = FixtureProc::new("/tmp/rustmite-fx-integ")
            .with_dir("proc/1")
            .with_file("proc/1/stat", make_stat(1, "systemd", 100))
            .with_file("proc/version", "Linux version 6.1.0 (test)\n")
            .with_file(
                "etc/passwd",
                "root:x:0:0:root:/root:/bin/bash\n",
            )
            .with_file(
                "proc/net/tcp",
                "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 00000000 100 0 0 10 0\n",
            )
            .with_file("proc/sys/kernel/pid_max", "512\n")
            .with_alive_pid(1);

        let fs = FixtureFs::new();
        let b = Budget::new(&Limits::default(), 60_000, 0);
        let ctx = CollectCtx {
            proc: &fx,
            fs: &fs,
            pid_probe: Some(&fx),
            budget: &b,
            euid: 0,
            self_pid: 99999,
            now_ms: 0,
        };
        let plan = CollectionPlan {
            collectors: vec![
                CollectorSpec::new("decloak.process"),
                CollectorSpec::new("process.inventory"),
                CollectorSpec::new("persistence.accounts"),
                CollectorSpec::new("net.sockets"),
                CollectorSpec::new("recon.inventory"),
            ],
            ..CollectionPlan::default()
        };
        let mut sink = VecSink::new();
        let reports = run_plan(&plan, &ctx, &mut sink).expect("run_plan");
        assert_eq!(reports.len(), 5);
        assert!(sink.observations.iter().any(|o| matches!(o, Observation::Account(_))));
        assert!(sink.observations.iter().any(|o| matches!(o, Observation::Process(_))));
        assert!(sink.observations.iter().any(|o| matches!(o, Observation::Socket(_))));
        assert!(sink.observations.iter().any(|o| matches!(o, Observation::Recon(_))));
    }
}
