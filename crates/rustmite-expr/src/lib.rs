//! Small, total, sandboxed expression language for check `where` clauses.
#![forbid(unsafe_code)]

mod ast;
mod context;
mod error;
mod eval;
mod lexer;
mod parser;
mod value;

pub use context::{observation_context, EvalContext};
pub use error::ExprError;
pub use eval::{compile, eval, CompiledExpr, DEFAULT_MAX_STEPS};
pub use value::Value;

#[cfg(test)]
mod tests {
    use super::*;
    use rustmite_proto::{Confidence, HiddenProcessObs, PathBytes, ProcessObs};

    fn process_obs(comm: &str, exe: Option<&str>, exe_memfd: bool) -> rustmite_proto::Observation {
        rustmite_proto::Observation::Process(ProcessObs {
            pid: 42,
            ppid: 1,
            comm: comm.into(),
            exe: exe.map(PathBytes::from_str),
            exe_deleted: false,
            exe_memfd,
            cmdline: vec![],
            cwd: None,
            root: None,
            uids: [0, 0, 0, 0],
            gids: [0, 0, 0, 0],
            starttime: 100,
            num_threads: 1,
            tty: 0,
            state: 'R',
            caps_eff: 0,
            ns: Default::default(),
            rwx_maps: 0,
            unbacked_exec: 0,
            listen_ports: vec![],
            selinux: None,
            environ_flags: vec![],
            username: None,
        })
    }

    #[test]
    fn rf_proc_0007_fake_kernel_thread() {
        let expr = compile(
            r#"
            process.comm matches "^\[.*\]$"
            and process.exe != null
            and process.exe != ""
            "#,
        )
        .expect("compile");

        let hit = observation_context(&process_obs("[kworker/0:1]", Some("/tmp/evil"), false));
        assert!(eval(&expr, &hit).unwrap());

        let miss_real_kthread = observation_context(&process_obs("[kworker/0:1]", None, false));
        assert!(!eval(&expr, &miss_real_kthread).unwrap());

        let miss_normal = observation_context(&process_obs("bash", Some("/bin/bash"), false));
        assert!(!eval(&expr, &miss_normal).unwrap());
    }

    #[test]
    fn rf_proc_0001_hidden_process() {
        let expr = compile("hidden_process.passes_confirmed >= 2").expect("compile");

        let hit = observation_context(&rustmite_proto::Observation::HiddenProcess(
            HiddenProcessObs {
                pid: 999,
                sources_present: vec!["kill0".into()],
                sources_absent: vec!["proc_readdir".into()],
                comm: Some("hidden".into()),
                exe: None,
                uid: Some(0),
                starttime: Some(1),
                cgroup: None,
                passes_confirmed: 2,
                confidence: Confidence::High,
                note: None,
            },
        ));
        assert!(eval(&expr, &hit).unwrap());

        let miss = observation_context(&rustmite_proto::Observation::HiddenProcess(
            HiddenProcessObs {
                pid: 999,
                sources_present: vec!["kill0".into()],
                sources_absent: vec!["proc_readdir".into()],
                comm: None,
                exe: None,
                uid: None,
                starttime: None,
                cgroup: None,
                passes_confirmed: 1,
                confidence: Confidence::Medium,
                note: None,
            },
        ));
        assert!(!eval(&expr, &miss).unwrap());
    }

    #[test]
    fn memfd_flag() {
        let expr = compile(r#"process.exe_memfd == true"#).expect("compile");
        let hit = observation_context(&process_obs(
            "x",
            Some("/memfd:payload (deleted)"),
            true,
        ));
        assert!(eval(&expr, &hit).unwrap());
        let miss = observation_context(&process_obs("x", Some("/bin/ls"), false));
        assert!(!eval(&expr, &miss).unwrap());
    }

    #[test]
    fn string_ops_and_null() {
        let expr = compile(
            r#"process.exe contains "(deleted)" and process.comm starts_with "b" and process.comm ends_with "sh""#,
        )
        .expect("compile");
        let ctx = observation_context(&process_obs(
            "bash",
            Some("/bin/bash (deleted)"),
            false,
        ));
        assert!(eval(&expr, &ctx).unwrap());
    }

    #[test]
    fn path_under_method() {
        let expr = compile(r#"process.exe.path_under("/tmp")"#).expect("compile");
        let hit = observation_context(&process_obs("x", Some("/tmp/foo"), false));
        assert!(eval(&expr, &hit).unwrap());
        let miss = observation_context(&process_obs("x", Some("/usr/bin/x"), false));
        assert!(!eval(&expr, &miss).unwrap());
    }

    #[test]
    fn euid_ruid_elevation_shape() {
        let mut obs = process_obs("find", Some("/usr/bin/find"), false);
        if let rustmite_proto::Observation::Process(ref mut p) = obs {
            p.uids = [1000, 0, 0, 0]; // ruid non-0, euid 0
        }
        let expr = compile(
            r#"process.euid == 0 and process.ruid != 0 and process.comm == "find""#,
        )
        .expect("compile");
        assert!(eval(&expr, &observation_context(&obs)).unwrap());
    }

    #[test]
    fn step_budget() {
        let mut expr = compile("true and true and true").unwrap();
        expr.max_steps = 2;
        let ctx = EvalContext::default();
        assert!(matches!(eval(&expr, &ctx), Err(ExprError::StepBudgetExceeded)));
    }
}
