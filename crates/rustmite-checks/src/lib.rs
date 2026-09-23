//! Check manifests and evaluation engine.
#![forbid(unsafe_code)]

mod baseline;
mod cred_correlate;
mod engine;
mod error;
mod key_graph;
mod manifest;

pub use baseline::{
    diff_baseline, diff_baseline_with, BaselineAccount, BaselineAuthorizedKey, BaselineFileHash,
    BaselineSnapshot, DiffOptions, DriftFinding,
};
pub use cred_correlate::{find_duplicate_shadow_hashes, ShadowPosture};
pub use engine::{CheckEngine, FindingDraft};
pub use error::CheckError;
pub use key_graph::{correlate_ssh_key_graph, KeyPlacement};
pub use manifest::{
    default_collectors_for_match, load_dir, load_manifest, match_observation, union_collectors,
    CheckManifest,
};

#[cfg(test)]
mod tests {
    use super::*;
    use rustmite_proto::{
        Confidence, HiddenProcessObs, Observation, PathBytes, ProcessObs, Severity,
    };

    fn sample_process(comm: &str, exe: Option<&str>) -> Observation {
        Observation::Process(ProcessObs {
            pid: 7,
            ppid: 1,
            comm: comm.into(),
            exe: exe.map(PathBytes::from_str),
            exe_deleted: false,
            exe_memfd: false,
            cmdline: vec![],
            cwd: None,
            root: None,
            uids: [0, 0, 0, 0],
            gids: [0, 0, 0, 0],
            starttime: 1,
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
    fn parse_manifest_toml() {
        let toml = r#"
id = "RM-PROC-0007"
version = 1
name = "Fake kernel thread"
type = "process"
severity = "high"
confidence = "high"
enabled = true
cost = "trivial"
match = "process"
where = '''
  process.comm matches "^\[.*\]$"
  and process.exe != null
'''
title = "Process '{{process.comm}}' masquerades as a kernel thread"
evidence_fields = ["pid", "comm", "exe"]
attack = ["T1014", "T1036"]
"#;
        let m = load_manifest(toml).expect("parse");
        assert_eq!(m.id.as_str(), "RM-PROC-0007");
        assert_eq!(m.severity, Severity::High);
        assert!(m.enabled);
    }

    #[test]
    fn engine_fires_proc_0007() {
        let toml = r#"
id = "RM-PROC-0007"
version = 1
name = "Fake kernel thread"
type = "process"
severity = "high"
confidence = "high"
enabled = true
cost = "trivial"
match = "process"
where = '''
  process.comm matches "^\[.*\]$"
  and process.exe != null
  and process.exe != ""
'''
title = "Process '{{process.comm}}' masquerades as a kernel thread"
evidence_fields = ["pid", "comm", "exe"]
attack = ["T1014"]
"#;
        let engine = CheckEngine::from_manifests(vec![load_manifest(toml).unwrap()]).unwrap();
        let obs = vec![
            sample_process("[kthreadd]", Some("/tmp/evil")),
            sample_process("bash", Some("/bin/bash")),
        ];
        let findings = engine.evaluate(&obs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_id.as_str(), "RM-PROC-0007");
        assert!(findings[0].title.contains("[kthreadd]"));
        assert_eq!(
            findings[0].evidence.get("pid").and_then(|v| v.as_i64()),
            Some(7)
        );
    }

    #[test]
    fn from_toml_for_test_runs_disabled_rules() {
        let toml = r#"
id = "RM-PROC-0007"
version = 1
name = "Fake kernel thread"
type = "process"
severity = "high"
confidence = "high"
enabled = false
cost = "trivial"
match = "process"
where = '''
  process.comm matches "^\[.*\]$"
  and process.exe != null
'''
title = "hit"
evidence_fields = ["pid"]
attack = []
"#;
        assert!(CheckEngine::from_toml(toml).unwrap().evaluate(&[sample_process("[x]", Some("/t"))]).is_empty());
        let engine = CheckEngine::from_toml_for_test(toml).unwrap();
        assert_eq!(engine.evaluate(&[sample_process("[x]", Some("/t"))]).len(), 1);
    }

    #[test]
    fn engine_fires_hidden_process() {
        let toml = r#"
id = "RM-PROC-0001"
version = 1
name = "Hidden process"
type = "process"
severity = "critical"
confidence = "high"
enabled = true
cost = "trivial"
match = "hidden_process"
where = "hidden_process.passes_confirmed >= 2"
title = "Hidden process pid {{hidden_process.pid}}"
evidence_fields = ["pid", "comm"]
attack = ["T1014"]
"#;
        let engine = CheckEngine::from_manifests(vec![load_manifest(toml).unwrap()]).unwrap();
        let obs = vec![Observation::HiddenProcess(HiddenProcessObs {
            pid: 404,
            sources_present: vec!["kill0".into()],
            sources_absent: vec!["proc".into()],
            comm: Some("x".into()),
            exe: None,
            uid: Some(0),
            starttime: Some(1),
            cgroup: None,
            passes_confirmed: 2,
            confidence: Confidence::High,
            note: None,
        })];
        let findings = engine.evaluate(&obs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn load_seed_catalog() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../checks");
        if !root.is_dir() {
            return;
        }
        let manifests = load_dir(&root).expect("load_dir");
        assert!(
            manifests.len() >= 40,
            "expected expanded catalog, got {}",
            manifests.len()
        );
        let engine = CheckEngine::from_manifests(manifests).expect("compile all");
        assert!(engine.len() >= 40);
        let plan = engine.collection_plan();
        assert!(!plan.collectors.is_empty());
    }
}
