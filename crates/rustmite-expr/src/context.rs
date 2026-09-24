//! EvalContext and Observation → value conversion.

use std::collections::BTreeMap;

use rustmite_proto::{
    AccountObs, AuthorizedKeyObs, BpfProgObs, Confidence, ContainerObs, DirAnomalyObs, ElfInfoObs,
    FileEntropyObs, FileMetaObs, HiddenProcessObs, HiddenSocketObs, IntegrityObs, IocHitObs,
    LogIntegrityObs, ModuleObs, MountObs, Observation, PathBytes, PolicyObs, PreloadObs,
    ProcessObs, ScheduledTaskObs, ServiceObs, ShadowEntryObs, SocketObs, SshHostKeyObs,
    SudoRuleObs, TimestompObs, UtmpSessionObs,
};

use crate::value::Value;

/// Root bindings for evaluation (e.g. `process` → record).
#[derive(Clone, Debug, Default)]
pub struct EvalContext {
    pub roots: BTreeMap<String, Value>,
}

impl EvalContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, name: impl Into<String>, value: Value) {
        self.roots.insert(name.into(), value);
    }

    pub fn get(&self, name: &str) -> Value {
        self.roots.get(name).cloned().unwrap_or(Value::Null)
    }

    pub fn lookup_path(&self, path: &[&str]) -> Value {
        if path.is_empty() {
            return Value::Null;
        }
        let mut cur = self.get(path[0]);
        for part in &path[1..] {
            cur = cur.get_field(part);
        }
        cur
    }
}

/// Build an [`EvalContext`] from a single [`Observation`].
pub fn observation_context(obs: &Observation) -> EvalContext {
    let mut ctx = EvalContext::new();
    match obs {
        Observation::Process(p) => ctx.insert("process", process_value(p)),
        Observation::HiddenProcess(p) => ctx.insert("hidden_process", hidden_process_value(p)),
        Observation::Socket(s) => ctx.insert("socket", socket_value(s)),
        Observation::HiddenSocket(s) => ctx.insert("hidden_socket", hidden_socket_value(s)),
        Observation::Module(m) | Observation::HiddenModule(m) => {
            ctx.insert("module", module_value(m));
        }
        Observation::FileEntropy(f) => ctx.insert("file_entropy", file_entropy_value(f)),
        Observation::ElfInfo(e) => ctx.insert("elf_info", elf_info_value(e)),
        Observation::Preload(p) => ctx.insert("preload", preload_value(p)),
        Observation::Account(a) => ctx.insert("account", account_value(a)),
        Observation::SshHostKey(k) => ctx.insert("ssh_host_key", ssh_host_key_value(k)),
        Observation::Policy(p) => ctx.insert("policy", policy_value(p)),
        Observation::Recon(r) => {
            let mut m = std::collections::BTreeMap::new();
            m.insert("category".into(), Value::String(r.category.clone()));
            ctx.insert("recon", Value::Record(m));
        }
        Observation::ShadowEntry(s) => ctx.insert("shadow_entry", shadow_entry_value(s)),
        Observation::SudoRule(r) => ctx.insert("sudo_rule", sudo_rule_value(r)),
        Observation::AuthorizedKey(k) => ctx.insert("authorized_key", authorized_key_value(k)),
        Observation::DirAnomaly(d) => ctx.insert("dir_anomaly", dir_anomaly_value(d)),
        Observation::LogIntegrity(l) => ctx.insert("log_integrity", log_integrity_value(l)),
        Observation::Timestomp(t) => ctx.insert("timestomp", timestomp_value(t)),
        Observation::FileMeta(f) => ctx.insert("file_meta", file_meta_value(f)),
        Observation::IocHit(i) => ctx.insert("ioc_hit", ioc_hit_value(i)),
        Observation::IntegrityMismatch(i) => ctx.insert("integrity_mismatch", integrity_value(i)),
        Observation::BpfProg(b) => ctx.insert("bpf_prog", bpf_prog_value(b)),
        Observation::ScheduledTask(t) => ctx.insert("scheduled_task", scheduled_task_value(t)),
        Observation::Service(s) => ctx.insert("service", service_value(s)),
        Observation::Mount(m) => ctx.insert("mount", mount_value(m)),
        Observation::UtmpSession(u) => ctx.insert("utmp_session", utmp_session_value(u)),
        Observation::ContainerInfo(c) => ctx.insert("container", container_value(c)),
    }
    ctx
}

fn process_value(p: &ProcessObs) -> Value {
    let mut m = BTreeMap::new();
    m.insert("pid".into(), Value::Int(p.pid as i64));
    m.insert("ppid".into(), Value::Int(p.ppid as i64));
    m.insert("comm".into(), Value::String(p.comm.clone()));
    m.insert("exe".into(), opt_path(&p.exe));
    m.insert("exe_deleted".into(), Value::Bool(p.exe_deleted));
    m.insert("exe_memfd".into(), Value::Bool(p.exe_memfd));
    m.insert(
        "cmdline".into(),
        Value::List(p.cmdline.iter().map(path_value).collect()),
    );
    m.insert("cwd".into(), opt_path(&p.cwd));
    m.insert("root".into(), opt_path(&p.root));
    // /proc/<pid>/status Uid: real, effective, saved, fs
    m.insert("uid".into(), Value::Int(p.uids[0] as i64));
    m.insert("ruid".into(), Value::Int(p.uids[0] as i64));
    m.insert("euid".into(), Value::Int(p.uids[1] as i64));
    m.insert("suid".into(), Value::Int(p.uids[2] as i64));
    m.insert(
        "username".into(),
        p.username
            .as_ref()
            .map(|u| Value::String(u.clone()))
            .unwrap_or(Value::Null),
    );
    m.insert(
        "uids".into(),
        Value::List(p.uids.iter().map(|u| Value::Int(*u as i64)).collect()),
    );
    m.insert(
        "gids".into(),
        Value::List(p.gids.iter().map(|g| Value::Int(*g as i64)).collect()),
    );
    m.insert("starttime".into(), Value::Int(p.starttime as i64));
    m.insert("num_threads".into(), Value::Int(p.num_threads));
    m.insert("tty".into(), Value::Int(p.tty as i64));
    m.insert("state".into(), Value::String(p.state.to_string()));
    m.insert("caps_eff".into(), Value::Int(p.caps_eff as i64));
    // Elastic LPE posture: CAP_SYS_MODULE|PTRACE|SYS_ADMIN|BPF
    const DANGEROUS_CAPS: u64 =
        (1u64 << 16) | (1u64 << 19) | (1u64 << 21) | (1u64 << 39);
    m.insert(
        "dangerous_caps".into(),
        Value::Bool(p.caps_eff & DANGEROUS_CAPS != 0),
    );
    m.insert("rwx_maps".into(), Value::Int(p.rwx_maps as i64));
    m.insert("unbacked_exec".into(), Value::Int(p.unbacked_exec as i64));
    m.insert(
        "listen_ports".into(),
        Value::List(p.listen_ports.iter().map(|p| Value::Int(*p as i64)).collect()),
    );
    m.insert(
        "environ_flags".into(),
        Value::List(
            p.environ_flags
                .iter()
                .map(|s| Value::String(s.clone()))
                .collect(),
        ),
    );
    Value::Record(m)
}

fn hidden_process_value(p: &HiddenProcessObs) -> Value {
    let mut m = BTreeMap::new();
    m.insert("pid".into(), Value::Int(p.pid as i64));
    m.insert(
        "sources_present".into(),
        Value::List(
            p.sources_present
                .iter()
                .map(|s| Value::String(s.clone()))
                .collect(),
        ),
    );
    m.insert(
        "sources_absent".into(),
        Value::List(
            p.sources_absent
                .iter()
                .map(|s| Value::String(s.clone()))
                .collect(),
        ),
    );
    m.insert(
        "comm".into(),
        p.comm
            .as_ref()
            .map(|s| Value::String(s.clone()))
            .unwrap_or(Value::Null),
    );
    m.insert("exe".into(), opt_path(&p.exe));
    m.insert(
        "uid".into(),
        p.uid.map(|u| Value::Int(u as i64)).unwrap_or(Value::Null),
    );
    m.insert(
        "starttime".into(),
        p.starttime
            .map(|t| Value::Int(t as i64))
            .unwrap_or(Value::Null),
    );
    m.insert(
        "cgroup".into(),
        p.cgroup
            .as_ref()
            .map(|s| Value::String(s.clone()))
            .unwrap_or(Value::Null),
    );
    m.insert(
        "passes_confirmed".into(),
        Value::Int(p.passes_confirmed as i64),
    );
    m.insert("confidence".into(), confidence_value(p.confidence));
    m.insert(
        "note".into(),
        p.note
            .as_ref()
            .map(|s| Value::String(s.clone()))
            .unwrap_or(Value::Null),
    );
    Value::Record(m)
}

fn socket_value(s: &SocketObs) -> Value {
    let mut m = BTreeMap::new();
    m.insert("inode".into(), Value::String(s.inode.0.clone()));
    m.insert("family".into(), Value::String(s.family.clone()));
    m.insert("protocol".into(), Value::String(s.protocol.clone()));
    m.insert("state".into(), Value::String(s.state.clone()));
    m.insert("local_ip".into(), Value::String(s.local_ip.clone()));
    m.insert("local_port".into(), Value::Int(s.local_port as i64));
    m.insert("remote_ip".into(), Value::String(s.remote_ip.clone()));
    m.insert("remote_port".into(), Value::Int(s.remote_port as i64));
    m.insert("uid".into(), Value::Int(s.uid as i64));
    m.insert(
        "owning_pid".into(),
        s.owning_pid
            .map(|p| Value::Int(p as i64))
            .unwrap_or(Value::Null),
    );
    m.insert(
        "owning_comm".into(),
        s.owning_comm
            .as_ref()
            .map(|c| Value::String(c.clone()))
            .unwrap_or(Value::Null),
    );
    m.insert(
        "owner_unresolved".into(),
        Value::Bool(s.owner_unresolved),
    );
    Value::Record(m)
}

fn hidden_socket_value(s: &HiddenSocketObs) -> Value {
    let mut m = BTreeMap::new();
    m.insert("inode".into(), Value::String(s.inode.0.clone()));
    m.insert("local_port".into(), Value::Int(s.local_port as i64));
    m.insert("protocol".into(), Value::String(s.protocol.clone()));
    m.insert(
        "sources_present".into(),
        Value::List(
            s.sources_present
                .iter()
                .map(|x| Value::String(x.clone()))
                .collect(),
        ),
    );
    m.insert(
        "sources_absent".into(),
        Value::List(
            s.sources_absent
                .iter()
                .map(|x| Value::String(x.clone()))
                .collect(),
        ),
    );
    m.insert("confidence".into(), confidence_value(s.confidence));
    Value::Record(m)
}

fn module_value(m: &ModuleObs) -> Value {
    let mut map = BTreeMap::new();
    map.insert("name".into(), Value::String(m.name.clone()));
    map.insert(
        "size".into(),
        m.size.map(|s| Value::Int(s as i64)).unwrap_or(Value::Null),
    );
    map.insert(
        "refcount".into(),
        m.refcount
            .map(|r| Value::Int(r as i64))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "used_by".into(),
        Value::List(m.used_by.iter().map(|s| Value::String(s.clone())).collect()),
    );
    map.insert("in_sysfs".into(), Value::Bool(m.in_sysfs));
    map.insert("in_proc_modules".into(), Value::Bool(m.in_proc_modules));
    map.insert(
        "taint_flags".into(),
        m.taint_flags
            .as_ref()
            .map(|s| Value::String(s.clone()))
            .unwrap_or(Value::Null),
    );
    Value::Record(map)
}

fn file_entropy_value(f: &FileEntropyObs) -> Value {
    let mut m = BTreeMap::new();
    m.insert("path".into(), path_value(&f.path));
    m.insert("entropy".into(), Value::Float(f.entropy));
    m.insert(
        "window_max".into(),
        f.window_max.map(Value::Float).unwrap_or(Value::Null),
    );
    m.insert(
        "window_offset".into(),
        f.window_offset
            .map(|o| Value::Int(o as i64))
            .unwrap_or(Value::Null),
    );
    m.insert("size".into(), Value::String(f.size.0.clone()));
    m.insert("is_elf".into(), Value::Bool(f.is_elf));
    m.insert(
        "sha256".into(),
        f.sha256
            .as_ref()
            .map(|s| Value::String(s.clone()))
            .unwrap_or(Value::Null),
    );
    Value::Record(m)
}

fn elf_info_value(e: &ElfInfoObs) -> Value {
    let mut m = BTreeMap::new();
    m.insert("path".into(), path_value(&e.path));
    m.insert("machine".into(), Value::String(e.machine.clone()));
    m.insert("is_static".into(), Value::Bool(e.is_static));
    m.insert("stripped".into(), Value::Bool(e.stripped));
    m.insert("interp".into(), opt_path(&e.interp));
    m.insert("section_count".into(), Value::Int(e.section_count as i64));
    m.insert("has_rwx_segment".into(), Value::Bool(e.has_rwx_segment));
    m.insert(
        "packer_hints".into(),
        Value::List(
            e.packer_hints
                .iter()
                .map(|s| Value::String(s.clone()))
                .collect(),
        ),
    );
    // Joined string for easy `contains` checks in manifests.
    m.insert(
        "packer_hints_joined".into(),
        Value::String(e.packer_hints.join(",").to_ascii_lowercase()),
    );
    m.insert("entry".into(), Value::String(e.entry.0.clone()));
    Value::Record(m)
}

fn preload_value(p: &PreloadObs) -> Value {
    let mut m = BTreeMap::new();
    m.insert("path".into(), path_value(&p.path));
    m.insert(
        "entries".into(),
        Value::List(p.entries.iter().map(path_value).collect()),
    );
    m.insert("present".into(), Value::Bool(p.present));
    Value::Record(m)
}

fn account_value(a: &AccountObs) -> Value {
    let mut m = BTreeMap::new();
    m.insert("username".into(), Value::String(a.username.clone()));
    m.insert("uid".into(), Value::Int(a.uid as i64));
    m.insert("gid".into(), Value::Int(a.gid as i64));
    m.insert("home".into(), path_value(&a.home));
    m.insert("shell".into(), path_value(&a.shell));
    m.insert("gecos".into(), Value::String(a.gecos.clone()));
    Value::Record(m)
}

fn ssh_host_key_value(k: &SshHostKeyObs) -> Value {
    let mut m = BTreeMap::new();
    m.insert("path".into(), path_value(&k.path));
    m.insert("key_type".into(), Value::String(k.key_type.clone()));
    m.insert("fingerprint".into(), Value::String(k.fingerprint.clone()));
    m.insert("changed".into(), Value::Bool(k.changed));
    Value::Record(m)
}

fn policy_value(p: &PolicyObs) -> Value {
    let mut m = BTreeMap::new();
    m.insert("code".into(), Value::String(p.code.clone()));
    m.insert("detail".into(), Value::String(p.detail.clone()));
    m.insert(
        "severity".into(),
        Value::String(format!("{:?}", p.severity).to_ascii_lowercase()),
    );
    Value::Record(m)
}

fn confidence_value(c: Confidence) -> Value {
    Value::String(
        match c {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
        .into(),
    )
}

fn path_value(p: &PathBytes) -> Value {
    Value::String(p.to_string_lossy())
}

fn opt_path(p: &Option<PathBytes>) -> Value {
    match p {
        Some(p) => path_value(p),
        None => Value::Null,
    }
}

fn shadow_entry_value(s: &ShadowEntryObs) -> Value {
    let mut m = BTreeMap::new();
    m.insert("username".into(), Value::String(s.username.clone()));
    m.insert("algorithm".into(), Value::String(s.algorithm.clone()));
    m.insert("empty_password".into(), Value::Bool(s.empty_password));
    m.insert("locked".into(), Value::Bool(s.locked));
    m.insert(
        "hash_fingerprint".into(),
        s.hash_fingerprint
            .as_ref()
            .map(|h| Value::String(h.clone()))
            .unwrap_or(Value::Null),
    );
    Value::Record(m)
}

fn sudo_rule_value(r: &SudoRuleObs) -> Value {
    let mut m = BTreeMap::new();
    m.insert("path".into(), path_value(&r.path));
    m.insert("line".into(), Value::String(r.line.clone()));
    m.insert("nopasswd".into(), Value::Bool(r.nopasswd));
    m.insert("all_commands".into(), Value::Bool(r.all_commands));
    Value::Record(m)
}

fn authorized_key_value(k: &AuthorizedKeyObs) -> Value {
    let mut m = BTreeMap::new();
    m.insert("path".into(), path_value(&k.path));
    m.insert("username".into(), Value::String(k.username.clone()));
    m.insert("key_type".into(), Value::String(k.key_type.clone()));
    m.insert("fingerprint".into(), Value::String(k.fingerprint.clone()));
    m.insert(
        "comment".into(),
        k.comment
            .as_ref()
            .map(|c| Value::String(c.clone()))
            .unwrap_or(Value::Null),
    );
    m.insert(
        "options".into(),
        Value::List(
            k.options
                .iter()
                .map(|o| Value::String(o.clone()))
                .collect(),
        ),
    );
    m.insert(
        "options_joined".into(),
        Value::String(k.options.join(",")),
    );
    m.insert(
        "bits".into(),
        k.bits
            .map(|b| Value::Int(b as i64))
            .unwrap_or(Value::Null),
    );
    Value::Record(m)
}

fn dir_anomaly_value(d: &DirAnomalyObs) -> Value {
    let mut m = BTreeMap::new();
    m.insert("path".into(), path_value(&d.path));
    m.insert("anomaly".into(), Value::String(d.anomaly.clone()));
    m.insert("detail".into(), Value::String(d.detail.clone()));
    m.insert("confidence".into(), confidence_value(d.confidence));
    Value::Record(m)
}

fn log_integrity_value(l: &LogIntegrityObs) -> Value {
    let mut m = BTreeMap::new();
    m.insert("path".into(), path_value(&l.path));
    m.insert("issue".into(), Value::String(l.issue.clone()));
    m.insert("detail".into(), Value::String(l.detail.clone()));
    Value::Record(m)
}

fn timestomp_value(t: &TimestompObs) -> Value {
    let mut m = BTreeMap::new();
    m.insert("path".into(), path_value(&t.path));
    m.insert(
        "btime".into(),
        t.btime.map(|b| Value::Int(b as i64)).unwrap_or(Value::Null),
    );
    m.insert("mtime".into(), Value::Int(t.mtime as i64));
    m.insert("ctime".into(), Value::Int(t.ctime as i64));
    m.insert(
        "btime_after_mtime".into(),
        Value::Bool(t.btime.is_some_and(|b| b > t.mtime)),
    );
    Value::Record(m)
}

fn file_meta_value(f: &FileMetaObs) -> Value {
    let mut m = BTreeMap::new();
    m.insert("path".into(), path_value(&f.path));
    m.insert("mode".into(), Value::Int(f.mode as i64));
    m.insert("uid".into(), Value::Int(f.uid as i64));
    m.insert("gid".into(), Value::Int(f.gid as i64));
    m.insert(
        "size".into(),
        f.size
            .as_u64()
            .map(|s| Value::Int(s as i64))
            .unwrap_or_else(|| Value::String(f.size.0.clone())),
    );
    m.insert("inode".into(), Value::String(f.inode.0.clone()));
    m.insert("nlink".into(), Value::Int(f.nlink as i64));
    m.insert("setuid".into(), Value::Bool(f.setuid));
    m.insert("setgid".into(), Value::Bool(f.setgid));
    m.insert("immutable".into(), Value::Bool(f.immutable));
    m.insert(
        "world_writable".into(),
        Value::Bool(f.mode & 0o002 != 0),
    );
    Value::Record(m)
}

fn ioc_hit_value(i: &IocHitObs) -> Value {
    let mut m = BTreeMap::new();
    m.insert("path".into(), path_value(&i.path));
    m.insert("ioc_kind".into(), Value::String(i.ioc_kind.clone()));
    m.insert("ioc_value".into(), Value::String(i.ioc_value.clone()));
    m.insert(
        "severity".into(),
        Value::String(format!("{:?}", i.severity).to_ascii_lowercase()),
    );
    Value::Record(m)
}

fn integrity_value(i: &IntegrityObs) -> Value {
    let mut m = BTreeMap::new();
    m.insert("path".into(), path_value(&i.path));
    m.insert("expected_hash".into(), Value::String(i.expected_hash.clone()));
    m.insert("actual_hash".into(), Value::String(i.actual_hash.clone()));
    m.insert(
        "package".into(),
        i.package
            .as_ref()
            .map(|p| Value::String(p.clone()))
            .unwrap_or(Value::Null),
    );
    Value::Record(m)
}

fn bpf_prog_value(b: &BpfProgObs) -> Value {
    let mut m = BTreeMap::new();
    m.insert("id".into(), Value::Int(b.id as i64));
    m.insert("prog_type".into(), Value::String(b.prog_type.clone()));
    m.insert(
        "name".into(),
        b.name
            .as_ref()
            .map(|n| Value::String(n.clone()))
            .unwrap_or(Value::Null),
    );
    m.insert(
        "tag".into(),
        b.tag
            .as_ref()
            .map(|t| Value::String(t.clone()))
            .unwrap_or(Value::Null),
    );
    m.insert("orphan".into(), Value::Bool(b.orphan));
    Value::Record(m)
}

fn scheduled_task_value(t: &ScheduledTaskObs) -> Value {
    let mut m = BTreeMap::new();
    m.insert("kind".into(), Value::String(t.kind.clone()));
    m.insert("path".into(), path_value(&t.path));
    m.insert(
        "user".into(),
        t.user
            .as_ref()
            .map(|u| Value::String(u.clone()))
            .unwrap_or(Value::Null),
    );
    m.insert(
        "schedule".into(),
        t.schedule
            .as_ref()
            .map(|s| Value::String(s.clone()))
            .unwrap_or(Value::Null),
    );
    m.insert("command".into(), Value::String(t.command.clone()));
    Value::Record(m)
}

fn service_value(s: &ServiceObs) -> Value {
    let mut m = BTreeMap::new();
    m.insert("name".into(), Value::String(s.name.clone()));
    m.insert("path".into(), path_value(&s.path));
    m.insert(
        "exec_start".into(),
        s.exec_start
            .as_ref()
            .map(|e| Value::String(e.clone()))
            .unwrap_or(Value::Null),
    );
    m.insert("unit_type".into(), Value::String(s.unit_type.clone()));
    Value::Record(m)
}

fn mount_value(mnt: &MountObs) -> Value {
    let mut m = BTreeMap::new();
    m.insert("device".into(), Value::String(mnt.device.clone()));
    m.insert("mountpoint".into(), path_value(&mnt.mountpoint));
    m.insert("fstype".into(), Value::String(mnt.fstype.clone()));
    m.insert("options".into(), Value::String(mnt.options.clone()));
    Value::Record(m)
}

fn utmp_session_value(u: &UtmpSessionObs) -> Value {
    let mut m = BTreeMap::new();
    m.insert("user".into(), Value::String(u.user.clone()));
    m.insert("line".into(), Value::String(u.line.clone()));
    m.insert("host".into(), Value::String(u.host.clone()));
    m.insert("pid".into(), Value::Int(u.pid as i64));
    m.insert("typ".into(), Value::Int(u.typ as i64));
    m.insert("time".into(), Value::Int(u.time as i64));
    Value::Record(m)
}

fn container_value(c: &ContainerObs) -> Value {
    let mut m = BTreeMap::new();
    m.insert("in_container".into(), Value::Bool(c.in_container));
    m.insert(
        "runtime".into(),
        c.runtime
            .as_ref()
            .map(|r| Value::String(r.clone()))
            .unwrap_or(Value::Null),
    );
    m.insert("privileged".into(), Value::Bool(c.privileged));
    m.insert("docker_sock_mounted".into(), Value::Bool(c.docker_sock_mounted));
    m.insert("host_pid_ns".into(), Value::Bool(c.host_pid_ns));
    Value::Record(m)
}
