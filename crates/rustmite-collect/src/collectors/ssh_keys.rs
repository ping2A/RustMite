//! `ssh.keys` — authorized_keys for all passwd homes + host public keys.

use rustmite_analyze::{parse_authorized_key_line, parse_passwd};
use rustmite_proto::{
    AuthorizedKeyObs, CollectorCost, CollectorId, CollectorReport, Observation, PathBytes,
    SshHostKeyObs,
};

use crate::{emit, CollectCtx, CollectError, Collector, ObservationSink};

pub struct SshKeysCollector;

impl Collector for SshKeysCollector {
    fn id(&self) -> &'static str {
        CollectorId::SSH_KEYS.as_str()
    }

    fn cost(&self) -> CollectorCost {
        CollectorCost::Low
    }

    fn collect(
        &self,
        ctx: &CollectCtx<'_>,
        sink: &mut dyn ObservationSink,
    ) -> Result<CollectorReport, CollectError> {
        let mut count = 0u32;
        for (rel_path, username) in authorized_key_targets(ctx) {
            let data = match ctx.fs.read(&rel_path).or_else(|_| {
                ctx.proc
                    .read(&rel_path)
                    .or_else(|_| ctx.fs.read(rel_path.trim_start_matches('/')))
            }) {
                Ok(d) => d,
                Err(_) => continue,
            };
            count = count.saturating_add(emit_keys(ctx, sink, &rel_path, &username, &data)?);
        }
        count = count.saturating_add(emit_host_keys(ctx, sink)?);
        Ok(CollectorReport::complete(CollectorId::SSH_KEYS, count, 0))
    }
}

fn authorized_key_targets(ctx: &CollectCtx<'_>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let passwd = ctx
        .proc
        .read("etc/passwd")
        .or_else(|_| ctx.fs.read("etc/passwd"))
        .ok();
    if let Some(data) = passwd {
        let s = String::from_utf8_lossy(&data);
        for e in parse_passwd(&s) {
            let home = e.home.trim_start_matches('/');
            if home.is_empty() || home == "nonexistent" {
                continue;
            }
            out.push((
                format!("{home}/.ssh/authorized_keys"),
                e.username.clone(),
            ));
            out.push((
                format!("{home}/.ssh/authorized_keys2"),
                e.username,
            ));
        }
    }
    if out.is_empty() {
        out.push(("root/.ssh/authorized_keys".into(), "root".into()));
    }
    out.sort();
    out.dedup();
    out
}

fn emit_host_keys(
    ctx: &CollectCtx<'_>,
    sink: &mut dyn ObservationSink,
) -> Result<u32, CollectError> {
    let mut count = 0u32;
    let names = match ctx.fs.list_dir("etc/ssh") {
        Ok(ents) => ents
            .into_iter()
            .filter_map(|e| String::from_utf8(e.name).ok())
            .filter(|n| n.starts_with("ssh_host_") && n.ends_with(".pub"))
            .collect::<Vec<_>>(),
        Err(_) => vec![
            "ssh_host_ed25519_key.pub".into(),
            "ssh_host_rsa_key.pub".into(),
            "ssh_host_ecdsa_key.pub".into(),
        ],
    };
    for name in names {
        let rel = format!("etc/ssh/{name}");
        let data = match ctx.fs.read(&rel) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let s = String::from_utf8_lossy(&data);
        let line = match s.lines().next() {
            Some(l) => l,
            None => continue,
        };
        let parsed = match parse_authorized_key_line(line) {
            Ok(p) => p,
            Err(_) => continue,
        };
        emit(
            ctx,
            sink,
            Observation::SshHostKey(SshHostKeyObs {
                path: PathBytes::from(format!("/{rel}")),
                key_type: parsed.key_type,
                fingerprint: parsed.fingerprint,
                changed: false,
            }),
        )?;
        count = count.saturating_add(1);
    }
    Ok(count)
}

fn emit_keys(
    ctx: &CollectCtx<'_>,
    sink: &mut dyn ObservationSink,
    rel_path: &str,
    username: &str,
    data: &[u8],
) -> Result<u32, CollectError> {
    let s = String::from_utf8_lossy(data);
    let display_path = format!("/{}", rel_path.trim_start_matches('/'));
    let mut count = 0u32;
    for line in s.lines() {
        let parsed = match parse_authorized_key_line(line) {
            Ok(p) => p,
            Err(_) => continue,
        };
        emit(
            ctx,
            sink,
            Observation::AuthorizedKey(AuthorizedKeyObs {
                path: PathBytes::from(display_path.clone()),
                username: username.to_string(),
                key_type: parsed.key_type,
                fingerprint: parsed.fingerprint,
                comment: parsed.comment,
                options: parsed.options,
                bits: parsed.bits,
            }),
        )?;
        count = count.saturating_add(1);
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use rustmite_proto::{Budget, Limits, Observation};
    use rustmite_sys::{FixtureFs, FixtureProc};

    use super::*;
    use crate::{CollectCtx, VecSink};

    #[test]
    fn reads_all_passwd_homes() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n";
        let fs = FixtureFs::new()
            .with_file("etc/passwd", passwd)
            .with_file(
                "root/.ssh/authorized_keys",
                "ssh-ed25519 aGVsbG8= root@h\n",
            )
            .with_file(
                "home/alice/.ssh/authorized_keys",
                "ssh-ed25519 d29ybGQ= alice@h\n",
            );
        let proc = FixtureProc::new("/tmp/rustmite-ssh-keys-test");
        let b = Budget::new(&Limits::default(), 60_000, 0);
        let ctx = CollectCtx {
            proc: &proc,
            fs: &fs,
            pid_probe: None,
            budget: &b,
            euid: 0,
            self_pid: 1,
            now_ms: 0,
        };
        let mut sink = VecSink::new();
        let report = SshKeysCollector.collect(&ctx, &mut sink).expect("collect");
        assert_eq!(report.observations, 2);
        assert!(sink.observations.iter().any(|o| matches!(
            o,
            Observation::AuthorizedKey(k) if k.username == "alice"
        )));
    }
}
