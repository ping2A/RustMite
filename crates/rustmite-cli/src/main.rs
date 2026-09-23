//! RustMite operator CLI.
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use rustmite_checks::CheckEngine;
use rustmite_cli::{default_checks_dir, diamorphine_assertion, scan_fixture, validate_check_file};
use rustmite_proto::{CollectorSpec, ProbeMode};
use rustmite_transport::{
    remote_scan, HostKeyPolicy, HostKeyRecord, RemoteScanOpts, TransportError,
};

#[derive(Parser, Debug)]
#[command(name = "rustmite-cli", about = "RustMite operator CLI")]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Scan a recorded fixture tree and print JSON findings
    ScanFixture {
        #[arg(long)]
        fixture: PathBuf,
        /// Directory of check manifests (default: checks/)
        #[arg(long, default_value = "checks")]
        checks: PathBuf,
    },
    /// Scan a live host over SSH (delivers the musl probe)
    Scan {
        #[arg(long)]
        host: String,
        #[arg(long, default_value_t = 22)]
        port: u16,
        #[arg(long, default_value = "root")]
        user: String,
        /// Path to OpenSSH private key
        #[arg(long, short = 'i')]
        identity: PathBuf,
        /// Path to Linux musl rustmite-probe ELF (optional when --probe-dir / catalog is used)
        #[arg(long)]
        probe: Option<PathBuf>,
        /// Optional stage-0 loader ELF (enables Method A when host supports memfd)
        #[arg(long)]
        loader: Option<PathBuf>,
        /// Directory / search root of built probes (auto-picks Linux 64/32 by host arch)
        #[arg(long, env = "RUSTMITE_PROBE_DIR")]
        probe_dir: Option<PathBuf>,
        #[arg(long, default_value = "checks")]
        checks: PathBuf,
        /// Pin expected host-key fingerprint (SHA256:…)
        #[arg(long)]
        pin: Option<String>,
        /// Host key algorithm for --pin (default ssh-ed25519)
        #[arg(long, default_value = "ssh-ed25519")]
        pin_type: String,
        /// Trust-on-first-use when no pin is set
        #[arg(long, default_value_t = false)]
        tofu: bool,
        /// Probe mode=selftest (Hello+Summary only)
        #[arg(long, default_value_t = false)]
        selftest: bool,
        /// Print raw NDJSON from the probe as well
        #[arg(long, default_value_t = false)]
        raw: bool,
    },
    /// Scan using a TOML config file (standalone M8 path)
    ScanConfig {
        #[arg(long, short = 'c')]
        config: PathBuf,
    },
    /// Check-manifest utilities
    Checks {
        #[command(subcommand)]
        cmd: ChecksCmd,
    },
}

#[derive(Subcommand, Debug)]
enum ChecksCmd {
    /// Validate a single check TOML file (parse + compile where)
    Validate {
        #[arg(long)]
        path: PathBuf,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<ExitCode> {
    let args = Args::parse();
    match args.cmd {
        Cmd::ScanFixture { fixture, checks } => {
            let checks_dir = resolve_checks(checks);
            let result = scan_fixture(&fixture, &checks_dir)?;
            println!("{}", serde_json::to_string_pretty(&result.findings)?);
            if let Err(e) = diamorphine_assertion(&fixture, &result.findings) {
                eprintln!("error: {e}");
                return Ok(ExitCode::from(1));
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Scan {
            host,
            port,
            user,
            identity,
            probe,
            loader,
            probe_dir,
            checks,
            pin,
            pin_type,
            tofu,
            selftest,
            raw,
        } => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(async move {
                run_remote_scan(
                    host,
                    port,
                    user,
                    identity,
                    probe,
                    loader,
                    probe_dir,
                    checks,
                    pin,
                    pin_type,
                    tofu,
                    selftest,
                    raw,
                )
                .await
            })
        }
        Cmd::ScanConfig { config } => {
            let text = std::fs::read_to_string(&config)
                .with_context(|| format!("read config {}", config.display()))?;
            let cfg: ScanConfigFile = toml::from_str(&text).context("parse scan config")?;
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(async move {
                run_remote_scan(
                    cfg.host,
                    cfg.port.unwrap_or(22),
                    cfg.user.unwrap_or_else(|| "root".into()),
                    cfg.identity,
                    cfg.probe,
                    cfg.loader,
                    cfg.probe_dir,
                    cfg.checks.unwrap_or_else(|| PathBuf::from("checks")),
                    cfg.pin,
                    cfg.pin_type.unwrap_or_else(|| "ssh-ed25519".into()),
                    cfg.tofu.unwrap_or(false),
                    cfg.selftest.unwrap_or(false),
                    cfg.raw.unwrap_or(false),
                )
                .await
            })
        }
        Cmd::Checks {
            cmd: ChecksCmd::Validate { path },
        } => {
            validate_check_file(&path)?;
            println!("ok: {}", path.display());
            Ok(ExitCode::SUCCESS)
        }
    }
}

#[derive(Debug, serde::Deserialize)]
struct ScanConfigFile {
    host: String,
    port: Option<u16>,
    user: Option<String>,
    identity: PathBuf,
    probe: Option<PathBuf>,
    loader: Option<PathBuf>,
    probe_dir: Option<PathBuf>,
    checks: Option<PathBuf>,
    pin: Option<String>,
    pin_type: Option<String>,
    tofu: Option<bool>,
    selftest: Option<bool>,
    raw: Option<bool>,
}

fn resolve_checks(checks: PathBuf) -> PathBuf {
    if checks.as_os_str() == "checks" && !checks.is_dir() {
        default_checks_dir()
    } else {
        checks
    }
}

async fn run_remote_scan(
    host: String,
    port: u16,
    user: String,
    identity: PathBuf,
    probe: Option<PathBuf>,
    loader: Option<PathBuf>,
    probe_dir: Option<PathBuf>,
    checks: PathBuf,
    pin: Option<String>,
    pin_type: String,
    tofu: bool,
    selftest: bool,
    raw: bool,
) -> Result<ExitCode> {
    let catalog = if probe.is_some() {
        None
    } else {
        let mut roots = rustmite_transport::default_search_roots();
        if let Some(dir) = &probe_dir {
            roots.insert(0, dir.clone());
        }
        let cat = rustmite_transport::ProbeCatalog::discover(
            rustmite_transport::DEFAULT_LINUX_TARGETS,
            &roots,
        );
        if cat.is_empty() {
            bail!(
                "no agentless probes found — build with `cargo xtask build-probes --all` or pass --probe"
            );
        }
        Some(cat)
    };

    let probe_elf = match &probe {
        Some(p) => std::fs::read(p).with_context(|| format!("read probe {}", p.display()))?,
        None => Vec::new(),
    };
    let loader_elf = match loader {
        Some(p) => Some(std::fs::read(&p).with_context(|| format!("read loader {}", p.display()))?),
        None => None,
    };

    let policy = match pin {
        Some(fp) => HostKeyPolicy {
            pinned: vec![HostKeyRecord {
                key_type: pin_type,
                fingerprint: fp,
            }],
            allow_tofu: false,
        },
        None => HostKeyPolicy {
            pinned: vec![],
            allow_tofu: tofu,
        },
    };
    if policy.pinned.is_empty() && !policy.allow_tofu {
        bail!("provide --pin SHA256:… or --tofu");
    }

    let collectors = if selftest {
        vec![]
    } else {
        vec![
            CollectorSpec::new("decloak.process"),
            CollectorSpec::new("process.inventory"),
            CollectorSpec::new("persistence.preload"),
            CollectorSpec::new("persistence.accounts"),
            CollectorSpec::new("modules.lkm"),
            CollectorSpec::new("net.sockets"),
            CollectorSpec::new("recon.inventory"),
        ]
    };

    let result = match remote_scan(RemoteScanOpts {
        host: &host,
        port,
        username: &user,
        credential: rustmite_transport::SshCredential::PublicKey {
            identity: &identity,
        },
        policy,
        probe_elf: &probe_elf,
        loader_elf: loader_elf.as_deref(),
        probe_catalog: catalog.as_ref(),
        collectors,
        mode: if selftest {
            ProbeMode::Selftest
        } else {
            ProbeMode::Scan
        },
        deadline_ms: 60_000,
        limits: rustmite_proto::Limits::default(),
        timeouts: Default::default(),
        sudo: Default::default(),
    })
    .await
    {
        Ok(r) => r,
        Err(TransportError::HostKeyChanged { expected, got }) => {
            eprintln!(
                "RM-POL-0001 host key changed: expected {expected}, got {got} — scan refused"
            );
            return Ok(ExitCode::from(2));
        }
        Err(e) => return Err(e.into()),
    };

    if let Some(hk) = &result.presented_host_key {
        eprintln!(
            "host_key {} {} delivery={:?} arch={:?} kernel={} probe={}",
            hk.key_type,
            hk.fingerprint,
            result.delivery.method,
            result.fingerprint.arch,
            result.fingerprint.kernel,
            result
                .probe_triple
                .as_deref()
                .or(result.probe_arch.as_deref())
                .unwrap_or("(fixed)")
        );
    }

    if raw {
        print!("{}", result.raw_stdout);
        if !result.raw_stderr.is_empty() {
            eprint!("{}", result.raw_stderr);
        }
    }

    let observations: Vec<_> = result
        .normalised
        .observations
        .into_iter()
        .map(|(_, _, o)| o)
        .collect();

    if selftest {
        let hello_ok = result.normalised.hello.is_some();
        let summary_ok = result.normalised.summary.is_some();
        println!(
            "{}",
            serde_json::json!({
                "selftest": hello_ok && summary_ok,
                "hello": hello_ok,
                "summary": summary_ok,
                "delivery": format!("{:?}", result.delivery.method),
                "outcome": format!("{:?}", result.normalised.outcome),
            })
        );
        return Ok(if hello_ok && summary_ok {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        });
    }

    let checks_dir = resolve_checks(checks);
    let engine = CheckEngine::from_dir(&checks_dir)
        .with_context(|| format!("load checks from {}", checks_dir.display()))?;
    let findings = engine.evaluate(&observations);
    println!("{}", serde_json::to_string_pretty(&findings)?);
    Ok(ExitCode::SUCCESS)
}
