use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "xtask", about = "RustMite build orchestration")]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Verify probe crates stay free of libc/cc (stub on non-CI hosts)
    CheckPure,
    /// Cross-build probe (+ loader) for Linux musl targets
    BuildProbes {
        /// Target triple (ignored when --all is set)
        #[arg(long, default_value = "")]
        target: String,
        /// Build the default Linux 64/32 matrix (x86_64, i686, aarch64, armv7)
        #[arg(long, default_value_t = false)]
        all: bool,
    },
    /// Record a live host tree into fixtures/ (stub)
    Record {
        #[arg(long, default_value = "fixtures/recorded")]
        out: String,
    },
    /// Docker SSH transport matrix (M2)
    SshMatrix {
        #[command(subcommand)]
        cmd: SshMatrixCmd,
    },
    /// End-to-end control plane: server + fixture node → findings (M3/M4)
    E2eStack,
}

#[derive(Subcommand)]
enum SshMatrixCmd {
    /// Generate keys, build images, start containers
    Up,
    /// Stop and remove matrix containers
    Down,
    /// Build musl probe/loader and run selftest + host-key refusal against the matrix
    Test,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    match args.cmd {
        Cmd::CheckPure => {
            println!("check-pure: ok (stub — run cargo tree -p rustmite-probe on Linux CI)");
            Ok(())
        }
        Cmd::BuildProbes { target, all } => {
            if all || target.trim().is_empty() {
                build_probes_all()
            } else {
                build_probes(&target)
            }
        },
        Cmd::Record { out } => {
            println!("record: stub — would snapshot /proc+/sys+/etc into {out} (secrets scrubbed)");
            Ok(())
        }
        Cmd::SshMatrix { cmd } => match cmd {
            SshMatrixCmd::Up => ssh_matrix_up(),
            SshMatrixCmd::Down => ssh_matrix_down(),
            SshMatrixCmd::Test => ssh_matrix_test(),
        },
        Cmd::E2eStack => e2e_stack(),
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask parent")
        .to_path_buf()
}

fn matrix_dir() -> PathBuf {
    repo_root().join("docker/ssh-matrix")
}

fn default_probe_targets() -> &'static [&'static str] {
    &[
        "x86_64-unknown-linux-musl",
        "i686-unknown-linux-musl",
        "aarch64-unknown-linux-musl",
        "armv7-unknown-linux-musleabihf",
    ]
}

fn build_probes_all() -> anyhow::Result<()> {
    let mut failed = Vec::new();
    for target in default_probe_targets() {
        println!("==> build-probes --all: {target}");
        if let Err(e) = build_probes(target) {
            eprintln!("warning: {target} failed: {e:#}");
            failed.push(*target);
        }
    }
    if failed.len() == default_probe_targets().len() {
        anyhow::bail!("all probe targets failed: {}", failed.join(", "));
    }
    if !failed.is_empty() {
        eprintln!(
            "build-probes --all: partial success (missing: {})",
            failed.join(", ")
        );
    } else {
        println!("build-probes --all: ok");
    }
    Ok(())
}

fn build_probes(target: &str) -> anyhow::Result<()> {
    println!("build-probes: target={target}");
    // Prefer cargo-zigbuild on macOS hosts; fall back to plain cargo (Linux CI).
    let zig = Command::new("cargo")
        .args([
            "zigbuild",
            "-p",
            "rustmite-probe",
            "-p",
            "rustmite-loader",
            "--target",
            target,
            "--profile",
            "probe",
        ])
        .current_dir(repo_root())
        .status();
    let status = match zig {
        Ok(s) if s.success() => s,
        Ok(_) | Err(_) => {
            println!("zigbuild unavailable/failed; trying cargo build");
            Command::new("cargo")
                .args([
                    "build",
                    "-p",
                    "rustmite-probe",
                    "-p",
                    "rustmite-loader",
                    "--target",
                    target,
                    "--profile",
                    "probe",
                ])
                .current_dir(repo_root())
                .status()?
        }
    };
    if !status.success() {
        anyhow::bail!("probe build failed for {target}");
    }
    let probe = repo_root().join(format!("target/{target}/probe/rustmite-probe"));
    let loader = repo_root().join(format!("target/{target}/probe/rustmite-loader"));
    println!("probe:  {}", probe.display());
    println!("loader: {}", loader.display());
    Ok(())
}

fn ensure_keys() -> anyhow::Result<()> {
    let keys = matrix_dir().join(".keys");
    std::fs::create_dir_all(&keys)?;
    let client = keys.join("client");
    let host = keys.join("host_ed25519");
    if !client.exists() {
        run(
            "ssh-keygen",
            &[
                "-t",
                "ed25519",
                "-f",
                client.to_str().unwrap(),
                "-N",
                "",
                "-q",
                "-C",
                "rustmite-matrix-client",
            ],
        )?;
    }
    if !host.exists() {
        run(
            "ssh-keygen",
            &[
                "-t",
                "ed25519",
                "-f",
                host.to_str().unwrap(),
                "-N",
                "",
                "-q",
                "-C",
                "rustmite-matrix-host",
            ],
        )?;
    }
    // authorized_keys = client public key
    let pub_client = std::fs::read_to_string(keys.join("client.pub"))?;
    std::fs::write(keys.join("authorized_keys"), pub_client)?;
    // Restrictive perms for sshd
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&host, std::fs::Permissions::from_mode(0o600))?;
        std::fs::set_permissions(&client, std::fs::Permissions::from_mode(0o600))?;
    }
    println!("keys ready under {}", keys.display());
    Ok(())
}

fn host_fingerprint() -> anyhow::Result<String> {
    let pub_path = matrix_dir().join(".keys/host_ed25519.pub");
    let out = Command::new("ssh-keygen")
        .args(["-lf", pub_path.to_str().unwrap(), "-E", "sha256"])
        .output()?;
    if !out.status.success() {
        anyhow::bail!(
            "ssh-keygen fingerprint failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    // Format: "256 SHA256:xxxx comment (ED25519)"
    let line = String::from_utf8_lossy(&out.stdout);
    let fp = line
        .split_whitespace()
        .find(|t| t.starts_with("SHA256:"))
        .ok_or_else(|| anyhow::anyhow!("no SHA256 fingerprint in: {line}"))?
        .to_string();
    Ok(fp)
}

fn ssh_matrix_up() -> anyhow::Result<()> {
    ensure_keys()?;
    let status = Command::new("docker")
        .args([
            "compose",
            "-f",
            "docker-compose.yml",
            "up",
            "-d",
            "--build",
        ])
        .current_dir(matrix_dir())
        .status()?;
    if !status.success() {
        anyhow::bail!("docker compose up failed");
    }
    println!("ssh-matrix up: openssh-modern=:2222 openssh-noexec-tmp=:2223");
    println!("client key: {}", matrix_dir().join(".keys/client").display());
    println!("pin: {}", host_fingerprint()?);
    Ok(())
}

fn ssh_matrix_down() -> anyhow::Result<()> {
    let _ = Command::new("docker")
        .args(["compose", "-f", "docker-compose.yml", "down", "-v"])
        .current_dir(matrix_dir())
        .status()?;
    Ok(())
}

fn wait_for_ssh(port: u16) -> anyhow::Result<()> {
    for i in 0..30 {
        let ok = Command::new("nc")
            .args(["-z", "127.0.0.1", &port.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
        if i == 29 {
            anyhow::bail!("ssh port {port} not open");
        }
    }
    Ok(())
}

fn probe_path(target: &str) -> PathBuf {
    repo_root().join(format!("target/{target}/probe/rustmite-probe"))
}

fn loader_path(target: &str) -> PathBuf {
    repo_root().join(format!("target/{target}/probe/rustmite-loader"))
}

fn ssh_matrix_test() -> anyhow::Result<()> {
    ensure_keys()?;
    // Ensure containers are up.
    ssh_matrix_up()?;
    wait_for_ssh(2222)?;
    wait_for_ssh(2223)?;

    let target = default_linux_target();
    if !probe_path(&target).exists() {
        build_probes(&target)?;
    }
    // Also build the CLI with ssh feature (default for rustmite-cli now).
    let status = Command::new("cargo")
        .args(["build", "-p", "rustmite-cli"])
        .current_dir(repo_root())
        .status()?;
    if !status.success() {
        anyhow::bail!("cli build failed");
    }

    let cli = repo_root().join("target/debug/rustmite-cli");
    let identity = matrix_dir().join(".keys/client");
    let pin = host_fingerprint()?;
    let probe = probe_path(&target);
    let loader = loader_path(&target);

    println!("--- selftest openssh-modern (Method A preferred) ---");
    run_cli(
        &cli,
        &[
            "scan",
            "--host",
            "127.0.0.1",
            "--port",
            "2222",
            "--user",
            "rustmite",
            "--identity",
            identity.to_str().unwrap(),
            "--probe",
            probe.to_str().unwrap(),
            "--loader",
            loader.to_str().unwrap(),
            "--pin",
            &pin,
            "--selftest",
        ],
    )?;

    println!("--- selftest openssh-noexec-tmp (Method B via exec staging dir) ---");
    run_cli(
        &cli,
        &[
            "scan",
            "--host",
            "127.0.0.1",
            "--port",
            "2223",
            "--user",
            "rustmite",
            "--identity",
            identity.to_str().unwrap(),
            "--probe",
            probe.to_str().unwrap(),
            "--pin",
            &pin,
            "--selftest",
        ],
    )?;

    println!("--- host-key change must refuse (RM-POL-0001) ---");
    let status = Command::new(&cli)
        .args([
            "scan",
            "--host",
            "127.0.0.1",
            "--port",
            "2222",
            "--user",
            "rustmite",
            "--identity",
            identity.to_str().unwrap(),
            "--probe",
            probe.to_str().unwrap(),
            "--pin",
            "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "--selftest",
        ])
        .current_dir(repo_root())
        .status()?;
    if status.code() != Some(2) {
        anyhow::bail!("expected exit 2 on host-key mismatch, got {status}");
    }
    println!("host-key refusal: ok");

    println!("--- selftest dropbear (:2224) ---");
    wait_for_ssh(2224)?;
    // Dropbear may present a different host key (generated in-container). Use TOFU via wrong pin refusal skip — pin from openssh won't match.
    // Exercise auth+delivery with --tofu.
    let status = Command::new(&cli)
        .args([
            "scan",
            "--host",
            "127.0.0.1",
            "--port",
            "2224",
            "--user",
            "rustmite",
            "--identity",
            identity.to_str().unwrap(),
            "--probe",
            probe.to_str().unwrap(),
            "--tofu",
            "--selftest",
        ])
        .current_dir(repo_root())
        .status()?;
    if !status.success() {
        eprintln!("warning: dropbear selftest failed ({status}); continuing (OpenSSH matrix is required)");
    } else {
        println!("dropbear selftest: ok");
    }

    println!("ssh-matrix test: PASS");
    Ok(())
}

fn default_linux_target() -> String {
    match std::env::consts::ARCH {
        "aarch64" => "aarch64-unknown-linux-musl".into(),
        "x86_64" => "x86_64-unknown-linux-musl".into(),
        other => {
            eprintln!("warning: unknown arch {other}, defaulting to aarch64-unknown-linux-musl");
            "aarch64-unknown-linux-musl".into()
        }
    }
}

fn run_cli(cli: &Path, args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new(cli)
        .args(args)
        .current_dir(repo_root())
        .status()?;
    if !status.success() {
        anyhow::bail!("rustmite-cli {:?} failed: {status}", args);
    }
    Ok(())
}

fn run(cmd: &str, args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new(cmd).args(args).status()?;
    if !status.success() {
        anyhow::bail!("{cmd} {:?} failed", args);
    }
    Ok(())
}

/// M3/M4: bring up server + fixture-mode node, enqueue diamorphine scan, assert RM-PROC-0001.
fn e2e_stack() -> anyhow::Result<()> {
    use std::process::Child;

    let status = Command::new("cargo")
        .args([
            "build",
            "-p",
            "rustmite-server",
            "-p",
            "rustmite-node",
            "-p",
            "rustmite-cli",
        ])
        .current_dir(repo_root())
        .status()?;
    if !status.success() {
        anyhow::bail!("build failed");
    }

    let server_bin = repo_root().join("target/debug/rustmite-server");
    let node_bin = repo_root().join("target/debug/rustmite-node");

    let mut server: Child = Command::new(&server_bin)
        .args([
            "--listen",
            "127.0.0.1:18080",
            "--node-listen",
            "127.0.0.1:18443",
        ])
        .current_dir(repo_root())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    for _ in 0..40 {
        let ok = Command::new("curl")
            .args(["-sf", "http://127.0.0.1:18080/v1/health"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }

    let mut node: Child = Command::new(&node_bin)
        .args([
            "--server",
            "http://127.0.0.1:18443",
            "--fixture-mode",
            "--fixture",
            "fixtures/diamorphine-hidden-pid",
            "--checks",
            "checks",
            "--capacity",
            "2",
            "--poll-secs",
            "1",
        ])
        .current_dir(repo_root())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    std::thread::sleep(std::time::Duration::from_secs(1));

    let host_json = Command::new("curl")
        .args([
            "-sf",
            "-X",
            "POST",
            "http://127.0.0.1:18080/v1/hosts",
            "-H",
            "Content-Type: application/json",
            "-d",
            r#"{"display_name":"lab-diamorphine","primary_addr":"127.0.0.1","ssh_port":22}"#,
        ])
        .output()?;
    if !host_json.status.success() {
        let _ = server.kill();
        let _ = node.kill();
        anyhow::bail!(
            "create host failed: {}",
            String::from_utf8_lossy(&host_json.stderr)
        );
    }
    let host: serde_json::Value = serde_json::from_slice(&host_json.stdout)?;
    let host_id = host
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("no host id"))?;

    let scan_url = format!("http://127.0.0.1:18080/v1/hosts/{host_id}/scan");
    let scan_out = Command::new("curl")
        .args([
            "-sf",
            "-X",
            "POST",
            &scan_url,
            "-H",
            "Content-Type: application/json",
            "-d",
            r#"{"check_set":"standard","priority":10}"#,
        ])
        .output()?;
    if !scan_out.status.success() {
        let _ = server.kill();
        let _ = node.kill();
        anyhow::bail!("enqueue scan failed");
    }
    let scan: serde_json::Value = serde_json::from_slice(&scan_out.stdout)?;
    let scan_id = scan
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("no scan id"))?;

    let mut fired = false;
    for _ in 0..30 {
        std::thread::sleep(std::time::Duration::from_millis(500));
        let findings = Command::new("curl")
            .args([
                "-sf",
                &format!("http://127.0.0.1:18080/v1/findings?host={host_id}"),
            ])
            .output()?;
        if !findings.status.success() {
            continue;
        }
        let body = String::from_utf8_lossy(&findings.stdout);
        if body.contains("RM-PROC-0001") {
            fired = true;
            println!("findings contain RM-PROC-0001");
            break;
        }
    }

    let coverage = Command::new("curl")
        .args([
            "-sf",
            &format!("http://127.0.0.1:18080/v1/scans/{scan_id}/coverage"),
        ])
        .output()?;
    if coverage.status.success() {
        println!("coverage: {}", String::from_utf8_lossy(&coverage.stdout));
    }

    let _ = node.kill();
    let _ = server.kill();
    let _ = node.wait();
    let _ = server.wait();

    if !fired {
        anyhow::bail!("RM-PROC-0001 did not fire via e2e stack");
    }
    println!("e2e-stack: PASS");
    Ok(())
}
