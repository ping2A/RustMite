# RustMite

<p align="center">
  <img src="assets/logo.png" alt="RustMite" width="280" />
</p>

Agentless Linux intrusion detection and forensics platform — pure Rust.

Nothing is installed on monitored hosts. A scanner node connects over SSH, delivers a
signed statically-linked probe into volatile memory, streams structured JSON results
back, and removes all trace of the probe.

> **Prime directive:** RustMite does not try to determine the truth about a compromised
> host. It determines whether the host is telling a consistent story.

## Workspace

| Crate | Role |
|---|---|
| `rustmite-sys` | Raw Linux syscalls + `ProcSource`/`FsSource` (fixture-testable) |
| `rustmite-proto` | Shared wire types (`no_std + alloc`) |
| `rustmite-analyze` | Pure analysis: entropy, ELF, hashing, parsers |
| `rustmite-collect` | Collectors (decloak, process, sockets, …) |
| `rustmite-probe` | Ephemeral target-side binary |
| `rustmite-loader` | Tiny stage-0 memfd loader |
| `rustmite-expr` | Check expression language |
| `rustmite-checks` | Check manifests + evaluation + baseline drift |
| `rustmite-transport` | SSH + two-stage probe delivery |
| `rustmite-crypto` | Signing, vault sealing |
| `rustmite-store` | In-memory + optional PostgreSQL repositories |
| `rustmite-notify` | Alert sinks (webhook, syslog, ndjson) |
| `rustmite-node` | Data-plane worker |
| `rustmite-server` | Control plane API |
| `rustmite-cli` | Operator CLI + standalone scanner |

Specification: [`docs/`](docs/). Visual walkthrough: [`docs/15-how-it-works.md`](docs/15-how-it-works.md). Operator console: [`docs/16-operator-console.md`](docs/16-operator-console.md).

## Quick start

```bash
# Unit + fixture tests
cargo test -p rustmite-proto -p rustmite-analyze -p rustmite-collect -p rustmite-expr -p rustmite-checks

# Evaluate seed checks against a fixture locally
cargo run -p rustmite-cli -- scan-fixture --fixture fixtures/diamorphine-hidden-pid

# Build Linux musl probes for x86_64 / i686 / aarch64 / armv7 (auto-picked by host arch)
cargo xtask build-probes --all

# M2 SSH transport matrix (Docker)
cargo xtask ssh-matrix up
cargo xtask ssh-matrix test

# M3/M4 control-plane e2e (server + fixture node → RM-PROC-0001)
cargo xtask e2e-stack
```

Local console (see `./dev.sh help`):

```bash
./dev.sh start
```

## Docker

### Use the image directly

If you already have `rustmite:<version>.tar.gz` (or pulled from a registry):

```bash
# From a shared archive
gunzip -c rustmite-0.1.0.tar.gz | docker load

# Or from a registry
# docker pull your-registry/rustmite:0.1.0

docker run --rm -p 8080:8080 -p 8443:8443 rustmite:0.1.0
# → http://127.0.0.1:8080/
```

Clean install (empty fleet). Stop with Ctrl+C. Persist data with a volume:

```bash
docker run --rm -p 8080:8080 -p 8443:8443 \
  -v rustmite-data:/opt/rustmite/data \
  rustmite:0.1.0
```

### Build & package (to share)

```bash
./scripts/share-image.sh
# → dist/rustmite-<version>.tar.gz
```

Details: [`docker/share/README.md`](docker/share/README.md).


