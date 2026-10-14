# Shareable Docker image

Appliance image: `rustmite-server`, `rustmite-node`, `rustmite-cli`, check catalog,
fixtures, **embedded ClickHouse**, and **agentless probe/loader binaries**
(`x86_64`, `i686`, `aarch64`, `armv7` musl) under `/opt/rustmite/probes/`.

`docker build` / `./scripts/share-image.sh` only **compile and package** the image.
ClickHouse + the control plane start later, on **`docker run`** (or Compose `up`).
Startup lines like `Starting embedded ClickHouse` / `ClickHouse connected` are
runtime logs, not build logs.

## Use the image directly

```bash
# From a shared archive
gunzip -c rustmite-0.1.0-amd64.tar.gz | docker load

# Or from a registry
# docker pull your-registry/rustmite:0.1.0

docker run --rm -p 8080:8080 -p 8443:8443 -p 8123:8123 \
  -v rustmite-data:/opt/rustmite/data \
  -v rustmite-tls:/opt/rustmite/tls \
  -v rustmite-vault:/opt/rustmite/vault \
  -v rustmite-ch-data:/var/lib/clickhouse \
  rustmite:0.1.0
# → https://127.0.0.1:8080/  (admin / admin; accept the self-signed cert)
# → ClickHouse HTTP :8123   (rustmite / rustmite)
```

The shipped image keeps **ClickHouse and the control-plane store empty**
(`RUSTMITE_SEED_DEMO=0`; `/var/lib/clickhouse` wiped at build). Schema is applied
on first start from `docker/clickhouse/init.sql` — no demo events are baked in.

**Hosts live in the ClickHouse volume, not in the image.** Loading a new
`rustmite:…` tag only replaces binaries. To keep your fleet across upgrades you
**must** remount the same named volumes every run (as above). Compose uses fixed
volume names (`rustmite-ch-data`, `rustmite-data`, …) so `docker compose up` and
`docker run -v rustmite-ch-data:…` share one database.

Without those `-v` mounts (or with `docker run --rm` and only anonymous volumes),
each new container starts empty. Wipe deliberately with
`docker volume rm rustmite-ch-data rustmite-data rustmite-tls rustmite-vault`.

On start the entrypoint brings up ClickHouse, applies the schema, ensures a fleet
credential keypair under `/opt/rustmite/vault/cred.{priv,pub}` (so SSH
password/identity hosts can be sealed without a separate node), starts the control
plane against `http://127.0.0.1:8123`, then starts an **embedded scanner node** that
registers with the local control plane (disable with `RUSTMITE_EMBEDDED_NODE=0`).

Agentless probes ship in the image (`RUSTMITE_PROBE_DIR=/opt/rustmite/probes`).
`./scripts/share-image.sh` runs `scripts/stage-share-probes.sh` first so all four
arches are present (build fails if any are missing):

```text
/opt/rustmite/probes/x86_64/{rustmite-probe,rustmite-loader}
/opt/rustmite/probes/i686/{rustmite-probe,rustmite-loader}
/opt/rustmite/probes/aarch64/{rustmite-probe,rustmite-loader}
/opt/rustmite/probes/armv7/{rustmite-probe,rustmite-loader}
```

On container start the entrypoint prints `OK` / `MISSING` for each arch.
`rustmite-node` and Settings → Versions use that directory by default.

HTTPS is on by default (self-signed cert under `/opt/rustmite/tls`). Publish
**8080** (operator console + `/v1/*`), **8443** (scanner nodes), and **8123**
(ClickHouse, optional).

Disable embedded ClickHouse (JSON store fallback) or the co-located scanner node:

```bash
docker run --rm -p 8080:8080 -e RUSTMITE_EMBEDDED_CLICKHOUSE=0 rustmite:0.1.0
docker run --rm -p 8080:8080 -e RUSTMITE_EMBEDDED_NODE=0 rustmite:0.1.0
```

Cleartext lab mode:

```bash
docker run --rm -p 8080:8080 -p 8443:8443 -p 8123:8123 \
  rustmite:0.1.0 server --no-tls
```

## Compose

```bash
docker compose -f docker/share/docker-compose.yml up
```

Optional fixture-mode node:

```bash
docker compose -f docker/share/docker-compose.yml --profile with-node up
```

## Other entrypoints

```bash
docker run --rm rustmite:0.1.0 cli scan-fixture \
  --fixture /opt/rustmite/fixtures/diamorphine-hidden-pid

docker run --rm rustmite:0.1.0 help
```

## Build & package (to share)

```bash
./scripts/share-image.sh --x64
# → dist/rustmite-0.1.0-amd64.tar.gz

./scripts/share-image.sh --tag 0.2.0 --x64
./scripts/share-image.sh --x64 --push ghcr.io/you
```

Or:

```bash
docker compose -f docker/share/docker-compose.yml build
```
