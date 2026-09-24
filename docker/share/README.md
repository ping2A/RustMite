# Shareable Docker image

Image contents: `rustmite-server`, `rustmite-node`, `rustmite-cli`, check catalog (`checks/`), and fixtures.

## Use the image directly

```bash
# From a shared archive
gunzip -c rustmite-0.1.0.tar.gz | docker load

# Or from a registry
# docker pull your-registry/rustmite:0.1.0

docker run --rm -p 8080:8080 -p 8443:8443 rustmite:0.1.0
# → http://127.0.0.1:8080/
```

Persist store / TLS / vault:

```bash
docker run --rm -p 8080:8080 -p 8443:8443 \
  -v rustmite-data:/opt/rustmite/data \
  -v rustmite-tls:/opt/rustmite/tls \
  -v rustmite-vault:/opt/rustmite/vault \
  rustmite:0.1.0
```

Compose (same image, named volumes):

```bash
docker compose -f docker/share/docker-compose.yml up
```

Optional fixture-mode node (posts diamorphine findings):

```bash
docker compose -f docker/share/docker-compose.yml --profile with-node up
```

## Other entrypoints

```bash
# CLI against a bundled fixture
docker run --rm rustmite:0.1.0 cli scan-fixture \
  --fixture /opt/rustmite/fixtures/diamorphine-hidden-pid

# Help
docker run --rm rustmite:0.1.0 help
```

## Build & package (to share)

```bash
./scripts/share-image.sh
# → dist/rustmite-0.1.0.tar.gz
```

Or Compose build:

```bash
docker compose -f docker/share/docker-compose.yml build
```

Push to a registry:

```bash
./scripts/share-image.sh --push ghcr.io/you
```

Default CMD starts the server with `--no-tls` and `RUSTMITE_SEED_DEMO=0` /
`RUSTMITE_SCAN_SIM=0` (empty fleet, ready to configure).
For production-like TLS, drop `--no-tls` and mount `/opt/rustmite/tls` (or let the
server auto-generate certs into the volume).
