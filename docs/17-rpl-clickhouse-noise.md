# RPL hunting, ClickHouse, and Noise XX

## ClickHouse

### Local development

Brought up automatically by `./dev.sh start` (`CLICKHOUSE=1` in `config/dev.env`). Disable with `CLICKHOUSE=0` or `./dev.sh start --no-clickhouse`.

```bash
./dev.sh start                 # starts ClickHouse + server
# or manually:
cd docker/clickhouse && docker compose up -d
```

The server auto-connects to `http://127.0.0.1:8123` (override with `RUSTMITE_CLICKHOUSE_URL`) and waits for readiness. With `--seed-demo` it inserts sample events when the table is empty.

Disable entirely: `RUSTMITE_CLICKHOUSE=0`.

### Shareable Docker image (embedded ClickHouse)

The packaged appliance image (`Dockerfile` / `./scripts/share-image.sh`) **includes ClickHouse**. On `server` start the entrypoint:

1. Starts ClickHouse inside the same container
2. Applies `docker/clickhouse/init.sql`
3. Points RustMite at `http://127.0.0.1:8123` (`rustmite` / `rustmite`)

```bash
./scripts/share-image.sh --x64
# → dist/rustmite-<version>-amd64.tar.gz

gunzip -c rustmite-0.1.0-amd64.tar.gz | docker load

docker run --rm -p 8080:8080 -p 8443:8443 -p 8123:8123 \
  -v rustmite-data:/opt/rustmite/data \
  -v rustmite-tls:/opt/rustmite/tls \
  -v rustmite-vault:/opt/rustmite/vault \
  -v rustmite-ch-data:/var/lib/clickhouse \
  rustmite:0.1.0
# → https://127.0.0.1:8080/   (admin / admin; accept self-signed cert)
# → ClickHouse HTTP :8123    (rustmite / rustmite)
```

| Port | Service |
|------|---------|
| 8080 | Operator console + `/v1/*` (HTTPS by default) |
| 8443 | Scanner node API (HTTPS) |
| 8123 | Embedded ClickHouse HTTP |

| Env | Default | Purpose |
|-----|---------|---------|
| `RUSTMITE_EMBEDDED_CLICKHOUSE` | `1` | Start ClickHouse in-process with the image |
| `RUSTMITE_CLICKHOUSE` | `1` | Server connects to ClickHouse (set `0` for JSON store only) |
| `RUSTMITE_CLICKHOUSE_URL` | `http://127.0.0.1:8123` | HTTP endpoint |
| `RUSTMITE_CLICKHOUSE_USER` / `_PASSWORD` / `_DB` | `rustmite` | Credentials / database |

Opt out of embedded ClickHouse (JSON fallback):

```bash
docker run --rm -p 8080:8080 -e RUSTMITE_EMBEDDED_CLICKHOUSE=0 rustmite:0.1.0
```

Compose (same appliance):

```bash
docker compose -f docker/share/docker-compose.yml up
```

Details: [`docker/share/README.md`](../docker/share/README.md).

Dev-only ClickHouse (separate container, no RustMite binaries): [`docker/clickhouse/`](../docker/clickhouse/).

## RPL (RustMite Pipe Language)
Pipe-oriented hunting language in `crates/rustmite-rpl`, compiled to ClickHouse SQL.
Operator console **RPL Hunt** (`/ui` → RPL Hunt) is a full search workspace (fields sidebar, histogram/timechart, results table, event inspector, SQL preview, language guide, saved queries).

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/hunt/rpl` | Execute RPL → `{engine, sql, count, columns, viz, rows, hint?}` |
| POST | `/v1/hunt/rpl/compile` | Compile only → `{sql, has_timechart, fields}` |
| GET | `/v1/hunt/rpl/fields` | Searchable field catalog |
| POST | `/v1/hunt/rpl/histogram` | Bucket counts for timeline (search clause only) |
| POST | `/v1/hunt` | Legacy expression hunt over stored observations |

`viz` is one of `timechart | stats | table | single_value`.

Language guide sources:
- Console: `crates/rustmite-server/static/assets/rpl-guide.js` (`window.RPL_GUIDE`)
- Docs: `docs/rpl-language-guide.ts`

## Noise XX
Pattern `Noise_XX_25519_ChaChaPoly_BLAKE2s` in `rustmite-transport::noise_xx`.
Server publishes fingerprint via `/v1/settings`. Node endpoint: `POST /v1/nodes/noise/xx`.
