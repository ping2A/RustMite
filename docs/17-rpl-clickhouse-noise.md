# RPL hunting, ClickHouse, and Noise XX

## ClickHouse
Brought up automatically by `./dev.sh start` (`CLICKHOUSE=1` in `config/dev.env`). Disable with `CLICKHOUSE=0` or `./dev.sh start --no-clickhouse`.

```bash
./dev.sh start                 # starts ClickHouse + server
# or manually:
cd docker/clickhouse && docker compose up -d
```

The server auto-connects to `http://127.0.0.1:8123` (override with `RUSTMITE_CLICKHOUSE_URL`) and waits for readiness. With `--seed-demo` it inserts sample events when the table is empty.

Disable entirely: `RUSTMITE_CLICKHOUSE=0`.

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
