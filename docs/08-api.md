# 08 — API (REST + WebSocket + Node Protocol)

Three surfaces: the **operator/API** (REST + WS), the **node protocol** (server↔node), and **egress sinks** (SIEM/webhook). Built with `axum`. Transport security is **TLS 1.3 via `rustls` by default**. On first start without `--tls-cert`/`--tls-key`, the server auto-generates a self-signed pair under `.dev/tls/` (SANs: `localhost`, `127.0.0.1`, `::1`) and reuses it on subsequent runs. Pass `--no-tls` (or `RUSTMITE_NO_TLS=1`) for cleartext local debugging; pass your own PEMs for production.

```bash
# Default: HTTPS with auto-generated self-signed certs in .dev/tls/
cargo run -p rustmite-server -- --listen 127.0.0.1:8080 --seed-demo

# Production PEMs + optional node mTLS
cargo run -p rustmite-server -- \
  --listen 0.0.0.0:443 --node-listen 0.0.0.0:8443 \
  --tls-cert /etc/rustmite/tls/cert.pem \
  --tls-key /etc/rustmite/tls/key.pem \
  --node-tls-client-ca /etc/rustmite/tls/clients-ca.pem
```

Operator and node share the same cert/key by default; override with `--node-tls-cert` / `--node-tls-key`. When `--node-tls-client-ca` is set, the node listener requires a client certificate signed by that CA.## 1. Conventions
- Base path `/v1`. JSON request/response; NDJSON for streams/exports.
- `Content-Type: application/json`; errors follow RFC 9457 (`application/problem+json`).
- Idempotency: mutating POSTs accept `Idempotency-Key`.
- Pagination: cursor-based (`?cursor=&limit=`), `limit ≤ 500`.
- Every response carries `X-Request-Id`; correlates with `tracing` span.
- OpenAPI 3.1 document served at `/v1/openapi.json`, generated from types (e.g. `utoipa`).

## 2. AuthN / AuthZ
- **Operators (default on)**: password login + optional per-user TOTP and/or YubiKey (WebAuthn/FIDO2) MFA → opaque session Bearer (`Authorization: Bearer …`). Passwords hashed with Argon2. Self-service password change requires the current password and revokes other sessions. Store: file-backed users/sessions (see `16-operator-console.md`). Disable with `RUSTMITE_REQUIRE_AUTH=0` for local open mode.
- **Auth endpoints**: `GET /v1/auth/status`, `POST /v1/auth/login`, `POST /v1/auth/mfa`, `POST /v1/auth/webauthn/login/{begin,finish}`, `POST /v1/auth/logout`, `GET /v1/auth/me`, `POST /v1/auth/password`, `POST /v1/auth/totp/{setup,enable,disable}`, `POST /v1/auth/webauthn/register/{begin,finish}`, `DELETE /v1/auth/webauthn/credentials/{id}`, `GET|POST /v1/auth/users`, `PATCH|DELETE /v1/auth/users/{id}` (admin).
- **Legacy API token**: optional `RUSTMITE_API_TOKEN` shared Bearer (admin-equivalent) for scripts.
- **Nodes**: mutual TLS. Node client cert fingerprint is registered in `nodes.cert_fingerprint`. Node endpoints are on a **separate listener/port** (8443) from the operator API (443), so operator credentials can never be used on node endpoints and vice-versa.
- **RBAC roles**: `viewer`, `analyst`, `admin` (console today); design also reserves `responder` / `auditor`. Admin-only: user CRUD.

## 3. Host & scan endpoints

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/v1/hosts` | viewer | list/filter hosts (`?label=env:prod&outcome=failed`) |
| POST | `/v1/hosts` | admin | register a host (addr, port, credential ref, labels) |
| POST | `/v1/hosts/test` | admin | quick SSH connectivity test (TCP/banner + optional key auth); can persist `auth_status` |
| POST | `/v1/credentials/ssh-identity` | admin | upload SSH private key PEM → `.dev/ssh-identities/` path for tests |
| GET | `/v1/hosts/{id}` | viewer | host detail incl. last scan, coverage, open findings |
| PATCH | `/v1/hosts/{id}` | admin | labels, credential ref, schedule overrides |
| DELETE | `/v1/hosts/{id}` | admin | decommission (cascades findings/scans for that host) |
| POST | `/v1/hosts/delete` | admin | bulk delete `{ host_ids: [...] }` |
| POST | `/v1/hosts/{id}/scan` | analyst | trigger an on-demand scan (`{check_set, priority}`) → `scan_id` |
| GET | `/v1/hosts/{id}/coverage` | viewer | applicable/passed/na per check, last success age |
| POST | `/v1/hosts/{id}/baseline` | admin | capture/refresh baseline (`{kinds:[...]}`) |
| GET | `/v1/ssh/summary` | viewer | SSH Hunter dashboard (keys, reuse, weak, zones) |
| GET | `/v1/ssh/keys` | viewer | Key Investigation (`?q=&tag=&reused=&weak=`) |
| GET | `/v1/ssh/keys/{fingerprint}` | viewer | Key detail + placements |
| POST | `/v1/ssh/keys` | analyst | Tag Workbench bulk tag (`{fingerprints,add,remove,set}`) |
| GET | `/v1/ssh/users` | viewer | User Investigation |
| GET | `/v1/ssh/hosts` | viewer | Host Investigation |
| GET | `/v1/ssh/graph` | viewer | key↔user↔host graph nodes/edges |
| GET | `/v1/ssh/tags` | viewer | unique key tags |
| GET/POST | `/v1/ssh/zones` | admin | list / create security zones |
| DELETE | `/v1/ssh/zones/{id}` | admin | delete zone |
| GET | `/v1/scans/{id}` | viewer | scan meta + outcome + delivery report |
| GET | `/v1/scans/{id}/observations` | analyst | NDJSON stream of stored observations (retro-hunt) |

## 4. Findings & hunting

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/v1/findings` | viewer | filter by `host,severity,confidence,check_id,status,attack,since` |
| GET | `/v1/findings/{id}` | viewer | full finding + evidence + linked observation |
| POST | `/v1/findings/{id}/ack` | analyst | acknowledge |
| POST | `/v1/findings/{id}/suppress` | analyst | create time-boxed allowlist entry (`{scope,expires,reason}`) |
| POST | `/v1/findings/{id}/resolve` | analyst | mark resolved |
| GET | `/v1/incidents` | viewer | correlated groups (`correlation_id`) |
| POST | `/v1/hunt` | analyst | run an ad-hoc expression (`05` language) over stored observations across hosts/time → NDJSON. **Retro-hunt** without rescanning. |
| POST | `/v1/hunt/rpl` | analyst | **RPL** pipe query → ClickHouse; body `{query, time_from?, time_to?, limit?}` → `{engine, sql, count, columns, viz, rows, hint?}`. `viz`: `timechart\|stats\|table\|single_value`. |
| POST | `/v1/hunt/rpl/compile` | analyst | Compile RPL → `{sql, has_timechart, fields}` without executing |
| GET | `/v1/hunt/rpl/fields` | viewer | Searchable field catalog for the Hunt sidebar |
| POST | `/v1/hunt/rpl/histogram` | analyst | Bucketed event counts for the Hunt timeline (`{buckets, span_minutes, sql}`) |
| POST | `/v1/checks/validate` | analyst | type-check a candidate check manifest; returns errors + a dry-run over recent observations |

Example hunt:
```json
POST /v1/hunt
{ "match":"process",
  "where":"process.exe_memfd == true or (process.exe_deleted and process.uids[1]==0)",
  "since":"-7d", "hosts":{"label":"env:prod"} }
```

## 5. Alerts, notifications, sinks

- **Routing policy** (`GET/PUT /v1/policy/alerts`): map `(severity, confidence, check_type, label)` → sink(s) + throttle. E.g. `critical AND high-confidence → pagerduty + slack immediately`; `low-confidence → daily digest`.
- **Sinks** (`rustmite-notify`, `/v1/sinks`): `webhook` (HMAC-signed payloads), `slack`, `email/SMTP`, `syslog` (RFC 5424, CEF/LEEF option), `splunk_hec`, `elastic`, `ndjson_file`, `kafka` (optional). Recon observations stream to SIEM sinks continuously (§7).
- **Dedupe/throttle** at the policy layer using the `finding_identity` key + `governor` rate limits, so a flapping host cannot page 400 times.

## 6. WebSocket (live)
`GET /v1/stream` (upgrade). Subscribe to `{topics:["findings","scans","coverage"], filter:{...}}`. Server pushes new findings, scan state transitions, and coverage regressions in real time for the console UI. Backpressure-aware; slow consumers are dropped with a resync marker.

## 7. Node protocol (server ↔ node, port 8443, mTLS)

Long-poll lease model (ADR-5), REST-over-HTTP/2:

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/nodes/register` | node announces id, version, capacity, embedded-probe manifest/hashes |
| POST | `/v1/nodes/lease` | long-poll (≤25 s) for up to `capacity` jobs; returns `ScanRequest`s + credential *references* (not secrets) |
| POST | `/v1/nodes/credentials` | node exchanges a credential reference for a short-TTL sealed credential (vault, `10` §3); audited |
| POST | `/v1/nodes/results` | chunked NDJSON: observations + scan_meta; node-signed |
| POST | `/v1/nodes/heartbeat` | capacity/in-flight/health |
| GET | `/v1/nodes/probes/{arch}` | fetch/verify a probe build if node lacks it (signed) |

- Credentials are **never** handed out in bulk at lease time; a node fetches the specific credential for a specific job, short-TTL, and zeroizes it after use. This limits blast radius if a node is compromised (`10` §2).
- Results are validated (`07` §6) and the node signature checked before persistence.

## 8. Export & integration
- `GET /v1/export/findings?format=ndjson|csv|cef` — bulk export for SIEM ingestion.
- `GET /v1/export/inventory` — recon inventory snapshot per host.
- STIX/TAXII IOC **import** endpoint (`POST /v1/ioc`) feeding `file.ioc` (`06` §14).
- Webhook payloads and syslog messages carry stable schema versions.

## 9. Standalone CLI parity
`rustmite-cli` exposes the same operations locally (`scan`, `hunt`, `checks validate`, `baseline`) so an IR responder can operate without the server. `rustmite-cli scan --host h --check-set incident --out result.ndjson` performs the full SSH+probe flow and evaluates checks locally against the bundled catalog.

## 10. Rate limiting & abuse
- `governor`-based per-token and per-IP limits on the operator API.
- `/v1/hunt` and cracking-related endpoints (`cred.audit` offline mode) are elevated-role, rate-limited, and fully audited.
- Request body size caps; streaming endpoints enforce backpressure.
