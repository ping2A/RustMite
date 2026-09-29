# 16 — Operator Console UI

The control plane serves an embedded operator console at `/` (same listener as the REST API).

Inspired by the major surfaces in [Sandfly’s getting started / UI docs](https://docs.sandflysecurity.com/docs/getting-started) — results viewer, hosts management, RPL Hunt, and check catalog — mapped onto RustMite’s API.

## Run

```bash
cargo run -p rustmite-server -- --listen 127.0.0.1:8080 --seed-demo
# open http://127.0.0.1:8080/

# Larger / smaller fleets
cargo run -p rustmite-server -- --seed-demo --seed-hosts 5000
```

`--seed-demo` (or `RUSTMITE_SEED_DEMO=1`) builds a multi-profile fleet (default **3000** hosts via `--seed-hosts` / `RUSTMITE_SEED_HOSTS`) with:

| Profile | Typical mix | Signal |
|---|---|---|
| `clean-web` / `clean-db` / `clean-app` | majority | quiet / rare posture noise |
| `staging-mix` / `dev-workstation` | mid | SSH key / config noise |
| `legacy-centos` | small | weak keys, unexpected listeners |
| `container-host` | small | container escape indicators |
| `bastion` | tiny | shared SSH keys |
| `lab-rootkit` | tiny | hidden processes / LKM |
| `compromised` | tiny | trojaned binaries, preload, memfd |
| `cred-risk` | small | weak / empty password hashes |
| `drift-heavy` | small | baseline / sshd_config drift |
| `edge-appliance` | small | appliance ports / arch mix |
| `unreachable` | small | failed scan outcomes |

Six regional nodes are registered. The console paginates hosts/findings/scans and can filter hosts by env/profile.

## Authentication (on by default)

Operator console login is **required by default** (Mobipwn-style): Argon2 passwords, session Bearer tokens, and optional per-user TOTP MFA.

| Env | Default | Purpose |
|---|---|---|
| `RUSTMITE_REQUIRE_AUTH` | on (`1`) | Set `0` / `false` / `off` to open the console (dev only) |
| `RUSTMITE_ADMIN_USER` | `admin` | Bootstrap admin username when the auth store is empty |
| `RUSTMITE_ADMIN_PASSWORD` | `admin` | Bootstrap admin password when the auth store is empty |
| `RUSTMITE_API_TOKEN` | unset | Optional legacy shared Bearer (sidebar “Legacy API token”) |

Users and sessions persist under `.dev/auth.json` (or `RUSTMITE_AUTH_FILE`). Change the default password immediately; enable MFA under **Settings → Account**. Admins manage users under **Settings → Users**.

Public without a session: `/`, `/ui/*`, `/v1/health`, `/v1/version`, `/v1/auth/status|login|mfa`, and virtual-agent ingest. All other `/v1/*` routes require `Authorization: Bearer <session>`.

## Screens (Sandfly ↔ RustMite)

| Sandfly concept | Console view | API |
|---|---|---|
| Results viewer / alerts | **Findings** — severity filter, by-host / by-check grouping, detail drawer with evidence + raw JSON + ATT&CK links | `GET /v1/findings`, `GET /v1/summary` |
| Hosts management / add hosts | **Hosts Management** — add by IP/hostname/CIDR, status presets, detail drawer, edit, bulk tag/scan/delete, CSV export | `GET/POST /v1/hosts`, `PATCH/DELETE /v1/hosts/{id}`, `POST /v1/hosts/delete`, `POST /v1/hosts/{id}/scan` |
| Scan / schedules | **Scans** + top-bar **Manual scan**; automatic collection is **opt-in** per host (Add/Edit → Enable scheduled collection). New hosts default to manual. | `GET /v1/scans`, `POST /v1/hosts/{id}/scan` |
| Sandfly Hunter | **RPL Hunt** — fields sidebar, histogram/timechart, results table, inspector, guide, saved queries; legacy expr tab | `POST /v1/hunt/rpl` (+ compile/fields/histogram), `POST /v1/hunt` |
| SSH Hunter | **SSH Hunter** — Summary, Security Zones, Key/User/Host Investigation, Tag Workbench + key graph | `GET /v1/ssh/*` |
| Sandflies catalog | **Checks** — loaded manifests, enable flag, where clause | `GET /v1/checks` |
| Dashboard / status | **Dashboard** — host count, severity rollup, recent alerts, coverage snapshot | `GET /v1/summary` |

## Layout

Mirrors Sandfly’s three-region UI ([overview](https://docs.sandflysecurity.com/docs/user-interface-overview)):

1. **Sidebar** — navigation + health + signed-in user / sign-out + optional legacy API token  
2. **Top bar** — page title, refresh, manual scan  
3. **Content** — tables, filters, drawers/modals  

Assets live under `crates/rustmite-server/static/` and are embedded in the binary via `include_dir`.

## Not yet in the console

Response actions, drift profile wizard, SSO/OIDC, schedules CRUD, and SIEM sink config remain API/docs-only for now (M8 backlog). SSH Hunter covers inventory/investigation/zones/tags; live revoke/dedupe response actions remain M8.
