//! Operator UI / API audit trail.
//!
//! Every mutating `/v1/*` call (and auth login/logout) is appended to the activity
//! store with `kind` prefix `audit.` — plain-language **action**, entity-aware
//! **summary** (host names resolved from path/body), and sanitized request body.

use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use axum::{Extension, Json};
use rustmite_proto::HostId;
use rustmite_store::{ActivityEvent, Store};
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use crate::operator_auth::{AuthContext, Role};
use crate::routes::AppState;

const AUDIT_KIND_PREFIX: &str = "audit.";
/// Cap buffered body for audit (settings / host create). Larger uploads are
/// **not** buffered here — buffering them previously returned HTTP 400 and
/// broke virtual import / tree upload.
const MAX_AUDIT_BODY: usize = 256 * 1024;

/// Paths that routinely carry multi‑MB JSON (file contents). Never buffer these
/// for audit — pass the stream through and log path/metadata only.
fn is_large_upload_path(path: &str) -> bool {
    let path = path.trim_end_matches('/');
    path == "/v1/hosts/virtual"
        || path == "/v1/hosts/virtual/import-tree"
        || path == "/v1/hosts/virtual/import-tree-upload"
        || path.ends_with("/ingest/import")
        || path == "/v1/ingest/logs"
        || path.starts_with("/v1/ingest/logs/")
        || path == "/v1/credentials/ssh-identity"
}

/// Paths that must not generate audit rows (noise / recursion).
fn skip_audit_path(path: &str) -> bool {
    let path = path.trim_end_matches('/');
    path == "/v1/audit"
        || path == "/v1/activity"
        || path == "/v1/health"
        || path == "/health"
        || path == "/v1/summary"
        || path == "/v1/metrics"
        || path == "/v1/queue"
        // Auth login/MFA logged explicitly with username (no session yet).
        || path == "/v1/auth/login"
        || path == "/v1/auth/mfa"
        || path == "/v1/auth/webauthn/login/begin"
        || path == "/v1/auth/webauthn/login/finish"
        || path == "/v1/auth/status"
        // Virtual-agent ingest is not an operator UI action.
        || path == "/v1/ingest/logs"
        || path.starts_with("/v1/ingest/logs/")
        // Node channel — not operator UI.
        || path.starts_with("/v1/nodes/register")
        || path.starts_with("/v1/nodes/lease")
        || path.starts_with("/v1/nodes/results")
        || path.starts_with("/v1/nodes/heartbeat")
        || path.starts_with("/v1/nodes/progress")
        || path.starts_with("/v1/nodes/noise")
        || path.starts_with("/v1/nodes/credentials")
}

fn is_mutating(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

fn level_for_status(status: u16) -> &'static str {
    if status >= 500 {
        "error"
    } else if status >= 400 {
        "warn"
    } else {
        "info"
    }
}

fn is_secret_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    k.contains("password")
        || k.contains("secret")
        || k.contains("token")
        || k.contains("private_key")
        || k.contains("privatekey")
        || k.contains("passphrase")
        || k.contains("credential")
        || k == "key"
        || k.ends_with("_key")
        || k.contains("authorization")
        || k == "cookie"
        || k.contains("totp")
        || k.contains("otp")
        || k == "pem"
        || k == "identity"
        || k.contains("ssh_identity_pem")
}

/// Redact secrets in-place; truncate long strings.
fn sanitize_value(v: &mut Value) {
    match v {
        Value::Object(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            for k in keys {
                if is_secret_key(&k) {
                    map.insert(k, Value::String("[redacted]".into()));
                } else if let Some(child) = map.get_mut(&k) {
                    sanitize_value(child);
                }
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                sanitize_value(item);
            }
        }
        Value::String(s) => {
            if s.len() > 240 {
                let keep = s.chars().take(200).collect::<String>();
                *s = format!("{keep}…(+{} chars)", s.len().saturating_sub(200));
            }
        }
        _ => {}
    }
}

fn parse_body_summary(bytes: &[u8]) -> Option<Value> {
    if bytes.is_empty() {
        return None;
    }
    let mut v: Value = serde_json::from_slice(bytes).ok()?;
    sanitize_value(&mut v);
    // Inline ingest payloads can still be large when under the audit cap —
    // replace file contents with names/counts so the audit log stays readable.
    if let Some(obj) = v.as_object_mut() {
        if let Some(files) = obj.get("files").cloned() {
            if let Some(arr) = files.as_array() {
                let names: Vec<String> = arr
                    .iter()
                    .filter_map(|f| f.get("name").and_then(|n| n.as_str()).map(str::to_string))
                    .take(8)
                    .collect();
                obj.insert(
                    "files".into(),
                    serde_json::json!({
                        "count": arr.len(),
                        "names": names,
                        "contents": "[omitted]",
                    }),
                );
            }
        }
    }
    Some(v)
}

fn path_segments(path: &str) -> Vec<&str> {
    path.trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect()
}

fn short_id(id: &str) -> String {
    let t = id.trim();
    if t.len() <= 12 {
        t.to_string()
    } else {
        format!("{}…", &t[..8])
    }
}

fn json_str<'a>(body: Option<&'a Value>, key: &str) -> Option<&'a str> {
    body.and_then(|b| b.get(key)).and_then(|v| v.as_str())
}

fn json_keys(body: Option<&Value>) -> Vec<String> {
    body.and_then(|b| b.as_object())
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}

fn preview_str(s: &str, n: usize) -> String {
    let t: String = s.chars().take(n).collect();
    if s.chars().count() > n {
        format!("{t}…")
    } else {
        t
    }
}

/// Resolved entities used to make audit lines readable (looked up before the handler runs).
#[derive(Clone, Debug, Default)]
struct EntityContext {
    host_id: Option<String>,
    host_name: Option<String>,
    host_addr: Option<String>,
    host_agent: Option<String>,
    /// For bulk delete: "name (id), …"
    host_list: Vec<String>,
}

impl EntityContext {
    fn host_label(&self) -> String {
        match (&self.host_name, &self.host_id) {
            (Some(n), Some(id)) => format!("{n} ({})", short_id(id)),
            (Some(n), None) => n.clone(),
            (None, Some(id)) => short_id(id),
            _ => String::new(),
        }
    }

    fn host_detail(&self) -> String {
        let mut parts = Vec::new();
        if let Some(n) = &self.host_name {
            parts.push(format!("name={n}"));
        }
        if let Some(a) = &self.host_addr {
            if !a.is_empty() {
                parts.push(format!("address={a}"));
            }
        }
        if let Some(k) = &self.host_agent {
            if !k.is_empty() {
                parts.push(format!("agent={k}"));
            }
        }
        if let Some(id) = &self.host_id {
            parts.push(format!("id={id}"));
        }
        parts.join(" ")
    }
}

async fn resolve_entities(state: &AppState, path: &str, body: Option<&Value>) -> EntityContext {
    let mut ctx = EntityContext::default();
    let segs = path_segments(path);
    let rest: Vec<&str> = if segs.first() == Some(&"v1") {
        segs[1..].to_vec()
    } else {
        segs
    };

    // /v1/hosts/{uuid}/…
    if rest.first() == Some(&"hosts") {
        if let Some(id_s) = rest.get(1) {
            if let Ok(id) = Uuid::parse_str(id_s) {
                ctx.host_id = Some(id.to_string());
                if let Ok(h) = state.store.get_host(HostId(id)).await {
                    ctx.host_name = Some(h.display_name);
                    ctx.host_addr = h.primary_addr;
                    ctx.host_agent = Some(h.agent_kind);
                }
            }
        }
    }

    // Bulk delete: resolve each host_id in the body.
    if rest.as_slice() == ["hosts", "delete"] {
        if let Some(arr) = body
            .and_then(|b| b.get("host_ids").or_else(|| b.get("ids")))
            .and_then(|v| v.as_array())
        {
            for v in arr.iter().take(50) {
                let Some(id_s) = v.as_str() else { continue };
                if let Ok(id) = Uuid::parse_str(id_s) {
                    if let Ok(h) = state.store.get_host(HostId(id)).await {
                        ctx.host_list
                            .push(format!("{} ({})", h.display_name, short_id(id_s)));
                    } else {
                        ctx.host_list.push(short_id(id_s));
                    }
                }
            }
            if arr.len() > 50 {
                ctx.host_list
                    .push(format!("(+{} more)", arr.len() - 50));
            }
        }
    }

    ctx
}

/// Human-readable action + one-line summary for the audit UI.
fn describe_action(
    method: &Method,
    path: &str,
    body: Option<&Value>,
    ent: &EntityContext,
) -> (String, String) {
    let segs = path_segments(path);
    let rest: Vec<&str> = if segs.first() == Some(&"v1") {
        segs[1..].to_vec()
    } else {
        segs
    };
    let m = method.as_str();
    let host = ent.host_label();
    let host_d = ent.host_detail();

    let (action, summary) = match (m, rest.as_slice()) {
        // —— Hosts ——
        ("POST", ["hosts"]) => {
            let name = json_str(body, "display_name")
                .or_else(|| json_str(body, "name"))
                .unwrap_or("host");
            let addr = json_str(body, "primary_addr")
                .or_else(|| json_str(body, "address"))
                .or_else(|| json_str(body, "host"))
                .unwrap_or("");
            let kind = json_str(body, "agent_kind").unwrap_or("ssh");
            (
                "Create host".into(),
                format!("name={name} address={addr} agent={kind}"),
            )
        }
        ("POST", ["hosts", "virtual"]) => {
            let name = json_str(body, "display_name")
                .or_else(|| json_str(body, "name"))
                .unwrap_or("virtual");
            let nfiles = body
                .and_then(|b| b.get("files"))
                .and_then(|v| {
                    v.as_array()
                        .map(|a| a.len())
                        .or_else(|| v.get("count").and_then(|c| c.as_u64()).map(|n| n as usize))
                })
                .unwrap_or(0);
            let agent = json_str(body, "virtual_agent_id").unwrap_or("");
            (
                "Create virtual host".into(),
                if nfiles > 0 {
                    format!("name={name} files={nfiles} agent={agent}")
                } else if body.is_none() {
                    "virtual host (+ upload; body omitted from audit)".into()
                } else {
                    format!("name={name} agent={agent}")
                },
            )
        }
        ("POST", ["hosts", "virtual", "import-tree"]) => {
            let root = json_str(body, "root").or_else(|| json_str(body, "path")).unwrap_or("?");
            (
                "Import virtual host tree".into(),
                format!("root={root}"),
            )
        }
        ("POST", ["hosts", "virtual", "import-tree-upload"]) => {
            let nfiles = body
                .and_then(|b| b.get("files"))
                .and_then(|v| {
                    v.as_array()
                        .map(|a| a.len())
                        .or_else(|| v.get("count").and_then(|c| c.as_u64()).map(|n| n as usize))
                })
                .unwrap_or(0);
            let host_from = json_str(body, "host_from").unwrap_or("dirname");
            (
                "Import virtual tree (folder upload)".into(),
                if nfiles > 0 {
                    format!("files={nfiles} host_from={host_from}")
                } else {
                    format!("folder upload host_from={host_from} (body omitted from audit)")
                },
            )
        }
        ("POST", ["hosts", _id, "ingest", "import"]) => {
            let nfiles = body
                .and_then(|b| b.get("files"))
                .and_then(|v| {
                    v.as_array()
                        .map(|a| a.len())
                        .or_else(|| v.get("count").and_then(|c| c.as_u64()).map(|n| n as usize))
                })
                .unwrap_or(0);
            (
                "Import virtual host feed".into(),
                format!(
                    "{} files={nfiles}",
                    if host_d.is_empty() {
                        format!("host={host}")
                    } else {
                        host_d.clone()
                    }
                ),
            )
        }
        ("PUT" | "PATCH", ["hosts", _id]) => {
            let keys = json_keys(body);
            (
                "Update host".into(),
                if host_d.is_empty() {
                    format!("fields={}", keys.join(","))
                } else {
                    format!("{host_d} fields={}", keys.join(","))
                },
            )
        }
        ("DELETE", ["hosts", _id]) => (
            "Delete host".into(),
            if host_d.is_empty() {
                format!("host={host}")
            } else {
                host_d
            },
        ),
        ("POST", ["hosts", "delete"]) => {
            let n = body
                .and_then(|b| b.get("host_ids").or_else(|| b.get("ids")))
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            let list = if ent.host_list.is_empty() {
                format!("{n} host(s)")
            } else {
                format!(
                    "deleted={n} hosts=[{}]",
                    ent.host_list.iter().take(8).cloned().collect::<Vec<_>>().join(", ")
                )
            };
            ("Delete hosts (bulk)".into(), list)
        }
        ("POST", ["hosts", "test"]) => {
            let addr = json_str(body, "host")
                .or_else(|| json_str(body, "address"))
                .unwrap_or("?");
            let user = json_str(body, "username").unwrap_or("");
            (
                "Test host connection".into(),
                if user.is_empty() {
                    format!("address={addr}")
                } else {
                    format!("address={addr} user={user}")
                },
            )
        }
        ("POST", ["hosts", _id, "scan"]) => {
            let set = json_str(body, "check_set").unwrap_or("standard");
            (
                "Start scan".into(),
                format!(
                    "{} check_set={set}",
                    if host_d.is_empty() {
                        format!("host={host}")
                    } else {
                        host_d
                    }
                ),
            )
        }
        ("POST", ["hosts", _id, "keys"]) => (
            "Pin host SSH key".into(),
            format!(
                "{} fingerprint={}",
                if host_d.is_empty() {
                    format!("host={host}")
                } else {
                    host_d
                },
                json_str(body, "fingerprint")
                    .map(|s| preview_str(s, 40))
                    .unwrap_or_else(|| "?".into())
            ),
        ),
        ("DELETE", ["hosts", _id, "keys"]) => (
            "Clear host key pins".into(),
            if host_d.is_empty() {
                format!("host={host}")
            } else {
                host_d
            },
        ),
        ("POST", ["hosts", _id, "baseline"]) => (
            "Capture host baseline".into(),
            if host_d.is_empty() {
                format!("host={host}")
            } else {
                host_d
            },
        ),
        ("POST", ["hosts", _id, "token"] | ["hosts", _id, "rotate-token"]) => (
            "Rotate virtual ingest token".into(),
            if host_d.is_empty() {
                format!("host={host}")
            } else {
                host_d
            },
        ),

        // —— Settings / data ——
        ("PUT", ["settings"]) => {
            let keys = json_keys(body);
            (
                "Update settings".into(),
                if keys.is_empty() {
                    "partial update".into()
                } else {
                    format!("changed: {}", keys.join(", "))
                },
            )
        }
        ("POST", ["data", "clear"]) => {
            let targets = body
                .and_then(|b| b.get("targets"))
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_else(|| "?".into());
            ("Clear data".into(), format!("targets=[{targets}]"))
        }

        // —— Checks ——
        ("POST", ["checks"]) => {
            let id = json_str(body, "id").unwrap_or("?");
            let title = json_str(body, "title").or_else(|| json_str(body, "name")).unwrap_or("");
            (
                "Create check".into(),
                if title.is_empty() {
                    format!("id={id}")
                } else {
                    format!("id={id} title={title}")
                },
            )
        }
        ("PUT" | "PATCH", ["checks", id]) => {
            let title = json_str(body, "title").or_else(|| json_str(body, "name")).unwrap_or("");
            (
                "Update check".into(),
                if title.is_empty() {
                    format!("id={id}")
                } else {
                    format!("id={id} title={title}")
                },
            )
        }
        ("DELETE", ["checks", id]) => ("Delete check".into(), format!("id={id}")),
        ("POST", ["checks", "reload"]) => ("Reload checks".into(), String::new()),
        ("POST", ["checks", "validate"]) => ("Validate check (draft)".into(), body_hint(body)),
        ("POST", ["checks", id, "validate"]) => {
            ("Validate check".into(), format!("id={id}"))
        }
        ("POST", ["checks", id, "test"]) => ("Test check".into(), format!("id={id}")),
        ("PUT", ["check-sets"]) => {
            let keys = json_keys(body);
            (
                "Update check sets".into(),
                if keys.is_empty() {
                    body_hint(body)
                } else {
                    format!("keys={}", keys.join(","))
                },
            )
        }
        ("POST", ["check-sets"]) => ("Reset check sets".into(), body_hint(body)),

        // —— Findings / scans ——
        ("DELETE", ["findings"]) => ("Clear findings".into(), body_hint(body)),
        ("PATCH", ["findings", id]) => {
            let st = json_str(body, "status").unwrap_or("?");
            (
                "Classify finding".into(),
                format!("finding={} status={st}", short_id(id)),
            )
        }
        ("DELETE", ["findings", id]) => {
            ("Delete finding".into(), format!("finding={}", short_id(id)))
        }
        ("POST", ["findings", id, rest @ ..]) => (
            "Update finding".into(),
            format!("finding={} {}", short_id(id), rest.join("/")),
        ),
        ("POST", ["scans"]) => ("Enqueue scan(s)".into(), body_hint(body)),
        ("DELETE", ["scans", id]) | ("POST", ["scans", id, "cancel"]) => {
            ("Cancel / delete scan".into(), format!("scan={}", short_id(id)))
        }

        // —— Hunt / RPL ——
        ("POST", ["hunt"]) => {
            let q = json_str(body, "query").unwrap_or("");
            (
                "Hunt query".into(),
                if q.is_empty() {
                    body_hint(body)
                } else {
                    format!("query={}", preview_str(q, 120))
                },
            )
        }
        ("POST", ["hunt", "rpl"]) => {
            let q = json_str(body, "query")
                .or_else(|| json_str(body, "rpl"))
                .unwrap_or("");
            (
                "RPL hunt".into(),
                if q.is_empty() {
                    body_hint(body)
                } else {
                    format!("query={}", preview_str(q, 120))
                },
            )
        }
        ("POST", ["hunt", "rpl", "compile"]) => {
            let q = json_str(body, "query")
                .or_else(|| json_str(body, "rpl"))
                .unwrap_or("");
            (
                "Compile RPL".into(),
                if q.is_empty() {
                    body_hint(body)
                } else {
                    format!("query={}", preview_str(q, 120))
                },
            )
        }
        ("POST", ["hunt", "rpl", "histogram"]) => ("RPL histogram".into(), body_hint(body)),

        // —— Sift ——
        ("POST", ["sift", "runs"]) => ("Run Sift fleet".into(), body_hint(body)),
        ("DELETE", ["sift", "runs"]) => ("Delete all Sift runs".into(), String::new()),
        ("DELETE", ["sift", "runs", id]) => {
            ("Delete Sift run".into(), format!("run={}", short_id(id)))
        }
        ("POST", ["sift", "temporal"]) => ("Run temporal Sift".into(), body_hint(body)),
        ("PUT" | "POST", ["sift", "config"]) => ("Update Sift config".into(), body_hint(body)),
        ("POST", ["sift", "detection-configs"]) => {
            let name = json_str(body, "name").or_else(|| json_str(body, "id")).unwrap_or("?");
            ("Create detection config".into(), format!("name={name}"))
        }
        ("PUT", ["sift", "detection-configs", "active"]) => {
            ("Set active detection config".into(), body_hint(body))
        }
        ("PUT", ["sift", "detection-configs", id]) => {
            ("Update detection config".into(), format!("id={}", short_id(id)))
        }
        ("DELETE", ["sift", "detection-configs", id]) => {
            ("Delete detection config".into(), format!("id={}", short_id(id)))
        }
        ("POST", ["sift", "detection-configs", id, "select"]) => {
            ("Select detection config".into(), format!("id={}", short_id(id)))
        }
        ("POST", ["sift", "platform", "sync"]) => ("Sync Sift fleet dataset".into(), body_hint(body)),
        ("POST", ["sift", "platform", "runs"]) => ("Create Sift platform run".into(), body_hint(body)),
        ("POST", ["sift", "platform", "anomark", "config"]) => {
            ("Update AnoMark config".into(), body_hint(body))
        }

        // —— SSH hunter ——
        ("POST", ["ssh", "keys"]) => ("Tag SSH keys".into(), body_hint(body)),
        ("POST", ["ssh", "zones"]) => {
            let name = json_str(body, "name").unwrap_or("zone");
            ("Create SSH zone".into(), format!("name={name}"))
        }
        ("PUT" | "PATCH", ["ssh", "zones", id]) => {
            ("Update SSH zone".into(), format!("zone={}", short_id(id)))
        }
        ("DELETE", ["ssh", "zones", id]) => {
            ("Delete SSH zone".into(), format!("zone={}", short_id(id)))
        }

        // —— Credentials ——
        ("POST", ["credentials", "ssh-identity"]) => {
            let name = json_str(body, "name").unwrap_or("identity");
            (
                "Upload SSH identity".into(),
                format!("name={name} [secret redacted]"),
            )
        }
        ("POST", ["credentials", "ssh-password"]) => {
            let name = json_str(body, "name").unwrap_or("password");
            (
                "Store SSH password".into(),
                format!("name={name} [secret redacted]"),
            )
        }

        // —— Virtual agents ——
        ("POST", ["virtual-agents"]) => {
            let name = json_str(body, "name")
                .or_else(|| json_str(body, "id"))
                .unwrap_or("profile");
            ("Create virtual agent profile".into(), format!("name={name}"))
        }
        ("PUT" | "PATCH", ["virtual-agents", id]) => (
            "Update virtual agent profile".into(),
            format!("id={}", short_id(id)),
        ),
        ("DELETE", ["virtual-agents", id]) => (
            "Delete virtual agent profile".into(),
            format!("id={}", short_id(id)),
        ),
        ("POST", ["virtual-agents", "preview"]) => {
            ("Preview virtual agent mapping".into(), body_hint(body))
        }

        // —— AnoMark ——
        ("POST", ["anomark", "models"]) => {
            let name = json_str(body, "name").unwrap_or("model");
            ("Train AnoMark model".into(), format!("name={name}"))
        }
        ("DELETE", ["anomark", "models", id]) => {
            ("Delete AnoMark model".into(), format!("id={}", short_id(id)))
        }
        ("PUT", ["anomark", "models", id, "favorite"]) => {
            ("Favorite AnoMark model".into(), format!("id={}", short_id(id)))
        }
        ("POST", ["anomark", "score"]) => ("Score with AnoMark".into(), body_hint(body)),
        ("POST", ["anomark", "apply"]) => ("Apply AnoMark to hosts".into(), body_hint(body)),

        // —— Auth ——
        ("POST", ["auth", "logout"]) => ("Logout".into(), String::new()),
        ("POST", ["auth", "password"]) => ("Change password".into(), "[secret redacted]".into()),
        ("POST", ["auth", "users"]) => {
            let name = json_str(body, "username").unwrap_or("?");
            let role = json_str(body, "role").unwrap_or("?");
            ("Create user".into(), format!("username={name} role={role}"))
        }
        ("PUT" | "PATCH", ["auth", "users", id]) => {
            let role = json_str(body, "role");
            let mut s = format!("user={}", short_id(id));
            if let Some(r) = role {
                s.push_str(&format!(" role={r}"));
            }
            ("Update user".into(), s)
        }
        ("DELETE", ["auth", "users", id]) => {
            ("Delete user".into(), format!("user={}", short_id(id)))
        }
        ("POST", ["auth", "totp", "setup"]) => ("Start MFA setup".into(), String::new()),
        ("POST", ["auth", "totp", "enable"]) => ("Enable MFA".into(), String::new()),
        ("POST", ["auth", "totp", "disable"]) => ("Disable MFA".into(), String::new()),
        ("POST", ["auth", "webauthn", "register", "begin"]) => {
            ("WebAuthn register begin".into(), String::new())
        }
        ("POST", ["auth", "webauthn", "register", "finish"]) => {
            ("WebAuthn register finish".into(), String::new())
        }
        ("DELETE", ["auth", "webauthn", ..]) => ("Delete WebAuthn credential".into(), body_hint(body)),
        ("POST", ["auth", "webauthn", ..]) => ("WebAuthn action".into(), path.to_string()),

        // —— Fallback ——
        _ => {
            let verb = match *method {
                Method::POST => "Run",
                Method::PUT | Method::PATCH => "Update",
                Method::DELETE => "Delete",
                _ => "Action",
            };
            let resource = if rest.is_empty() {
                path.to_string()
            } else {
                rest.join(" / ")
            };
            let mut summary = body_hint(body);
            if !host_d.is_empty() {
                if summary.is_empty() {
                    summary = host_d;
                } else {
                    summary = format!("{host_d} {summary}");
                }
            }
            (format!("{verb} {resource}"), summary)
        }
    };

    (action, summary)
}

fn body_hint(body: Option<&Value>) -> String {
    let Some(b) = body else {
        return String::new();
    };
    match b {
        Value::Object(m) => {
            let mut parts = Vec::new();
            for (k, v) in m.iter().take(8) {
                let vs = match v {
                    Value::String(s) => preview_str(s, 60),
                    Value::Number(n) => n.to_string(),
                    Value::Bool(x) => x.to_string(),
                    Value::Array(a) => format!("[{} items]", a.len()),
                    Value::Object(o) => {
                        format!("{{{}}}", o.keys().cloned().collect::<Vec<_>>().join(","))
                    }
                    Value::Null => "null".into(),
                };
                parts.push(format!("{k}={vs}"));
            }
            if m.len() > 8 {
                parts.push(format!("(+{} more)", m.len() - 8));
            }
            parts.join(" ")
        }
        Value::Array(a) => format!("{} item(s)", a.len()),
        _ => String::new(),
    }
}

/// Rich operator mutation audit used from route handlers when needed.
pub async fn audit_action(
    state: &AppState,
    actor: Option<&AuthContext>,
    action: &str,
    summary: &str,
    mut detail: serde_json::Value,
) {
    if let Some(obj) = detail.as_object_mut() {
        obj.insert("action".into(), serde_json::json!(action));
        obj.insert("summary".into(), serde_json::json!(summary));
    }
    let username = actor.map(|a| a.username.as_str()).unwrap_or("anonymous");
    let message = if summary.is_empty() {
        format!("{username} · {action}")
    } else {
        format!("{username} · {action}: {summary}")
    };
    record_audit(state, actor, "ui", &message, detail, "info").await;
}

/// Persist one audit row (best-effort; never fails the request).
pub async fn record_audit(
    state: &AppState,
    actor: Option<&AuthContext>,
    kind: &str,
    message: &str,
    detail: serde_json::Value,
    level: &str,
) {
    let kind = if kind.starts_with(AUDIT_KIND_PREFIX) {
        kind.to_string()
    } else {
        format!("{AUDIT_KIND_PREFIX}{kind}")
    };
    let _ = state
        .store
        .push_activity(ActivityEvent {
            id: Uuid::new_v4(),
            ts: crate::sys_metrics::utc_now_rfc3339(),
            level: level.into(),
            kind,
            message: message.into(),
            scan_id: None,
            host_id: None,
            node_id: None,
            detail: Some({
                let mut d = detail;
                if let Some(obj) = d.as_object_mut() {
                    if let Some(ctx) = actor {
                        obj.insert("actor".into(), serde_json::json!(ctx.username));
                        obj.insert(
                            "actor_id".into(),
                            serde_json::json!(ctx.user_id.to_string()),
                        );
                        obj.insert("role".into(), serde_json::json!(ctx.role.as_str()));
                    }
                }
                d
            }),
        })
        .await;
}

/// Middleware: log every mutating `/v1/*` operator action with a
/// human-readable description, resolved host names, and sanitized body.
///
/// Never fails the request because of audit body buffering — large uploads
/// (virtual import / tree upload) pass through untouched.
pub async fn audit_ui_actions(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let query = req.uri().query().map(|q| q.to_string());
    let actor = req.extensions().get::<AuthContext>().cloned();
    let content_length = req
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());

    let should_log =
        is_mutating(&method) && path.starts_with("/v1/") && !skip_audit_path(&path);

    let (req, body_bytes, body_omitted) = if should_log {
        match buffer_request_body_for_audit(req, &path, content_length).await {
            Ok(triple) => triple,
            Err(resp) => return resp,
        }
    } else {
        (req, Bytes::new(), false)
    };

    let body_summary = if should_log && !body_omitted {
        parse_body_summary(&body_bytes)
    } else {
        None
    };

    // Resolve host names *before* the handler (needed for deletes).
    let ent = if should_log {
        resolve_entities(&state, &path, body_summary.as_ref()).await
    } else {
        EntityContext::default()
    };

    let (action, mut summary) = if should_log {
        describe_action(&method, &path, body_summary.as_ref(), &ent)
    } else {
        (String::new(), String::new())
    };
    if should_log && body_omitted {
        let size = content_length
            .map(|n| format!("{n} bytes"))
            .unwrap_or_else(|| "large body".into());
        if summary.is_empty() {
            summary = format!("payload omitted from audit ({size})");
        } else if !summary.contains("omitted") {
            summary = format!("{summary}; payload omitted from audit ({size})");
        }
    }

    let response = next.run(req).await;
    if !should_log {
        return response;
    }

    let status = response.status().as_u16();
    let username = actor
        .as_ref()
        .map(|a| a.username.as_str())
        .unwrap_or("anonymous");

    let message = if summary.is_empty() {
        format!("{username} · {action} → {status}")
    } else {
        format!("{username} · {action}: {summary} → {status}")
    };

    let detail = serde_json::json!({
        "action": action,
        "summary": summary,
        "method": method.as_str(),
        "path": path,
        "query": query,
        "status": status,
        "content_length": content_length,
        "body_omitted": body_omitted,
        "host_id": ent.host_id,
        "host_name": ent.host_name,
        "host_addr": ent.host_addr,
        "hosts": if ent.host_list.is_empty() { Value::Null } else { json_list(&ent.host_list) },
        "body": body_summary,
    });
    let level = level_for_status(status).to_string();
    let state2 = state.clone();
    let actor2 = actor.clone();
    tokio::spawn(async move {
        record_audit(&state2, actor2.as_ref(), "ui", &message, detail, &level).await;
    });

    response
}

fn json_list(items: &[String]) -> Value {
    Value::Array(items.iter().map(|s| Value::String(s.clone())).collect())
}

/// Buffer a small JSON body for audit, or pass the request through unchanged
/// for large / upload paths.
///
/// Upload paths and bodies larger than [`MAX_AUDIT_BODY`] are never buffered
/// (this used to return HTTP 400 and break virtual imports).
async fn buffer_request_body_for_audit(
    req: Request,
    path: &str,
    content_length: Option<u64>,
) -> Result<(Request, Bytes, bool), Response> {
    let skip = is_large_upload_path(path)
        || content_length
            .map(|n| n > MAX_AUDIT_BODY as u64)
            .unwrap_or(false);
    if skip {
        return Ok((req, Bytes::new(), true));
    }

    let (parts, body) = req.into_parts();
    match axum::body::to_bytes(body, MAX_AUDIT_BODY).await {
        Ok(bytes) => {
            let req = Request::from_parts(parts, Body::from(bytes.clone()));
            Ok((req, bytes, false))
        }
        Err(_) => {
            // Exceeded cap without Content-Length (chunked). Stream is spent —
            // reject rather than forwarding a broken/empty body to the handler.
            Err(Response::builder()
                .status(StatusCode::PAYLOAD_TOO_LARGE)
                .body(Body::from(
                    "request body too large (exceeded audit buffer; send Content-Length or use an upload endpoint)",
                ))
                .unwrap_or_else(|_| Response::new(Body::empty())))
        }
    }
}

#[derive(Deserialize)]
pub struct AuditQuery {
    pub limit: Option<usize>,
    /// Optional substring filter on path / message / actor / action / summary.
    pub q: Option<String>,
}

/// Admin-only: list UI/API audit events for inspection.
pub async fn list_audit(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    axum::extract::Query(q): axum::extract::Query<AuditQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !ctx.role.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    let limit = q.limit.unwrap_or(500).clamp(1, 2000);
    let all = state
        .store
        .list_activity(limit.saturating_mul(4).max(500))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let needle = q
        .q
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase());

    let events: Vec<_> = all
        .into_iter()
        .filter(|e| e.kind.starts_with(AUDIT_KIND_PREFIX))
        .filter(|e| {
            let Some(ref n) = needle else {
                return true;
            };
            let d = e.detail.as_ref();
            let actor = d
                .and_then(|d| d.get("actor"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let path = d
                .and_then(|d| d.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let action = d
                .and_then(|d| d.get("action"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let summary = d
                .and_then(|d| d.get("summary"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let host_name = d
                .and_then(|d| d.get("host_name"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let body_s = d
                .and_then(|d| d.get("body"))
                .map(|v| v.to_string())
                .unwrap_or_default();
            e.message.to_ascii_lowercase().contains(n)
                || actor.to_ascii_lowercase().contains(n)
                || path.to_ascii_lowercase().contains(n)
                || action.to_ascii_lowercase().contains(n)
                || summary.to_ascii_lowercase().contains(n)
                || host_name.to_ascii_lowercase().contains(n)
                || body_s.to_ascii_lowercase().contains(n)
                || e.kind.to_ascii_lowercase().contains(n)
        })
        .take(limit)
        .collect();

    Ok(Json(serde_json::json!({
        "count": events.len(),
        "events": events,
    })))
}

/// Convenience used from auth handlers (login success / failure).
pub async fn audit_auth_event(
    state: &AppState,
    username: &str,
    kind: &str,
    ok: bool,
    detail: serde_json::Value,
) {
    let level = if ok { "info" } else { "warn" };
    let action = match kind {
        k if k.contains("login") && ok => "Login",
        k if k.contains("login") => "Login failed",
        k if k.contains("logout") => "Logout",
        k if k.contains("mfa") && ok => "MFA verified",
        k if k.contains("mfa") => "MFA failed",
        k if k.contains("webauthn") && ok => "WebAuthn login",
        k if k.contains("webauthn") => "WebAuthn failed",
        _ => "Auth",
    };
    let message = format!("{username} · {action}");
    let mut detail = detail;
    if let Some(obj) = detail.as_object_mut() {
        obj.insert("action".into(), serde_json::json!(action));
        obj.insert("summary".into(), serde_json::json!(kind));
    }
    let ctx = AuthContext {
        user_id: Uuid::nil(),
        username: username.into(),
        role: Role::Viewer,
    };
    record_audit(state, Some(&ctx), kind, &message, detail, level).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn describe_clear_data() {
        let body = json!({"targets": ["findings", "scans", "all"]});
        let (a, s) = describe_action(
            &Method::POST,
            "/v1/data/clear",
            Some(&body),
            &EntityContext::default(),
        );
        assert_eq!(a, "Clear data");
        assert!(s.contains("findings"));
    }

    #[test]
    fn describe_create_host() {
        let body = json!({"display_name": "web-1", "primary_addr": "10.0.0.5", "agent_kind": "ssh"});
        let (a, s) = describe_action(
            &Method::POST,
            "/v1/hosts",
            Some(&body),
            &EntityContext::default(),
        );
        assert_eq!(a, "Create host");
        assert!(s.contains("web-1"));
        assert!(s.contains("10.0.0.5"));
    }

    #[test]
    fn describe_delete_host_uses_entity() {
        let ent = EntityContext {
            host_id: Some("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into()),
            host_name: Some("db-prod".into()),
            host_addr: Some("10.1.2.3".into()),
            host_agent: Some("ssh".into()),
            host_list: vec![],
        };
        let (a, s) = describe_action(
            &Method::DELETE,
            "/v1/hosts/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            None,
            &ent,
        );
        assert_eq!(a, "Delete host");
        assert!(s.contains("db-prod"));
        assert!(s.contains("10.1.2.3"));
    }

    #[test]
    fn sanitize_redacts_password() {
        let mut v = json!({"username": "alice", "password": "s3cret", "nested": {"token": "abc"}});
        sanitize_value(&mut v);
        assert_eq!(v["password"], "[redacted]");
        assert_eq!(v["nested"]["token"], "[redacted]");
        assert_eq!(v["username"], "alice");
    }

    #[test]
    fn describe_settings_lists_keys() {
        let body = json!({"scan_history_per_host": 10, "scan_interval": "1h"});
        let (a, s) = describe_action(
            &Method::PUT,
            "/v1/settings",
            Some(&body),
            &EntityContext::default(),
        );
        assert_eq!(a, "Update settings");
        assert!(s.contains("scan_history_per_host"));
    }

    #[test]
    fn describe_rpl_hunt() {
        let body = json!({"query": "process_name = \"nc\" | stats count()"});
        let (a, s) = describe_action(
            &Method::POST,
            "/v1/hunt/rpl",
            Some(&body),
            &EntityContext::default(),
        );
        assert_eq!(a, "RPL hunt");
        assert!(s.contains("process_name"));
    }
}
