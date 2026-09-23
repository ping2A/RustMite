//! SSH credential sealing + persistence in the control-plane store.
//!
//! Secrets are sealed to the fleet credential public key (node-only decrypt).
//! Ciphertext lives in [`rustmite_store::StoredCredential`] (ClickHouse / store.json).

use std::fs;
use std::path::{Path, PathBuf};

use axum::http::StatusCode;
use base64::Engine as _;
use rustmite_store::{Store, StoredCredential};

use crate::routes::{ApiError, AppState};

fn sanitize_name(raw: &str) -> String {
    let base = Path::new(raw)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("cred");
    let cleaned: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        "cred".into()
    } else {
        cleaned
    }
}

fn stamp_id(hint: &str) -> String {
    let name = sanitize_name(hint);
    let stamp = crate::sys_metrics::utc_now_rfc3339()
        .chars()
        .filter(|c| c.is_ascii_digit())
        .take(14)
        .collect::<String>();
    format!("{stamp}-{name}")
}

fn mirror_sealed(dir: &str, id: &str, sealed: &[u8]) {
    let root = PathBuf::from(dir);
    let _ = fs::create_dir_all(&root);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&root, fs::Permissions::from_mode(0o700));
    }
    let path = root.join(id);
    let _ = fs::write(&path, sealed);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
}

/// Seal plaintext and upsert into the control-plane database.
pub async fn store_sealed_credential(
    state: &AppState,
    kind: &str,
    hint: &str,
    plaintext: &[u8],
    pubk: &rustmite_crypto::CredPublicKey,
) -> Result<StoredCredential, ApiError> {
    let id = stamp_id(hint);
    let sealed = rustmite_crypto::seal_for_node(pubk, plaintext).map_err(|e| {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("seal credential for nodes: {e}"),
        )
    })?;
    let sealed_b64 = base64::engine::general_purpose::STANDARD.encode(&sealed);
    let now = crate::sys_metrics::utc_now_rfc3339();
    let saved = state
        .store
        .upsert_credential(StoredCredential {
            id: id.clone(),
            kind: kind.to_string(),
            sealed_b64,
            plaintext_bytes: plaintext.len() as u64,
            created_at: now.clone(),
            updated_at: now,
        })
        .await?;

    let mirror_dir = if kind == "identity" {
        ".dev/ssh-identities"
    } else {
        ".dev/ssh-secrets"
    };
    mirror_sealed(mirror_dir, &id, &sealed);
    Ok(saved)
}

/// Resolve a credential reference (id or legacy path) to sealed base64 for lease delivery.
pub async fn resolve_cred_box_b64(state: &AppState, reference: &str) -> Result<String, ApiError> {
    if let Ok(Some(cred)) = state.store.get_credential(reference).await {
        return Ok(cred.sealed_b64);
    }
    // Legacy filesystem fallback (+ lazy import when sealed).
    let path = PathBuf::from(reference);
    let raw = fs::read(&path).map_err(|e| {
        ApiError(
            StatusCode::BAD_REQUEST,
            format!("read credential {}: {e}", path.display()),
        )
    })?;
    if !rustmite_crypto::is_cred_box(&raw) {
        return Err(ApiError(
            StatusCode::CONFLICT,
            format!(
                "credential {} is not node-sealed (re-upload after starting a scanner node)",
                path.display()
            ),
        ));
    }
    let b64 = base64::engine::general_purpose::STANDARD.encode(&raw);
    let id = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(reference)
        .to_string();
    let kind = if reference.contains("ssh-identities") || reference.contains("identity") {
        "identity"
    } else {
        "password"
    };
    let now = crate::sys_metrics::utc_now_rfc3339();
    let _ = state
        .store
        .upsert_credential(StoredCredential {
            id,
            kind: kind.into(),
            sealed_b64: b64.clone(),
            plaintext_bytes: 0,
            created_at: now.clone(),
            updated_at: now,
        })
        .await;
    Ok(b64)
}

/// Import legacy `.dev/ssh-*` sealed files into the control-plane store.
pub async fn import_filesystem_credentials(state: &AppState) -> usize {
    let mut n = 0usize;
    for (dir, kind) in [
        (".dev/ssh-identities", "identity"),
        (".dev/ssh-secrets", "password"),
    ] {
        let Ok(rd) = fs::read_dir(dir) else {
            continue;
        };
        for ent in rd.flatten() {
            let path = ent.path();
            if !path.is_file() {
                continue;
            }
            let Some(id) = path.file_name().and_then(|s| s.to_str()).map(str::to_string) else {
                continue;
            };
            if id.starts_with('.') {
                continue;
            }
            if state
                .store
                .get_credential(&id)
                .await
                .ok()
                .flatten()
                .is_some()
            {
                continue;
            }
            let Ok(raw) = fs::read(&path) else {
                continue;
            };
            if !rustmite_crypto::is_cred_box(&raw) {
                // Skip legacy plaintext — must be re-uploaded to seal for nodes.
                tracing::warn!(
                    path = %path.display(),
                    "skipping unsealed legacy credential; re-upload to store in database"
                );
                continue;
            }
            let now = crate::sys_metrics::utc_now_rfc3339();
            let sealed_b64 = base64::engine::general_purpose::STANDARD.encode(&raw);
            if state
                .store
                .upsert_credential(StoredCredential {
                    id,
                    kind: kind.into(),
                    sealed_b64,
                    plaintext_bytes: 0,
                    created_at: now.clone(),
                    updated_at: now,
                })
                .await
                .is_ok()
            {
                n += 1;
            }
        }
    }
    if n > 0 {
        tracing::info!(count = n, "imported sealed SSH credentials from filesystem into database");
        state.store.mark_dirty_public();
    }
    n
}
