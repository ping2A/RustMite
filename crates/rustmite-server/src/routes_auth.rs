//! `/v1/auth/*` — login, MFA (TOTP + WebAuthn/YubiKey), password, user admin.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, patch, post};
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::operator_auth::{AuthContext, OperatorAuth, UserRecord};
use crate::routes::AppState;
use crate::webauthn;

pub fn auth_routes() -> Router<AppState> {
    Router::new()
        .route("/v1/auth/status", get(auth_status))
        .route("/v1/auth/login", post(login))
        .route("/v1/auth/mfa", post(verify_mfa))
        .route("/v1/auth/logout", post(logout))
        .route("/v1/auth/me", get(me))
        .route("/v1/auth/password", post(change_password))
        .route("/v1/auth/totp/setup", post(totp_setup))
        .route("/v1/auth/totp/enable", post(totp_enable))
        .route("/v1/auth/totp/disable", post(totp_disable))
        .route(
            "/v1/auth/webauthn/register/begin",
            post(webauthn_register_begin),
        )
        .route(
            "/v1/auth/webauthn/register/finish",
            post(webauthn_register_finish),
        )
        .route(
            "/v1/auth/webauthn/credentials/{id}",
            axum::routing::delete(webauthn_delete),
        )
        .route(
            "/v1/auth/webauthn/login/begin",
            post(webauthn_login_begin),
        )
        .route(
            "/v1/auth/webauthn/login/finish",
            post(webauthn_login_finish),
        )
        .route("/v1/auth/users", get(list_users).post(create_user))
        .route(
            "/v1/auth/users/{id}",
            patch(patch_user).delete(delete_user),
        )
}

fn auth(state: &AppState) -> Arc<OperatorAuth> {
    state.operator_auth.clone()
}

fn rp_pair(
    headers: &HeaderMap,
    cfg: &crate::webauthn::WebauthnRpConfig,
) -> Result<(String, String), (StatusCode, String)> {
    let origin = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok());
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok());
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok());
    webauthn::rp_from_request(origin, host, proto, cfg)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))
}

fn bearer_from_headers(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
}

#[derive(Serialize)]
struct AuthStatusResponse {
    require_auth: bool,
}

async fn auth_status(State(state): State<AppState>) -> Json<AuthStatusResponse> {
    Json(AuthStatusResponse {
        require_auth: state.operator_auth.require_auth,
    })
}

#[derive(Deserialize)]
struct LoginBody {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct AuthUserResponse {
    user: UserRecord,
    token: String,
}

async fn login(
    State(state): State<AppState>,
    Json(body): Json<LoginBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let store = auth(&state);
    let user = store
        .authenticate(body.username.trim(), &body.password)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::UNAUTHORIZED, "invalid credentials".into()))?;

    if OperatorAuth::user_needs_mfa(&user) {
        let challenge_id = store
            .create_mfa_challenge(user.id)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        return Ok(Json(serde_json::json!({
            "mfa_required": true,
            "challenge_id": challenge_id.to_string(),
            "methods": OperatorAuth::user_mfa_methods(&user),
        })));
    }

    let token = store
        .create_session(&user, true)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(serde_json::json!(AuthUserResponse {
        user: user.to_record(),
        token,
    })))
}

#[derive(Deserialize)]
struct MfaBody {
    challenge_id: String,
    code: String,
}

async fn verify_mfa(
    State(state): State<AppState>,
    Json(body): Json<MfaBody>,
) -> Result<Json<AuthUserResponse>, (StatusCode, String)> {
    let challenge_id = Uuid::parse_str(body.challenge_id.trim())
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid challenge".into()))?;
    let store = auth(&state);
    let user = store
        .verify_mfa_totp(challenge_id, &body.code)
        .await
        .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?
        .ok_or((StatusCode::UNAUTHORIZED, "challenge expired".into()))?;

    let token = store
        .create_session(&user, true)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(AuthUserResponse {
        user: user.to_record(),
        token,
    }))
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> StatusCode {
    if let Some(token) = bearer_from_headers(&headers) {
        let _ = auth(&state).delete_session(token).await;
    }
    StatusCode::NO_CONTENT
}

async fn me(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
) -> Result<Json<UserRecord>, StatusCode> {
    if ctx.user_id.is_nil() {
        return Ok(Json(UserRecord {
            id: ctx.user_id,
            username: ctx.username.clone(),
            role: ctx.role.as_str().into(),
            totp_enabled: false,
            webauthn_enabled: false,
            webauthn_credentials: Vec::new(),
            created_at: 0,
        }));
    }
    auth(&state)
        .get_user(ctx.user_id)
        .await
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

#[derive(Deserialize)]
struct ChangePasswordBody {
    current_password: String,
    new_password: String,
}

async fn change_password(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    headers: HeaderMap,
    Json(body): Json<ChangePasswordBody>,
) -> Result<StatusCode, (StatusCode, String)> {
    if ctx.user_id.is_nil() {
        return Err((
            StatusCode::BAD_REQUEST,
            "sign in with a user account to change password".into(),
        ));
    }
    auth(&state)
        .change_password(
            ctx.user_id,
            &body.current_password,
            &body.new_password,
            bearer_from_headers(&headers),
        )
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("incorrect") {
                (StatusCode::UNAUTHORIZED, msg)
            } else {
                (StatusCode::BAD_REQUEST, msg)
            }
        })?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
struct TotpSetupResponse {
    secret: String,
    uri: String,
}

async fn totp_setup(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
) -> Result<Json<TotpSetupResponse>, StatusCode> {
    if ctx.user_id.is_nil() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let (secret, uri) = auth(&state)
        .setup_totp(ctx.user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(TotpSetupResponse { secret, uri }))
}

#[derive(Deserialize)]
struct TotpCodeBody {
    code: String,
}

async fn totp_enable(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Json(body): Json<TotpCodeBody>,
) -> Result<StatusCode, StatusCode> {
    if ctx.user_id.is_nil() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let ok = auth(&state)
        .enable_totp(ctx.user_id, &body.code)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if ok {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(StatusCode::BAD_REQUEST)
    }
}

async fn totp_disable(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
) -> Result<StatusCode, StatusCode> {
    if ctx.user_id.is_nil() {
        return Err(StatusCode::BAD_REQUEST);
    }
    auth(&state)
        .disable_totp(ctx.user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct WebauthnFinishBody {
    #[allow(dead_code)]
    id: Option<String>,
    #[serde(rename = "rawId")]
    raw_id: String,
    response: WebauthnResponseBody,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Deserialize)]
struct WebauthnResponseBody {
    #[serde(default, rename = "clientDataJSON")]
    client_data_json: String,
    #[serde(default, rename = "attestationObject")]
    attestation_object: Option<String>,
    #[serde(default, rename = "authenticatorData")]
    authenticator_data: Option<String>,
    #[serde(default)]
    signature: Option<String>,
}

#[derive(Deserialize)]
struct WebauthnLoginBeginBody {
    challenge_id: String,
}

async fn webauthn_register_begin(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if ctx.user_id.is_nil() {
        return Err((StatusCode::BAD_REQUEST, "sign in first".into()));
    }
    let cfg = state.webauthn_rp.read().await.clone();
    let (rp_id, origin) = rp_pair(&headers, &cfg)?;
    let opts = auth(&state)
        .webauthn_register_begin(ctx.user_id, &rp_id, &origin)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok(Json(opts))
}

async fn webauthn_register_finish(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Json(body): Json<WebauthnFinishBody>,
) -> Result<Json<UserRecord>, (StatusCode, String)> {
    if ctx.user_id.is_nil() {
        return Err((StatusCode::BAD_REQUEST, "sign in first".into()));
    }
    let att = body
        .response
        .attestation_object
        .as_deref()
        .ok_or((StatusCode::BAD_REQUEST, "missing attestationObject".into()))?;
    let rec = auth(&state)
        .webauthn_register_finish(
            ctx.user_id,
            att,
            &body.response.client_data_json,
            &body.raw_id,
            body.name.as_deref(),
        )
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok(Json(rec))
}

async fn webauthn_delete(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    if ctx.user_id.is_nil() {
        return Err((StatusCode::BAD_REQUEST, "sign in first".into()));
    }
    let ok = auth(&state)
        .delete_webauthn_credential(ctx.user_id, &id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if ok {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err((StatusCode::NOT_FOUND, "not found".into()))
    }
}

async fn webauthn_login_begin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<WebauthnLoginBeginBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let challenge_id = Uuid::parse_str(body.challenge_id.trim())
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid challenge".into()))?;
    let cfg = state.webauthn_rp.read().await.clone();
    let (rp_id, origin) = rp_pair(&headers, &cfg)?;
    let opts = auth(&state)
        .webauthn_login_begin(challenge_id, &rp_id, &origin)
        .await
        .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;
    Ok(Json(opts))
}

#[derive(Deserialize)]
struct WebauthnLoginFinishBody {
    challenge_id: String,
    #[serde(rename = "rawId")]
    raw_id: String,
    response: WebauthnResponseBody,
}

async fn webauthn_login_finish(
    State(state): State<AppState>,
    Json(body): Json<WebauthnLoginFinishBody>,
) -> Result<Json<AuthUserResponse>, (StatusCode, String)> {
    let challenge_id = Uuid::parse_str(body.challenge_id.trim())
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid challenge".into()))?;
    let auth_data = body
        .response
        .authenticator_data
        .as_deref()
        .ok_or((StatusCode::BAD_REQUEST, "missing authenticatorData".into()))?;
    let signature = body
        .response
        .signature
        .as_deref()
        .ok_or((StatusCode::BAD_REQUEST, "missing signature".into()))?;
    let store = auth(&state);
    let user = store
        .webauthn_login_finish(
            challenge_id,
            &body.raw_id,
            auth_data,
            &body.response.client_data_json,
            signature,
        )
        .await
        .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;
    let token = store
        .create_session(&user, true)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(AuthUserResponse {
        user: user.to_record(),
        token,
    }))
}

fn require_admin(ctx: &AuthContext) -> Result<(), StatusCode> {
    if ctx.role.is_admin() {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

async fn list_users(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
) -> Result<Json<Vec<UserRecord>>, StatusCode> {
    require_admin(&ctx)?;
    Ok(Json(auth(&state).list_users().await))
}

#[derive(Deserialize)]
struct CreateUserBody {
    username: String,
    password: String,
    #[serde(default = "default_role")]
    role: String,
}

fn default_role() -> String {
    "analyst".into()
}

async fn create_user(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Json(body): Json<CreateUserBody>,
) -> Result<Json<UserRecord>, (StatusCode, String)> {
    require_admin(&ctx).map_err(|s| (s, "forbidden".into()))?;
    auth(&state)
        .create_user(&body.username, &body.password, &body.role)
        .await
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))
}

#[derive(Deserialize)]
struct PatchUserBody {
    role: Option<String>,
    password: Option<String>,
}

async fn patch_user(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(id): Path<Uuid>,
    Json(body): Json<PatchUserBody>,
) -> Result<Json<UserRecord>, (StatusCode, String)> {
    require_admin(&ctx).map_err(|s| (s, "forbidden".into()))?;
    let rec = auth(&state)
        .update_user(id, body.role.as_deref(), body.password.as_deref())
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "not found".into()))?;
    Ok(Json(rec))
}

async fn delete_user(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    require_admin(&ctx).map_err(|s| (s, "forbidden".into()))?;
    let ok = auth(&state)
        .delete_user(id)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    if ok {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err((StatusCode::NOT_FOUND, "not found".into()))
    }
}
