//! `/v1/auth/*` — login, MFA, account TOTP, user admin (Mobipwn-shaped).

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, patch, post};
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::operator_auth::{AuthContext, OperatorAuth, UserRecord};
use crate::routes::AppState;

pub fn auth_routes() -> Router<AppState> {
    Router::new()
        .route("/v1/auth/status", get(auth_status))
        .route("/v1/auth/login", post(login))
        .route("/v1/auth/mfa", post(verify_mfa))
        .route("/v1/auth/logout", post(logout))
        .route("/v1/auth/me", get(me))
        .route("/v1/auth/totp/setup", post(totp_setup))
        .route("/v1/auth/totp/enable", post(totp_enable))
        .route("/v1/auth/totp/disable", post(totp_disable))
        .route("/v1/auth/users", get(list_users).post(create_user))
        .route(
            "/v1/auth/users/{id}",
            patch(patch_user).delete(delete_user),
        )
}

fn auth(state: &AppState) -> Arc<OperatorAuth> {
    state.operator_auth.clone()
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

#[derive(Serialize)]
struct MfaRequiredResponse {
    mfa_required: bool,
    challenge_id: String,
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

    if user.totp_enabled {
        let challenge_id = store
            .create_mfa_challenge(user.id)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        return Ok(Json(serde_json::json!(MfaRequiredResponse {
            mfa_required: true,
            challenge_id: challenge_id.to_string(),
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
        .consume_mfa_challenge(challenge_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::UNAUTHORIZED, "challenge expired".into()))?;

    if !user.verify_totp(&body.code) {
        return Err((StatusCode::UNAUTHORIZED, "invalid code".into()));
    }

    let token = store
        .create_session(&user, true)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(AuthUserResponse {
        user: user.to_record(),
        token,
    }))
}

fn bearer_from_headers(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
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
        // Open mode / legacy API token — synthetic user.
        return Ok(Json(UserRecord {
            id: ctx.user_id,
            username: ctx.username.clone(),
            role: ctx.role.as_str().into(),
            totp_enabled: false,
            created_at: 0,
        }));
    }
    auth(&state)
        .get_user(ctx.user_id)
        .await
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
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
