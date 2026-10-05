//! Operator API authentication middleware.
//!
//! When `require_auth` is on (default), `/v1/*` needs a session Bearer token
//! (or legacy `RUSTMITE_API_TOKEN`). UI static assets and auth endpoints stay open.

use std::sync::Arc;

use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::operator_auth::{AuthContext, OperatorAuth};

#[derive(Clone)]
pub struct AuthGate {
    pub auth: Arc<OperatorAuth>,
    /// Optional legacy shared bearer (RUSTMITE_API_TOKEN).
    pub api_token: Option<String>,
}

fn is_public_path(path: &str) -> bool {
    path.ends_with("/health")
        || path == "/health"
        || path.ends_with("/version")
        || path == "/v1/version"
        || path == "/"
        || path == "/ui"
        || path == "/ui/"
        || path.starts_with("/ui/")
        || path == "/v1/auth/status"
        || path == "/v1/auth/login"
        || path == "/v1/auth/mfa"
        || path == "/v1/auth/webauthn/login/begin"
        || path == "/v1/auth/webauthn/login/finish"
        // Virtual agents authenticate with their own ingest token.
        || path == "/v1/ingest/logs"
        || path.starts_with("/v1/ingest/logs/")
}

fn bearer_token(req: &Request) -> Option<&str> {
    req.headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
}

/// Gate operator routes. Inserts `AuthContext` when a user session is valid.
pub async fn require_auth(gate: AuthGate, mut req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    if is_public_path(&path) {
        return next.run(req).await;
    }

    if !gate.auth.require_auth {
        // Dev open mode — synthetic admin context.
        req.extensions_mut().insert(AuthContext {
            user_id: uuid::Uuid::nil(),
            username: "anonymous".into(),
            role: crate::operator_auth::Role::Admin,
        });
        return next.run(req).await;
    }

    let Some(token) = bearer_token(&req).map(str::to_string) else {
        return (StatusCode::UNAUTHORIZED, "missing credentials").into_response();
    };

    // Legacy shared API token still accepted when configured.
    if let Some(expected) = gate.api_token.as_deref() {
        if token == expected {
            req.extensions_mut().insert(AuthContext {
                user_id: uuid::Uuid::nil(),
                username: "api-token".into(),
                role: crate::operator_auth::Role::Admin,
            });
            return next.run(req).await;
        }
    }

    match gate.auth.verify_session(&token).await {
        Ok(Some(ctx)) => {
            req.extensions_mut().insert(ctx);
            next.run(req).await
        }
        Ok(None) => (StatusCode::UNAUTHORIZED, "invalid credentials").into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "auth session verify failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "auth error").into_response()
        }
    }
}
