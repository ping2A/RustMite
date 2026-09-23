use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// Simple bearer-token gate. Skips health and embedded UI assets.
pub async fn bearer_auth(
    expected: Option<String>,
    req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path();
    let open = path.ends_with("/health")
        || path == "/health"
        || path.ends_with("/version")
        || path == "/v1/version"
        || path == "/"
        || path == "/ui"
        || path == "/ui/"
        || path.starts_with("/ui/")
        // Virtual agents authenticate with their own ingest token, not the operator API token.
        || path == "/v1/ingest/logs"
        || path.starts_with("/v1/ingest/logs/");
    if open {
        return next.run(req).await;
    }
    let Some(token) = expected else {
        // No token configured → open (dev mode).
        return next.run(req).await;
    };
    let ok = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|h| {
            h.strip_prefix("Bearer ")
                .map(|t| t == token)
                .unwrap_or(false)
        })
        .unwrap_or(false);
    if ok {
        next.run(req).await
    } else {
        (StatusCode::UNAUTHORIZED, "unauthorized").into_response()
    }
}
