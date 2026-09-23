//! Embedded operator console (static SPA).

use axum::http::{header, StatusCode, Uri};
use axum::response::{Html, IntoResponse, Response};
use include_dir::{include_dir, Dir};

static UI_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/static");

pub async fn index() -> Html<&'static str> {
    let html = UI_DIR
        .get_file("index.html")
        .and_then(|f| f.contents_utf8())
        .unwrap_or("<!doctype html><title>RustMite</title><p>UI missing</p>");
    Html(html)
}

pub async fn asset(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    // Expect /ui/assets/...
    let rel = path.strip_prefix("ui/").unwrap_or(path);
    match UI_DIR.get_file(rel) {
        Some(file) => {
            let mime = mime_guess::from_path(rel)
                .first_or_octet_stream()
                .essence_str()
                .to_string();
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, mime)],
                file.contents(),
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}
