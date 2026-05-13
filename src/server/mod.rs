//! Web dashboard server module — axum-based local HTTP server for interactive reports.

use std::net::SocketAddr;

use axum::{
    extract::Multipart,
    http::StatusCode,
    response::Html,
    routing::{get, post},
    Router,
};
use include_dir::{include_dir, Dir};
use tokio::signal;
use tracing::info;

use crate::cli::serve::ServeArgs;
use crate::error::Error;
use crate::report::{ReportContext, ReportEngine};
use crate::scanner::models::DiscoveredHost;

static STATIC_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/src/server/static");

/// Start the web server. Blocks until Ctrl+C.
pub async fn run(args: ServeArgs) -> Result<(), Error> {
    let addr: SocketAddr = format!("{}:{}", args.bind, args.port)
        .parse()
        .map_err(|e| Error::Parse(format!("Invalid bind address: {e}")))?;

    let app = Router::new()
        .route("/", get(index))
        .route("/report", post(report))
        .route("/health", get(health));

    info!("Starting dashboard server on http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| Error::Network(format!("Failed to bind to {addr}: {e}")))?;

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| Error::Network(format!("Server error: {e}")))?;

    info!("Server shut down gracefully");
    Ok(())
}

async fn shutdown_signal() {
    signal::ctrl_c()
        .await
        .expect("Failed to install Ctrl+C handler");
}

/// GET / — Serve the upload form.
async fn index() -> Html<String> {
    let file = STATIC_DIR
        .get_file("index.html")
        .expect("index.html not found in static directory");

    let content = String::from_utf8_lossy(file.contents()).into_owned();
    Html(content)
}

/// GET /health — Health check.
async fn health() -> &'static str {
    "ok"
}

/// POST /report — Accept multipart upload, render report.
async fn report(mut multipart: Multipart) -> Result<Html<String>, StatusCode> {
    let mut file_bytes: Option<Vec<u8>> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?
    {
        if field.name().is_some_and(|name| name == "file") {
            file_bytes = Some(
                field
                    .bytes()
                    .await
                    .map_err(|_| StatusCode::BAD_REQUEST)?
                    .to_vec(),
            );
        }
    }

    let bytes = file_bytes.ok_or(StatusCode::BAD_REQUEST)?;

    if bytes.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let hosts: Vec<DiscoveredHost> =
        serde_json::from_slice(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;

    let ctx = ReportContext::from(&hosts);

    let engine = ReportEngine::new().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let html = tokio::task::spawn_blocking(move || engine.render_html(&ctx))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Html(html))
}

/// Convert an error to an appropriate HTTP status code.
/// Extracted for reuse by future handlers that need to map `Error` to HTTP responses.
#[expect(dead_code)]
fn into_status_code(err: &Error) -> StatusCode {
    match err {
        Error::Parse(_) | Error::Report(_) | Error::Template(_) => StatusCode::BAD_REQUEST,
        Error::Network(_) => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::{get, post};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn app() -> Router {
        Router::new()
            .route("/", get(index))
            .route("/report", post(report))
            .route("/health", get(health))
    }

    // ── index() handler tests ──

    #[tokio::test]
    async fn index_returns_html_with_form() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let html = String::from_utf8_lossy(&body);

        assert!(html.contains("<form"), "Response should contain a form element");
        assert!(
            html.contains("action=\"/report\""),
            "Form should post to /report"
        );
    }

    #[tokio::test]
    async fn index_accepts_json_files() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let html = String::from_utf8_lossy(&body);

        assert!(
            html.contains("accept=\".json\""),
            "File input should accept .json files"
        );
    }

    // ── health() handler tests ──

    #[tokio::test]
    async fn health_returns_ok() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "ok");
    }

    // ── report() handler tests ──

    fn build_multipart_body(field_name: &str, filename: &str, content: &[u8]) -> (String, Vec<u8>) {
        let boundary = "----TestBoundary123";
        let mut body = Vec::new();

        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        body.extend_from_slice(
            format!(
                "Content-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\n",
                field_name, filename
            )
            .as_bytes(),
        );
        body.extend_from_slice("Content-Type: application/json\r\n\r\n".as_bytes());
        body.extend_from_slice(content);
        body.extend_from_slice(format!("\r\n--{}--\r\n", boundary).as_bytes());

        (format!("multipart/form-data; boundary={}", boundary), body)
    }

    #[tokio::test]
    async fn report_valid_json_returns_html() {
        let scan_data = serde_json::json!([
            {
                "ip": "192.168.1.10",
                "mac": null,
                "hostname": "test-host",
                "method": "tcp",
                "open_ports": [],
                "rtt_ms": null,
                "vendor": null
            }
        ]);
        let json_bytes = serde_json::to_vec(&scan_data).unwrap();
        let (content_type, body) = build_multipart_body("file", "scan.json", &json_bytes);

        let response = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/report")
                    .header("content-type", content_type)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let html = String::from_utf8_lossy(&body);

        assert!(html.contains("<!DOCTYPE html>"), "Should return HTML report");
        assert!(html.contains("192.168.1.10"), "Should contain host IP");
    }

    #[tokio::test]
    async fn report_malformed_json_returns_400() {
        let (content_type, body) = build_multipart_body("file", "scan.json", b"not valid json");

        let response = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/report")
                    .header("content-type", content_type)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn report_empty_file_returns_400() {
        let (content_type, body) = build_multipart_body("file", "scan.json", b"");

        let response = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/report")
                    .header("content-type", content_type)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn report_missing_file_field_returns_400() {
        // Build multipart with a different field name (not "file")
        let boundary = "----TestBoundary123";
        let mut body = Vec::new();
        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        body.extend_from_slice(
            "Content-Disposition: form-data; name=\"other\"; filename=\"data.txt\"\r\n".as_bytes(),
        );
        body.extend_from_slice("Content-Type: text/plain\r\n\r\n".as_bytes());
        body.extend_from_slice(b"some data");
        body.extend_from_slice(format!("\r\n--{}--\r\n", boundary).as_bytes());

        let content_type = format!("multipart/form-data; boundary={}", boundary);

        let response = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/report")
                    .header("content-type", content_type)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // ── into_status_code tests ──

    #[test]
    fn into_status_code_parse_error_is_400() {
        let err = Error::Parse("bad input".into());
        assert_eq!(into_status_code(&err), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn into_status_code_network_error_is_503() {
        let err = Error::Network("bind failed".into());
        assert_eq!(into_status_code(&err), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn into_status_code_unknown_is_500() {
        let err = Error::Config("missing".into());
        assert_eq!(into_status_code(&err), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
