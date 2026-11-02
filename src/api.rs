use crate::state::AppState;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, Request as HttpRequest, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/style.css", get(style))
        .route("/app.js", get(script))
        .route("/api/health", get(health))
        .route("/api/status", get(status))
        .route("/api/interfaces", get(interfaces))
        .route("/api/flows", get(flows))
        .route("/api/flows/{id}", get(flow))
        .route("/api/stats", get(stats))
        .route("/api/control/ai", post(control_ai))
        .route("/api/control/interface", post(control_interface))
        .route("/ws", get(crate::websocket::upgrade))
        .layer(middleware::from_fn_with_state(state.clone(), validate_host))
        .with_state(state)
}
// Validate Host independently of Origin so a DNS-rebinding page cannot claim
// the loopback dashboard as its own origin.
async fn validate_host(
    State(state): State<AppState>,
    request: HttpRequest<axum::body::Body>,
    next: Next,
) -> Response {
    let headers = request.headers();
    let mut hosts = headers.get_all("host").iter();
    let host = hosts.next().and_then(|h| h.to_str().ok());
    let valid = hosts.next().is_none()
        && host
            .and_then(|value| value.parse::<axum::http::uri::Authority>().ok())
            .is_some_and(|authority| {
                let host = authority
                    .host()
                    .trim_start_matches('[')
                    .trim_end_matches(']');
                state.allowed_hosts.iter().any(|allowed| {
                    allowed
                        .trim_start_matches('[')
                        .trim_end_matches(']')
                        .eq_ignore_ascii_case(host)
                })
            });
    if !valid {
        return (StatusCode::FORBIDDEN, "Unrecognized Host header").into_response();
    }
    next.run(request).await
}
async fn index() -> Html<&'static str> {
    Html(include_str!("../web/index.html"))
}
async fn style() -> impl IntoResponse {
    (
        [("content-type", "text/css; charset=utf-8")],
        include_str!("../web/style.css"),
    )
}
async fn script() -> impl IntoResponse {
    (
        [("content-type", "text/javascript; charset=utf-8")],
        include_str!("../web/app.js"),
    )
}
async fn health() -> Json<serde_json::Value> {
    Json(json!({"status":"ok"}))
}
async fn status(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.inner.read().await.status.clone())
}
async fn stats(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.inner.read().await.stats.clone())
}
async fn interfaces() -> Response {
    match tokio::task::spawn_blocking(pcap::Device::list).await {
        Ok(Ok(devices)) => {
            Json(json!({"interfaces": devices.into_iter().map(|d| d.name).collect::<Vec<_>>() }))
                .into_response()
        }
        Ok(Err(error)) => (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("Could not enumerate capture interfaces: {error}"),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Interface enumeration failed",
        )
            .into_response(),
    }
}
#[derive(Deserialize)]
struct FlowQuery {
    limit: Option<usize>,
    offset: Option<usize>,
}
async fn flows(State(state): State<AppState>, Query(query): Query<FlowQuery>) -> impl IntoResponse {
    let inner = state.inner.read().await;
    let mut values: Vec<_> = inner.flows.values().collect();
    values.sort_unstable_by_key(|view| std::cmp::Reverse(view.flow.last_seen_ms));
    let offset = query.offset.unwrap_or(0).min(values.len());
    let limit = query.limit.unwrap_or(100).clamp(1, 1000);
    Json(
        json!({"flows": values.into_iter().skip(offset).take(limit).cloned().collect::<Vec<_>>() }),
    )
}
async fn flow(State(state): State<AppState>, Path(id): Path<u64>) -> Response {
    match state.inner.read().await.flows.get(&id).cloned() {
        Some(view) => Json(view).into_response(),
        None => (StatusCode::NOT_FOUND, "Flow not found").into_response(),
    }
}
#[derive(Deserialize)]
struct AiControl {
    enabled: bool,
}
async fn control_ai(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<AiControl>,
) -> Response {
    if !same_origin(&headers) {
        return (
            StatusCode::FORBIDDEN,
            "Cross-origin controls are not allowed",
        )
            .into_response();
    }
    let mut inner = state.inner.write().await;
    if input.enabled && inner.status.mode.starts_with("demo") {
        return (
            StatusCode::CONFLICT,
            "Cloud analysis is unavailable for simulated demo traffic",
        )
            .into_response();
    }
    inner.status.ai_enabled = input.enabled;
    if !input.enabled {
        inner.status.ai_status = "disabled".into();
    } else if inner.status.ai_status == "disabled" {
        inner.status.ai_status = "offline".into();
    }
    let status = inner.status.clone();
    drop(inner);
    state.emit("status", &status);
    Json(status).into_response()
}
#[derive(Deserialize)]
struct InterfaceControl {
    interface: String,
}
async fn control_interface(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<InterfaceControl>,
) -> Response {
    if !same_origin(&headers) {
        return (
            StatusCode::FORBIDDEN,
            "Cross-origin controls are not allowed",
        )
            .into_response();
    }
    if input.interface.is_empty() || input.interface.len() > 256 {
        return (StatusCode::BAD_REQUEST, "Invalid interface name").into_response();
    }
    let name = input.interface.clone();
    match tokio::task::spawn_blocking(move || {
        pcap::Device::list().map(|devices| devices.iter().any(|d| d.name == name))
    })
    .await
    {
        Ok(Ok(true)) => {}
        Ok(Ok(false)) => return (StatusCode::BAD_REQUEST, "Interface not found").into_response(),
        _ => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "Could not enumerate interfaces",
            )
                .into_response()
        }
    }
    let mut inner = state.inner.write().await;
    if inner.status.capture_running {
        return (
            StatusCode::CONFLICT,
            "Stop capture before selecting an interface",
        )
            .into_response();
    }
    inner.status.interface = input.interface;
    let status = inner.status.clone();
    drop(inner);
    state.emit("status", &status);
    Json(status).into_response()
}

// Browsers send Origin for POSTs; reject foreign origins and cross-site fetches.
// Requests without Origin remain usable by local CLI clients.
pub(crate) fn same_origin(headers: &HeaderMap) -> bool {
    if headers
        .get("sec-fetch-site")
        .and_then(|h| h.to_str().ok())
        .is_some_and(|v| v == "cross-site")
    {
        return false;
    }
    match headers.get("origin") {
        None => true,
        Some(origin) => {
            let Some(origin) = origin.to_str().ok() else {
                return false;
            };
            let Some(host) = headers.get("host").and_then(|h| h.to_str().ok()) else {
                return false;
            };
            origin == format!("http://{host}") || origin == format!("https://{host}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Status;
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use tower::ServiceExt;

    fn test_state() -> AppState {
        AppState::new(Status {
            capture_running: false,
            ai_status: "disabled".into(),
            interface: "".into(),
            mode: "live".into(),
            ai_enabled: false,
            last_error: None,
        })
    }
    #[tokio::test]
    async fn health_status_flows_and_missing_flow() {
        let app = router(test_state());
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/health")
                    .header("host", "127.0.0.1:8080")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()["status"],
            "ok"
        );
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/flows?limit=999999")
                    .header("host", "127.0.0.1:8080")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        assert!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()["flows"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/flows/999")
                    .header("host", "127.0.0.1:8080")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
    #[tokio::test]
    async fn rejects_dns_rebinding_and_missing_host() {
        let app = router(test_state());
        for host in [None, Some("attacker.example:8080")] {
            let mut request = Request::builder().uri("/api/status");
            if let Some(host) = host {
                request = request.header("host", host);
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/status")
                    .header("host", "localhost:8080")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    #[tokio::test]
    async fn ai_control_rejects_foreign_origin_and_updates_state() {
        let state = test_state();
        let app = router(state.clone());
        let request = || {
            Request::builder()
                .method("POST")
                .uri("/api/control/ai")
                .header("content-type", "application/json")
                .header("host", "127.0.0.1:8080")
                .header("origin", "https://evil.example")
                .body(Body::from(r#"{"enabled":true}"#))
                .unwrap()
        };
        assert_eq!(
            app.clone().oneshot(request()).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        assert!(!state.inner.read().await.status.ai_enabled);
        let request = Request::builder()
            .method("POST")
            .uri("/api/control/ai")
            .header("content-type", "application/json")
            .header("host", "127.0.0.1:8080")
            .header("origin", "http://127.0.0.1:8080")
            .body(Body::from(r#"{"enabled":true}"#))
            .unwrap();
        assert_eq!(app.oneshot(request).await.unwrap().status(), StatusCode::OK);
        assert!(state.inner.read().await.status.ai_enabled);
    }
}
