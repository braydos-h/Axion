use crate::state::AppState;
use axum::{
    extract::{rejection::JsonRejection, Path, Query, State},
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
        .route("/api/interfaces/auto", post(select_auto))
        .route("/api/capture/start", post(start_capture))
        .route("/api/capture/stop", post(stop_capture))
        .route("/api/capture/restart", post(restart_capture))
        .route("/api/config", get(get_config).put(update_config))
        .route("/api/config/reset", post(reset_config))
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
fn parse_json<T>(input: Result<Json<T>, JsonRejection>) -> Result<T, (StatusCode, String)> {
    input
        .map(|Json(value)| value)
        .map_err(|e| (e.status(), e.body_text()))
}
fn error(status: StatusCode, message: impl ToString) -> Response {
    (status, Json(json!({"error": message.to_string()}))).into_response()
}
async fn interfaces() -> Response {
    match tokio::task::spawn_blocking(crate::capture::interface_details).await {
        Ok(Ok(devices)) => {
            let names: Vec<_> = devices.iter().map(|d| d.name.clone()).collect();
            Json(json!({"interfaces": names, "details": devices})).into_response()
        }
        Ok(Err(e)) => error(StatusCode::SERVICE_UNAVAILABLE, e),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}
fn persist_settings(state: &AppState, settings: &crate::config::Settings) -> anyhow::Result<()> {
    let path = state
        .settings_path
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Cannot determine user configuration directory"))?;
    settings.save_to(path)
}
async fn get_config(State(state): State<AppState>) -> Response {
    Json(state.settings.read().await.clone()).into_response()
}
async fn save_config(state: AppState, settings: crate::config::Settings) -> Response {
    let _guard = state.settings_control.lock().await;
    save_config_locked(&state, settings).await
}
async fn save_config_locked(state: &AppState, settings: crate::config::Settings) -> Response {
    if let Err(e) = settings.validate() {
        return error(StatusCode::BAD_REQUEST, e);
    }
    if settings.ai_enabled && state.inner.read().await.status.mode.starts_with("demo") {
        return error(
            StatusCode::CONFLICT,
            "Cloud analysis is unavailable for simulated demo traffic",
        );
    }
    if let Err(e) = persist_settings(state, &settings) {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Could not save settings: {e}"),
        );
    }
    let previous = &state.active_settings;
    let restart_required = previous.web_host != settings.web_host
        || previous.web_port != settings.web_port
        || previous.strict_port != settings.strict_port
        || previous.max_flows != settings.max_flows
        || previous.flow_timeout_seconds != settings.flow_timeout_seconds
        || previous.log_filter != settings.log_filter;
    *state.settings.write().await = settings.clone();
    let mut inner = state.inner.write().await;
    inner.status.ai_enabled = settings.ai_enabled;
    if !settings.ai_enabled {
        inner.status.ai_status = "disabled".into();
    } else if inner.status.ai_status == "disabled" {
        inner.status.ai_status = "offline".into();
    }
    let status = inner.status.clone();
    drop(inner);
    state.emit("status", &status);
    Json(json!({"settings": settings, "restart_required": restart_required})).into_response()
}
async fn update_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    input: Result<Json<crate::config::Settings>, JsonRejection>,
) -> Response {
    if !same_origin(&headers) {
        return error(
            StatusCode::FORBIDDEN,
            "Cross-origin controls are not allowed",
        );
    }
    let settings = match parse_json(input) {
        Ok(value) => value,
        Err((status, message)) => return error(status, message),
    };
    save_config(state, settings).await
}
async fn reset_config(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !same_origin(&headers) {
        return error(
            StatusCode::FORBIDDEN,
            "Cross-origin controls are not allowed",
        );
    }
    save_config(state, crate::config::Settings::default()).await
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
    input: Result<Json<AiControl>, JsonRejection>,
) -> Response {
    if !same_origin(&headers) {
        return (
            StatusCode::FORBIDDEN,
            "Cross-origin controls are not allowed",
        )
            .into_response();
    }
    let input = match parse_json(input) {
        Ok(value) => value,
        Err((status, message)) => return error(status, message),
    };
    let _guard = state.settings_control.lock().await;
    let mut settings = state.settings.read().await.clone();
    settings.ai_enabled = input.enabled;
    let response = save_config_locked(&state, settings).await;
    if response.status() != StatusCode::OK {
        return response;
    }
    Json(state.inner.read().await.status.clone()).into_response()
}
#[derive(Deserialize)]
struct InterfaceControl {
    interface: String,
}
#[derive(Default, Deserialize)]
struct CaptureControl {
    interface: Option<String>,
}
async fn perform_capture(
    state: AppState,
    action: &str,
    requested: Option<String>,
    persist: bool,
) -> Response {
    let _guard = state.capture_control.lock().await;
    let Some(manager) = state.capture.as_ref() else {
        return error(
            StatusCode::CONFLICT,
            "Live capture controls are unavailable in this mode",
        );
    };
    let current = state.inner.read().await.status.interface.clone();
    let name = requested.unwrap_or_else(|| {
        if current.is_empty() {
            "auto".into()
        } else {
            current
        }
    });
    if name.trim().is_empty() || name.len() > 256 {
        return error(StatusCode::BAD_REQUEST, "Invalid interface name");
    }
    let result = match action {
        "stop" => manager.stop(state.clone()).await,
        "start" => manager.start(state.clone(), name.clone()).await,
        "restart" => manager.restart(state.clone(), name.clone()).await,
        "select" => {
            if state.inner.read().await.status.capture_running {
                manager.restart(state.clone(), name.clone()).await
            } else {
                let candidate = name.clone();
                match tokio::task::spawn_blocking(move || {
                    if candidate == "auto" {
                        crate::capture::auto_interface()
                    } else if crate::capture::interfaces()?.contains(&candidate) {
                        Ok(candidate)
                    } else {
                        Err("Interface not found".into())
                    }
                })
                .await
                {
                    Ok(Ok(selected)) => {
                        let mut inner = state.inner.write().await;
                        inner.status.interface = selected;
                        inner.status.last_error = None;
                        let status = inner.status.clone();
                        drop(inner);
                        state.emit("status", &status);
                        Ok(())
                    }
                    Ok(Err(e)) => Err(e),
                    Err(e) => Err(e.to_string()),
                }
            }
        }
        _ => unreachable!(),
    };
    if let Err(e) = result {
        let mut inner = state.inner.write().await;
        inner.status.last_error = Some(e.clone());
        let status = inner.status.clone();
        drop(inner);
        state.emit("status", &status);
        return error(StatusCode::CONFLICT, e);
    }
    if persist {
        let _settings_guard = state.settings_control.lock().await;
        let mut settings = state.settings.write().await;
        let mut updated = settings.clone();
        updated.auto_interface = name == "auto";
        updated.preferred_interface = if name == "auto" { None } else { Some(name) };
        if let Err(e) = persist_settings(&state, &updated) {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Interface changed but settings could not be saved: {e}"),
            );
        }
        *settings = updated;
    }
    Json(state.inner.read().await.status.clone()).into_response()
}
async fn start_capture(
    State(state): State<AppState>,
    headers: HeaderMap,
    input: Result<Json<CaptureControl>, JsonRejection>,
) -> Response {
    if !same_origin(&headers) {
        return error(
            StatusCode::FORBIDDEN,
            "Cross-origin controls are not allowed",
        );
    }
    let input = match parse_json(input) {
        Ok(value) => value,
        Err((status, message)) => return error(status, message),
    };
    let persist = input.interface.is_some();
    perform_capture(state, "start", input.interface, persist).await
}
async fn stop_capture(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !same_origin(&headers) {
        return error(
            StatusCode::FORBIDDEN,
            "Cross-origin controls are not allowed",
        );
    }
    perform_capture(state, "stop", None, false).await
}
async fn restart_capture(
    State(state): State<AppState>,
    headers: HeaderMap,
    input: Result<Json<CaptureControl>, JsonRejection>,
) -> Response {
    if !same_origin(&headers) {
        return error(
            StatusCode::FORBIDDEN,
            "Cross-origin controls are not allowed",
        );
    }
    let input = match parse_json(input) {
        Ok(value) => value,
        Err((status, message)) => return error(status, message),
    };
    let persist = input.interface.is_some();
    perform_capture(state, "restart", input.interface, persist).await
}
async fn control_interface(
    State(state): State<AppState>,
    headers: HeaderMap,
    input: Result<Json<InterfaceControl>, JsonRejection>,
) -> Response {
    if !same_origin(&headers) {
        return error(
            StatusCode::FORBIDDEN,
            "Cross-origin controls are not allowed",
        );
    }
    let input = match parse_json(input) {
        Ok(value) => value,
        Err((status, message)) => return error(status, message),
    };
    perform_capture(state, "select", Some(input.interface), true).await
}
async fn select_auto(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !same_origin(&headers) {
        return error(
            StatusCode::FORBIDDEN,
            "Cross-origin controls are not allowed",
        );
    }
    perform_capture(state, "select", Some("auto".into()), true).await
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
        let mut state = AppState::new(Status {
            capture_running: false,
            ai_status: "disabled".into(),
            interface: "".into(),
            mode: "live".into(),
            ai_enabled: false,
            last_error: None,
        });
        state.settings_path = Some(std::env::temp_dir().join(format!(
            "axion-api-test-{}-{:?}.json",
            std::process::id(),
            std::thread::current().id()
        )));
        state
    }
    #[tokio::test]
    async fn config_validation_malformed_json_and_origin_are_rejected() {
        let state = test_state();
        let app = router(state.clone());
        let settings = crate::config::Settings {
            web_host: "0.0.0.0".into(),
            ..Default::default()
        };
        let invalid = Request::builder()
            .method("PUT")
            .uri("/api/config")
            .header("host", "127.0.0.1:8080")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&settings).unwrap()))
            .unwrap();
        let response = app.clone().oneshot(invalid).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        assert!(serde_json::from_slice::<serde_json::Value>(&body).unwrap()["error"].is_string());
        let malformed = Request::builder()
            .method("POST")
            .uri("/api/capture/start")
            .header("host", "127.0.0.1:8080")
            .header("content-type", "application/json")
            .body(Body::from("{"))
            .unwrap();
        let response = app.clone().oneshot(malformed).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        assert!(serde_json::from_slice::<serde_json::Value>(&body).unwrap()["error"].is_string());
        let foreign = Request::builder()
            .method("POST")
            .uri("/api/capture/stop")
            .header("host", "127.0.0.1:8080")
            .header("origin", "https://attacker.invalid")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.oneshot(foreign).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(state.settings.read().await.web_host, "127.0.0.1");
    }
    #[tokio::test]
    async fn demo_rejects_enabling_cloud_analysis() {
        let state = test_state();
        state.inner.write().await.status.mode = "demo — simulated traffic".into();
        let app = router(state.clone());
        let request = Request::builder()
            .method("POST")
            .uri("/api/control/ai")
            .header("host", "127.0.0.1:8080")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"enabled":true}"#))
            .unwrap();
        assert_eq!(
            app.oneshot(request).await.unwrap().status(),
            StatusCode::CONFLICT
        );
        assert!(!state.inner.read().await.status.ai_enabled);
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
