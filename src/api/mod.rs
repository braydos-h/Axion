//! Embedded management API and dashboard. Binds to localhost by default and
//! supports an optional bearer token. There is no external web dependency.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{header, HeaderValue, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::config::{Action, ApiConfig};
use crate::demo::{
    self, DemoError, DemoManager, DemoScenario, DemoSessionDetail, DemoSessionSummary,
};
use crate::engine::Engine;

const DASHBOARD_HTML: &str = include_str!("dashboard.html");
const DASHBOARD_JS: &str = include_str!("dashboard.js");
const DASHBOARD_CSS: &str = include_str!("dashboard.css");

#[derive(Clone)]
struct ApiState {
    engine: Arc<Engine>,
    token: Option<Arc<str>>,
    demo: Option<Arc<DemoManager>>,
    demo_only: bool,
}

pub struct ApiHandle {
    pub addr: SocketAddr,
    join: JoinHandle<()>,
    demo_ticker: Option<JoinHandle<()>>,
}

impl ApiHandle {
    pub async fn wait(self) {
        let _ = self.join.await;
        if let Some(ticker) = self.demo_ticker {
            ticker.abort();
        }
    }
}

pub async fn serve(
    engine: Arc<Engine>,
    config: &ApiConfig,
    shutdown: oneshot::Receiver<()>,
) -> Result<ApiHandle> {
    serve_with_demo(engine, config, Some(DemoManager::new(4)), false, shutdown).await
}

/// Start the management API with an optional demo manager. `demo_only` locks
/// production mutation routes without changing authentication or headers.
pub async fn serve_with_demo(
    engine: Arc<Engine>,
    config: &ApiConfig,
    demo: Option<Arc<DemoManager>>,
    demo_only: bool,
    shutdown: oneshot::Receiver<()>,
) -> Result<ApiHandle> {
    let demo_ticker = demo.as_ref().map(|manager| manager.spawn_ticker());
    let state = ApiState {
        engine,
        token: config.token.as_deref().map(Arc::from),
        demo,
        demo_only,
    };
    let app = router(state, config.request_body_limit);
    let listener = TcpListener::bind(config.bind).await?;
    let addr = listener.local_addr()?;
    tracing::info!(%addr, demo_only, "management API listening");
    let join = tokio::spawn(async move {
        let server = axum::serve(listener, app).with_graceful_shutdown(async move {
            let _ = shutdown.await;
        });
        if let Err(err) = server.await {
            tracing::error!(error = %err, "management API stopped with an error");
        }
    });
    Ok(ApiHandle {
        addr,
        join,
        demo_ticker,
    })
}

fn router(state: ApiState, body_limit: usize) -> Router {
    Router::new()
        .route("/", get(dashboard))
        .route("/dashboard.js", get(dashboard_js))
        .route("/dashboard.css", get(dashboard_css))
        .route("/api/health", get(health))
        .route("/api/status", get(status))
        .route("/api/flows", get(flows))
        .route("/api/events", get(events))
        .route("/api/rules", get(rules))
        .route("/api/rules/reload", post(reload_rules))
        .route("/api/mode", post(set_mode))
        .route("/api/dry-run", post(set_dry_run))
        .route("/api/demo/scenarios", get(demo_scenarios))
        .route("/api/demo/status", get(demo_overview))
        .route(
            "/api/demo/sessions",
            get(demo_list_sessions).post(demo_start_session),
        )
        .route(
            "/api/demo/sessions/{id}",
            get(demo_session).delete(demo_stop_session),
        )
        .route("/api/demo/sessions/{id}/status", get(demo_session))
        .route("/api/demo/sessions/{id}/flows", get(demo_flows))
        .route("/api/demo/sessions/{id}/events", get(demo_events))
        .route("/api/demo/sessions/{id}/pause", post(demo_pause))
        .route("/api/demo/sessions/{id}/resume", post(demo_resume))
        .route("/api/demo/sessions/{id}/reset", post(demo_reset))
        .route("/api/demo/sessions/{id}/speed", post(demo_speed))
        .route(
            "/api/demo/sessions/{id}/stop",
            post(demo_stop_session).delete(demo_stop_session),
        )
        .layer(DefaultBodyLimit::max(body_limit.max(1024)))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

async fn dashboard() -> impl IntoResponse {
    Html(DASHBOARD_HTML)
}

async fn dashboard_js() -> Response {
    asset(DASHBOARD_JS, "text/javascript; charset=utf-8")
}

async fn dashboard_css() -> Response {
    asset(DASHBOARD_CSS, "text/css; charset=utf-8")
}

fn asset(content: &'static str, content_type: &'static str) -> Response {
    (
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-cache")),
        ],
        content,
    )
        .into_response()
}

async fn health() -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "service": "axion",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    version: &'static str,
    mode: String,
    dry_run: bool,
    enforcement_active: bool,
    can_enforce: bool,
    backend: String,
    capture_source: String,
    capture_workers: usize,
    active_flows: usize,
    event_buffer: usize,
    uptime_seconds: u64,
    auto_block_confidence: f32,
    monitor_confidence: f32,
    detection_enabled: bool,
    rules: RuleSummary,
    metrics: crate::telemetry::MetricsSnapshot,
    demo_only: bool,
    demo_enabled: bool,
}

#[derive(Debug, Serialize)]
struct RuleSummary {
    compiled: usize,
    allowlist: usize,
    blocklist: usize,
}

async fn status(State(state): State<ApiState>) -> impl IntoResponse {
    let engine = &state.engine;
    let active = engine.active_flows();
    Json(StatusResponse {
        version: env!("CARGO_PKG_VERSION"),
        mode: engine.mode().to_string(),
        dry_run: engine.dry_run(),
        enforcement_active: engine.enforcement_active(),
        can_enforce: engine.can_enforce(),
        backend: engine.backend(),
        capture_source: engine.capture_source(),
        capture_workers: engine.capture_workers(),
        active_flows: active,
        event_buffer: engine.telemetry().events.len(),
        uptime_seconds: engine.telemetry().metrics.uptime_seconds(),
        auto_block_confidence: engine.config().general.auto_block_confidence,
        monitor_confidence: engine.config().general.monitor_confidence,
        detection_enabled: engine.config().detection.enabled,
        rules: RuleSummary {
            compiled: engine.rules().current().rule_count(),
            allowlist: engine.rules().current().allowlist_len(),
            blocklist: engine.rules().current().blocklist_len(),
        },
        metrics: engine.telemetry().metrics.snapshot(active),
        demo_only: state.demo_only,
        demo_enabled: state.demo.is_some(),
    })
}

#[derive(Debug, Deserialize)]
struct LimitQuery {
    limit: Option<usize>,
}

async fn flows(
    State(state): State<ApiState>,
    Query(query): Query<LimitQuery>,
) -> impl IntoResponse {
    let limit = query.limit.unwrap_or(100).clamp(1, 1000);
    Json(state.engine.snapshot_flows(limit))
}

async fn events(
    State(state): State<ApiState>,
    Query(query): Query<LimitQuery>,
) -> impl IntoResponse {
    let limit = query.limit.unwrap_or(200).clamp(1, 1000);
    Json(state.engine.telemetry().events.recent(limit))
}

#[derive(Serialize)]
struct RulesResponse {
    rules: Vec<crate::config::RuleConfig>,
    default_action: Action,
    allow_overrides: bool,
    allowlist_cidrs: Vec<String>,
    blocklist_cidrs: Vec<String>,
    auto_block_confidence: f32,
    monitor_confidence: f32,
    compiled_count: usize,
}

async fn rules(State(state): State<ApiState>) -> impl IntoResponse {
    let rules = state.engine.rules().current();
    let config = state.engine.config();
    Json(RulesResponse {
        rules: rules.views().to_vec(),
        default_action: config.policy.default_action,
        allow_overrides: config.policy.allow_overrides,
        allowlist_cidrs: config.policy.allowlist_cidrs.clone(),
        blocklist_cidrs: config.policy.blocklist_cidrs.clone(),
        auto_block_confidence: config.general.auto_block_confidence,
        monitor_confidence: config.general.monitor_confidence,
        compiled_count: rules.rule_count(),
    })
}

async fn reload_rules(State(state): State<ApiState>) -> Result<Json<serde_json::Value>, ApiError> {
    let store = Arc::clone(state.engine.rules());
    let result = tokio::task::spawn_blocking(move || store.reload()).await;
    match result {
        Ok(Ok(count)) => {
            tracing::info!(rules = count, "rules hot-reloaded through API");
            Ok(Json(json!({"reloaded": true, "rules": count})))
        }
        Ok(Err(err)) => Err(ApiError::bad_request(format!("{err:#}"))),
        Err(err) => Err(ApiError::internal(format!("reload task failed: {err}"))),
    }
}

#[derive(Deserialize)]
struct ModeRequest {
    mode: String,
}

async fn set_mode(
    State(state): State<ApiState>,
    Json(request): Json<ModeRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mode = match request.mode.to_ascii_lowercase().as_str() {
        "monitor" => crate::config::Mode::Monitor,
        "enforce" => crate::config::Mode::Enforce,
        other => return Err(ApiError::bad_request(format!("unknown mode {other:?}"))),
    };
    state.engine.set_mode(mode).map_err(|err| {
        ApiError::conflict(format!(
            "{err}; start with --inline (NFQUEUE) to enable runtime enforcement"
        ))
    })?;
    tracing::warn!(mode = %mode, "enforcement mode changed through API");
    Ok(Json(json!({
        "mode": mode.to_string(),
        "enforcement_active": state.engine.enforcement_active()
    })))
}

#[derive(Deserialize)]
struct DryRunRequest {
    enabled: bool,
}

async fn set_dry_run(
    State(state): State<ApiState>,
    Json(request): Json<DryRunRequest>,
) -> impl IntoResponse {
    state.engine.set_dry_run(request.enabled);
    tracing::warn!(dry_run = request.enabled, "dry-run changed through API");
    Json(json!({
        "dry_run": state.engine.dry_run(),
        "enforcement_active": state.engine.enforcement_active()
    }))
}

#[derive(Debug, Serialize)]
struct DemoScenariosResponse {
    scenarios: &'static [DemoScenario],
    max_sessions: usize,
    session_ttl_seconds: u64,
    isolation: &'static demo::DemoIsolation,
    demo_only: bool,
}

#[derive(Debug, Serialize)]
struct DemoSessionListResponse {
    sessions: Vec<DemoSessionSummary>,
    active_sessions: usize,
    max_sessions: usize,
    session_ttl_seconds: u64,
    demo_only: bool,
    isolation: &'static demo::DemoIsolation,
}

#[derive(Debug, Serialize)]
struct DemoOverviewResponse {
    demo_only: bool,
    active_sessions: usize,
    max_sessions: usize,
    session_ttl_seconds: u64,
    sessions: Vec<DemoSessionSummary>,
    isolation: &'static demo::DemoIsolation,
}

#[derive(Debug, Deserialize)]
struct DemoStartRequest {
    scenario_id: String,
    speed: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct DemoSpeedRequest {
    speed: f64,
}

fn demo_manager(state: &ApiState) -> Result<Arc<DemoManager>, ApiError> {
    state
        .demo
        .as_ref()
        .cloned()
        .ok_or_else(|| ApiError::not_found("demo playback is not enabled on this server"))
}

fn demo_error(error: DemoError) -> ApiError {
    match error {
        DemoError::UnknownScenario(message) => {
            ApiError::not_found(format!("unknown demo scenario {message:?}"))
        }
        DemoError::TooManySessions(max) => ApiError::too_many_requests(format!(
            "demo session limit reached ({max}); stop an existing session and retry"
        )),
        DemoError::NotFound(message) => ApiError::not_found(format!("demo session {message:?}")),
        DemoError::InvalidSpeed(_) => ApiError::bad_request(error.to_string()),
        DemoError::InvalidState(_) => ApiError::conflict(error.to_string()),
        DemoError::Internal(message) => {
            tracing::error!(error = %message, "demo playback failed");
            ApiError::internal("demo playback failed")
        }
    }
}

async fn demo_scenarios(
    State(state): State<ApiState>,
) -> Result<Json<DemoScenariosResponse>, ApiError> {
    let manager = demo_manager(&state)?;
    Ok(Json(DemoScenariosResponse {
        scenarios: demo::scenarios(),
        max_sessions: manager.max_sessions(),
        session_ttl_seconds: manager.session_ttl_seconds(),
        isolation: &demo::ISOLATION,
        demo_only: state.demo_only,
    }))
}

async fn demo_overview(
    State(state): State<ApiState>,
) -> Result<Json<DemoOverviewResponse>, ApiError> {
    let manager = demo_manager(&state)?;
    let sessions = manager.sessions();
    Ok(Json(DemoOverviewResponse {
        demo_only: state.demo_only,
        active_sessions: sessions.len(),
        max_sessions: manager.max_sessions(),
        session_ttl_seconds: manager.session_ttl_seconds(),
        sessions,
        isolation: &demo::ISOLATION,
    }))
}

async fn demo_list_sessions(
    State(state): State<ApiState>,
) -> Result<Json<DemoSessionListResponse>, ApiError> {
    let manager = demo_manager(&state)?;
    let sessions = manager.sessions();
    Ok(Json(DemoSessionListResponse {
        active_sessions: sessions.len(),
        max_sessions: manager.max_sessions(),
        session_ttl_seconds: manager.session_ttl_seconds(),
        sessions,
        demo_only: state.demo_only,
        isolation: &demo::ISOLATION,
    }))
}

async fn demo_start_session(
    State(state): State<ApiState>,
    Json(request): Json<DemoStartRequest>,
) -> Result<Response, ApiError> {
    let manager = demo_manager(&state)?;
    if request.scenario_id.is_empty() || request.scenario_id.len() > 64 {
        return Err(ApiError::bad_request("invalid demo scenario id"));
    }
    let session = manager
        .create(&request.scenario_id, request.speed)
        .map_err(demo_error)?;
    let detail = session.detail(100, 200, crate::flow::unix_ms());
    Ok((StatusCode::CREATED, Json(detail)).into_response())
}

async fn demo_session(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Query(query): Query<LimitQuery>,
) -> Result<Json<DemoSessionDetail>, ApiError> {
    let manager = demo_manager(&state)?;
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    let session = manager.get(&id).map_err(demo_error)?;
    Ok(Json(session.detail(limit, limit, crate::flow::unix_ms())))
}

async fn demo_flows(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Query(query): Query<LimitQuery>,
) -> Result<Json<Vec<crate::flow::FlowSnapshot>>, ApiError> {
    let manager = demo_manager(&state)?;
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    let session = manager.get(&id).map_err(demo_error)?;
    Ok(Json(session.flows(limit, crate::flow::unix_ms())))
}

async fn demo_events(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Query(query): Query<LimitQuery>,
) -> Result<Json<Vec<crate::telemetry::DetectionEvent>>, ApiError> {
    let manager = demo_manager(&state)?;
    let limit = query.limit.unwrap_or(200).clamp(1, 500);
    let session = manager.get(&id).map_err(demo_error)?;
    Ok(Json(session.events(limit, crate::flow::unix_ms())))
}

async fn demo_pause(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<DemoSessionDetail>, ApiError> {
    let manager = demo_manager(&state)?;
    let session = manager.get(&id).map_err(demo_error)?;
    let now = crate::flow::unix_ms();
    session.pause(now).map_err(demo_error)?;
    Ok(Json(session.detail(100, 200, now)))
}

async fn demo_resume(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<DemoSessionDetail>, ApiError> {
    let manager = demo_manager(&state)?;
    let session = manager.get(&id).map_err(demo_error)?;
    let now = crate::flow::unix_ms();
    session.resume(now).map_err(demo_error)?;
    Ok(Json(session.detail(100, 200, now)))
}

async fn demo_reset(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<DemoSessionDetail>, ApiError> {
    let manager = demo_manager(&state)?;
    let session = manager.get(&id).map_err(demo_error)?;
    let now = crate::flow::unix_ms();
    session.reset(now).map_err(demo_error)?;
    Ok(Json(session.detail(100, 200, now)))
}

async fn demo_speed(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(request): Json<DemoSpeedRequest>,
) -> Result<Json<DemoSessionDetail>, ApiError> {
    let manager = demo_manager(&state)?;
    let session = manager.get(&id).map_err(demo_error)?;
    let now = crate::flow::unix_ms();
    session.set_speed(request.speed, now).map_err(demo_error)?;
    Ok(Json(session.detail(100, 200, now)))
}

async fn demo_stop_session(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let manager = demo_manager(&state)?;
    manager.stop(&id).map_err(demo_error)?;
    Ok(Json(json!({"stopped": true, "id": id})))
}

async fn auth_middleware(
    State(state): State<ApiState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    // Static dashboard assets contain no data; all privileged operations live
    // under /api/. The browser cannot set a bearer header on navigation, so
    // requiring one here would make token-protected dashboards unusable.
    if !request.uri().path().starts_with("/api/") || request.uri().path() == "/api/health" {
        return next.run(request).await;
    }
    if let Some(expected) = &state.token {
        let provided = request
            .headers()
            .get("x-axion-token")
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_string())
            .or_else(|| {
                request
                    .headers()
                    .get(header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.strip_prefix("Bearer "))
                    .map(|value| value.to_string())
            });
        let authorized = provided
            .map(|provided| constant_time_eq(provided.as_bytes(), expected.as_bytes()))
            .unwrap_or(false);
        if !authorized {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "management token required"})),
            )
                .into_response();
        }
    }
    // Demo-only deployments expose no production controls. Authentication is
    // checked first so an invalid token still receives 401.
    if state.demo_only && demo_only_mutation(request.uri().path()) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "production management operations are disabled in demo-only mode"
            })),
        )
            .into_response();
    }
    next.run(request).await
}

fn demo_only_mutation(path: &str) -> bool {
    matches!(path, "/api/rules/reload" | "/api/mode" | "/api/dry-run")
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

async fn security_headers(request: Request<axum::body::Body>, next: Next) -> Response {
    let is_api = request.uri().path().starts_with("/api/");
    let mut response = next.run(request).await;
    if is_api {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        ),
    );
    headers.insert(
        header::HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("geolocation=(), microphone=(), camera=()"),
    );
    response
}

struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn too_many_requests(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({"error": self.message}))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::rules::RuleStore;
    use crate::telemetry::Telemetry;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn state(token: Option<&str>) -> ApiState {
        let config = Config::default();
        let telemetry = Arc::new(Telemetry::new(10, 1000, 32));
        let rules = RuleStore::new("test.toml".into(), &config).unwrap();
        let engine = Engine::new(Arc::new(config), rules, telemetry, true, "test").unwrap();
        ApiState {
            engine,
            token: token.map(Arc::from),
            demo: None,
            demo_only: false,
        }
    }

    fn demo_state(
        token: Option<&str>,
        max_sessions: usize,
        demo_only: bool,
    ) -> (ApiState, Arc<DemoManager>) {
        let mut state = state(token);
        let manager = DemoManager::new(max_sessions);
        state.demo = Some(Arc::clone(&manager));
        state.demo_only = demo_only;
        (state, manager)
    }

    async fn body_json(response: Response) -> serde_json::Value {
        let body = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&body).unwrap()
    }

    fn post_json(uri: &str, body: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    #[tokio::test]
    async fn health_is_public() {
        let app = router(state(Some("secret")), 4096);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn token_is_required_for_status() {
        let app = router(state(Some("secret")), 4096);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/status")
                    .header("x-axion-token", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["mode"], "monitor");
    }

    #[tokio::test]
    async fn dashboard_is_served() {
        let app = router(state(None), 4096);
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().contains_key("content-security-policy"));
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("Axion"));
        assert!(text.contains("dashboard.js"));
    }

    #[tokio::test]
    async fn mode_switch_to_enforce() {
        let app = router(state(None), 4096);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/mode")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"mode":"enforce"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn demo_scenarios_are_listed() {
        let (api_state, _) = demo_state(None, 4, false);
        let app = router(api_state, 4096);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/demo/scenarios")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().contains_key("content-security-policy"));
        assert_eq!(response.headers()["x-frame-options"], "DENY");
        assert_eq!(response.headers()["cache-control"], "no-store");
        let json = body_json(response).await;
        let scenarios = json["scenarios"].as_array().expect("scenario list");
        assert_eq!(scenarios.len(), 7);
        assert!(scenarios
            .iter()
            .any(|scenario| scenario["id"] == "normal-https"));
        assert_eq!(json["isolation"]["real_capture"], false);
        assert_eq!(json["isolation"]["accepts_paths"], false);
    }

    #[tokio::test]
    async fn demo_session_lifecycle_and_real_output() {
        let (api_state, manager) = demo_state(None, 4, false);
        let production = Arc::clone(&api_state.engine);
        let app = router(api_state, 4096);

        let response = app
            .clone()
            .oneshot(post_json(
                "/api/demo/sessions",
                r#"{"scenario_id":"socks5-proxy","speed":1.0}"#,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let json = body_json(response).await;
        let id = json["id"].as_str().unwrap().to_string();
        assert_eq!(json["state"], "playing");
        assert_eq!(json["scenario_id"], "socks5-proxy");
        assert_eq!(json["enforcement"]["can_enforce"], false);

        // Drive the bounded ticker deterministically.
        let now = crate::flow::unix_ms() + 120_000;
        manager.tick_at(now);
        manager.tick_at(now + 2_000);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/demo/sessions/{id}/status"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["state"], "completed");
        assert_eq!(json["processed_frames"], 1);
        assert_eq!(json["flows"].as_array().unwrap().len(), 1);
        assert!(json["flows"][0]["proxy_score"].as_f64().unwrap() > 0.9);
        assert_eq!(json["flows"][0]["action"], "drop");
        assert_eq!(json["flows"][0]["blocked"], false);
        assert_eq!(json["events"].as_array().unwrap().len(), 1);
        assert_eq!(json["events"][0]["action"], "drop");
        assert!(json["metrics"]["packets_total"].as_u64().unwrap() >= 1);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/demo/sessions/{id}/events"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_json(response).await.as_array().unwrap().len(), 1);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/demo/sessions/{id}/flows"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let flows = body_json(response).await;
        assert_eq!(flows.as_array().unwrap().len(), 1);
        assert_eq!(flows[0]["detected_protocols"][0], "socks5");

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/demo/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["active_sessions"], 1);
        assert_eq!(json["sessions"][0]["state"], "completed");
        assert_eq!(json["isolation"]["real_enforcement"], false);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/demo/sessions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_json(response).await["active_sessions"], 1);

        // Production counters are isolated from demo playback.
        assert_eq!(
            production
                .telemetry()
                .metrics
                .snapshot(production.active_flows())
                .packets_total,
            0
        );
        assert_eq!(production.telemetry().events.len(), 0);
        assert_eq!(production.active_flows(), 0);

        let response = app
            .clone()
            .oneshot(post_json(&format!("/api/demo/sessions/{id}/pause"), "{}"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(
            body_json(response).await["error"],
            "pause is only available while playback is running"
        );

        let response = app
            .clone()
            .oneshot(post_json(&format!("/api/demo/sessions/{id}/reset"), "{}"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["state"], "playing");
        assert_eq!(json["processed_frames"], 0);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/demo/sessions/{id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_json(response).await["stopped"], true);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/demo/sessions/{id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn demo_pause_resume_speed_and_reset() {
        let (api_state, _manager) = demo_state(None, 4, false);
        let app = router(api_state, 4096);
        let response = app
            .clone()
            .oneshot(post_json(
                "/api/demo/sessions",
                r#"{"scenario_id":"mixed-traffic"}"#,
            ))
            .await
            .unwrap();
        let json = body_json(response).await;
        let id = json["id"].as_str().unwrap().to_string();

        let response = app
            .clone()
            .oneshot(post_json(&format!("/api/demo/sessions/{id}/pause"), "{}"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_json(response).await["state"], "paused");

        let response = app
            .clone()
            .oneshot(post_json(
                &format!("/api/demo/sessions/{id}/speed"),
                r#"{"speed":2.0}"#,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_json(response).await["speed"], 2.0);

        let response = app
            .clone()
            .oneshot(post_json(
                &format!("/api/demo/sessions/{id}/speed"),
                r#"{"speed":99.0}"#,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let response = app
            .clone()
            .oneshot(post_json(&format!("/api/demo/sessions/{id}/resume"), "{}"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_json(response).await["state"], "playing");

        let response = app
            .clone()
            .oneshot(post_json(&format!("/api/demo/sessions/{id}/reset"), "{}"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_json(response).await["processed_frames"], 0);
    }

    #[tokio::test]
    async fn demo_endpoints_require_the_management_token() {
        let (api_state, _) = demo_state(Some("secret"), 4, false);
        let app = router(api_state, 4096);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/demo/scenarios")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/demo/scenarios")
                    .header("x-axion-token", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/demo/sessions")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"scenario_id":"normal-https"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/demo/sessions")
                    .header("content-type", "application/json")
                    .header("x-axion-token", "secret")
                    .body(Body::from(r#"{"scenario_id":"normal-https"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn demo_only_blocks_production_management_but_not_demo_controls() {
        let (api_state, _) = demo_state(None, 4, true);
        let app = router(api_state, 4096);

        let response = app
            .clone()
            .oneshot(post_json("/api/mode", r#"{"mode":"enforce"}"#))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let response = app
            .clone()
            .oneshot(post_json("/api/rules/reload", "{}"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let response = app
            .clone()
            .oneshot(post_json(
                "/api/demo/sessions",
                r#"{"scenario_id":"normal-https"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body_json(response).await;
        assert_eq!(json["demo_only"], true);
        assert_eq!(json["demo_enabled"], true);
        assert_eq!(json["enforcement_active"], false);
    }

    #[tokio::test]
    async fn demo_session_limit_and_unknown_ids_are_safe() {
        let (api_state, _manager) = demo_state(None, 1, false);
        let app = router(api_state, 4096);

        let response = app
            .clone()
            .oneshot(post_json(
                "/api/demo/sessions",
                r#"{"scenario_id":"normal-https"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let response = app
            .clone()
            .oneshot(post_json(
                "/api/demo/sessions",
                r#"{"scenario_id":"socks5-proxy"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

        let response = app
            .clone()
            .oneshot(post_json(
                "/api/demo/sessions",
                r#"{"scenario_id":"../../etc/passwd"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/demo/sessions/does-not-exist")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
