//! Embedded management API and dashboard. Binds to localhost by default and
//! supports an optional bearer token. There is no external web dependency.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use axum::extract::{DefaultBodyLimit, Query, State};
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
use crate::engine::Engine;

const DASHBOARD_HTML: &str = include_str!("dashboard.html");
const DASHBOARD_JS: &str = include_str!("dashboard.js");
const DASHBOARD_CSS: &str = include_str!("dashboard.css");

#[derive(Clone)]
struct ApiState {
    engine: Arc<Engine>,
    token: Option<Arc<str>>,
}

pub struct ApiHandle {
    pub addr: SocketAddr,
    join: JoinHandle<()>,
}

impl ApiHandle {
    pub async fn wait(self) {
        let _ = self.join.await;
    }
}

pub async fn serve(
    engine: Arc<Engine>,
    config: &ApiConfig,
    shutdown: oneshot::Receiver<()>,
) -> Result<ApiHandle> {
    let state = ApiState {
        engine,
        token: config.token.as_deref().map(Arc::from),
    };
    let app = router(state, config.request_body_limit);
    let listener = TcpListener::bind(config.bind).await?;
    let addr = listener.local_addr()?;
    tracing::info!(%addr, "management API listening");
    let join = tokio::spawn(async move {
        let server = axum::serve(listener, app).with_graceful_shutdown(async move {
            let _ = shutdown.await;
        });
        if let Err(err) = server.await {
            tracing::error!(error = %err, "management API stopped with an error");
        }
    });
    Ok(ApiHandle { addr, join })
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
    let Some(expected) = &state.token else {
        return next.run(request).await;
    };
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
    if let Some(provided) = provided {
        if constant_time_eq(provided.as_bytes(), expected.as_bytes()) {
            return next.run(request).await;
        }
    }
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": "management token required"})),
    )
        .into_response()
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
    let mut response = next.run(request).await;
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
        }
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
}
