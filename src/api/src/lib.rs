//! HTTP API для AI-агента.
//!
//! Предоставляет REST API для тестирования стратегий, fine-tuning параметров
//! и мониторинга состояния движка. Слушает ТОЛЬКО localhost:11337.
//!
//! # Аутентификация
//! Все запросы требуют заголовок `X-API-Key: <key>`.
//!
//! # Эндпоинты
//! - `GET /api/v1/status` — статус движка
//! - `POST /api/v1/strategies/test` — тест стратегии
//! - `GET /api/v1/strategies/stats` — статистика стратегий
//! - `POST /api/v1/strategies/tune` — изменение параметров
//! - `GET /api/v1/conntrack` — активные соединения
//! - `GET /api/v1/dns/cache` — DNS кэш
//! - `POST /api/v1/routing/override` — override маршрута
//! - `GET /api/v1/health` — health check
//! - `GET /api/v1/metrics` — ProcessingStats snapshot (inject counters, latency, etc.)

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{error, info, warn};

// ─── Типы данных ───────────────────────────────────────────────────────────

/// Состояние API, разделяемое между эндпоинтами.
pub struct ApiState {
    pub engine: Arc<dyn EngineHandle + Send + Sync>,
    pub api_key: String,
}

/// Хендл к движку (core).
///
/// Предоставляет методы, необходимые API.
/// Реализуется в service-крейте.
pub trait EngineHandle {
    fn uptime(&self) -> u64;
    fn packets_processed(&self) -> u64;
    fn active_connections(&self) -> u64;
    fn windivert_ok(&self) -> bool;
    fn raw_socket_ok(&self) -> bool;
    fn strategy_stats(&self) -> serde_json::Value;
    fn conntrack_snapshot(&self) -> serde_json::Value;
    fn dns_cache_snapshot(&self) -> serde_json::Value;
    fn shutdown(&self);
    fn test_strategy(&self, params: &StrategyTestParams) -> Result<StrategyTestResult, String>;
    fn tune_strategy(&self, params: &TuneParams);
    fn set_routing_override(&self, params: &RoutingOverride);
    fn probe_domain(
        &self,
        domain: &str,
        full: bool,
        apply: bool,
    ) -> Result<serde_json::Value, String>;
    fn probe_batch(&self, domains: &[&str], full: bool) -> Result<serde_json::Value, String>;
    fn get_presets(&self) -> serde_json::Value;
    fn get_probe_history(&self) -> serde_json::Value;
    /// Returns a JSON snapshot of all ProcessingStats counters.
    fn processing_stats(&self) -> serde_json::Value;

    // ─── Split Tunnel ─────────────────────────────────────────────────────
    fn split_tunnel_state(&self) -> serde_json::Value;
    fn split_tunnel_set_mode(&self, mode: &str);
    fn split_tunnel_add(&self, list: &str, entry_type: &str, value: &str) -> Result<(), String>;
    fn split_tunnel_remove(&self, list: &str, entry_type: &str, value: &str) -> Result<(), String>;

    // ─── Geoblock Domains ─────────────────────────────────────────────────
    fn geoblock_state(&self) -> serde_json::Value;
    fn geoblock_add(&self, domain: &str) -> Result<(), String>;
    fn geoblock_remove(&self, domain: &str) -> Result<(), String>;
    fn geoblock_update_proxy(
        &self,
        enabled: bool,
        host: &str,
        port: u16,
        username: Option<&str>,
        password: Option<&str>,
        use_opera_fallback: bool,
    ) -> Result<(), String>;

    // ─── QA observer surface (/qa/*) ──────────────────────────────────────
    /// GET /qa/strategy_inventory — live strategy registry snapshot.
    #[cfg(feature = "qa")]
    fn qa_strategy_inventory(&self) -> serde_json::Value;
    /// GET /qa/runtime_strategy_snapshot — current active strategy params.
    #[cfg(feature = "qa")]
    fn qa_runtime_strategy_snapshot(&self) -> serde_json::Value;
    /// GET /qa/flow_telemetry — packet/flow counters for testlab probes.
    #[cfg(feature = "qa")]
    fn qa_flow_telemetry(&self) -> serde_json::Value;
    /// GET /qa/autotune_state — adaptive tuner state.
    #[cfg(feature = "qa")]
    fn qa_autotune_state(&self) -> serde_json::Value;
    /// GET /qa/autotune_decision_log — recent autotune decisions.
    #[cfg(feature = "qa")]
    fn qa_autotune_decision_log(&self) -> serde_json::Value;
    /// GET /qa/windivert_stats — WinDivert driver-level stats.
    #[cfg(feature = "qa")]
    fn qa_windivert_stats(&self) -> serde_json::Value;
    /// GET /qa/driver_service_stats — service/driver composite stats.
    #[cfg(feature = "qa")]
    fn qa_driver_service_stats(&self) -> serde_json::Value;
    /// POST /qa/reset_state — reset non-persistent engine state.
    #[cfg(feature = "qa")]
    fn qa_reset_state(&self) -> serde_json::Value;
    /// POST /qa/reset_telemetry — zero out telemetry counters.
    #[cfg(feature = "qa")]
    fn qa_reset_telemetry(&self) -> serde_json::Value;
    /// POST /qa/export_test_report — export current state as a test report.
    #[cfg(feature = "qa")]
    fn qa_export_test_report(&self) -> serde_json::Value;
}

// ─── Request/Response типы ─────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct StrategyTestParams {
    pub domain: String,
    pub strategy_id: u32,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    pub params: Option<serde_json::Value>,
}

fn default_timeout() -> u64 {
    5000
}

#[derive(Debug, Serialize)]
pub struct StrategyTestResult {
    pub test_id: String,
    pub domain: String,
    pub strategy_id: u32,
    pub success: bool,
    pub latency_ms: u64,
    pub handshake_completed: bool,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TuneParams {
    pub strategy_id: u32,
    pub params: serde_json::Value,
    #[serde(default)]
    pub persist: bool,
}

#[derive(Debug, Deserialize)]
pub struct RoutingOverride {
    pub domain: String,
    pub region: String,
    #[serde(default = "default_ttl")]
    pub ttl_minutes: u64,
}

fn default_ttl() -> u64 {
    60
}

#[derive(Debug, Deserialize)]
pub struct ProbeRequest {
    pub domain: String,
    #[serde(default = "default_false")]
    pub full: bool,
    #[serde(default = "default_false")]
    pub apply: bool,
}

#[derive(Debug, Deserialize)]
pub struct BatchProbeRequest {
    pub preset_ids: Vec<String>,
    #[serde(default = "default_false")]
    pub full: bool,
}

fn default_false() -> bool {
    false
}

// ─── API Server ────────────────────────────────────────────────────────────

/// Запускает HTTP API сервер.
///
/// Слушает на `127.0.0.1:{port}`. Все эндпоинты требуют `X-API-Key`.
pub async fn serve(engine: Arc<dyn EngineHandle + Send + Sync>, api_key: String, port: u16) {
    let state = Arc::new(ApiState { engine, api_key });

    let app = Router::new()
        .route("/api/v1/status", get(status_handler))
        .route("/api/v1/strategies/test", post(test_strategy_handler))
        .route("/api/v1/strategies/stats", get(strategy_stats_handler))
        .route("/api/v1/strategies/tune", post(tune_strategy_handler))
        .route("/api/v1/conntrack", get(conntrack_handler))
        .route("/api/v1/dns/cache", get(dns_cache_handler))
        .route("/api/v1/routing/override", post(routing_override_handler))
        .route("/api/v1/health", get(health_handler))
        .route("/api/v1/probe", post(probe_handler))
        .route("/api/v1/probe/batch", post(batch_probe_handler))
        .route("/api/v1/probe/presets", get(presets_handler))
        .route("/api/v1/probe/history", get(history_handler))
        .route("/api/v1/metrics", get(metrics_handler))
        .route("/api/v1/splittunnel", get(split_tunnel_state_handler))
        .route(
            "/api/v1/splittunnel/mode",
            post(split_tunnel_set_mode_handler),
        )
        .route("/api/v1/splittunnel/add", post(split_tunnel_add_handler))
        .route(
            "/api/v1/splittunnel/remove",
            post(split_tunnel_remove_handler),
        )
        .route("/api/v1/geoblock", get(geoblock_state_handler))
        .route("/api/v1/geoblock/add", post(geoblock_add_handler))
        .route("/api/v1/geoblock/remove", post(geoblock_remove_handler))
        .route("/api/v1/geoblock/proxy", post(geoblock_proxy_handler));

    let app = add_qa_routes(app)
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    info!("API server listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[cfg(feature = "qa")]
fn add_qa_routes(app: Router<Arc<ApiState>>) -> Router<Arc<ApiState>> {
    app.route("/qa/capabilities", get(qa_capabilities_handler))
        .route("/qa/health", get(qa_health_handler))
        .route("/qa/strategy_inventory", get(qa_strategy_inventory_handler))
        .route(
            "/qa/runtime_strategy_snapshot",
            get(qa_runtime_strategy_snapshot_handler),
        )
        .route("/qa/flow_telemetry", get(qa_flow_telemetry_handler))
        .route("/qa/autotune_state", get(qa_autotune_state_handler))
        .route(
            "/qa/autotune_decision_log",
            get(qa_autotune_decision_log_handler),
        )
        .route("/qa/windivert_stats", get(qa_windivert_stats_handler))
        .route(
            "/qa/driver_service_stats",
            get(qa_driver_service_stats_handler),
        )
        .route("/qa/reset_state", post(qa_reset_state_handler))
        .route("/qa/reset_telemetry", post(qa_reset_telemetry_handler))
        .route(
            "/qa/export_test_report",
            post(qa_export_test_report_handler),
        )
}

#[cfg(not(feature = "qa"))]
fn add_qa_routes(app: Router<Arc<ApiState>>) -> Router<Arc<ApiState>> {
    app
}

// ─── Auth Middleware ───────────────────────────────────────────────────────

async fn auth_middleware(
    State(state): State<Arc<ApiState>>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if state.api_key.is_empty() {
        error!("FATAL CONFIG ERROR: API key is empty! Access disabled for security.");
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }

    let key = req
        .headers()
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if key == state.api_key {
        Ok(next.run(req).await)
    } else {
        warn!("API auth failed: invalid key");
        Err(StatusCode::UNAUTHORIZED)
    }
}

// ─── Handlers ──────────────────────────────────────────────────────────────

/// `GET /api/v1/status` — статус движка.
async fn status_handler(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "running",
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_seconds": state.engine.uptime(),
        "packets_processed": state.engine.packets_processed(),
        "active_connections": state.engine.active_connections(),
        "api_port": 11337,
    }))
}

/// `POST /api/v1/strategies/test` — тестирование стратегии.
async fn test_strategy_handler(
    State(state): State<Arc<ApiState>>,
    Json(params): Json<StrategyTestParams>,
) -> impl IntoResponse {
    match state.engine.test_strategy(&params) {
        Ok(result) => (StatusCode::OK, Json(serde_json::to_value(result).unwrap())),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": e
            })),
        ),
    }
}

/// `GET /api/v1/strategies/stats` — статистика стратегий.
async fn strategy_stats_handler(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    Json(state.engine.strategy_stats())
}

/// `POST /api/v1/strategies/tune` — настройка стратегии.
async fn tune_strategy_handler(
    State(state): State<Arc<ApiState>>,
    Json(params): Json<TuneParams>,
) -> impl IntoResponse {
    state.engine.tune_strategy(&params);
    Json(serde_json::json!({
        "tuned": true,
        "strategy_id": params.strategy_id,
    }))
}

/// `GET /api/v1/conntrack` — список активных соединений.
async fn conntrack_handler(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    Json(state.engine.conntrack_snapshot())
}

/// `GET /api/v1/dns/cache` — содержимое DNS кэша.
async fn dns_cache_handler(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    Json(state.engine.dns_cache_snapshot())
}

/// `POST /api/v1/routing/override` — override маршрута для домена.
async fn routing_override_handler(
    State(state): State<Arc<ApiState>>,
    Json(params): Json<RoutingOverride>,
) -> impl IntoResponse {
    state.engine.set_routing_override(&params);
    Json(serde_json::json!({
        "overridden": true,
        "domain": params.domain,
        "region": params.region,
    }))
}

/// `GET /api/v1/health` — health check.
async fn health_handler(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    Json(serde_json::json!({
        "healthy": true,
        "windivert_ok": state.engine.windivert_ok(),
        "raw_socket_ok": state.engine.raw_socket_ok(),
        "uptime_seconds": state.engine.uptime(),
    }))
}

/// `GET /api/v1/metrics` — полный снимок ProcessingStats.
///
/// Возвращает все счётчики движка, включая:
/// - `inject_scheduled` / `inject_sent`: разделённые метрики инъекций
/// - `desync_latency_us_p50/p95/p99`: перцентили задержки применения техник
/// - `capture_*`: классификация пойманных пакетов
/// - `invariant_*`: счётчики отброшенных невалидных пакетов
async fn metrics_handler(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    Json(state.engine.processing_stats())
}

// ─── QA observer surface handlers (/qa/*) ─────────────────────────────────
//
// All GET handlers must return {"ok": true, ...} for qa_contract_check.py flat_ok().
// POST handlers return {"ok": true} on success.

/// `GET /qa/capabilities` — lists supported QA surface features.
#[cfg(feature = "qa")]
async fn qa_capabilities_handler(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    Json(serde_json::json!({
        "ok": true,
        "version": env!("CARGO_PKG_VERSION"),
        "capabilities": [
            "flow_telemetry", "strategy_inventory", "runtime_strategy_snapshot",
            "windivert_stats", "driver_service_stats",
            "reset_state", "reset_telemetry", "export_test_report"
        ],
        "windivert_ok": state.engine.windivert_ok(),
        "uptime_seconds": state.engine.uptime(),
    }))
}

/// `GET /qa/health` — health check with full diagnostic info.
#[cfg(feature = "qa")]
async fn qa_health_handler(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    Json(serde_json::json!({
        "ok": true,
        "healthy": true,
        "windivert_ok": state.engine.windivert_ok(),
        "raw_socket_ok": state.engine.raw_socket_ok(),
        "uptime_seconds": state.engine.uptime(),
        "active_connections": state.engine.active_connections(),
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// `GET /qa/strategy_inventory` — live strategy registry snapshot.
///
/// Returns `{"ok": true, "data": {...}}` per strategy_inventory.py contract.
#[cfg(feature = "qa")]
async fn qa_strategy_inventory_handler(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let inv = state.engine.qa_strategy_inventory();
    // Return BOTH at root and inside data to satisfy all tools (reconcile vs inventory)
    let mut map = inv.as_object().cloned().unwrap_or_default();
    map.insert("ok".to_string(), serde_json::Value::Bool(true));
    map.insert("data".to_string(), inv.clone());
    Json(serde_json::Value::Object(map))
}

/// `GET /qa/runtime_strategy_snapshot` — current active strategy params.
#[cfg(feature = "qa")]
async fn qa_runtime_strategy_snapshot_handler(
    State(state): State<Arc<ApiState>>,
) -> impl IntoResponse {
    Json(state.engine.qa_runtime_strategy_snapshot())
}

/// `GET /qa/flow_telemetry` — packet/flow counters.
///
/// Returns `{"ok": true, "aggregate": {...}}` where aggregate fields are
/// summed by flow_telemetry_probe.py to determine if counters changed.
#[cfg(feature = "qa")]
async fn qa_flow_telemetry_handler(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    Json(state.engine.qa_flow_telemetry())
}

/// `GET /qa/autotune_state` — adaptive tuner state.
#[cfg(feature = "qa")]
async fn qa_autotune_state_handler(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    Json(state.engine.qa_autotune_state())
}

/// `GET /qa/autotune_decision_log` — recent autotune decisions.
#[cfg(feature = "qa")]
async fn qa_autotune_decision_log_handler(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    Json(state.engine.qa_autotune_decision_log())
}

/// `GET /qa/windivert_stats` — WinDivert driver stats.
#[cfg(feature = "qa")]
async fn qa_windivert_stats_handler(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    Json(state.engine.qa_windivert_stats())
}

/// `GET /qa/driver_service_stats` — service/driver composite stats.
#[cfg(feature = "qa")]
async fn qa_driver_service_stats_handler(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    Json(state.engine.qa_driver_service_stats())
}

/// `POST /qa/reset_state` — reset non-persistent engine state.
#[cfg(feature = "qa")]
async fn qa_reset_state_handler(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    Json(state.engine.qa_reset_state())
}

/// `POST /qa/reset_telemetry` — zero out telemetry counters.
#[cfg(feature = "qa")]
async fn qa_reset_telemetry_handler(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    Json(state.engine.qa_reset_telemetry())
}

/// `POST /qa/export_test_report` — export current state as a test report.
#[cfg(feature = "qa")]
async fn qa_export_test_report_handler(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    Json(state.engine.qa_export_test_report())
}

/// `POST /api/v1/probe/batch` — batch probe для нескольких доменов.
async fn batch_probe_handler(
    State(state): State<Arc<ApiState>>,
    Json(params): Json<BatchProbeRequest>,
) -> impl IntoResponse {
    let preset_refs: Vec<&str> = params.preset_ids.iter().map(|s| s.as_str()).collect();
    match state.engine.probe_batch(&preset_refs, params.full) {
        Ok(result) => (StatusCode::OK, Json(result)),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e })),
        ),
    }
}

/// `POST /api/v1/probe` — запуск DPI probe для домена.
async fn probe_handler(
    State(state): State<Arc<ApiState>>,
    Json(params): Json<ProbeRequest>,
) -> impl IntoResponse {
    match state
        .engine
        .probe_domain(&params.domain, params.full, params.apply)
    {
        Ok(result) => (StatusCode::OK, Json(result)),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e })),
        ),
    }
}

/// `GET /api/v1/probe/presets` — список preset доменов.
async fn presets_handler(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    Json(state.engine.get_presets())
}

/// `GET /api/v1/probe/history` — история probe'ов.
async fn history_handler(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    Json(state.engine.get_probe_history())
}

// ─── Split Tunnel Request Types ────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SplitTunnelModeRequest {
    pub mode: String,
}

#[derive(Debug, Deserialize)]
pub struct SplitTunnelEntryRequest {
    pub list: String,
    pub entry_type: String,
    pub value: String,
}

// ─── Split Tunnel Handlers ─────────────────────────────────────────────────

/// `GET /api/v1/splittunnel` — полное состояние split tunnel.
async fn split_tunnel_state_handler(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    Json(state.engine.split_tunnel_state())
}

/// `POST /api/v1/splittunnel/mode` — смена режима.
async fn split_tunnel_set_mode_handler(
    State(state): State<Arc<ApiState>>,
    Json(params): Json<SplitTunnelModeRequest>,
) -> impl IntoResponse {
    state.engine.split_tunnel_set_mode(&params.mode);
    Json(serde_json::json!({
        "mode": params.mode,
        "updated": true,
    }))
}

/// `POST /api/v1/splittunnel/add` — добавление записи.
async fn split_tunnel_add_handler(
    State(state): State<Arc<ApiState>>,
    Json(params): Json<SplitTunnelEntryRequest>,
) -> impl IntoResponse {
    match state
        .engine
        .split_tunnel_add(&params.list, &params.entry_type, &params.value)
    {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "added": true,
                "list": params.list,
                "entry_type": params.entry_type,
                "value": params.value,
            })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e })),
        ),
    }
}

/// `POST /api/v1/splittunnel/remove` — удаление записи.
async fn split_tunnel_remove_handler(
    State(state): State<Arc<ApiState>>,
    Json(params): Json<SplitTunnelEntryRequest>,
) -> impl IntoResponse {
    match state
        .engine
        .split_tunnel_remove(&params.list, &params.entry_type, &params.value)
    {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "removed": true,
                "list": params.list,
                "entry_type": params.entry_type,
                "value": params.value,
            })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e })),
        ),
    }
}
#[derive(Debug, Deserialize)]
pub struct GeoblockAddRemoveRequest {
    pub domain: String,
}

// ─── Geoblock Handlers ──────────────────────────────────────────────────

/// `GET /api/v1/geoblock` — полное состояние списков гео-обхода.
async fn geoblock_state_handler(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    Json(state.engine.geoblock_state())
}

/// `POST /api/v1/geoblock/add` — добавление домена.
async fn geoblock_add_handler(
    State(state): State<Arc<ApiState>>,
    Json(params): Json<GeoblockAddRemoveRequest>,
) -> impl IntoResponse {
    match state.engine.geoblock_add(&params.domain) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "added": true,
                "domain": params.domain,
            })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e })),
        ),
    }
}

/// `POST /api/v1/geoblock/remove` — удаление домена.
async fn geoblock_remove_handler(
    State(state): State<Arc<ApiState>>,
    Json(params): Json<GeoblockAddRemoveRequest>,
) -> impl IntoResponse {
    match state.engine.geoblock_remove(&params.domain) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "removed": true,
                "domain": params.domain,
            })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e })),
        ),
    }
}

#[derive(Debug, Deserialize)]
pub struct GeoblockProxyConfigRequest {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub use_opera_fallback: bool,
}

/// `POST /api/v1/geoblock/proxy` — обновление настроек кастомного прокси.
async fn geoblock_proxy_handler(
    State(state): State<Arc<ApiState>>,
    Json(params): Json<GeoblockProxyConfigRequest>,
) -> impl IntoResponse {
    match state.engine.geoblock_update_proxy(
        params.enabled,
        &params.host,
        params.port,
        params.username.as_deref(),
        params.password.as_deref(),
        params.use_opera_fallback,
    ) {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "updated": true }))),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e })),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockEngine;

    impl EngineHandle for MockEngine {
        fn uptime(&self) -> u64 {
            3600
        }
        fn packets_processed(&self) -> u64 {
            1000000
        }
        fn active_connections(&self) -> u64 {
            342
        }
        fn windivert_ok(&self) -> bool {
            true
        }
        fn raw_socket_ok(&self) -> bool {
            true
        }
        fn strategy_stats(&self) -> serde_json::Value {
            serde_json::json!({"total": 106, "active": 42})
        }
        fn conntrack_snapshot(&self) -> serde_json::Value {
            serde_json::json!({"total": 342, "entries": []})
        }
        fn dns_cache_snapshot(&self) -> serde_json::Value {
            serde_json::json!({"total": 150, "entries": {}})
        }
        fn shutdown(&self) {}
        fn test_strategy(
            &self,
            _params: &StrategyTestParams,
        ) -> Result<StrategyTestResult, String> {
            Ok(StrategyTestResult {
                test_id: "test-1".to_string(),
                domain: "example.com".to_string(),
                strategy_id: 42,
                success: true,
                latency_ms: 120,
                handshake_completed: true,
                error: None,
            })
        }
        fn tune_strategy(&self, _params: &TuneParams) {}
        fn set_routing_override(&self, _params: &RoutingOverride) {}
        fn probe_domain(
            &self,
            domain: &str,
            _full: bool,
            _apply: bool,
        ) -> Result<serde_json::Value, String> {
            Ok(serde_json::json!({
                "domain": domain,
                "verdict": "ambiguous",
                "confidence": 0.5,
                "dns": { "phase": "dns", "status": "ok", "detail": "Ok" },
                "tcp": { "phase": "tcp", "status": "ok", "detail": "ConnectOk" },
                "tls": null,
                "http": null,
                "recommendations": [],
                "timestamp": "",
            }))
        }
        fn probe_batch(&self, _domains: &[&str], _full: bool) -> Result<serde_json::Value, String> {
            Ok(serde_json::json!([]))
        }
        fn get_presets(&self) -> serde_json::Value {
            serde_json::json!([])
        }
        fn get_probe_history(&self) -> serde_json::Value {
            serde_json::json!([])
        }
        fn processing_stats(&self) -> serde_json::Value {
            serde_json::json!({
                "total_received": 0u64,
                "inject_scheduled": 0u64,
                "inject_sent": 0u64,
                "forwarded": 0u64,
                "dropped": 0u64,
                "errors": 0u64,
            })
        }
        #[cfg(feature = "qa")]
        fn qa_strategy_inventory(&self) -> serde_json::Value {
            serde_json::json!({
                "live_profiles": [],
                "total": 0u64,
            })
        }
        #[cfg(feature = "qa")]
        fn qa_runtime_strategy_snapshot(&self) -> serde_json::Value {
            serde_json::json!({
                "ok": true,
                "active_strategy_id": null,
                "params": {},
            })
        }
        #[cfg(feature = "qa")]
        fn qa_flow_telemetry(&self) -> serde_json::Value {
            serde_json::json!({
                "ok": true,
                "aggregate": {
                    "flows_observed": 0u64,
                    "packets_received": 0u64,
                    "packets_forwarded": 0u64,
                    "packets_modified": 0u64,
                    "packets_injected": 0u64,
                    "packets_dropped": 0u64,
                    "tls_outbound": 0u64,
                    "dns_queries": 0u64,
                    "quic_initial": 0u64,
                },
            })
        }
        #[cfg(feature = "qa")]
        fn qa_autotune_state(&self) -> serde_json::Value {
            serde_json::json!({ "ok": true, "enabled": false, "current_strategy_id": null })
        }
        #[cfg(feature = "qa")]
        fn qa_autotune_decision_log(&self) -> serde_json::Value {
            serde_json::json!({ "ok": true, "decisions": [] })
        }
        #[cfg(feature = "qa")]
        fn qa_windivert_stats(&self) -> serde_json::Value {
            serde_json::json!({ "ok": true, "recv": 0u64, "drop": 0u64, "queue_len": 0u64 })
        }
        #[cfg(feature = "qa")]
        fn qa_driver_service_stats(&self) -> serde_json::Value {
            serde_json::json!({
                "ok": true,
                "uptime_seconds": 0u64,
                "active_connections": 0u64,
                "windivert_ok": true,
            })
        }
        #[cfg(feature = "qa")]
        fn qa_reset_state(&self) -> serde_json::Value {
            serde_json::json!({ "ok": true, "reset": "state" })
        }
        #[cfg(feature = "qa")]
        fn qa_reset_telemetry(&self) -> serde_json::Value {
            serde_json::json!({ "ok": true, "reset": "telemetry" })
        }
        #[cfg(feature = "qa")]
        fn qa_export_test_report(&self) -> serde_json::Value {
            serde_json::json!({ "ok": true, "report": { "version": env!("CARGO_PKG_VERSION") } })
        }

        fn split_tunnel_state(&self) -> serde_json::Value {
            serde_json::json!({
                "mode": "BlacklistOnly",
                "blacklist_domains": [],
                "blacklist_ips": [],
                "blacklist_cidrs": [],
                "whitelist_domains": [],
                "whitelist_ips": [],
                "whitelist_cidrs": [],
            })
        }
        fn split_tunnel_set_mode(&self, _mode: &str) {}
        fn split_tunnel_add(
            &self,
            _list: &str,
            _entry_type: &str,
            _value: &str,
        ) -> Result<(), String> {
            Ok(())
        }
        fn split_tunnel_remove(
            &self,
            _list: &str,
            _entry_type: &str,
            _value: &str,
        ) -> Result<(), String> {
            Ok(())
        }
        fn geoblock_state(&self) -> serde_json::Value {
            serde_json::json!({
                "static_count": 47,
                "user_domains": ["netflix.com", "spotify.com"],
                "probed_domains": []
            })
        }
        fn geoblock_add(&self, _domain: &str) -> Result<(), String> {
            Ok(())
        }
        fn geoblock_remove(&self, _domain: &str) -> Result<(), String> {
            Ok(())
        }
        fn geoblock_update_proxy(
            &self,
            _enabled: bool,
            _host: &str,
            _port: u16,
            _username: Option<&str>,
            _password: Option<&str>,
            _use_opera_fallback: bool,
        ) -> Result<(), String> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_status_endpoint() {
        let engine = Arc::new(MockEngine);
        let state = Arc::new(ApiState {
            engine,
            api_key: "test-key".to_string(),
        });

        let response = status_handler(State(state)).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_strategy_test_params() {
        let json = serde_json::json!({
            "domain": "example.com",
            "strategy_id": 42,
            "timeout_ms": 3000,
        });
        let params: StrategyTestParams = serde_json::from_value(json).unwrap();
        assert_eq!(params.domain, "example.com");
        assert_eq!(params.strategy_id, 42);
        assert_eq!(params.timeout_ms, 3000);
    }

    #[tokio::test]
    async fn test_metrics_endpoint() {
        let engine = Arc::new(MockEngine);
        let state = Arc::new(ApiState {
            engine,
            api_key: "test-key".to_string(),
        });

        let response = metrics_handler(State(state)).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);

        // Verify body contains inject counters
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json.get("inject_scheduled").is_some() || json.get("total_received").is_some(),
            "metrics response must contain packet counters, got: {}",
            json
        );
    }
}
