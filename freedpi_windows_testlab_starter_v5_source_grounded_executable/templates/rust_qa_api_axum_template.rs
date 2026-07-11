//! Test-only QA API template for FreeDPI Windows.
//! Compile only with: --features qa or --features testlab.
//!
//! This file is a scaffold for the implementation agent. Adapt names/types to the actual API crate.

#![cfg(feature = "qa")]

use std::sync::Arc;
use serde::{Serialize, Deserialize};
use axum::{Json, Router, routing::{get, post}};
use uuid::Uuid;

#[derive(Clone)]
pub struct QaAppState {
    pub service: Arc<dyn QaServiceControl + Send + Sync>,
    pub telemetry: Arc<dyn QaTelemetryRead + Send + Sync>,
}

#[derive(Serialize)]
pub struct QaEnvelope<T: Serialize> {
    pub ok: bool,
    pub request_id: String,
    pub timestamp_utc: String,
    pub duration_ms: u128,
    pub data: Option<T>,
    pub error: Option<QaError>,
}

#[derive(Serialize)]
pub struct QaError {
    pub code: String,
    pub message: String,
}

fn envelope<T: Serialize>(data: T) -> Json<QaEnvelope<T>> {
    Json(QaEnvelope {
        ok: true,
        request_id: Uuid::new_v4().to_string(),
        timestamp_utc: chrono::Utc::now().to_rfc3339(),
        duration_ms: 0,
        data: Some(data),
        error: None,
    })
}

pub trait QaServiceControl {
    fn reset_state(&self) -> anyhow::Result<()>;
    fn reset_telemetry(&self) -> anyhow::Result<()>;
    fn start_auto(&self) -> anyhow::Result<()>;
    fn force_strategy_for_smoke_only(&self, strategy_id: &str) -> anyhow::Result<()>;
    fn reset_forced_strategy(&self) -> anyhow::Result<()>;
    fn run_probe(&self, target: QaProbeTarget) -> anyhow::Result<()>;
}

pub trait QaTelemetryRead {
    fn capabilities(&self) -> QaCapabilities;
    fn health(&self) -> QaHealth;
    fn strategy_inventory(&self) -> QaStrategyInventory;
    fn runtime_strategy_snapshot(&self) -> QaRuntimeStrategySnapshot;
    fn flow_telemetry(&self) -> QaFlowTelemetry;
    fn last_probe_result(&self) -> Option<QaProbeResult>;
    fn autotune_state(&self) -> QaAutotuneState;
    fn autotune_decision_log(&self) -> Vec<QaAutotuneDecisionEvent>;
}

#[derive(Serialize, Deserialize, Clone)]
pub struct QaProbeTarget {
    pub target_url: String,
    pub expected_oracle_mode: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct QaCapabilities { pub qa_enabled: bool, pub windivert_available: bool, pub service_mode: String }
#[derive(Serialize, Clone)]
pub struct QaHealth { pub status: String }
#[derive(Serialize, Clone)]
pub struct QaStrategyInventory { pub count: usize, pub strategies: Vec<QaStrategyInfo> }
#[derive(Serialize, Clone)]
pub struct QaStrategyInfo { pub id: String, pub name: String, pub source: String, pub enabled_in_auto: bool, pub unsupported_reasons: Vec<String> }
#[derive(Serialize, Clone)]
pub struct QaRuntimeStrategySnapshot { pub mode: String, pub active_strategy_id: String, pub generation: u64, pub selected_by: String }
#[derive(Serialize, Clone)]
pub struct QaFlowTelemetry { pub observed_flows: u64, pub processed_flows: u64, pub flows: Vec<serde_json::Value> }
#[derive(Serialize, Clone)]
pub struct QaProbeResult { pub block_class: String, pub confidence: f64, pub evidence: Vec<serde_json::Value>, pub selected_by: String }
#[derive(Serialize, Clone)]
pub struct QaAutotuneState { pub mode: String, pub generation: u64 }

#[derive(Serialize, Clone)]
pub struct QaAutotuneDecisionEvent {
    pub event_id: String,
    pub timestamp_utc: String,
    pub target_hash: String,
    pub block_class: String,
    pub probe_confidence: f64,
    pub previous_strategy_id: String,
    pub candidate_strategy_id: String,
    pub reason: String,
    pub phase: String,
    pub generation: u64,
    pub selected_by: String, // must be "app" for AutoTune causal pass
    pub external_intervention: bool,
    pub safe_rollout_state: String,
}

pub fn router(state: QaAppState) -> Router {
    Router::new()
        .route("/qa/capabilities", get(move || async move { envelope(state.telemetry.capabilities()) }))
        // Implementation agent: add the rest of the routes using typed handlers.
}
