//! Test-only decision log template for AutoTune causal-chain verification.
//! This is not an external strategy controller. It only records decisions made by the app.

#![cfg(feature = "qa")]

use std::sync::{Arc, Mutex};
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
pub struct QaDecisionEvent {
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
    pub selected_by: String,
    pub external_intervention: bool,
    pub safe_rollout_state: String,
}

#[derive(Default, Clone)]
pub struct QaDecisionLog {
    events: Arc<Mutex<Vec<QaDecisionEvent>>>,
}

impl QaDecisionLog {
    pub fn record_app_event(&self, mut event: QaDecisionEvent) {
        event.event_id = Uuid::new_v4().to_string();
        event.timestamp_utc = chrono::Utc::now().to_rfc3339();
        event.selected_by = "app".to_string();
        event.external_intervention = false;
        self.events.lock().unwrap().push(event);
    }

    pub fn record_forced_test_event(&self, mut event: QaDecisionEvent) {
        event.event_id = Uuid::new_v4().to_string();
        event.timestamp_utc = chrono::Utc::now().to_rfc3339();
        event.selected_by = "runner".to_string();
        event.external_intervention = true;
        self.events.lock().unwrap().push(event);
    }

    pub fn snapshot(&self) -> Vec<QaDecisionEvent> {
        self.events.lock().unwrap().clone()
    }

    pub fn reset(&self) {
        self.events.lock().unwrap().clear();
    }
}
