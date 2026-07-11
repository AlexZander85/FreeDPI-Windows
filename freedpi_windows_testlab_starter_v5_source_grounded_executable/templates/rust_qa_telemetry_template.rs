//! Test-only runtime telemetry template.
//! The runner must verify app telemetry, not merely client success.

#![cfg(feature = "qa")]

use std::sync::atomic::{AtomicU64, Ordering};
use serde::Serialize;

#[derive(Default)]
pub struct QaRuntimeTelemetry {
    pub flows_observed: AtomicU64,
    pub flows_processed: AtomicU64,
    pub packets_captured: AtomicU64,
    pub packets_modified: AtomicU64,
    pub packets_injected: AtomicU64,
    pub packets_dropped: AtomicU64,
    pub windivert_recv_errors: AtomicU64,
    pub windivert_send_errors: AtomicU64,
}

#[derive(Serialize)]
pub struct QaTelemetrySnapshot {
    pub flows_observed: u64,
    pub flows_processed: u64,
    pub packets_captured: u64,
    pub packets_modified: u64,
    pub packets_injected: u64,
    pub packets_dropped: u64,
    pub windivert_recv_errors: u64,
    pub windivert_send_errors: u64,
}

impl QaRuntimeTelemetry {
    pub fn snapshot(&self) -> QaTelemetrySnapshot {
        QaTelemetrySnapshot {
            flows_observed: self.flows_observed.load(Ordering::Relaxed),
            flows_processed: self.flows_processed.load(Ordering::Relaxed),
            packets_captured: self.packets_captured.load(Ordering::Relaxed),
            packets_modified: self.packets_modified.load(Ordering::Relaxed),
            packets_injected: self.packets_injected.load(Ordering::Relaxed),
            packets_dropped: self.packets_dropped.load(Ordering::Relaxed),
            windivert_recv_errors: self.windivert_recv_errors.load(Ordering::Relaxed),
            windivert_send_errors: self.windivert_send_errors.load(Ordering::Relaxed),
        }
    }
}
